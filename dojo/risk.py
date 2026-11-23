"""Clasificación 2B: impacto potencial, calidad del soporte y estado separados."""

from collections import Counter
from copy import deepcopy
import re

from dojo.detection import _bytes_out, _digest, _file_target, _jsonable, _rdp, _shell_payload, _web_command, command_tags, executable
from dojo.normalization import N


MODEL_VERSION = "2B.1"
DEFAULT_MODEL = {
    "weights": {
        "authentication_failures": 10, "multiple_accounts": 10, "later_authentication": 10,
        "encoded_powershell": 20, "discovery": 10, "shadow_delete_command": 40,
        "repeated_file_access": 25, "compression_command": 15,
        "outbound_posts": 25, "large_recorded_volume": 15,
        "task_creation": 15, "service_installation": 15, "recurrent_process": 15,
        "web_command_requests": 15, "web_process_context": 45, "shell_identity": 15,
        "observed_network_surface": 5,
    },
    "severity_thresholds": {"Medio": 25, "Alto": 50, "Crítico": 85},
    "large_volume_bytes": 104857600,
    "critical_min_impact_families": 2,
    "confidence_weights": {
        "verified_provenance": 25, "complete_timestamps": 15, "complete_identity": 10,
        "multiple_unique_events": 10, "direct_attribute_link": 15,
        "typed_observation_bridge": 15, "distinct_log_sources": 10,
    },
    "confidence_thresholds": {"Media": 45, "Alta": 80},
    "corroboration_min_confidence": 80,
}


def model_parameters(overrides=None):
    model = deepcopy(DEFAULT_MODEL)
    if overrides is not None and not isinstance(overrides, dict):
        raise ValueError("El modelo debe ser un objeto de parámetros.")
    for key, value in (overrides or {}).items():
        if key not in model:
            raise ValueError(f"Parámetro de clasificación desconocido: {key}")
        if isinstance(model[key], dict):
            if not isinstance(value, dict) or set(value) - set(model[key]):
                raise ValueError(f"Configuración inválida: {key}")
            model[key].update(deepcopy(value))
        else:
            model[key] = deepcopy(value)
    for section in ("weights", "confidence_weights"):
        if any(type(v) is not int or not 0 <= v <= 100 for v in model[section].values()):
            raise ValueError(f"{section}: cada peso debe ser entero entre 0 y 100.")
    for section, labels in (("severity_thresholds", ("Medio", "Alto", "Crítico")),
                            ("confidence_thresholds", ("Media", "Alta"))):
        values = [model[section][label] for label in labels]
        if any(type(v) is not int or not 1 <= v <= 100 for v in values) or values != sorted(set(values)):
            raise ValueError(f"{section}: umbrales enteros estrictamente crecientes de 1 a 100.")
    for key, maximum in (("large_volume_bytes", 10**15), ("critical_min_impact_families", 10),
                         ("corroboration_min_confidence", 100)):
        if type(model[key]) is not int or not 1 <= model[key] <= maximum:
            raise ValueError(f"Parámetro inválido: {key}")
    return model


def row_key(row):
    return row["__dojo_sha256"], row["__dojo_sheet"], int(row["__dojo_row"])


def proof(row):
    return _jsonable(dict(file=row["__dojo_file"], sha256=row["__dojo_sha256"],
                          sheet=row["__dojo_sheet"], excel_row=int(row["__dojo_row"]),
                          Log_ID=row["Log_ID"], Timestamp=row["Timestamp"]))


def _unique_proofs(rows):
    return [proof(row) for _, row in sorted({row_key(row): row for row in rows}.items())]


def service_path(row):
    if row[N + "event_id"] != "7045":
        return None
    match = re.search(r'\bImagePath\s*=\s*(?:"([^"\r\n]+\.exe)"|([^;\r\n]*?\.exe))(?=\s|;|$)', row[N + "command"] or "", re.I)
    return (match.group(1) or match.group(2)).strip().casefold() if match else None


def observation_bridges(rows, params):
    """Puentes fácticos sobre eventos únicos, aun contenidos en una sola detección.

    No dependen de cuántas reglas representan los mismos eventos.
    """
    bridges = {}
    processes = [r for r in rows if r[N + "event_id"] == "4688"]
    for a in rows:
        for b in processes:
            if row_key(a)[:2] != row_key(b)[:2] or a[N + "timestamp"] is None or b[N + "timestamp"] is None:
                continue
            gap = (b[N + "timestamp"] - a[N + "timestamp"]).total_seconds()
            if gap <= 0:
                continue
            fields = {f: a[N + f] for f in ("host", "user", "ip") if a[N + f] is not None and a[N + f] == b[N + f]}
            configured = service_path(a)
            if configured and all(f in fields for f in ("host", "user", "ip")) and configured == executable(b[N + "command"]) and gap <= params["strong_window_seconds"]:
                item = dict(criterion="service_process_path", matched_fields={**fields, "process": configured}, evidence=[proof(a), proof(b)], window_seconds=params["strong_window_seconds"], observed_seconds=gap)
                bridges[("service_process_path", row_key(a), row_key(b))] = item
            command = _web_command(a) if a[N + "event_id"] == "HTTP_ACCESS" and a[N + "source"] == "iis" else None
            if command and command == _shell_payload(b) and all(f in fields for f in ("host", "ip")) and (b[N + "user"] or "").startswith("iis apppool\\") and gap <= params["web_window_seconds"]:
                item = dict(criterion="web_command_process", matched_fields={"host": fields["host"], "ip": fields["ip"], "command": command}, evidence=[proof(a), proof(b)], window_seconds=params["web_window_seconds"], observed_seconds=gap)
                bridges[("web_command_process", row_key(a), row_key(b))] = item
    return [bridges[key] for key in sorted(bridges)]


def _title(active):
    if "web_process_context" in active:
        return "Solicitudes y proceso IIS con comando coincidente"
    if "outbound_posts" in active:
        return "Compresión y POST salientes registrados" if "compression_command" in active else "POST salientes registrados"
    if "task_creation" in active or "service_installation" in active:
        if {"task_creation", "service_installation", "recurrent_process"} <= active:
            return "Tareas, servicios y procesos registrados"
        labels = [label for factor, label in (("task_creation", "tarea programada"),
                                              ("service_installation", "servicio"),
                                              ("recurrent_process", "creaciones recurrentes de proceso")) if factor in active]
        return "Actividad registrada: " + ", ".join(labels)
    if "shadow_delete_command" in active:
        return "Comandos de administración sensible registrados"
    if "authentication_failures" in active:
        return "Autenticaciones y comandos en contexto coincidente" if "encoded_powershell" in active else "Autenticaciones fallidas para investigación"
    if "repeated_file_access" in active:
        return "Accesos repetitivos a documentos registrados"
    if "recurrent_process" in active:
        return "Creaciones recurrentes de proceso"
    return "Actividad registrada para revisión"


def classify_group(group, rows, model, review=None):
    """rows solo contiene evidencia ya verificada. Cada factor se activa una vez."""
    primary_keys = {(e["sha256"], e["sheet"], e["excel_row"]) for e in group["evidence"] if e["primary"]}
    primary = [r for r in rows if row_key(r) in primary_keys]
    by_code = lambda code: [r for r in primary if r[N + "event_id"] == code]
    failures = [r for r in by_code("4625") if r[N + "result"] == "failure"]
    # Un éxito contextual solo aporta hechos si realmente sucede a un fallo de
    # la misma cuenta/host/IP; no convierte el éxito en acceso no autorizado.
    successes = [r for r in rows if r[N + "event_id"] == "4624" and r[N + "result"] == "success"
                 and any(all(r[N + key] is not None and r[N + key] == f[N + key] for key in ("host", "user", "ip"))
                         and r[N + "timestamp"] is not None and f[N + "timestamp"] is not None
                         and r[N + "timestamp"] > f[N + "timestamp"] for f in failures)]
    tags = {}
    for tag in ("powershell_encoded", "discovery", "shadow_delete", "compression", "shell_identity"):
        tags[tag] = [r for r in rows if r[N + "event_id"] in ("4688", "4104") and tag in command_tags(r)]
    posts = [r for r in rows if r[N + "event_id"] == "PROXY_ACCESS" and r[N + "source"] == "proxy"
             and _bytes_out(r) is not None and re.search(r"\bHTTPS?\s+POST\s+outbound\b", r[N + "description"] or "", re.I)]
    recorded_bytes = sum(_bytes_out(r) for r in posts)
    bridges = observation_bridges(rows, group["correlation_parameters"])
    web_bridge = [bridge for bridge in bridges if bridge["criterion"] == "web_command_process"]
    web_rows = [r for r in rows if row_key(r) in {(p["sha256"], p["sheet"], p["excel_row"]) for b in web_bridge for p in b["evidence"]}]
    network = [r for r in rows if r[N + "event_id"] == "HTTP_ACCESS" or
               (r[N + "event_id"] in ("4624", "4625") and _rdp(r))] + posts
    file_rows = [r for r in rows if r[N + "event_id"] == "4663" and _file_target(r)]
    process_buckets = Counter((r[N + "host"], r[N + "user"], r[N + "ip"], executable(r[N + "command"])) for r in rows
                              if r[N + "event_id"] == "4688" and executable(r[N + "command"]) and all(r[N + f] for f in ("host", "user", "ip")))
    suspicious_requests = [r for r in rows if r[N + "event_id"] == "HTTP_ACCESS" and r[N + "source"] == "iis" and _web_command(r)]
    features = {
        "authentication_failures": (bool(failures), failures, "Fallos de autenticación registrados; autorización desconocida."),
        "multiple_accounts": (len({r[N + "user"] for r in failures if r[N + "user"]}) >= 3, failures, "Fallos contra varias cuentas conocidas."),
        "later_authentication": (bool(successes), successes + failures, "Éxito posterior con cuenta/host/IP coincidentes; causalidad no demostrada."),
        "encoded_powershell": (bool(tags["powershell_encoded"]), tags["powershell_encoded"], "Texto de PowerShell con parámetro de codificación."),
        "discovery": (bool(tags["discovery"]), tags["discovery"], "Comandos de descubrimiento registrados."),
        "shadow_delete_command": (bool(tags["shadow_delete"]), tags["shadow_delete"], "Comando de eliminación de instantáneas registrado; efectos no probados."),
        "repeated_file_access": (len(file_rows) >= 5 and len({_file_target(r) for r in file_rows}) >= 5, file_rows, "Cinco o más accesos/intentos a rutas distintas; sin prueba de copia o cifrado."),
        "compression_command": (bool(tags["compression"]), tags["compression"], "Comando de compresión registrado; archivo resultante no verificado."),
        "outbound_posts": (bool(posts), posts, "POST salientes con bytes_out registrados; contenido y autorización desconocidos."),
        "large_recorded_volume": (bool(posts) and recorded_bytes >= model["large_volume_bytes"], posts, "Volumen registrado supera el umbral configurado; no determina contenido."),
        "task_creation": (bool(by_code("4698")), by_code("4698"), "Creación de tarea registrada; puede ser administración autorizada."),
        "service_installation": (bool(by_code("7045")), by_code("7045"), "Instalación de servicio registrada; naturaleza del binario no determinada."),
        "recurrent_process": (max(process_buckets.values(), default=0) >= 3, [r for r in rows if r[N + "event_id"] == "4688"], "Tres o más creaciones del mismo ejecutable/contexto; no prueban persistencia maliciosa."),
        # La señal web compuesta sustituye a sus señales individuales; no suma
        # R06A + R06B + R03 para la misma observación.
        "web_command_requests": (bool(suspicious_requests), suspicious_requests, "Parámetros de comando en solicitudes web."),
        "web_process_context": (bool(web_bridge), web_rows, "Coincidencia de comando/host/IP entre solicitud y proceso IIS posterior; no prueba RCE."),
        "shell_identity": (bool(tags["shell_identity"]), tags["shell_identity"], "Shell con comando de identidad registrado."),
        "observed_network_surface": (bool(network), network, "Superficie RDP/HTTP o salida de datos explícita en los registros; exposición externa real no determinada."),
    }
    factors = []
    for name, (active, evidence_rows, reason) in features.items():
        suppressed = bool(web_bridge) and name in ("web_command_requests", "shell_identity")
        factors.append(dict(factor=name, active=bool(active), weight=model["weights"][name],
                            points=model["weights"][name] if active and not suppressed else 0,
                            suppressed_by="web_process_context" if suppressed and active else None,
                            reason=reason, evidence=_unique_proofs(evidence_rows) if active else []))
    active = {f["factor"] for f in factors if f["active"]}
    score = min(100, sum(f["points"] for f in factors))
    impacts = []
    for condition, family, description in [
        ("shadow_delete_command" in active, "recovery", "Potencial afectación de capacidad de recuperación si el comando tuviera efecto."),
        ("outbound_posts" in active, "data", "Potencial exposición de información; contenido y autorización no establecidos."),
        ("web_process_context" in active, "application", "Potencial ejecución a través de aplicación web, pendiente de vínculo causal."),
        ("task_creation" in active or "service_installation" in active, "persistence", "Potencial mecanismo de persistencia o administración legítima."),
        (bool(successes), "access", "Potencial uso de cuenta tras fallos; no se demuestra acceso no autorizado."),
    ]:
        if condition:
            impacts.append(dict(family=family, description=description, confirmed=False))
    thresholds = model["severity_thresholds"]
    critical_gate = len(impacts) >= model["critical_min_impact_families"]
    severity = "Crítico" if score >= thresholds["Crítico"] and critical_gate else "Alto" if score >= thresholds["Alto"] else "Medio" if score >= thresholds["Medio"] else "Bajo"
    sources = {r[N + "source"] for r in rows if r[N + "source"]}
    identity_link = bool(bridges) or any(
        row_key(a) != row_key(b) and a[N + "timestamp"] is not None and b[N + "timestamp"] is not None
        and abs((a[N + "timestamp"] - b[N + "timestamp"]).total_seconds()) <= group["correlation_parameters"]["strong_window_seconds"]
        and all(a[N + f] is not None and a[N + f] == b[N + f] for f in ("host", "user", "ip"))
        for i, a in enumerate(rows) for b in rows[i + 1:])
    checks = {
        "verified_provenance": (True, "Todas las referencias y valores se cotejaron con el origen importado."),
        "complete_timestamps": (all(r[N + "timestamp"] is not None for r in rows), "Timestamps válidos en toda la evidencia, sin asignar zona."),
        "complete_identity": (all(all(r[N + f] is not None for f in ("host", "user", "ip")) for r in rows), "Host, usuario e IP conocidos en toda la evidencia."),
        "multiple_unique_events": (len(rows) >= 2, "Varios eventos originales distintos, contados una sola vez."),
        "direct_attribute_link": (identity_link, "Coocurrencia directa de atributos en eventos distintos, independiente de cuántas reglas los representen."),
        "typed_observation_bridge": (bool(bridges), "Coincidencia explícita de ruta servicio/proceso o de comando solicitud/proceso."),
        "distinct_log_sources": (len(sources) >= 2, "Más de una etiqueta Log_Source; no se presupone independencia de sensores."),
    }
    confidence_factors = [dict(factor=name, active=bool(active), weight=model["confidence_weights"][name],
                               points=model["confidence_weights"][name] if active else 0, reason=reason)
                          for name, (active, reason) in checks.items()]
    confidence_score = min(100, sum(f["points"] for f in confidence_factors))
    confidence = "Alta" if confidence_score >= model["confidence_thresholds"]["Alta"] else "Media" if confidence_score >= model["confidence_thresholds"]["Media"] else "Baja"
    corroborations = [dict(
        criterion=b["criterion"], window_seconds=b["window_seconds"], observed_seconds=b["observed_seconds"],
        window_basis="witness_time_gap",
        activity="Coincidencia de ruta configurada en servicio y ejecutable registrado" if b["criterion"] == "service_process_path" else "Coincidencia textual de comando en solicitud y proceso IIS posterior",
        evidence=b["evidence"], fields=b["matched_fields"],
        scope="Actividad/coincidencia registrada. No confirma causalidad, intención maliciosa ni incidente de seguridad.",
    ) for b in bridges]
    automatic_state = "Corroborado" if corroborations and confidence_score >= model["corroboration_min_confidence"] else "Indicador" if len(rows) == 1 else "En investigación"
    state = automatic_state
    if review is not None:
        if not isinstance(review, dict) or set(review) != {"state", "reason", "evidence"}:
            raise ValueError("La revisión requiere state, reason y evidence.")
        if review["state"] not in ("En investigación", "Descartado") or not isinstance(review["reason"], str) or not review["reason"].strip():
            raise ValueError("Revisión inválida: se requiere estado permitido y justificación explícita.")
        available = {(e["sha256"], e["sheet"], e["excel_row"]) for e in group["evidence"]}
        evidence = review["evidence"]
        if not isinstance(evidence, list) or not evidence or any(not isinstance(e, dict) or set(e) != {"sha256", "sheet", "excel_row"} for e in evidence):
            raise ValueError("La revisión necesita referencias de evidencia existentes.")
        if any((e["sha256"], e["sheet"], e["excel_row"]) not in available for e in evidence):
            raise ValueError("La revisión contiene evidencia ajena a la agrupación.")
        review = dict(state=review["state"], reason=review["reason"].strip(),
                      evidence=sorted(evidence, key=lambda e: (e["sha256"], e["sheet"], e["excel_row"])),
                      source="Decisión explícita del analista, no validada externamente.")
        state = review["state"]
    hypotheses = []
    actions = ["Contrastar autorización, inventario y línea base con el responsable del caso."]
    if failures:
        hypotheses.append("Posible intento de acceso mediante credenciales; errores legítimos siguen siendo una alternativa.")
        actions.append("Revisar autenticaciones, ID de logon/sesión y uso autorizado de las cuentas; no atribuir 4672 a escalamiento.")
    if tags["powershell_encoded"] or tags["shadow_delete"] or tags["discovery"]:
        hypotheses.append("Los comandos pueden corresponder a administración legítima o actividad no autorizada; sus efectos no están demostrados.")
        actions.append("Obtener script, árbol de procesos y artefactos EDR; verificar efectos del comando sin ejecutarlo.")
    if "repeated_file_access" in active or posts:
        hypotheses.append("Posible recopilación/transferencia de información; no se establece contenido ni prohibición.")
        actions.append("Contrastar accesos y bytes del proxy con autorizaciones y contenido disponible; no inferir exfiltración.")
    if "task_creation" in active or "service_installation" in active or "recurrent_process" in active:
        hypotheses.append("Posible mecanismo de persistencia o mantenimiento autorizado; naturaleza del ejecutable no determinada.")
        actions.append("Revisar XML de tarea, configuración del servicio, firma/hash del binario y árbol de procesos.")
    if "web_command_requests" in active or "web_process_context" in active:
        hypotheses.append("Posible ejecución de comandos a través de la aplicación, pendiente de vínculo solicitud/proceso.")
        actions.append("Revisar logs de aplicación/IIS y procesos padre-hijo sin reproducir solicitudes potencialmente activas.")
    missing = ["Zona horaria y sincronización de relojes no establecidas.",
               "Autorización, inventario y línea base no aportados.",
               "IDs de sesión/logon, PID/PPID, hashes de ejecutables y contenido de transferencias no disponibles."]
    for field in ("timestamp", "host", "user", "ip"):
        count = sum(r[N + field] is None for r in primary)
        if count:
            missing.append(f"{count} eventos primarios sin {field} normalizado utilizable.")
    return dict(
        title=_title(active),
        description=f"{len(group['detection_ids'])} detecciones asociadas, {len(rows)} eventos originales únicos; vínculos observacionales sin causalidad atribuida.",
        facts=dict(unique_events=len(rows), primary_events=len(primary), event_counts=dict(sorted(Counter(r[N + 'event_id'] or 'desconocido' for r in rows).items())),
                   failed_authentications=len(failures), distinct_failed_accounts=len({r[N + 'user'] for r in failures if r[N + 'user']}),
                   later_authentications=len(successes), outbound_post_events=len(posts), recorded_bytes_out=recorded_bytes,
                   suspicious_web_requests=len(suspicious_requests), http_events=len([r for r in rows if r[N + "event_id"] == "HTTP_ACCESS"]),
                   behavior_observations=[dict(factor=f['factor'], statement=f['reason'], evidence=f['evidence']) for f in factors if f['active']]),
        hypotheses=hypotheses, corroborations=corroborations,
        severity=dict(label=severity, score=score, factors=factors, thresholds=thresholds,
                      critical_gate_satisfied=critical_gate, potential_impacts=impacts,
                      exposure="Superficies observadas en logs; exposición real, titularidad y geolocalización no determinadas.",
                      context="Sin inventario o autorización; no se asigna criticidad por nombres de usuario/host o Severity del SIEM.",
                      confirmed_impact=False, scope="Priorización de impacto potencial; no prueba daños reales."),
        confidence=dict(label=confidence, score=confidence_score, factors=confidence_factors,
                        scope="Confianza en trazabilidad y asociación observada, no en causalidad, malicia o compromiso."),
        investigation_state=state, automatic_state=automatic_state, review=review,
        incident_confirmed=False, confirmed_impact=False,
        missing_information=missing,
        recommended_actions=actions,
        classification_id="K-" + _digest([MODEL_VERSION, group["group_id"], model, factors, confidence_factors, review])[:24],
    )
