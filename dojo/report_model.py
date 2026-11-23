"""Snapshot común de informes; coteja procedencia sin ejecutar motores analíticos."""

from collections import Counter, defaultdict
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
import re

from dojo.dashboard import CRITICALITIES, event_key, group_references
from dojo.detection import _digest, _jsonable
from dojo.ingestion import REQUIRED_COLUMNS
from dojo.normalization import N
from dojo.rules import RULES


VERSION = "4.1.1"
FILE_ACCESS_RECOMMENDATION = (
    "Investigar los eventos 4663: verificar las rutas accedidas, los permisos, "
    "la identidad y la autorización del usuario. Solicitar otras fuentes de "
    "corroboración cuando correspondan antes de inferir copia o transferencia."
)
COMBINED_ACCESS_RECOMMENDATION = "Contrastar accesos y bytes del proxy con autorizaciones y contenido disponible; no inferir exfiltración."
POLICY = {
    "investigation": "Preservar evidencia y contrastar autorización, inventario y línea base. Obtener sesiones, árboles de procesos y artefactos adicionales antes de atribuir intención o causalidad.",
    "containment": "Si se confirma actividad no autorizada y el responsable lo aprueba, evaluar restricciones de acceso o aislamiento acotado, preservando evidencia y continuidad operativa. No se ordena contención automática por una detección.",
    "remediation": "Después de establecer causa y alcance, corregir configuraciones o vulnerabilidades verificadas y validar la recuperación. Evitar eliminar tareas, servicios o archivos sin confirmar su función y autorización.",
}
CONCLUSION = (
    "Las activaciones y asociaciones justifican investigación, no una declaración de incidente confirmado. "
    "Corroborado respalda únicamente la actividad o coincidencia indicada; no confirma compromiso, causalidad, malicia ni daños. "
    "El alcance se limita al exportado recibido: la ausencia de registros no demuestra ausencia de actividad."
)


class ReportInputError(ValueError):
    """Entrada incompleta o inconsistente: no se exporta un informe parcial."""


def counted(count, singular, plural):
    return f"{count} {singular if count == 1 else plural}"


def report_narrative(value):
    """Concordancia de plantillas heredadas, solo para narrativa del informe.

    No aplicar a registros, comandos, roles o texto probatorio original.
    Los textos del resultado analítico se conservan por separado sin cambios.
    """
    variants = {
        "detecciones asociadas": "detección asociada",
        "eventos originales únicos": "evento original único",
        "registros previos de compresión compatibles": "registro previo de compresión compatible",
        "registros previos de compresión": "registro previo de compresión",
        "POST salientes registran": "POST saliente registra",
        "fallos RDP preceden": "fallo RDP precede",
        "fallos 4625": "fallo 4625",
        "solicitudes IIS incluyen": "solicitud IIS incluye",
        "registros 4663": "registro 4663", "registros 4688": "registro 4688",
        "rutas distintas": "ruta distinta", "cuentas": "cuenta",
    }
    pattern = r"\b1 (" + "|".join(re.escape(v) for v in variants) + r")\b"
    return re.sub(pattern, lambda match: "1 " + variants[match[1]], value)


def argentina_date():
    # Fecha de emisión; nunca se aplica este offset a los timestamps del SIEM.
    return datetime.now(timezone(timedelta(hours=-3))).date()


def report_signature(imported, analysis, correlation, case_name, issued_date):
    return _digest([VERSION, imported.digest, imported.filename, imported.sheet,
                    case_name, str(issued_date), analysis.report, correlation])


def _walk_references(value, verify, allowed):
    if isinstance(value, dict):
        if "excel_row" in value:
            key = verify(value)
            if key not in allowed:
                raise ReportInputError("Una referencia probatoria está fuera de las investigaciones.")
        for child in value.values():
            _walk_references(child, verify, allowed)
    elif isinstance(value, list):
        for child in value:
            _walk_references(child, verify, allowed)


def build_report_model(imported, analysis, correlation, case_name="Caso ficticio SOC L2", issued_date=None):
    """Copia independiente de datos y narrativas compartidas por los tres PDF.

    Las clasificaciones se consumen, no se recalculan. Los conteos se cotejan
    contra referencias únicas; no se insertan constantes del caso de regresión.
    """
    case_name = str(case_name).strip()
    if not case_name or len(case_name) > 200:
        raise ReportInputError("El nombre del caso debe contener de 1 a 200 caracteres.")
    issued_date = str(issued_date or argentina_date())
    try:
        date.fromisoformat(issued_date)
    except ValueError as exc:
        raise ReportInputError("Fecha de emisión inválida; usar AAAA-MM-DD.") from exc
    try:
        ar = analysis.report
        if (ar["input_sha256"] != imported.digest or ar["file"] != imported.filename
                or ar["sheet"] != imported.sheet or ar["record_count"] != len(imported.records)
                or correlation["source_analysis_id"] != ar["analysis_id"]
                or correlation["input_sha256"] != imported.digest):
            raise ReportInputError("Análisis, correlación y hoja no corresponden a la misma entrada.")
        columns = list(imported.records.columns)
        if not analysis.normalized[columns].equals(imported.records.reset_index(drop=True)):
            raise ReportInputError("Los valores originales del análisis cambiaron respecto de la importación.")
        rows = {event_key(r): r for r in imported.records.to_dict("records")}
        if len(rows) != len(imported.records):
            raise ReportInputError("La procedencia original está repetida.")

        def verify(ref, full=False):
            key = ref["sha256"], ref["sheet"], ref["excel_row"]
            raw = rows.get(key)
            if raw is None or ref.get("file", raw["__dojo_file"]) != raw["__dojo_file"]:
                raise ReportInputError("Referencia inexistente o archivo de evidencia inconsistente.")
            for column in REQUIRED_COLUMNS:
                if (full or column in ref) and ref[column] != _jsonable(raw[column]):
                    raise ReportInputError(f"Evidencia distinta del origen: fila {key[2]}, campo {column}.")
            if (full or "event_id_excel_type" in ref) and ref["event_id_excel_type"] != raw["__dojo_event_id_type"]:
                raise ReportInputError("El tipo Excel de Event_ID no coincide.")
            return key

        findings = ar["findings"]
        finding_map = {f["finding_id"]: f for f in findings}
        if len(finding_map) != len(findings):
            raise ReportInputError("IDs de detección repetidos.")
        references, primaries = Counter(), set()
        finding_keys, finding_roles = {}, {}
        for finding in findings:
            if finding["incident_confirmed"] is not False or finding["rule_id"] not in RULES:
                raise ReportInputError("La exportación solo admite activaciones sin incidentes confirmados.")
            keys = set()
            roles = {}
            for ref in finding["evidence"]:
                key = verify(ref, full=True)
                if not ref["roles"] or key in keys:
                    raise ReportInputError("Roles ausentes o evidencia duplicada dentro de una detección.")
                keys.add(key)
                roles[key] = sorted(ref["roles"])
                if any(not role.endswith("_context") for role in ref["roles"]):
                    primaries.add(key)
            finding_keys[finding["finding_id"]] = keys
            finding_roles[finding["finding_id"]] = roles
            references.update(keys)
        if correlation["incident_confirmed"] is not False or correlation["confirmed_impact"] is not False:
            raise ReportInputError("No se admite confirmación de incidente o daño en este modelo.")
        groups = correlation["groups"]
        if len({g["group_id"] for g in groups}) != len(groups):
            raise ReportInputError("IDs de línea repetidos.")
        owners = Counter(d for g in groups for d in g["detection_ids"])
        if set(owners) != set(finding_map) or any(n != 1 for n in owners.values()):
            raise ReportInputError("La partición de detecciones no coincide con las líneas.")
        short = group_references(groups)
        memberships = defaultdict(list)
        for group in groups:
            if group["incident_confirmed"] is not False or group["confirmed_impact"] is not False:
                raise ReportInputError("Una línea contiene confirmación no admitida.")
            if group["severity"]["confirmed_impact"] is not False:
                raise ReportInputError("La criticidad debe expresar impacto potencial.")
            if group["severity"]["label"] not in CRITICALITIES or group["confidence"]["label"] not in ("Alta", "Media", "Baja"):
                raise ReportInputError("Clasificación desconocida.")
            if group["investigation_state"] not in ("Indicador", "En investigación", "Corroborado", "Descartado"):
                raise ReportInputError("Estado de investigación desconocido.")
            if any(impact["confirmed"] is not False for impact in group["severity"]["potential_impacts"]):
                raise ReportInputError("Se requiere expresar impacto potencial, sin daños confirmados.")
            expected = set().union(*(finding_keys[d] for d in group["detection_ids"]))
            keys = set()
            for ref in group["evidence"]:
                key = verify(ref, full=True)
                roles = {d: finding_roles[d][key] for d in group["detection_ids"] if key in finding_keys[d]}
                primary = any(not role.endswith("_context") for values in roles.values() for role in values)
                if key in keys or ref["detection_roles"] != roles or ref["primary"] != primary:
                    raise ReportInputError("Roles o deduplicación de evidencia de línea inconsistentes.")
                keys.add(key)
                memberships[key].append(dict(group_id=group["group_id"], line=short[group["group_id"]],
                                               primary=primary, detection_roles=deepcopy(roles)))
            if keys != expected or {verify(e, full=True) for e in group["timeline"]} != keys or len(group["timeline"]) != len(keys):
                raise ReportInputError("Anexo, detecciones y línea temporal no contienen las mismas referencias.")
            for name in ("facts", "severity", "corroborations", "review"):
                _walk_references(group[name], verify, keys)
        allowed = set(references)
        if set(memberships) != allowed:
            raise ReportInputError("El anexo no cubre todas las evidencias.")
        _walk_references(correlation, verify, allowed)
        summary = dict(detections=len(findings), groups=len(groups), unique_events=len(allowed),
                       event_references=sum(references.values()), duplicate_event_references=sum(n - 1 for n in references.values()),
                       primary_unique_events=len(primaries), active_groups=sum(g["investigation_state"] != "Descartado" for g in groups),
                       severities=dict(Counter(g["severity"]["label"] for g in groups)),
                       confidences=dict(Counter(g["confidence"]["label"] for g in groups)),
                       states=dict(Counter(g["investigation_state"] for g in groups)))
        if summary != correlation["summary"]:
            raise ReportInputError("Los contadores del resultado no coinciden con la evidencia.")
        evidence = []
        evidence_ids = {key: f"E{i:04d}" for i, key in enumerate(sorted(allowed), 1)}
        for key in sorted(allowed):
            raw = rows[key]
            evidence.append(dict(ref=evidence_ids[key], file=raw["__dojo_file"], sha256=key[0], sheet=key[1], excel_row=key[2],
                                 values={c: _jsonable(raw[c]) for c in imported.columns},
                                 event_id_excel_type=raw["__dojo_event_id_type"], memberships=memberships[key]))
        lines = []
        for group in groups:
            line = deepcopy(group)
            line["ref"] = short[group["group_id"]]
            line["evidence_refs"] = [evidence_ids[event_key(e)] for e in group["evidence"]]
            line["timeline_refs"] = [evidence_ids[event_key(e)] for e in group["timeline"]]
            line["report_description"] = report_narrative(group["description"])
            investigation = deepcopy(group["recommended_actions"])
            if "R04A" in group["rules"] and group["facts"]["outbound_post_events"] == 0:
                investigation = [FILE_ACCESS_RECOMMENDATION if action == COMBINED_ACCESS_RECOMMENDATION else action
                                 for action in investigation]
            line["recommendations"] = dict(investigation=investigation,
                                            containment=[POLICY["containment"]], remediation=[POLICY["remediation"]])
            lines.append(line)
        sources = Counter(_jsonable(v) for v in imported.records["Log_Source"] if _jsonable(v) is not None)
        siem = Counter(_jsonable(v) for v in imported.records["Severity"] if _jsonable(v) is not None)
        diagnostics = deepcopy(ar["diagnostics"])
        coverage = [f"{d['rule_id']}: {d['state']}; candidatos {d['candidate_records']}, utilizables {d['eligible_records']}, excluidos por datos incompletos {d['skipped_incomplete']}." for d in diagnostics]
        priorities = []
        for label in CRITICALITIES:
            refs = [g["ref"] for g in lines if g["severity"]["label"] == label and g["investigation_state"] != "Descartado"]
            if refs:
                priorities.append(dict(criticality=label, lines=refs,
                    decision=f"Priorizar revisión de {', '.join(refs)} según criticidad potencial {label}; verificar autorización y alcance antes de decidir medidas operativas."))
        executive_observations = []
        for line in lines:
            facts = line["facts"]
            if facts["outbound_post_events"]:
                volume = f"{facts['recorded_bytes_out']:,}".replace(",", ".")
                executive_observations.append(
                    f"{line['ref']}: {counted(facts['outbound_post_events'], 'solicitud POST', 'solicitudes POST')} "
                    f"con {volume} {('byte saliente registrado' if facts['recorded_bytes_out'] == 1 else 'bytes salientes registrados')}; "
                    "no se afirma exfiltración ni se establece el contenido transferido."
                )
            if any(c["criterion"] == "web_command_process" for c in line["corroborations"]):
                executive_observations.append(
                    f"{line['ref']}: asociación observacional entre solicitudes IIS y un proceso con comando coincidente, "
                    "sin ejecución remota confirmada."
                )
        model = dict(version=VERSION, case_name=case_name, issued_date=issued_date, fictitious=True,
            provenance=dict(file=imported.filename, sha256=imported.digest, sheet=imported.sheet,
                            columns=list(imported.columns), records=len(imported.records),
                            time_start=imported.summary["time_start"], time_end=imported.summary["time_end"],
                            timezone="Zona horaria de los logs no especificada"),
            analysis_id=ar["analysis_id"], correlation_id=correlation["correlation_id"],
            engine_version=ar["engine_version"], normalization_version=ar["normalization_version"],
            correlation_version=correlation["correlation_version"], risk_version=correlation["model_version"],
            summary=summary, sources=dict(sources), siem_severities=dict(siem),
            executive_summary=[
                f"{'Se analizó' if len(imported.records) == 1 else 'Se analizaron'} {counted(len(imported.records), 'registro', 'registros')} de {counted(len(sources), 'fuente de logs', 'fuentes de logs')}. Se conservaron valores y procedencia del Excel, sin atribuir zona horaria.",
                f"El resultado vigente contiene {counted(summary['detections'], 'activación', 'activaciones')} y {counted(summary['groups'], 'línea de investigación', 'líneas de investigación')}, con {counted(summary['unique_events'], 'evento original único asociado', 'eventos originales únicos asociados')}. Son unidades distintas y no equivalen a incidentes confirmados.",
                "La criticidad expresa prioridad de impacto potencial. La confianza expresa soporte observacional de la asociación, no probabilidad de ataque."],
            executive_observations=executive_observations,
            finding_narratives={f["finding_id"]: report_narrative(f["reason"]) for f in findings},
            conclusion=CONCLUSION, recommendation_policy=deepcopy(POLICY), priorities=priorities,
            lines=lines, findings=deepcopy(findings), evidence=evidence, links=deepcopy(correlation["links"]),
            overlaps=deepcopy(correlation["overlaps"]), diagnostics=diagnostics, coverage=coverage,
            normalization_issues=deepcopy(ar["normalization_issues"]), import_issues=deepcopy(ar["import_issues"]),
            quality=_jsonable(imported.quality.to_dict("records")),
            rules=[dict(rule_id=r, **deepcopy(RULES[r]), parameters=deepcopy(ar["parameters"][r])) for r in ar["enabled_rules"]],
            correlation_parameters=deepcopy(correlation["parameters"]), risk_model=deepcopy(correlation["risk_model"]),
            limitations=list(dict.fromkeys(correlation["limitations"] + [
                "Caso ficticio. No se geolocalizan IP reservadas para documentación ni se identifica un atacante real.",
                "No se infiere escalamiento por Event_ID 4672, transferencia por 5156, ni efectos exitosos de un comando registrado.",
                "Sin IDs de sesión/logon, PID/PPID, inventario, autorización, contenido o línea base suficientes para atribuir causalidad.",
                "Las recomendaciones son propuestas condicionadas; no son acciones ejecutadas ni hechos observados."])),
            incident_confirmed=False, confirmed_impact=False)
        model["report_id"] = "I-" + _digest(model)[:24]
        return model
    except ReportInputError:
        raise
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        raise ReportInputError("El resultado estructurado está incompleto o contiene referencias inconsistentes.") from exc
