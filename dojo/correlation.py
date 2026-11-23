"""Correlación 2B con enlaces explícitos y agrupación de enlace completo."""

from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from itertools import combinations
import re

from dojo.detection import _digest, _jsonable, _shell_payload, _web_command, executable
from dojo.ingestion import REQUIRED_COLUMNS
from dojo.normalization import N
from dojo.risk import MODEL_VERSION, classify_group, model_parameters, proof, row_key, service_path
from dojo.rules import RULES


VERSION = "2B.1"
DEFAULT_PARAMETERS = dict(strong_window_seconds=1800, context_window_seconds=600,
                          temporal_window_seconds=300, web_window_seconds=300,
                          group_window_seconds=1800, max_detections=1000)


def correlation_parameters(overrides=None):
    result = dict(DEFAULT_PARAMETERS)
    if overrides is not None and not isinstance(overrides, dict):
        raise ValueError("La correlación requiere un objeto de parámetros.")
    if set(overrides or {}) - set(result):
        raise ValueError("Parámetro de correlación desconocido.")
    result.update(overrides or {})
    for name, value in result.items():
        maximum = 1000 if name == "max_detections" else 604800
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f"{name}: se requiere entero de 1 a {maximum}.")
    return result


def _bounds(rows):
    times = [row[N + "timestamp"] for row in rows]
    valid = [value for value in times if value is not None]
    return (min(valid) if valid else None, max(valid) if valid else None, bool(times) and len(valid) == len(times))


@dataclass
class _Node:
    detection: dict
    all_keys: set
    primary_keys: set
    rows: list
    primary: list

    @property
    def id(self):
        return self.detection["finding_id"]

    @property
    def order(self):
        start, _, _ = _bounds(self.rows)
        return start or datetime.max, self.detection["rule_id"], self.id


def _load(analysis):
    rowmap = {}
    for row in analysis.normalized.to_dict("records"):
        key = row_key(row)
        if key in rowmap:
            raise ValueError("Procedencia repetida en el análisis de origen.")
        rowmap[key] = row
    nodes = []
    seen_ids = set()
    for detection in analysis.report["findings"]:
        ident = detection.get("finding_id")
        if not isinstance(ident, str) or not ident or ident in seen_ids or detection.get("rule_id") not in RULES:
            raise ValueError("Identificador de detección ausente/repetido o regla desconocida.")
        seen_ids.add(ident)
        all_keys, primary_keys = set(), set()
        for evidence in detection.get("evidence", []):
            try:
                key = evidence["sha256"], evidence["sheet"], evidence["excel_row"]
                row = rowmap[key]
                if evidence["file"] != row["__dojo_file"] or evidence["event_id_excel_type"] != row["__dojo_event_id_type"]:
                    raise ValueError("Metadatos de evidencia inconsistentes.")
                if any(_jsonable(row[column]) != evidence[column] for column in REQUIRED_COLUMNS):
                    raise ValueError("Los valores de evidencia no coinciden con el registro original.")
                roles = evidence["roles"]
                if not isinstance(roles, list) or not roles or any(not isinstance(role, str) or not role for role in roles):
                    raise ValueError("Roles de evidencia ausentes o inválidos.")
                all_keys.add(key)
                if any(not role.endswith("_context") for role in roles):
                    primary_keys.add(key)
            except (KeyError, TypeError) as exc:
                raise ValueError("Referencia inexistente o incompleta en la evidencia de origen.") from exc
        if not primary_keys:
            raise ValueError("Una detección debe contener al menos un evento primario.")
        nodes.append(_Node(detection, all_keys, primary_keys,
                           [rowmap[k] for k in sorted(all_keys)], [rowmap[k] for k in sorted(primary_keys)]))
    return sorted(nodes, key=lambda node: node.order), rowmap


def _service_path(row):
    return service_path(row)


def _process(row):
    return _service_path(row) or (executable(row[N + "command"]) if row[N + "event_id"] == "4688" else None)


def _matches(left, right):
    values = {field: left[N + field] for field in ("host", "user", "ip", "destination")
              if left[N + field] is not None and left[N + field] == right[N + field]}
    process = _process(left)
    if process and process == _process(right):
        values["process"] = process
    return values


def _criterion(name, fields, rows, window, basis, gap, explanation):
    return dict(criterion=name, matched_fields=fields, evidence=[proof(row) for row in rows],
                window_seconds=window, window_basis=basis, observed_seconds=gap,
                reason=explanation, causal=False)


def _pair(left, right, params):
    if {_k[:2] for _k in left.all_keys} != {_k[:2] for _k in right.all_keys} or len({k[:2] for k in left.all_keys | right.all_keys}) != 1:
        return None
    start, end, complete = _bounds(left.rows + right.rows)
    span = (end - start).total_seconds() if start is not None else None
    strong, contextual = {}, {}
    overlap = left.all_keys & right.all_keys
    shared_primary = left.primary_keys & right.primary_keys
    if shared_primary:
        rows = [r for r in left.primary if row_key(r) in shared_primary]
        strong["same_original_event"] = _criterion(
            "same_original_event", {"source_event_identity": True}, rows, None, "exact_event_identity", None,
            "Las detecciones comparten eventos primarios idénticos, cotejados con el origen; no son observaciones independientes.")
    nearest = None
    for a in left.primary:
        for b in right.primary:
            if row_key(a) == row_key(b):
                continue
            ta, tb = a[N + "timestamp"], b[N + "timestamp"]
            if ta is None or tb is None:
                continue
            gap = abs((tb - ta).total_seconds())
            if nearest is None or (gap, row_key(a), row_key(b)) < nearest[0]:
                nearest = ((gap, row_key(a), row_key(b)), a, b)
            matches = _matches(a, b)
            bounded = complete and span <= params["strong_window_seconds"]
            if bounded and all(field in matches for field in ("host", "user", "ip")):
                strong.setdefault("same_host_user_ip", _criterion(
                    "same_host_user_ip", matches, [a, b], params["strong_window_seconds"], "combined_evidence_span", span,
                    "Host, usuario e IP coinciden en un par de eventos distinto, dentro de la duración máxima de toda la evidencia. No acredita misma sesión ni causalidad."))
            service, process = (a, b) if a[N + "event_id"] == "7045" else (b, a)
            if bounded and _service_path(service) and process[N + "event_id"] == "4688" and all(f in matches for f in ("host", "user", "ip", "process")) and process[N + "timestamp"] > service[N + "timestamp"]:
                strong.setdefault("service_process_path", _criterion(
                    "service_process_path", matches, [service, process], params["strong_window_seconds"], "combined_evidence_span", span,
                    "ImagePath de un servicio coincide con el ejecutable de un 4688 posterior del mismo host/usuario/IP. No demuestra que el servicio haya iniciado el proceso."))
            request, shell = (a, b) if a[N + "event_id"] == "HTTP_ACCESS" else (b, a)
            payload = _shell_payload(shell) if shell[N + "event_id"] == "4688" else None
            if bounded and request[N + "event_id"] == "HTTP_ACCESS" and request[N + "source"] == "iis" and payload and _web_command(request) == payload and all(f in matches for f in ("host", "ip")) and (shell[N + "user"] or "").startswith("iis apppool\\") and 0 < (shell[N + "timestamp"] - request[N + "timestamp"]).total_seconds() <= params["web_window_seconds"]:
                strong.setdefault("web_command_process", _criterion(
                    "web_command_process", {"host": matches["host"], "ip": matches["ip"], "command": payload}, [request, shell], params["web_window_seconds"], "witness_time_gap", (shell[N + "timestamp"] - request[N + "timestamp"]).total_seconds(),
                    "Solicitud y proceso IIS posterior comparten host/IP/comando textual. Usuario HTTP desconocido no se equipara a la cuenta AppPool; falta vínculo causal solicitud/proceso."))
            if gap <= params["context_window_seconds"] and len(matches) >= 2 and ("host" in matches or "user" in matches):
                contextual.setdefault("shared_attributes", _criterion(
                    "shared_attributes", matches, [a, b], params["context_window_seconds"], "witness_time_gap", gap,
                    "Atributos explícitos parcialmente coincidentes y proximidad temporal; insuficientes para fusionar grupos o afirmar identidad causal."))
    if strong:
        kind, criteria = "fuerte", list(strong.values())
    elif contextual:
        kind, criteria = "contextual", list(contextual.values())
    elif nearest and nearest[0][0] <= params["temporal_window_seconds"]:
        _, a, b = nearest
        kind, criteria = "temporal", [_criterion(
            "time_only", _matches(a, b), [a, b], params["temporal_window_seconds"], "witness_time_gap", nearest[0][0],
            "Proximidad temporal sin atributos suficientes. No se utiliza para agrupar ni aumentar riesgo o confianza.")]
    elif overlap:
        kind, criteria = "contextual", [_criterion(
            "context_event_overlap", {"source_event_identity": True}, [r for r in left.rows if row_key(r) in overlap], None, "exact_event_identity", None,
            "Se comparten eventos que tienen rol de contexto en alguna detección; no se presume soporte independiente.")]
    else:
        return None
    payload = dict(detection_ids=sorted([left.id, right.id]), kind=kind, criteria=sorted(criteria, key=lambda c: c["criterion"]))
    return dict(link_id="V-" + _digest([VERSION, payload])[:24], **payload,
                shared_events=len(overlap), shared_primary_events=len(shared_primary),
                causal=False, combined_span_seconds=span if complete else None)


def _assemble(members, links, rowmap, params):
    member_ids = sorted(n.id for n in members)
    keys = set().union(*(node.all_keys for node in members))
    primary_keys = set().union(*(node.primary_keys for node in members))
    evidence = []
    for key in sorted(keys):
        row = rowmap[key]
        roles = defaultdict(list)
        for node in members:
            for item in node.detection["evidence"]:
                if (item["sha256"], item["sheet"], item["excel_row"]) == key:
                    roles[node.id] = sorted(set(roles[node.id]) | set(item["roles"]))
        evidence.append(dict(**proof(row), **{c: _jsonable(row[c]) for c in REQUIRED_COLUMNS if c not in ("Log_ID", "Timestamp")},
                             event_id_excel_type=row["__dojo_event_id_type"], primary=key in primary_keys,
                             detection_roles=dict(sorted(roles.items()))))
    ordered = sorted(evidence, key=lambda e: (rowmap[(e["sha256"], e["sheet"], e["excel_row"])][N + "timestamp"] or datetime.max, e["sha256"], e["sheet"], e["excel_row"]))
    return dict(
        group_id="L-" + _digest([VERSION, member_ids, [proof(rowmap[k]) for k in sorted(keys)]])[:24],
        detection_ids=member_ids, rules=sorted({n.detection["rule_id"] for n in members}),
        detection_statuses=sorted(n.detection["status"] for n in members),
        detections=[dict(finding_id=n.id, rule_id=n.detection["rule_id"], parameters=deepcopy(n.detection["parameters"]), facts=deepcopy(n.detection["facts"])) for n in sorted(members, key=lambda n: n.id)],
        evidence=evidence, timeline=ordered,
        links=[deepcopy(link) for link in links if set(link["detection_ids"]) <= set(member_ids)],
        grouping_method="Enlace completo: todas las parejas de miembros tienen vínculo fuerte directo. No se fusiona por transitividad débil.",
        grouping_window_seconds=params["group_window_seconds"],
        correlation_parameters=dict(params),
        alternatives=sorted({a for node in members for a in node.detection["alternatives"]}),
        limitations=sorted({a for node in members for a in node.detection["limitations"]} | {
            "Agrupación observacional; no identifica una misma sesión ni acredita causalidad.",
            "Contexto y coincidencia temporal se muestran sin fusionar grupos ni sumar puntuación.",
            "La clasificación no confirma compromiso, daño o incidente de seguridad.",
        }),
    )


def correlate(analysis, parameters=None, risk_model=None, reviews=None):
    params = correlation_parameters(parameters)
    model = model_parameters(risk_model)
    nodes, rowmap = _load(analysis)
    if len(nodes) > params["max_detections"]:
        raise ValueError("Se excedió max_detections. No se correlaciona parcialmente ni se truncan detecciones.")
    links = [link for a, b in combinations(nodes, 2) if (link := _pair(a, b, params)) is not None]
    strong = {frozenset(link["detection_ids"]) for link in links if link["kind"] == "fuerte"}
    clusters = []
    for node in nodes:
        target = None
        for cluster in clusters:
            if not all(frozenset([node.id, other.id]) in strong for other in cluster):
                continue
            start, end, _ = _bounds(node.rows + [r for member in cluster for r in member.rows])
            if start is None or (end - start).total_seconds() <= params["group_window_seconds"]:
                target = cluster
                break
        if target is None:
            clusters.append([node])
        else:
            target.append(node)
    groups = [_assemble(cluster, links, rowmap, params) for cluster in clusters]
    valid_ids = {group["group_id"] for group in groups}
    if reviews is not None and (not isinstance(reviews, dict) or set(reviews) - valid_ids):
        raise ValueError("La revisión refiere a una agrupación inexistente o de otra configuración.")
    owner = {ident: group["group_id"] for group in groups for ident in group["detection_ids"]}
    for link in links:
        link["group_ids"] = sorted({owner[ident] for ident in link["detection_ids"]})
        link["used_for_grouping"] = len(link["group_ids"]) == 1 and link["kind"] == "fuerte"
        if link["kind"] == "fuerte" and len(link["group_ids"]) > 1:
            link["not_merged_reason"] = "No se satisface enlace completo o duración máxima con todos los miembros. No se aplica clausura transitiva."
    for group in groups:
        group["links"] = [deepcopy(link) for link in links if link["used_for_grouping"] and set(link["detection_ids"]) <= set(group["detection_ids"])]
        group["external_links"] = [deepcopy(link) for link in links if group["group_id"] in link["group_ids"] and len(link["group_ids"]) > 1]
        keys = {(e["sha256"], e["sheet"], e["excel_row"]) for e in group["evidence"]}
        group.update(classify_group(group, [rowmap[k] for k in sorted(keys)], model, (reviews or {}).get(group["group_id"])))
    occurrences = Counter(key for node in nodes for key in node.all_keys)
    overlaps = []
    for a, b in combinations(nodes, 2):
        shared = a.all_keys & b.all_keys
        if shared:
            overlaps.append(dict(detection_ids=sorted([a.id, b.id]), group_ids=sorted({owner[a.id], owner[b.id]}),
                                 shared_events=[proof(rowmap[k]) for k in sorted(shared)],
                                 primary_shared=len(a.primary_keys & b.primary_keys),
                                 treatment="Un evento por SHA-256/hoja/fila. Factores por comportamiento, sin sumar activaciones superpuestas."))
    run = dict(correlation_version=VERSION, model_version=MODEL_VERSION,
               source_analysis_id=analysis.report["analysis_id"], input_sha256=analysis.report["input_sha256"],
               parameters=params, risk_model=model, reviews={group["group_id"]: {key: group["review"][key] for key in ("state", "reason", "evidence")} for group in groups if group["review"]})
    return dict(
        **run, correlation_id="C-" + _digest([run, [g["group_id"] for g in groups]])[:24],
        groups=groups, links=links, overlaps=overlaps,
        summary=dict(detections=len(nodes), groups=len(groups), unique_events=len(occurrences),
                     event_references=sum(occurrences.values()), duplicate_event_references=sum(n - 1 for n in occurrences.values()),
                     primary_unique_events=len(set().union(*(node.primary_keys for node in nodes))) if nodes else 0,
                     active_groups=sum(g["investigation_state"] != "Descartado" for g in groups),
                     severities=dict(Counter(g["severity"]["label"] for g in groups)),
                     confidences=dict(Counter(g["confidence"]["label"] for g in groups)),
                     states=dict(Counter(g["investigation_state"] for g in groups))),
        source_diagnostics=deepcopy(analysis.report["diagnostics"]),
        limitations=["Solo se usa evidencia de detecciones 2A; no se incorporan otros eventos de la hoja por inferencia.",
                     "Los eventos únicos globales no se obtienen sumando grupos si estos comparten evidencia.",
                     "Severidad potencial y confianza observacional; incidentes y daños no confirmados."],
        incident_confirmed=False, confirmed_impact=False,
    )
