"""Vistas derivadas de resultados cerrados. No ejecuta reglas ni clasifica."""

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

import pandas as pd

from dojo.normalization import N, text


CRITICALITIES = ("Crítico", "Alto", "Medio", "Bajo")
EVENT_FIELDS = {
    "users": "User", "hosts": "Hostname", "ips": "Source_IP",
    "sources": "Log_Source", "severities": "Severity",
}


def event_key(record):
    """Log_ID no necesariamente es único; la identidad es la procedencia."""
    if "__dojo_row" in record:
        return record["__dojo_sha256"], record["__dojo_sheet"], record["__dojo_row"]
    return record["sha256"], record["sheet"], record["excel_row"]


def evidence_keys(item):
    return {event_key(e) for e in item["evidence"]}


@dataclass(frozen=True)
class DashboardFilters:
    start: datetime | None = None
    end: datetime | None = None
    include_unknown_time: bool = True
    users: tuple = ()
    hosts: tuple = ()
    ips: tuple = ()
    sources: tuple = ()
    severities: tuple = ()
    criticalities: tuple = ()
    rules: tuple = ()
    groups: tuple = ()


@dataclass
class DashboardView:
    records: pd.DataFrame
    findings: list
    groups: list
    associated_keys: set
    metrics: dict = field(default_factory=dict)


def filter_dashboard(analysis, correlation, filters=None):
    """AND entre campos, OR dentro de cada selección; ventanas inclusivas.

    Sin filtros relacionales se consultan todos los eventos, incluidos los que
    no tienen detección. Criticidad/línea acotan a su unión de evidencia; regla
    acota a evidencia de esas activaciones. Luego se intersectan filtros de evento.
    Una detección/línea es visible si conserva al menos una referencia visible.
    La clasificación pertenece siempre a la línea completa, nunca al subconjunto.
    """
    filters = filters or DashboardFilters()
    if (correlation["source_analysis_id"] != analysis.report["analysis_id"]
            or correlation["input_sha256"] != analysis.report["input_sha256"]):
        raise ValueError("El dashboard requiere correlación y análisis de la misma entrada vigente.")
    if filters.start and filters.end and filters.start > filters.end:
        raise ValueError("El inicio del intervalo no puede superar el fin.")
    for bound in (filters.start, filters.end):
        if bound is not None and bound.tzinfo is not None:
            raise ValueError("No se atribuye zona horaria al filtro temporal.")
    frame = analysis.normalized
    mask = pd.Series(True, index=frame.index)
    for name, column in EVENT_FIELDS.items():
        values = getattr(filters, name)
        if values:
            mask &= frame[column].isin(values)
    times = frame[N + "timestamp"]
    known = times.notna()
    time_mask = known.copy()
    if filters.start:
        time_mask &= times.map(lambda t: t is not None and t >= filters.start)
    if filters.end:
        time_mask &= times.map(lambda t: t is not None and t <= filters.end)
    if filters.include_unknown_time:
        time_mask |= ~known
    mask &= time_mask

    groups = [g for g in correlation["groups"]
              if (not filters.groups or g["group_id"] in filters.groups)
              and (not filters.criticalities or g["severity"]["label"] in filters.criticalities)]
    group_scope = set().union(*(evidence_keys(g) for g in groups))
    allowed_detections = {d for g in groups for d in g["detection_ids"]}
    findings = [f for f in analysis.report["findings"]
                if (not filters.rules or f["rule_id"] in filters.rules)
                and (not (filters.groups or filters.criticalities)
                     or f["finding_id"] in allowed_detections)]
    record_keys = frame.apply(event_key, axis=1) if len(frame) else pd.Series([], dtype=object)
    if filters.groups or filters.criticalities:
        mask &= record_keys.isin(group_scope)
    if filters.rules:
        rule_scope = set().union(*(evidence_keys(f) for f in findings))
        mask &= record_keys.isin(rule_scope)
    records = frame.loc[mask].copy(deep=True)
    visible_keys = set(record_keys.loc[mask])
    findings = [f for f in findings if evidence_keys(f) & visible_keys]
    visible_detections = {f["finding_id"] for f in findings}
    groups = [g for g in groups if evidence_keys(g) & visible_keys
              and (not filters.rules or visible_detections.intersection(g["detection_ids"]))]
    associated = visible_keys & set().union(*(evidence_keys(g) for g in groups))
    criticalities = Counter(g["severity"]["label"] for g in groups)
    metrics = dict(records=len(records), sources=records["Log_Source"].dropna().nunique(),
                   detections=len(findings), groups=len(groups), unique_events=len(associated),
                   criticalities={label: criticalities[label] for label in CRITICALITIES},
                   unknown_time=int(records[N + "timestamp"].isna().sum()))
    # Los diccionarios analíticos no se editan; la vista conserva referencias de lectura.
    return DashboardView(records, findings, groups, associated, metrics)


def group_references(groups):
    """Referencia de presentación local al resultado completo; ID técnico intacto."""
    return {g["group_id"]: f"L{i:02d}" for i, g in enumerate(groups, 1)}


def group_label(group, references):
    return f"{references[group['group_id']]} · {group['title']}"


def group_table(view, references):
    visible = {event_key(r) for r in view.records.to_dict("records")}
    return pd.DataFrame([{
        "Línea": references[g["group_id"]], "Investigación": g["title"],
        "Criticidad calculada": g["severity"]["label"],
        "Puntos": g["severity"]["score"], "Confianza": g["confidence"]["label"],
        "Estado": g["investigation_state"], "Reglas": ", ".join(g["rules"]),
        "Eventos visibles": len(evidence_keys(g) & visible), "Eventos de la línea": len(evidence_keys(g)),
        "ID técnico": g["group_id"],
    } for g in view.groups], columns=["Línea", "Investigación", "Criticidad calculada", "Puntos",
                                    "Confianza", "Estado", "Reglas", "Eventos visibles",
                                    "Eventos de la línea", "ID técnico"])


def category_counts(frame, column):
    """Sin top-N oculto. None se muestra sin sustituir la celda original."""
    counts = Counter(text(v) for v in frame[column])
    return pd.DataFrame([{"Valor": value if value is not None else "(Sin dato)", "Cantidad": count,
                          "Clave": value} for value, count in
                         sorted(counts.items(), key=lambda item: (-item[1], str(item[0])))],
                        columns=["Valor", "Cantidad", "Clave"])


def timeline_counts(frame, minutes=5):
    if minutes not in (1, 5, 15, 60):
        raise ValueError("Agrupación temporal no admitida.")
    # Sin localización ni conversión UTC. Solo fechas ya normalizadas por 2A.
    times = pd.to_datetime(frame[N + "timestamp"].dropna())
    counts = times.dt.floor(f"{minutes}min").value_counts().sort_index()
    return pd.DataFrame({"Intervalo": counts.index, "Eventos": counts.values})


def original_records(imported, keys):
    """Devuelve las columnas originales y su procedencia, no reconstrucciones."""
    frame = imported.records
    if frame.empty:
        return frame.copy()
    return frame.loc[frame.apply(event_key, axis=1).isin(keys)].copy(deep=True)
