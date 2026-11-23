"""Dashboard local: filtros de visualización, gráficos y acceso al origen."""

from collections import Counter
from datetime import timedelta
from html import escape

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dojo.dashboard import (
    CRITICALITIES, EVENT_FIELDS, DashboardFilters, category_counts, event_key,
    evidence_keys, filter_dashboard, group_label, group_references, group_table,
    original_records, timeline_counts,
)
from dojo.detection import _digest
from dojo.normalization import N, text
from dojo.query import display_records
from dojo.presentation import counted, render_coverage, style_chart, ui_narrative


BLUE = "#60a5fa"
RISK_COLORS = {"Crítico": "#f87171", "Alto": "#fb923c", "Medio": "#22d3ee", "Bajo": "#94a3b8"}
SIEM_COLORS = {"Critical": "#7c3aed", "High": "#a855f7", "Medium": "#6366f1",
               "Warning": "#60a5fa", "Informational": "#94a3b8"}


def reset_filters():
    for key in list(st.session_state):
        if key.startswith("dash_filter_"):
            del st.session_state[key]


def _filters(analysis, correlation, references):
    frame = analysis.normalized
    with st.expander("Filtros de visualización · combinables", expanded=False):
        st.caption("AND entre campos y OR dentro de una selección. Vacío = todos. Valores originales exactos; no se fusionan alias. Los límites temporales son inclusivos y sin zona atribuida.")
        times = frame[N + "timestamp"].dropna()
        start = end = None
        if len(times) and times.min() != times.max():
            start, end = st.slider("Intervalo temporal", min_value=times.min(), max_value=times.max(),
                                   value=(times.min(), times.max()), format="YYYY-MM-DD HH:mm:ss",
                                   step=timedelta(seconds=1), key="dash_filter_time")
        elif len(times):
            st.caption(f"Única fecha interpretable: {times.iloc[0]}")
        unknown = st.checkbox("Incluir registros sin fecha interpretable", value=True,
                              key="dash_filter_unknown", disabled=not frame[N + "timestamp"].isna().any())
        selections = {}
        columns = st.columns(3)
        labels = {"users": "Usuario", "hosts": "Host", "ips": "IP de origen",
                  "sources": "Fuente de log", "severities": "Severidad original del SIEM"}
        for i, (name, column) in enumerate(EVENT_FIELDS.items()):
            options = sorted(frame[column].dropna().unique(), key=str)
            with columns[i % 3]:
                selections[name] = tuple(st.multiselect(labels[name], options, key="dash_filter_" + name))
        with columns[2]:
            selections["criticalities"] = tuple(st.multiselect("Criticidad calculada de la línea", CRITICALITIES,
                                                               key="dash_filter_criticalities"))
        left, right = st.columns(2)
        with left:
            selections["rules"] = tuple(st.multiselect("Regla activada", sorted({f["rule_id"] for f in analysis.report["findings"]}),
                                                       key="dash_filter_rules"))
        with right:
            lookup = {g["group_id"]: g for g in correlation["groups"]}
            selections["groups"] = tuple(st.multiselect("Línea de investigación (vista)", list(lookup),
                format_func=lambda ident: group_label(lookup[ident], references), key="dash_filter_groups"))
        st.button("Restablecer filtros", key="dash_reset", on_click=reset_filters)
        st.caption("Criticidad/línea restringen a sus eventos asociados; regla, a evidencia de esas activaciones. Una detección o línea cuenta si tiene evidencia visible. Puntuaciones, confianza y estados corresponden a la línea completa, incluso ante evidencia parcial.")
    return DashboardFilters(start=start, end=end, include_unknown_time=unknown, **selections)


def _drill(imported, keys, title):
    with st.expander(f"Registros originales de la selección · {title}", expanded=True):
        original = original_records(imported, keys)
        st.caption(f"{counted(len(original), 'evento único', 'eventos únicos')}. Selección del gráfico; no modifica los filtros ni el análisis.")
        st.dataframe(display_records(original), hide_index=True, width="stretch", height=260)


def _bar(title, counts, chart_key, imported, keys_for_value, colors=None):
    st.markdown(f"**{title}**")
    if counts.empty:
        st.info("Sin datos en esta vista.")
        return
    values = counts["Valor"].tolist()
    fig = go.Figure(go.Bar(x=counts["Cantidad"].tolist(), y=[escape(str(v)) for v in values],
                          customdata=[[v] for v in counts["Clave"]], orientation="h",
                          marker_color=[(colors or {}).get(v, BLUE) for v in values],
                          text=counts["Cantidad"].tolist(), textposition="outside", cliponaxis=False,
                          hovertemplate="%{y}: %{x}<extra></extra>"))
    fig.update_layout(height=max(240, min(520, 95 + len(values) * 28)),
                      margin=dict(l=5, r=45, t=10, b=20), showlegend=False,
                      xaxis_title="Cantidad", yaxis=dict(autorange="reversed"),
                      clickmode="event+select")
    fig.update_xaxes(rangemode="tozero", dtick=1 if counts["Cantidad"].max() < 10 else None)
    event = st.plotly_chart(style_chart(fig), width="stretch", theme="streamlit", key=chart_key, on_select="rerun",
                            selection_mode="points", config={"displaylogo": False},
                            alt=title + ". Seleccioná una barra para consultar sus registros originales.")
    points = event.selection.points
    if points:
        # Usar la clave original, no etiquetas HTML ni el índice de una vista anterior.
        selected = {p["customdata"][0] for p in points if p.get("customdata")}
        _drill(imported, set().union(*(keys_for_value(v) for v in selected)), title)


def _category_chart(title, frame, column, key, imported, colors=None):
    records = frame.to_dict("records")
    _bar(title, category_counts(frame, column), key, imported,
         lambda value: {event_key(r) for r in records if text(r[column]) == value}, colors)


def _evidence_browser(imported, view, references):
    st.markdown("**Explorador de registros originales**")
    lookup = {g["group_id"]: g for g in view.groups}
    chosen = st.selectbox("Acotar evidencias a una línea", [""] + list(lookup), key="dash_evidence_group",
                          format_func=lambda v: group_label(lookup[v], references) if v else "Todos los registros de la vista")
    keys = {event_key(r) for r in view.records.to_dict("records")}
    if chosen:
        keys &= evidence_keys(lookup[chosen])
        group = lookup[chosen]
        st.caption(f"{references[chosen]} · {chosen} · Criticidad {group['severity']['label']} · Confianza {group['confidence']['label']} · {group['investigation_state']}")
        st.write(ui_narrative(group["description"]))
    original = original_records(imported, keys)
    st.caption(f"{len(original)} registros de origen; archivo, SHA-256, hoja, fila Excel y Log_ID conservados. Seleccioná una fila para abrir su contenido completo.")
    order = ["Log_ID", "Timestamp", "Hostname", "User", "Source_IP", "Log_Source", "Event_ID", "Severity",
             "__dojo_row", "__dojo_file", "__dojo_sheet", "__dojo_sha256"]
    event = st.dataframe(display_records(original), hide_index=True, width="stretch", height=360,
                         column_order=order + [c for c in original.columns if c not in order],
                         key="dash_records_" + _digest(sorted(keys))[:12], on_select="rerun",
                         selection_mode="single-row")
    if event.selection.rows:
        row = original.iloc[event.selection.rows[0]]
        st.markdown(f"**Fila Excel {int(row['__dojo_row'])} · registro original**")
        st.dataframe(display_records(row.to_frame().T), hide_index=True, width="stretch", key="dash_original")
        st.code(f"Archivo: {row['__dojo_file']}\nSHA-256: {row['__dojo_sha256']}\nHoja: {row['__dojo_sheet']}\nFila Excel: {row['__dojo_row']}\nLog_ID: {row['Log_ID']}", language=None)


def render_dashboard(imported, analysis, correlation):
    st.subheader("Dashboard de investigación")
    st.caption("Vista del resultado vigente · eventos, detecciones y líneas son unidades distintas. Ninguna línea representa un incidente confirmado.")
    if st.session_state.get("dashboard_generation") != correlation["correlation_id"]:
        reset_filters()
        st.session_state.pop("dash_evidence_group", None)
        st.session_state["dashboard_generation"] = correlation["correlation_id"]
    references = group_references(correlation["groups"])
    filters = _filters(analysis, correlation, references)
    view = filter_dashboard(analysis, correlation, filters)
    complete = filter_dashboard(analysis, correlation)
    total, metrics = complete.metrics, view.metrics
    st.caption(f"Análisis completo: {counted(total['records'], 'registro', 'registros')} · "
               f"{counted(total['sources'], 'fuente', 'fuentes')} · {counted(total['detections'], 'detección', 'detecciones')} · "
               f"{counted(total['groups'], 'línea', 'líneas')} · {counted(total['unique_events'], 'evento único asociado', 'eventos únicos asociados')}. "
               "Los filtros no recalculan reglas ni clasificación.")
    for col, label, name in zip(st.columns(5),
            ["Registros en vista", "Fuentes en vista", "Detecciones con evidencia", "Líneas con evidencia", "Eventos únicos asociados"],
            ["records", "sources", "detections", "groups", "unique_events"]):
        col.metric(label, metrics[name], border=True, help=f"De {total[name]} en el resultado completo.")
    for col, label in zip(st.columns(4), CRITICALITIES):
        col.metric(f"Líneas · {label}", metrics["criticalities"][label], border=True)
    st.caption("Criticidad calculada de líneas completas, separada de Severity original y confianza observacional. Los eventos de contexto también pueden estar asociados; no se presumen maliciosos. Se incluyen líneas Descartado si existen.")
    if not len(view.records):
        st.info("Ningún registro coincide con los filtros. El análisis completo se conserva; esto no demuestra ausencia de actividad.")
    token = _digest(filters.__dict__)[:12]
    overview, activity, evidence = st.tabs(["Panorama", "Actividad y actores", "Evidencias"])
    records = view.records
    with overview:
        st.caption("Seleccioná barras para abrir los registros que las componen. Los gráficos cuentan el subconjunto visible una sola vez por procedencia.")
        left, right = st.columns(2)
        with left:
            _category_chart("Severidad original del SIEM · eventos", records, "Severity", "dash_siem_" + token, imported, SIEM_COLORS)
        with right:
            counts = pd.DataFrame([dict(Valor=c, Cantidad=metrics["criticalities"][c], Clave=c) for c in CRITICALITIES])
            visible_keys = {event_key(r) for r in records.to_dict("records")}
            _bar("Criticidad calculada · líneas de investigación", counts, "dash_risk_" + token, imported,
                 lambda label: visible_keys & set().union(*(evidence_keys(g) for g in view.groups if g["severity"]["label"] == label)), RISK_COLORS)
        st.markdown("**Líneas de investigación · resumen**")
        st.caption("Referencias L01… locales al resultado completo; el ID técnico estable se conserva. Eventos visibles / totales permiten reconocer evidencia parcial. Abrí una línea en Evidencias o revisá su justificación en Correlación.")
        lines = st.dataframe(group_table(view, references), hide_index=True, width="stretch",
                             key="dash_lines_" + token, on_select="rerun", selection_mode="single-row")
        if lines.selection.rows:
            chosen = view.groups[lines.selection.rows[0]]
            _drill(imported, evidence_keys(chosen) & visible_keys, group_label(chosen, references))
        counts = Counter(f["rule_id"] for f in view.findings)
        rule_counts = pd.DataFrame([dict(Valor=k, Cantidad=v, Clave=k) for k, v in sorted(counts.items())],
                                    columns=["Valor", "Cantidad", "Clave"])
        _bar("Activaciones por regla · detecciones con evidencia visible", rule_counts, "dash_rules_" + token,
             imported, lambda rule: visible_keys & set().union(*(evidence_keys(f) for f in view.findings if f["rule_id"] == rule)))
    with activity:
        minutes = st.selectbox("Agrupación temporal (minutos)", [5, 1, 15, 60], key="dash_interval")
        counts = timeline_counts(records, minutes)
        st.markdown("**Evolución temporal · eventos por intervalo**")
        if len(counts):
            fig = go.Figure(go.Bar(x=counts["Intervalo"].tolist(), y=counts["Eventos"].tolist(),
                                  marker_color=BLUE, customdata=[[v.isoformat()] for v in counts["Intervalo"]],
                                  hovertext=[counted(n, 'evento', 'eventos') for n in counts["Eventos"]],
                                  hovertemplate="%{x|%Y-%m-%d %H:%M:%S}<br>%{hovertext}<extra></extra>"))
            fig.update_layout(height=290, margin=dict(l=5, r=10, t=10, b=20), xaxis_title="Inicio del intervalo · zona no especificada",
                              yaxis_title="Eventos", clickmode="event+select")
            selected = st.plotly_chart(style_chart(fig), width="stretch", theme="streamlit", key="dash_time_" + token + str(minutes),
                                       on_select="rerun", selection_mode="points", config={"displaylogo": False})
            if selected.selection.points:
                bins = {p["customdata"][0] for p in selected.selection.points if p.get("customdata")}
                keys = {event_key(r) for r in records.to_dict("records") if r[N + "timestamp"] is not None
                        and pd.Timestamp(r[N + "timestamp"]).floor(f"{minutes}min").isoformat() in bins}
                _drill(imported, keys, "intervalos temporales")
        else:
            st.info("Sin fechas interpretables en la vista.")
        st.caption(f"{metrics['unknown_time']} registros visibles sin fecha interpretable se excluyen únicamente del gráfico temporal. Los intervalos sin registros no acreditan ausencia de actividad.")
        left, right = st.columns(2)
        with left:
            _category_chart("Fuentes de logs · eventos", records, "Log_Source", "dash_source_" + token, imported)
        with right:
            _category_chart("Event_ID · eventos", records, N + "event_id", "dash_event_" + token, imported)
        actor = st.radio("Actividad por", ["Usuario", "Host", "IP"], horizontal=True, key="dash_actor")
        column = {"Usuario": "User", "Host": "Hostname", "IP": "Source_IP"}[actor]
        _category_chart(f"Actividad por {actor.lower()} · eventos", records, column, "dash_actor_chart_" + token + column, imported)
        st.caption("Todas las categorías visibles, sin top-N. El marcador '-' permanece como valor original no identificado. IP descriptivas: no se geolocalizan ni se atribuyen a atacantes.")
    with evidence:
        _evidence_browser(imported, view, references)
    with st.expander("Cobertura, límites y trazabilidad del resultado"):
        st.write("La vista usa toda la hoja analizada. La evidencia asociada es el subconjunto seleccionado por 2A/2B, no toda la actividad existente. Los filtros no modifican hechos, riesgo potencial, confianza o revisiones. Corroborado se refiere a actividad/coincidencia; no confirma compromiso, causalidad ni daños.")
        render_coverage(analysis.report["diagnostics"])
        st.caption(f"Observaciones de importación: {len(analysis.report['import_issues'])} · normalización: {len(analysis.report['normalization_issues'])}.")
        for limit in correlation["limitations"]:
            st.write("• " + limit)
        st.code(f"Archivo: {imported.filename}\nSHA-256: {imported.digest}\nHoja: {imported.sheet}\nAnálisis: {analysis.report['analysis_id']}\nCorrelación: {correlation['correlation_id']}", language=None)
        st.caption("Las referencias cortas se conservan al filtrar; pueden cambiar al generar un resultado nuevo. Los IDs técnicos permanecen disponibles. Cambiar resultado o revisión restablece los filtros del dashboard.")
