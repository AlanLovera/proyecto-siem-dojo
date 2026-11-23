"""Consulta de líneas de investigación y clasificación; estado solo en sesión."""

from copy import deepcopy
import json

import pandas as pd
import streamlit as st

from dojo.correlation import VERSION, correlate, correlation_parameters
from dojo.detection import _digest
from dojo.query import display_records
from dojo.risk import DEFAULT_MODEL, model_parameters
from dojo.dashboard import group_label, group_references
from dojo.presentation import counted, facts_table, link_summary, render_coverage, ui_narrative


def clear_correlation():
    for key in ("correlation_result", "correlation_key", "correlation_group", "correlation_row", "correlation_reviews"):
        st.session_state.pop(key, None)


def render_correlation(imported, analysis):
    st.subheader("Líneas de investigación y clasificación")
    st.caption("Asocia las detecciones vigentes. Corroborado respalda una actividad/coincidencia observada; no confirma un incidente ni daños.")
    with st.expander("Parámetros de correlación y clasificación", expanded=False):
        params = correlation_parameters()
        for name, value in params.items():
            params[name] = st.number_input(f"2B · {name}", min_value=1,
                                          max_value=1000 if name == "max_detections" else 604800,
                                          value=value, step=1, key="corr_" + name)
        st.caption("Modelo editable en JSON: pesos, umbrales de severidad/confianza y condiciones. Un peso se aplica una vez por comportamiento, con supresión de solapamientos.")
        raw_model = st.text_area("Modelo de clasificación (JSON)", json.dumps(DEFAULT_MODEL, ensure_ascii=False, indent=2),
                                 height=240, key="risk_model_json")
    try:
        params = correlation_parameters(params)
        model = model_parameters(json.loads(raw_model))
    except (ValueError, TypeError) as exc:
        st.error(f"Configuración 2B inválida: {exc}")
        return
    signature = _digest([VERSION, analysis.report["analysis_id"], params, model])
    if st.button("Correlacionar y clasificar", key="run_correlation"):
        clear_correlation()
        try:
            st.session_state["correlation_result"] = correlate(analysis, params, model)
            st.session_state["correlation_key"] = signature
            st.session_state["correlation_reviews"] = {}
        except ValueError as exc:
            st.error(f"Correlación detenida: {exc}")
            return
    if st.session_state.get("correlation_key") != signature:
        st.info("Cambió la configuración 2B; recalculá para consultar resultados vigentes." if "correlation_result" in st.session_state else "Pulsá Correlacionar y clasificar para generar las líneas de investigación.")
        return
    report = st.session_state["correlation_result"]
    summary = report["summary"]
    st.success(f"{counted(summary['detections'], 'detección', 'detecciones')} → "
               f"{counted(summary['groups'], 'línea', 'líneas')}; "
               f"{counted(summary['unique_events'], 'evento único', 'eventos únicos')}. "
               f"{counted(summary['duplicate_event_references'], 'referencia repetida', 'referencias repetidas')} sin doble contabilización.")
    st.text(f"Correlación: {report['correlation_id']} | Versión: {report['correlation_version']}")
    st.warning("La severidad es potencial y la confianza se refiere al soporte de la asociación. Compromiso, intención maliciosa y daños no están confirmados.")
    with st.expander("Solapamientos y cobertura de origen", expanded=False):
        facts_table("Recuentos del resultado completo", summary)
        render_coverage(report["source_diagnostics"])
        with st.expander("Detalle técnico de solapamientos", expanded=False):
            st.json(report["overlaps"], expanded=False)
    if not report["groups"]:
        st.info("No hay detecciones de origen para agrupar. No demuestra ausencia de actividad sospechosa.")
        return report
    short_refs = group_references(report["groups"])
    st.dataframe(pd.DataFrame([
        dict(línea=short_refs[g["group_id"]], ID=g["group_id"], título=g["title"], reglas=", ".join(g["rules"]),
             eventos=len(g["evidence"]), severidad=g["severity"]["label"], puntos=g["severity"]["score"],
             confianza=g["confidence"]["label"], estado=g["investigation_state"])
        for g in report["groups"]
    ]), hide_index=True, width="stretch")
    lookup = {g["group_id"]: g for g in report["groups"]}
    selected = st.selectbox("Línea de investigación", list(lookup), key="correlation_group",
                            format_func=lambda ident: f"{group_label(lookup[ident], short_refs)} · {lookup[ident]['severity']['label']}")
    group = lookup[selected]
    st.write(ui_narrative(group["description"]))
    st.caption(f"ID técnico estable: {selected}")
    st.caption("Limitaciones: " + " ".join(group["limitations"]))
    st.caption("Información pendiente: " + " ".join(group["missing_information"]))
    facts_table("Hechos observados", group["facts"])
    with st.expander("Hipótesis, corroboraciones y límites"):
        facts_table("Hipótesis pendientes", group["hypotheses"])
        facts_table("Corroboraciones de actividad/coincidencia", group["corroborations"] or ["Evidencia insuficiente para corroboración adicional a los hechos registrados."])
        for title, key in [("Alternativas", "alternatives"), ("Acciones iniciales", "recommended_actions")]:
            facts_table(title, group[key])
    st.write("Estado de investigación: " + group["investigation_state"])
    if group["review"]:
        facts_table("Revisión explícita del analista", group["review"])
    with st.expander("Justificación de criticidad y confianza", expanded=False):
        facts_table("Criticidad calculada", {key: value for key, value in group["severity"].items() if key != "factors"})
        st.dataframe(display_records(pd.DataFrame(group["severity"]["factors"])), hide_index=True, width="stretch")
        facts_table("Confianza observacional", {key: value for key, value in group["confidence"].items() if key != "factors"})
        st.dataframe(display_records(pd.DataFrame(group["confidence"]["factors"])), hide_index=True, width="stretch")
    with st.expander("Vínculos directos y asociaciones externas", expanded=False):
        st.write(link_summary(group))
        for label, links in (("Directas", group["links"]), ("Externas", group["external_links"])):
            if links:
                st.dataframe(pd.DataFrame([{"Relación": label, "ID": link["link_id"],
                                            "Tipo": link["kind"], "Criterios": len(link["criteria"]),
                                            "Acredita causalidad": link["causal"]} for link in links]),
                             hide_index=True, width="stretch")
        with st.expander("JSON original de vínculos", expanded=False):
            st.json({"grouping_method": group["grouping_method"], "links": group["links"], "external_links": group["external_links"]}, expanded=False)
    with st.expander("Datos técnicos completos de la línea", expanded=False):
        st.json(group, expanded=False)
    st.write("Línea temporal con timestamps originales; fechas desconocidas al final, sin atribuir orden causal a empates.")
    st.dataframe(display_records(pd.DataFrame(group["timeline"])), hide_index=True, width="stretch", key="correlation_timeline")
    choices = [(e["sha256"], e["sheet"], e["excel_row"]) for e in group["evidence"]]
    with st.expander("Revisión del estado (solo en esta sesión)"):
        st.caption("Descartar requiere una decisión explícita y referencias del analista. No altera hechos, puntuación potencial ni evidencia. Sin revisión recupera el estado automático.")
        disposition = st.selectbox("Decisión", ["Sin revisión", "En investigación", "Descartado"], key="review_state_" + selected)
        reason = st.text_area("Justificación del analista", key="review_reason_" + selected)
        references = st.multiselect("Evidencia para la revisión", choices, key="review_evidence_" + selected,
                                    format_func=lambda key: f"{key[1]} · fila {key[2]}")
        if st.button("Aplicar revisión", key="apply_review"):
            reviews = deepcopy(st.session_state["correlation_reviews"])
            if disposition == "Sin revisión":
                reviews.pop(selected, None)
            else:
                reviews[selected] = dict(state=disposition, reason=reason,
                                         evidence=[dict(sha256=key[0], sheet=key[1], excel_row=key[2]) for key in references])
            try:
                updated = correlate(analysis, params, model, reviews)
                st.session_state["correlation_result"] = updated
                st.session_state["correlation_reviews"] = reviews
                st.rerun()
            except ValueError as exc:
                st.error(f"No se aplicó la revisión: {exc}")
    key = st.selectbox("Abrir evidencia original de la línea", choices, key="correlation_row",
                       format_func=lambda value: f"{value[1]} · fila {value[2]}")
    frame = imported.records
    original = frame[frame["__dojo_sha256"].eq(key[0]) & frame["__dojo_sheet"].eq(key[1]) & frame["__dojo_row"].eq(key[2])]
    st.dataframe(display_records(original), hide_index=True, width="stretch", key="correlation_original")
    return report
