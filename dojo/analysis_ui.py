"""Controles y revisión del motor 2A, separados de la carga ya validada."""

from collections import Counter
from hashlib import sha256
import json

import pandas as pd
import streamlit as st

from dojo.detection import ENGINE_VERSION, analyze
from dojo.normalization import N
from dojo.query import display_records
from dojo.rules import RULES, parameter_max, parameters
from dojo.correlation_ui import clear_correlation
from dojo.presentation import counted, facts_table, render_coverage, ui_narrative


def clear_analysis():
    clear_correlation()
    for key in ("analysis_result", "analysis_key", "finding", "evidence_row"):
        st.session_state.pop(key, None)


def render_analysis(imported):
    st.subheader("Análisis de actividad sospechosa")
    st.caption("Se evalúa la hoja completa, independientemente de los filtros de consulta. Una activación no confirma un incidente.")
    enabled = st.multiselect("Reglas habilitadas", list(RULES), default=list(RULES), key="enabled_rules")
    config = parameters()
    with st.expander("Reglas, condiciones, parámetros y limitaciones", expanded=False):
        for rule, info in RULES.items():
            st.write(f"{rule} · {info['name']}")
            st.caption(info["conditions"])
            for key, default in config[rule].items():
                widget_key = f"param_{rule}_{key}"
                if isinstance(default, list):
                    config[rule][key] = st.multiselect(f"{rule} · {key}", default, default=default, key=widget_key)
                else:
                    config[rule][key] = st.number_input(
                        f"{rule} · {key}", min_value=2 if key == "min_users" else 1,
                        max_value=parameter_max(key), value=default, step=1, key=widget_key,
                    )
            st.write("Limitaciones: " + " ".join(info["limitations"]))
            st.write("Alternativas: " + " ".join(info["alternatives"]))
    try:
        config = parameters(config)
    except ValueError as exc:
        st.error(f"Configuración inválida: {exc}")
        return
    signature = sha256(json.dumps(
        [imported.digest, imported.filename, imported.sheet, ENGINE_VERSION, sorted(enabled), config],
        sort_keys=True,
    ).encode()).hexdigest()
    if st.button("Analizar registros", key="run_analysis", disabled=not enabled):
        try:
            clear_analysis()
            st.session_state["analysis_result"] = analyze(imported, config, enabled)
            st.session_state["analysis_key"] = signature
        except ValueError as exc:
            st.error(f"Análisis detenido: {exc}")
            return
    if st.session_state.get("analysis_key") != signature:
        if "analysis_result" in st.session_state:
            st.info("Cambió la configuración. Ejecutá nuevamente el análisis para consultar resultados vigentes.")
        else:
            st.info("Configurá las reglas y pulsá Analizar registros. Estado: pendiente de análisis.")
        return
    analysis = st.session_state["analysis_result"]
    report = analysis.report
    findings = report["findings"]
    indicators = sum(f["status"] == "Indicador" for f in findings)
    st.success(f"Análisis finalizado: {counted(len(findings), 'activación', 'activaciones')}, "
               f"{counted(indicators, 'indicador', 'indicadores')} y "
               f"{counted(len(findings) - indicators, 'hallazgo sospechoso', 'hallazgos sospechosos')}. Confirmación de incidentes: no evaluada.")
    st.text(f"Motor: {report['engine_version']} | Análisis: {report['analysis_id']}")
    incomplete = sum(d["skipped_incomplete"] for d in report["diagnostics"])
    if incomplete:
        st.warning(f"Cobertura parcial: {incomplete} exclusiones por datos incompletos, sumadas por regla; un evento puede participar en varias reglas. Revisá el detalle de cobertura.")
    if report["normalization_issues"]:
        st.warning(f"{len(report['normalization_issues'])} observaciones de normalización. Revisá las exclusiones por regla.")
    with st.expander("Cobertura, datos incompletos y representaciones normalizadas", expanded=False):
        render_coverage(report["diagnostics"])
        if report["normalization_issues"]:
            st.dataframe(display_records(pd.DataFrame(report["normalization_issues"])), hide_index=True, width="stretch")
        else:
            st.caption("Sin errores de normalización de fechas, IP o Event_ID; la cobertura por regla puede ser parcial por campos no disponibles.")
        columns = ["Log_ID", "Timestamp", "User", "Hostname", "Source_IP", "Event_ID", "Result",
                   "__dojo_file", "__dojo_sha256", "__dojo_sheet", "__dojo_row"]
        columns += [column for column in analysis.normalized.columns if column.startswith(N)]
        st.dataframe(display_records(analysis.normalized[columns]), hide_index=True, width="stretch")
    facts_table("Activaciones por regla", dict(Counter(f["rule_id"] for f in findings)))
    if not findings:
        st.info("Ninguna regla se activó con estos parámetros. Esto no acredita ausencia de actividad sospechosa; revisá la cobertura.")
        return analysis
    st.dataframe(pd.DataFrame([
        dict(ID=f["finding_id"], regla=f["rule_id"], estado=f["status"],
             eventos=len(f["evidence"]), descripción=f["title"]) for f in findings
    ]), hide_index=True, width="stretch")
    lookup = {finding["finding_id"]: finding for finding in findings}
    selected = st.selectbox("Hallazgo / indicador", list(lookup), key="finding",
                            format_func=lambda value: f"{lookup[value]['rule_id']} · {lookup[value]['title']} · {value}")
    finding = lookup[selected]
    facts_table("Hechos observados", finding["facts"])
    st.write("Motivo de activación: " + ui_narrative(finding["reason"]))
    st.write("Limitaciones: " + " ".join(finding["limitations"]))
    st.write("Explicaciones alternativas: " + " ".join(finding["alternatives"]))
    with st.expander("Detalles técnicos de la activación", expanded=False):
        st.json({"regla": finding["rule_id"], "parámetros": finding["parameters"],
                 "condiciones": finding["conditions"], "incident_confirmed": False}, expanded=False)
    st.caption("Evidencia exacta. Las filas con rol de contexto no se consideran por sí mismas sospechosas.")
    st.dataframe(display_records(pd.DataFrame(finding["evidence"])), hide_index=True, width="stretch")
    rows = [e["excel_row"] for e in finding["evidence"]]
    excel_row = st.selectbox("Abrir registro original (fila Excel)", rows, key="evidence_row")
    original = imported.records[imported.records["__dojo_row"].eq(excel_row)]
    st.dataframe(display_records(original), hide_index=True, width="stretch", key="analysis_original")
    return analysis
