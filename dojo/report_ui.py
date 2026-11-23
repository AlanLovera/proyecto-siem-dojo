"""Generación explícita y descargas en memoria de la sesión, sin caché compartida."""

import streamlit as st

from dojo.report_model import ReportInputError, argentina_date, build_report_model, counted, report_signature
from dojo.report_pdf import KINDS, ReportPDFError, generate_pdf


def clear_reports():
    for key in ("pdf_signature", "pdf_documents", "pdf_model"):
        st.session_state.pop(key, None)


def render_reports(imported, analysis, correlation, case_name):
    st.subheader("Informes PDF / caso ficticio")
    st.caption("Corporativo, técnico y consolidado desde el mismo resultado completo. No se aplican los filtros del dashboard ni se recalculan detecciones, riesgo o confianza. Los archivos permanecen en esta sesión hasta descargarlos.")
    if analysis is None or correlation is None:
        clear_reports()
        st.info("Los informes requieren análisis y correlación vigentes. Ejecutá los pasos pendientes antes de exportar.")
        return
    issued_date = st.date_input("Fecha de emisión del informe (Argentina)", value=argentina_date(), key="pdf_issued_date")
    st.caption("La fecha de emisión es metadato del documento. Los timestamps originales de los logs siguen sin zona horaria especificada.")
    signature = report_signature(imported, analysis, correlation, case_name, issued_date)
    if st.session_state.get("pdf_signature") != signature:
        clear_reports()
    if st.button("Generar los tres PDF", key="generate_reports", type="primary"):
        clear_reports()
        try:
            with st.spinner("Cotejando evidencia y generando informes locales..."):
                model = build_report_model(imported, analysis, correlation, case_name, issued_date)
                documents = {kind: generate_pdf(model, kind) for kind in KINDS}
            st.session_state["pdf_model"] = model
            st.session_state["pdf_documents"] = documents
            st.session_state["pdf_signature"] = signature
        except (ReportInputError, ReportPDFError, OSError) as exc:
            st.error(f"No se generaron los informes: {exc}")
    if "pdf_documents" not in st.session_state:
        st.info("Pulsá Generar los tres PDF para crear el snapshot y habilitar las descargas.")
        return
    model = st.session_state["pdf_model"]
    st.success(f"Tres PDF disponibles / {model['report_id']} / {counted(model['summary']['groups'], 'línea', 'líneas')} y {counted(model['summary']['unique_events'], 'evento asociado único', 'eventos asociados únicos')}.")
    st.caption("Caso ficticio. Corroborado no significa compromiso confirmado. Generados con la configuración y revisiones vigentes; un cambio de fuente, parámetros, revisión, nombre o fecha invalida las descargas anteriores.")
    for column, (kind, label) in zip(st.columns(3), KINDS.items()):
        with column:
            st.download_button(label, st.session_state["pdf_documents"][kind],
                               file_name=f"DOJO_SIEM_Analyzer_{kind}_{model['report_id']}.pdf",
                               mime="application/pdf", key="download_" + kind, on_click="ignore")
    with st.expander("Trazabilidad del snapshot exportado"):
        st.code(f"Archivo: {model['provenance']['file']}\nSHA-256: {model['provenance']['sha256']}\nHoja: {model['provenance']['sheet']}\nAnálisis: {model['analysis_id']}\nCorrelación: {model['correlation_id']}\nInforme: {model['report_id']}", language=None)

