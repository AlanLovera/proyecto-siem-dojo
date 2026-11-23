"""Ejecutar desde la raíz con: python -m streamlit run app.py."""

from hashlib import sha256

import streamlit as st

from dojo.ingestion import ExcelImportError, MAX_BYTES, import_sheet, list_sheets
from dojo.query import display_records, filter_records
from dojo.analysis_ui import clear_analysis, render_analysis
from dojo.correlation_ui import render_correlation
from dojo.dashboard_ui import render_dashboard
from dojo.presentation import APP_CSS, APP_SUBTITLE, APP_TITLE, facts_table
from dojo.report_ui import clear_reports, render_reports
from dojo.ai_ui import clear_ai, render_ai


def render_import(result):
    summary = result.summary
    st.success("Carga finalizada. Datos de origen disponibles para consulta.")
    st.text(f"Archivo: {result.filename} | Hoja: {result.sheet}")
    st.text(f"Período interpretable: {summary['time_start'] or 'sin datos'} a {summary['time_end'] or 'sin datos'}")
    for widget, label, key in zip(st.columns(3), ["Registros", "Columnas de origen", "Fuentes"], ["records", "columns", "sources"]):
        widget.metric(label, summary[key])
    st.caption(f"Esquema validado: {len(result.columns)} columnas de origen; referencias de archivo, hoja y fila conservadas.")
    with st.expander("Columnas validadas · detalles técnicos", expanded=False):
        st.json(list(result.columns), expanded=False)
        st.caption("Cabeceras exactas, sin renombrado ni mapeo automático.")

    if not result.issues.empty:
        st.warning(f"{len(result.issues)} observaciones de importación. Los registros se conservaron; revisá Calidad de datos.")
    with st.expander("Calidad de datos y observaciones", expanded=False):
        st.dataframe(result.quality, hide_index=True, width="stretch")
        facts_table("Resumen de calidad", {
            "Filas vacías omitidas (se conserva numeración Excel)": summary["blank_rows"],
            "Filas con Log_ID duplicado": summary["duplicate_id_rows"],
            "Log_ID faltantes": summary["missing_ids"],
            "Filas repetidas sin Log_ID (posteriores a la primera)": summary["duplicate_rows_without_id"],
            "Timestamp inválidos o faltantes": summary["invalid_timestamps"],
            "User con marcador '-' (no identificado)": summary["unidentified_users"],
            "Fórmulas sin evaluar": summary["formulas"],
            "Errores de celda Excel": summary["excel_errors"],
        })
        if result.issues.empty:
            st.info("Sin errores de celda, fórmulas, fechas inválidas o problemas de Log_ID detectados. Revisá los faltantes por columna.")
        else:
            st.dataframe(display_records(result.issues), hide_index=True, width="stretch")
    if not summary["records"]:
        st.warning("La hoja tiene cabeceras válidas y ningún registro de datos.")

    with st.expander("Vista previa de origen (15 filas)"):
        st.caption("Event_ID se presenta como texto. __dojo_event_id_type conserva el tipo Excel; los valores importados permanecen sin modificar.")
        st.dataframe(display_records(result.records.head(15)), hide_index=True, width="stretch")
    st.subheader("Consulta de registros")
    text = st.text_input("Buscar texto literal en cualquier columna", key="search")
    sources = st.multiselect("Log_Source", sorted(result.records["Log_Source"].dropna().unique(), key=str), key="sources")
    severities = st.multiselect("Severity original", sorted(result.records["Severity"].dropna().unique(), key=str), key="severities")
    filtered = filter_records(result.records, text, sources, severities)
    st.caption(f"Mostrando {len(filtered)} de {len(result.records)} registros. Tabla de solo lectura, con ordenamiento por columna.")
    st.dataframe(display_records(filtered), hide_index=True, width="stretch", height=480)


def main():
    st.set_page_config(page_title=APP_TITLE, page_icon="🛡️", layout="wide")
    st.markdown(APP_CSS, unsafe_allow_html=True)
    st.title(APP_TITLE)
    st.caption(APP_SUBTITLE)
    st.warning("Caso ficticio / zona horaria no especificada. No se infiere zona horaria ni se confirman incidentes.")
    case = st.sidebar.text_input("Nombre del caso", "Caso ficticio SOC L2")
    st.text(f"Caso: {case}")
    try:
        upload = st.file_uploader("Cargar archivo Excel", type=["xlsx"], max_upload_size=20,
                                  key="excel_upload", help="Seleccioná manualmente un .xlsx. Límite: 20 MiB; no se modifica el original.")
        if upload is None:
            st.session_state.pop("import_result", None)
            st.session_state.pop("import_key", None)
            clear_analysis()
            clear_reports()
            clear_ai()
            st.info("Seleccioná el archivo .xlsx para comenzar. Los resultados aparecerán después de importarlo.")
            return
        if upload.size > MAX_BYTES:
            raise ExcelImportError("El archivo supera el límite de 20 MiB.")
        data, filename = upload.getvalue(), upload.name
        digest = sha256(data).hexdigest()
        with st.sidebar:
            sheet = st.selectbox("Hoja", list_sheets(data, filename), key="sheet")
            with st.expander("Archivo y huella SHA-256"):
                st.text(filename)
                st.code(digest, language=None)
        key = (digest, filename, sheet)
        if st.session_state.get("import_key") != key:
            clear_analysis()
            result = import_sheet(data, filename, sheet)
            st.session_state["import_result"] = result
            st.session_state["import_key"] = key
            for control in ("search", "sources", "severities"):
                st.session_state.pop(control, None)
        imported = st.session_state["import_result"]
        st.caption(f"{filename} · {sheet} · {len(imported.records)} registros · {imported.summary['time_start'] or 'sin fecha'} → {imported.summary['time_end'] or 'sin fecha'}")
        load, detection, correlation, dashboard, reports, assistance = st.tabs(["1 · Carga y calidad", "2 · Análisis", "3 · Correlación", "4 · Dashboard", "5 · Informes PDF", "6 · Asistencia IA"])
        with load:
            render_import(imported)
        with detection:
            analysis = render_analysis(imported)
        report = None
        with correlation:
            if analysis is not None:
                report = render_correlation(imported, analysis)
            else:
                st.info("Ejecutá el análisis vigente en la sección Análisis para habilitar la correlación.")
        with dashboard:
            if report is not None:
                render_dashboard(imported, analysis, report)
            else:
                st.info("El dashboard requiere análisis y correlación vigentes. Completá las secciones Análisis y Correlación.")
        with reports:
            render_reports(imported, analysis, report, case)
        with assistance:
            render_ai(imported, analysis, report, case)
    except (ExcelImportError, OSError) as exc:
        st.session_state.pop("import_result", None)
        st.session_state.pop("import_key", None)
        clear_analysis()
        clear_reports()
        clear_ai()
        st.error(f"Importación detenida: {exc}")


if __name__ == "__main__":
    main()
