"""Presentación legible de estructuras analíticas, sin cambiar su contenido."""

import pandas as pd
import re
import streamlit as st


APP_TITLE = "DOJO SIEM Analyzer"
APP_SUBTITLE = "Investigación SIEM · Evidencia trazable · Análisis reproducible"
APP_CSS = """<style>
[data-testid="stMainBlockContainer"] {padding-top: 1.8rem; max-width: 1600px;}
[data-testid="stMain"] h1 {font-size: clamp(1.7rem, 2.4vw, 2.6rem); line-height: 1.2; overflow-wrap: break-word;}
[data-testid="stMetric"] {background: #152238; border: 1px solid #334155; border-radius: 10px; padding: 1rem;}
[data-testid="stMetricValue"] {font-size: 1.8rem;}
[data-testid="stMetricLabel"] p {white-space: normal; overflow: visible; text-overflow: unset;}
</style>"""


def style_chart(fig):
    """Solo presentación: conserva trazas, selecciones, claves y colores semánticos."""
    fig.update_layout(template="plotly_dark", paper_bgcolor="#0b1220", plot_bgcolor="#0b1220",
                      font=dict(family="Arial", color="#e2e8f0"))
    fig.update_xaxes(gridcolor="#283a52", zerolinecolor="#334155", automargin=True)
    fig.update_yaxes(gridcolor="#283a52", zerolinecolor="#334155", automargin=True)
    return fig


def counted(count, singular, plural):
    return f"{count} {singular if count == 1 else plural}"


def ui_narrative(value):
    """Concordancia solo en narrativa generada por la app; nunca sobre logs/JSON."""
    variants = {
        "detecciones asociadas": "detección asociada", "hallazgos sospechosos": "hallazgo sospechoso",
        "eventos originales únicos asociados": "evento original único asociado",
        "eventos originales únicos": "evento original único", "eventos únicos asociados": "evento único asociado",
        "eventos únicos": "evento único", "líneas de investigación": "línea de investigación",
        "vínculos internos": "vínculo interno", "asociaciones externas": "asociación externa",
        "registros previos de compresión compatibles": "registro previo de compresión compatible",
        "registros previos de compresión": "registro previo de compresión",
        "POST salientes registran": "POST saliente registra", "fallos RDP preceden": "fallo RDP precede",
        "detecciones": "detección", "hallazgos": "hallazgo", "eventos": "evento", "líneas": "línea",
        "vínculos": "vínculo", "asociaciones": "asociación", "registros": "registro",
    }
    pattern = r"\b1 (" + "|".join(re.escape(v) for v in variants) + r")\b"
    return re.sub(pattern, lambda match: "1 " + variants[match[1]], value)


COVERAGE_HEADERS = {
    "rule_id": "Regla", "candidate_records": "Registros candidatos", "eligible_records": "Registros utilizables",
    "skipped_incomplete": "Excluidos por datos incompletos", "missing_by_field": "Campos faltantes",
    "state": "Cobertura", "findings": "Hallazgos",
}
MISSING_LABELS = {"file_target": "Ruta de archivo", "destination": "Destino", "timestamp": "Fecha/hora",
                  "host": "Host", "user": "Usuario", "ip": "IP", "command": "Comando", "result": "Resultado"}


def coverage_frame(diagnostics):
    frame = pd.DataFrame(diagnostics, columns=list(COVERAGE_HEADERS))
    frame["missing_by_field"] = frame["missing_by_field"].map(
        lambda fields: "; ".join(f"{MISSING_LABELS.get(k, k)} ({k}): {v}" for k, v in fields.items())
        if fields else "Sin faltantes registrados")
    return frame.rename(columns=COVERAGE_HEADERS)


def render_coverage(diagnostics):
    st.dataframe(coverage_frame(diagnostics), hide_index=True, width="stretch")
    st.caption("Los campos faltantes pueden superponerse en un mismo registro y no deben sumarse directamente. "
               "La exclusión total por regla se muestra por separado.")
    with st.expander("JSON original de cobertura", expanded=False):
        st.json(diagnostics, expanded=False)


def link_summary(group):
    internal, external = group["links"], group["external_links"]
    summary = (f"Esta línea contiene {counted(len(group['detection_ids']), 'detección', 'detecciones')}. "
               f"{counted(len(internal), 'vínculo interno', 'vínculos internos')} y "
               f"{counted(len(external), 'asociación externa', 'asociaciones externas')}.")
    if not internal and not external:
        return summary + (" No se identificaron vínculos adicionales entre detecciones ni asociaciones externas registradas. "
                          "La ausencia de vínculos no significa ausencia de eventos asociados.")
    types = {
        "fuerte": "Tipo fuerte: coincidencias de evidencia o atributos según los criterios registrados.",
        "contextual": "Tipo contextual: coincidencias parciales de atributos o eventos de contexto.",
        "temporal": "Tipo temporal: proximidad de timestamps, sin soporte suficiente de otros atributos.",
    }
    explanations = [types.get(kind, f"Tipo registrado: {kind}; consultar sus criterios en el JSON.")
                    for kind in sorted({link["kind"] for link in internal + external})]
    return summary + " " + " ".join(explanations) + " Estas relaciones son observacionales; no acreditan causalidad ni compromiso."


def readable(value):
    if isinstance(value, dict):
        if "Log_ID" in value and "excel_row" in value:
            return f"{value['Log_ID']} · fila {value['excel_row']}"
        return "; ".join(f"{k.replace('_', ' ')}: {readable(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return " · ".join(readable(v) for v in value)
    return str(value) if value is not None else "Sin dato"


def facts_table(title, facts):
    st.markdown(f"**{title}**")
    if isinstance(facts, dict):
        scalars = {k: v for k, v in facts.items() if not (isinstance(v, list) and v and isinstance(v[0], dict))}
        if scalars:
            st.dataframe(pd.DataFrame([{"Observación": str(k).replace('_', ' '), "Valor registrado": readable(v)}
                                       for k, v in scalars.items()]), hide_index=True, width="stretch")
        for key in facts:
            if key in scalars:
                continue
            with st.expander(str(key).replace('_', ' '), expanded=False):
                st.dataframe(pd.DataFrame([{k.replace('_', ' '): readable(v) for k, v in item.items()}
                                           for item in facts[key]]), hide_index=True, width="stretch")
    elif isinstance(facts, list):
        for fact in facts:
            if isinstance(fact, dict):
                facts_table("Detalle observado", fact)
            else:
                st.write(fact)
    else:
        st.write(facts)
