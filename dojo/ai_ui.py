"""Asistencia optativa bajo demanda. Nunca modifica análisis, revisiones ni PDF."""

from hashlib import sha256
from copy import deepcopy

import streamlit as st

from dojo.ai_client import OPTIONS, OllamaClient, ProviderError
from dojo.ai_context import ContextError, canonical, context_hash, inference_context, prepare_context
from dojo.ai_contract import PROMPT_VERSION, REVIEW_WARNING, input_budget
from dojo.ai_service import draft_text, record_decision, run_assistance, validate_draft
from dojo.report_model import ReportInputError, argentina_date, build_report_model, report_signature

LABELS = {"interpretacion": "Interpretación técnica", "hipotesis": "Hipótesis por corroborar",
          "alternativas": "Explicaciones alternativas", "corroboraciones": "Corroboraciones pendientes",
          "investigacion": "Recomendaciones de investigación", "contencion_condicionada": "Contención condicionada",
          "remediacion": "Remediación posterior a establecer causa"}


def clear_ai():
    archive_decision()
    for key in list(st.session_state):
        if key.startswith("ai_") and key not in ("ai_enabled", "ai_decision_history"):
            st.session_state.pop(key, None)


def clear_proposal():
    archive_decision()
    for key in ("ai_result", "ai_draft", "ai_review_ack", "ai_approved_hash", "ai_evidence"):
        st.session_state.pop(key, None)


def archive_decision():
    audit = st.session_state.get("ai_result", {}).get("audit", {})
    if audit.get("decision") in ("aprobado por el analista", "descartado por el analista"):
        history = st.session_state.setdefault("ai_decision_history", [])
        if audit not in history:
            history.append(deepcopy(audit))


def render_diagnostics(audit):
    with st.expander("Diagnóstico de inferencia (tiempos en segundos)"):
        data = audit.get("diagnostics", {})
        keys = ("request_wall_seconds", "chat_wall_seconds", "total_duration_seconds", "load_duration_seconds",
                "prompt_eval_count", "prompt_eval_duration_seconds", "eval_count", "eval_duration_seconds", "done_reason")
        st.dataframe([{"Métrica": k, "Valor": "No disponible" if data.get(k) is None else str(data[k])} for k in keys],
                     hide_index=True, width="stretch")
        st.write({"modelo": audit["model"], "parámetros enviados": audit["parameters"]})


def render_ai(imported, analysis, correlation, case_name):
    st.subheader("Asistencia IA local")
    st.caption("HECHO → INTERPRETACIÓN/HIPÓTESIS → CORROBORACIÓN → CONCLUSIÓN. "
               "Función opcional, sin alterar detecciones, criticidad, confianza, estados ni informes PDF.")
    enabled = st.checkbox("Habilitar asistencia IA en esta sesión", value=False, key="ai_enabled")
    if st.session_state.get("ai_decision_history"):
        with st.expander("Decisiones históricas de esta sesión (solo metadatos)"):
            st.download_button("Descargar decisiones históricas de esta sesión", canonical(st.session_state["ai_decision_history"]),
                               file_name="dojo_ia_decisiones.json", mime="application/json", key="ai_history_download")
    if not enabled:
        clear_ai()
        st.info("IA deshabilitada. El análisis, dashboard y PDF funcionan sin Ollama.")
        return
    st.warning("Solo Ollama en 127.0.0.1:11434. Se envían datos de una única línea al modelo local al pulsar Generar. "
               "No hay descargas, herramientas ni acciones automáticas. Revisá el contexto antes de enviarlo.")
    if st.button("Consultar Ollama local", key="ai_check"):
        try:
            st.session_state["ai_models"] = OllamaClient().local_models()
            st.session_state.pop("ai_provider_error", None)
        except ProviderError as exc:
            st.session_state["ai_models"] = []
            st.session_state["ai_provider_error"] = str(exc)
    if st.session_state.get("ai_provider_error"):
        st.warning(st.session_state["ai_provider_error"])
    models = st.session_state.get("ai_models", [])
    if not models:
        clear_proposal()
        st.info("Consultá disponibilidad. Se requiere un modelo local de texto instalado; no se descargan modelos.")
        return
    names = [m["name"] for m in models]
    model = st.selectbox("Modelo local instalado", names,
                         index=names.index("llama3.2:3b") if "llama3.2:3b" in names else 0, key="ai_model")
    timeout = st.number_input("Espera máxima de Ollama (segundos)", min_value=10, max_value=180,
                              value=120, step=10, key="ai_timeout")
    if analysis is None or correlation is None:
        clear_proposal()
        st.session_state.pop("ai_snapshot", None)
        st.session_state.pop("ai_snapshot_signature", None)
        st.info("La asistencia requiere análisis y correlación vigentes. Completá esas secciones.")
        return
    issued = st.session_state.get("pdf_issued_date", argentina_date())
    signature = report_signature(imported, analysis, correlation, case_name, issued)
    if st.session_state.get("ai_snapshot_signature") != signature:
        clear_proposal()
        try:
            st.session_state["ai_snapshot"] = build_report_model(imported, analysis, correlation, case_name, issued)
            st.session_state["ai_snapshot_signature"] = signature
        except ReportInputError as exc:
            st.error(f"No se pudo preparar el snapshot: {exc}")
            return
    snapshot = st.session_state["ai_snapshot"]
    lines = {l["group_id"]: l for l in snapshot["lines"]}
    if not lines:
        clear_proposal()
        st.info("No hay líneas en el resultado vigente.")
        return
    if st.session_state.get("ai_line") not in lines:
        st.session_state.pop("ai_line", None)
    line_id = st.selectbox("Línea de investigación para IA", list(lines),
                           format_func=lambda k: f"{lines[k]['ref']} · {lines[k]['title']}", key="ai_line")
    try:
        context = prepare_context(snapshot, line_id)
    except ContextError as exc:
        clear_proposal()
        st.error(str(exc))
        return
    fingerprint = (context_hash(context), model, int(timeout), PROMPT_VERSION, canonical(OPTIONS))
    if st.session_state.get("ai_request_key") != fingerprint:
        clear_proposal()
        st.session_state["ai_request_key"] = fingerprint
    coverage = context["coverage"]
    wire = inference_context(context)
    budget = input_budget(context, OPTIONS)
    st.caption(f"{context['line_ref']} · {coverage['included_events']}/{coverage['total_line_events']} eventos incluidos · "
               f"{len(canonical(context).encode('utf-8'))} bytes · {context['snapshot_id']}")
    st.write("Clasificación vigente: " + " · ".join(f"{k}: {v}" for k, v in context["classification"].items()))
    with st.expander("Revisar contexto y limitaciones antes de generar", expanded=False):
        st.code("SHA-256 contexto enviado: " + context_hash(wire), language=None)
        st.dataframe([{"Dato de la solicitud": k, "Valor": str(v)} for k, v in budget.items()], hide_index=True, width="stretch")
        st.caption("Valores comunes + valores de cada evento reconstruyen todos los campos originales incluidos. "
                   "La procedencia y los parámetros completos se conservan localmente:")
        with st.expander("JSON del contexto enviado", expanded=False):
            st.json({"presupuesto": budget, "contexto_enviado": wire}, expanded=False)
        with st.expander("JSON de origen y procedencia", expanded=False):
            st.json(context, expanded=False)
    st.caption(f"Configuración: 4096 tokens de ventana / 1200 de salida. Prompt completo: {budget['prompt_bytes']} bytes; "
               f"cota de entrada con plantilla: {budget['input_token_upper_bound']} tokens. "
               "El cliente verifica la plantilla/tokenizador antes de consultar.")
    if not budget["fits"]:
        st.error("La cota conservadora de entrada más la salida reservada supera 4096 tokens. No se enviará ni truncará evidencia.")
    with st.expander("Hechos y métricas deterministas (aplicación)"):
        st.dataframe([{**{"Referencia": e["ref"], "Fila Excel": e["excel_row"]},
                       **{k: str(v) for k, v in e["values"].items()}} for e in context["events"]],
                     hide_index=True, width="stretch")
        st.dataframe([{"Métrica de la línea completa": k, "Valor": str(v)} for k, v in context["metrics_full_line"].items()],
                     hide_index=True, width="stretch")
    if coverage["omitted_references"]:
        st.warning("Contexto parcial: no se permiten conclusiones sobre evidencia omitida. " +
                   ", ".join(coverage["omitted_references"]))
    if st.button("Generar asistencia local", key="ai_generate", type="primary", disabled=not budget["fits"]):
        clear_proposal()
        try:
            with st.spinner("Consultando el modelo local; las demás funciones conservan sus resultados..."):
                result = run_assistance(OllamaClient(int(timeout)), model, context)
            st.session_state["ai_result"] = result
            if result["response"] is not None:
                st.session_state["ai_draft"] = draft_text(result["response"])
        except ProviderError as exc:
            st.error(str(exc))
            st.info("No se obtuvo una respuesta utilizable. El análisis determinista permanece disponible.")
    result = st.session_state.get("ai_result")
    if result is None:
        return
    validation = result["validation"]
    state = result["audit"]["state"]
    discarded = state == "discarded"
    if discarded:
        for key in ("ai_draft", "ai_review_ack", "ai_approved_hash"):
            st.session_state.pop(key, None)
        st.info("Propuesta descartada por el analista; contenido retirado. Los controles automáticos conservan su resultado original.")
    elif state == "provider_error":
        st.error("Error de proveedor: " + result["provider_error"])
        st.info("Sin respuesta ni borrador para revisar. El análisis determinista permanece disponible.")
    elif state in ("invalid_response", "input_error"):
        st.error("Respuesta inválida. No se puede aprobar." if state == "invalid_response" else "Contexto no compatible; solicitud no enviada.")
        st.write(validation.errors)
    else:
        st.warning(REVIEW_WARNING)
        response = result["response"]
        st.caption("Controles estructurales aprobados; texto libre sujeto a revisión humana.")
        for key, title in LABELS.items():
            with st.expander(title, expanded=key == "interpretacion"):
                st.text(response[key])
        cited = sorted(response["referencias"])
        ref = st.selectbox("Abrir evidencia original citada", cited, key="ai_evidence")
        event = next(e for e in context["events"] if e["ref"] == ref)
        with st.expander("Registro original y trazabilidad", expanded=True):
            st.text(f"{ref} · {event['file']} · {event['sheet']} · fila Excel {event['excel_row']}")
            st.code(event["sha256"], language=None)
            st.caption("Función: " + ("primaria" if event["primary"] else "contextual"))
            st.dataframe([{"Campo": k, "Valor original": str(v)} for k, v in event["values"].items()],
                         hide_index=True, width="stretch")
        text = st.text_area("Borrador técnico editable (no se incorpora a los PDF)", height=180, key="ai_draft")
        edited_validation = validate_draft(response, text, context)
        digest = sha256(text.encode("utf-8")).hexdigest()
        if result["audit"]["decision"] == "aprobado por el analista" and st.session_state.get("ai_approved_hash") != digest:
            archive_decision()
            result["audit"]["decision"] = "pendiente de revisión humana (texto editado)"
            result["audit"]["state"] = "pending_review"
            result["state"] = "pending_review"
            for key in ("decision_at_utc", "reviewed_text_sha256"):
                result["audit"].pop(key, None)
            st.session_state["ai_review_ack"] = False
        if not edited_validation.accepted:
            st.error("La edición contradice el contrato: " + "; ".join(edited_validation.errors))
        checked = st.checkbox("Revisé hechos, citas, límites y el borrador; asumo la revisión humana", key="ai_review_ack")
        approve, discard = st.columns(2)
        if approve.button("Aprobar borrador revisado", key="ai_approve", disabled=not checked or not edited_validation.accepted):
            result["audit"] = record_decision(result["audit"], "aprobado por el analista", text)
            result["state"] = "approved"
            st.session_state["ai_approved_hash"] = digest
            archive_decision()
        if discard.button("Descartar propuesta", key="ai_discard"):
            result["audit"] = record_decision(result["audit"], "descartado por el analista", text)
            result["state"] = "discarded"
            archive_decision()
            result["response"] = None
            # Rerun evita que un texto descartado siga visible o aprobable.
            st.rerun()
    if result["audit"]["decision"] is not None:
        st.info("Decisión: " + result["audit"]["decision"])
    render_diagnostics(result["audit"])
    with st.expander("Metadatos de auditoría (sin prompt ni respuesta)", expanded=False):
        st.json(result["audit"], expanded=False)
        st.download_button("Descargar metadatos de auditoría", canonical(result["audit"]),
                           file_name="dojo_ia_auditoria.json", mime="application/json", key="ai_audit_download")
