"""Orquesta una solicitud explícita; auditoría solo de metadatos en memoria."""

from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
from time import perf_counter

from dojo.ai_client import OPTIONS, InputBudgetError, InvalidResponseError, ProviderError, diagnostics
from dojo.ai_context import canonical, context_hash, inference_context
from dojo.ai_contract import PROMPT_VERSION, Validation, validate_response


def run_assistance(client, model, context):
    requested = datetime.now(timezone.utc).isoformat()
    started = perf_counter()
    provider_error = None
    provider = {"model": model, "digest": None, **diagnostics()}
    try:
        raw, provider = client.generate(model, context)
        response, validation = validate_response(raw, context)
        state = "pending_review" if validation.accepted else "invalid_response"
    except (InputBudgetError, InvalidResponseError) as exc:
        provider.update(getattr(exc, "diagnostics", {}))
        response, validation = None, Validation(False, [str(exc)])
        state = "input_error" if isinstance(exc, InputBudgetError) else "invalid_response"
    except ProviderError as exc:
        provider_error = str(exc)
        provider.update(getattr(exc, "diagnostics", {}))
        provider["digest"] = provider.get("digest") or getattr(exc, "verified_model", {}).get("digest")
        response, validation, state = None, None, "provider_error"
    audit = {"snapshot_id": context["snapshot_id"], "analysis_id": context["analysis_id"],
             "line_id": context["line_id"], "line_ref": context["line_ref"],
             "context_sha256": context_hash(inference_context(context)), "source_context_sha256": context_hash(context),
             "context_version": context["context_version"],
             "provider": "Ollama / loopback", "model": provider["model"], "model_digest": provider["digest"],
             "prompt_version": PROMPT_VERSION, "parameters": dict(OPTIONS), "timeout_seconds": client.timeout,
             "requested_at_utc": requested,
             "validation": asdict(validation) if validation is not None else None, "state": state,
             "decision": "pendiente de revisión humana" if state == "pending_review" else None,
             "coverage": dict(context["coverage"]),
             "usage": {k: provider.get(k) for k in ("prompt_eval_count", "eval_count")},
             "diagnostics": {**{k: v for k, v in provider.items() if k not in ("model", "digest")},
                             "request_wall_seconds": perf_counter() - started}}
    # La respuesta rechazada no se conserva ni se presenta como análisis utilizable.
    return {"response": response, "validation": validation, "audit": audit, "provider_error": provider_error, "state": state}


def draft_text(response):
    return response["borrador"]


def validate_draft(response, text, context):
    """La edición también debe respetar el contrato; el significado sigue bajo revisión."""
    from copy import deepcopy
    edited = deepcopy(response)
    import re
    edited["borrador"] = text
    edited["referencias"] = sorted(set(re.findall(r"\bE\d{4,}\b", " ".join(edited[s] for s in (
        "interpretacion", "hipotesis", "alternativas", "corroboraciones", "investigacion", "contencion_condicionada", "remediacion", "borrador")))))
    return validate_response(canonical(edited), context)[1]


def record_decision(audit, decision, text):
    if decision not in ("aprobado por el analista", "descartado por el analista"):
        raise ValueError("Decisión inválida.")
    if not (audit.get("validation") or {}).get("accepted") or audit.get("state") not in ("pending_review", "approved"):
        raise ValueError("Solo una respuesta válida y revisable admite decisión humana.")
    return {**audit, "state": "approved" if decision == "aprobado por el analista" else "discarded",
            "decision": decision, "decision_at_utc": datetime.now(timezone.utc).isoformat(),
            "reviewed_text_sha256": sha256(text.encode("utf-8")).hexdigest()}
