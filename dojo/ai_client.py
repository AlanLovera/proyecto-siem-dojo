"""API Ollama exclusivamente loopback; sin SDK, proxies, redirects, descargas ni herramientas."""

import json
from hashlib import sha256
import re
import socket
from time import perf_counter
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from dojo.ai_contract import input_budget, messages, response_schema

BASE_URL = "http://127.0.0.1:11434"
OPTIONS = {"temperature": 0, "seed": 42, "num_ctx": 4096, "num_predict": 1200}
MAX_RESPONSE = 2 * 1024 * 1024
# /show de llama3.2:3b local: dos mensajes, sin herramientas ni historial.
LLAMA_TEMPLATE_SHA256 = "966de95ca8a62200913e3f8bfbf84c8494536f1b94b49166851e76644e966396"
DURATION_FIELDS = ("total_duration", "load_duration", "prompt_eval_duration", "eval_duration")


class ProviderError(RuntimeError):
    pass


class InvalidResponseError(ProviderError):
    pass


class InputBudgetError(ProviderError):
    pass


def diagnostics(response=None):
    response = response or {}
    result = {k: response.get(k) for k in (*DURATION_FIELDS, "prompt_eval_count", "eval_count", "done_reason")}
    for k in (*DURATION_FIELDS, "prompt_eval_count", "eval_count"):
        value = result[k]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            result[k] = None
    result.update({k + "_seconds": None if result[k] is None else result[k] / 1e9 for k in DURATION_FIELDS})
    return result


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProviderError("Ollama devolvió una redirección; conexión bloqueada.")


class OllamaClient:
    def __init__(self, timeout=120):
        if not 1 <= timeout <= 180:
            raise ValueError("Timeout fuera de rango.")
        self.timeout = timeout
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def _request(self, endpoint, payload=None, timeout=None):
        if endpoint not in ("/api/tags", "/api/show", "/api/chat"):
            raise ProviderError("Endpoint no autorizado.")
        data = None if payload is None else json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        request = Request(BASE_URL + endpoint, data=data, headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=timeout or self.timeout) as response:
                raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise InvalidResponseError("Respuesta local demasiado grande.")
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise InvalidResponseError("Ollama devolvió un formato de respuesta inesperado.")
            if "error" in result:
                raise ProviderError("Ollama devolvió un error o formato inesperado.")
            return result
        except HTTPError as exc:
            code = exc.code
            exc.close()
            raise ProviderError(f"Ollama respondió HTTP {code}; comprobar servicio y modelo local.") from None
        except (TimeoutError, socket.timeout):
            raise ProviderError("Ollama excedió el tiempo de espera. El análisis determinista sigue disponible.") from None
        except (URLError, OSError):
            raise ProviderError("No se pudo conectar con Ollama en loopback. Comprobar que esté iniciado.") from None
        except (ValueError, UnicodeError, RecursionError):
            raise InvalidResponseError("Ollama devolvió una respuesta ilegible.") from None

    def local_models(self):
        tags = self._request("/api/tags", timeout=5)
        models = tags.get("models")
        if not isinstance(models, list):
            raise ProviderError("Inventario de modelos inválido.")
        # Modelos cloud/proxy y embeddings no se ofrecen. /show se comprueba también antes de inferir.
        return [m for m in models if isinstance(m, dict) and isinstance(m.get("name"), str)
                and not any(t in m["name"].lower() for t in ("cloud", "embed"))
                and re.fullmatch(r"[0-9a-f]{64}", str(m.get("digest", "")))
                and isinstance(m.get("size"), int) and m["size"] > 0
                and not m.get("remote_host") and not m.get("remote_model")]

    def check_model(self, name):
        model = next((m for m in self.local_models() if m["name"] == name), None)
        if model is None:
            raise ProviderError("El modelo seleccionado ya no está instalado localmente.")
        details = self._request("/api/show", {"model": name}, timeout=10)
        capabilities = details.get("capabilities")
        if (details.get("remote_host") or details.get("remote_model")
                or not isinstance(capabilities, list) or "completion" not in capabilities):
            raise ProviderError("Se requiere un modelo local con capacidad de completar texto, sin proxy cloud.")
        return {**model, "template_sha256": sha256(details.get("template", "").encode("utf-8")).hexdigest(),
                "tokenizer": details.get("model_info", {}).get("tokenizer.ggml.model")}

    def generate(self, name, context):
        model = self.check_model(name)
        budget = input_budget(context, OPTIONS)
        metadata = {"model": name, "digest": model["digest"], "parameters": dict(OPTIONS),
                    "budget": budget, **diagnostics()}
        if (not budget["fits"] or model.get("tokenizer") != "gpt2"
                or model.get("template_sha256") != LLAMA_TEMPLATE_SHA256):
            error = InputBudgetError("No se puede garantizar el presupuesto de 4096 tokens con reserva de 1200, "
                                     "o la plantilla/tokenizador no está verificada para ese presupuesto. "
                                     "No se envió evidencia ni se truncó contenido.")
            error.diagnostics = metadata
            raise error
        started = perf_counter()
        try:
            response = self._request("/api/chat", {"model": name, "messages": messages(context),
                                                   "format": response_schema(context), "stream": False,
                                                   "options": dict(OPTIONS), "keep_alive": "5m"})
        except ProviderError as exc:
            exc.verified_model = model
            exc.diagnostics = {**metadata, "chat_wall_seconds": perf_counter() - started}
            raise
        metadata.update(diagnostics(response))
        metadata["chat_wall_seconds"] = perf_counter() - started
        metadata["response_model"] = response.get("model")
        message = response.get("message", {})
        if (response.get("done") is not True or response.get("done_reason") not in (None, "stop")
                or not isinstance(message, dict) or message.get("tool_calls")
                or not isinstance(message.get("content"), str)):
            error = InvalidResponseError("Generación incompleta, truncada o con herramientas: respuesta inválida.")
            error.diagnostics = metadata
            raise error
        count = metadata["prompt_eval_count"]
        if count is not None and count > budget["input_token_upper_bound"]:
            error = InvalidResponseError("Ollama superó la cota verificada de entrada; no se acepta posible truncamiento.")
            error.diagnostics = metadata
            raise error
        return message["content"], metadata
