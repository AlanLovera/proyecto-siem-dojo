"""Representaciones derivadas; nunca reemplaza las columnas de origen."""

from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
import math
import re

import pandas as pd

from dojo.ingestion import ImportResult


N = "__dojo_n_"
VERSION = "2A.1"


@dataclass
class NormalizedData:
    records: pd.DataFrame
    issues: list[dict]


def text(value):
    if value is None or (not isinstance(value, (list, dict)) and pd.isna(value)):
        return None
    value = str(value).strip()
    return value or None


def identity(value):
    value = text(value)
    return value.casefold() if value and value != "-" else None


def timestamp(value):
    if value is None or pd.isna(value):
        return None
    if isinstance(value, datetime):
        # No comparar relojes con y sin offset ni quitar zonas silenciosamente.
        return value if value.tzinfo is None else None
    value = text(value)
    if value:
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    return None


def ip(value):
    value = text(value)
    if value:
        try:
            return str(ip_address(value))
        except ValueError:
            pass
    return None


def event_id(value):
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return str(int(value)) if math.isfinite(value) and int(value) == value else None
    value = text(value)
    if not value:
        return None
    if re.fullmatch(r"\d+(?:\.0+)?", value):
        return str(int(value.split(".")[0]))
    return value.upper()


def result(value):
    value = identity(value)
    if value and re.fullmatch(r"[1-5]\d{2}", value):
        return "http_" + value
    return value


def normalize_records(imported: ImportResult) -> NormalizedData:
    frame = imported.records.copy(deep=True).reset_index(drop=True)
    provenance = ["__dojo_sha256", "__dojo_sheet", "__dojo_row"]
    if frame[provenance].isna().any().any() or frame.duplicated(provenance).any():
        raise ValueError("La procedencia (SHA-256, hoja, fila) está ausente o repetida.")
    blocked = {
        (issue["fila_excel"], issue["columna"])
        for issue in imported.issues.to_dict("records")
        if issue["tipo"] in ("formula", "error_excel")
    }
    issues = []
    converters = {
        "timestamp": ("Timestamp", timestamp), "user": ("User", identity),
        "host": ("Hostname", identity), "ip": ("Source_IP", ip),
        "event_id": ("Event_ID", event_id), "result": ("Result", result),
        "destination": ("Destination", identity), "source": ("Log_Source", identity),
        "command": ("Process_CommandLine", text), "description": ("Event_Description", text),
    }
    original_records = frame.to_dict("records")
    for name, (column, convert) in converters.items():
        values = []
        for record in original_records:
            row = record["__dojo_row"]
            unavailable = (row, column) in blocked
            value = None if unavailable else convert(record[column])
            values.append(value)
            if unavailable or (name in ("timestamp", "ip", "event_id") and value is None):
                issues.append({
                    "fila_excel": row, "Log_ID": record["Log_ID"], "columna": column,
                    "motivo": "Fórmula/error Excel excluido de la normalización." if unavailable
                    else "Valor ausente, inválido o formato no admitido; no se infiere.",
                })
        # object mantiene None y datetime sin convertirlos a NaT/nan.
        frame[N + name] = pd.Series(values, dtype=object)
    return NormalizedData(frame, issues)
