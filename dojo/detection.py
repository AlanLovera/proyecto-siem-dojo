"""Motor reproducible. Señales observadas y asociaciones simples, sin incidentes confirmados."""

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from hashlib import sha256
import json
import re
from urllib.parse import parse_qsl, urlsplit

import pandas as pd

from dojo.ingestion import REQUIRED_COLUMNS
from dojo.normalization import N, VERSION as NORMALIZATION_VERSION, normalize_records
from dojo.rules import RULES, parameters


ENGINE_VERSION = "2A.1"


def _jsonable(value):
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat(sep=" ")
    if isinstance(value, (date, time)):
        return value.isoformat()
    if isinstance(value, timedelta):
        return str(value)
    if value is None or pd.isna(value):
        return None
    if hasattr(value, "item"):
        return value.item()
    return value


def _digest(value):
    return sha256(json.dumps(_jsonable(value), sort_keys=True, ensure_ascii=False,
                             separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _ref(row):
    return row["__dojo_sha256"], row["__dojo_sheet"], int(row["__dojo_row"])


def _sort(row):
    return row[N + "timestamp"] or datetime.max, _ref(row)


def _groups(rows, fields):
    groups = defaultdict(list)
    for row in rows:
        # No cruzar archivos/hojas aunque coincidan otras claves.
        key = (row["__dojo_sha256"], row["__dojo_sheet"], *(row[N + f] for f in fields))
        groups[key].append(row)
    return [sorted(group, key=_sort) for _, group in sorted(groups.items(), key=lambda item: str(item[0]))]


def _windows(rows, seconds, minimum, distinct=None, min_distinct=1, weight=None, min_weight=0):
    """Ventanas máximas hacia adelante, inclusivas y sin encadenar episodios.

    Avanza un registro si no cumple. Si cumple, consume la ventana completa.
    Dos punteros y contador evitan rescans O(n²) cuando el umbral no se alcanza.
    """
    left = right = 0
    counts = Counter()
    total = 0
    while left < len(rows):
        while right < len(rows) and (rows[right][N + "timestamp"] - rows[left][N + "timestamp"]).total_seconds() <= seconds:
            if distinct:
                counts[rows[right][distinct]] += 1
            if weight:
                total += rows[right][weight]
            right += 1
        if right - left >= minimum and (not distinct or len(counts) >= min_distinct) and total >= min_weight:
            yield rows[left:right]
            left = right
            counts.clear()
            total = 0
        else:
            if distinct:
                value = rows[left][distinct]
                counts[value] -= 1
                if not counts[value]:
                    del counts[value]
            if weight:
                total -= rows[left][weight]
            left += 1


def executable(command):
    if not command:
        return None
    # Solo el ejecutable al inicio, incluyendo ruta entre comillas. No buscar
    # nombres de ejecutables en argumentos ni en texto arbitrario del registro.
    match = re.match(r'^\s*(?:"([^"\r\n]+\.exe)"|([^\s"\r\n]+\.exe))(?=\s|$)', command, re.I)
    return (match.group(1) or match.group(2)).casefold() if match else None


def command_tags(row):
    command = row[N + "command"] or ""
    exe = executable(command)
    base = re.split(r"[\\/]", exe)[-1] if exe else ""
    tags = []
    if base in ("powershell.exe", "pwsh.exe") and re.search(r"(?:^|\s)-(?:enc|encodedcommand|ec)(?=\s|$)", command, re.I):
        tags.append("powershell_encoded")
    if base == "vssadmin.exe" and re.search(r"\bdelete\s+shadows\b", command, re.I):
        tags.append("shadow_delete")
    description = row[N + "description"] or ""
    if (base in ("net.exe", "net1.exe") and re.search(r"\s(?:view|user|localgroup)\b", command, re.I)) or (
        row[N + "event_id"] == "4104" and re.search(r"\b(?:Get-LocalGroupMember|Get-SmbShare)\b", description, re.I)
    ):
        tags.append("discovery")
    if (base in ("7z.exe", "7za.exe") and re.search(r"\s+a\s", command, re.I)) or (
        base == "tar.exe" and re.search(r"(?:^|\s)-(?:[a-z]*c[a-z]*|create)(?=\s|$)", command, re.I)
    ) or (base in ("powershell.exe", "pwsh.exe") and re.search(r"\bCompress-Archive\b", command, re.I)):
        tags.append("compression")
    if base == "cmd.exe" and re.search(r"\s/c\s+(?:whoami|hostname|ipconfig)(?=\s|$)", command, re.I):
        tags.append("shell_identity")
    return tags


def _rdp(row):
    return bool(re.search(r"\bRDP\b|\bLogonType\s*=\s*10\b", row[N + "description"] or "", re.I))


def _file_target(row):
    for field in ("command", "description"):
        match = re.search(r"(?:^|\b)(?:File access|Detailed file share access):\s*(.+)$", row[N + field] or "", re.I)
        if match:
            return match.group(1).strip().casefold() or None
    return None


def _bytes_out(row):
    command = row[N + "command"] or ""
    # Exactamente un token, sin sumar valores parciales o negativos.
    tokens = re.findall(r"(?:^|\s)bytes_out=([^\s]+)", command, re.I)
    return int(tokens[0]) if len(tokens) == 1 and re.fullmatch(r"\d{1,18}", tokens[0]) else None


def _web_command(row):
    try:
        pairs = parse_qsl(urlsplit(row[N + "command"] or "").query, keep_blank_values=True)
    except ValueError:
        return None
    values = [" ".join(value.casefold().split()) for key, value in pairs
              if key.casefold() in ("cmd", "exec", "command") and value.strip()]
    # No interpretar solicitudes ambiguas con varios parámetros de comando.
    return values[0] if len(values) == 1 else None


def _shell_payload(row):
    command = row[N + "command"] or ""
    exe = executable(command)
    if not exe:
        return None
    base = re.split(r"[\\/]", exe)[-1]
    pattern = r"\s/c\s+(.+)$" if base == "cmd.exe" else r"\s-(?:command|c)\s+(.+)$" if base in ("powershell.exe", "pwsh.exe") else None
    match = re.search(pattern, command, re.I) if pattern else None
    return " ".join(match.group(1).strip('"').casefold().split()) if match else None


def _finding(rule, config, tagged, facts, reason, individual=False):
    unique = {}
    for row, role in tagged:
        key = _ref(row)
        if key not in unique:
            unique[key] = dict(
                file=row["__dojo_file"], sha256=row["__dojo_sha256"], sheet=row["__dojo_sheet"],
                excel_row=int(row["__dojo_row"]), roles=[],
                event_id_excel_type=row["__dojo_event_id_type"],
                **{column: row[column] for column in REQUIRED_COLUMNS},
            )
        if role not in unique[key]["roles"]:
            unique[key]["roles"].append(role)
    evidence = [_jsonable(unique[key]) for key in sorted(unique)]
    payload = dict(engine_version=ENGINE_VERSION, rule_id=rule, parameters=config,
                   evidence=evidence, facts=facts)
    return dict(
        finding_id=f"F-{rule}-{_digest(payload)[:24]}", **payload,
        title=RULES[rule]["name"], rule_triggered=True,
        conditions=RULES[rule]["conditions"],
        status="Indicador" if individual else "Hallazgo sospechoso",
        incident_confirmed=False, reason=reason,
        limitations=list(RULES[rule]["limitations"]),
        alternatives=list(RULES[rule]["alternatives"]),
    )


class _Engine:
    def __init__(self, frame, config):
        self.rows = sorted(frame.to_dict("records"), key=_sort)
        self.config = config
        self.diagnostics = []

    def eligible(self, rule, candidates, fields):
        missing = Counter()
        valid = []
        for row in candidates:
            absent = [field for field in fields if row[N + field] is None]
            missing.update(absent)
            if not absent:
                valid.append(row)
        self.diagnostics.append(dict(
            rule_id=rule, candidate_records=len(candidates), eligible_records=len(valid),
            skipped_incomplete=len(candidates) - len(valid), missing_by_field=dict(missing),
            state="sin_eventos_candidatos" if not candidates else "no_evaluable" if not valid
            else "parcial" if missing else "evaluada",
        ))
        return valid

    def r01(self, p):
        candidates = [r for r in self.rows if r[N + "event_id"] == "4625"]
        valid = self.eligible("R01", candidates, ["timestamp", "host", "ip", "user", "result"])
        valid = [r for r in valid if r[N + "result"] == "failure"]
        for group in _groups(valid, ["host", "ip"]):
            for window in _windows(group, p["window_seconds"], p["min_failures"]):
                users = sorted({r[N + "user"] for r in window})
                classification = "possible_spray" if len(users) >= p["min_users"] else "single_account_repetition" if len(users) == 1 else "multiple_failures"
                successes = [r for r in self.rows if r[N + "event_id"] == "4624"
                             and r[N + "result"] == "success" and r[N + "timestamp"] is not None
                             and _ref(r)[:2] == _ref(window[0])[:2]
                             and r[N + "host"] == window[0][N + "host"] and r[N + "ip"] == window[0][N + "ip"]
                             and r[N + "user"] in users
                             and window[-1][N + "timestamp"] < r[N + "timestamp"]
                             and (r[N + "timestamp"] - window[0][N + "timestamp"]).total_seconds() <= p["window_seconds"]]
                facts = dict(failed_events=len(window), distinct_users=len(users), users=users,
                             classification=classification, later_successes=len(successes))
                yield _finding("R01", p, [(r, "failure") for r in window] + [(r, "later_success_context") for r in successes], facts,
                               f"{len(window)} fallos 4625 en una ventana de hasta {p['window_seconds']} s, contra {len(users)} cuentas; categoría {classification}. Los éxitos son contexto sin causalidad probada.")

    def r02(self, p):
        candidates = [r for r in self.rows if r[N + "event_id"] in ("4625", "4624") and _rdp(r)]
        valid = self.eligible("R02", candidates, ["timestamp", "host", "ip", "user", "destination", "result"])
        for group in _groups(valid, ["host", "ip", "user", "destination"]):
            pending = []
            for row in group:
                if row[N + "event_id"] == "4625" and row[N + "result"] == "failure":
                    pending.append(row)
                elif row[N + "event_id"] == "4624" and row[N + "result"] == "success":
                    failures = [r for r in pending if 0 < (row[N + "timestamp"] - r[N + "timestamp"]).total_seconds() <= p["window_seconds"]]
                    if len(failures) >= p["min_failures"]:
                        yield _finding("R02", p, [(r, "rdp_failure") for r in failures] + [(row, "rdp_success")],
                                       dict(failed_events=len(failures), successful_events=1),
                                       f"{len(failures)} fallos RDP preceden a un éxito RDP con host, IP, usuario y destino coincidentes.")
                    # Un éxito separa episodios, incluso si no se alcanzó el umbral.
                    pending = []

    def r03(self, p):
        candidates = [r.copy() for r in self.rows if r[N + "event_id"] in ("4688", "4104")]
        for row in candidates:
            row[N + "content"] = row[N + "command"] or row[N + "description"]
        valid = self.eligible("R03", candidates, ["content"])
        for row in valid:
            tags = sorted(set(command_tags(row)) & set(p["patterns"]))
            if len(tags) >= p["min_patterns"]:
                yield _finding("R03", p, [(row, "command_indicator")], dict(patterns=tags),
                               "Patrones textuales observados: " + ", ".join(tags) + ". No se infiere el efecto del comando.", True)

    def r04a(self, p):
        candidates = [r.copy() for r in self.rows if r[N + "event_id"] == "4663"]
        for row in candidates:
            row[N + "file_target"] = _file_target(row)
        valid = self.eligible("R04A", candidates, ["timestamp", "host", "user", "ip", "destination", "file_target"])
        for group in _groups(valid, ["host", "user", "ip", "destination"]):
            for window in _windows(group, p["window_seconds"], p["min_events"], N + "file_target", p["min_files"]):
                files = sorted({r[N + "file_target"] for r in window})
                yield _finding("R04A", p, [(r, "file_access") for r in window],
                               dict(access_events=len(window), distinct_files=len(files), files=files),
                               f"{len(window)} registros 4663 con {len(files)} rutas distintas y claves de contexto coincidentes.")

    def r04b(self, p):
        candidates = [r.copy() for r in self.rows if r[N + "event_id"] == "PROXY_ACCESS"
                      and re.search(r"\bHTTPS?\s+POST\s+outbound\b", r[N + "description"] or "", re.I)]
        for row in candidates:
            row[N + "bytes_out"] = _bytes_out(row)
        valid = self.eligible("R04B", candidates, ["timestamp", "host", "user", "ip", "destination", "source", "result", "bytes_out"])
        valid = [r for r in valid if r[N + "source"] == "proxy" and
                 (r[N + "result"] == "allowed" or re.fullmatch(r"http_2\d{2}", r[N + "result"]))]
        for group in _groups(valid, ["host", "user", "ip", "destination"]):
            # El umbral de bytes se evalúa dentro de cada ventana, sin sumar episodios.
            for window in _windows(group, p["window_seconds"], p["min_posts"], weight=N + "bytes_out", min_weight=p["min_bytes"]):
                total = sum(r[N + "bytes_out"] for r in window)
                compression = [r for r in self.rows if r[N + "event_id"] == "4688" and "compression" in command_tags(r)
                               and r[N + "timestamp"] is not None and _ref(r)[:2] == _ref(window[0])[:2]
                               and all(r[N + field] == window[0][N + field] for field in ("host", "user", "ip"))
                               and r[N + "timestamp"] < window[0][N + "timestamp"]
                               and (window[-1][N + "timestamp"] - r[N + "timestamp"]).total_seconds() <= p["window_seconds"]]
                yield _finding("R04B", p, [(r, "outbound_post") for r in window] + [(r, "compression_context") for r in compression],
                               dict(post_events=len(window), recorded_bytes_out=total, compression_context_events=len(compression)),
                               f"{len(window)} POST salientes registran {total} bytes_out; {len(compression)} registros previos de compresión compatibles solo como contexto.")

    def r05a(self, p):
        candidates = [r for r in self.rows if r[N + "event_id"] in p["event_ids"]]
        for row in self.eligible("R05A", candidates, []):
            yield _finding("R05A", p, [(row, "task_creation" if row[N + "event_id"] == "4698" else "service_installation")],
                           dict(event_id=row[N + "event_id"], recorded_result=row[N + "result"]),
                           f"Registro {row[N + 'event_id']} de creación de tarea o instalación de servicio; requiere revisión de autorización.", True)

    def r05b(self, p):
        candidates = [r.copy() for r in self.rows if r[N + "event_id"] == "4688"]
        for row in candidates:
            row[N + "executable"] = executable(row[N + "command"])
        valid = self.eligible("R05B", candidates, ["timestamp", "host", "user", "ip", "executable"])
        for group in _groups(valid, ["host", "user", "ip", "executable"]):
            for window in _windows(group, p["window_seconds"], p["min_executions"]):
                yield _finding("R05B", p, [(r, "recurrent_process_creation") for r in window],
                               dict(process_creation_events=len(window), executable=window[0][N + "executable"]),
                               f"{len(window)} registros 4688 del mismo ejecutable y contexto; no se concluye persistencia maliciosa.")

    def _web(self, rule):
        candidates = [r.copy() for r in self.rows if r[N + "event_id"] == "HTTP_ACCESS"]
        valid = self.eligible(rule, candidates, ["timestamp", "host", "ip", "source", "command"])
        for row in valid:
            row[N + "web_command"] = _web_command(row)
        return [r for r in valid if r[N + "source"] == "iis"]

    def r06a(self, p):
        valid = [r for r in self._web("R06A") if r[N + "web_command"]]
        for group in _groups(valid, ["host", "ip"]):
            for window in _windows(group, p["window_seconds"], p["min_requests"]):
                yield _finding("R06A", p, [(r, "suspicious_request") for r in window],
                               dict(suspicious_requests=len(window), commands=sorted({r[N + "web_command"] for r in window})),
                               f"{len(window)} solicitudes IIS incluyen un parámetro de comando no vacío.", len(window) == 1)

    def r06b(self, p):
        requests = self._web("R06B")
        processes = [r for r in self.rows if r[N + "event_id"] == "4688"]
        # Diagnóstico separado para no ocultar procesos sin identidad o reloj.
        valid = self.eligible("R06B/process", processes, ["timestamp", "host", "ip", "user", "command"])
        for process in valid:
            payload = _shell_payload(process)
            if not process[N + "user"].startswith("iis apppool\\") or not payload:
                continue
            context = [r for r in requests if _ref(r)[:2] == _ref(process)[:2]
                       and r[N + "host"] == process[N + "host"] and r[N + "ip"] == process[N + "ip"]
                       and 0 < (process[N + "timestamp"] - r[N + "timestamp"]).total_seconds() <= p["window_seconds"]]
            matching = [r for r in context if r[N + "web_command"] == payload]
            if len(matching) >= p["min_requests"]:
                matching_refs = {_ref(r) for r in matching}
                yield _finding("R06B", p, [(r, "suspicious_request" if _ref(r) in matching_refs else "http_context") for r in context] + [(process, "iis_shell_process")],
                               dict(matching_requests=len(matching), http_context_events=len(context), process_events=1, matched_command=payload),
                               "Solicitud(es) y proceso IIS posterior coinciden en host, IP y comando literal dentro de la ventana. Asociación observacional, sin RCE confirmada.")


@dataclass
class AnalysisResult:
    report: dict
    normalized: pd.DataFrame


def analyze(imported, overrides=None, enabled=None):
    config = parameters(overrides)
    enabled = tuple(sorted(RULES if enabled is None else enabled))
    if len(set(enabled)) != len(enabled) or any(rule not in RULES for rule in enabled):
        raise ValueError("Selección de reglas inválida.")
    normalized = normalize_records(imported)
    engine = _Engine(normalized.records, config)
    findings = []
    for rule in enabled:
        findings.extend(getattr(engine, rule.lower())(config[rule]))
    findings.sort(key=lambda item: (item["rule_id"], item["finding_id"]))
    for rule in RULES:
        if rule not in enabled:
            engine.diagnostics.append(dict(rule_id=rule, state="desactivada", candidate_records=0,
                                           eligible_records=0, skipped_incomplete=0, missing_by_field={}))
    for item in engine.diagnostics:
        item["findings"] = sum(f["rule_id"] == item["rule_id"].split("/")[0] for f in findings)
    run = dict(engine_version=ENGINE_VERSION, normalization_version=NORMALIZATION_VERSION,
               input_sha256=imported.digest, file=imported.filename, sheet=imported.sheet,
               record_count=len(normalized.records), parameters=config, enabled_rules=list(enabled))
    report = dict(
        **run, analysis_id="A-" + _digest(run), findings=findings,
        diagnostics=engine.diagnostics, normalization_issues=_jsonable(normalized.issues),
        import_issues=_jsonable(imported.issues.to_dict("records")),
        incident_confirmation="No evaluada. Ninguna regla confirma incidentes.",
    )
    return AnalysisResult(report, normalized.records)
