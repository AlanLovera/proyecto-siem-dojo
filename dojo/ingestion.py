"""Lectura de XLSX sin escrituras, evaluación de fórmulas ni acceso a enlaces."""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from io import BytesIO
from pathlib import PurePath
from zipfile import ZipFile

import pandas as pd
from openpyxl import load_workbook


REQUIRED_COLUMNS = (
    "Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP",
    "Destination", "Log_Source", "Event_Description", "Process_CommandLine",
    "Result", "Severity",
)
PREFIX = "__dojo_"
MAX_BYTES = 20 * 1024 * 1024
MAX_EXPANDED_BYTES = 100 * 1024 * 1024
MAX_ROWS = 100_000
MAX_COLUMNS = 100


class ExcelImportError(ValueError):
    """Error de archivo o estructura que puede presentarse al usuario."""


@dataclass
class ImportResult:
    filename: str
    sheet: str
    digest: str
    columns: tuple[str, ...]
    records: pd.DataFrame
    quality: pd.DataFrame
    issues: pd.DataFrame
    summary: dict


def is_blank(value):
    return value is None or (isinstance(value, str) and not value.strip())


def _open(data: bytes, filename: str):
    if PurePath(filename).suffix.lower() != ".xlsx":
        raise ExcelImportError("Solo se admiten archivos .xlsx.")
    if not data:
        raise ExcelImportError("El archivo está vacío.")
    if len(data) > MAX_BYTES:
        raise ExcelImportError("El archivo supera el límite de 20 MiB.")
    try:
        with ZipFile(BytesIO(data)) as archive:
            if sum(item.file_size for item in archive.infolist()) > MAX_EXPANDED_BYTES:
                raise ExcelImportError("El contenido descomprimido supera 100 MiB.")
            names = [name.lower() for name in archive.namelist()]
            if any("vbaproject" in name or "/activex/" in name for name in names):
                raise ExcelImportError("Se rechaza contenido VBA/ActiveX en el archivo.")
        return load_workbook(
            BytesIO(data), read_only=True, data_only=False, keep_links=False,
        )
    except ExcelImportError:
        raise
    except Exception as exc:
        # Frontera de entrada: XML/ZIP corrupto, cifrado o formato no compatible.
        raise ExcelImportError(
            f"No se pudo abrir el XLSX ({type(exc).__name__}). "
            "Verificá que no esté corrupto, cifrado ni renombrado desde otro formato."
        ) from exc


def list_sheets(data: bytes, filename: str) -> tuple[str, ...]:
    workbook = _open(data, filename)
    try:
        names = tuple(workbook.sheetnames)
        if not names:
            raise ExcelImportError("El libro no contiene hojas de cálculo.")
        return names
    finally:
        workbook.close()


def _timestamp(value):
    """Sin inferir zona ni interpretar números como fechas Unix/Excel."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    return None


def import_sheet(data: bytes, filename: str, sheet: str) -> ImportResult:
    digest = sha256(data).hexdigest()
    workbook = _open(data, filename)
    try:
        if sheet not in workbook.sheetnames:
            raise ExcelImportError(f"La hoja solicitada no existe: {sheet}.")
        worksheet = workbook[sheet]
        # No confiar en dimensiones ausentes o incorrectas del exportador.
        worksheet.reset_dimensions()
        rows = worksheet.iter_rows()
        first = next(rows, ())
        headers = [cell.value for cell in first]
        while headers and headers[-1] is None:
            headers.pop()
        if not headers:
            raise ExcelImportError("La hoja está vacía o no tiene cabecera en la fila 1.")
        if len(headers) > MAX_COLUMNS:
            raise ExcelImportError("La hoja supera el límite de 100 columnas.")
        if any(not isinstance(h, str) or is_blank(h) for h in headers):
            raise ExcelImportError("Hay cabeceras vacías o no textuales en la fila 1.")
        duplicates = [h for h, count in Counter(headers).items() if count > 1]
        if duplicates:
            raise ExcelImportError("Columnas duplicadas: " + ", ".join(duplicates))
        missing = [h for h in REQUIRED_COLUMNS if h not in headers]
        if missing:
            raise ExcelImportError("Faltan columnas obligatorias: " + ", ".join(missing))
        if any(h.startswith(PREFIX) for h in headers):
            raise ExcelImportError(f"Las columnas con prefijo {PREFIX} están reservadas.")

        records, issues, event_types = [], [], []
        skipped = 0
        for excel_row, cells in enumerate(rows, start=2):
            if excel_row > MAX_ROWS + 1:
                raise ExcelImportError("La hoja supera el límite de 100.000 filas de datos.")
            if len(cells) > len(headers) and any(
                cell.value is not None for cell in cells[len(headers):]
            ):
                raise ExcelImportError(
                    f"Fila {excel_row}: hay datos en columnas sin cabecera."
                )
            values = [cell.value for cell in cells[:len(headers)]]
            values += [None] * (len(headers) - len(values))
            if all(is_blank(value) for value in values):
                skipped += 1
                continue
            record = dict(zip(headers, values))
            record.update({
                PREFIX + "file": filename, PREFIX + "sheet": sheet,
                PREFIX + "row": excel_row, PREFIX + "sha256": digest,
            })
            event_index = headers.index("Event_ID")
            event_types.append(cells[event_index].data_type if event_index < len(cells) else "n")
            for cell, column in zip(cells, headers):
                if cell.data_type in ("f", "e"):
                    issues.append({
                        "fila_excel": excel_row, "Log_ID": record["Log_ID"],
                        "columna": column, "tipo": "formula" if cell.data_type == "f" else "error_excel",
                        "detalle": "Fórmula conservada como texto; no se evalúa." if cell.data_type == "f"
                        else f"Error de celda de origen: {cell.value}",
                    })
            records.append(record)

        frame = pd.DataFrame(records, columns=headers + [
            PREFIX + "file", PREFIX + "sheet", PREFIX + "row", PREFIX + "sha256",
        ], dtype=object)
        frame[PREFIX + "event_id_type"] = pd.Series(event_types, dtype=object)
        summary, quality = _quality(frame, headers, issues, skipped)
        return ImportResult(
            filename, sheet, digest, tuple(headers), frame, quality,
            pd.DataFrame(issues, columns=["fila_excel", "Log_ID", "columna", "tipo", "detalle"]),
            summary,
        )
    except ExcelImportError:
        raise
    except Exception as exc:
        raise ExcelImportError(
            f"No se pudo leer la hoja ({type(exc).__name__}). No se importaron datos parciales."
        ) from exc
    finally:
        workbook.close()


def _quality(frame, headers, issues, skipped):
    count = len(frame)
    blanks = {h: frame[h].map(is_blank) for h in headers}
    quality = pd.DataFrame([
        {"columna": h, "faltantes": int(mask.sum()),
         "porcentaje_faltante": round(100 * mask.sum() / count, 2) if count else 0.0}
        for h, mask in blanks.items()
    ])
    parsed = frame["Timestamp"].map(_timestamp)
    invalid_times = parsed.map(lambda value: value is None or pd.isna(value))
    missing_ids = blanks["Log_ID"]
    duplicated_ids = frame["Log_ID"].duplicated(keep=False) & ~missing_ids
    for mask, column, kind, detail in [
        (invalid_times, "Timestamp", "timestamp_invalido", "Se espera YYYY-MM-DD HH:MM:SS o celda datetime; sin inferir zona."),
        (missing_ids, "Log_ID", "id_faltante", "El registro se conserva con su fila original."),
        (duplicated_ids, "Log_ID", "id_duplicado", "Log_ID no identifica una fila única; usar archivo, hash, hoja y fila."),
    ]:
        for index in frame.index[mask]:
            issues.append({"fila_excel": frame.at[index, PREFIX + "row"],
                           "Log_ID": frame.at[index, "Log_ID"], "columna": column,
                           "tipo": kind, "detalle": detail})
    # ISO conserva la representación temporal y evita comparar aware con naive.
    valid_times = [value.isoformat(sep=" ") for value in parsed if value is not None and not pd.isna(value)]
    return {
        "records": count, "columns": len(headers),
        "sources": frame.loc[~blanks["Log_Source"], "Log_Source"].nunique(),
        "blank_rows": skipped, "missing_ids": int(missing_ids.sum()),
        "duplicate_id_rows": int(duplicated_ids.sum()),
        "duplicate_rows_without_id": int(frame[[h for h in headers if h != "Log_ID"]].duplicated().sum()),
        "invalid_timestamps": int(invalid_times.sum()),
        "unidentified_users": int(frame["User"].eq("-").sum()),
        "formulas": sum(issue["tipo"] == "formula" for issue in issues),
        "excel_errors": sum(issue["tipo"] == "error_excel" for issue in issues),
        "time_start": min(valid_times) if valid_times else None,
        "time_end": max(valid_times) if valid_times else None,
    }, quality
