"""Fixtures sintéticas en memoria, sin registros de ningún caso de estudio."""

from hashlib import sha256
from io import BytesIO
from pathlib import Path
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from openpyxl import Workbook

from dojo.ingestion import ExcelImportError, REQUIRED_COLUMNS, import_sheet, list_sheets
from dojo.query import display_records, filter_records




def row(**changes):
    values = dict(zip(REQUIRED_COLUMNS, [
        "TEST-1", "2026-10-23 07:46:07", "TEST-HOST", 4624, "TEST-USER",
        "192.0.2.1", None, "Security", "Fixture de prueba", None, "Success", "Informational",
    ]))
    values.update(changes)
    return [values[h] for h in REQUIRED_COLUMNS]


def fixture(rows=None, headers=REQUIRED_COLUMNS, second=False):
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = "Logs"
    if headers is not None:
        worksheet.append(list(headers))
    for values in rows or []:
        worksheet.append(values)
    if second:
        other = workbook.create_sheet("Otra hoja")
        other.append(list(REQUIRED_COLUMNS))
        other.append(row(Log_ID="TEST-OTHER"))
    stream = BytesIO()
    workbook.save(stream)
    workbook.close()
    return stream.getvalue()


class IngestionTests(unittest.TestCase):

    def test_blank_rows_do_not_shift_provenance(self):
        result = import_sheet(fixture([row(), [None] * 12, row(Log_ID="TEST-2")]), "test.xlsx", "Logs")
        self.assertEqual(result.records["__dojo_row"].tolist(), [2, 4])
        self.assertEqual(result.summary["blank_rows"], 1)

    def test_missing_columns(self):
        with self.assertRaisesRegex(ExcelImportError, "Timestamp"):
            import_sheet(fixture(headers=["Log_ID"]), "test.xlsx", "Logs")

    def test_duplicate_headers(self):
        with self.assertRaisesRegex(ExcelImportError, "duplicadas"):
            import_sheet(fixture(headers=[*REQUIRED_COLUMNS, "Log_ID"]), "test.xlsx", "Logs")

    def test_blank_header_and_orphan_data(self):
        for headers, values in [([*REQUIRED_COLUMNS, None, "Extra"], None), (REQUIRED_COLUMNS, [*row(), "orphan"])]:
            with self.subTest(headers=headers), self.assertRaises(ExcelImportError):
                import_sheet(fixture([values] if values else [], headers=headers), "test.xlsx", "Logs")

    def test_reserved_headers(self):
        with self.assertRaisesRegex(ExcelImportError, "reservadas"):
            import_sheet(fixture(headers=[*REQUIRED_COLUMNS, "__dojo_row"]), "test.xlsx", "Logs")

    def test_extra_column_is_preserved(self):
        result = import_sheet(fixture([[*row(), "extra"]], headers=[*REQUIRED_COLUMNS, "Extra"]), "test.xlsx", "Logs")
        self.assertEqual(result.records.iloc[0]["Extra"], "extra")

    def test_invalid_files(self):
        for data, name in [(b"", "empty.xlsx"), (b"not an excel", "invalid.xlsx"), (fixture(), "test.xlsm")]:
            with self.subTest(name=name), self.assertRaises(ExcelImportError):
                list_sheets(data, name)

    def test_wrong_zip_format(self):
        stream = BytesIO()
        with ZipFile(stream, "w") as archive:
            archive.writestr("unrelated.txt", "fixture")
        with self.assertRaises(ExcelImportError):
            list_sheets(stream.getvalue(), "test.xlsx")

    def test_size_limits(self):
        data = fixture([row(), row(Log_ID="TEST-2")])
        for variable in ("MAX_BYTES", "MAX_EXPANDED_BYTES", "MAX_COLUMNS", "MAX_ROWS"):
            with self.subTest(variable=variable), patch("dojo.ingestion." + variable, 1):
                with self.assertRaises(ExcelImportError):
                    import_sheet(data, "test.xlsx", "Logs")

    def test_active_parts_rejected(self):
        stream = BytesIO(fixture())
        with ZipFile(stream, "a") as archive:
            archive.writestr("xl/vbaProject.bin", b"inert fixture")
        with self.assertRaisesRegex(ExcelImportError, "VBA/ActiveX"):
            list_sheets(stream.getvalue(), "test.xlsx")

    def test_empty_sheet_and_header_only(self):
        with self.assertRaisesRegex(ExcelImportError, "vacía"):
            import_sheet(fixture(headers=None), "test.xlsx", "Logs")
        result = import_sheet(fixture(), "test.xlsx", "Logs")
        self.assertEqual(result.summary["records"], 0)
        self.assertTrue(result.issues.empty)

    def test_sheet_selection(self):
        data = fixture([row()], second=True)
        self.assertEqual(list_sheets(data, "test.xlsx"), ("Logs", "Otra hoja"))
        result = import_sheet(data, "test.xlsx", "Otra hoja")
        self.assertEqual(result.records.iloc[0]["Log_ID"], "TEST-OTHER")
        with self.assertRaisesRegex(ExcelImportError, "no existe"):
            import_sheet(data, "test.xlsx", "Missing")

    def test_quality_errors_do_not_drop_rows(self):
        result = import_sheet(fixture([
            row(), row(Timestamp="invalid", User="-"), row(Log_ID=None, Timestamp=None),
        ]), "test.xlsx", "Logs")
        self.assertEqual(result.summary["records"], 3)
        self.assertEqual(result.summary["duplicate_id_rows"], 2)
        self.assertEqual(result.summary["missing_ids"], 1)
        self.assertEqual(result.summary["invalid_timestamps"], 2)
        self.assertEqual(result.summary["unidentified_users"], 1)
        self.assertEqual(len(result.issues), 5)

    def test_formulas_and_excel_errors_are_inert_and_reported(self):
        result = import_sheet(fixture([row(Process_CommandLine="=1+1", Result="#DIV/0!")]), "test.xlsx", "Logs")
        self.assertEqual(result.records.iloc[0]["Process_CommandLine"], "=1+1")
        self.assertEqual(result.summary["formulas"], 1)
        self.assertEqual(result.summary["excel_errors"], 1)
        self.assertEqual(set(result.issues["fila_excel"]), {2})

    def test_mixed_types_and_markers_remain_original(self):
        result = import_sheet(fixture([
            row(Event_ID=4624, User="-", Hostname="DC-01"),
            row(Log_ID="NA", Event_ID="HTTP_ACCESS", Hostname="DC01"),
        ]), "test.xlsx", "Logs")
        self.assertIsInstance(result.records.iloc[0]["Event_ID"], int)
        self.assertEqual(result.records.iloc[0]["User"], "-")
        self.assertEqual(result.records.iloc[1]["Log_ID"], "NA")
        self.assertEqual(result.records["Hostname"].nunique(), 2)
        self.assertEqual(display_records(result.records).iloc[0]["Event_ID"], "4624")

    def test_literal_filter_and_sort_keep_references(self):
        result = import_sheet(fixture([row(), row(Log_ID="TEST-2", Log_Source="IIS", Severity="High")]), "test.xlsx", "Logs")
        filtered = filter_records(result.records, "test-2", ["IIS"], ["High"]).sort_values("Log_ID")
        self.assertEqual(filtered["__dojo_row"].tolist(), [3])
        self.assertTrue(filter_records(result.records, "[").empty)
        self.assertEqual(len(result.records), 2)


if __name__ == "__main__":
    unittest.main()
