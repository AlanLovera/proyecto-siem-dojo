"""Public integration checks. No private data and no model inference."""
from copy import deepcopy
from io import BytesIO
from pathlib import Path
import tomllib
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from pypdf import PdfReader
from streamlit.testing.v1 import AppTest
from dojo.correlation import correlate
from dojo.dashboard import DashboardFilters, filter_dashboard
from dojo.detection import analyze
from dojo.ingestion import import_sheet, list_sheets
from dojo.presentation import APP_TITLE
from dojo.report_model import build_report_model
from dojo.report_pdf import KINDS, generate_pdf
from scripts.generate_synthetic_excel import workbook_bytes, synthetic_rows

ROOT = Path(__file__).resolve().parents[1]
MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def load_synthetic():
    return import_sheet(workbook_bytes(), "synthetic_demo.xlsx", "Synthetic Logs")


class SyntheticModuleExecutionTests(unittest.TestCase):
    def test_module_without_pythonpath_creates_valid_excel_and_never_overwrites(self):
        # A fresh interpreter starts at the public root; no import-path setup.
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        with tempfile.TemporaryDirectory(prefix="dojo-synthetic-module-") as directory:
            output = Path(directory) / "synthetic_demo.xlsx"
            command = [sys.executable, "-B", "-m",
                       "scripts.generate_synthetic_excel", str(output)]
            created = subprocess.run(command, cwd=ROOT, env=env,
                                     capture_output=True, text=True,
                                     encoding="utf-8", timeout=60, check=False)
            self.assertEqual(created.returncode, 0, created.stderr)
            self.assertTrue(output.is_file())
            before = output.read_bytes()
            modified = output.stat().st_mtime_ns
            with ZipFile(BytesIO(before)) as archive:
                self.assertIsNone(archive.testzip())
            self.assertEqual(list_sheets(before, output.name), ("Synthetic Logs",))
            imported = import_sheet(before, output.name, "Synthetic Logs")
            self.assertEqual(imported.summary["records"], 12)
            self.assertEqual(imported.records["Log_ID"].tolist(),
                             [f"SYNTH-{i:04d}" for i in range(1, 13)])
            self.assertTrue(imported.records["Event_Description"].str.startswith("SYNTHETIC:").all())
            repeated = subprocess.run(command, cwd=ROOT, env=env,
                                      capture_output=True, text=True,
                                      encoding="utf-8", timeout=60, check=False)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertIn("FileExistsError", repeated.stderr)
            self.assertEqual(output.read_bytes(), before)
            self.assertEqual(output.stat().st_mtime_ns, modified)


class PublicPipelineTests(unittest.TestCase):
    def test_synthetic_provenance_and_neutral_workbook_metadata(self):
        data = workbook_bytes()
        self.assertEqual(list_sheets(data, "synthetic_demo.xlsx"), ("Synthetic Logs",))
        self.assertEqual(len(synthetic_rows()), 12)
        with ZipFile(BytesIO(data)) as archive:
            self.assertIn("DOJO SIEM Analyzer", archive.read("docProps/core.xml").decode())
        result = load_synthetic()
        self.assertEqual(result.summary["records"], 12)
        self.assertTrue(result.records["Log_ID"].str.startswith("SYNTH-").all())
        self.assertTrue(result.records["Event_Description"].str.startswith("SYNTHETIC:").all())

    def test_analysis_correlation_dashboard_and_input_integrity(self):
        source = load_synthetic()
        before = source.records.copy(deep=True)
        analysis = analyze(source)
        report = correlate(analysis)
        self.assertGreater(len(analysis.report["findings"]), 0)
        self.assertGreater(len(report["groups"]), 0)
        self.assertEqual(filter_dashboard(analysis, report).metrics["records"], 12)
        narrowed = filter_dashboard(analysis, report, DashboardFilters(sources=("IIS",)))
        self.assertEqual(narrowed.metrics["records"], 1)
        self.assertTrue(source.records.equals(before))
        self.assertEqual(analysis.report, analyze(source).report)

    def test_three_pdfs_have_neutral_metadata_and_synthetic_evidence(self):
        source = load_synthetic()
        analysis = analyze(source)
        correlation = correlate(analysis)
        model = build_report_model(source, analysis, correlation, "SYNTHETIC demonstration", "2030-01-01")
        for kind in KINDS:
            with self.subTest(kind=kind):
                reader = PdfReader(BytesIO(generate_pdf(model, kind)))
                self.assertGreater(len(reader.pages), 0)
                self.assertEqual(reader.metadata.author, "DOJO SIEM Analyzer")
                self.assertIn("DOJO SIEM Analyzer", reader.metadata.title)
                text = "\n".join(p.extract_text() or "" for p in reader.pages)
                self.assertIn("SYNTHETIC demonstration", text)
                if kind != "corporativo":
                    self.assertIn("SYNTH-", text)

    def test_empty_valid_workbook_does_not_require_case_data(self):
        from test_ingestion import fixture
        source = import_sheet(fixture([]), "empty.xlsx", "Logs")
        analysis = analyze(source)
        self.assertEqual(filter_dashboard(analysis, correlate(analysis)).metrics["records"], 0)


class PublicAppTests(unittest.TestCase):
    def start(self):
        return AppTest.from_file(str(ROOT / "app.py"), default_timeout=30).run()

    def upload(self):
        app = self.start()
        return app.file_uploader(key="excel_upload").set_value(("synthetic_demo.xlsx", workbook_bytes(), MIME)).run()

    def test_start_without_excel_and_public_branding(self):
        with patch("dojo.ai_ui.OllamaClient", side_effect=AssertionError("No provider access")):
            app = self.start()
        self.assertFalse(app.exception)
        self.assertEqual(app.title[0].value, "DOJO SIEM Analyzer")
        self.assertEqual(APP_TITLE, "DOJO SIEM Analyzer")
        self.assertEqual(len(app.metric), 0)
        self.assertNotIn("import_result", app.session_state)
        self.assertTrue(any("Seleccioná" in i.value for i in app.info))

    def test_visual_config_is_dark_local_and_disables_usage_statistics(self):
        cfg = tomllib.loads((ROOT / ".streamlit/config.toml").read_text(encoding="utf8"))
        self.assertEqual(cfg["theme"]["base"], "dark")
        self.assertEqual(cfg["server"]["address"], "127.0.0.1")
        self.assertFalse(cfg["browser"]["gatherUsageStats"])
        self.assertTrue(any("<style>" in m.value for m in self.start().markdown))

    def test_upload_analyze_dashboard_export_and_ai_stays_disabled(self):
        with patch("dojo.ai_ui.OllamaClient", side_effect=AssertionError("No provider access")):
            app = self.upload()
            self.assertFalse(app.exception)
            self.assertEqual(app.session_state["import_result"].summary["records"], 12)
            self.assertFalse(app.checkbox(key="ai_enabled").value)
            app.button(key="run_analysis").click().run()
            app.button(key="run_correlation").click().run()
            self.assertFalse(app.exception)
            self.assertEqual({t.label for t in app.tabs if t.label[:1].isdigit()}, {"1 · Carga y calidad", "2 · Análisis", "3 · Correlación", "4 · Dashboard", "5 · Informes PDF", "6 · Asistencia IA"})
            before = deepcopy(app.session_state["analysis_result"].report)
            app.multiselect(key="dash_filter_sources").set_value(["IIS"]).run()
            self.assertFalse(app.exception)
            app.button(key="generate_reports").click().run(timeout=45)
            self.assertFalse(app.exception)
            self.assertEqual(len(app.get("download_button")), 3)
            self.assertEqual(set(app.session_state["pdf_documents"]), set(KINDS))
            self.assertEqual(app.session_state["analysis_result"].report, before)
            self.assertEqual(app.session_state["pdf_model"]["provenance"]["records"], 12)
            self.assertFalse(app.checkbox(key="ai_enabled").value)

    def test_invalid_upload_rejected_without_partial_results(self):
        app = self.upload()
        app.file_uploader(key="excel_upload").set_value(("invalid.xlsx", b"not an xlsx", MIME)).run()
        self.assertFalse(app.exception)
        self.assertTrue(app.error)
        self.assertNotIn("import_result", app.session_state)


if __name__ == "__main__":
    unittest.main()
