"""Puntuación por hechos únicos, sin inflar por activaciones superpuestas."""

from copy import deepcopy
import unittest

from dojo.correlation import correlate
from dojo.detection import analyze
from dojo.risk import DEFAULT_MODEL, model_parameters
from test_correlation import group_for, signal_analysis, signals
from test_detection import event, imported, post, process


class RiskTests(unittest.TestCase):
    def test_single_creation_title_does_not_invent_other_activity(self):
        for code, present, absent in ((4698, "tarea", ("servicio", "proceso")),
                                      (7045, "servicio", ("tarea", "proceso"))):
            group = correlate(analyze(imported([event(1, event_id=code)]), enabled=["R05A"]))["groups"][0]
            self.assertIn(present, group["title"].casefold())
            for word in absent:
                self.assertNotIn(word, group["title"].casefold())

    def test_single_indicator_low_potential_risk_with_reasoned_confidence(self):
        group = correlate(signal_analysis(signals((0,))))["groups"][0]
        self.assertEqual((group["severity"]["label"], group["severity"]["score"]), ("Bajo", 20))
        self.assertEqual((group["confidence"]["label"], group["confidence"]["score"]), ("Media", 50))
        self.assertEqual(group["investigation_state"], "Indicador")
        self.assertTrue(group["severity"]["factors"])
        self.assertTrue(group["confidence"]["factors"])

    def test_original_siem_severity_alone_cannot_change_risk(self):
        scores = []
        for original_severity in ("Informational", "High", "Critical", None):
            group = correlate(signal_analysis(signals((0,), Severity=original_severity)))["groups"][0]
            scores.append((group["severity"]["label"], group["severity"]["score"]))
        self.assertEqual(len(set(scores)), 1)

    def test_threshold_exact_boundary(self):
        analysis = signal_analysis(signals((0,)))
        model = {"severity_thresholds": {"Medio": 20, "Alto": 50, "Crítico": 85}}
        self.assertEqual(correlate(analysis, risk_model=model)["groups"][0]["severity"]["label"], "Medio")
        model["severity_thresholds"]["Medio"] = 21
        self.assertEqual(correlate(analysis, risk_model=model)["groups"][0]["severity"]["label"], "Bajo")
        model["severity_thresholds"] = {"Medio": 10, "Alto": 20, "Crítico": 85}
        self.assertEqual(correlate(analysis, risk_model=model)["groups"][0]["severity"]["label"], "Alto")

    def test_critical_needs_score_and_potential_impact_gate(self):
        analysis = signal_analysis([process(0, 0, "vssadmin.exe delete shadows")])
        model = {"severity_thresholds": {"Medio": 10, "Alto": 30, "Crítico": 40}}
        group = correlate(analysis, risk_model=model)["groups"][0]
        self.assertEqual(group["severity"]["score"], 40)
        self.assertEqual(group["severity"]["label"], "Alto")
        self.assertFalse(group["severity"]["critical_gate_satisfied"])
        model["critical_min_impact_families"] = 1
        group = correlate(analysis, risk_model=model)["groups"][0]
        self.assertEqual(group["severity"]["label"], "Crítico")
        self.assertFalse(group["confirmed_impact"])
        self.assertFalse(group["incident_confirmed"])

    def test_diverse_potential_impacts_can_reach_critical_without_confirming_damage(self):
        events = signals() + [process(2, 2, "7z.exe a archive.7z files")]
        events += [post(i + 3, i + 3, 30 * 1024 * 1024) for i in range(5)]
        report = correlate(analyze(imported(events), enabled=["R03", "R04B"]))
        self.assertEqual(len(report["groups"]), 1)
        group = report["groups"][0]
        self.assertEqual(group["severity"]["score"], 100)
        self.assertEqual(group["severity"]["label"], "Crítico")
        self.assertTrue(all(not impact["confirmed"] for impact in group["severity"]["potential_impacts"]))
        self.assertFalse(group["confirmed_impact"])

    def test_incomplete_data_lowers_confidence_and_is_explicit(self):
        group = correlate(signal_analysis(signals((0,), Timestamp=None, User=None, Source_IP=None)))["groups"][0]
        self.assertEqual((group["confidence"]["label"], group["confidence"]["score"]), ("Baja", 25))
        self.assertTrue(any("timestamp" in text for text in group["missing_information"]))
        self.assertEqual(group["investigation_state"], "Indicador")

    def test_confidence_boundary_is_inclusive(self):
        analysis = signal_analysis(signals((0,)))
        model = {"confidence_thresholds": {"Media": 50, "Alta": 80}}
        self.assertEqual(correlate(analysis, risk_model=model)["groups"][0]["confidence"]["label"], "Media")
        model["confidence_thresholds"] = {"Media": 49, "Alta": 50}
        self.assertEqual(correlate(analysis, risk_model=model)["groups"][0]["confidence"]["label"], "Alta")



    def test_duplicate_rule_activation_is_not_new_evidence(self):
        analysis = signal_analysis(signals((0,)))
        first = correlate(analysis)["groups"][0]
        for i in range(3):
            clone = deepcopy(analysis.report["findings"][0])
            clone["finding_id"] += f"-fixture-{i}"
            analysis.report["findings"].append(clone)
        second = correlate(analysis)["groups"][0]
        self.assertEqual(first["severity"], second["severity"])
        self.assertEqual(first["confidence"], second["confidence"])
        self.assertEqual(second["investigation_state"], "Indicador")
        self.assertEqual(len(second["evidence"]), 1)





    def test_invalid_review_cannot_fabricate_corroboration_or_discard(self):
        analysis = signal_analysis(signals((0,)))
        group = correlate(analysis)["groups"][0]
        e = group["evidence"][0]
        ref = {k: e[k] for k in ("sha256", "sheet", "excel_row")}
        for decision in [dict(state="Descartado", reason="", evidence=[ref]),
                         dict(state="Descartado", reason="test", evidence=[]),
                         dict(state="Corroborado", reason="test", evidence=[ref]),
                         dict(state="Descartado", reason="test", evidence=[{**ref, "excel_row": 9999}])]:
            with self.subTest(decision=decision), self.assertRaises(ValueError):
                correlate(analysis, reviews={group["group_id"]: decision})
        with self.assertRaises(ValueError):
            correlate(analysis, reviews={"unknown": {}})


    def test_model_validation_and_default_not_mutated(self):
        original = deepcopy(DEFAULT_MODEL)
        for model in [[], {"unknown": 1}, {"weights": {"unknown": 1}}, {"weights": {"encoded_powershell": -1}},
                      {"weights": {"encoded_powershell": True}}, {"large_volume_bytes": 0},
                      {"severity_thresholds": {"Medio": 50, "Alto": 50}},
                      {"confidence_thresholds": {"Alta": 20}}, {"corroboration_min_confidence": 101}]:
            with self.subTest(model=model), self.assertRaises(ValueError):
                model_parameters(model)
        model_parameters({"weights": {"encoded_powershell": 0}})
        self.assertEqual(DEFAULT_MODEL, original)


if __name__ == "__main__":
    unittest.main()
