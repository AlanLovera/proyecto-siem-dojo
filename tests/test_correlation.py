"""Enlaces y particiones sobre fixtures sintéticas creadas para pruebas."""

from collections import Counter
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
import unittest

import pandas as pd

from dojo.correlation import correlate, correlation_parameters
from dojo.detection import analyze
from dojo.ingestion import REQUIRED_COLUMNS, import_sheet
from test_detection import imported, process


def signals(times=(0, 1), **changes):
    commands = ["powershell.exe -enc TEST", "vssadmin.exe delete shadows /all /quiet", "net.exe view \\\\TEST"]
    return [process(i, sec, commands[i % len(commands)], **changes) for i, sec in enumerate(times)]


def signal_analysis(events):
    return analyze(imported(events), enabled=["R03"])




def group_for(report, rule, log_id=None):
    return next(g for g in report["groups"] if rule in g["rules"] and
                (log_id is None or any(e["Log_ID"] == log_id for e in g["evidence"])))


class CorrelationTests(unittest.TestCase):
    def test_strong_link_preserves_witness_fields_window_and_rows(self):
        report = correlate(signal_analysis(signals()))
        self.assertEqual(len(report["groups"]), 1)
        link = report["links"][0]
        self.assertEqual(link["kind"], "fuerte")
        self.assertFalse(link["causal"])
        self.assertTrue(link["used_for_grouping"])
        criterion = next(c for c in link["criteria"] if c["criterion"] == "same_host_user_ip")
        self.assertEqual(set(criterion["matched_fields"]), {"host", "user", "ip"})
        self.assertEqual([p["excel_row"] for p in criterion["evidence"]], [2, 3])
        self.assertEqual(criterion["window_basis"], "combined_evidence_span")

    def test_contextual_link_does_not_merge_or_raise_scores(self):
        events = [process(0, 0, "powershell.exe -enc TEST", Hostname="CLIENT"),
                  process(1, 1, "vssadmin.exe delete shadows", Hostname="SERVER")]
        analysis = signal_analysis(events)
        report = correlate(analysis)
        self.assertEqual(len(report["groups"]), 2)
        self.assertEqual(report["links"][0]["kind"], "contextual")
        self.assertEqual(report["links"][0]["criteria"][0]["matched_fields"].keys(), {"user", "ip"})
        self.assertFalse(report["links"][0]["used_for_grouping"])
        self.assertEqual(sorted(g["severity"]["score"] for g in report["groups"]), [20, 40])

    def test_only_time_is_visible_and_never_merges(self):
        events = [process(0, 0, "powershell.exe -enc TEST", Hostname="A", User="A", Source_IP="192.0.2.1"),
                  process(1, 300, "net.exe view \\\\TEST", Hostname="B", User="B", Source_IP="192.0.2.2")]
        report = correlate(signal_analysis(events))
        self.assertEqual(len(report["groups"]), 2)
        self.assertEqual(report["links"][0]["kind"], "temporal")
        self.assertEqual(report["links"][0]["criteria"][0]["observed_seconds"], 300)
        events[1] = process(1, 301, "net.exe view \\\\TEST", Hostname="B", User="B", Source_IP="192.0.2.2")
        self.assertFalse(correlate(signal_analysis(events))["links"])

    def test_strong_window_exact_limit_and_one_second_outside(self):
        self.assertEqual(len(correlate(signal_analysis(signals((0, 1800))))["groups"]), 1)
        report = correlate(signal_analysis(signals((0, 1801))))
        self.assertEqual(len(report["groups"]), 2)
        self.assertFalse(any(l["kind"] == "fuerte" for l in report["links"]))

    def test_context_window_exact_limit(self):
        events = [process(0, 0, "powershell.exe -enc TEST", Hostname="A"),
                  process(1, 600, "vssadmin.exe delete shadows", Hostname="B")]
        self.assertEqual(correlate(signal_analysis(events))["links"][0]["kind"], "contextual")
        events[1] = process(1, 601, "vssadmin.exe delete shadows", Hostname="B")
        self.assertFalse(correlate(signal_analysis(events))["links"])

    def test_no_transitive_closure_even_for_chain_of_strong_edges(self):
        report = correlate(signal_analysis(signals((0, 50, 100))), {"strong_window_seconds": 60})
        self.assertEqual(sorted(len(g["detection_ids"]) for g in report["groups"]), [1, 2])
        external_strong = [l for l in report["links"] if l["kind"] == "fuerte" and not l["used_for_grouping"]]
        self.assertEqual(len(external_strong), 1)
        self.assertIn("transitiva", external_strong[0]["not_merged_reason"])
        for group in report["groups"]:
            member_count = len(group["detection_ids"])
            self.assertEqual(len(group["links"]), member_count * (member_count - 1) // 2)

    def test_group_maximum_span_is_separate_from_pair_window(self):
        report = correlate(signal_analysis(signals((0, 600, 1200))), {"group_window_seconds": 600})
        self.assertEqual(sorted(len(g["detection_ids"]) for g in report["groups"]), [1, 2])

    def test_missing_keys_are_not_shared_identity(self):
        report = correlate(signal_analysis(signals(User=None, Source_IP=None)))
        self.assertEqual(len(report["groups"]), 2)
        self.assertFalse(any(l["kind"] == "fuerte" for l in report["links"]))
        self.assertTrue(all(g["missing_information"] for g in report["groups"]))

    def test_missing_clock_cannot_create_temporal_relationship(self):
        report = correlate(signal_analysis(signals(Timestamp=None)))
        self.assertEqual(len(report["groups"]), 2)
        self.assertFalse(report["links"])
        self.assertTrue(all(g["confidence"]["score"] < 50 for g in report["groups"]))

    def test_duplicate_same_event_can_be_deduplicated_without_clock(self):
        analysis = signal_analysis(signals((0,), Timestamp=None))
        clone = deepcopy(analysis.report["findings"][0])
        clone["finding_id"] += "-duplicate-fixture"
        analysis.report["findings"].append(clone)
        report = correlate(analysis)
        self.assertEqual(report["summary"]["unique_events"], 1)
        self.assertEqual(report["summary"]["duplicate_event_references"], 1)
        self.assertEqual(len(report["groups"]), 1)
        self.assertEqual(report["groups"][0]["investigation_state"], "Indicador")

    def test_host_aliases_not_assumed(self):
        events = [process(0, 0, "powershell.exe -enc TEST", Hostname="DC-01"),
                  process(1, 1, "vssadmin.exe delete shadows", Hostname="DC01")]
        report = correlate(signal_analysis(events))
        self.assertEqual(len(report["groups"]), 2)
        self.assertEqual(report["links"][0]["kind"], "contextual")

    def test_no_cross_file_links(self):
        left = signal_analysis(signals((0,)))
        right = signal_analysis([process(10, 1, "net.exe view \\\\TEST")])
        report = deepcopy(left.report)
        report["findings"] += right.report["findings"]
        combined = replace(left, report=report, normalized=pd.concat([left.normalized, right.normalized], ignore_index=True))
        result = correlate(combined)
        self.assertEqual(len(result["groups"]), 2)
        self.assertFalse(result["links"])

    def test_overlap_is_deduplicated_by_coordinates_not_log_id(self):
        analysis = signal_analysis(signals())
        # IDs repetidos en el origen no sustituyen la coordenada exacta.
        source = imported([process(1, 0, "powershell.exe -enc TEST"), process(1, 1, "net.exe view \\\\TEST")])
        report = correlate(analyze(source, enabled=["R03"]))
        self.assertEqual(report["summary"]["unique_events"], 2)
        self.assertFalse(report["overlaps"])
        self.assertEqual(len(analysis.report["findings"]), 2)

    def test_invalid_or_fabricated_evidence_fails_closed(self):
        for field, value in [("Timestamp", "invented"), ("Log_ID", "invented"), ("sha256", "0" * 64),
                             ("file", "wrong.xlsx"), ("roles", [])]:
            with self.subTest(field=field):
                analysis = signal_analysis(signals((0,)))
                analysis.report["findings"][0]["evidence"][0][field] = value
                with self.assertRaises(ValueError):
                    correlate(analysis)

    def test_duplicate_detection_id_rejected(self):
        analysis = signal_analysis(signals())
        analysis.report["findings"][1]["finding_id"] = analysis.report["findings"][0]["finding_id"]
        with self.assertRaises(ValueError):
            correlate(analysis)

    def test_empty_and_isolated_input(self):
        self.assertEqual(correlate(analyze(imported([])))["summary"]["groups"], 0)
        result = correlate(signal_analysis(signals((0,))))
        self.assertEqual(len(result["groups"]), 1)
        self.assertFalse(result["links"])
        self.assertEqual(result["groups"][0]["investigation_state"], "Indicador")

    def test_parameters_validated_and_limit_never_truncates(self):
        for params in ({"unknown": 1}, {"strong_window_seconds": 0}, {"context_window_seconds": True}, {"max_detections": 1001}):
            with self.subTest(params=params), self.assertRaises(ValueError):
                correlation_parameters(params)
        with self.assertRaisesRegex(ValueError, "parcialmente"):
            correlate(signal_analysis(signals()), {"max_detections": 1})




if __name__ == "__main__":
    unittest.main()
