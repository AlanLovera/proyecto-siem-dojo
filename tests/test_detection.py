"""Reglas contra fixtures exclusivamente sintéticas; los comandos son texto inerte."""

from collections import Counter
from dataclasses import replace
from datetime import datetime, time, timedelta, timezone
from hashlib import sha256
import json
import unittest

import pandas as pd

from dojo.detection import analyze
from dojo.ingestion import REQUIRED_COLUMNS, import_sheet
from dojo.normalization import N, normalize_records
from dojo.rules import RULES, parameters
from test_ingestion import fixture, row


def event(index, seconds=0, event_id=4625, **changes):
    values = dict(Log_ID=f"TEST-{index}", Timestamp=(datetime(2026, 10, 23) + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S"),
                  Event_ID=event_id, Result="Failure" if event_id == 4625 else "Success")
    values.update(changes)
    return row(**values)


def imported(events):
    return import_sheet(fixture(events), "synthetic.xlsx", "Logs")


def run(rule, events, **params):
    return analyze(imported(events), {rule: params}, [rule]).report


def found(rule, events, **params):
    return run(rule, events, **params)["findings"]


def failures(last=900):
    return [event(i, seconds=t, User=f"SYNTHETIC_LAB\\U{i % 3}") for i, t in enumerate([0, 1, 2, 3, last])]


def rdp(index, sec, success=False, **changes):
    values = dict(Destination="TEST-HOST", Event_Description="LogonType=10; RDP")
    values.update(changes)
    return event(index, sec, 4624 if success else 4625, **values)


def access(index, sec, **changes):
    values = dict(Destination="\\\\TEST-HOST\\Share", Process_CommandLine=f"File access: Share\\doc{index}.txt")
    values.update(changes)
    return event(index, sec, 4663, **values)


def post(index, sec, byte_count=100, **changes):
    values = dict(Log_Source="Proxy", Destination="192.0.2.2:443", Event_Description="HTTPS POST outbound",
                  Process_CommandLine=f"bytes_out={byte_count} uri=/upload", Result="Allowed")
    values.update(changes)
    return event(index, sec, "PROXY_ACCESS", **values)


def process(index, sec, command="C:\\ProgramData\\worker.exe", **changes):
    return event(index, sec, 4688, Process_CommandLine=command, **changes)


def web(index, sec, url="/test?cmd=whoami", **changes):
    values = dict(Log_Source="IIS", User="-", Destination="TEST-HOST:443", Process_CommandLine=url, Result="200")
    values.update(changes)
    return event(index, sec, "HTTP_ACCESS", **values)


def iis_process(index=2, sec=300, **changes):
    values = dict(User="IIS APPPOOL\\TestPool")
    values.update(changes)
    return process(index, sec, "cmd.exe /c whoami", **values)


class NormalizationTests(unittest.TestCase):
    def test_preserves_all_source_values_and_provenance(self):
        source = imported([event(1, User=" SYNTHETIC_LAB\\ADMIN ", Hostname=" DC-01 ", Source_IP="2001:0db8::0001", Event_ID=4624.0, Result="200"),
                           event(2, User="-", Hostname="DC01", Source_IP="not-an-ip", Timestamp="invalid")])
        before = source.records.copy(deep=True)
        normalized = normalize_records(source)
        pd.testing.assert_frame_equal(source.records, before)
        pd.testing.assert_frame_equal(normalized.records[before.columns], before)
        f = normalized.records
        self.assertEqual(f.at[0, N + "user"], "synthetic_lab\\admin")
        self.assertIsNone(f.at[1, N + "user"])
        self.assertNotEqual(f.at[0, N + "host"], f.at[1, N + "host"])
        self.assertEqual(f.at[0, N + "ip"], "2001:db8::1")
        self.assertIsNone(f.at[1, N + "ip"])
        self.assertEqual(f.at[0, N + "event_id"], "4624")
        self.assertEqual(f.at[0, N + "result"], "http_200")
        self.assertIsNone(f.at[0, N + "timestamp"].tzinfo)
        self.assertIsNone(f.at[1, N + "timestamp"])
        self.assertEqual(len(normalized.issues), 2)

    def test_formula_and_error_cells_cannot_supply_normalized_keys_or_commands(self):
        source = imported([event(1, Timestamp="=1+1", Source_IP="#VALUE!", Process_CommandLine='=powershell.exe -enc TEST', Event_ID=4688)])
        normalized = normalize_records(source)
        for name in ("timestamp", "ip", "command"):
            self.assertIsNone(normalized.records.at[0, N + name])
        self.assertFalse(analyze(source, enabled=["R03"]).report["findings"])
        self.assertEqual(source.records.at[0, "Timestamp"], "=1+1")

    def test_aware_timestamp_is_preserved_and_not_mixed_with_local_clock(self):
        source = imported([event(1)])
        original = datetime(2026, 10, 23, tzinfo=timezone.utc)
        source.records.at[0, "Timestamp"] = original
        result = normalize_records(source)
        self.assertEqual(result.records.at[0, "Timestamp"], original)
        self.assertIsNone(result.records.at[0, N + "timestamp"])

    def test_ambiguous_provenance_is_rejected(self):
        source = imported([event(1), event(2)])
        source.records.at[1, "__dojo_row"] = 2
        with self.assertRaisesRegex(ValueError, "procedencia"):
            normalize_records(source)

    def test_nat_is_missing_and_never_used_as_temporal_key(self):
        source = imported(failures())
        source.records.at[0, "Timestamp"] = pd.NaT
        report = analyze(source, enabled=["R01"]).report
        self.assertFalse(report["findings"])
        self.assertEqual(report["diagnostics"][0]["skipped_incomplete"], 1)


class RuleTests(unittest.TestCase):
    def test_r01_threshold_and_inclusive_window(self):
        self.assertEqual(found("R01", failures())[0]["facts"]["distinct_users"], 3)
        self.assertFalse(found("R01", failures(901)))
        self.assertFalse(found("R01", failures()[:4]))
        self.assertFalse(found("R01", failures(), min_failures=6))
        self.assertEqual(found("R01", failures(), min_users=4)[0]["facts"]["classification"], "multiple_failures")

    def test_r01_single_account_is_not_password_spray(self):
        events = [event(i, i) for i in range(5)]
        self.assertEqual(found("R01", events)[0]["facts"]["classification"], "single_account_repetition")

    def test_r01_success_context_requires_exact_keys_order_and_window(self):
        events = failures(4)
        for changes, expected in [({}, 1), ({"Source_IP": "192.0.2.9"}, 0), ({"Hostname": "OTHER"}, 0), ({"User": "OTHER"}, 0)]:
            with self.subTest(changes=changes):
                success = event(20, 900, 4624, User="SYNTHETIC_LAB\\U0")
                for key, value in changes.items():
                    success[list(REQUIRED_COLUMNS).index(key)] = value
                self.assertEqual(found("R01", events + [success])[0]["facts"]["later_successes"], expected)
        self.assertEqual(found("R01", events + [event(20, 901, 4624, User="SYNTHETIC_LAB\\U0")])[0]["facts"]["later_successes"], 0)

    def test_r01_missing_data_and_different_hosts_do_not_join(self):
        events = [event(i, i, User=f"U{i}", Hostname=f"H{i}") for i in range(5)]
        self.assertFalse(found("R01", events))
        report = run("R01", [event(i, i, Source_IP=None) for i in range(5)])
        self.assertFalse(report["findings"])
        self.assertEqual(report["diagnostics"][0]["state"], "no_evaluable")
        self.assertEqual(report["diagnostics"][0]["skipped_incomplete"], 5)

    def test_r02_threshold_window_and_explicit_rdp(self):
        events = [rdp(i, i) for i in range(3)]
        self.assertEqual(found("R02", events + [rdp(4, 900, True)])[0]["facts"]["failed_events"], 3)
        self.assertFalse(found("R02", events + [rdp(4, 901, True)]))
        self.assertFalse(found("R02", events[:2] + [rdp(4, 900, True)]))
        self.assertFalse(found("R02", events + [event(4, 900, 4624, Destination="TEST-HOST")]))
        self.assertFalse(found("R02", events + [rdp(4, 900, True)], min_failures=4))

    def test_r02_no_cross_identity_no_reversed_or_equal_time_sequence(self):
        events = [rdp(i, i) for i in range(3)]
        for field in ("User", "Hostname", "Source_IP", "Destination"):
            with self.subTest(field=field):
                value = "192.0.2.99" if field == "Source_IP" else "OTHER"
                self.assertFalse(found("R02", events + [rdp(4, 10, True, **{field: value})]))
                self.assertFalse(found("R02", events + [rdp(4, 10, True, **{field: None})]))
        self.assertFalse(found("R02", [rdp(i, 0) for i in range(3)] + [rdp(4, 0, True)]))
        self.assertFalse(found("R02", [rdp(4, 0, True)] + [rdp(i, i + 1) for i in range(3)]))

    def test_r03_each_pattern_and_parameter_selection(self):
        examples = [
            ("powershell.exe -EncodedCommand REDACTED", "powershell_encoded"),
            ('"C:\\Windows\\powershell.exe" -enc TEST', "powershell_encoded"),
            ("vssadmin.exe delete shadows /all /quiet", "shadow_delete"),
            ("net.exe view \\\\HOST", "discovery"),
            ("tar.exe -a -c -f archive.zip files", "compression"),
            ("7z.exe a archive.7z files", "compression"),
            ("cmd.exe /c whoami", "shell_identity"),
        ]
        for command, expected in examples:
            with self.subTest(command=command):
                results = found("R03", [process(1, 0, command)])
                self.assertIn(expected, results[0]["facts"]["patterns"])
                self.assertEqual(results[0]["status"], "Indicador")
                self.assertFalse(found("R03", [process(1, 0, command)], min_patterns=2))
        self.assertFalse(found("R03", [process(1, 0, examples[0][0])], patterns=["shadow_delete"]))
        script = event(1, event_id=4104, Event_Description="PowerShell Script Block: Get-SmbShare", Process_CommandLine="powershell.exe")
        self.assertEqual(found("R03", [script])[0]["facts"]["patterns"], ["discovery"])

    def test_r03_incomplete_and_benign_commands(self):
        for command in ("explorer.exe", "powershell.exe -Encoding UTF8", "echo.exe powershell.exe -enc TEST", None):
            with self.subTest(command=command):
                self.assertFalse(found("R03", [process(1, 0, command)]))
        self.assertTrue(found("R03", [process(1, 0, "powershell.exe -enc TEST", Event_Description=None, Timestamp=None)]))
        self.assertFalse(found("R03", [event(1, event_id=4672, Process_CommandLine="powershell.exe -enc TEST")]))

    def test_r04a_counts_distinct_files_and_window(self):
        events = [access(i, sec) for i, sec in enumerate([0, 1, 2, 3, 300])]
        facts = found("R04A", events)[0]["facts"]
        self.assertEqual((facts["access_events"], facts["distinct_files"]), (5, 5))
        self.assertFalse(found("R04A", events[:4]))
        self.assertFalse(found("R04A", events, min_files=6))
        self.assertFalse(found("R04A", events, min_events=6))
        self.assertFalse(found("R04A", events[:4] + [access(4, 301)]))
        self.assertFalse(found("R04A", [access(i, i, Process_CommandLine="File access: same.txt") for i in range(5)]))

    def test_r04a_missing_path_and_context_not_invented(self):
        self.assertFalse(found("R04A", [access(i, i, Process_CommandLine=None) for i in range(5)]))
        for field in ("User", "Hostname", "Source_IP", "Destination"):
            with self.subTest(field=field):
                self.assertFalse(found("R04A", [access(i, i, **{field: None}) for i in range(5)]))

    def test_r04b_byte_count_post_threshold_and_window(self):
        events = [post(i, sec) for i, sec in enumerate([0, 1, 2, 3, 600])]
        self.assertEqual(found("R04B", events, min_bytes=500)[0]["facts"]["recorded_bytes_out"], 500)
        self.assertFalse(found("R04B", events, min_bytes=501))
        self.assertFalse(found("R04B", events, min_bytes=500, min_posts=6))
        self.assertFalse(found("R04B", events[:4] + [post(4, 601)], min_bytes=500))

    def test_r04b_weighted_sliding_window_does_not_miss_later_episode(self):
        events = [post(0, 0, 0), post(1, 500, 200), post(2, 600, 200), post(3, 700, 200)]
        result = found("R04B", events, min_posts=2, min_bytes=500)
        self.assertEqual(result[0]["facts"]["recorded_bytes_out"], 600)
        self.assertEqual([e["Log_ID"] for e in result[0]["evidence"]], ["TEST-1", "TEST-2", "TEST-3"])

    def test_r04b_unknown_or_invalid_bytes_are_not_zero(self):
        for command in (None, "bytes_out=-1", "bytes_out=abc", "bytes_out=100 bytes_out=200", "bytes_out=100abc"):
            with self.subTest(command=command):
                report = run("R04B", [post(i, i) for i in range(4)] + [post(4, 4, Process_CommandLine=command)], min_bytes=1)
                self.assertFalse(report["findings"])
                self.assertEqual(report["diagnostics"][0]["skipped_incomplete"], 1)

    def test_r04b_compression_context_requires_keys_and_complete_window(self):
        events = [post(i, i + 1) for i in range(5)]
        command = "7z.exe a archive.7z files"
        result = found("R04B", [process(10, 0, command)] + events, min_bytes=500)
        self.assertEqual(result[0]["facts"]["compression_context_events"], 1)
        for change in ({"Source_IP": "192.0.2.9"}, {"Hostname": "OTHER"}, {"User": "OTHER"}, {"Timestamp": "2026-10-22 23:00:00"}):
            with self.subTest(change=change):
                result = found("R04B", [process(10, 0, command, **change)] + events, min_bytes=500)
                self.assertEqual(result[0]["facts"]["compression_context_events"], 0)
        self.assertFalse(found("R04B", [process(1, 0, command), event(2, 1, 5156, Result="Allowed")]))

    def test_r05a_individual_descriptive_events_and_selection(self):
        for code in (4698, 7045):
            result = found("R05A", [event(1, event_id=code, User=None, Hostname=None)])
            self.assertEqual(result[0]["facts"]["event_id"], str(code))
            self.assertEqual(result[0]["status"], "Indicador")
        self.assertFalse(found("R05A", [event(1, event_id=4672)]))
        self.assertFalse(found("R05A", [event(1, event_id=4698)], event_ids=["7045"]))

    def test_r05b_same_executable_threshold_and_window(self):
        events = [process(i, sec, f"worker.exe --argument {i}") for i, sec in enumerate([0, 1, 1800])]
        self.assertEqual(found("R05B", events)[0]["facts"]["process_creation_events"], 3)
        self.assertFalse(found("R05B", events, min_executions=4))
        self.assertFalse(found("R05B", events[:2] + [process(2, 1801, "worker.exe")]))

    def test_r05b_no_alias_or_context_guessing(self):
        self.assertFalse(found("R05B", [process(0, 0, "worker.exe"), process(1, 1, "C:\\worker.exe"), process(2, 2, "D:\\worker.exe")]))
        self.assertFalse(found("R05B", [process(i, i, None) for i in range(3)]))
        for field in ("Hostname", "User", "Source_IP"):
            with self.subTest(field=field):
                value = "192.0.2.9" if field == "Source_IP" else "OTHER"
                self.assertFalse(found("R05B", [process(0, 0), process(1, 1), process(2, 2, **{field: value})]))

    def test_r06a_request_threshold_and_window(self):
        self.assertEqual(found("R06A", [web(1, 0)])[0]["facts"]["commands"], ["whoami"])
        self.assertTrue(found("R06A", [web(1, 0), web(2, 300)], min_requests=2))
        self.assertFalse(found("R06A", [web(1, 0), web(2, 301)], min_requests=2))
        self.assertFalse(found("R06A", [web(1, 0)], min_requests=2))
        for url in ("/safe", "/?cmd=", "/?cmd=whoami&exec=dir"):
            with self.subTest(url=url):
                self.assertFalse(found("R06A", [web(1, 0, url)]))

    def test_r06b_context_command_threshold_and_window(self):
        result = found("R06B", [web(1, 0), web(3, 100, "/safe"), iis_process()])[0]
        self.assertEqual(result["facts"], dict(matching_requests=1, http_context_events=2, process_events=1, matched_command="whoami"))
        self.assertEqual(result["evidence"][1]["roles"], ["http_context"])
        self.assertFalse(found("R06B", [web(1, 0), iis_process(sec=301)]))
        self.assertFalse(found("R06B", [web(1, 0), iis_process(sec=0)]))
        self.assertFalse(found("R06B", [web(1, 0), iis_process()], min_requests=2))
        self.assertTrue(found("R06B", [web(1, 0), web(3, 1), iis_process()], min_requests=2))

    def test_r06b_never_links_isolated_or_mismatched_events(self):
        self.assertFalse(found("R06B", [web(1, 0)]))
        self.assertFalse(found("R06B", [iis_process()]))
        for changes in ({"User": "SYNTHETIC_LAB\\admin"}, {"User": None}, {"Hostname": "OTHER"}, {"Source_IP": "192.0.2.99"}, {"Source_IP": None}):
            with self.subTest(changes=changes):
                self.assertFalse(found("R06B", [web(1, 0), iis_process(**changes)]))
        self.assertFalse(found("R06B", [web(1, 0, "/?cmd=dir"), iis_process()]))
        self.assertFalse(found("R06B", [web(1, 0, Hostname="DC-01"), iis_process(Hostname="DC01")]))

    def test_r06_url_decoded_once_without_executing(self):
        self.assertTrue(found("R06B", [web(1, 0, "/?cmd=who%61mi"), iis_process()]))
        self.assertFalse(found("R06B", [web(1, 0, "/?cmd=%2577hoami"), iis_process()]))

    def test_windows_do_not_chain_beyond_configured_span(self):
        events = [process(i, i * 1000, "worker.exe") for i in range(5)]
        self.assertFalse(found("R05B", events, window_seconds=1800, min_executions=3))

    def test_temporal_rules_do_not_fire_on_single_record(self):
        samples = {"R01": event(1), "R02": rdp(1, 0), "R04A": access(1, 0),
                   "R04B": post(1, 0, 9999999), "R05B": process(1, 0), "R06B": web(1, 0)}
        for rule, sample in samples.items():
            with self.subTest(rule=rule):
                self.assertFalse(found(rule, [sample]))

    def test_no_cross_sheet_or_file_grouping(self):
        source = imported([process(i, i) for i in range(3)])
        for field in ("__dojo_sheet", "__dojo_sha256"):
            records = source.records.copy(deep=True)
            records.at[2, field] = "Other" if field == "__dojo_sheet" else "0" * 64
            report = analyze(replace(source, records=records), enabled=["R05B"]).report
            self.assertFalse(report["findings"])

    def test_incomplete_data_is_safe_and_visible(self):
        events = [event(i, event_id=code, Timestamp=None, User=None, Hostname=None, Source_IP=None,
                        Destination=None, Process_CommandLine=None, Event_Description=None, Result=None)
                  for i, code in enumerate([4624, 4625, 4688, 4663, "HTTP_ACCESS", "PROXY_ACCESS", 4672])]
        report = analyze(imported(events)).report
        self.assertFalse(report["findings"])
        self.assertTrue(report["normalization_issues"])
        self.assertTrue(any(d["state"] == "no_evaluable" for d in report["diagnostics"]))


class ReproducibilityTests(unittest.TestCase):
    def test_excel_time_cell_is_serializable_without_overwriting_original(self):
        source = imported([event(1, event_id=4698, Process_CommandLine=time(12, 30))])
        self.assertIsInstance(source.records.at[0, "Process_CommandLine"], time)
        report = analyze(source, enabled=["R05A"]).report
        json.dumps(report, allow_nan=False)
        self.assertEqual(report["findings"][0]["evidence"][0]["Process_CommandLine"], "12:30:00")
        self.assertIsInstance(source.records.at[0, "Process_CommandLine"], time)
    def test_reproducible_json_ids_and_source_unchanged(self):
        source = imported(failures())
        before = source.records.copy(deep=True)
        first = analyze(source).report
        second = analyze(source).report
        shuffled = replace(source, records=source.records.sample(frac=1, random_state=42))
        self.assertEqual(first, second)
        self.assertEqual(first, analyze(shuffled).report)
        self.assertEqual(json.loads(json.dumps(first, allow_nan=False)), first)
        pd.testing.assert_frame_equal(source.records, before)
        changed = analyze(source, {"R01": {"window_seconds": 901}}).report
        self.assertNotEqual(first["analysis_id"], changed["analysis_id"])
        self.assertNotEqual(first["findings"][0]["finding_id"], changed["findings"][0]["finding_id"])

    def test_parameters_validate_and_disabled_rules_are_reported(self):
        for overrides in ({"R00": {}}, {"R01": {"missing": 1}}, {"R01": {"min_users": 1}},
                          {"R02": {"min_failures": 0}}, {"R02": {"window_seconds": True}},
                          {"R03": {"patterns": []}}, {"R05A": {"event_ids": ["4672"]}}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                parameters(overrides)
        source = imported(failures())
        self.assertFalse(analyze(source, enabled=[]).report["findings"])
        self.assertTrue(all(d["state"] == "desactivada" for d in analyze(source, enabled=[]).report["diagnostics"]))
        with self.assertRaises(ValueError):
            analyze(source, enabled=["R00"])

    def test_empty_dataset_and_all_4672_are_not_confirmations(self):
        for source in (imported([]), imported([event(i, event_id=4672) for i in range(5)])):
            report = analyze(source).report
            self.assertFalse(report["findings"])
            self.assertIn("Ninguna regla confirma", report["incident_confirmation"])



if __name__ == "__main__":
    unittest.main()
