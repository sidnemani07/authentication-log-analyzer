import csv
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from authentication_log_analyzer import LogAnalyzer

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_CSV = ROOT / "sample-data" / "logins.csv"
SAMPLE_JSON = ROOT / "sample-data" / "logins.json"


@pytest.fixture
def analyzer():
    return LogAnalyzer()


@pytest.fixture(params=[SAMPLE_CSV, SAMPLE_JSON], ids=["csv", "json"])
def sample(request, analyzer):
    """Load the sample data in each format and run every detection."""
    events, skipped = analyzer.load_events(request.param)
    return events, skipped, analyzer.run_detections(events)


def ev(seconds, user="admin", ip="203.0.113.9", result="failure"):
    """Build a normalised event `seconds` after a fixed start time."""
    return {
        "timestamp": datetime(2026, 11, 8, 2, 0, 0) + timedelta(seconds=seconds),
        "username": user,
        "source_ip": ip,
        "result": result,
        "event_type": "ssh_login",
    }


# ---------------------------------------------------------------- loading
def test_sample_counts(sample):
    events, skipped, _ = sample
    assert len(events) == 43
    assert skipped == 2


def test_events_are_sorted_by_time(sample):
    events, _, _ = sample
    times = [e["timestamp"] for e in events]
    assert times == sorted(times)


def test_csv_and_json_give_identical_events(analyzer):
    assert analyzer.load_events(SAMPLE_CSV)[0] == analyzer.load_events(SAMPLE_JSON)[0]


def test_unsupported_file_type_raises(analyzer, tmp_path):
    bad = tmp_path / "logins.txt"
    bad.write_text("hello")
    with pytest.raises(ValueError):
        analyzer.load_events(bad)


def test_json_must_be_a_list(analyzer, tmp_path):
    bad = tmp_path / "logins.json"
    bad.write_text('{"not": "a list"}')
    with pytest.raises(ValueError):
        analyzer.load_events(bad)


@pytest.mark.parametrize("record", [
    {"timestamp": "not-a-date", "username": "a", "source_ip": "1.2.3.4", "result": "failure"},
    {"timestamp": "2026-11-08T02:00:00", "source_ip": "1.2.3.4", "result": "failure"},
    {"timestamp": "2026-11-08T02:00:00", "username": "a", "source_ip": "", "result": "failure"},
    {"timestamp": "2026-11-08T02:00:00", "username": "a", "source_ip": "1.2.3.4", "result": "maybe"},
    {"timestamp": None, "username": "a", "source_ip": "1.2.3.4", "result": "failure"},
], ids=["bad-date", "missing-username", "empty-ip", "unknown-result", "null-timestamp"])
def test_malformed_records_are_rejected(analyzer, record):
    assert analyzer.normalize(record) is None


def test_normalize_cleans_whitespace_and_case(analyzer):
    event = analyzer.normalize({
        "timestamp": " 2026-11-08T02:00:00 ", "username": " sid ",
        "source_ip": " 10.0.0.1 ", "result": " FAILURE ",
    })
    assert event["username"] == "sid"
    assert event["source_ip"] == "10.0.0.1"
    assert event["result"] == "failure"


# ------------------------------------------------- detections on sample data
def pairs(findings, name):
    return {(f["source_ip"], f["targeted_users"]) for f in findings if f["detection"] == name}


def test_brute_force_detected(sample):
    _, _, findings = sample
    assert pairs(findings, "brute_force") == {
        ("198.51.100.23", "root"),
        ("203.0.113.45", "admin"),
    }


def test_password_spray_detected(sample):
    _, _, findings = sample
    spray = [f for f in findings if f["detection"] == "password_spray"]
    assert len(spray) == 1
    assert spray[0]["source_ip"] == "192.0.2.77"
    assert spray[0]["count"] == 7


def test_success_after_failures_detected(sample):
    _, _, findings = sample
    assert pairs(findings, "success_after_failures") == {
        ("203.0.113.45", "admin"),
        ("192.168.1.35", "dave"),   # known false positive: forgetful user
    }
    assert all(f["severity"] == "critical"
               for f in findings if f["detection"] == "success_after_failures")


def test_normal_activity_is_not_flagged(sample):
    _, _, findings = sample
    flagged_users = {u for f in findings for u in f["targeted_users"].split(";")}
    assert not flagged_users & {"sid", "alice", "bob", "carol"}


def test_total_finding_count(sample):
    assert len(sample[2]) == 5


# ----------------------------------------------------- threshold boundaries
def test_brute_force_needs_five_failures(analyzer):
    four = [ev(i * 60) for i in range(4)]
    five = [ev(i * 60) for i in range(5)]
    assert analyzer.detect_brute_force(four) == []
    assert len(analyzer.detect_brute_force(five)) == 1


def test_brute_force_failures_must_fall_inside_window(analyzer):
    spread_out = [ev(i * 180) for i in range(5)]   # 12 minutes end to end
    assert analyzer.detect_brute_force(spread_out) == []


def test_brute_force_is_per_ip_and_user(analyzer):
    mixed = [ev(i * 10, user=f"user{i}") for i in range(5)]
    assert analyzer.detect_brute_force(mixed) == []


def test_password_spray_needs_five_users(analyzer):
    four = [ev(i, user=f"user{i}") for i in range(4)]
    five = [ev(i, user=f"user{i}") for i in range(5)]
    assert analyzer.detect_password_spray(four) == []
    assert len(analyzer.detect_password_spray(five)) == 1


def test_password_spray_ignores_successes(analyzer):
    events = [ev(i, user=f"user{i}", result="success") for i in range(6)]
    assert analyzer.detect_password_spray(events) == []


def test_success_after_three_failures_flagged(analyzer):
    events = [ev(0), ev(10), ev(20), ev(30, result="success")]
    assert len(analyzer.detect_success_after_failures(events)) == 1


def test_success_after_two_failures_not_flagged(analyzer):
    events = [ev(0), ev(10), ev(30, result="success")]
    assert analyzer.detect_success_after_failures(events) == []


def test_success_after_old_failures_not_flagged(analyzer):
    events = [ev(0), ev(10), ev(20), ev(700, result="success")]
    assert analyzer.detect_success_after_failures(events) == []


def test_success_from_a_different_ip_not_flagged(analyzer):
    events = [ev(0), ev(10), ev(20), ev(30, ip="198.51.100.1", result="success")]
    assert analyzer.detect_success_after_failures(events) == []


# --------------------------------------------------------------- reporting
def test_write_findings_creates_csv_and_json(analyzer, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    events, _ = analyzer.load_events(SAMPLE_CSV)
    findings = analyzer.run_detections(events)
    analyzer.write_findings(findings)

    with open(tmp_path / "output" / "findings.json", encoding="utf-8") as f:
        assert json.load(f) == findings
    with open(tmp_path / "output" / "findings.csv", newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == len(findings)
    assert rows[0]["detection"] == findings[0]["detection"]


def test_write_findings_with_no_findings_writes_header_only(analyzer, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    analyzer.write_findings([])
    text = (tmp_path / "output" / "findings.csv").read_text(encoding="utf-8")
    assert text.strip().startswith("detection,severity")
    assert len(text.strip().splitlines()) == 1
