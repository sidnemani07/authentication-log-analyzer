"""Authentication Log Analyzer.

Reads authentication events from a CSV or JSON file, flags suspicious login
patterns, and writes findings to CSV and JSON for analyst review.

Usage:
    python src/authentication_log_analyzer.py sample-data/logins.csv
"""

import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime as dt
from datetime import timedelta as td
from pathlib import Path


class LogAnalyzer:
    # ---- Detection thresholds (tune these; see README "Limitations") ----
    FAIL_THRESHOLD = 5            # failures that count as brute force
    WINDOW = td(minutes=10)       # time window for brute force / success-after-failures
    SPRAY_USER_THRESHOLD = 5      # distinct usernames failing from one IP
    SUCCESS_AFTER_FAILS = 3       # failures before a success is suspicious

    VALID_RESULTS = {"success", "failure"}

    # ------------------------------------------------------------------
    # Command-line arguments
    # ------------------------------------------------------------------
    @staticmethod
    def parse_args():
        parser = argparse.ArgumentParser(
            description="Analyse authentication logs for suspicious activity."
        )
        parser.add_argument("input_file", help="Path to a .csv or .json log file")
        return parser.parse_args()

    # ------------------------------------------------------------------
    # Step 1: Load either format into the same shape
    # ------------------------------------------------------------------
    def normalize(self, record):
        """Clean one raw record. Return None if it is malformed."""
        try:
            event = {
                "timestamp": dt.fromisoformat(record["timestamp"].strip()),
                "username": record["username"].strip(),
                "source_ip": record["source_ip"].strip(),
                "result": record["result"].strip().lower(),
                "event_type": record.get("event_type", "login").strip(),
            }
        except (KeyError, ValueError, AttributeError):
            return None

        # Reject empty identifiers and results the detections cannot interpret.
        if not event["username"] or not event["source_ip"]:
            return None
        if event["result"] not in self.VALID_RESULTS:
            return None
        return event

    def load_csv(self, path):
        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    def load_json(self, path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("JSON file must contain a list of records")
        return data

    def load_events(self, path):
        suffix = Path(path).suffix.lower()
        if suffix == ".csv":
            raw = self.load_csv(path)
        elif suffix == ".json":
            raw = self.load_json(path)
        else:
            raise ValueError(f"Unsupported file type: {suffix}")

        events, skipped = [], 0
        for record in raw:
            event = self.normalize(record)
            if event:
                events.append(event)
            else:
                skipped += 1
        events.sort(key=lambda e: e["timestamp"])
        return events, skipped

    # ------------------------------------------------------------------
    # Step 2: Find the suspicious ones
    # ------------------------------------------------------------------
    def detect_brute_force(self, events):
        groups = defaultdict(list)
        for e in events:
            if e["result"] == "failure":
                groups[(e["source_ip"], e["username"])].append(e["timestamp"])

        findings = []
        for (ip, user), times in groups.items():
            start = 0
            for end in range(len(times)):
                while times[end] - times[start] > self.WINDOW:
                    start += 1
                if end - start + 1 >= self.FAIL_THRESHOLD:
                    findings.append({
                        "detection": "brute_force",
                        "source_ip": ip,
                        "targeted_users": user,
                        "count": len(times),
                        "first_seen": times[0].isoformat(),
                        "last_seen": times[-1].isoformat(),
                        "severity": "high",
                    })
                    break
        return findings

    def detect_password_spray(self, events):
        users_by_ip = defaultdict(set)
        for e in events:
            if e["result"] == "failure":
                users_by_ip[e["source_ip"]].add(e["username"])
        return [
            {
                "detection": "password_spray",
                "source_ip": ip,
                "targeted_users": ";".join(sorted(users)),
                "count": len(users),
                "severity": "medium",
            }
            for ip, users in users_by_ip.items()
            if len(users) >= self.SPRAY_USER_THRESHOLD
        ]

    def detect_success_after_failures(self, events):
        findings = []
        for i, e in enumerate(events):
            if e["result"] != "success":
                continue
            recent_fails = [
                f for f in events[:i]
                if f["result"] == "failure"
                and f["source_ip"] == e["source_ip"]
                and f["username"] == e["username"]
                and e["timestamp"] - f["timestamp"] <= self.WINDOW
            ]
            if len(recent_fails) >= self.SUCCESS_AFTER_FAILS:
                findings.append({
                    "detection": "success_after_failures",
                    "source_ip": e["source_ip"],
                    "targeted_users": e["username"],
                    "count": len(recent_fails),
                    "first_seen": recent_fails[0]["timestamp"].isoformat(),
                    "last_seen": e["timestamp"].isoformat(),
                    "severity": "critical",
                })
        return findings

    def run_detections(self, events):
        return (
            self.detect_brute_force(events)
            + self.detect_password_spray(events)
            + self.detect_success_after_failures(events)
        )

    # ------------------------------------------------------------------
    # Step 3: Write findings
    # ------------------------------------------------------------------
    def write_findings(self, findings,
                       csv_path="output/findings.csv",
                       json_path="output/findings.json"):
        Path(json_path).parent.mkdir(parents=True, exist_ok=True)
        Path(csv_path).parent.mkdir(parents=True, exist_ok=True)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)

        fields = ["detection", "severity", "source_ip", "targeted_users",
                  "count", "first_seen", "last_seen"]
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields,
                                    extrasaction="ignore", restval="")
            writer.writeheader()
            writer.writerows(findings)


def main():
    args = LogAnalyzer.parse_args()
    analyzer = LogAnalyzer()

    try:
        events, skipped = analyzer.load_events(args.input_file)
    except FileNotFoundError:
        raise SystemExit(f"Error: file not found: {args.input_file}")
    except ValueError as err:
        raise SystemExit(f"Error: {err}")

    print(f"Loaded {len(events)} events ({skipped} malformed records skipped)")

    findings = analyzer.run_detections(events)
    for f in findings:
        print(f"[{f['severity'].upper()}] {f['detection']} from {f['source_ip']} "
              f"({f['count']} events)")
    analyzer.write_findings(findings)
    print(f"Wrote {len(findings)} findings to output/findings.csv and output/findings.json")


if __name__ == "__main__":
    main()
