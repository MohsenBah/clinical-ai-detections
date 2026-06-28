#!/usr/bin/env python3
"""
Validate Clinical AI Gateway detection rules against wazuh/tests/validation-cases.json.

Modes:
  --offline   Rule logic simulation (default, CI-friendly; no Wazuh required)
  --wazuh     Run /var/ossec/bin/wazuh-logtest when available on the host
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CASES_FILE = ROOT / "wazuh" / "tests" / "validation-cases.json"

BLOCKED_PATTERN = re.compile(r"^blocked_pattern:")
ADMIN_SCOPE = re.compile(r"^blocked_admin_scope:")
PHI_QUERY = re.compile(
    r"(?i).*(ssn|social security|date of birth|dob|address|insurance|"
    r"phone number|contact info|medical record).*"
)
SYSTEM_PROMPT = re.compile(r"system prompt", re.I)
INSTRUCTION_OVERRIDE = re.compile(r"ignore all previous instructions", re.I)

# Repeated-injection correlation (rule 100200): 3 blocks per user in 5 min.
CORRELATION_WINDOW_SEC = 300
CORRELATION_MIN_MATCHES = 3
# Repeated-ingestion-failure correlation (rule 100321): 3 failures per collection in 10 min.
INGESTION_WINDOW_SEC = 600
INGESTION_MIN_MATCHES = 3


@dataclass
class CorrelationState:
    """Tracks rule fires per key for offline frequency-rule simulation."""

    window_sec: int = CORRELATION_WINDOW_SEC
    min_matches: int = CORRELATION_MIN_MATCHES
    hits: dict[str, list[float]] = field(default_factory=dict)

    def record(self, key: str, timestamp: float) -> bool:
        self.hits.setdefault(key, []).append(timestamp)
        window_start = timestamp - self.window_sec
        recent = [t for t in self.hits[key] if t >= window_start]
        self.hits[key] = recent
        return len(recent) >= self.min_matches


def parse_timestamp(value: str) -> float:
    from datetime import datetime

    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized).timestamp()


def match_rule_100100(event: dict[str, Any]) -> bool:
    return (
        event.get("event_type") == "query"
        and event.get("decision") == "blocked"
        and bool(BLOCKED_PATTERN.match(str(event.get("reason", ""))))
    )


def match_rule_100101(event: dict[str, Any]) -> bool:
    return match_rule_100100(event) and bool(
        SYSTEM_PROMPT.search(str(event.get("reason", "")))
    )


def match_rule_100102(event: dict[str, Any]) -> bool:
    return match_rule_100100(event) and bool(
        INSTRUCTION_OVERRIDE.search(str(event.get("reason", "")))
    )


def match_rule_100300(event: dict[str, Any]) -> bool:
    query = str(event.get("query", ""))
    return event.get("event_type") == "query" and bool(PHI_QUERY.search(query))


def match_rule_100310(event: dict[str, Any]) -> bool:
    return (
        event.get("event_type") == "query"
        and event.get("decision") == "blocked"
        and bool(ADMIN_SCOPE.match(str(event.get("reason", ""))))
    )


def match_rule_100320(event: dict[str, Any]) -> bool:
    return (
        event.get("event_type") == "ingestion"
        and event.get("status") == "failed"
    )


def match_rule_100400(event: dict[str, Any]) -> bool:
    return (
        event.get("event_type") == "query"
        and event.get("query_length_bucket") == "large"
    )


def match_rule_100401(event: dict[str, Any]) -> bool:
    return match_rule_100400(event) and event.get("decision") == "blocked"


def evaluate_offline(
    event: dict[str, Any],
    correlation: CorrelationState,
    ingestion_correlation: CorrelationState | None = None,
) -> set[str]:
    matched: set[str] = set()

    if match_rule_100100(event):
        matched.add("100100")
    if match_rule_100101(event):
        matched.add("100101")
    if match_rule_100102(event):
        matched.add("100102")
    if match_rule_100300(event):
        matched.add("100300")
    if match_rule_100310(event):
        matched.add("100310")
    if match_rule_100320(event):
        matched.add("100320")
    if match_rule_100400(event):
        matched.add("100400")
    if match_rule_100401(event):
        matched.add("100401")

    if match_rule_100100(event):
        user_id = str(event.get("user_id", ""))
        ts = parse_timestamp(str(event.get("timestamp", "1970-01-01T00:00:00+00:00")))
        if correlation.record(user_id, ts):
            matched.add("100200")

    if match_rule_100320(event) and ingestion_correlation is not None:
        collection = str(event.get("collection_name", ""))
        ts = parse_timestamp(str(event.get("timestamp", "1970-01-01T00:00:00+00:00")))
        if ingestion_correlation.record(collection, ts):
            matched.add("100321")

    return matched


def parse_logtest_rules(output: str) -> set[str]:
    rules: set[str] = set()
    for line in output.splitlines():
        line = line.strip()
        if "Rule:" in line or "rule id" in line.lower():
            for token in re.findall(r"\b100\d{3}\b", line):
                rules.add(token)
        for token in re.findall(r"\bid:['\"]?(100\d{3})['\"]?", line, re.I):
            rules.add(token)
    if "100" in output:
        for token in re.findall(r"\b(100\d{3})\b", output):
            rules.add(token)
    return rules


def evaluate_wazuh(event: dict[str, Any], logtest_bin: str) -> set[str]:
    payload = json.dumps(event, ensure_ascii=False)
    proc = subprocess.run(
        [logtest_bin],
        input=f"{payload}\n\n",
        capture_output=True,
        text=True,
        timeout=30,
    )
    combined = proc.stdout + proc.stderr
    if proc.returncode != 0 and not re.search(r"\b100\d{3}\b", combined):
        raise RuntimeError(f"wazuh-logtest failed:\n{combined}")
    return parse_logtest_rules(combined)


def load_cases(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def check_case(
    case_id: str,
    matched: set[str],
    expect: list[str],
    reject: list[str],
) -> list[str]:
    errors: list[str] = []
    expect_set = set(expect)
    reject_set = set(reject)

    missing = sorted(expect_set - matched)
    if missing:
        errors.append(f"{case_id}: missing expected rules {missing} (got {sorted(matched)})")

    unexpected_reject = sorted(reject_set & matched)
    if unexpected_reject:
        errors.append(
            f"{case_id}: matched rejected rules {unexpected_reject} (got {sorted(matched)})"
        )

    return errors


def run_offline(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    correlation = CorrelationState()
    ingestion_correlation = CorrelationState(
        window_sec=INGESTION_WINDOW_SEC, min_matches=INGESTION_MIN_MATCHES
    )

    for case in data.get("cases", []):
        matched = evaluate_offline(case["event"], correlation, ingestion_correlation)
        errors.extend(
            check_case(
                case["id"],
                matched,
                case.get("expect_rules", []),
                case.get("reject_rules", []),
            )
        )

    for sequence in data.get("sequences", []):
        seq_correlation = CorrelationState()
        seq_ingestion_correlation = CorrelationState(
            window_sec=INGESTION_WINDOW_SEC, min_matches=INGESTION_MIN_MATCHES
        )
        expectations = sequence.get("expect_rules_per_event", [])
        for idx, event in enumerate(sequence.get("events", [])):
            matched = evaluate_offline(
                event, seq_correlation, seq_ingestion_correlation
            )
            if idx < len(expectations):
                errors.extend(
                    check_case(
                        f"{sequence['id']}[{idx}]",
                        matched,
                        expectations[idx],
                        [],
                    )
                )

    return errors


def run_wazuh(data: dict[str, Any], logtest_bin: str) -> list[str]:
    errors: list[str] = []

    for case in data.get("cases", []):
        matched = evaluate_wazuh(case["event"], logtest_bin)
        errors.extend(
            check_case(
                case["id"],
                matched,
                case.get("expect_rules", []),
                case.get("reject_rules", []),
            )
        )

    for sequence in data.get("sequences", []):
        expectations = sequence.get("expect_rules_per_event", [])
        for idx, event in enumerate(sequence.get("events", [])):
            matched = evaluate_wazuh(event, logtest_bin)
            if idx < len(expectations):
                errors.extend(
                    check_case(
                        f"{sequence['id']}[{idx}]",
                        matched,
                        expectations[idx],
                        [],
                    )
                )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Wazuh detection rules")
    parser.add_argument(
        "--cases",
        type=Path,
        default=CASES_FILE,
        help="Path to validation-cases.json",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Offline rule simulation (default when --wazuh is not set)",
    )
    parser.add_argument(
        "--wazuh",
        action="store_true",
        help="Use wazuh-logtest binary on this host",
    )
    parser.add_argument(
        "--logtest-bin",
        default="/var/ossec/bin/wazuh-logtest",
        help="Path to wazuh-logtest",
    )
    args = parser.parse_args()

    if not args.cases.exists():
        print(f"Cases file not found: {args.cases}", file=sys.stderr)
        return 1

    data = load_cases(args.cases)
    case_count = len(data.get("cases", [])) + len(data.get("sequences", []))

    if args.wazuh:
        if not shutil.which(args.logtest_bin) and not Path(args.logtest_bin).exists():
            print(
                f"wazuh-logtest not found at {args.logtest_bin}. "
                "Use --offline for CI or install Wazuh manager.",
                file=sys.stderr,
            )
            return 1
        errors = run_wazuh(data, args.logtest_bin)
        mode_label = "wazuh-logtest"
    else:
        errors = run_offline(data)
        mode_label = "offline"

    if errors:
        print(f"FAILED ({mode_label}): {len(errors)} issue(s)")
        for err in errors:
            print(f"  - {err}")
        return 1

    print(f"PASSED ({mode_label}): {case_count} case group(s) validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
