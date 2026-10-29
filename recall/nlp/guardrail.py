"""Fact guardrail. Extracts every checkable fact from a draft (verdicts, timestamps, dates,
clock times, email addresses, identifiers, record and access counts, patient names) and rejects
the draft if any of them is not in the engine's structured output."""

import json
import re

from recall.engine.rules import VERDICTS
from recall.mocks.synthetic import load_roster

ISO_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\b")
DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
TIME_RE = re.compile(r"(?<![\d:])([01]?\d|2[0-3]):([0-5]\d)(?::[0-5]\d)?(?![\d:])")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
ID_RE = re.compile(r"\b(?:P-\d{4}|A-\d{4}|INC-\d{4}|(?:lk|sh|msg|ord|dlv|doc)_[0-9a-f]{10}|key-[a-z0-9-]+)\b")
PATIENT_RE = re.compile(r"\bP-\d{4}\b")
VERDICT_RE = re.compile(r"\b(" + "|".join(VERDICTS) + r")\b")
NUM = r"(\d+|no|zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)"
RECORD_RE = re.compile(NUM + r"\s+(?:patient\s+|affected\s+)?records?\b", re.I)
ACCESS_RE = re.compile(NUM + r"\s+(?:external\s+|unauthori[sz]ed\s+)?(?:views?|access(?:es)?|uses?|reads?|downloads?)\b", re.I)
WORDS = {"no": 0, "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
         "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12}

RECIPIENT_FACING = {"deletion_request"}
REQUIRES_VERDICT = {"incident_report", "risk_assessment"}


def _num(s):
    return int(s) if s.isdigit() else WORDS[s.lower()]


def _names():
    roster = load_roster()
    full = {f"{p['first']} {p['last']}" for p in roster.values()}
    last = {p["last"] for p in roster.values()}
    return full | last


def allowed_facts(facts):
    blob = json.dumps(facts, sort_keys=True)
    stamps = set(ISO_RE.findall(blob))
    return {
        "timestamps": stamps,
        "dates": {s[:10] for s in stamps},
        "times": {s[11:16] for s in stamps},
        "emails": set(EMAIL_RE.findall(blob)),
        "ids": set(ID_RE.findall(blob)),
    }


def check(kind, text, facts):
    """Returns {'ok': bool, 'violations': [str]}."""
    allowed = allowed_facts(facts)
    v = []

    verdicts = set(VERDICT_RE.findall(text))
    if verdicts - {facts["verdict"]}:
        v.append(f"verdict mismatch: draft states {sorted(verdicts - {facts['verdict']})}, engine says {facts['verdict']}")
    if kind in REQUIRES_VERDICT and facts["verdict"] not in verdicts:
        v.append(f"draft does not state the engine verdict {facts['verdict']}")

    stamps = ISO_RE.findall(text)
    for s in stamps:
        if s not in allowed["timestamps"]:
            v.append(f"timestamp {s} is not in the engine output")
    rest = ISO_RE.sub(" ", text)
    for d in DATE_RE.findall(rest):
        if d not in allowed["dates"]:
            v.append(f"date {d} is not in the engine output")
    for m in TIME_RE.finditer(DATE_RE.sub(" ", rest)):
        hhmm = f"{int(m.group(1)):02d}:{m.group(2)}"
        if hhmm not in allowed["times"]:
            v.append(f"time {m.group(0)} is not in the engine output")

    emails = set(EMAIL_RE.findall(text))
    permitted = allowed["emails"]
    if kind in RECIPIENT_FACING:
        permitted = set(facts.get("deletion_recipients", [])) | {facts["contact"]}
    for e in sorted(emails - permitted):
        v.append(f"email address {e} is not permitted in this draft")

    for i in sorted(set(ID_RE.findall(text))):
        if i not in allowed["ids"]:
            v.append(f"identifier {i} is not in the engine output")
        elif kind in RECIPIENT_FACING and PATIENT_RE.fullmatch(i):
            v.append(f"patient identifier {i} must not appear in a recipient-facing draft")

    for m in RECORD_RE.finditer(text):
        if _num(m.group(1)) != facts["record_count"]:
            v.append(f"record count '{m.group(0)}' does not match engine value {facts['record_count']}")
    for m in ACCESS_RE.finditer(text):
        if _num(m.group(1)) != facts["view_count"]:
            v.append(f"access count '{m.group(0)}' does not match engine value {facts['view_count']}")

    for name in sorted(_names()):
        if re.search(r"\b" + re.escape(name) + r"\b", text):
            v.append(f"patient name '{name}' must not appear in any draft")

    if kind in RECIPIENT_FACING and not (emails & set(facts.get("deletion_recipients", []))):
        v.append("deletion request is not addressed to a recipient identified by the engine")

    return {"ok": not v, "violations": v}
