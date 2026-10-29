"""Fuzzing.

Part 1, verdict safety. Random incidents with random access events and random faults (missing
logs, truncated logs, missing coverage metadata, clock skew, failed revocations, partial failures).
Ground truth comes from the mocks' raw logs, which the engine never sees. Targets:
  - zero false CONTAINED / REVERSED (a "safe" verdict when data was accessed or evidence was degraded)
  - zero false EXPOSED (an exposure claimed when nothing was accessed)
  - exact verdicts whenever no fault was injected

Part 2, guardrail. Every template draft from part 1 is mutated (verdict, timestamp, clock time,
record count, access count, email address, identifier, patient name). Target: zero mutated drafts pass.

    python3 validation/fuzz.py [--n 600] [--seed 7]
"""

import argparse
import random
import sys

from common import ROOT  # noqa: F401  (sets sys.path)

from recall.config import ORG_DOMAIN, is_internal
from recall.mocks.synthetic import load_roster
from recall.nlp import guardrail
from recall.scenario import run_scenario

SECRET = "rcl_live_FuZzKeY0123456789abcdef"
FILE = {"id": "F-9000", "name": "fuzz_export.csv", "records": ["P-1003", "P-1004", "P-1005"]}
EXTERNAL = ["intake@riverside-clinic.example", "x.ray@freemail.example", "ip:203.0.113.9"]
INTERNAL = [f"staff@{ORG_DOMAIN}", "svc:fuzz-worker", "ip:10.0.0.7"]
KINDS = ["link", "link2", "share", "key", "mail", "order"]
SYSTEM = {"link": "links", "link2": "links", "share": "files", "key": "vault", "mail": "mail", "order": "orders"}
SAFE = {"CONTAINED", "REVERSED"}


def hms(sec):
    return f"+{sec // 3600:02d}:{sec % 3600 // 60:02d}:{sec % 60:02d}"


def gen(rng, i):
    kind = rng.choice(KINDS)
    incident = rng.randint(120, 4 * 3600)
    spec = {"id": f"fuzz{i}", "start": "2026-06-01T08:00:00Z", "incident": {"at": hms(incident)},
            "setup": {"files": [FILE], "keys": [{"id": "key-fuzz", "secret": SECRET, "service": "svc:fuzz-worker"}]},
            "events": []}
    recips = ["intake@riverside-clinic.example"]
    if kind in ("link", "link2"):
        if kind == "link2":
            recips = ["intake@riverside-clinic.example", "x.ray@freemail.example"]
        spec["action"] = {"tool": "send_email", "args": {"to": recips, "records": ["P-1010"]}}
        ev = "link_view"
    elif kind == "share":
        spec["action"] = {"tool": "share_file", "args": {"file_id": "F-9000"}}
        ev = "file_access"
    elif kind == "key":
        spec["action"] = {"tool": "send_email", "args": {"to": ["dev@vendor.example"], "body": SECRET}}
        ev = "key_use"
    elif kind == "mail":
        recips = [f"wrong.person@{ORG_DOMAIN}"]
        spec["action"] = {"tool": "send_email", "args": {"to": recips, "records": ["P-1011"]}}
        ev = "mail_read"
    else:
        spec["action"] = {"tool": rng.choice(["create_order", "issue_refund"]), "args": {"counterparty": "v", "amount": 10}}
        ev = "order_fulfill"

    for _ in range(rng.randint(0, 3)):
        at = rng.randint(1, incident + 3600)
        if ev == "order_fulfill":
            spec["events"].append({"at": hms(at), "type": ev})
            continue
        if ev == "mail_read":
            actor = rng.choice(recips + [f"other@{ORG_DOMAIN}"])
        else:
            actor = rng.choice(EXTERNAL + INTERNAL if ev != "link_view" else recips + INTERNAL[:1])
        e = {"at": hms(at), "type": ev, "actor": actor}
        if ev == "link_view":
            e["recipient"] = rng.choice(recips)
        spec["events"].append(e)

    faults = {}
    sysname = SYSTEM[kind]
    if rng.random() < 0.5:
        f = rng.choice(["unavailable", "truncate", "coverage", "skew", "fail", "fail_partial"])
        if f == "unavailable":
            faults["log_unavailable"] = [sysname]
        elif f == "truncate":
            faults["log_truncated_before"] = {sysname: hms(rng.randint(1, incident))}
        elif f == "coverage":
            faults["missing_coverage"] = [sysname]
        elif f == "skew":
            faults["clock_skew"] = {sysname: rng.choice([-7200, -600, -30, 45, 900, 5400])}
        elif f == "fail":
            op = {"links": "revoke", "files": "revoke", "vault": "rotate", "mail": "purge", "orders": "cancel"}[sysname]
            faults["fail_ops"] = [f"{sysname}.{op}"]
        elif kind == "link2":
            faults["fail_ops"] = [f"links.revoke#{rng.randint(0, 1)}"]
        else:
            faults["log_unavailable"] = [sysname]
    spec["faults"] = faults
    return spec, kind


def truth(run, kind):
    """Ground truth from raw logs: was the data actually accessed by an unauthorized party?"""
    w = run.world
    action = run.ledger.get_action(run.action["action_id"])
    start = action["executed_at"]
    if kind in ("link", "link2"):
        log = w.links.raw_log()
        return any(e["event"] == "view" and e["result"] == "allowed" and not is_internal(e["actor"]) for e in log)
    if kind == "share":
        return any(e["event"] == "download" and e["result"] == "allowed" and not is_internal(e["actor"])
                   for e in w.files.raw_log())
    if kind == "key":
        return any(e["event"] == "use" and e["result"] == "allowed" and not is_internal(e["actor"]) and e["ts"] >= start
                   for e in w.vault.raw_log())
    if kind == "mail":
        return any(e["event"] == "read" and e["result"] == "allowed" for e in w.mail.raw_log())
    return False


def oracle(spec, kind, accessed, run):
    """Expected verdict when no fault is injected."""
    if kind == "order":
        fulfilled = any(e["event"] == "fulfill" and e["result"] == "allowed" for e in run.world.orders.raw_log())
        return "ESCALATED" if fulfilled else "REVERSED"
    if accessed:
        return "EXPOSED"
    return "CONTAINED" if kind in ("link", "link2", "share") else "REVERSED"


MUTATIONS = ["verdict", "timestamp", "clock", "records", "accesses", "email", "identifier", "name"]


def mutate(text, facts, how, rng):
    import re
    if how == "verdict":
        other = rng.choice([v for v in ("REVERSED", "CONTAINED", "EXPOSED", "ESCALATED") if v != facts["verdict"]])
        return text.replace(facts["verdict"], other) if facts["verdict"] in text else None
    if how == "timestamp":
        m = guardrail.ISO_RE.search(text)
        if not m:
            return None
        s = m.group(0)
        mm = (int(s[14:16]) + rng.randint(1, 50)) % 60
        return text.replace(s, f"{s[:14]}{mm:02d}{s[16:]}", 1) if f"{s[:14]}{mm:02d}{s[16:]}" not in guardrail.allowed_facts(facts)["timestamps"] else None
    if how == "clock":
        times = guardrail.allowed_facts(facts)["times"]
        for h in range(24):
            t = f"{h:02d}:17"
            if t not in times:
                return text + f"\nThe recipient opened it at {t}."
        return None
    if how == "records":
        m = guardrail.RECORD_RE.search(text)
        return text[:m.start(1)] + str(facts["record_count"] + rng.randint(1, 5)) + text[m.end(1):] if m else \
            text + f"\nAffected: {facts['record_count'] + 2} patient records."
    if how == "accesses":
        return text + f"\nLogs recorded {facts['view_count'] + rng.randint(1, 3)} views."
    if how == "email":
        emails = guardrail.EMAIL_RE.findall(text)
        return text.replace(emails[0], "someone.else@unrelated.example") if emails else \
            text + "\nCopy sent to someone.else@unrelated.example."
    if how == "identifier":
        ids = set(guardrail.allowed_facts(facts)["ids"])
        new = next(f"P-{n}" for n in range(1001, 1041) if f"P-{n}" not in ids)
        return text + f"\nAlso concerns {new}."
    if how == "name":
        p = rng.choice(list(load_roster().values()))
        return text + f"\nPatient: {p['first']} {p['last']}."
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=600)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    stats = {"runs": 0, "faulted": 0, "false_safe": 0, "false_exposed": 0, "clean_wrong": 0, "verdicts": {}}
    failures = []
    drafts = []
    for i in range(args.n):
        spec, kind = gen(rng, i)
        run = run_scenario(spec, llm=False, incident_id=f"INC-{i % 9999 + 1:04d}")
        r = run.result
        v = r["verdict"]
        accessed = truth(run, kind)
        faulted = bool(spec["faults"])
        stats["runs"] += 1
        stats["faulted"] += faulted
        stats["verdicts"][v] = stats["verdicts"].get(v, 0) + 1
        if v in SAFE and (accessed or (faulted and kind != "order")):
            stats["false_safe"] += 1
            failures.append((spec["id"], kind, v, "safe verdict despite access or degraded evidence", spec))
        if v == "EXPOSED" and not accessed:
            stats["false_exposed"] += 1
            failures.append((spec["id"], kind, v, "exposure claimed without access", spec))
        if not faulted:
            exp = oracle(spec, kind, accessed, run)
            if v != exp:
                stats["clean_wrong"] += 1
                failures.append((spec["id"], kind, v, f"expected {exp} with no faults", spec))
        for d in r["drafts"]:
            if not d["guardrail"]["ok"]:
                failures.append((spec["id"], kind, v, f"template {d['kind']} blocked: {d['guardrail']['violations']}", spec))
            drafts.append((d["kind"], d["text"], r["facts"]))

    g = {"mutants": 0, "passed": 0}
    for kind, text, facts in drafts:
        for how in MUTATIONS:
            bad = mutate(text, facts, how, rng)
            if bad is None or bad == text:
                continue
            g["mutants"] += 1
            if guardrail.check(kind, bad, facts)["ok"]:
                g["passed"] += 1
                failures.append(("guardrail", kind, how, "mutated draft passed the guardrail", bad[-200:]))

    print(f"verdict fuzz: {stats['runs']} incidents, {stats['faulted']} with injected faults")
    print(f"  verdict mix: {dict(sorted(stats['verdicts'].items()))}")
    print(f"  false CONTAINED/REVERSED: {stats['false_safe']}")
    print(f"  false EXPOSED:            {stats['false_exposed']}")
    print(f"  wrong verdicts, no fault: {stats['clean_wrong']}")
    print(f"guardrail fuzz: {g['mutants']} mutated drafts from {len(drafts)} templates")
    print(f"  mutated drafts that passed: {g['passed']}")
    for f in failures[:10]:
        print("  FAIL", f[:4])
    ok = not failures
    print(f"RESULT: {'PASS' if ok else 'FAIL'}")
    return ok


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
