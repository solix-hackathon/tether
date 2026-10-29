"""Verdict rules. Deterministic, ordered, and conservative: CONTAINED and REVERSED need positive
evidence; anything missing, failed or contradictory becomes ESCALATED."""

REVERSED, CONTAINED, EXPOSED, ESCALATED = "REVERSED", "CONTAINED", "EXPOSED", "ESCALATED"
VERDICTS = (REVERSED, CONTAINED, EXPOSED, ESCALATED)

CONTAIN_PLAYBOOKS = {"revoke_links", "revoke_share"}


def accesses(n: int) -> str:
    return f"{n} unauthorized {'access' if n == 1 else 'accesses'}"


def decide(action, reversals, evidence):
    """Return (verdict, reasons). Reasons never contain verdict words, so drafts can be checked."""
    if action is None:
        return ESCALATED, ["no ledger record matches the incident, so the action cannot be identified"]

    inconsistent = [i for i in evidence if i["status"] == "inconsistent"]
    if inconsistent:
        return ESCALATED, [f"evidence for {i['resource']} is internally inconsistent: {'; '.join(i['notes'])}"
                           for i in inconsistent]

    seen = [a for i in evidence for a in i["access"]]
    if seen:
        actors = sorted({a["actor"] for a in seen})
        who = ", ".join(actors[:5]) + (f" and {len(actors) - 5} others" if len(actors) > 5 else "")
        reasons = [f"access logs show {accesses(len(seen))} by {who}"]
        failed = [r for r in reversals if not r["confirmed"]]
        if failed:
            reasons.append("further access is not yet cut off: " + ", ".join(r["resource"] for r in failed))
        return EXPOSED, reasons

    if action["data"].get("unknown_secrets"):
        return ESCALATED, ["a credential was detected that does not match any vault key, so it cannot be rotated"]

    if action.get("payload_left_org"):
        return ESCALATED, ["sensitive records were delivered outside the organization with no revocation path "
                           "and no access log, so non-access cannot be proven"]

    if not reversals:
        return ESCALATED, ["no reversal playbook applies to this action"]

    failed = [r for r in reversals if not r["confirmed"]]
    if failed:
        return ESCALATED, [f"{r['playbook']} on {r['resource']} was not confirmed by the target system"
                           + (f" ({r['error']})" if r["error"] else "") for r in failed]

    gaps = [i for i in evidence if i["status"] != "ok"]
    if gaps:
        return ESCALATED, [f"no positive evidence of non-access for {i['resource']}: {'; '.join(i['notes'])}"
                           for i in gaps]

    confirmed = "all reversals were confirmed by the target systems"
    if CONTAIN_PLAYBOOKS & set(action["playbooks"]):
        return CONTAINED, [confirmed, f"access logs covering the full exposure window show {accesses(0)}"]
    reasons = [confirmed]
    if evidence:
        reasons.append(f"access logs covering the full exposure window show {accesses(0)}")
    return REVERSED, reasons
