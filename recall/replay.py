"""Replay script for the dashboard: the incident as it played out with Recall, side by side with
the same agent action and the same outside events in a world with no gateway and no recovery.

Both sides come from the mock systems' own event logs, so the animation shows what the
simulation actually did, not a scripted story. The "without Recall" side reruns the scenario
from scratch: the action executes raw, every event is replayed, and nobody intervenes.
"""

from recall.config import is_internal
from recall.engine.rules import ESCALATED
from recall.gateway.gateway import record_bypass
from recall.ledger.ledger import Ledger
from recall.mocks.systems import World
from recall.scenario import _apply, _setup
from recall.timeutil import iso, parse_iso, resolve

ACCESS = {"view", "download", "use", "read"}

TARGET = {"link": "Secure link", "share": "Public share", "key": "API key", "mail": "Staff inbox",
          "order": "Order API", "outbound": "Fax line", "inbox": "Their inbox"}

REVERSAL_TEXT = {
    "revoke_links": "Recall revoked the link{for_}",
    "revoke_share": "Recall revoked the public share",
    "rotate_key": "Recall rotated the key; the leaked copy no longer works",
    "purge_mail": "Recall purged the email from the mailbox",
    "cancel_order": "Recall cancelled the order",
    "cancel_hold": "Recall cancelled the held fax before it was sent",
}
REVERSAL_STATUS = {"revoke_links": "revoked", "revoke_share": "revoked", "rotate_key": "rotated",
                   "purge_mail": "purged", "cancel_order": "cancelled", "cancel_hold": "cancelled"}


def _plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def _payload(action):
    d = action["data"]
    if action["tool"] in ("create_order", "issue_refund"):
        return "refund" if action["tool"] == "issue_refund" else "order"
    if d["record_count"]:
        return _plural(d["record_count"], "patient record")
    if d["key_ids"] or d["classification"] == "SECRET":
        return "production API key"
    return "message"


def _target_kind(action):
    res = action.get("resources") or {}
    if action["status"] == "held" or action["tool"] in ("send_fax", "post_external"):
        return "outbound"
    if res.get("links"):
        return "link"
    if "share_id" in res or action["tool"] == "share_file":
        return "share"
    if res.get("key_ids") and action["action_class"] != "purgeable":
        return "key" if not action["data"]["records"] else "inbox"
    if "order_id" in res or action["tool"] in ("create_order", "issue_refund"):
        return "order"
    if action["action_class"] == "purgeable":
        return "mail"
    return "inbox"


def _entries(world, action):
    """Raw access-type events on the resources this action touched."""
    res = action.get("resources") or {}
    out = []
    for kind, lid in (("link", lid) for lid in res.get("links", {}).values()):
        out += [(kind, e) for e in world.links.raw_log() if e["resource"] == lid and e["event"] == "view"]
    if "share_id" in res:
        out += [("share", e) for e in world.files.raw_log()
                if e.get("share_id") == res["share_id"] and e["event"] == "download"]
    for kid in res.get("key_ids", []):
        out += [("key", e) for e in world.vault.raw_log() if e["resource"] == kid and e["event"] == "use"]
    if "message_id" in res and action["action_class"] == "purgeable":
        out += [("mail", e) for e in world.mail.raw_log() if e["resource"] == res["message_id"] and e["event"] == "read"]
    if "order_id" in res:
        out += [("order", e) for e in world.orders.raw_log() if e["resource"] == res["order_id"] and e["event"] == "fulfill"]
    if "delivery_id" in res:
        out += [("outbound", e) for e in world.outbound.raw_log() if e["resource"] == res["delivery_id"]]
    return sorted(out, key=lambda x: x[1]["ts"])


def _access_beat(panel, kind, e, action):
    actor, ok = e["actor"], e["result"] == "allowed"
    if kind == "outbound":
        return {"panel": panel, "ts": e["ts"], "type": "deliver", "tone": "bad",
                "text": f"Fax delivered to {actor}. There is no way to call it back."}
    if kind == "order":
        what = "refund paid out" if action["tool"] == "issue_refund" else "order shipped"
        return {"panel": panel, "ts": e["ts"], "type": "access", "result": "allowed" if ok else "denied",
                "who": "system", "tone": "bad" if ok else "good",
                "text": what.capitalize() if ok else f"Fulfilment blocked: the order was already cancelled"}
    unauthorized = (actor in action["target"]) if kind == "mail" else not is_internal(actor)
    verb = {"link": "opened the link", "share": "downloaded the file", "key": "used the key",
            "mail": "read the email"}[kind]
    if not unauthorized:
        return {"panel": panel, "ts": e["ts"], "type": "access", "result": e["result"], "who": "inside",
                "actor": actor, "tone": "neutral", "text": f"{actor} {verb} (authorized)"}
    if ok:
        return {"panel": panel, "ts": e["ts"], "type": "access", "result": "allowed", "who": "outside",
                "actor": actor, "tone": "bad", "text": f"{actor} {verb}"}
    attempt = {"link": "tried the link", "share": "tried the file", "key": "tried the key",
               "mail": "tried to read the email"}[kind]
    return {"panel": panel, "ts": e["ts"], "type": "access", "result": "denied", "who": "outside",
            "actor": actor, "tone": "good", "text": f"{actor} {attempt}: denied"}


def _gateway_beat(action, ts):
    b = {"panel": "with", "ts": ts, "type": "gateway"}
    pb = action["playbooks"]
    if not action["via_gateway"]:
        return {**b, "mode": "bypassed", "tone": "bad",
                "text": "The agent went around the gateway: raw data left without a kill switch"}
    if action["status"] in ("held", "rejected") or "hold_until" in action:
        return {**b, "mode": "hold", "tone": "warn",
                "text": "Gateway held the fax: irreversible actions with patient data wait for approval"}
    if "revoke_links" in pb:
        n = len(action["resources"]["links"])
        return {**b, "mode": "rewrite", "tone": "good", "label": "link",
                "text": f"Gateway swapped the {_payload(action)} for {_plural(n, 'expiring link')}; nothing sensitive left"}
    if "rotate_key" in pb:
        return {**b, "mode": "flag", "tone": "warn", "text": "Gateway spotted a production key and logged it for rotation"}
    if "revoke_share" in pb:
        return {**b, "mode": "flag", "tone": "neutral", "text": "Gateway logged the public share as revocable"}
    if "cancel_order" in pb:
        return {**b, "mode": "flag", "tone": "neutral", "text": "Gateway logged the order as cancellable"}
    if "purge_mail" in pb:
        return {**b, "mode": "flag", "tone": "neutral", "text": "Gateway logged the internal email as purgeable"}
    return {**b, "mode": "flag", "tone": "neutral", "text": "Gateway passed it through: no sensitive data found"}


def _send_text(action, raw):
    tool = action["tool"]
    who = ", ".join(action["target"])
    verb = {"send_email": f"emailed {who}", "share_file": f"shared {who} publicly",
            "create_order": f"placed an order with {who}", "issue_refund": f"issued a refund to {who}",
            "send_fax": f"faxed {who}", "post_external": f"posted to {who}"}[tool]
    return f"{action['agent']} {verb}" + (f" with {_payload(action)}" if action["data"]["record_count"] or raw else "")


def _with_beats(run):
    world, ledger, result = run.world, run.ledger, run.result
    action = result["action"]
    entries = ledger.entries()
    t0 = next(e["ts"] for e in entries if e["type"] == "action")
    incident_ts = next(e["ts"] for e in entries if e["type"] == "incident_opened")
    kind = _target_kind(action)
    beats = [{"panel": "with", "ts": t0, "type": "send", "label": _payload(action), "tone": "neutral",
              "to": "target" if not action["via_gateway"] else "gateway", "text": _send_text(action, False)},
             _gateway_beat(action, t0)]
    for e in entries:
        if e["type"] == "hold_released":
            beats.append({"panel": "with", "ts": e["ts"], "type": "gateway", "mode": "release", "tone": "warn",
                          "text": f"{e['approved_by']} approved the hold; the fax goes out"})
    # An attempt in the same second as the recall belongs after it if the system refused it.
    before = lambda e: e["ts"] < incident_ts or (e["ts"] == incident_ts and e["result"] == "allowed")  # noqa: E731
    beats += [_access_beat("with", k, e, action) for k, e in _entries(world, action) if before(e)]
    beats.append({"panel": "with", "ts": incident_ts, "type": "incident", "tone": "warn",
                  "text": f"Incident reported. Recall finds {result['action_id']} in the ledger"})
    for r in result["reversals"]:
        label = REVERSAL_TEXT[r["playbook"]].format(for_=f" for {r['recipient']}" if r.get("recipient") else "")
        beats.append({"panel": "with", "ts": incident_ts, "type": "reversal", "ok": r["confirmed"],
                      "status": REVERSAL_STATUS[r["playbook"]] if r["confirmed"] else "failed",
                      "tone": "good" if r["confirmed"] else "bad",
                      "text": label if r["confirmed"] else f"{label.replace('Recall ', 'Recall tried: ')}. It failed"})
    if result["evidence"]:
        bad = [i for i in result["evidence"] if i["status"] != "ok"]
        if bad:
            text = "Evidence check: " + "; ".join(n for i in bad for n in i["notes"])
        else:
            text = f"Evidence check: {_plural(len(result['evidence']), 'access log')} complete for the whole window"
        beats.append({"panel": "with", "ts": incident_ts, "type": "evidence", "tone": "warn" if bad else "good",
                      "text": text})
    beats.append({"panel": "with", "ts": incident_ts, "type": "verdict", "verdict": result["verdict"],
                  "tone": "neutral", "text": f"Verdict {result['verdict']}: {result['reasons'][0]}"})
    beats += [_access_beat("with", k, e, action) for k, e in _entries(world, action) if not before(e)]
    return beats, kind, incident_ts


def counterfactual(spec):
    """Rerun the scenario with no gateway and no recovery engine."""
    start = parse_iso(spec["start"])
    world = World(start, seed=spec.get("id", "scenario") + "-without")
    _setup(world, spec.get("setup", {}))
    ledger = Ledger()
    act = spec["action"]
    world.clock.advance_to(resolve(act.get("at", "+00:00:00"), start))
    out = record_bypass(world, ledger, act.get("agent", "agent:care-coordinator"), act["tool"], act["args"])
    action = ledger.get_action(out["action_id"])
    untracked = []
    for ts, _, e in sorted((resolve(e["at"], start), i, e) for i, e in enumerate(spec.get("events", []))):
        world.clock.advance_to(ts)
        if e["type"] == "approve_hold":
            continue
        if e["type"] == "link_view":
            untracked.append((ts, e["actor"]))
            continue
        _apply(world, ledger, None, out["action_id"], e)
    return world, action, untracked


def _without_beats(run, incident_ts):
    world, action, untracked = counterfactual(run.spec)
    kind = _target_kind(action)
    t0 = action["executed_at"]
    beats = [{"panel": "without", "ts": t0, "type": "send", "label": _payload(action), "raw": True, "to": "target",
              "tone": "bad" if action["data"]["classification"] != "NONE" else "neutral",
              "text": _send_text(action, True) + " (raw)"},
             {"panel": "without", "ts": t0, "type": "gateway", "mode": "absent", "tone": "neutral",
              "text": f"No gateway: the {_payload(action)} leaves as-is" if action["tool"] != "share_file"
              else "No gateway: nothing records what was shared or how to undo it"}]
    events = [_access_beat("without", k, e, action) for k, e in _entries(world, action)]
    events += [{"panel": "without", "ts": ts, "type": "access", "result": "untracked", "who": "outside",
                "actor": actor, "tone": "bad", "text": f"{actor} opened the email. Nobody can see this: no log exists"}
               for ts, actor in untracked]
    events.sort(key=lambda b: b["ts"])
    beats += [b for b in events if b["ts"] <= incident_ts]
    beats.append({"panel": "without", "ts": incident_ts, "type": "incident", "tone": "warn",
                  "text": "Incident reported. There is no ledger, so nobody knows exactly what the agent sent"})
    beats += [b for b in events if b["ts"] > incident_ts]
    return beats, kind, world, action, untracked


def _without_outcome(world, action, untracked, beats):
    outside = sum(1 for b in beats if b["type"] == "access" and b.get("who") == "outside" and b["result"] == "allowed")
    tool, d = action["tool"], action["data"]
    if tool == "share_file":
        return "STILL PUBLIC", f"{_plural(outside, 'outside download')}. The share is still live."
    if tool in ("send_fax", "post_external"):
        return "DELIVERED", "Sent instantly with no hold window. Nothing can call it back."
    if tool in ("create_order", "issue_refund"):
        st = world.orders.orders[action["resources"]["order_id"]]["status"]
        return ("PAID OUT" if st == "settled" else "SHIPPED" if st == "shipped" else "NOT CANCELLED",
                "Nobody calls the cancel API.")
    if action["action_class"] == "purgeable":
        return "STILL IN INBOX", f"Read {_plural(outside, 'time')}. Nobody removes it."
    if d["records"]:
        return "UNKNOWN", "The record sits in an outside inbox. No unsend, no log: nobody can say if it was read."
    if d["key_ids"]:
        return "KEY STILL LIVE", f"{_plural(outside, 'outside use')} so far. The key still works."
    return "NO RECORD", "Nothing records the action, so there is nothing to act on."


def _with_outcome(result, beats):
    v = result["verdict"]
    closed = bool(result["reversals"]) and all(r["confirmed"] for r in result["reversals"])
    text = {
        "REVERSED": "Fully undone, confirmed by the target system.",
        "CONTAINED": "Cut off before anyone outside saw it, with log proof.",
        "EXPOSED": "Exposure proven with a timeline" + ("; access is now cut off." if closed else "; follow-up needed."),
        "ESCALATED": "Recall couldn't prove it either way, so a human takes over with the full record.",
    }[v]
    blocked = sum(1 for b in beats if b["type"] == "access" and b["result"] == "denied" and b.get("who") == "outside")
    return text + (f" {_plural(blocked, 'later attempt')} blocked." if blocked else "")


def _batch(beats, min_run=3):
    """Merge runs of similar accesses (same result, same kind of party, same action) into one beat,
    so a room of 40 phones replays as one step, not 40."""
    def sig(b):
        if b["type"] != "access" or not b.get("actor"):
            return None
        return b["result"], b.get("who"), b["text"][len(b["actor"]):].strip()

    out, i = [], 0
    while i < len(beats):
        s, j = sig(beats[i]), i + 1
        while s is not None and j < len(beats) and sig(beats[j]) == s:
            j += 1
        if s is None or j - i < min_run:
            out.append(beats[i])
            i += 1
            continue
        run = beats[i:j]
        actors = list(dict.fromkeys(b["actor"] for b in run))
        names = ", ".join(actors[:3]) + (f" and {len(actors) - 3} more" if len(actors) > 3 else "")
        out.append({**run[0], "text": f"{names} {s[2]}", "count": len(run), "actors": actors})
        i = j
    return out


def _steps(a, b):
    """Pair the two panels' beats into steps on a shared clock."""
    steps, i, j = [], 0, 0
    while i < len(a) or j < len(b):
        ts = min(x[k]["ts"] for x, k in ((a, i), (b, j)) if k < len(x))
        step = {"ts": ts, "at": iso(ts), "with": None, "without": None}
        if i < len(a) and a[i]["ts"] == ts:
            step["with"] = a[i]
            i += 1
        if j < len(b) and b[j]["ts"] == ts:
            step["without"] = b[j]
            j += 1
        steps.append(step)
    return steps


def build(run):
    with_b, with_kind, incident_ts = _with_beats(run)
    without_b, without_kind, cf_world, cf_action, untracked = _without_beats(run, incident_ts)
    result = run.result
    headline, detail = _without_outcome(cf_world, cf_action, untracked, without_b)
    end = max(b["ts"] for b in with_b + without_b)
    steps = _steps(_batch(with_b), _batch(without_b))  # counts below use the unbatched beats
    steps.append({"ts": end, "at": iso(end), "final": True,
                  "with": {"panel": "with", "type": "final", "headline": result["verdict"], "class": result["verdict"],
                           "text": _with_outcome(result, with_b)},
                  "without": {"panel": "without", "type": "final", "headline": headline, "class": "WITHOUT",
                              "text": detail}})

    def tally(beats, result_value):
        return sum(1 for x in beats if x["type"] == "access" and x.get("who") == "outside" and x["result"] == result_value)

    unresolved = (result["verdict"] == ESCALATED or not all(r["confirmed"] for r in result["reversals"])
                  or not result["reversals"])
    compare = [
        {"label": "Outside accesses that got through", "with": tally(with_b, "allowed"),
         "without": f"{tally(without_b, 'allowed')} + {len(untracked)} unknown" if untracked
         else tally(without_b, "allowed")},
        {"label": "Attempts blocked after the incident", "with": tally(with_b, "denied"), "without": 0},
        {"label": "Record of exactly what the agent did", "with": "Yes, hash-chained ledger", "without": "No"},
        {"label": "Proof of what was exposed", "with": "No, escalated to a human" if result["verdict"] == ESCALATED
         else f"Yes: {result['verdict']}", "without": "No"},
        {"label": "Still accessible from outside", "with": "Needs follow-up" if unresolved else "No",
         "without": "No" if headline in ("NO RECORD",) else "Yes"},
    ]
    return {
        "panels": {
            "without": {"title": "Without Recall", "agent": run.result["action"]["agent"],
                        "gateway": "No gateway", "target": TARGET[without_kind], "kind": without_kind},
            "with": {"title": "With Recall", "agent": run.result["action"]["agent"],
                     "gateway": "Recall gateway", "target": TARGET[with_kind], "kind": with_kind},
        },
        "steps": steps,
        "compare": compare,
    }
