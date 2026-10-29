"""Evidence collector: reads access logs for every affected resource and judges whether they can
be trusted. A log only counts as positive evidence when it is available, covers the whole
exposure window, and agrees with the reference clock and with the revocation record."""

from recall.config import CLOCK_TOLERANCE, is_internal
from recall.mocks.systems import LogUnavailable
from recall.timeutil import iso

ACCESS_EVENTS = {"view", "download", "use", "read"}
STATUS_RANK = {"ok": 0, "incomplete": 1, "no_visibility": 2, "unavailable": 3, "inconsistent": 4}


def _unauthorized(kind, entry, action):
    if entry["event"] not in ACCESS_EVENTS or entry["result"] != "allowed":
        return False
    if kind == "mail":
        # An internal mis-send: any read by a recipient of the wrong message is an exposure.
        return entry["actor"] in action["target"]
    return not is_internal(entry["actor"])


def _inspect(world, system, kind, resource, action, start, end, created_by_action=True, entry_filter=None):
    item = {"kind": kind, "resource": resource, "system": system.name, "status": "ok",
            "notes": [], "access": [], "entries": [], "window": {"start": start, "end": end}}
    try:
        log = system.access_log(resource)
    except LogUnavailable as e:
        item["status"] = "unavailable"
        item["notes"].append(str(e))
        return item

    problems = []  # (status, note)
    cov = log["coverage"]
    now = world.clock.now
    if cov is None:
        problems.append(("incomplete", "log has no coverage metadata, so completeness cannot be shown"))
    else:
        drift = cov["end"] - now
        if abs(drift) > CLOCK_TOLERANCE:
            problems.append(("inconsistent", f"log clock differs from the reference clock by {drift} s"))
        elif cov["start"] > start:
            problems.append(("incomplete", f"log coverage begins {iso(cov['start'])}, after the action at {iso(start)}"))

    entries = [e for e in log["entries"] if entry_filter is None or entry_filter(e)]
    for e in entries:
        if created_by_action and e["ts"] < start:
            problems.append(("inconsistent", f"log entry at {iso(e['ts'])} predates the resource"))
        if end is not None and e["ts"] > end and e["result"] == "allowed" and e["event"] in ACCESS_EVENTS:
            problems.append(("inconsistent", f"access allowed at {iso(e['ts'])}, after revocation at {iso(end)}"))

    window = [e for e in entries if e["ts"] >= start]
    item["entries"] = window
    item["access"] = [e for e in window if _unauthorized(kind, e, action)]
    for status, note in problems:
        if STATUS_RANK[status] > STATUS_RANK[item["status"]]:
            item["status"] = status
        if note not in item["notes"]:
            item["notes"].append(note)
    return item


def collect(world, action, reversals):
    """Evidence items, one per resource the action touched."""
    start = action["executed_at"]
    res = action.get("resources", {})
    ended = {r["resource"]: (r["at"] if r["confirmed"] else None) for r in reversals}
    items = []
    for lid in res.get("links", {}).values():
        items.append(_inspect(world, world.links, "link", lid, action, start, ended.get(lid)))
    if "share_id" in res:
        sid = res["share_id"]
        items.append(_inspect(world, world.files, "share", res["file_id"], action, start, ended.get(sid),
                              entry_filter=lambda e: e.get("share_id") == sid))
    for kid in res.get("key_ids", []):
        items.append(_inspect(world, world.vault, "key", kid, action, start, ended.get(kid),
                              created_by_action=False))
    if "purge_mail" in action.get("playbooks", []):
        mid = res["message_id"]
        items.append(_inspect(world, world.mail, "mail", mid, action, start, ended.get(mid)))
    if action.get("payload_left_org"):
        rid = res.get("message_id") or res.get("delivery_id")
        items.append({"kind": "external_delivery", "resource": rid, "system": "external", "status": "no_visibility",
                      "notes": ["data was delivered to a system outside the organization that has no access log"],
                      "access": [], "entries": [], "window": {"start": start, "end": None}})
    return items


def timeline(action, reversals, evidence, reported_at):
    events = [{"ts": action["executed_at"], "event": "action_executed",
               "detail": f"{action['tool']} by {action['agent']} to {', '.join(action['target'])}"}]
    for item in evidence:
        for e in item["entries"]:
            if e["event"] in ("create", "share_create", "delivered", "delivered_external"):
                continue
            name = e["event"] if e["event"].startswith(item["kind"]) else f"{item['kind']}_{e['event']}"
            events.append({"ts": e["ts"], "event": name,
                           "detail": f"{e['event']} of {item['resource']} by {e['actor']} ({e['result']})"})
    events.append({"ts": reported_at, "event": "incident_reported", "detail": "incident raised"})
    for r in reversals:
        if r["confirmed"]:
            events.append({"ts": r["at"], "event": r["playbook"], "detail": f"{r['playbook']} confirmed for {r['resource']}"})
    events.sort(key=lambda x: x["ts"])
    return [{"at": iso(e["ts"]), "event": e["event"], "detail": e["detail"]} for e in events]
