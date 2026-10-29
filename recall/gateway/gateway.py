"""The Recall gateway: sits between the agent and every outbound tool.

1. Classifies each action (reversible / revocable / compensable / purgeable / irreversible).
2. Rewrites sensitive email payloads into expiring, per-recipient revocable links.
3. Holds irreversible actions that carry sensitive data until a human approves them.
4. Records everything in the append-only ledger.
"""

import re

from recall.config import HOLD_SECONDS, LINK_TTL, ORG_NAME, is_internal
from recall.timeutil import iso

SECRET_RE = re.compile(r"\brcl_live_[A-Za-z0-9]{20,}\b")
PATIENT_ID_RE = re.compile(r"\bP-\d{4}\b")

TOOLS = ("send_email", "share_file", "create_order", "issue_refund", "send_fax", "post_external")


def _as_list(v):
    return [v] if isinstance(v, str) else list(v or [])


def target_of(tool, args):
    if tool == "send_email":
        return _as_list(args["to"])
    if tool == "share_file":
        return [args["file_id"]]
    if tool in ("create_order", "issue_refund"):
        return [args["counterparty"]]
    return [args["destination"]]


def classify(world, tool, args, via_gateway=True):
    """Deterministic classification. Returns the action class, the playbooks that can undo or
    contain it, and the data it carries."""
    if tool not in TOOLS:
        raise ValueError(f"unknown tool {tool!r}")
    text = f"{args.get('subject', '')} {args.get('body', '')}"
    records = set(args.get("records", [])) | set(PATIENT_ID_RE.findall(text))
    secrets = SECRET_RE.findall(text)
    key_ids = []
    for s in secrets:
        kid = world.vault.find_by_secret(s)
        if kid and kid not in key_ids:
            key_ids.append(kid)
    unknown_secrets = len(set(secrets)) - len(key_ids)

    playbooks, reasons = [], []
    payload_left = False
    cls = None

    if tool == "send_email":
        to = _as_list(args["to"])
        if all(is_internal(r) for r in to):
            cls = "purgeable"
            playbooks = ["purge_mail"]
            reasons.append("all recipients are internal; an admin purge is available")
        else:
            if records and via_gateway:
                cls = "revocable"
                playbooks.append("revoke_links")
                reasons.append("sensitive records are sent as expiring, revocable links instead of payloads")
            elif records:
                cls = "irreversible"
                payload_left = True
                reasons.append("raw records were delivered outside the organization without the gateway")
            if key_ids:
                cls = cls or "revocable"
                playbooks.append("rotate_key")
                reasons.append("a vault credential was detected; rotation makes the leaked copy worthless")
            if cls is None:
                cls = "irreversible"
                reasons.append("external email with no detected sensitive data")
    elif tool == "share_file":
        records |= set(world.files.files[args["file_id"]]["records"])
        cls = "revocable"
        playbooks = ["revoke_share"]
        reasons.append("public shares can be revoked by the file share")
    elif tool in ("create_order", "issue_refund"):
        cls = "compensable"
        playbooks = ["cancel_order"]
        reasons.append("the order API exposes a cancel call for open orders")
    else:
        cls = "irreversible"
        payload_left = bool(records)
        reasons.append(f"{tool} has no recall mechanism and no recipient access log")

    if unknown_secrets:
        reasons.append("a credential pattern was detected that does not match any vault key")

    classification = "PHI" if records else ("SECRET" if secrets else "NONE")
    return {
        "action_class": cls,
        "playbooks": playbooks,
        "data": {"classification": classification, "records": sorted(records), "record_count": len(records),
                 "key_ids": key_ids, "unknown_secrets": unknown_secrets},
        "payload_left_org": payload_left,
        "classifier_reasons": reasons,
    }


def _execute(world, agent, tool, args, c, link_ttl):
    """Perform the (possibly rewritten) action against the target system. Returns resource ids."""
    res = {}
    if tool == "send_email":
        to = _as_list(args["to"])
        subject = args.get("subject", "")
        if "revoke_links" in c["playbooks"]:
            doc = world.add_document(subject, c["data"]["records"], c["data"]["classification"])
            res.update(document_id=doc, links={}, messages={})
            for r in to:
                link = world.links.create(doc, r, agent, link_ttl)
                body = (f"{ORG_NAME} has shared a secure document with you.\n"
                        f"Open it here: {link['url']}\n"
                        f"This link is personal to {r}, expires {iso(link['expires_at'])}, and may be revoked.")
                res["links"][r] = link["id"]
                res["messages"][r] = world.mail.send(agent, [r], subject, body)
            res["rewritten"] = True
        else:
            res["message_id"] = world.mail.send(agent, to, subject, args.get("body", ""))
        if c["data"]["key_ids"]:
            res["key_ids"] = list(c["data"]["key_ids"])
    elif tool == "share_file":
        res = {"file_id": args["file_id"], "share_id": world.files.share_public(args["file_id"], agent)}
    elif tool in ("create_order", "issue_refund"):
        kind = "refund" if tool == "issue_refund" else "order"
        res = {"order_id": world.orders.create(kind, args.get("amount", 0), args["counterparty"], agent)}
    else:
        res = {"delivery_id": world.outbound.deliver(tool, args["destination"], agent)}
    return res


class Gateway:
    def __init__(self, world, ledger, hold_seconds=HOLD_SECONDS, link_ttl=LINK_TTL):
        self.world = world
        self.ledger = ledger
        self.hold_seconds = hold_seconds
        self.link_ttl = link_ttl
        self._pending = {}

    def submit(self, agent, tool, args):
        now = self.world.clock.now
        c = classify(self.world, tool, args)
        aid = self.ledger.next_action_id()
        base = dict(action_id=aid, agent=agent, tool=tool, target=target_of(tool, args), via_gateway=True, **c)
        if c["action_class"] == "irreversible" and c["data"]["classification"] != "NONE":
            hold_until = now + self.hold_seconds
            self._pending[aid] = (agent, tool, dict(args), c, hold_until)
            self.ledger.append("action", now, status="held", hold_until=hold_until, **base)
            return {"action_id": aid, "status": "held", "hold_until": hold_until, **c}
        resources = _execute(self.world, agent, tool, args, c, self.link_ttl)
        self.ledger.append("action", now, status="executed", executed_at=now, resources=resources, **base)
        return {"action_id": aid, "status": "executed", "resources": resources, **c}

    def pending(self):
        return sorted(self._pending)

    def approve(self, action_id, approver):
        if action_id not in self._pending:
            raise KeyError(f"{action_id} is not awaiting approval")
        agent, tool, args, c, hold_until = self._pending[action_id]
        now = self.world.clock.now
        if now > hold_until:
            self.reject(action_id, "system:hold-timeout", "hold window expired before approval")
            return {"action_id": action_id, "status": "rejected"}
        del self._pending[action_id]
        resources = _execute(self.world, agent, tool, args, c, self.link_ttl)
        self.ledger.append("hold_released", now, action_id=action_id, status="executed", executed_at=now,
                           resources=resources, approved_by=approver)
        return {"action_id": action_id, "status": "executed", "resources": resources}

    def reject(self, action_id, actor, reason):
        if action_id not in self._pending:
            raise KeyError(f"{action_id} is not awaiting approval")
        del self._pending[action_id]
        self.ledger.append("hold_rejected", self.world.clock.now, action_id=action_id, status="rejected",
                           rejected_by=actor, reason=reason)
        return {"action_id": action_id, "status": "rejected"}

    def expire_holds(self):
        now = self.world.clock.now
        for aid in [a for a, p in self._pending.items() if now > p[4]]:
            self.reject(aid, "system:hold-timeout", "hold window expired before approval")


def record_bypass(world, ledger, agent, tool, args, source="detector"):
    """An action that went around the gateway, reconstructed into the ledger by a detector or a
    human report. It executes raw: no link rewriting, no hold."""
    now = world.clock.now
    c = classify(world, tool, args, via_gateway=False)
    res = {}
    if tool == "send_email":
        res["message_id"] = world.mail.send(agent, _as_list(args["to"]), args.get("subject", ""), args.get("body", ""))
        if c["data"]["key_ids"]:
            res["key_ids"] = list(c["data"]["key_ids"])
    else:
        res = _execute(world, agent, tool, args, c, LINK_TTL)
    aid = ledger.next_action_id()
    ledger.append("action", now, action_id=aid, agent=agent, tool=tool, target=target_of(tool, args),
                  via_gateway=False, source=source, status="executed", executed_at=now, resources=res, **c)
    return {"action_id": aid, "status": "executed", "resources": res, **c}
