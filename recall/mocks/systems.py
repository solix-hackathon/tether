"""Mock external systems: secure links, file share, key vault, order API, mail, outbound channel.

Each system keeps a true event log internally. Readers only see it through `access_log()`,
which applies the scenario's fault plan (outages, truncation, missing metadata, clock skew)
the way a real log API might misbehave. `raw_log()` is the ground truth and is used only by
the validation suite, never by the engine.
"""

import hashlib

from recall.config import LINK_BASE, LOG_RETENTION, SHARE_BASE, is_internal
from recall.timeutil import resolve


class LogUnavailable(Exception):
    pass


class OperationFailed(Exception):
    pass


class SimClock:
    def __init__(self, now: int):
        self.now = now

    def advance_to(self, ts: int):
        if ts < self.now:
            raise ValueError("simulated clock cannot move backwards")
        self.now = ts


class FaultPlan:
    """Faults injected into the mocks. Keys are system names (links, files, vault, mail, orders)."""

    def __init__(self, spec=None, base: int = 0):
        spec = spec or {}
        self.spec = spec
        self.unavailable = set(spec.get("log_unavailable", []))
        self.missing_coverage = set(spec.get("missing_coverage", []))
        self.truncate = {k: resolve(v, base) for k, v in spec.get("log_truncated_before", {}).items()}
        self.skew = {k: int(v) for k, v in spec.get("clock_skew", {}).items()}
        self.fail_ops = set(spec.get("fail_ops", []))

    def affects_evidence(self, system: str) -> bool:
        return (system in self.unavailable or system in self.missing_coverage
                or system in self.truncate or self.skew.get(system, 0) != 0)


class System:
    name = "system"

    def __init__(self, world):
        self.world = world
        self._log = []
        self._seq = 0

    @property
    def now(self):
        return self.world.clock.now

    def _id(self, prefix):
        self._seq += 1
        digest = hashlib.sha256(f"{self.world.seed}:{self.name}:{self._seq}".encode()).hexdigest()[:10]
        return f"{prefix}_{digest}"

    def _record(self, resource, actor, event, result="allowed", **extra):
        self._log.append({"ts": self.now, "system": self.name, "resource": resource,
                          "actor": actor, "event": event, "result": result, **extra})

    def _check(self, op, index=None):
        f = self.world.faults.fail_ops
        if f"{self.name}.{op}" in f or (index is not None and f"{self.name}.{op}#{index}" in f):
            raise OperationFailed(f"{self.name}.{op} failed: upstream returned 503 (simulated)")

    def raw_log(self):
        return [dict(e) for e in self._log]

    def access_log(self, resource):
        f = self.world.faults
        if self.name in f.unavailable:
            raise LogUnavailable(f"{self.name} access log unavailable (simulated outage)")
        skew = f.skew.get(self.name, 0)
        start = self.world.log_retention_start
        entries = [e for e in self._log if e["resource"] == resource]
        if self.name in f.truncate:
            start = max(start, f.truncate[self.name])
            entries = [e for e in entries if e["ts"] >= start]
        entries = [dict(e, ts=e["ts"] + skew) for e in entries]
        coverage = None if self.name in f.missing_coverage else {"start": start + skew, "end": self.now + skew}
        return {"system": self.name, "resource": resource, "coverage": coverage, "entries": entries}


class LinkService(System):
    """Expiring, revocable links. The gateway sends these instead of payloads."""
    name = "links"

    def __init__(self, world):
        super().__init__(world)
        self.links = {}
        self.base = LINK_BASE

    def create(self, document_id, recipient, created_by, ttl):
        lid = self._id("lk")
        self.links[lid] = {"id": lid, "url": self.base + lid, "document_id": document_id,
                           "recipient": recipient, "created_at": self.now,
                           "expires_at": self.now + ttl, "revoked_at": None, "index": len(self.links)}
        self._record(lid, created_by, "create")
        return dict(self.links[lid])

    def status(self, lid):
        link = self.links[lid]
        active = link["revoked_at"] is None and self.now < link["expires_at"]
        return {"id": lid, "active": active, "revoked_at": link["revoked_at"], "expires_at": link["expires_at"]}

    def revoke(self, lid, actor="svc:recall"):
        link = self.links[lid]
        self._check("revoke", link["index"])
        if link["revoked_at"] is None:
            link["revoked_at"] = self.now
            self._record(lid, actor, "revoke")
        return {"ok": True, "link_id": lid, "revoked_at": link["revoked_at"]}

    def open(self, lid, actor):
        active = self.status(lid)["active"]
        self._record(lid, actor, "view", "allowed" if active else "denied")
        return active


class FileShare(System):
    name = "files"

    def __init__(self, world):
        super().__init__(world)
        self.files = {}
        self.shares = {}

    def add_file(self, file_id, name, records, owner):
        self.files[file_id] = {"id": file_id, "name": name, "records": list(records), "owner": owner}
        return file_id

    def share_public(self, file_id, by):
        sid = self._id("sh")
        self.shares[sid] = {"id": sid, "file_id": file_id, "url": SHARE_BASE + sid, "scope": "public",
                            "created_at": self.now, "revoked_at": None, "index": len(self.shares)}
        self._record(file_id, by, "share_create", share_id=sid)
        return sid

    def share_status(self, sid):
        s = self.shares[sid]
        return {"id": sid, "active": s["revoked_at"] is None, "revoked_at": s["revoked_at"]}

    def revoke_share(self, sid, actor="svc:recall"):
        s = self.shares[sid]
        self._check("revoke", s["index"])
        if s["revoked_at"] is None:
            s["revoked_at"] = self.now
            self._record(s["file_id"], actor, "share_revoke", share_id=sid)
        return {"ok": True, "share_id": sid, "revoked_at": s["revoked_at"]}

    def access(self, sid, actor):
        s = self.shares[sid]
        active = s["revoked_at"] is None
        self._record(s["file_id"], actor, "download", "allowed" if active else "denied", share_id=sid)
        return active


class KeyVault(System):
    name = "vault"

    def __init__(self, world):
        super().__init__(world)
        self.keys = {}

    def add_key(self, key_id, secret, service):
        self.keys[key_id] = {"id": key_id, "secret": secret, "service": service, "status": "active",
                             "rotated_at": None, "successor": None}
        return key_id

    def find_by_secret(self, secret):
        for k in self.keys.values():
            if k["secret"] == secret:
                return k["id"]
        return None

    def status(self, key_id):
        k = self.keys[key_id]
        return {"id": key_id, "status": k["status"], "rotated_at": k["rotated_at"], "successor": k["successor"]}

    def rotate(self, key_id, actor="svc:recall"):
        self._check("rotate")
        k = self.keys[key_id]
        if k["status"] == "active":
            new_id = f"{key_id}-r{sum(1 for x in self.keys if x.startswith(key_id)) }"
            new_secret = "rcl_live_" + hashlib.sha256(f"{k['secret']}:{self.now}".encode()).hexdigest()[:24]
            self.add_key(new_id, new_secret, k["service"])
            k.update(status="revoked", rotated_at=self.now, successor=new_id)
            self._record(key_id, actor, "rotate", successor=new_id)
        return {"ok": True, "old_key_id": key_id, "new_key_id": k["successor"], "rotated_at": k["rotated_at"]}

    def use(self, secret, actor):
        kid = self.find_by_secret(secret)
        if kid is None:
            return False
        active = self.keys[kid]["status"] == "active"
        self._record(kid, actor, "use", "allowed" if active else "denied")
        return active


class OrderAPI(System):
    name = "orders"

    def __init__(self, world):
        super().__init__(world)
        self.orders = {}

    def create(self, kind, amount, counterparty, by):
        oid = self._id("ord")
        self.orders[oid] = {"id": oid, "kind": kind, "amount": amount, "counterparty": counterparty,
                            "status": "open", "updated_at": self.now}
        self._record(oid, by, "create")
        return oid

    def fulfill(self, oid):
        o = self.orders[oid]
        if o["status"] != "open":
            self._record(oid, "svc:fulfillment", "fulfill", "denied")
            return
        o.update(status="settled" if o["kind"] == "refund" else "shipped", updated_at=self.now)
        self._record(oid, "svc:fulfillment", "fulfill")

    def status(self, oid):
        o = self.orders[oid]
        return {"id": oid, "status": o["status"], "updated_at": o["updated_at"]}

    def cancel(self, oid, actor="svc:recall"):
        self._check("cancel")
        o = self.orders[oid]
        if o["status"] == "cancelled":
            return {"ok": True, "order_id": oid, "cancelled_at": o["updated_at"]}
        if o["status"] != "open":
            raise OperationFailed(f"order {oid} already {o['status']}; cannot cancel")
        o.update(status="cancelled", updated_at=self.now)
        self._record(oid, actor, "cancel")
        return {"ok": True, "order_id": oid, "cancelled_at": self.now}


class MailServer(System):
    name = "mail"

    def __init__(self, world):
        super().__init__(world)
        self.messages = {}

    def send(self, sender, to, subject, body):
        mid = self._id("msg")
        internal = [r for r in to if is_internal(r)]
        external = [r for r in to if not is_internal(r)]
        self.messages[mid] = {"id": mid, "sender": sender, "to": list(to), "subject": subject, "body": body,
                              "internal_copies": set(internal), "external": external,
                              "sent_at": self.now, "purged_at": None}
        for r in internal:
            self._record(mid, r, "delivered")
        for r in external:
            self._record(mid, r, "delivered_external")
        return mid

    def read(self, mid, actor):
        m = self.messages[mid]
        ok = actor in m["internal_copies"]
        self._record(mid, actor, "read", "allowed" if ok else "denied")
        return ok

    def purge(self, mid, actor="svc:recall"):
        self._check("purge")
        m = self.messages[mid]
        if m["purged_at"] is None:
            m["internal_copies"] = set()
            m["purged_at"] = self.now
            self._record(mid, actor, "purge")
        return {"ok": True, "message_id": mid, "purged_at": m["purged_at"]}

    def status(self, mid):
        m = self.messages[mid]
        return {"id": mid, "internal_copies": len(m["internal_copies"]),
                "external_recipients": list(m["external"]), "purged_at": m["purged_at"]}


class OutboundChannel(System):
    """Fax / partner API posts: once delivered, there is no kill switch and no access log."""
    name = "outbound"

    def deliver(self, kind, destination, by):
        did = self._id("dlv")
        self._record(did, destination, "delivered_external", channel=kind, sender=by)
        return did


class World:
    def __init__(self, start: int, faults=None, seed: str = "recall"):
        self.seed = seed
        self.clock = SimClock(start)
        self.log_retention_start = start - LOG_RETENTION
        self.faults = faults if isinstance(faults, FaultPlan) else FaultPlan(faults, start)
        self.documents = {}
        self.links = LinkService(self)
        self.files = FileShare(self)
        self.vault = KeyVault(self)
        self.orders = OrderAPI(self)
        self.mail = MailServer(self)
        self.outbound = OutboundChannel(self)

    def systems(self):
        return [self.links, self.files, self.vault, self.orders, self.mail, self.outbound]

    def add_document(self, title, records, data_class):
        doc_id = "doc_" + hashlib.sha256(f"{self.seed}:doc:{len(self.documents)}".encode()).hexdigest()[:10]
        self.documents[doc_id] = {"id": doc_id, "title": title, "records": list(records), "data_class": data_class}
        return doc_id

    def snapshot(self):
        def clean(d):
            return {k: (sorted(v) if isinstance(v, set) else v) for k, v in d.items()}
        return {
            "documents": self.documents,
            "links": self.links.links,
            "files": self.files.files,
            "shares": self.files.shares,
            "keys": {k: {**v, "secret": v["secret"][:12] + "…"} for k, v in self.vault.keys.items()},
            "orders": self.orders.orders,
            "mail": {k: clean(v) for k, v in self.mail.messages.items()},
            "logs": {s.name: s.raw_log() for s in self.systems()},
        }
