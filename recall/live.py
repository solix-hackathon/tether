"""Live audience demo: the same gateway, links, vault, ledger and recovery engine, running on the
wall clock and serving real pages that people open on their phones.

Two rounds, one at a time:
  link  The care agent emails a (synthetic) discharge summary to the wrong clinic. The gateway
        rewrites it into a secure link; the room opens it; Recall revokes it.
        Ends CONTAINED (nobody opened it first) or EXPOSED (someone did).
  key   The support agent pastes a production API key into a reply to a customer. The room can
        read the leaked email and press "Try this key"; Recall rotates the key.
        Ends REVERSED (nobody used it first) or EXPOSED (someone did).

The outage switch takes the relevant access log offline before Recall runs. Recall can still
revoke or rotate, but it cannot prove who got in, so the verdict is ESCALATED.
Nothing is rigged: verdicts come from the normal engine reading the normal mock logs.
"""

import secrets
import threading
import time

from recall.engine.recovery import RecoveryEngine
from recall.gateway.gateway import Gateway
from recall.ledger.ledger import Ledger
from recall.mocks.synthetic import load_roster
from recall.mocks.systems import World
from recall.scenario import Run
from recall.timeutil import iso

CARE_AGENT = "agent:care-coordinator"
SUPPORT_AGENT = "agent:support-bot"
WRONG_CLINIC = "intake@riverside-clinic.example"
CUSTOMER = "dana.whitfield@customer-mail.example"
PATIENT = "P-1004"
KEY_ID = "key-billing-prod"
KEY_SERVICE = "svc:billing-worker"
MODES = ("link", "key")


def device_label(user_agent: str) -> str:
    ua = user_agent or ""
    for key, label in (("iPhone", "iPhone"), ("iPad", "iPad"), ("Android", "Android"), ("Macintosh", "Mac"),
                       ("Windows", "Windows"), ("Linux", "Linux"), ("curl", "curl")):
        if key in ua:
            return label
    return "browser"


class LiveSession:
    def __init__(self, store):
        self.store = store
        self.lock = threading.RLock()
        self.reset()

    def reset(self):
        with self.lock:
            self.world = None
            self.ledger = None
            self.gateway = None
            self.action = None
            self.mode = None
            self.link_id = None
            self.message_id = None
            self.secret = None
            self.outage = False
            self.visitors = {}
            self.page_views = []
            self.run = None
            self.started = 0

    def _now(self):
        now = int(time.time())
        if self.world:
            self.world.clock.advance_to(max(now, self.world.clock.now))
        return now

    @property
    def status(self):
        if self.world is None:
            return "idle"
        return "recalled" if self.run else "sent"

    # ---- presenter actions -------------------------------------------------------------------

    def send(self, base_url=None, mode="link", outage=False):
        """Start a round. The outage is chosen per round and never carries over to the next one."""
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}")
        with self.lock:
            self.reset()
            self.outage = bool(outage)
            now = int(time.time())
            self.started = now
            self.mode = mode
            self.world = World(now, seed=f"live-{now}")
            if base_url:
                self.world.links.base = base_url.rstrip("/") + "/l/"
            self.ledger = Ledger()
            self.gateway = Gateway(self.world, self.ledger)
            if mode == "link":
                p = load_roster()[PATIENT]
                self.args = {"to": [WRONG_CLINIC], "subject": "Discharge summary",
                             "body": (f"Discharge summary for {p['first']} {p['last']} ({PATIENT}, {p['mrn']}, "
                                      f"DOB {p['dob']}). Admitted for {p['condition']}. Follow-up in 2 weeks.")}
                self.agent = CARE_AGENT
                self.action = self.gateway.submit(CARE_AGENT, "send_email", self.args)
                self.link_id = self.action["resources"]["links"][WRONG_CLINIC]
            else:
                self.secret = "rcl_live_" + secrets.token_hex(12)
                self.world.vault.add_key(KEY_ID, self.secret, KEY_SERVICE)
                self.args = {"to": [CUSTOMER], "subject": "Re: billing API errors",
                             "body": (f"Hi Dana, sorry about the errors on your side. Until we fix it, you can call "
                                      f"the billing API with our production key: {self.secret}")}
                self.agent = SUPPORT_AGENT
                self.action = self.gateway.submit(SUPPORT_AGENT, "send_email", self.args)
                self.message_id = self.action["resources"]["message_id"]
            return self.state()

    def set_outage(self, on: bool):
        with self.lock:
            if self.run is not None:
                raise RuntimeError("the incident has already been recalled")
            self.outage = bool(on)
            return self.state()

    def recall(self):
        with self.lock:
            if self.world is None:
                raise RuntimeError("nothing has been sent yet")
            if self.run is not None:
                return self.state()
            self._now()
            system = "links" if self.mode == "link" else "vault"
            if self.outage:
                self.world.faults.unavailable.add(system)
            incident_id = self.store.next_id()
            engine = RecoveryEngine(self.world, self.ledger, self.gateway, llm=self.store.llm)
            # The verdict comes back at once; drafts (possibly model-written) follow after the lock is
            # released, so phones polling the link never wait on drafting.
            result = engine.handle(incident_id, self.action["action_id"], source="presenter", write_drafts=False)
            title = {"link": "Live demo: patient record link", "key": "Live demo: leaked API key"}[self.mode]
            spec = {
                "id": f"live-{self.mode}-{self.started}", "title": title + (" (log outage)" if self.outage else ""),
                "expected": result["verdict"], "start": iso(self.started),
                "action": {"tool": "send_email", "agent": self.agent, "args": self.args},
                "events": self._audience_events(),
                "incident": {"at": self._offset(self.world.clock.now)},
                "faults": {"log_unavailable": [system]} if self.outage else {},
            }
            if self.mode == "key":
                spec["setup"] = {"keys": [{"id": KEY_ID, "secret": self.secret, "service": KEY_SERVICE}]}
            self.run = Run(spec, self.world, self.ledger, self.gateway, engine, self.action, result)
            self.store.add(incident_id, self.run)
            state = self.state()
        self.store.finish_drafts(self.run)
        return state

    # ---- audience actions --------------------------------------------------------------------

    def visitor(self, token, user_agent):
        """Stable label for a phone, kept by cookie: 'guest-3 (iPhone)'."""
        with self.lock:
            if token not in self.visitors:
                self.visitors[token] = f"guest-{len(self.visitors) + 1} ({device_label(user_agent)})"
            return self.visitors[token]

    def open_link(self, link_id, token, user_agent):
        """Returns (state, payload) where state is 'ok', 'revoked' or 'unknown'."""
        with self.lock:
            if self.mode != "link" or link_id not in self.world.links.links:
                return "unknown", None
            self._now()
            actor = self.visitor(token, user_agent)
            allowed = self.world.links.open(link_id, actor)
            self._after_recall("link_view", actor)
            if not allowed:
                return "revoked", self.link_status(link_id)
            link = self.world.links.links[link_id]
            return "ok", {"patient": load_roster()[PATIENT], "actor": actor, "link": link,
                          "expires": iso(link["expires_at"])}

    def link_status(self, link_id):
        with self.lock:
            if self.mode != "link" or link_id not in self.world.links.links:
                return {"active": False, "revoked_at": None, "unknown": True}
            self._now()
            st = self.world.links.status(link_id)
            return {"active": st["active"], "revoked_at": iso(st["revoked_at"])}

    def open_message(self, message_id, token, user_agent):
        """The leaked support email, as the customer (or anyone they forward it to) sees it."""
        with self.lock:
            if self.mode != "key" or message_id != self.message_id:
                return "unknown", None
            self._now()
            actor = self.visitor(token, user_agent)
            self.page_views.append((self.world.clock.now, actor))
            m = self.world.mail.messages[message_id]
            return "ok", {"actor": actor, "from": "support@stmarys-health.example", "to": CUSTOMER,
                          "subject": m["subject"], "body": m["body"], "secret": self.secret,
                          "sent_at": iso(m["sent_at"])}

    def try_key(self, message_id, token, user_agent):
        with self.lock:
            if self.mode != "key" or message_id != self.message_id:
                return None
            self._now()
            actor = self.visitor(token, user_agent)
            ok = self.world.vault.use(self.secret, actor)
            self._after_recall("key_use", actor)
            return {"ok": ok, "actor": actor, **self.key_status(message_id)}

    def key_status(self, message_id):
        with self.lock:
            if self.mode != "key" or message_id != self.message_id:
                return {"active": False, "rotated_at": None, "unknown": True}
            self._now()
            st = self.world.vault.status(KEY_ID)
            return {"active": st["status"] == "active", "rotated_at": iso(st["rotated_at"])}

    # ---- helpers -----------------------------------------------------------------------------

    def _offset(self, ts):
        d = ts - self.started
        return f"+{d // 3600:02d}:{d % 3600 // 60:02d}:{d % 60:02d}"

    def _after_recall(self, event_type, actor):
        """Keep the replay's no-Recall rerun in step with attempts made after the recall."""
        if self.run is not None:
            e = {"at": self._offset(self.world.clock.now), "type": event_type, "actor": actor}
            if event_type == "link_view":
                e["recipient"] = WRONG_CLINIC
            self.run.spec["events"].append(e)

    def _audience_events(self):
        if self.mode == "link":
            return [{"at": self._offset(e["ts"]), "type": "link_view", "actor": e["actor"], "recipient": WRONG_CLINIC}
                    for e in self.world.links.raw_log() if e["event"] == "view"]
        return [{"at": self._offset(e["ts"]), "type": "key_use", "actor": e["actor"]}
                for e in self.world.vault.raw_log() if e["event"] == "use"]

    def _log(self):
        """Ground truth for the presenter's screen, straight from the mock systems."""
        if self.mode == "link":
            out = []
            for e in self.world.links.raw_log():
                if e["event"] == "view":
                    kind = "open" if e["result"] == "allowed" else "blocked"
                    text = (f"{e['actor']} opened the discharge summary" if kind == "open"
                            else f"{e['actor']} tried the link: blocked")
                    out.append((e["ts"], kind, text))
                elif e["event"] == "revoke":
                    out.append((e["ts"], "recall", "Recall revoked the link"))
            return out
        out = [(ts, "saw", f"{actor} read the leaked email") for ts, actor in self.page_views]
        for e in self.world.vault.raw_log():
            if e["event"] == "use":
                kind = "open" if e["result"] == "allowed" else "blocked"
                text = (f"{e['actor']} used the key: it worked" if kind == "open"
                        else f"{e['actor']} tried the key: rejected")
                out.append((e["ts"], kind, text))
            elif e["event"] == "rotate":
                out.append((e["ts"], "recall", "Recall rotated the key"))
        return sorted(out, key=lambda x: x[0])

    def state(self):
        with self.lock:
            if self.world is None:
                return {"status": "idle", "outage": self.outage}
            self._now()
            log = self._log()
            n = {k: sum(1 for x in log if x[1] == k) for k in ("open", "blocked", "saw")}
            if self.mode == "link":
                st = self.world.links.status(self.link_id)
                mid = self.action["resources"]["messages"][WRONG_CLINIC]
                out = {"path": f"/l/{self.link_id}", "target_active": st["active"], "closed_at": iso(st["revoked_at"]),
                       "recipient": WRONG_CLINIC, "left": self.world.mail.messages[mid]["body"],
                       "counters": [{"label": "opens", "value": n["open"]},
                                    {"label": "devices", "value": len(self.visitors)},
                                    {"label": "blocked", "value": n["blocked"]}]}
            else:
                st = self.world.vault.status(KEY_ID)
                out = {"path": f"/m/{self.message_id}", "target_active": st["status"] == "active",
                       "closed_at": iso(st["rotated_at"]), "recipient": CUSTOMER,
                       "left": self.world.mail.messages[self.message_id]["body"],
                       "counters": [{"label": "saw the key", "value": len({a for _, a in self.page_views})},
                                    {"label": "key worked", "value": n["open"]},
                                    {"label": "rejected", "value": n["blocked"]}]}
            out.update(status=self.status, mode=self.mode, outage=self.outage, sent_at=iso(self.started),
                       agent=self.agent, original=self.args["body"], opened=n["open"], blocked=n["blocked"],
                       events=[{"at": iso(ts), "kind": k, "text": t} for ts, k, t in log])
            if self.run:
                out.update(incident_id=self.run.result["incident_id"], verdict=self.run.result["verdict"],
                           reasons=self.run.result["reasons"])
            return out
