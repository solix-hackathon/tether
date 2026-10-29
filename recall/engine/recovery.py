"""Recovery engine: given an incident, find the action in the ledger, run its playbooks, collect
evidence, decide a verdict and hand the structured facts to the drafter. Fully deterministic;
the language model never influences a verdict."""

from recall.config import ORG_NAME, PRIVACY_CONTACT, is_internal
from recall.engine import playbooks
from recall.engine.rules import CONTAINED, ESCALATED, EXPOSED, REVERSED, decide
from recall.evidence.collector import collect, timeline
from recall.timeutil import iso


class RecoveryEngine:
    def __init__(self, world, ledger, gateway=None, llm=None):
        self.world = world
        self.ledger = ledger
        self.gateway = gateway
        self.llm = llm  # None = auto (use the model when configured), False = templates only

    def handle(self, incident_id, action_id, source="human_report", write_drafts=True):
        """Recover and decide. With write_drafts=False the result comes back as soon as the verdict
        is known, with drafts_pending set; call write_drafts(result) later (it may call the model)."""
        now = self.world.clock.now
        self.ledger.append("incident_opened", now, incident_id=incident_id, action_id=action_id, source=source)
        action = self.ledger.get_action(action_id)
        reversals, evidence = [], []

        if action is None:
            verdict, reasons = decide(None, [], [])
        elif action["status"] == "held":
            reversals = [self._cancel_hold(action)]
            if reversals[0]["confirmed"]:
                verdict, reasons = REVERSED, ["the action was held by the gateway and cancelled before execution; "
                                              "nothing left the organization"]
            else:
                verdict, reasons = ESCALATED, ["the held action could not be cancelled"]
        elif action["status"] == "rejected":
            verdict, reasons = REVERSED, ["the action was rejected during its hold window and never executed"]
        else:
            reversals = playbooks.run(self.world, action)
            evidence = collect(self.world, action, reversals)
            verdict, reasons = decide(action, reversals, evidence)

        for r in reversals:
            self.ledger.append("reversal", self.world.clock.now, incident_id=incident_id, action_id=action_id, **r)
        self.ledger.append("verdict", self.world.clock.now, incident_id=incident_id, action_id=action_id,
                           verdict=verdict, reasons=reasons)

        facts = build_facts(incident_id, action_id, action, reversals, evidence, verdict, reasons, now,
                            self.world.clock.now)
        result = {"incident_id": incident_id, "action_id": action_id, "verdict": verdict, "reasons": reasons,
                  "action": action, "reversals": reversals, "evidence": evidence, "facts": facts,
                  "drafts": [], "drafts_pending": True}
        if write_drafts:
            self.write_drafts(result)
        return result

    def write_drafts(self, result):
        from recall.nlp.drafter import draft_all  # local import keeps the engine free of NLP at import time
        drafts = draft_all(result["facts"], llm=self.llm)
        for d in drafts:
            self.ledger.append("draft_created", self.world.clock.now, incident_id=result["incident_id"],
                               kind=d["kind"], status=d["status"], source=d["source"],
                               guardrail_ok=d["guardrail"]["ok"])
        result["drafts"] = drafts
        result["drafts_pending"] = False
        return drafts

    def _cancel_hold(self, action):
        aid = action["action_id"]
        try:
            self.gateway.reject(aid, "svc:recall", "incident raised before approval")
        except (KeyError, AttributeError):
            pass
        after = self.ledger.get_action(aid)
        return {"playbook": "cancel_hold", "resource": aid, "confirmed": after["status"] == "rejected",
                "at": self.world.clock.now, "error": None}


def _deletion_recipients(action, verdict, views):
    if action is None or verdict not in (EXPOSED, ESCALATED) or action["status"] != "executed":
        return []
    if not action["data"]["records"]:
        return []
    viewers = sorted({v["actor"] for v in views if "@" in v["actor"] and not is_internal(v["actor"])})
    if verdict == EXPOSED and viewers:
        return viewers
    if action["tool"] == "send_email":
        return sorted(r for r in action["target"] if not is_internal(r))
    return viewers


def build_facts(incident_id, action_id, action, reversals, evidence, verdict, reasons, reported_at, now):
    """The engine's structured output. Every fact a draft may state comes from here."""
    views = [{"actor": a["actor"], "at": iso(a["ts"]), "resource": i["resource"], "event": a["event"]}
             for i in evidence for a in i["access"]]
    contained = [r["at"] for r in reversals if r["confirmed"] and r["at"] is not None]
    facts = {
        "org": ORG_NAME,
        "contact": PRIVACY_CONTACT,
        "incident_id": incident_id,
        "action_id": action_id,
        "verdict": verdict,
        "reasons": reasons,
        "reported_at": iso(reported_at),
        "recovered_at": iso(now),
        "contained_at": iso(max(contained)) if contained and len(contained) == len(reversals) else None,
        "views": views,
        "view_count": len(views),
        "reversals": [{**r, "at": iso(r["at"])} for r in reversals],
        "evidence": [{"kind": i["kind"], "resource": i["resource"], "status": i["status"], "notes": i["notes"],
                      "window_start": iso(i["window"]["start"]), "window_end": iso(i["window"]["end"])}
                     for i in evidence],
    }
    if action is None:
        facts.update(agent=None, tool=None, action_class=None, via_gateway=None, recipients=[],
                     data_classification="UNKNOWN", record_count=0, subjects=[], action_at=None,
                     timeline=[{"at": iso(reported_at), "event": "incident_reported", "detail": "incident raised"}],
                     deletion_recipients=[])
        return facts
    executed_at = action.get("executed_at")
    facts.update(
        agent=action["agent"],
        tool=action["tool"],
        action_class=action["action_class"],
        action_status=action["status"],
        via_gateway=action["via_gateway"],
        recipients=action["target"],
        data_classification=action["data"]["classification"],
        record_count=action["data"]["record_count"],
        subjects=action["data"]["records"],
        key_ids=action["data"]["key_ids"],
        action_at=iso(executed_at if executed_at is not None else action["ts"]),
        deletion_recipients=_deletion_recipients(action, verdict, views),
    )
    if action["status"] == "executed":
        facts["timeline"] = timeline(action, reversals, evidence, reported_at)
    else:
        facts["timeline"] = [
            {"at": iso(action["ts"]), "event": "action_held", "detail": f"{action['tool']} held by the gateway"},
            {"at": iso(reported_at), "event": "incident_reported", "detail": "incident raised"},
        ] + [{"at": iso(r["at"]), "event": r["playbook"], "detail": f"hold cancelled for {r['resource']}"}
             for r in reversals if r["confirmed"]]
    return facts
