"""Incident store with the human-in-the-loop step. Nothing outbound leaves without approval, and
an edited draft is re-checked by the guardrail before it can be approved."""

import threading

from recall.config import PRIVACY_CONTACT
from recall.nlp import guardrail
from recall.nlp.drafter import _llm_enabled
from recall.scenario import run_scenario
from recall.timeutil import iso


class ApprovalError(Exception):
    pass


class IncidentStore:
    def __init__(self, llm=None):
        self.llm = llm
        self.runs = {}
        self._count = 0
        self._lock = threading.Lock()

    def next_id(self):
        with self._lock:
            self._count += 1
            return f"INC-{self._count:04d}"

    def add(self, incident_id, run):
        self.runs[incident_id] = run

    def clear(self):
        """Drop every incident (demo data only lives in memory). Ids keep counting up."""
        self.runs.clear()

    @property
    def drafts_in_background(self):
        """Model drafting can take many seconds; templates are instant and stay synchronous."""
        return _llm_enabled(self.llm)

    def finish_drafts(self, run):
        if not run.result.get("drafts_pending"):
            return
        if self.drafts_in_background:
            threading.Thread(target=run.engine.write_drafts, args=(run.result,), daemon=True).start()
        else:
            run.engine.write_drafts(run.result)

    def run(self, spec):
        incident_id = self.next_id()
        run = run_scenario(spec, llm=self.llm, incident_id=incident_id, drafts=False)
        self.add(incident_id, run)
        self.finish_drafts(run)
        return run.result

    def get(self, incident_id):
        if incident_id not in self.runs:
            raise KeyError(incident_id)
        return self.runs[incident_id]

    def _draft(self, incident_id, kind):
        for d in self.get(incident_id).result["drafts"]:
            if d["kind"] == kind:
                return d
        raise KeyError(f"{incident_id} has no {kind} draft")

    def approve(self, incident_id, kind, approver, text=None):
        run = self.get(incident_id)
        d = self._draft(incident_id, kind)
        if d["status"] not in ("pending_approval", "blocked"):
            raise ApprovalError(f"{kind} is already {d['status']}")
        if not approver:
            raise ApprovalError("an approver is required")
        if text is not None and text != d["text"]:
            check = guardrail.check(kind, text, run.result["facts"])
            if not check["ok"]:
                raise ApprovalError("edited draft rejected by the fact guardrail: " + "; ".join(check["violations"]))
            d.update(text=text, source="human-edited", guardrail=check)
        if not d["guardrail"]["ok"]:
            raise ApprovalError("draft is blocked by the fact guardrail and cannot be approved")
        now = run.world.clock.now
        d.update(status="approved", approved_by=approver, approved_at=iso(now))
        run.ledger.append("draft_approved", now, incident_id=incident_id, kind=kind, approver=approver)
        if kind == "deletion_request":
            to = run.result["facts"]["deletion_recipients"]
            mid = run.world.mail.send(PRIVACY_CONTACT, to, "Request to delete information sent to you in error", d["text"])
            d.update(status="sent", message_id=mid)
            run.ledger.append("notice_sent", now, incident_id=incident_id, kind=kind, to=to, message_id=mid)
        return d

    def reject(self, incident_id, kind, approver, reason=""):
        run = self.get(incident_id)
        d = self._draft(incident_id, kind)
        d.update(status="rejected", rejected_by=approver, reason=reason)
        run.ledger.append("draft_rejected", run.world.clock.now, incident_id=incident_id, kind=kind,
                          approver=approver, reason=reason)
        return d
