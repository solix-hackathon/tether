"""Drafter: turns the engine's facts into an incident report, a HIPAA four-factor risk
assessment and a recipient deletion request. Templates are the deterministic baseline; when the
Anthropic SDK and credentials are available, Claude writes the drafts instead. Every draft,
template or model-written, must pass the fact guardrail; a rejected model draft falls back to the
template. All drafts start as pending human approval."""

import json
import os

from recall.config import MODEL
from recall.engine.rules import CONTAINED, ESCALATED, EXPOSED, REVERSED, accesses
from recall.nlp import guardrail


def _records(n):
    return f"{n} patient {'record' if n == 1 else 'records'}"


def _bullets(lines):
    return "\n".join(f"  - {line}" for line in lines) if lines else "  - none"


def incident_report(f):
    lines = [
        f"INCIDENT REPORT {f['incident_id']} (DRAFT: requires human approval)",
        "",
        f"Verdict: {f['verdict']}",
        f"Action: {f['action_id']} | tool {f['tool']} | agent {f['agent']} | class {f['action_class']}"
        f"{'' if f['via_gateway'] in (None, True) else ' | bypassed gateway'}",
        f"Executed: {f['action_at']}    Reported: {f['reported_at']}    Recovered: {f['recovered_at']}",
        f"Recipients / target: {', '.join(f['recipients']) or 'unknown'}",
        f"Data: {f['data_classification']}, {_records(f['record_count'])}"
        + (f" ({', '.join(f['subjects'])})" if f["subjects"] else ""),
        "",
        "Why this verdict:",
        _bullets(f["reasons"]),
        "",
        "What Recall did:",
        _bullets([f"{r['playbook']} on {r['resource']}: "
                  + (f"confirmed at {r['at']}" if r["confirmed"] else f"NOT confirmed ({r['error'] or 'still active'})")
                  for r in f["reversals"]]),
        "",
        "Evidence:",
        _bullets([f"{e['kind']} {e['resource']}: log {e['status']}"
                  + (f" ({'; '.join(e['notes'])})" if e["notes"] else "") for e in f["evidence"]]),
        "",
        f"Exposure: {accesses(f['view_count'])}",
        _bullets([f"{v['event']} by {v['actor']} at {v['at']}" for v in f["views"]]) if f["views"] else None,
        "",
        "Timeline:",
        _bullets([f"{t['at']}  {t['event']}: {t['detail']}" for t in f["timeline"]]),
        "",
        "Next steps:",
        _bullets(_next_steps(f)),
    ]
    return "\n".join(line for line in lines if line is not None)


def _next_steps(f):
    v = f["verdict"]
    if v == REVERSED:
        return ["confirm the reversal with the system owner", "close the incident after review"]
    if v == CONTAINED:
        return ["privacy officer reviews the risk assessment", "document the low-probability-of-compromise determination"]
    if v == EXPOSED:
        steps = ["privacy officer reviews the risk assessment and breach notification obligations"]
        if f.get("deletion_recipients"):
            steps.append("approve and send the deletion request")
        return steps
    return ["a human investigator must obtain the missing evidence before any determination",
            "treat as a presumed breach until evidence shows otherwise"]


def _unauthorized_parties(f):
    observed = sorted({v["actor"] for v in f["views"]})
    if f["tool"] == "share_file":
        who = f"anyone holding the public link to {', '.join(f['recipients'])}"
        return who + (f"; observed: {', '.join(observed)}" if observed else "; no outside access observed")
    return ", ".join(f["recipients"])


def risk_assessment(f):
    v = f["verdict"]
    if v == CONTAINED:
        factor3 = (f"Not acquired or viewed. Access was revoked at {f['contained_at']} and access logs covering "
                   f"the full window show {accesses(0)}.")
        outcome = "Low probability of compromise; supports a not-reportable determination, subject to review."
    elif v == EXPOSED:
        factor3 = f"Acquired or viewed: {accesses(f['view_count'])}; " + "; ".join(
            f"{x['actor']} at {x['at']}" for x in f["views"]) + "."
        outcome = "Presumed breach. Notification analysis is required."
    elif v == REVERSED:
        factor3 = "Not acquired or viewed: the action was fully undone before any access."
        outcome = "Low probability of compromise; supports a not-reportable determination, subject to review."
    else:
        factor3 = "Cannot be determined from available evidence: " + "; ".join(f["reasons"])
        outcome = "Undetermined. Treat as a presumed breach until evidence is obtained."
    mitig = [f"{r['playbook']} confirmed at {r['at']}" for r in f["reversals"] if r["confirmed"]]
    if f.get("deletion_recipients"):
        mitig.append("deletion request drafted for " + ", ".join(f["deletion_recipients"]) + " (pending approval)")
    return "\n".join([
        f"HIPAA BREACH RISK ASSESSMENT, FOUR-FACTOR (DRAFT) for {f['incident_id']}",
        f"Prepared from Recall verdict {v}. Not legal advice; the privacy officer makes the determination.",
        "",
        f"Factor 1. Nature and extent of PHI: {_records(f['record_count'])}"
        + (f" ({', '.join(f['subjects'])})" if f["subjects"] else "") + f", classification {f['data_classification']}.",
        f"Factor 2. Unauthorized person: {_unauthorized_parties(f)}.",
        f"Factor 3. Whether PHI was actually acquired or viewed: {factor3}",
        f"Factor 4. Extent of mitigation: {'; '.join(mitig) if mitig else 'no mitigation confirmed'}.",
        "",
        f"Preliminary indication: {outcome}",
    ])


def deletion_request(f):
    when = f["action_at"][:10]
    channel = "a shared file link" if f["tool"] == "share_file" else (
        "a secure link" if f["action_class"] == "revocable" else "email")
    return "\n".join([
        f"To: {', '.join(f['deletion_recipients'])}",
        f"From: {f['contact']}",
        "Subject: Request to delete information sent to you in error",
        "",
        "Hello,",
        "",
        f"On {when}, {f['org']} sent you information in error through {channel}. It contains confidential "
        "health information that was not intended for you.",
        "",
        "Please delete every copy you hold, including downloads, forwards and printouts, do not use or share it, "
        f"and reply to {f['contact']} to confirm the deletion.",
        "",
        "Thank you for your help.",
        f"Privacy Office, {f['org']}",
    ])


TEMPLATES = {"incident_report": incident_report, "risk_assessment": risk_assessment,
             "deletion_request": deletion_request}


def kinds_for(f):
    kinds = ["incident_report"]
    if f["data_classification"] == "PHI":
        kinds.append("risk_assessment")
    if f.get("deletion_recipients"):
        kinds.append("deletion_request")
    return kinds


SYSTEM_PROMPT = """You draft incident documents for a hospital privacy office. You receive the \
structured output of a deterministic recovery engine and a template draft built from it.

Rewrite the template into a clear, professional document of the requested kind. Rules:
- Use only facts present in the engine output. Do not invent names, times, counts, addresses or identifiers.
- Copy timestamps exactly in the form 2026-01-01T09:00:00Z. Copy identifiers and email addresses exactly.
- State the verdict word exactly as given, in capitals, and never write any other verdict word in capitals.
- Never include patient names. In a deletion request, never include patient identifiers.
- Output only the document text, with no preamble."""


def _llm_enabled(llm):
    if llm is False:
        return False
    if llm is True:
        return True
    return bool(os.environ.get("ANTHROPIC_API_KEY")) and os.environ.get("RECALL_LLM", "1") != "0"


def llm_draft(kind, facts, template_text):
    """Ask Claude for a draft. Returns text, or None when the model is unavailable or declines."""
    try:
        import anthropic
    except ImportError:
        return None
    try:
        client = anthropic.Anthropic()
        response = client.messages.create(
            model=MODEL,
            max_tokens=4000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content":
                       f"Document kind: {kind}\n\nEngine output (JSON):\n{json.dumps(facts, indent=2)}\n\n"
                       f"Template draft:\n{template_text}"}],
            extra_headers={"anthropic-beta": "server-side-fallback-2026-07-01"},
            extra_body={"output_config": {"effort": "low"}, "fallbacks": "default"},
        )
    except anthropic.APIError:
        return None
    if response.stop_reason == "refusal":
        return None
    text = "".join(b.text for b in response.content if b.type == "text").strip()
    return text or None


def draft_all(facts, llm=None):
    use_llm = _llm_enabled(llm)
    drafts = []
    for kind in kinds_for(facts):
        template_text = TEMPLATES[kind](facts)
        text, source, llm_rejection = template_text, "template", None
        if use_llm:
            candidate = llm_draft(kind, facts, template_text)
            if candidate is not None:
                verdict = guardrail.check(kind, candidate, facts)
                if verdict["ok"]:
                    text, source = candidate, "llm"
                else:
                    llm_rejection = verdict["violations"]
        check = guardrail.check(kind, text, facts)
        drafts.append({"kind": kind, "text": text, "source": source, "guardrail": check,
                       "llm_rejected": llm_rejection,
                       "status": "pending_approval" if check["ok"] else "blocked"})
    return drafts
