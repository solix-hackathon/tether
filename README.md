# Recall: Damage Control for AI Agents

AI agents can undo a database change. They can't unsend an email. Recall handles the actions that can't be undone.

When an AI agent sends a patient record to the wrong clinic, shares a file publicly, or leaks an API key, a database rollback does nothing. Recall works out what is still within your control after the action happened, takes it back where it can, contains it where it can't, and proves exactly what was exposed so the organization knows whether it has a reportable breach.

> **Hackathon prototype, not a compliance product.** Built for the Solix AI Hackathon 2026 (AI Safety & Security track). All data is synthetic and all external systems (mail, file sharing, key vault, orders, fax) are mocks with access logs. See [What's real and what's mocked](#whats-real-and-whats-mocked). Nothing here is legal or regulatory advice.

## Quickstart

Python 3.10+. No dependencies. Install the `anthropic` package and set `ANTHROPIC_API_KEY` if you want Claude to write the drafts. Without them, Recall uses deterministic templates, and every draft passes through the same fact guardrail either way.

```bash
cd recall
python3 mocks/seed.py      # build synthetic patients, links, logs
python3 app.py             # dashboard at http://127.0.0.1:8000
python3 demo.py            # run all three scenarios from the command line (--llm to use Claude)
```

## Dashboard

- **New incident** opens a picker of the 24 seeded and held-out scenarios; the three demos come first.
- Each incident has six tabs:
  - **Replay:** an animated, side-by-side run of the same events with and without Recall, ending in a comparison table. Large audiences are batched into a few steps.
  - **Overview:** the verdict in plain words and the key numbers.
  - **Timeline:** every event in order.
  - **Evidence:** what Recall did and which access logs it trusted.
  - **Drafts:** the report, risk assessment and deletion request, editable and approvable. An edit is re-checked by the guardrail.
  - **Ledger:** the hash-chained record, with a tamper check.
- **Live demo** in the sidebar runs the audience demo below, and **Clear all** empties the incident list between rehearsals.

## Live audience demo

The audience's phones become the "outside world":

```bash
cd recall
python3 app.py --live      # phones on the same Wi-Fi can open the secure links
```

Open http://127.0.0.1:8000 on the presenting laptop, choose **Live demo** in the sidebar, and pick a round. The room scans the QR code; each phone appears in the live activity log as `guest-N (device)`. **Projector view** shows a full-screen QR code, live counters and the Recall button (Esc to exit). Use **Reset demo** between rounds.

| Round | What the room sees | Possible verdicts |
|---|---|---|
| **A · Patient record link** | The synthetic discharge summary. Press **Recall it** and every open phone flips to "This link has been revoked" within two seconds. | CONTAINED if you recall before anyone opens it, EXPOSED if someone did |
| **B · Leaked API key** | The leaked email with the key and a **Try this key** button that calls the mock billing API. Press **Rotate the key**: the email stays (it can't be unsent), a banner says the key no longer works, and tries return 401. | REVERSED if you rotate before anyone uses the key, EXPOSED if someone did |
| **C · Access log outage** | The same as round A; the link is still revoked. | Always ESCALATED: Recall can't read who got in, so it refuses to guess |

Verdicts are not scripted. Each round runs through the normal gateway, engine, evidence checks, drafts, ledger and replay. Recall answers immediately; when Claude is writing the drafts they follow a few seconds later, so phones never wait on the model.

In `--live` mode, other devices can reach only the phone pages (`/l/` for links, `/m/` for the leaked email and its Try button); the dashboard and its API answer only this machine. If the venue Wi-Fi blocks device-to-device traffic, run a tunnel (for example `ngrok http 8000`) and start with `RECALL_PUBLIC_URL=https://<tunnel-host> python3 app.py --live`. Requests that arrive through a tunnel are also limited to the link pages. The QR code is generated locally, so no internet connection is needed on the same Wi-Fi.

## Validation

Every scenario is synthetic and seeded with a known correct verdict. Run from the repository root:

```bash
python3 -m unittest discover -s tests     # 66 unit tests: playbooks, rules, guardrail, ledger, replay, live demo, QR, access guard
python3 validation/harness.py             # seeded scenarios: verdict accuracy
python3 validation/holdout.py             # held-out scenarios never used during rule development
python3 validation/fuzz.py                # missing logs, partial failures, clock skew, guardrail mutations
python3 validation/verify_all.py          # one command: RESULT: PASS / FAIL
```

| Target | Current result |
|---|---|
| 100% correct verdicts on seeded scenarios | 14 / 14 |
| 100% correct verdicts on held-out scenarios | 10 / 10 |
| Zero false CONTAINED (or REVERSED) under fuzzing | 0 in 600 incidents, 302 with injected faults |
| Zero false EXPOSED under fuzzing | 0 |
| Zero drafts passing the guardrail with a mismatched fact | 0 of 8,885 mutated drafts |

## How it works

Recall responds to every irreversible action in three tiers, tried in order.

1. **Reverse.** Many actions that look final have a kill switch. A public share can be revoked. A leaked key can be rotated so the leaked copy is worthless. An order can be cancelled through the API that created it, and an internal email can be purged by an admin.
2. **Contain by design: send pointers, not payloads.** The gateway rewrites outbound email so sensitive data travels as an expiring, revocable, per-recipient link. "Unsend" becomes "revoke the link."
3. **Prove.** When nothing can be reversed, Recall checks the access logs to answer whether the data was exposed. It assigns a verdict, then drafts the incident report, a HIPAA four-factor risk assessment and a deletion request for human review.

### Verdicts

| Verdict | Meaning | Required evidence |
|---|---|---|
| `REVERSED` | The action was fully undone | Reversal confirmed by the target system |
| `CONTAINED` | Access revoked before anyone viewed the data | Revocation confirmed, and the access log shows zero views |
| `EXPOSED` | Data was viewed by an unauthorized party | Access log shows at least one external view |
| `ESCALATED` | Recall cannot prove either way | Missing or incomplete evidence |

Recall never declares `CONTAINED` without positive evidence. Missing logs mean `ESCALATED`, never "probably fine."

### Ground rules (enforced in code)

- **The engine decides; the language model only writes.** Classification, playbooks and verdicts come from `recall/engine/rules.py`. The drafter never sees a verdict it could change. The guardrail (`recall/nlp/guardrail.py`) extracts verdict words, timestamps, dates, clock times, email addresses, identifiers, record counts, access counts and patient names, and blocks any draft containing a fact the engine did not produce. A blocked Claude draft falls back to the template.
- **When in doubt, escalate.** The rules are ordered so that every uncertain outcome lands on `ESCALATED`: inconsistent logs, unavailable logs, logs without coverage metadata, logs that start after the action, failed or unconfirmed reversals, unknown credentials, and data that left with no visibility.
- **Human in the loop for anything outbound.** Reversals inside owned systems run automatically. Reports, assessments and deletion requests stay `pending_approval` until a named person approves them. An edited draft is re-checked by the guardrail before approval, and the deletion request is only sent after approval.
- **Synthetic data only.** Patients are generated by `recall/mocks/synthetic.py`. Domains use `.example`.

## What counts as evidence

The evidence collector (`recall/evidence/collector.py`) treats a log as positive evidence only if all four of these hold:

- the log is **available**
- it carries **coverage metadata** that spans the whole window from the action to the revocation
- its clock agrees with the reference clock within 2 seconds
- it doesn't contradict itself or the revocation record. Two examples of contradiction: an entry that predates the resource, or an access that was allowed after revocation.

Playbooks never trust the return value of their own call. After acting, each one re-reads the target system's state to confirm the result.

Known limit: if a log silently drops entries while still claiming complete coverage, Recall cannot detect it. No log consumer can. The mocks report coverage honestly, and the fuzzer does not inject silent drops.

## Architecture

```
AI agent
   │
   ▼
Recall Gateway ── classifier (revocable / compensable / purgeable / irreversible)
   │              payload rewriter (records → expiring per-recipient link)
   │              hold window (irreversible + sensitive waits for approval)
   ▼
Action ledger (append-only, hash-chained)  ◄── incident trigger (human report or detector)
   │
   ▼
Recovery engine ── playbooks: revoke links · revoke share · rotate key · purge mail · cancel order · cancel hold
   │                    │
   │                    ▼
   │            mock systems (links · file share · key vault · orders · mail · outbound) + access logs
   ▼                    │
Evidence collector ◄────┘
   │
   ▼
Verdict (REVERSED · CONTAINED · EXPOSED · ESCALATED)
   │
   ▼
Drafter (template, or Claude in the background) ─► fact guardrail ─► human approval ─► notice sent
```

Around the engine sits the presentation layer, which reads the same ledger and mock logs:

```
Dashboard (recall/app.py + static/index.html, laptop only)
   ├── Incidents: replay · overview · timeline · evidence · drafts · ledger
   ├── Replay (recall/replay.py) ── reruns the same events with no gateway and no recovery
   └── Live demo (recall/live.py) ── wall-clock session on the real gateway, engine and mocks
          │
          ▼
   Phone pages (recall/phone.py, any device on the Wi-Fi or tunnel)
       /l/<link>   discharge summary → flips to "revoked"
       /m/<email>  leaked key email → "Try this key" → 200 or 401
       QR code (recall/qr.py, generated locally)
```

### Action catalog

| Agent action | Class | Recall's response |
|---|---|---|
| Email with sensitive data (rewritten to link) | Revocable | Revoke link, check views |
| Public file share | Revocable | Revoke share, check views |
| API key in outbound message | Revocable | Rotate key, check usage of old key |
| Third-party order or refund | Compensable | Call cancel API |
| Internal email | Purgeable | Admin purge, check reads |
| Fax / partner post with sensitive data | Irreversible | Held for approval; cancelled if an incident arrives first |
| Raw data sent externally (bypassed gateway) | Irreversible | Evidence, verdict, deletion request, report |

## Demo scenarios

1. **Wrong clinic, never opened.** Recall revokes the link and the access log shows zero views. Verdict `CONTAINED`, and the risk assessment is pre-filled with "not acquired or viewed."
2. **Leaked API key.** Recall rotates the key four minutes after the leak and confirms the old key was used only by the owning service. Verdict `REVERSED`. A later attempt from outside is denied.
3. **Opened externally.** An outside address downloaded the shared file 40 minutes before the incident was raised. Recall revokes access, and the verdict is `EXPOSED`. It drafts the incident report with a full timeline, a risk assessment and a deletion request to the recipient, all waiting for human approval.

## Repository layout

| Path | What |
|---|---|
| `recall/gateway/` | Action classifier, payload rewriter, hold window, bypass recording |
| `recall/engine/` | Recovery engine, playbooks, verdict rules |
| `recall/ledger/` | Append-only, hash-chained action ledger |
| `recall/evidence/` | Access log readers, trust checks and exposure timeline |
| `recall/nlp/` | Drafter (templates and Claude) and fact guardrail |
| `recall/mocks/` | Mail, file share, key vault, order API, outbound channel, synthetic data, seed |
| `recall/scenario.py` | Scenario runner: builds a fresh mock world, replays events, raises the incident |
| `recall/incidents.py` | Incident store, background drafting and human approval |
| `recall/app.py`, `recall/static/index.html` | Dashboard server and single-page UI (standard library only) |
| `recall/config.py`, `recall/timeutil.py` | Synthetic org settings and simulated time |
| `recall/live.py`, `recall/phone.py`, `recall/qr.py` | Live audience demo: wall-clock session, phone pages, dependency-free QR encoder |
| `recall/replay.py` | Side-by-side replay with a no-Recall rerun of the same events |
| `scenarios/` | Seeded and held-out incident scenarios (JSON) |
| `validation/` | Harness, fuzzer, verifier |
| `tests/` | Unit tests |

## LLM drafting

When `ANTHROPIC_API_KEY` is set and the `anthropic` package is installed, the dashboard asks `claude-opus-5-5` (low effort) to rewrite each template draft. Drafting runs in the background: the verdict and reversal are shown at once, and the Drafts tab says "Claude is writing the drafts…" until they arrive. The request opts into server-side refusal fallbacks (`fallbacks: "default"`). A refusal, an API error, or a draft that fails the guardrail all fall back to the template, and the dashboard shows the rejected facts. Set `RECALL_LLM=0` to force templates. The validation suite always runs with templates so its results are deterministic.

## What's real and what's mocked

| Real, working code | Mocked or synthetic |
|---|---|
| Gateway classification, payload rewriting and hold window | Mail server, file share, key vault, order API, fax line and "billing API" (in-memory, with access logs) |
| Recovery playbooks, evidence checks and verdict rules | Patients: 40 generated names and record numbers, labelled synthetic |
| Hash-chained ledger with tamper detection | Domains: `.example` addresses that can never exist |
| Fact guardrail and draft templates | Agents: scripted actions in scenario files, or a button press in the live demo |
| Dashboard, replay and the no-Recall rerun | Time: simulated in scenarios (the live demo uses the real clock) |
| Live demo links served to real phones, real revocation, local QR codes | Storage: everything is in memory and cleared on restart |
| Claude drafting code (runs only when an API key is set) | |

To go to production, each mock is swapped for a connector (Gmail or Microsoft 365, Google Drive sharing, a secrets manager, Stripe), a real agent is connected through its tool calls, and the ledger moves to a database. The engine, rules and guardrail do not change.

## Related work

Rubrik Agent Rewind (snapshot-based recovery of agent changes), EvoUndo and UndoLane (selective undo that preserves later human edits) and Backtrack (cause-and-effect undo planning across agents) all address state inside owned systems. Secure email products such as Virtru offer revocable messages for humans. Recall focuses on the gap between them: recovery and proof of exposure for agent actions that leave the organization.

## Roadmap

Real connectors for Google Workspace and Microsoft 365, GDPR breach workflows alongside HIPAA, a detector that raises incidents automatically from anomalous outbound actions, and per-recipient link policies (expiry, single view, watermarking).
