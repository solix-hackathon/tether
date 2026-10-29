"""Scenario runner: builds a fresh mock world from a JSON spec, routes the agent action through the
gateway (or around it), replays access events, raises the incident and runs recovery."""

import json
from dataclasses import dataclass
from pathlib import Path

from recall.engine.recovery import RecoveryEngine
from recall.gateway.gateway import Gateway, record_bypass
from recall.ledger.ledger import Ledger
from recall.mocks.systems import FaultPlan, World
from recall.timeutil import parse_iso, resolve

ROOT = Path(__file__).resolve().parents[1]
SCENARIO_DIR = ROOT / "scenarios"


@dataclass
class Run:
    spec: dict
    world: World
    ledger: Ledger
    gateway: Gateway
    engine: RecoveryEngine
    action: dict
    result: dict


def load(path):
    return json.loads(Path(path).read_text())


def load_dir(name):
    return [load(p) for p in sorted((SCENARIO_DIR / name).glob("*.json"))]


def _setup(world, setup):
    for f in setup.get("files", []):
        world.files.add_file(f["id"], f["name"], f["records"], f.get("owner", "svc:ehr-export"))
    for k in setup.get("keys", []):
        world.vault.add_key(k["id"], k["secret"], k["service"])


def _apply(world, ledger, gateway, action_id, e):
    action = ledger.get_action(action_id)
    res = action.get("resources") or {}
    kind = e["type"]
    if kind == "link_view":
        links = res["links"]
        world.links.open(links[e.get("recipient") or next(iter(links))], e["actor"])
    elif kind == "file_access":
        world.files.access(res["share_id"], e["actor"])
    elif kind == "key_use":
        kid = e.get("key") or res["key_ids"][0]
        world.vault.use(world.vault.keys[kid]["secret"], e["actor"])
    elif kind == "mail_read":
        world.mail.read(res["message_id"], e["actor"])
    elif kind == "order_fulfill":
        world.orders.fulfill(res["order_id"])
    elif kind == "approve_hold":
        gateway.approve(action_id, e["actor"])
    else:
        raise ValueError(f"unknown event type {kind!r}")


def run_scenario(spec, llm=False, incident_id="INC-0001", drafts=True):
    start = parse_iso(spec["start"])
    world = World(start, faults=FaultPlan(spec.get("faults"), start), seed=spec.get("id", "scenario"))
    _setup(world, spec.get("setup", {}))
    ledger = Ledger()
    gateway = Gateway(world, ledger)
    engine = RecoveryEngine(world, ledger, gateway, llm=llm)

    act = spec["action"]
    world.clock.advance_to(resolve(act.get("at", "+00:00:00"), start))
    agent = act.get("agent", "agent:care-coordinator")
    if act.get("via_gateway", True):
        out = gateway.submit(agent, act["tool"], act["args"])
    else:
        out = record_bypass(world, ledger, agent, act["tool"], act["args"])
    action_id = out["action_id"]

    incident_at = resolve(spec["incident"]["at"], start)
    events = sorted(((resolve(e["at"], start), i, e) for i, e in enumerate(spec.get("events", []))),
                    key=lambda x: (x[0], x[1]))
    for ts, _, e in [x for x in events if x[0] <= incident_at]:
        world.clock.advance_to(ts)
        _apply(world, ledger, gateway, action_id, e)
    world.clock.advance_to(incident_at)
    gateway.expire_holds()
    result = engine.handle(incident_id, action_id, source=spec["incident"].get("source", "human_report"),
                           write_drafts=drafts)
    # Attempts after recovery: these should all be denied by the target systems.
    for ts, _, e in [x for x in events if x[0] > incident_at]:
        world.clock.advance_to(ts)
        _apply(world, ledger, gateway, action_id, e)
    return Run(spec, world, ledger, gateway, engine, out, result)
