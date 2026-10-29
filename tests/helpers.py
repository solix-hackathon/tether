import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from recall.gateway.gateway import Gateway  # noqa: E402
from recall.ledger.ledger import Ledger  # noqa: E402
from recall.mocks.systems import FaultPlan, World  # noqa: E402
from recall.timeutil import parse_iso  # noqa: E402

START = parse_iso("2026-05-01T09:00:00Z")
SECRET = "rcl_live_AbCdEfGhIjKlMnOpQrStUv12"
ORG = "stmarys-health.example"


def make(faults=None):
    world = World(START, faults=FaultPlan(faults, START), seed="test")
    world.vault.add_key("key-test", SECRET, "svc:test-worker")
    world.files.add_file("F-1", "export.csv", ["P-1001", "P-1002"], "svc:ehr-export")
    ledger = Ledger()
    return world, ledger, Gateway(world, ledger)


def advance(world, seconds):
    world.clock.advance_to(world.clock.now + seconds)
