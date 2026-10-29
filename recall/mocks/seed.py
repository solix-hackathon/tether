"""Build the synthetic data set: patient roster, plus a snapshot of each demo world (links,
shares, keys, mail and access logs) for inspection.

    cd recall && python3 mocks/seed.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from recall.mocks.synthetic import DATA_DIR, ROSTER_PATH, generate  # noqa: E402
from recall.scenario import load_dir, run_scenario  # noqa: E402


def main():
    DATA_DIR.mkdir(exist_ok=True)
    roster = generate()
    ROSTER_PATH.write_text(json.dumps(roster, indent=2) + "\n")
    print(f"wrote {len(roster)} synthetic patients -> {ROSTER_PATH}")

    out = DATA_DIR / "worlds"
    out.mkdir(exist_ok=True)
    for spec in load_dir("seeded"):
        run = run_scenario(spec)
        snap = {"scenario": spec["id"], "world": run.world.snapshot(), "ledger": run.ledger.entries()}
        (out / f"{spec['id']}.json").write_text(json.dumps(snap, indent=2, default=str) + "\n")
    print(f"wrote {len(list(out.glob('*.json')))} seeded world snapshots -> {out}")


if __name__ == "__main__":
    main()
