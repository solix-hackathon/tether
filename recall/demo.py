"""Run the three demo scenarios from the command line.

    cd recall && python3 demo.py            # templates only
    cd recall && python3 demo.py --llm      # let Claude draft (needs ANTHROPIC_API_KEY)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recall.incidents import IncidentStore  # noqa: E402
from recall.scenario import load_dir  # noqa: E402

COLORS = {"REVERSED": "\033[32m", "CONTAINED": "\033[36m", "EXPOSED": "\033[31m", "ESCALATED": "\033[33m"}
RESET = "\033[0m"


def main():
    store = IncidentStore(llm=True if "--llm" in sys.argv else False)
    demos = sorted((s for s in load_dir("seeded") if s.get("demo")), key=lambda s: s["demo"])
    for spec in demos:
        r = store.run(spec)
        print("=" * 78)
        print(f"Scenario {spec['demo']}: {spec['title']}")
        print(f"Verdict:  {COLORS[r['verdict']]}{r['verdict']}{RESET}   (expected {spec['expected']})")
        for reason in r["reasons"]:
            print(f"  why: {reason}")
        for rev in r["facts"]["reversals"]:
            state = f"confirmed at {rev['at']}" if rev["confirmed"] else f"FAILED: {rev['error']}"
            print(f"  did: {rev['playbook']} {rev['resource']} {state}")
        for d in r["drafts"]:
            ok = "passed" if d["guardrail"]["ok"] else "BLOCKED"
            print(f"  draft: {d['kind']:<17} source={d['source']:<8} guardrail {ok}, status {d['status']}")
        main_draft = r["drafts"][-1] if spec["demo"] == 3 else r["drafts"][min(1, len(r["drafts"]) - 1)]
        print("-" * 78)
        print(main_draft["text"])
    print("=" * 78)
    print("All drafts are pending human approval. Open the dashboard (python3 app.py) to approve them.")


if __name__ == "__main__":
    main()
