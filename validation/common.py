import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from recall.scenario import load_dir, run_scenario  # noqa: E402


def score(set_name):
    specs = load_dir(set_name)
    rows, correct, guard_fail = [], 0, 0
    for s in specs:
        r = run_scenario(s, llm=False).result
        ok = r["verdict"] == s["expected"]
        correct += ok
        bad = [d["kind"] for d in r["drafts"] if not d["guardrail"]["ok"]]
        guard_fail += bool(bad)
        rows.append((s["id"], s["expected"], r["verdict"], ok, bad))
    width = max(len(r[0]) for r in rows)
    print(f"{'scenario':<{width}}  {'expected':<10} {'got':<10} result")
    for sid, exp, got, ok, bad in rows:
        note = "" if not bad else f"  guardrail blocked {bad}"
        print(f"{sid:<{width}}  {exp:<10} {got:<10} {'PASS' if ok else 'FAIL'}{note}")
    total = len(specs)
    print(f"\n{set_name}: {correct}/{total} correct verdicts ({100 * correct / total:.0f}%), "
          f"{guard_fail} scenarios with blocked template drafts")
    passed = correct == total and guard_fail == 0
    print(f"RESULT: {'PASS' if passed else 'FAIL'}")
    return passed
