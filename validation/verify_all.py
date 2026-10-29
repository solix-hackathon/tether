"""One command: unit tests, seeded scenarios, held-out scenarios, fuzzing. Prints RESULT: PASS / FAIL."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STEPS = [
    ("unit tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests"]),
    ("seeded scenarios", [sys.executable, "validation/harness.py"]),
    ("held-out scenarios", [sys.executable, "validation/holdout.py"]),
    ("fuzzing", [sys.executable, "validation/fuzz.py"]),
]


def main():
    results = []
    for name, cmd in STEPS:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        out = (p.stdout + p.stderr).strip()
        print(f"── {name} {'─' * (60 - len(name))}")
        print("\n".join(out.splitlines()[-8:]))
        results.append((name, p.returncode == 0))
    print("─" * 64)
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    passed = all(ok for _, ok in results)
    print(f"RESULT: {'PASS' if passed else 'FAIL'}")
    return passed


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
