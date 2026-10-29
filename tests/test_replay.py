import unittest

from tests.helpers import ROOT  # noqa: F401  (sets sys.path)

from recall import replay
from recall.scenario import load_dir, run_scenario


def build(prefix):
    spec = next(s for s in load_dir("seeded") if s["id"].startswith(prefix))
    return replay.build(run_scenario(spec))


def beats(r, panel):
    return [s[panel] for s in r["steps"] if s[panel]]


class ReplayTests(unittest.TestCase):
    def test_every_scenario_builds_and_ends_with_both_outcomes(self):
        for d in ("seeded", "holdout"):
            for spec in load_dir(d):
                r = replay.build(run_scenario(spec))
                final = r["steps"][-1]
                self.assertTrue(final.get("final"), spec["id"])
                self.assertEqual(final["with"]["headline"], spec["expected"], spec["id"])
                self.assertTrue(final["without"]["headline"])
                ts = [s["ts"] for s in r["steps"]]
                self.assertEqual(ts, sorted(ts), spec["id"])

    def test_share_without_recall_keeps_leaking(self):
        r = build("s03")
        late_with = [b for b in beats(r, "with") if b["type"] == "access" and b["ts"] > r["steps"][3]["ts"]]
        late_without = [b for b in beats(r, "without") if b["type"] == "access" and b["ts"] > r["steps"][3]["ts"]]
        self.assertEqual([b["result"] for b in late_with], ["denied"])
        self.assertEqual([b["result"] for b in late_without], ["allowed"])
        self.assertEqual(r["steps"][-1]["without"]["headline"], "STILL PUBLIC")

    def test_raw_email_without_recall_is_untracked(self):
        r = build("s01")
        self.assertIn("untracked", [b.get("result") for b in beats(r, "without")])
        self.assertEqual(r["steps"][-1]["without"]["headline"], "UNKNOWN")
        self.assertIn("rewrite", [b.get("mode") for b in beats(r, "with")])

    def test_held_fax_never_leaves_with_recall(self):
        r = build("s13")
        self.assertNotIn("deliver", [b["type"] for b in beats(r, "with")])
        self.assertIn("deliver", [b["type"] for b in beats(r, "without")])


if __name__ == "__main__":
    unittest.main()
