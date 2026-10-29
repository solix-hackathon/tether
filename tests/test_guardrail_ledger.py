import unittest

from tests.helpers import ROOT  # noqa: F401  (sets sys.path)

from recall.incidents import ApprovalError, IncidentStore
from recall.ledger.ledger import Ledger, LedgerError
from recall.mocks.synthetic import load_roster
from recall.nlp import guardrail
from recall.scenario import SCENARIO_DIR, load, run_scenario


def demo(name):
    return load(SCENARIO_DIR / "seeded" / f"{name}.json")


class GuardrailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = run_scenario(demo("s03_shared_file_opened")).result
        cls.f = cls.r["facts"]
        cls.report = next(d["text"] for d in cls.r["drafts"] if d["kind"] == "incident_report")
        cls.notice = next(d["text"] for d in cls.r["drafts"] if d["kind"] == "deletion_request")

    def assertRejected(self, kind, text):
        self.assertFalse(guardrail.check(kind, text, self.f)["ok"], text[:200])

    def test_template_drafts_pass(self):
        for d in self.r["drafts"]:
            self.assertTrue(d["guardrail"]["ok"], d["guardrail"]["violations"])

    def test_wrong_verdict(self):
        self.assertRejected("incident_report", self.report.replace("EXPOSED", "CONTAINED"))

    def test_missing_verdict(self):
        self.assertRejected("incident_report", self.report.replace("EXPOSED", "see below"))

    def test_wrong_time(self):
        self.assertRejected("incident_report", self.report.replace("2026-03-04T10:40:00Z", "2026-03-04T10:41:00Z"))
        self.assertRejected("incident_report", self.report + "\nFirst opened at 11:15.")

    def test_wrong_count(self):
        self.assertRejected("incident_report", self.report.replace("12 patient records", "11 patient records"))
        self.assertRejected("incident_report", self.report + "\nThe file was viewed: two views.")

    def test_wrong_email_and_id(self):
        self.assertRejected("incident_report", self.report.replace("m.osei@freemail.example", "m.osei@gmail.example"))
        self.assertRejected("incident_report", self.report + "\nAlso affects P-1099.")

    def test_patient_names_and_ids_blocked(self):
        p = load_roster()["P-1007"]
        self.assertRejected("incident_report", self.report + f"\nPatient: {p['first']} {p['last']}")
        self.assertRejected("deletion_request", self.notice + "\nThis concerns P-1007.")

    def test_notice_cannot_go_to_other_address(self):
        self.assertRejected("deletion_request", self.notice.replace("To: m.osei@freemail.example", "To: x@y.example"))


class LedgerTests(unittest.TestCase):
    def test_chain_and_tamper_detection(self):
        led = Ledger()
        led.append("action", 1, action_id="A-0001", status="executed")
        led.append("verdict", 2, action_id="A-0001", verdict="CONTAINED")
        self.assertTrue(led.verify())
        led._entries[1]["verdict"] = "REVERSED"
        with self.assertRaises(LedgerError):
            led.verify()

    def test_entries_are_copies(self):
        led = Ledger()
        led.append("action", 1, action_id="A-0001", status="executed")
        led.entries()[0]["status"] = "tampered"
        self.assertEqual(led.get_action("A-0001")["status"], "executed")


class ApprovalTests(unittest.TestCase):
    def test_drafts_pending_until_approved_and_notice_sent(self):
        store = IncidentStore(llm=False)
        r = store.run(demo("s03_shared_file_opened"))
        self.assertTrue(all(d["status"] == "pending_approval" for d in r["drafts"]))
        d = store.approve(r["incident_id"], "deletion_request", "Privacy Officer")
        self.assertEqual(d["status"], "sent")
        run = store.get(r["incident_id"])
        self.assertTrue(run.ledger.entries("notice_sent"))
        self.assertTrue(run.ledger.verify())

    def test_edited_draft_rechecked(self):
        store = IncidentStore(llm=False)
        r = store.run(demo("s01_wrong_clinic_unopened"))
        text = next(d["text"] for d in r["drafts"] if d["kind"] == "incident_report")
        with self.assertRaises(ApprovalError):
            store.approve(r["incident_id"], "incident_report", "PO", text.replace("CONTAINED", "REVERSED"))
        with self.assertRaises(ApprovalError):
            store.approve(r["incident_id"], "incident_report", "")
        # A rejected edit must not taint the original draft.
        self.assertEqual(store.approve(r["incident_id"], "incident_report", "PO")["status"], "approved")


if __name__ == "__main__":
    unittest.main()
