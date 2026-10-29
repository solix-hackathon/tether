import unittest

from tests.helpers import ORG, SECRET, advance, make

from recall.gateway.gateway import classify, record_bypass


class ClassifierTests(unittest.TestCase):
    def setUp(self):
        self.world, self.ledger, self.gw = make()

    def c(self, tool, args, via=True):
        return classify(self.world, tool, args, via_gateway=via)

    def test_external_phi_email_is_revocable(self):
        c = self.c("send_email", {"to": ["a@clinic.example"], "records": ["P-1004"]})
        self.assertEqual(c["action_class"], "revocable")
        self.assertEqual(c["playbooks"], ["revoke_links"])
        self.assertEqual(c["data"]["classification"], "PHI")

    def test_patient_id_in_body_is_detected(self):
        c = self.c("send_email", {"to": ["a@clinic.example"], "body": "Results for P-1010 attached"})
        self.assertEqual(c["data"]["records"], ["P-1010"])

    def test_internal_email_is_purgeable(self):
        c = self.c("send_email", {"to": [f"x@{ORG}"], "records": ["P-1004"]})
        self.assertEqual(c["action_class"], "purgeable")

    def test_key_in_email_triggers_rotation(self):
        c = self.c("send_email", {"to": ["a@vendor.example"], "body": f"key {SECRET}"})
        self.assertEqual(c["playbooks"], ["rotate_key"])
        self.assertEqual(c["data"]["key_ids"], ["key-test"])

    def test_unknown_secret_is_flagged(self):
        c = self.c("send_email", {"to": ["a@vendor.example"], "body": "rcl_live_ZZZZZZZZZZZZZZZZZZZZZZZZ"})
        self.assertEqual(c["data"]["unknown_secrets"], 1)

    def test_bypass_raw_records_are_irreversible(self):
        c = self.c("send_email", {"to": ["a@clinic.example"], "records": ["P-1004"]}, via=False)
        self.assertEqual(c["action_class"], "irreversible")
        self.assertTrue(c["payload_left_org"])

    def test_share_order_fax(self):
        self.assertEqual(self.c("share_file", {"file_id": "F-1"})["action_class"], "revocable")
        self.assertEqual(self.c("issue_refund", {"counterparty": "x", "amount": 1})["action_class"], "compensable")
        self.assertEqual(self.c("send_fax", {"destination": "fax:1", "records": ["P-1"]})["action_class"], "irreversible")

    def test_unknown_tool_rejected(self):
        with self.assertRaises(ValueError):
            self.c("delete_database", {})


class RewriterTests(unittest.TestCase):
    def test_payload_becomes_per_recipient_link(self):
        world, ledger, gw = make()
        out = gw.submit("agent:x", "send_email", {"to": ["a@c1.example", "b@c2.example"], "subject": "s",
                                                  "body": "Diagnosis for P-1004: pneumonia", "records": ["P-1004"]})
        links = out["resources"]["links"]
        self.assertEqual(set(links), {"a@c1.example", "b@c2.example"})
        self.assertNotEqual(links["a@c1.example"], links["b@c2.example"])
        for r, mid in out["resources"]["messages"].items():
            body = world.mail.messages[mid]["body"]
            self.assertNotIn("P-1004", body)
            self.assertNotIn("pneumonia", body)
            self.assertIn(world.links.links[links[r]]["url"], body)


class HoldWindowTests(unittest.TestCase):
    def setUp(self):
        self.world, self.ledger, self.gw = make()
        self.out = self.gw.submit("agent:x", "send_fax", {"destination": "fax:1", "records": ["P-1001"]})

    def test_irreversible_sensitive_action_is_held(self):
        self.assertEqual(self.out["status"], "held")
        self.assertEqual(self.world.outbound.raw_log(), [])

    def test_approval_executes(self):
        self.gw.approve(self.out["action_id"], f"nurse@{ORG}")
        self.assertEqual(self.ledger.get_action(self.out["action_id"])["status"], "executed")
        self.assertEqual(len(self.world.outbound.raw_log()), 1)

    def test_expired_hold_is_rejected_not_executed(self):
        advance(self.world, 3600)
        self.gw.approve(self.out["action_id"], f"nurse@{ORG}")
        self.assertEqual(self.ledger.get_action(self.out["action_id"])["status"], "rejected")
        self.assertEqual(self.world.outbound.raw_log(), [])

    def test_non_sensitive_irreversible_is_not_held(self):
        out = self.gw.submit("agent:x", "send_fax", {"destination": "fax:2"})
        self.assertEqual(out["status"], "executed")


class BypassTests(unittest.TestCase):
    def test_bypass_is_recorded_with_source(self):
        world, ledger, gw = make()
        out = record_bypass(world, ledger, "agent:x", "send_email", {"to": ["a@c.example"], "records": ["P-1001"]})
        a = ledger.get_action(out["action_id"])
        self.assertFalse(a["via_gateway"])
        self.assertEqual(a["source"], "detector")


if __name__ == "__main__":
    unittest.main()
