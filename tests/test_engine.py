import unittest

from tests.helpers import ORG, SECRET, advance, make

from recall.engine.recovery import RecoveryEngine
from recall.engine.rules import CONTAINED, ESCALATED, EXPOSED, REVERSED, decide
from recall.gateway.gateway import record_bypass


def recover(world, ledger, gw, aid):
    return RecoveryEngine(world, ledger, gw, llm=False).handle("INC-0001", aid)


class PlaybookTests(unittest.TestCase):
    def test_revoke_links_confirmed_and_later_views_denied(self):
        world, ledger, gw = make()
        out = gw.submit("agent:x", "send_email", {"to": ["a@c.example"], "records": ["P-1001"]})
        advance(world, 600)
        r = recover(world, ledger, gw, out["action_id"])
        self.assertEqual(r["verdict"], CONTAINED)
        lid = out["resources"]["links"]["a@c.example"]
        advance(world, 60)
        self.assertFalse(world.links.open(lid, "a@c.example"))

    def test_rotate_key_makes_leaked_copy_worthless(self):
        world, ledger, gw = make()
        out = gw.submit("agent:x", "send_email", {"to": ["a@v.example"], "body": SECRET})
        advance(world, 60)
        r = recover(world, ledger, gw, out["action_id"])
        self.assertEqual(r["verdict"], REVERSED)
        self.assertFalse(world.vault.use(SECRET, "ip:203.0.113.1"))
        self.assertEqual(world.vault.status("key-test")["successor"], "key-test-r1")

    def test_revoke_share(self):
        world, ledger, gw = make()
        out = gw.submit("agent:x", "share_file", {"file_id": "F-1"})
        advance(world, 60)
        world.files.access(out["resources"]["share_id"], "outsider@mail.example")
        advance(world, 60)
        r = recover(world, ledger, gw, out["action_id"])
        self.assertEqual(r["verdict"], EXPOSED)
        self.assertFalse(world.files.share_status(out["resources"]["share_id"])["active"])
        self.assertEqual(r["facts"]["deletion_recipients"], ["outsider@mail.example"])

    def test_purge_mail(self):
        world, ledger, gw = make()
        out = gw.submit("agent:x", "send_email", {"to": [f"d@{ORG}"], "records": ["P-1001"]})
        advance(world, 60)
        r = recover(world, ledger, gw, out["action_id"])
        self.assertEqual(r["verdict"], REVERSED)
        self.assertFalse(world.mail.read(out["resources"]["message_id"], f"d@{ORG}"))

    def test_cancel_order_and_refusal(self):
        world, ledger, gw = make()
        a = gw.submit("agent:x", "create_order", {"counterparty": "v", "amount": 5})
        b = gw.submit("agent:x", "create_order", {"counterparty": "v", "amount": 6})
        world.orders.fulfill(b["resources"]["order_id"])
        self.assertEqual(recover(world, ledger, gw, a["action_id"])["verdict"], REVERSED)
        r = RecoveryEngine(world, ledger, gw, llm=False).handle("INC-0002", b["action_id"])
        self.assertEqual(r["verdict"], ESCALATED)
        self.assertIn("already shipped", r["reversals"][0]["error"])

    def test_held_action_cancelled(self):
        world, ledger, gw = make()
        out = gw.submit("agent:x", "send_fax", {"destination": "fax:1", "records": ["P-1001"]})
        r = recover(world, ledger, gw, out["action_id"])
        self.assertEqual(r["verdict"], REVERSED)
        self.assertEqual(world.outbound.raw_log(), [])


class EvidenceRuleTests(unittest.TestCase):
    def link_case(self, faults=None, view=None):
        world, ledger, gw = make(faults)
        out = gw.submit("agent:x", "send_email", {"to": ["a@c.example"], "records": ["P-1001"]})
        advance(world, 300)
        if view:
            world.links.open(out["resources"]["links"]["a@c.example"], view)
        advance(world, 300)
        return recover(world, ledger, gw, out["action_id"])

    def test_external_view_is_exposed(self):
        self.assertEqual(self.link_case(view="a@c.example")["verdict"], EXPOSED)

    def test_internal_view_is_not_exposure(self):
        self.assertEqual(self.link_case(view=f"sender@{ORG}")["verdict"], CONTAINED)

    def test_missing_log_escalates(self):
        self.assertEqual(self.link_case({"log_unavailable": ["links"]})["verdict"], ESCALATED)

    def test_missing_coverage_escalates(self):
        self.assertEqual(self.link_case({"missing_coverage": ["links"]})["verdict"], ESCALATED)

    def test_truncated_log_escalates_even_if_view_dropped(self):
        r = self.link_case({"log_truncated_before": {"links": "+00:08:00"}}, view="a@c.example")
        self.assertEqual(r["verdict"], ESCALATED)

    def test_clock_skew_escalates(self):
        r = self.link_case({"clock_skew": {"links": -3600}}, view="a@c.example")
        self.assertEqual(r["verdict"], ESCALATED)

    def test_failed_revocation_escalates(self):
        self.assertEqual(self.link_case({"fail_ops": ["links.revoke"]})["verdict"], ESCALATED)

    def test_unknown_action_escalates(self):
        world, ledger, gw = make()
        self.assertEqual(recover(world, ledger, gw, "A-9999")["verdict"], ESCALATED)

    def test_bypass_without_visibility_escalates(self):
        world, ledger, gw = make()
        out = record_bypass(world, ledger, "agent:x", "send_email", {"to": ["a@c.example"], "records": ["P-1001"]})
        self.assertEqual(recover(world, ledger, gw, out["action_id"])["verdict"], ESCALATED)

    def test_contained_requires_positive_evidence(self):
        action = {"action_class": "revocable", "playbooks": ["revoke_links"], "data": {"unknown_secrets": 0},
                  "payload_left_org": False}
        rev = [{"playbook": "revoke_links", "resource": "lk", "confirmed": True, "at": 1, "error": None}]
        ev = [{"kind": "link", "resource": "lk", "status": "unavailable", "notes": ["down"], "access": []}]
        self.assertEqual(decide(action, rev, ev)[0], ESCALATED)
        ev[0]["status"] = "ok"
        self.assertEqual(decide(action, rev, ev)[0], CONTAINED)

    def test_reasons_never_contain_verdict_words(self):
        for faults in (None, {"log_unavailable": ["links"]}, {"fail_ops": ["links.revoke"]}):
            r = self.link_case(faults)
            for reason in r["reasons"]:
                for v in (REVERSED, CONTAINED, EXPOSED, ESCALATED):
                    self.assertNotIn(v, reason)


if __name__ == "__main__":
    unittest.main()
