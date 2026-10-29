import http.client
import threading
import unittest
from http.server import ThreadingHTTPServer

from tests.helpers import ROOT  # noqa: F401  (sets sys.path)

from recall import app, qr, replay
from recall.incidents import IncidentStore
from recall.live import LiveSession


class LiveSessionTests(unittest.TestCase):
    def setUp(self):
        self.store = IncidentStore(llm=False)
        self.live = LiveSession(self.store)
        self.state = self.live.send()
        self.link = self.live.link_id

    def test_send_rewrites_the_payload(self):
        self.assertIn("P-1004", self.state["original"])
        self.assertNotIn("P-1004", self.state["left"])
        self.assertIn(self.link, self.state["left"])

    def test_unopened_link_is_contained(self):
        s = self.live.recall()
        self.assertEqual(s["verdict"], "CONTAINED")
        self.assertEqual(self.live.open_link(self.link, "a" * 16, "iPhone")[0], "revoked")

    def test_opened_link_is_exposed_and_later_attempts_blocked(self):
        state, doc = self.live.open_link(self.link, "a" * 16, "Mozilla (iPhone)")
        self.assertEqual(state, "ok")
        self.assertEqual(doc["actor"], "guest-1 (iPhone)")
        self.live.open_link(self.link, "b" * 16, "Android")
        s = self.live.recall()
        self.assertEqual(s["verdict"], "EXPOSED")
        self.assertEqual(self.live.open_link(self.link, "a" * 16, "iPhone")[0], "revoked")
        s = self.live.state()
        self.assertEqual((s["opened"], s["blocked"]), (2, 1))
        self.assertEqual(s["counters"][1]["value"], 2)

    def test_outage_escalates_even_after_opens(self):
        self.live.open_link(self.link, "a" * 16, "iPhone")
        self.live.set_outage(True)
        s = self.live.recall()
        self.assertEqual(s["verdict"], "ESCALATED")
        self.assertFalse(self.live.link_status(self.link)["active"])
        with self.assertRaises(RuntimeError):
            self.live.set_outage(False)

    def test_live_incident_has_replay_and_passing_drafts(self):
        self.live.open_link(self.link, "a" * 16, "iPhone")
        s = self.live.recall()
        run = self.store.get(s["incident_id"])
        self.assertTrue(all(d["guardrail"]["ok"] for d in run.result["drafts"]))
        r = replay.build(run)
        self.assertEqual(r["steps"][-1]["with"]["headline"], "EXPOSED")
        self.assertEqual(r["steps"][-1]["without"]["headline"], "UNKNOWN")

    def test_big_audience_replays_in_few_steps(self):
        for i in range(40):
            self.live.open_link(self.link, f"{i:016x}", ["iPhone", "Android"][i % 2])
        s = self.live.recall()
        for i in range(5):
            self.live.open_link(self.link, f"{i:016x}", "iPhone")
        r = replay.build(self.store.get(s["incident_id"]))
        self.assertLessEqual(len(r["steps"]), 12)
        with_beats = [st["with"] for st in r["steps"] if st["with"]]
        types = [b["type"] for b in with_beats]
        self.assertLess(types.index("incident"), max(i for i, b in enumerate(with_beats) if b.get("result") == "denied"))
        self.assertEqual(r["compare"][0]["with"], 40)
        self.assertEqual(r["compare"][1]["with"], 5)
        self.assertIn("and 35 others", s["reasons"][0])

    def test_unknown_link(self):
        self.assertEqual(self.live.open_link("lk_0000000000", "a" * 16, "x")[0], "unknown")


class LiveKeyTests(unittest.TestCase):
    def setUp(self):
        self.store = IncidentStore(llm=False)
        self.live = LiveSession(self.store)
        self.state = self.live.send(mode="key")
        self.mid = self.live.message_id

    def test_key_leaks_raw_in_the_email(self):
        state, m = self.live.open_message(self.mid, "a" * 16, "iPhone")
        self.assertEqual(state, "ok")
        self.assertIn(m["secret"], m["body"])

    def test_rotated_before_use_is_reversed_and_key_dies(self):
        self.live.open_message(self.mid, "a" * 16, "iPhone")
        s = self.live.recall()
        self.assertEqual(s["verdict"], "REVERSED")
        r = self.live.try_key(self.mid, "a" * 16, "iPhone")
        self.assertFalse(r["ok"])
        self.assertEqual(self.live.state()["blocked"], 1)

    def test_used_before_rotation_is_exposed(self):
        self.assertTrue(self.live.try_key(self.mid, "a" * 16, "iPhone")["ok"])
        self.assertEqual(self.live.recall()["verdict"], "EXPOSED")

    def test_outage_escalates(self):
        self.live.set_outage(True)
        self.assertEqual(self.live.recall()["verdict"], "ESCALATED")
        self.assertFalse(self.live.key_status(self.mid)["active"])

    def test_key_incident_replays(self):
        self.live.recall()
        self.live.try_key(self.mid, "b" * 16, "Android")
        run = next(iter(self.store.runs.values()))
        r = replay.build(run)
        self.assertEqual(r["steps"][-1]["with"]["headline"], "REVERSED")
        self.assertEqual(r["steps"][-1]["without"]["headline"], "KEY STILL LIVE")
        self.assertTrue(all(d["guardrail"]["ok"] for d in run.result["drafts"]))

    def test_outage_never_carries_into_the_next_round(self):
        self.live.send(mode="link", outage=True)
        self.assertTrue(self.live.state()["outage"])
        self.live.send(mode="key")
        self.assertFalse(self.live.state()["outage"])
        self.assertEqual(self.live.recall()["verdict"], "REVERSED")

    def test_wrong_mode_pages_are_unknown(self):
        self.assertEqual(self.live.open_link("lk_0000000000", "a" * 16, "x")[0], "unknown")
        self.assertIsNone(self.live.try_key("msg_0000000000", "a" * 16, "x"))


class SlowModelTests(unittest.TestCase):
    """With model drafting on, Recall must not wait for the model, and phones must not either."""

    def test_recall_returns_before_slow_drafts(self):
        import time
        from unittest import mock

        from recall.nlp import drafter

        def slow_model(kind, facts, template):
            time.sleep(1.0)
            return None  # behave like a model that declined: template is used

        store = IncidentStore(llm=True)
        live = LiveSession(store)
        live.send()
        with mock.patch.object(drafter, "llm_draft", slow_model):
            t0 = time.time()
            s = live.recall()
            recall_secs = time.time() - t0
            t1 = time.time()
            self.assertFalse(live.link_status(live.link_id)["active"])
            status_secs = time.time() - t1
            run = store.get(s["incident_id"])
            self.assertTrue(run.result["drafts_pending"])
            for _ in range(80):
                if not run.result["drafts_pending"]:
                    break
                time.sleep(0.1)
        self.assertLess(recall_secs, 0.5)
        self.assertLess(status_secs, 0.5)
        self.assertFalse(run.result["drafts_pending"])
        self.assertTrue(run.result["drafts"])
        self.assertTrue(all(d["guardrail"]["ok"] for d in run.result["drafts"]))
        self.assertTrue(run.ledger.verify())


class QRTests(unittest.TestCase):
    def test_qr_decodes(self):
        try:
            import cv2
            import numpy as np
        except ImportError:
            self.skipTest("OpenCV not installed")
        for text in ("http://192.168.1.20:8000/l/lk_0123456789", "https://example-tunnel.app/l/lk_abcdefabcd", "x" * 150):
            m = qr.encode(text)
            n = len(m)
            img = np.full((n + 8, n + 8), 255, np.uint8)
            for y, row in enumerate(m):
                for x, v in enumerate(row):
                    if v:
                        img[y + 4, x + 4] = 0
            img = cv2.resize(img, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
            self.assertEqual(cv2.QRCodeDetector().detectAndDecode(img)[0], text)


class AccessGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        app.LIVE.reset()
        app.LIVE.send()
        cls.link = app.LIVE.link_id

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        app.LIVE.reset()

    def get(self, path, headers=None, method="GET"):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request(method, path, body=b"{}" if method == "POST" else None, headers=headers or {})
        r = c.getresponse()
        return r.status, r.read()

    def test_local_dashboard_works(self):
        self.assertEqual(self.get("/api/incidents")[0], 200)

    def test_tunnel_or_lan_host_gets_links_only(self):
        for h in ({"Host": "abc.ngrok-free.app"}, {"X-Forwarded-For": "203.0.113.5"}):
            self.assertEqual(self.get("/api/incidents", h)[0], 403)
            self.assertEqual(self.get("/", h)[0], 403)
            self.assertEqual(self.get("/api/live/recall", h, "POST")[0], 403)
            self.assertEqual(self.get(f"/l/{self.link}/status", h)[0], 200)
        status, body = self.get(f"/l/{self.link}", {"Host": "abc.ngrok-free.app", "User-Agent": "iPhone"})
        self.assertEqual(status, 200)
        self.assertIn(b"Discharge summary", body)
        self.assertEqual(self.get("/api/live/outage", {"Host": "abc.ngrok-free.app"}, "POST")[0], 403)

    def test_remote_can_try_a_leaked_key_but_nothing_else(self):
        app.LIVE.send(mode="key")
        mid = app.LIVE.message_id
        h = {"Host": "abc.ngrok-free.app", "User-Agent": "Android"}
        self.assertEqual(self.get(f"/m/{mid}", h)[0], 200)
        self.assertEqual(self.get(f"/m/{mid}/try", h, "POST")[0], 200)
        self.assertEqual(self.get("/api/live/send", h, "POST")[0], 403)
        app.LIVE.send()
        type(self).link = app.LIVE.link_id


if __name__ == "__main__":
    unittest.main()
