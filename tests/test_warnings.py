import tempfile, unittest
from pathlib import Path
from unittest.mock import patch

from src.domain import ConflictError
from src.repository import Repository
from src.service import Service


class WarningTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _make_construction(self, building, severity="high", quantity=5, threshold=10):
        item = self.service.create_item(
            {"title": "t", "description": "d", "severity": severity,
             "quantity": quantity, "threshold": threshold, "building": building},
            "creator", "assessor")
        item = self.service.transition(item["id"], "assessed", item["version"],
                                       "eng", "assessor")
        item = self.service.transition(item["id"], "design", item["version"],
                                       "eng", "structural_engineer")
        item = self.service.transition(item["id"], "construction", item["version"],
                                       "eng", "structural_engineer")
        return item

    def test_same_event_generates_one_result(self):
        self._make_construction("B1")
        first = self.service.push_warning(
            {"event_id": "E1", "building": "B1", "severity": "high"},
            "op", "assessor")
        second = self.service.push_warning(
            {"event_id": "E1", "building": "B1", "severity": "high"},
            "op", "assessor")
        self.assertTrue(second["duplicate"])
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(len(self.repo.list_warnings()), 1)

    def test_concurrent_push_keeps_one_batch(self):
        from concurrent.futures import ThreadPoolExecutor
        self._make_construction("B1")

        def push():
            return self.service.push_warning(
                {"event_id": "E1", "building": "B1", "severity": "high"},
                "op", "assessor")

        with ThreadPoolExecutor(max_workers=8) as ex:
            results = [f.result() for f in [ex.submit(push) for _ in range(8)]]
        self.assertEqual(len(self.repo.list_warnings()), 1)
        self.assertTrue(all(r["event_id"] == "E1" for r in results))

    def test_pause_only_in_construction_in_building(self):
        c1 = self._make_construction("B1")
        c2 = self._make_construction("B2")
        c3 = self.service.create_item(
            {"title": "t3", "description": "d", "severity": "high",
             "building": "B1"}, "creator", "assessor")
        self.service.push_warning(
            {"event_id": "E1", "building": "B1", "severity": "high"},
            "op", "assessor")
        self.assertTrue(self.service.get_item(c1["id"], "viewer")["paused"])
        self.assertFalse(self.service.get_item(c2["id"], "viewer")["paused"])
        self.assertFalse(self.service.get_item(c3["id"], "viewer")["paused"])
        batch = self.service.get_warning("E1", "viewer")
        self.assertEqual([p["item_id"] for p in batch["result"]["paused"]],
                         [c1["id"]])

    def test_release_requires_two_different_persons(self):
        item = self._make_construction("B1")
        self.service.push_warning(
            {"event_id": "E1", "building": "B1", "severity": "high"},
            "op", "assessor")
        self.service.confirm_release("E1", "alice", "assessor")
        self.assertTrue(self.service.get_item(item["id"], "viewer")["paused"])
        with self.assertRaises(ConflictError):
            self.service.confirm_release("E1", "alice", "assessor")
        batch = self.service.get_warning("E1", "viewer")
        self.assertEqual(batch["status"], "release_pending")
        self.service.confirm_release("E1", "bob", "assessor")
        batch = self.service.get_warning("E1", "viewer")
        self.assertEqual(batch["status"], "released")
        self.assertFalse(self.service.get_item(item["id"], "viewer")["paused"])
        with self.assertRaises(ConflictError):
            self.service.confirm_release("E1", "carol", "assessor")

    def test_risk_update_invalidates_pending_recovery(self):
        item = self._make_construction("B1", severity="high", quantity=5,
                                       threshold=10)
        self.service.push_warning(
            {"event_id": "E1", "building": "B1", "severity": "high"},
            "op", "assessor")
        self.service.confirm_release("E1", "alice", "assessor")
        self.assertTrue(self.service.get_item(item["id"], "viewer")["paused"])
        current = self.service.get_item(item["id"], "viewer")
        self.service.update_item(
            item["id"],
            {"severity": "severe", "quantity": 20, "threshold": 10,
             "expected_version": current["version"]},
            "eng", "assessor")
        batch = self.service.get_warning("E1", "viewer")
        self.assertEqual(batch["status"], "active")
        self.assertEqual(batch["confirmations"], [])
        snap = batch["result"]["paused"][0]
        self.assertEqual(snap["severity"], "severe")
        self.assertEqual(snap["quantity"], 20)
        self.service.confirm_release("E1", "bob", "assessor")
        self.service.confirm_release("E1", "carol", "assessor")
        self.assertEqual(self.service.get_warning("E1", "viewer")["status"],
                         "released")
        self.assertFalse(self.service.get_item(item["id"], "viewer")["paused"])

    def test_released_records_archived_on_risk_update(self):
        item = self._make_construction("B1")
        self.service.push_warning(
            {"event_id": "E1", "building": "B1", "severity": "high"},
            "op", "assessor")
        self.service.confirm_release("E1", "alice", "assessor")
        self.service.confirm_release("E1", "bob", "assessor")
        batch = self.service.get_warning("E1", "viewer")
        self.assertEqual(batch["status"], "released")
        self.assertEqual(len(batch["result"]["resumed"]), 1)
        current = self.service.get_item(item["id"], "viewer")
        self.service.update_item(
            item["id"],
            {"severity": "severe", "expected_version": current["version"]},
            "eng", "assessor")
        batch = self.service.get_warning("E1", "viewer")
        self.assertEqual(batch["status"], "released")
        self.assertEqual(len(batch["result"]["resumed"]), 1)

    def test_failure_keeps_batch_and_retry_succeeds(self):
        item = self._make_construction("B1")
        original = self.repo.pause_item
        state = {"n": 0}

        def flaky(item_id):
            state["n"] += 1
            if state["n"] == 1:
                raise RuntimeError("simulated failure")
            return original(item_id)

        with patch.object(self.repo, "pause_item", flaky):
            with self.assertRaises(ConflictError):
                self.service.push_warning(
                    {"event_id": "E1", "building": "B1", "severity": "high"},
                    "op", "assessor")
        batch = self.service.get_warning("E1", "viewer")
        self.assertEqual(batch["status"], "failed")
        result = self.service.retry_warning("E1", "op", "assessor")
        self.assertEqual(result["status"], "active")
        self.assertTrue(self.service.get_item(item["id"], "viewer")["paused"])

    def test_audit_chain_intact(self):
        self._make_construction("B1")
        self.service.push_warning(
            {"event_id": "E1", "building": "B1", "severity": "high"},
            "op", "assessor")
        self.service.confirm_release("E1", "alice", "assessor")
        self.service.confirm_release("E1", "bob", "assessor")
        self.assertTrue(self.repo.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
