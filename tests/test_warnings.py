import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from src.domain import ConflictError, PermissionDenied
from src.repository import Repository
from src.rules import STATES
from src.service import Service


class WarningFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "warn.db"))
        self.service = Service(self.repo)
        # 三个项目：同楼栋两个在施，同楼栋一个在设计阶段，另一楼栋一个在施
        self.a = self.service.create_item(
            {"title": "A栋施工1", "description": "same building under construction",
             "severity": "high", "quantity": 12, "threshold": 2,
             "building": "BLD-A", "external_ref": "A-1"}, "creator", "assessor")
        self.b = self.service.create_item(
            {"title": "A栋施工2", "description": "another under construction",
             "severity": "low", "quantity": 0, "threshold": 1,
             "building": "BLD-A", "external_ref": "A-2"}, "creator", "assessor")
        self.design = self.service.create_item(
            {"title": "A栋设计", "description": "design stage",
             "severity": "high", "quantity": 5, "threshold": 1,
             "building": "BLD-A", "external_ref": "A-3"}, "creator", "assessor")
        self.other = self.service.create_item(
            {"title": "B栋施工", "description": "other building",
             "severity": "high", "quantity": 5, "threshold": 1,
             "building": "BLD-B", "external_ref": "B-1"}, "creator", "assessor")
        for item in (self.a, self.b, self.other):
            current = self.service.get_item(item["id"], "viewer")
            for target in ("assessed", "design", "construction"):
                role = {STATES[1]: "assessor", "design": "structural_engineer",
                        "construction": "structural_engineer"}[target]
                current = self.service.transition(current["id"], target,
                                                  current["version"], "mover", role)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _alert_event(self, event_id="EV-1", level="medium", building="BLD-A"):
        return {"event_id": event_id, "kind": "alert", "level": level,
                "building": building, "message": "aftershock warning"}

    def test_same_event_generates_single_result_and_pauses_same_building(self):
        batch = self.service.push_warnings(
            {"events": [self._alert_event()]}, "monitor", "assessor")
        self.assertEqual(batch["status"], "completed")
        alert_id = batch["items"][0]["id"]  # batch_item id; 取真正预警
        del alert_id
        alerts = self.service.list_alerts("viewer")
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        paused_item_ids = {d["item_id"] for d in alert["dispositions"]
                           if d["status"] == "paused"}
        # 同楼栋在施项目全部先暂停；不同楼栋、非在施项目不暂停
        self.assertEqual(paused_item_ids, {self.a["id"], self.b["id"]})
        self.assertNotIn(self.design["id"], paused_item_ids)
        self.assertNotIn(self.other["id"], paused_item_ids)
        # 重复推送同一事件：幂等，不生成第二份结果
        again = self.service.push_warnings(
            {"events": [self._alert_event()]}, "monitor", "assessor")
        self.assertEqual(len(self.service.list_alerts("viewer")), 1)
        self.assertEqual(again["items"][0]["status"], "ok")
        self.assertEqual(len(self.repo.list_dispositions(alert["id"])), 2)

    def test_release_needs_two_distinct_people_in_order(self):
        self.service.push_warnings(
            {"events": [self._alert_event()]}, "monitor", "assessor")
        alert = self.service.list_alerts("viewer")[0]
        # 未登记解除消息前不能确认
        with self.assertRaises(ConflictError):
            self.service.confirm_release(alert["id"], {}, "eng1", "structural_engineer")
        release = self.service.push_warnings({"events": [
            {"event_id": "REL-1", "kind": "release", "ref_event_id": "EV-1",
             "message": "clear"}]}, "monitor", "assessor")
        self.assertEqual(release["status"], "completed")
        alert = self.service.get_alert(alert["id"], "viewer")
        self.assertEqual(alert["status"], "release_pending")
        # 第一次确认后仍未恢复
        first = self.service.confirm_release(alert["id"], {}, "eng1",
                                             "structural_engineer")
        self.assertFalse(first["resumed"])
        self.assertTrue(
            all(d["status"] == "paused" for d in first["dispositions"]
                if d["item_id"] in (self.a["id"], self.b["id"])))
        # 同一人不能重复确认
        with self.assertRaises(ConflictError):
            self.service.confirm_release(alert["id"], {}, "eng1",
                                         "structural_engineer")
        # 无权限角色不能确认
        with self.assertRaises(PermissionDenied):
            self.service.confirm_release(alert["id"], {}, "viewer1", "viewer")
        # 第二名不同人员确认后恢复
        second = self.service.confirm_release(alert["id"], {}, "boss", "review_board")
        self.assertTrue(second["resumed"])
        self.assertEqual(second["status"], "resumed")
        statuses = {d["item_id"]: d["status"] for d in second["dispositions"]}
        self.assertEqual(statuses[self.a["id"]], "resumed")
        self.assertEqual(statuses[self.b["id"]], "resumed")

    def test_risk_update_invalidates_pending_recovery_and_recalculates(self):
        self.service.push_warnings(
            {"events": [self._alert_event(level="medium")]}, "monitor", "assessor")
        alert = self.service.list_alerts("viewer")[0]
        # 项目B低风险：初始仍被保守暂停
        # 风险参数更新为低分值 -> 未完成恢复失效，按新预警重算后不再暂停
        b = self.service.get_item(self.b["id"], "viewer")
        outcome = self.service.update_item_risk(
            b["id"], {"severity": "low", "quantity": 0, "threshold": 1,
                      "expected_version": b["version"]},
            "riskadmin", "structural_engineer")
        self.assertEqual(len(outcome["changes"]), 1)
        self.assertFalse(outcome["changes"][0]["paused"])
        alert = self.service.get_alert(alert["id"], "viewer")
        self.assertEqual(alert["status"], "active")
        generations = {d["item_id"]: d for d in alert["dispositions"]
                       if d["item_id"] == self.b["id"]}
        # 仅有第一代记录且已失效
        self.assertEqual(len(generations), 1)
        self.assertEqual(generations[self.b["id"]]["status"], "invalidated")
        # 风险又升高 -> 重新暂停为新一代，必须重新双人确认
        b = self.service.get_item(self.b["id"], "viewer")
        outcome = self.service.update_item_risk(
            b["id"], {"severity": "high", "quantity": 12, "threshold": 2,
                      "expected_version": b["version"]},
            "riskadmin", "structural_engineer")
        self.assertTrue(outcome["changes"][0]["paused"])
        self.assertEqual(outcome["changes"][0]["generation"], 2)
        alert = self.service.get_alert(alert["id"], "viewer")
        self.assertEqual(alert["status"], "active")
        self.assertEqual(alert["confirmations"], [])

    def test_resumed_records_are_archived_after_risk_update(self):
        self.service.push_warnings(
            {"events": [self._alert_event(level="medium")]}, "monitor", "assessor")
        alert = self.service.list_alerts("viewer")[0]
        self.service.push_warnings({"events": [
            {"event_id": "REL-1", "kind": "release", "ref_event_id": "EV-1",
             "message": "clear"}]}, "monitor", "assessor")
        self.service.confirm_release(alert["id"], {}, "eng1", "structural_engineer")
        self.service.confirm_release(alert["id"], {}, "boss", "review_board")
        # 已复工后再更新风险参数：复工记录留档，不重新暂停
        a = self.service.get_item(self.a["id"], "viewer")
        outcome = self.service.update_item_risk(
            a["id"], {"severity": "high", "quantity": 30, "threshold": 1,
                      "expected_version": a["version"]},
            "riskadmin", "structural_engineer")
        self.assertEqual(outcome["changes"], [])
        alert = self.service.get_alert(alert["id"], "viewer")
        disposition = next(d for d in alert["dispositions"]
                           if d["item_id"] == self.a["id"])
        self.assertEqual(disposition["status"], "resumed")
        self.assertEqual(disposition["resumed_by"], "boss")
        self.assertIsNotNone(disposition["resumed_at"])

    def test_concurrent_duplicate_push_leaves_single_disposition(self):
        event = self._alert_event(event_id="EV-CONC")
        errors = []

        def push():
            try:
                self.service.push_warnings(
                    {"batch_ref": "BAT-CONC", "events": [event]},
                    "monitor", "assessor")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _: push(), range(8)))
        self.assertEqual(errors, [])
        alerts = [a for a in self.service.list_alerts("viewer")
                  if a["event_id"] == "EV-CONC"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            len([d for d in alerts[0]["dispositions"] if d["status"] == "paused"]),
            2)

    def test_failed_batch_is_retained_and_retried(self):
        # 解除消息引用了不存在的预警：条目失败但批次保留
        batch = self.service.push_warnings({"batch_ref": "BAT-FAIL", "events": [
            {"event_id": "REL-GHOST", "kind": "release",
             "ref_event_id": "NO-SUCH", "message": "clear"}]},
            "monitor", "assessor")
        self.assertEqual(batch["status"], "failed")
        self.assertEqual(batch["items"][0]["status"], "failed")
        self.assertTrue(batch["items"][0]["error"])
        # 先补推原预警，再重试原批次：失败条目转成功
        self.service.push_warnings(
            {"events": [self._alert_event(event_id="NO-SUCH")]},
            "monitor", "assessor")
        retried = self.service.retry_batch(batch["id"], "monitor", "assessor")
        self.assertEqual(retried["status"], "completed")
        self.assertEqual(retried["items"][0]["status"], "ok")

    def test_permission_and_version_guards(self):
        with self.assertRaises(PermissionDenied):
            self.service.push_warnings(
                {"events": [self._alert_event()]}, "x", "viewer")
        self.service.push_warnings(
            {"events": [self._alert_event()]}, "monitor", "assessor")
        a = self.service.get_item(self.a["id"], "viewer")
        with self.assertRaises(PermissionDenied):
            self.service.update_item_risk(
                a["id"], {"severity": "low", "expected_version": a["version"]},
                "x", "viewer")
        with self.assertRaises(ConflictError):
            self.service.update_item_risk(
                a["id"], {"severity": "low", "expected_version": a["version"] + 9},
                "x", "assessor")

    def test_partial_batch_only_marks_failures(self):
        batch = self.service.push_warnings({"batch_ref": "BAT-MIX", "events": [
            self._alert_event(event_id="EV-OK"),
            {"event_id": "REL-X", "kind": "release", "ref_event_id": "GONE",
             "message": "clear"},
        ]}, "monitor", "assessor")
        self.assertEqual(batch["status"], "partial")
        self.assertEqual([i["status"] for i in batch["items"]], ["ok", "failed"])
        self.assertTrue(self.repo.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
