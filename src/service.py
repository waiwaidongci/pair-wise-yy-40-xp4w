from __future__ import annotations

from typing import Any, Dict, List, Optional

from .domain import (ConflictError, PermissionDenied, ensure_role, normalize_severity,
                     require_number, require_text)
from .audit import utc_now
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES, TITLE,
                    VIEW_ROLES, WARNING_ENTITY, RELEASE_CONFIRMATIONS_REQUIRED,
                    can_confirm_release, can_push_warning, can_retry_warning,
                    completion_blockers, escalation_required, next_confirmation_seq,
                    pause_eligible, priority_score, recovery_invalidates,
                    recalculates_on_update, response_deadline_hours,
                    role_for_transition, validate_transition,
                    warning_allows_confirmation)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        building = payload.get("building")
        if building is not None:
            building = require_text(building, "building", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor, building)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            from .domain import ConflictError
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    # ---- 预警处置用例 ----

    def push_warning(self, payload: Dict[str, Any], actor: str,
                     role: str) -> Dict[str, Any]:
        if not can_push_warning(role):
            raise PermissionDenied("当前角色无权发布预警")
        actor = require_text(actor, "actor", 100)
        event_id = require_text(payload.get("event_id"), "event_id", 100)
        building = require_text(payload.get("building"), "building", 100)
        severity = normalize_severity(payload.get("severity"))
        # 同一事件只生成一次结果：重复推送直接返回已有处置
        existing = self.repository.get_warning_batch_by_event(event_id)
        if existing is not None:
            return self._enrich_warning(existing, duplicate=True)
        try:
            batch = self.repository.create_warning_batch(
                event_id, building, severity, actor)
        except ConflictError:
            existing = self.repository.get_warning_batch_by_event(event_id)
            return self._enrich_warning(existing, duplicate=True)
        try:
            result = self._build_pause_result(building)
            batch = self.repository.update_warning_result(batch["id"], result)
        except Exception as exc:
            # 失败后保留批次再重试
            self.repository.update_warning_status(batch["id"], "failed")
            self.repository.append_audit("warning_failed", WARNING_ENTITY,
                                         batch["id"], actor,
                                         {"event_id": event_id, "error": str(exc)})
            raise ConflictError(f"预警处置失败，批次已保留可重试: {exc}") from exc
        self.repository.append_audit("warning_pushed", WARNING_ENTITY,
                                     batch["id"], actor,
                                     {"event_id": event_id, "building": building,
                                      "severity": severity,
                                      "paused": [p["item_id"] for p in result["paused"]]})
        return self._enrich_warning(batch)

    def confirm_release(self, event_id: str, actor: str, role: str) -> Dict[str, Any]:
        if not can_confirm_release(role):
            raise PermissionDenied("当前角色无权确认解除")
        actor = require_text(actor, "actor", 100)
        batch = self.repository.get_warning_batch_by_event(event_id)
        if batch is None:
            raise NotFoundError("预警事件不存在")
        status = batch["status"]
        if status == "released":
            raise ConflictError("预警已解除，无需重复确认")
        if status == "failed":
            raise ConflictError("预警批次处置失败，请先重试")
        if not warning_allows_confirmation(status):
            raise ConflictError("当前状态不可确认解除")
        confirmations = self.repository.list_warning_confirmations(batch["id"])
        if len(confirmations) >= RELEASE_CONFIRMATIONS_REQUIRED:
            raise ConflictError("解除已确认完成")
        seq = next_confirmation_seq(len(confirmations))
        if seq == 1:
            self.repository.add_warning_confirmation(batch["id"], seq, actor)
            self.repository.update_warning_status(batch["id"], "release_pending")
            self.repository.append_audit("release_confirmed", WARNING_ENTITY,
                                         batch["id"], actor,
                                         {"event_id": event_id, "seq": seq})
            return self._enrich_warning(self.repository.get_warning_batch(batch["id"]))
        first_actor = confirmations[0]["actor"]
        if first_actor == actor:
            raise ConflictError("解除需两名不同人员先后确认")
        self.repository.add_warning_confirmation(batch["id"], seq, actor)
        result = batch["result"]
        resumed: List[Dict[str, Any]] = []
        for snap in result.get("paused", []):
            item_id = snap["item_id"]
            # 仍有其他未解除预警覆盖则不复工
            if self._covered_by_other_active_warning(item_id, batch["id"]):
                continue
            self.repository.resume_item(item_id)
            resumed.append(dict(snap, resumed_by=[first_actor, actor],
                                resumed_at=utc_now()))
        result["resumed"] = result.get("resumed", []) + resumed
        resumed_ids = {r["item_id"] for r in resumed}
        result["paused"] = [s for s in result["paused"]
                            if s["item_id"] not in resumed_ids]
        updated = self.repository.update_warning_result(batch["id"], result, "released")
        self.repository.append_audit("release_confirmed", WARNING_ENTITY,
                                     batch["id"], actor,
                                     {"event_id": event_id, "seq": seq})
        self.repository.append_audit("warning_released", WARNING_ENTITY,
                                     batch["id"], actor,
                                     {"event_id": event_id,
                                      "resumed": [r["item_id"] for r in resumed]})
        return self._enrich_warning(updated)

    def retry_warning(self, event_id: str, actor: str, role: str) -> Dict[str, Any]:
        if not can_retry_warning(role):
            raise PermissionDenied("当前角色无权重试预警")
        actor = require_text(actor, "actor", 100)
        batch = self.repository.get_warning_batch_by_event(event_id)
        if batch is None:
            raise NotFoundError("预警事件不存在")
        if batch["status"] != "failed":
            raise ConflictError("批次无需重试")
        try:
            result = self._build_pause_result(batch["building"])
            batch = self.repository.update_warning_result(batch["id"], result, "active")
        except Exception as exc:
            self.repository.append_audit("warning_retry_failed", WARNING_ENTITY,
                                         batch["id"], actor,
                                         {"event_id": event_id, "error": str(exc)})
            raise ConflictError(f"预警重试失败，批次仍保留: {exc}") from exc
        self.repository.append_audit("warning_retried", WARNING_ENTITY,
                                     batch["id"], actor, {"event_id": event_id})
        return self._enrich_warning(batch)

    def list_warnings(self, role: str, status: Optional[str] = None,
                      building: Optional[str] = None) -> list:
        self._view(role)
        return [self._enrich_warning(b)
                for b in self.repository.list_warnings(status, building)]

    def get_warning(self, event_id: str, role: str) -> Dict[str, Any]:
        self._view(role)
        batch = self.repository.get_warning_batch_by_event(event_id)
        if batch is None:
            raise NotFoundError("预警事件不存在")
        return self._enrich_warning(batch)

    def update_item(self, item_id: int, payload: Dict[str, Any], actor: str,
                    role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        expected = payload.get("expected_version")
        if not isinstance(expected, int) or expected < 1:
            raise ValueError("expected_version必须是正整数")
        severity = (normalize_severity(payload["severity"])
                    if payload.get("severity") is not None else item["severity"])
        quantity = (require_number(payload["quantity"], "quantity")
                    if payload.get("quantity") is not None else item["quantity"])
        threshold = (require_number(payload["threshold"], "threshold", 0.000001)
                     if payload.get("threshold") is not None else item["threshold"])
        updated = self.repository.update_item_risk(
            item_id, severity, quantity, threshold, expected, actor)
        self._invalidate_and_recalculate(item_id, actor)
        self.repository.append_audit("risk_params_updated", ENTITY, item_id, actor,
                                     {"severity": severity, "quantity": quantity,
                                      "threshold": threshold})
        return self.enrich(updated)

    def _invalidate_and_recalculate(self, item_id: int, actor: str) -> None:
        for batch in self.repository.list_warnings():
            if batch["status"] == "released":
                # 已经复工的记录留档，不再重算
                continue
            result = batch["result"]
            if not any(s["item_id"] == item_id for s in result.get("paused", [])):
                continue
            item = self.repository.get_item(item_id)
            result["paused"] = [self._risk_snapshot(item)
                                if s["item_id"] == item_id else s
                                for s in result["paused"]]
            if recovery_invalidates(batch["status"]):
                # 未完成的恢复立即失效，按新预警重算
                self.repository.delete_warning_confirmations(batch["id"])
                self.repository.update_warning_result(batch["id"], result, "active")
                self.repository.append_audit("recovery_invalidated", WARNING_ENTITY,
                                             batch["id"], actor,
                                             {"event_id": batch["event_id"],
                                              "item_id": item_id})
            elif recalculates_on_update(batch["status"]):
                self.repository.update_warning_result(batch["id"], result)
                self.repository.append_audit("warning_recalculated", WARNING_ENTITY,
                                             batch["id"], actor,
                                             {"event_id": batch["event_id"],
                                              "item_id": item_id})

    def _build_pause_result(self, building: str) -> Dict[str, Any]:
        items = self.repository.find_items(building=building, status="construction")
        paused = []
        for item in items:
            if pause_eligible(item) and not item["paused"]:
                self.repository.pause_item(item["id"])
            paused.append(self._risk_snapshot(item))
        return {"paused": paused, "resumed": []}

    def _covered_by_other_active_warning(self, item_id: int,
                                         exclude_batch_id: int) -> bool:
        for batch in self.repository.list_warnings():
            if batch["id"] == exclude_batch_id or batch["status"] == "released":
                continue
            if any(s["item_id"] == item_id for s in batch["result"].get("paused", [])):
                return True
        return False

    @staticmethod
    def _risk_snapshot(item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "item_id": item["id"],
            "title": item["title"],
            "severity": item["severity"],
            "quantity": item["quantity"],
            "threshold": item["threshold"],
            "priority": priority_score(item["severity"], item["quantity"],
                                        item["threshold"]),
            "deadline_hours": response_deadline_hours(item["severity"],
                                                      item["quantity"],
                                                      item["threshold"]),
        }

    def _enrich_warning(self, batch: Dict[str, Any],
                        duplicate: bool = False) -> Dict[str, Any]:
        result = dict(batch)
        result["duplicate"] = duplicate
        result["confirmations"] = self.repository.list_warning_confirmations(batch["id"])
        return result

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
