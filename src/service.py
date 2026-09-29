from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from .domain import (ConflictError, ensure_role, normalize_severity,
                     require_number, require_text)
from .repository import Repository
from .rules import (ALERT_CONFIRM_ROLES, ALERT_ENTITY, ALERT_PUSH_ROLES,
                    AUDIT_ROLES, BATCH_ENTITY, CREATE_ROLES, DISPOSITION_ENTITY,
                    ENTITY, RECORD_ROLES, RISK_UPDATE_ROLES, TITLE, VIEW_ROLES,
                    can_confirm_release, completion_blockers,
                    escalation_required, normalize_alert_kind,
                    normalize_alert_level, recalc_pause_required, priority_score,
                    response_deadline_hours, role_for_transition, same_building,
                    validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    @staticmethod
    def _building(payload: Dict[str, Any]) -> str:
        building = payload.get("building", "") or ""
        return require_text(building, "building", 200) if building else ""

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
        building = self._building(payload)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, building, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "building": building, "priority": priority_score(severity, quantity, threshold),
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

    # ===== 余震预警处置 =====
    @staticmethod
    def _parse_event(event: Any, position: int) -> Dict[str, Any]:
        if not isinstance(event, dict):
            raise ValueError(f"第{position}条事件必须是对象")
        kind = normalize_alert_kind(event.get("kind"))
        event_id = require_text(event.get("event_id"), "event_id", 100)
        message = require_text(event.get("message", ""), "message", 2000)
        if kind == "alert":
            level = normalize_alert_level(event.get("level"))
            building = require_text(event.get("building"), "building", 200)
            return {"event_id": event_id, "kind": kind, "level": level,
                    "building": building, "message": message, "ref_event_id": None}
        ref_event_id = require_text(event.get("ref_event_id"), "ref_event_id", 100)
        return {"event_id": event_id, "kind": kind, "level": None,
                "building": None, "message": message, "ref_event_id": ref_event_id}

    def _ingest_alert(self, event: Dict[str, Any], batch_item_id: Optional[int],
                      actor: str) -> Dict[str, Any]:
        existing = self.repository.get_alert_by_event(event["event_id"])
        if existing is not None:
            return existing
        targets = self.repository.list_under_construction(event["building"])
        alert = self.repository.create_alert_with_dispositions(
            event["event_id"], event["building"], event["level"], event["message"],
            batch_item_id, targets, actor)
        self.repository.append_audit("ingest_alert", ALERT_ENTITY, alert["id"], actor, {
            "event_id": event["event_id"], "building": event["building"],
            "level": event["level"], "paused_items": len(targets),
        })
        return alert

    def _ingest_release(self, event: Dict[str, Any], batch_item_id: Optional[int],
                        actor: str) -> Dict[str, Any]:
        # 幂等只认“已挂到某条预警上”的解除事件；失败批次重试时事件尚未生效，应继续处理
        linked = self.repository.get_alert_by_release_event(event["event_id"])
        if linked is not None:
            return linked
        alert = self.repository.ingest_release(
            event["event_id"], event["ref_event_id"], batch_item_id)
        if alert is None:
            return self.repository.get_alert_by_event(event["ref_event_id"])
        self.repository.append_audit("ingest_release", ALERT_ENTITY, alert["id"], actor, {
            "event_id": event["event_id"], "ref_event_id": event["ref_event_id"],
        })
        return alert

    def _run_batch(self, batch_id: int, actor: str,
                   retry_failed: bool = False) -> Dict[str, Any]:
        batch = self.repository.get_batch(batch_id)
        for item in batch["items"]:
            if item["status"] == "ok":
                continue
            if item["status"] == "failed" and not retry_failed:
                continue
            try:
                event = {"event_id": item["event_id"], "kind": item["kind"],
                         "ref_event_id": item["ref_event_id"], "level": item["level"],
                         "building": item["building"], "message": item["message"]}
                if item["kind"] == "alert":
                    self._ingest_alert(event, item["id"], actor)
                else:
                    self._ingest_release(event, item["id"], actor)
            except Exception as exc:  # 单条失败不拖垮整批，批次保留可重试
                self.repository.mark_batch_item(item["id"], "failed", str(exc))
            else:
                self.repository.mark_batch_item(item["id"], "ok")
        return self.repository.get_batch(batch_id)

    def push_warnings(self, payload: Dict[str, Any], actor: str,
                      role: str) -> Dict[str, Any]:
        ensure_role(role, ALERT_PUSH_ROLES)
        actor = require_text(actor, "actor", 100)
        events_raw = payload.get("events")
        if not isinstance(events_raw, list) or not events_raw:
            raise ValueError("events必须是非空数组")
        if len(events_raw) > 1000:
            raise ValueError("单批最多1000条事件")
        events = [self._parse_event(event, index) for index, event in enumerate(events_raw)]
        batch_ref = payload.get("batch_ref")
        if batch_ref is not None:
            batch_ref = require_text(batch_ref, "batch_ref", 100)
            present = self.repository.get_batch_by_ref(batch_ref)
            if present is not None:
                return self._run_batch(present["id"], actor)
        else:
            batch_ref = "BAT-" + uuid.uuid4().hex
        try:
            batch = self.repository.create_batch(batch_ref, events, actor)
        except ConflictError:
            # 并发推送同一batch_ref：只保留一份处置，挂到既有批次继续执行
            present = self.repository.get_batch_by_ref(batch_ref)
            if present is None:
                raise
            return self._run_batch(present["id"], actor, retry_failed=True)
        self.repository.append_audit("push_batch", BATCH_ENTITY, batch["id"], actor, {
            "batch_ref": batch_ref, "events": len(events),
        })
        return self._run_batch(batch["id"], actor)

    def retry_batch(self, batch_id: int, actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, ALERT_PUSH_ROLES)
        actor = require_text(actor, "actor", 100)
        batch = self.repository.get_batch(batch_id)
        self.repository.append_audit("retry_batch", BATCH_ENTITY, batch_id, actor, {
            "status": batch["status"],
        })
        return self._run_batch(batch_id, actor, retry_failed=True)

    def confirm_release(self, alert_id: int, payload: Dict[str, Any],
                        actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, ALERT_CONFIRM_ROLES)
        actor = require_text(actor, "actor", 100)
        alert = self.repository.get_alert(alert_id)
        prior = [entry["actor"] for entry in self.repository.list_confirmations(alert_id)]
        if not can_confirm_release(role, actor, prior):
            raise ConflictError("解除必须由两名不同人员先后确认")
        result = self.repository.add_release_confirmation(alert_id, actor, role)
        self.repository.append_audit("confirm_release", ALERT_ENTITY, alert_id, actor, {
            "event_id": alert["event_id"], "ordinal": result["ordinal"],
            "resumed": result["resumed"],
        })
        for disposition_id in result.get("resumed_disposition_ids", []):
            disposition = next(
                (entry for entry in self.repository.list_dispositions(alert_id)
                 if entry["id"] == disposition_id), None)
            self.repository.append_audit(
                "resume_disposition", DISPOSITION_ENTITY, disposition_id, actor, {
                    "alert_id": alert_id,
                    "item_id": disposition["item_id"] if disposition else None,
                })
        return self._alert_view(result)

    def update_item_risk(self, item_id: int, payload: Dict[str, Any],
                         actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, RISK_UPDATE_ROLES)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        severity = normalize_severity(payload.get("severity", item["severity"]))
        quantity = require_number(payload.get("quantity", item["quantity"]), "quantity")
        threshold = require_number(payload.get("threshold", item["threshold"]),
                                   "threshold", 0.000001)
        building_raw = payload.get("building", item["building"])
        building = require_text(building_raw, "building", 200) if (building_raw or "") else ""
        expected_version = payload.get("expected_version")
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")

        def decider(updated: Dict[str, Any], alert: Dict[str, Any]) -> Dict[str, bool]:
            matches = same_building(updated, alert["building"])
            return {"matches_building": matches,
                    "pause": matches and recalc_pause_required(updated, alert["level"])}

        outcome = self.repository.update_item_risk_and_reconsider(
            item_id, severity, quantity, threshold, building, expected_version,
            actor, decider)
        self.repository.append_audit("update_risk", ENTITY, item_id, actor, {
            "severity": severity, "quantity": quantity, "threshold": threshold,
            "building": building, "changes": outcome["changes"],
        })
        return {"item": self.enrich(outcome["item"]), "changes": outcome["changes"]}

    def list_alerts(self, role: str, building: Optional[str] = None) -> list:
        self._view(role)
        return [self._alert_view(alert)
                for alert in self.repository.list_alerts(building)]

    def get_alert(self, alert_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self._alert_view(self.repository.get_alert(alert_id))

    def get_batch(self, batch_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.repository.get_batch(batch_id)

    def _alert_view(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(alert)
        result["dispositions"] = self.repository.list_dispositions(alert["id"])
        result["confirmations"] = self.repository.list_confirmations(alert["id"])
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
