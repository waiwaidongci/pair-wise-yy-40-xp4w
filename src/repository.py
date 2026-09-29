from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import (ALERT_STATUSES, BATCH_ITEM_STATUSES, BATCH_STATUSES,
                    CONSTRUCTION_STATE, DISPOSITION_STATUSES, STATES)


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        alert_statuses = ",".join("'" + s + "'" for s in ALERT_STATUSES)
        disposition_statuses = ",".join("'" + s + "'" for s in DISPOSITION_STATUSES)
        batch_statuses = ",".join("'" + s + "'" for s in BATCH_STATUSES)
        batch_item_statuses = ",".join("'" + s + "'" for s in BATCH_ITEM_STATUSES)
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    building TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alert_batches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_ref TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL CHECK(status IN ({batch_statuses})),
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alert_batch_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id INTEGER NOT NULL REFERENCES alert_batches(id) ON DELETE CASCADE,
                    position INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('alert','release')),
                    ref_event_id TEXT,
                    level TEXT,
                    building TEXT,
                    message TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL CHECK(status IN ({batch_item_statuses})),
                    error TEXT NOT NULL DEFAULT '',
                    UNIQUE(batch_id, position)
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    release_event_id TEXT,
                    building TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL CHECK(status IN ({alert_statuses})),
                    batch_item_id INTEGER REFERENCES alert_batch_items(id),
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS dispositions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    generation INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({disposition_statuses})),
                    reason TEXT NOT NULL DEFAULT '',
                    resumed_by TEXT,
                    resumed_at TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(alert_id, item_id, generation)
                );
                CREATE INDEX IF NOT EXISTS ix_dispositions_item ON dispositions(item_id);
                CREATE TABLE IF NOT EXISTS release_confirmations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                    ordinal INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(alert_id, ordinal),
                    UNIQUE(alert_id, actor)
                );
            """)
            columns = [row[1] for row in self.conn.execute("PRAGMA table_info(items)").fetchall()]
            if "building" not in columns:
                self.conn.execute(
                    "ALTER TABLE items ADD COLUMN building TEXT NOT NULL DEFAULT ''")

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    building: str, actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, building, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, building, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = row["entry_hash"] if row else "GENESIS"
            event = make_entry(action, entity_type, entity_id, actor, detail, previous)
            cur = self.conn.execute(
                """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                   previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                 json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                 event["previous_hash"], event["entry_hash"], event["created_at"]),
            )
            event_id = int(cur.lastrowid)
        event["id"] = event_id
        return event

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    # ===== 余震预警存储 =====
    def list_under_construction(self, building: str) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM items WHERE status=? AND building=? ORDER BY id",
                (CONSTRUCTION_STATE, building),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_alert_by_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM alerts WHERE event_id=?", (event_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_alert(self, alert_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if row is None:
            raise NotFoundError("预警事件不存在")
        return dict(row)

    def list_alerts(self, building: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM alerts"
        params: tuple = ()
        if building:
            sql += " WHERE building=?"
            params = (building,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def create_alert_with_dispositions(self, event_id: str, building: str, level: str,
                                       message: str, batch_item_id: Optional[int],
                                       targets: List[Dict[str, Any]],
                                       actor: str) -> Dict[str, Any]:
        """同一事件只生成一次结果：预警与其全部暂停处置在一个事务内落库。"""
        now = utc_now()
        with self._lock, self.conn:
            exists = self.conn.execute(
                "SELECT id FROM alerts WHERE event_id=?", (event_id,)
            ).fetchone()
            if exists is not None:
                return self.get_alert(int(exists["id"]))
            try:
                cur = self.conn.execute(
                    """INSERT INTO alerts(event_id, building, level, message, status,
                       batch_item_id, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (event_id, building, level, message, ALERT_STATUSES[0],
                     batch_item_id, actor, now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("同一预警事件已生成过处置") from exc
            alert_id = int(cur.lastrowid)
            for target in targets:
                self.conn.execute(
                    """INSERT INTO dispositions(alert_id, item_id, generation, status, reason,
                       created_by, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)""",
                    (alert_id, int(target["id"]), 1, DISPOSITION_STATUSES[0],
                     "同楼栋在施项目先暂停", actor, now, now),
                )
        return self.get_alert(alert_id)

    def list_dispositions(self, alert_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM dispositions WHERE alert_id=? ORDER BY id", (alert_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def current_disposition(self, alert_id: int, item_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                """SELECT * FROM dispositions WHERE alert_id=? AND item_id=?
                   ORDER BY generation DESC LIMIT 1""",
                (alert_id, item_id),
            ).fetchone()
        return dict(row) if row else None

    def get_alert_by_release_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM alerts WHERE release_event_id=?", (event_id,)
            ).fetchone()
        return dict(row) if row else None

    def ingest_release(self, event_id: str, ref_event_id: str,
                       batch_item_id: Optional[int]) -> Optional[Dict[str, Any]]:
        """登记解除消息：幂等；返回None表示重复解除。已复工的事件拒绝。"""
        now = utc_now()
        with self._lock, self.conn:
            alert = self.conn.execute(
                "SELECT * FROM alerts WHERE event_id=?", (ref_event_id,)
            ).fetchone()
            if alert is None:
                raise NotFoundError("解除消息对应的预警事件不存在")
            if alert["release_event_id"] == event_id:
                return None
            if alert["release_event_id"] is not None:
                return None
            if alert["status"] == ALERT_STATUSES[2]:
                raise ConflictError("预警已完成复工确认")
            self.conn.execute(
                """UPDATE alerts SET release_event_id=?, status=?, batch_item_id=COALESCE(?,batch_item_id),
                   updated_at=? WHERE id=?""",
                (event_id, ALERT_STATUSES[1], batch_item_id, now, alert["id"]),
            )
        return self.get_alert(int(alert["id"]))

    def list_confirmations(self, alert_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM release_confirmations WHERE alert_id=? ORDER BY ordinal",
                (alert_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def add_release_confirmation(self, alert_id: int, actor: str,
                                 role: str) -> Dict[str, Any]:
        """两名不同人员先后确认；第二次确认原子地恢复全部暂停处置。"""
        now = utc_now()
        with self._lock, self.conn:
            alert = self.conn.execute(
                "SELECT * FROM alerts WHERE id=?", (alert_id,)
            ).fetchone()
            if alert is None:
                raise NotFoundError("预警事件不存在")
            if alert["status"] == ALERT_STATUSES[0]:
                raise ConflictError("解除消息尚未登记")
            if alert["status"] == ALERT_STATUSES[2]:
                raise ConflictError("解除已确认完成")
            duplicate = self.conn.execute(
                "SELECT 1 FROM release_confirmations WHERE alert_id=? AND actor=?",
                (alert_id, actor),
            ).fetchone()
            if duplicate is not None:
                raise ConflictError("同一确认人不能重复确认")
            ordinal = int(self.conn.execute(
                "SELECT COUNT(*) AS n FROM release_confirmations WHERE alert_id=?",
                (alert_id,),
            ).fetchone()["n"]) + 1
            self.conn.execute(
                """INSERT INTO release_confirmations(alert_id, ordinal, actor, role, created_at)
                   VALUES(?,?,?,?,?)""",
                (alert_id, ordinal, actor, role, now),
            )
            resumed = False
            resumed_ids: List[int] = []
            if ordinal >= 2:
                self.conn.execute(
                    """UPDATE dispositions SET status=?, resumed_by=?, resumed_at=?, updated_at=?
                       WHERE alert_id=? AND status='paused'""",
                    (DISPOSITION_STATUSES[1], actor, now, now, alert_id),
                )
                resumed_ids = [int(row[0]) for row in self.conn.execute(
                    "SELECT id FROM dispositions WHERE alert_id=? AND resumed_at=?",
                    (alert_id, now),
                ).fetchall()]
                self.conn.execute(
                    "UPDATE alerts SET status=?, updated_at=? WHERE id=?",
                    (ALERT_STATUSES[2], now, alert_id),
                )
                resumed = True
        result = self.get_alert(alert_id)
        result["ordinal"] = ordinal
        result["resumed"] = resumed
        result["resumed_disposition_ids"] = resumed_ids
        return result

    def create_batch(self, batch_ref: str, events: List[Dict[str, Any]],
                     actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            try:
                cur = self.conn.execute(
                    """INSERT INTO alert_batches(batch_ref, status, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?)""",
                    (batch_ref, BATCH_STATUSES[0], actor, now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("批次已存在") from exc
            batch_id = int(cur.lastrowid)
            for position, event in enumerate(events):
                self.conn.execute(
                    """INSERT INTO alert_batch_items(batch_id, position, event_id, kind,
                       ref_event_id, level, building, message, status)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (batch_id, position, event["event_id"], event["kind"],
                     event.get("ref_event_id"), event.get("level"),
                     event.get("building"), event.get("message", ""),
                     BATCH_ITEM_STATUSES[0]),
                )
        return self.get_batch(batch_id)

    def get_batch(self, batch_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM alert_batches WHERE id=?", (batch_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("批次不存在")
        result = dict(row)
        with self._lock:
            items = self.conn.execute(
                "SELECT * FROM alert_batch_items WHERE batch_id=? ORDER BY position",
                (batch_id,),
            ).fetchall()
        result["items"] = [dict(item) for item in items]
        return result

    def get_batch_by_ref(self, batch_ref: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM alert_batches WHERE batch_ref=?", (batch_ref,)
            ).fetchone()
        return self.get_batch(int(row["id"])) if row else None

    def mark_batch_item(self, batch_item_id: int, status: str, error: str = "") -> None:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE alert_batch_items SET status=?, error=? WHERE id=?",
                (status, error, batch_item_id),
            )
            aggregate = self.conn.execute(
                "SELECT status FROM alert_batch_items WHERE batch_id=(SELECT batch_id FROM alert_batch_items WHERE id=?)",
                (batch_item_id,),
            ).fetchall()
            statuses = [row["status"] for row in aggregate]
            if any(s == BATCH_ITEM_STATUSES[0] for s in statuses):
                batch_status = BATCH_STATUSES[0]
            elif all(s == BATCH_ITEM_STATUSES[2] for s in statuses):
                batch_status = BATCH_STATUSES[3]
            elif any(s == BATCH_ITEM_STATUSES[2] for s in statuses):
                batch_status = BATCH_STATUSES[2]
            else:
                batch_status = BATCH_STATUSES[1]
            self.conn.execute(
                "UPDATE alert_batches SET status=?, updated_at=? WHERE id=(SELECT batch_id FROM alert_batch_items WHERE id=?)",
                (batch_status, now, batch_item_id),
            )

    def update_item_risk_and_reconsider(
            self, item_id: int, severity: str, quantity: float, threshold: float,
            building: str, expected_version: int, actor: str,
            decider: Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, bool]]
    ) -> Dict[str, Any]:
        """风险参数更新与处置重算在一个事务内完成：未完成恢复立即失效，已复工留档。"""
        now = utc_now()
        with self._lock, self.conn:
            item = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("项目不存在")
            cur = self.conn.execute(
                """UPDATE items SET severity=?, quantity=?, threshold=?, building=?,
                   version=version+1, updated_at=? WHERE id=? AND version=?""",
                (severity, quantity, threshold, building, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                raise ConflictError("版本冲突，请刷新后重试")
            updated = dict(item)
            updated.update(severity=severity, quantity=quantity, threshold=threshold,
                           building=building, version=int(item["version"]) + 1,
                           updated_at=now)
            alerts = self.conn.execute(
                "SELECT * FROM alerts WHERE status!=? ORDER BY id", (ALERT_STATUSES[2],)
            ).fetchall()
            changes: List[Dict[str, Any]] = []
            for alert in alerts:
                disposition = self.conn.execute(
                    """SELECT * FROM dispositions WHERE alert_id=? AND item_id=?
                       ORDER BY generation DESC LIMIT 1""",
                    (alert["id"], item_id),
                ).fetchone()
                decision = decider(updated, dict(alert))
                matches = bool(decision["matches_building"])
                paused = bool(decision["pause"])
                if disposition is not None and disposition["status"] == DISPOSITION_STATUSES[1]:
                    # 已复工记录留档，风险参数更新不再重新暂停
                    continue
                if not matches:
                    if disposition is not None and disposition["status"] == DISPOSITION_STATUSES[0]:
                        self.conn.execute(
                            "UPDATE dispositions SET status=?, updated_at=? WHERE id=?",
                            (DISPOSITION_STATUSES[2], now, disposition["id"]),
                        )
                        changes.append({"alert_id": int(alert["id"]), "event_id": alert["event_id"],
                                        "generation": int(disposition["generation"]),
                                        "paused": False, "invalidated": True})
                    continue
                active_disposition = disposition is not None and disposition["status"] != DISPOSITION_STATUSES[2]
                if active_disposition or paused:
                    # 未完成的恢复立即失效：清掉确认、把预警拉回active，按新预警重新走双人确认
                    if disposition is not None and disposition["status"] == DISPOSITION_STATUSES[0]:
                        self.conn.execute(
                            "UPDATE dispositions SET status=?, updated_at=? WHERE id=?",
                            (DISPOSITION_STATUSES[2], now, disposition["id"]),
                        )
                    self.conn.execute(
                        "DELETE FROM release_confirmations WHERE alert_id=?",
                        (alert["id"],),
                    )
                    self.conn.execute(
                        "UPDATE alerts SET status=?, release_event_id=NULL, updated_at=? WHERE id=?",
                        (ALERT_STATUSES[0], now, alert["id"]),
                    )
                    if paused:
                        generation = int(disposition["generation"]) + 1 if disposition is not None else 1
                        self.conn.execute(
                            """INSERT INTO dispositions(alert_id, item_id, generation, status, reason,
                               created_by, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)""",
                            (alert["id"], item_id, generation, DISPOSITION_STATUSES[0],
                             "风险参数更新后按新预警重算", actor, now, now),
                        )
                        changes.append({"alert_id": int(alert["id"]), "event_id": alert["event_id"],
                                        "generation": generation, "paused": True,
                                        "invalidated": bool(active_disposition)})
                    elif active_disposition:
                        changes.append({"alert_id": int(alert["id"]), "event_id": alert["event_id"],
                                        "generation": int(disposition["generation"]),
                                        "paused": False, "invalidated": True})
        return {"item": self.get_item(item_id), "changes": changes}


    def close(self) -> None:
        with self._lock:
            self.conn.close()
