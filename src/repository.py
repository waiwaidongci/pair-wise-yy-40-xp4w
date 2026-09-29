from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ID_PREFIX, STATES


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
                    building TEXT,
                    paused INTEGER NOT NULL DEFAULT 0 CHECK(paused IN (0,1)),
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
            """)
        # 兼容旧库：补充楼栋与暂停标记列
        for column, ddl in (("building", "TEXT"), ("paused", "INTEGER NOT NULL DEFAULT 0")):
            try:
                self.conn.execute(f"ALTER TABLE items ADD COLUMN {column} {ddl}")
            except sqlite3.OperationalError:
                pass
        with self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS warning_batches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    building TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active'
                        CHECK(status IN ('active','release_pending','released','failed')),
                    result TEXT NOT NULL DEFAULT '{}',
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS warning_confirmations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id INTEGER NOT NULL
                        REFERENCES warning_batches(id) ON DELETE CASCADE,
                    seq INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(batch_id, seq),
                    UNIQUE(batch_id, actor)
                );
            """)

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str, building: Optional[str] = None) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, building, paused, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, building, 0, actor, now, now),
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

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # ---- 预警处置存储 ----

    @staticmethod
    def _warning_batch(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["result"] = json.loads(d["result"])
        return d

    def create_warning_batch(self, event_id: str, building: str, severity: str,
                             actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO warning_batches(event_id, building, severity, status, result,
                       created_by, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)""",
                    (event_id, building, severity, "active", "{}", actor, now, now),
                )
                batch_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("预警事件已存在") from exc
        return self.get_warning_batch(batch_id)

    def get_warning_batch(self, batch_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM warning_batches WHERE id=?", (batch_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("预警批次不存在")
        return self._warning_batch(row)

    def get_warning_batch_by_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM warning_batches WHERE event_id=?", (event_id,)
            ).fetchone()
        return self._warning_batch(row) if row is not None else None

    def list_warnings(self, status: Optional[str] = None,
                      building: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM warning_batches WHERE 1=1"
        params: list = []
        if status:
            sql += " AND status=?"
            params.append(status)
        if building:
            sql += " AND building=?"
            params.append(building)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._warning_batch(row) for row in rows]

    def update_warning_result(self, batch_id: int, result: Dict[str, Any],
                               status: Optional[str] = None) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            if status is None:
                self.conn.execute(
                    "UPDATE warning_batches SET result=?, updated_at=? WHERE id=?",
                    (json.dumps(result, ensure_ascii=False), now, batch_id),
                )
            else:
                self.conn.execute(
                    "UPDATE warning_batches SET result=?, status=?, updated_at=? WHERE id=?",
                    (json.dumps(result, ensure_ascii=False), status, now, batch_id),
                )
        return self.get_warning_batch(batch_id)

    def update_warning_status(self, batch_id: int, status: str) -> None:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE warning_batches SET status=?, updated_at=? WHERE id=?",
                (status, now, batch_id),
            )

    def add_warning_confirmation(self, batch_id: int, seq: int, actor: str) -> None:
        now = utc_now()
        try:
            with self._lock, self.conn:
                self.conn.execute(
                    """INSERT INTO warning_confirmations(batch_id, seq, actor, created_at)
                       VALUES(?,?,?,?)""",
                    (batch_id, seq, actor, now),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("确认冲突：序号或人员已存在") from exc

    def list_warning_confirmations(self, batch_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM warning_confirmations WHERE batch_id=? ORDER BY seq",
                (batch_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_warning_confirmations(self, batch_id: int) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "DELETE FROM warning_confirmations WHERE batch_id=?", (batch_id,)
            )

    def find_items(self, building: Optional[str] = None,
                   status: Optional[str] = None,
                   paused: Optional[bool] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items WHERE 1=1"
        params: list = []
        if building is not None:
            sql += " AND building=?"
            params.append(building)
        if status is not None:
            sql += " AND status=?"
            params.append(status)
        if paused is not None:
            sql += " AND paused=?"
            params.append(1 if paused else 0)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def pause_item(self, item_id: int) -> None:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                "UPDATE items SET paused=1, version=version+1, updated_at=? "
                "WHERE id=? AND status=?",
                (now, item_id, "construction"),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute(
                    "SELECT 1 FROM items WHERE id=?", (item_id,)
                ).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("项目不在施工状态，无法暂停")

    def resume_item(self, item_id: int) -> None:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                "UPDATE items SET paused=0, version=version+1, updated_at=? "
                "WHERE id=? AND paused=1",
                (now, item_id),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute(
                    "SELECT 1 FROM items WHERE id=?", (item_id,)
                ).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")

    def update_item_risk(self, item_id: int, severity: str, quantity: float,
                         threshold: float, expected_version: int,
                         actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET severity=?, quantity=?, threshold=?,
                   version=version+1, updated_at=? WHERE id=? AND version=?""",
                (severity, quantity, threshold, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute(
                    "SELECT 1 FROM items WHERE id=?", (item_id,)
                ).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)
