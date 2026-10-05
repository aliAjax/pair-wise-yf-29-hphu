"""法律证据保管与流转后台。"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sqlite3
import threading
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "custody.db"
MEMBER_ROLES = {"custodian", "analyst", "auditor"}


class BusinessError(Exception):
    def __init__(self, message, status=400, code="bad_request", details=None):
        super().__init__(message)
        self.message, self.status, self.code, self.details = message, status, code, details


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class CustodyStore:
    def __init__(self, db_path=DEFAULT_DB):
        self.db_path = str(db_path)
        self._lock = threading.Lock()

    def connect(self):
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    def init_schema(self):
        with self._lock, self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users(
                    id TEXT PRIMARY KEY, name TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
                );
                CREATE TABLE IF NOT EXISTS cases(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, case_number TEXT NOT NULL UNIQUE,
                    title TEXT NOT NULL, created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS case_members(
                    case_id INTEGER NOT NULL REFERENCES cases(id), user_id TEXT NOT NULL REFERENCES users(id),
                    role TEXT NOT NULL CHECK(role IN ('custodian','analyst','auditor')),
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
                    granted_by TEXT NOT NULL REFERENCES users(id), granted_at TEXT NOT NULL,
                    PRIMARY KEY(case_id,user_id)
                );
                CREATE TABLE IF NOT EXISTS evidence(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id), label TEXT NOT NULL,
                    filename TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
                    content BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'custody'
                        CHECK(status IN ('custody','opened','released','derivative')),
                    current_custodian TEXT NOT NULL, legal_hold INTEGER NOT NULL DEFAULT 0 CHECK(legal_hold IN (0,1)),
                    retention_until TEXT NOT NULL, created_by TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL, UNIQUE(case_id,label)
                );
                CREATE TABLE IF NOT EXISTS custody_events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id INTEGER NOT NULL REFERENCES evidence(id), sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL CHECK(event_type IN ('INGEST','TRANSFER','OPEN','ANALYZE','RELEASE','HOLD_SET','HOLD_CLEARED')),
                    actor_id TEXT NOT NULL REFERENCES users(id), from_person TEXT,
                    to_person TEXT, location TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
                    previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL, UNIQUE(evidence_id,sequence)
                );
                CREATE TABLE IF NOT EXISTS derivatives(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    parent_evidence_id INTEGER NOT NULL REFERENCES evidence(id),
                    child_evidence_id INTEGER NOT NULL UNIQUE REFERENCES evidence(id),
                    method TEXT NOT NULL, actor_id TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL, UNIQUE(parent_evidence_id,child_evidence_id)
                );
                CREATE TABLE IF NOT EXISTS audit_log(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id), actor_id TEXT NOT NULL REFERENCES users(id),
                    action TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS baselines(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id),
                    baseline_no INTEGER NOT NULL, actor_id TEXT NOT NULL REFERENCES users(id),
                    note TEXT NOT NULL DEFAULT '', complete INTEGER NOT NULL DEFAULT 1 CHECK(complete IN (0,1)),
                    created_at TEXT NOT NULL, UNIQUE(case_id,baseline_no)
                );
                CREATE TABLE IF NOT EXISTS baseline_entries(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    baseline_id INTEGER NOT NULL REFERENCES baselines(id),
                    case_id INTEGER NOT NULL REFERENCES cases(id),
                    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
                    tip_event_hash TEXT NOT NULL, tip_sequence INTEGER NOT NULL,
                    summary_hash TEXT NOT NULL, status TEXT NOT NULL,
                    created_at TEXT NOT NULL, UNIQUE(baseline_id,evidence_id)
                );
                CREATE INDEX IF NOT EXISTS idx_baseline_entries_case ON baseline_entries(case_id,evidence_id);
                """
            )
            self._migrate(conn)

    def _migrate(self, conn):
        """旧库升级：补基线列，为已有案件回填 1 号基线，历史事件和原编号保持不变。"""
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(custody_events)").fetchall()}
        if "baseline_no" not in cols:
            conn.execute("ALTER TABLE custody_events ADD COLUMN baseline_no INTEGER")
        system = "system-migration"
        conn.execute("INSERT OR IGNORE INTO users(id,name,active) VALUES(?,?,'1')", (system, "旧数据升级"))
        # 只回填尚不存在基线、且已有证据的案件；历史事件 baseline_no 留空（NULL 表示基线前事件）
        for case in conn.execute(
            """SELECT c.id AS case_id FROM cases c
               WHERE NOT EXISTS (SELECT 1 FROM baselines b WHERE b.case_id=c.id)
                 AND EXISTS (SELECT 1 FROM evidence e WHERE e.case_id=c.id)"""
        ).fetchall():
            case_id = case["case_id"]
            created_at = now()
            cur = conn.execute(
                "INSERT INTO baselines(case_id,baseline_no,actor_id,note,complete,created_at) VALUES(?,?,?,?,1,?)",
                (case_id, 1, system, "旧数据升级自动补封基线", created_at),
            )
            baseline_id = cur.lastrowid
            for e in conn.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id", (case_id,)).fetchall():
                tip = conn.execute(
                    "SELECT sequence,event_hash FROM custody_events WHERE evidence_id=? ORDER BY sequence DESC LIMIT 1",
                    (e["id"],),
                ).fetchone()
                tip_sequence = tip["sequence"] if tip else 0
                tip_hash = tip["event_hash"] if tip else "GENESIS"
                summary = self._summary(e, tip_sequence, tip_hash)
                conn.execute(
                    """INSERT INTO baseline_entries(baseline_id,case_id,evidence_id,tip_event_hash,tip_sequence,summary_hash,status,created_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (baseline_id, case_id, e["id"], tip_hash, tip_sequence,
                     self._event_hash(summary), e["status"], created_at),
                )
            conn.execute(
                "INSERT INTO audit_log(case_id,actor_id,action,detail,created_at) VALUES(?,?,?,?,?)",
                (case_id, system, "baseline.backfill",
                 json.dumps({"baseline_no": 1, "reason": "legacy_upgrade"}, ensure_ascii=False, sort_keys=True),
                 created_at),
            )

    def seed(self):
        self.init_schema()
        with self.connect() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO users(id,name) VALUES(?,?)",
                [
                    ("custodian1", "证据保管员甲"), ("custodian2", "证据保管员乙"),
                    ("analyst1", "电子数据分析员"), ("auditor1", "案件审计员"), ("outsider", "外部人员"),
                ],
            )

    def _user(self, conn, user_id):
        if not user_id:
            raise BusinessError("缺少 X-User-Id", 401, "authentication_required")
        user = conn.execute("SELECT * FROM users WHERE id=? AND active=1", (user_id,)).fetchone()
        if not user:
            raise BusinessError("用户不存在或已停用", 401, "unknown_user")
        return user

    def _case(self, conn, case_id):
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise BusinessError("案件不存在", 404, "not_found")
        return row

    def _member(self, conn, case_id, user_id, roles=None):
        user = self._user(conn, user_id)
        self._case(conn, case_id)
        row = conn.execute(
            "SELECT * FROM case_members WHERE case_id=? AND user_id=? AND active=1", (case_id, user_id)
        ).fetchone()
        if not row:
            raise BusinessError("不是案件有效成员", 403, "forbidden")
        if roles and row["role"] not in roles:
            raise BusinessError("当前案件角色无权执行此操作", 403, "forbidden")
        return user, row

    def _audit(self, conn, case_id, actor_id, action, detail):
        conn.execute(
            "INSERT INTO audit_log(case_id,actor_id,action,detail,created_at) VALUES(?,?,?,?,?)",
            (case_id, actor_id, action, json.dumps(detail, ensure_ascii=False, sort_keys=True), now()),
        )

    def create_case(self, user_id, case_number, title):
        if not case_number.strip() or len(title.strip()) < 2:
            raise BusinessError("案件编号和标题不能为空", 422, "invalid_case")
        with self.connect() as conn:
            self._user(conn, user_id)
            try:
                cur = conn.execute(
                    "INSERT INTO cases(case_number,title,created_by,created_at) VALUES(?,?,?,?)",
                    (case_number.strip(), title.strip(), user_id, now()),
                )
            except sqlite3.IntegrityError:
                raise BusinessError("案件编号已存在", 409, "case_exists")
            case_id = cur.lastrowid
            conn.execute(
                "INSERT INTO case_members(case_id,user_id,role,granted_by,granted_at) VALUES(?,?,?,?,?)",
                (case_id, user_id, "custodian", user_id, now()),
            )
            self._audit(conn, case_id, user_id, "case.create", {"case_number": case_number.strip()})
            return {"id": case_id, "case_number": case_number.strip(), "title": title.strip()}

    def add_member(self, user_id, case_id, member_id, role):
        if role not in MEMBER_ROLES:
            raise BusinessError("案件角色必须是 custodian、analyst 或 auditor", 422, "invalid_role")
        with self.connect() as conn:
            case = self._case(conn, case_id)
            if case["created_by"] != user_id:
                raise BusinessError("只有案件创建人可以授权成员", 403, "forbidden")
            self._user(conn, member_id)
            conn.execute(
                """INSERT INTO case_members(case_id,user_id,role,active,granted_by,granted_at) VALUES(?,?,?,1,?,?)
                   ON CONFLICT(case_id,user_id) DO UPDATE SET role=excluded.role,active=1,granted_by=excluded.granted_by,granted_at=excluded.granted_at""",
                (case_id, member_id, role, user_id, now()),
            )
            self._audit(conn, case_id, user_id, "member.grant", {"member_id": member_id, "role": role})
            return {"case_id": case_id, "member_id": member_id, "role": role}

    @staticmethod
    def _event_hash(event):
        canonical = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(canonical).hexdigest()

    def _append_event(self, conn, evidence_id, event_type, actor, from_person="", to_person="", location="", note="", baseline_no=None):
        previous = conn.execute(
            "SELECT event_hash,sequence FROM custody_events WHERE evidence_id=? ORDER BY sequence DESC LIMIT 1", (evidence_id,)
        ).fetchone()
        sequence = (previous["sequence"] + 1) if previous else 1
        previous_hash = previous["event_hash"] if previous else "GENESIS"
        payload = {
            "evidence_id": evidence_id, "sequence": sequence, "event_type": event_type,
            "actor_id": actor, "from_person": from_person or None, "to_person": to_person or None,
            "location": location, "note": note, "previous_hash": previous_hash, "created_at": now(),
        }
        digest = self._event_hash(payload)
        cur = conn.execute(
            """INSERT INTO custody_events(evidence_id,sequence,event_type,actor_id,from_person,to_person,location,note,previous_hash,event_hash,created_at,baseline_no)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (evidence_id, sequence, event_type, actor, from_person or None, to_person or None, location, note, previous_hash, digest, payload["created_at"], baseline_no),
        )
        return cur.lastrowid, digest

    def ingest_evidence(self, user_id, case_id, label, filename, content_b64, retention_until, custodian=None):
        label, filename = label.strip(), filename.strip()
        if not label or not filename:
            raise BusinessError("证据标签和文件名不能为空", 422, "invalid_evidence")
        try:
            content = base64.b64decode(content_b64, validate=True)
            deadline = date.fromisoformat(retention_until)
        except (binascii.Error, ValueError, TypeError):
            raise BusinessError("证据内容 Base64 或保留期限格式错误", 422, "invalid_evidence")
        if deadline < date.today():
            raise BusinessError("保留期限不能早于今天", 422, "invalid_retention")
        digest = hashlib.sha256(content).hexdigest()
        custodian = (custodian or user_id).strip()
        with self.connect() as conn:
            _, member = self._member(conn, case_id, user_id, {"custodian"})
            if not custodian:
                raise BusinessError("保管人不能为空", 422, "invalid_custodian")
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    """INSERT INTO evidence(case_id,label,filename,sha256,size,content,current_custodian,retention_until,created_by,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (case_id, label, filename, digest, len(content), content, custodian, retention_until, user_id, now()),
                )
                evidence_id = cur.lastrowid
                self._append_event(conn, evidence_id, "INGEST", user_id, to_person=custodian, note=f"入册 SHA-256 {digest}")
                self._audit(conn, case_id, user_id, "evidence.ingest", {"evidence_id": evidence_id, "sha256": digest, "label": label})
                return {"id": evidence_id, "label": label, "sha256": digest, "size": len(content), "status": "custody", "current_custodian": custodian}
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError("该案件中的证据标签已存在", 409, "label_exists")
            except Exception:
                conn.rollback()
                raise

    def _evidence(self, conn, evidence_id):
        row = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if not row:
            raise BusinessError("证据不存在", 404, "not_found")
        return row

    def get_evidence(self, user_id, evidence_id, include_content=False):
        with self.connect() as conn:
            row = self._evidence(conn, evidence_id)
            self._member(conn, row["case_id"], user_id)
            result = {k: row[k] for k in row.keys() if k != "content"}
            result["legal_hold"] = bool(row["legal_hold"])
            result["integrity_valid"] = hashlib.sha256(row["content"]).hexdigest() == row["sha256"]
            result["events"] = [dict(x) for x in conn.execute("SELECT * FROM custody_events WHERE evidence_id=? ORDER BY sequence", (evidence_id,)).fetchall()]
            result["derived_children"] = [dict(x) for x in conn.execute("SELECT * FROM derivatives WHERE parent_evidence_id=? ORDER BY id", (evidence_id,)).fetchall()]
            if include_content:
                result["content_b64"] = base64.b64encode(row["content"]).decode()
            return result

    def transfer(self, user_id, evidence_id, to_person, location, note="", baseline_no=None):
        if not to_person.strip() or not location.strip():
            raise BusinessError("接收人和保管位置不能为空", 422, "invalid_transfer")
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._evidence(conn, evidence_id)
                _, member = self._member(conn, row["case_id"], user_id, {"custodian"})
                self._guard_baseline(conn, row["case_id"], evidence_id, baseline_no)
                if row["status"] == "released":
                    raise BusinessError("已释放证据不能再移交", 409, "evidence_released")
                self._append_event(conn, evidence_id, "TRANSFER", user_id, from_person=row["current_custodian"], to_person=to_person.strip(), location=location.strip(), note=note.strip(), baseline_no=baseline_no)
                conn.execute("UPDATE evidence SET current_custodian=? WHERE id=?", (to_person.strip(), evidence_id))
                self._audit(conn, row["case_id"], user_id, "custody.transfer", {"evidence_id": evidence_id, "to": to_person.strip(), "location": location.strip(), "baseline_no": baseline_no})
                return {"id": evidence_id, "current_custodian": to_person.strip(), "location": location.strip(), "baseline_no": baseline_no}
            except Exception:
                conn.rollback()
                raise

    def open_evidence(self, user_id, evidence_id, location, note="", baseline_no=None):
        if not location.strip():
            raise BusinessError("开箱地点不能为空", 422, "location_required")
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._evidence(conn, evidence_id)
                _, member = self._member(conn, row["case_id"], user_id, {"custodian"})
                self._guard_baseline(conn, row["case_id"], evidence_id, baseline_no)
                if row["status"] != "custody":
                    raise BusinessError("只有处于封存保管状态的证据可以开箱", 409, "invalid_status")
                self._append_event(conn, evidence_id, "OPEN", user_id, from_person=row["current_custodian"], location=location.strip(), note=note.strip(), baseline_no=baseline_no)
                conn.execute("UPDATE evidence SET status='opened' WHERE id=?", (evidence_id,))
                self._audit(conn, row["case_id"], user_id, "evidence.open", {"evidence_id": evidence_id, "location": location.strip(), "baseline_no": baseline_no})
                return {"id": evidence_id, "status": "opened", "location": location.strip(), "baseline_no": baseline_no}
            except Exception:
                conn.rollback()
                raise

    def derive(self, user_id, evidence_id, method, label, filename, content_b64, baseline_no=None):
        if len(method.strip()) < 3 or not label.strip() or not filename.strip():
            raise BusinessError("分析方法、子证据标签和文件名不能为空", 422, "invalid_derivative")
        try:
            content = base64.b64decode(content_b64, validate=True)
        except (binascii.Error, ValueError, TypeError):
            raise BusinessError("content_b64 不是合法 Base64", 422, "invalid_base64")
        digest = hashlib.sha256(content).hexdigest()
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                parent = self._evidence(conn, evidence_id)
                _, member = self._member(conn, parent["case_id"], user_id, {"analyst"})
                self._guard_baseline(conn, parent["case_id"], evidence_id, baseline_no)
                if parent["status"] != "opened":
                    raise BusinessError("原始证据必须先开箱才能分析", 409, "evidence_not_opened")
                cur = conn.execute(
                    """INSERT INTO evidence(case_id,label,filename,sha256,size,content,status,current_custodian,legal_hold,retention_until,created_by,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (parent["case_id"], label.strip(), filename.strip(), digest, len(content), content, "derivative", user_id, 0, parent["retention_until"], user_id, now()),
                )
                child_id = cur.lastrowid
                conn.execute(
                    "INSERT INTO derivatives(parent_evidence_id,child_evidence_id,method,actor_id,created_at) VALUES(?,?,?,?,?)",
                    (evidence_id, child_id, method.strip(), user_id, now()),
                )
                self._append_event(conn, evidence_id, "ANALYZE", user_id, from_person=parent["current_custodian"], note=f"生成衍生证据 #{child_id}: {method.strip()}", baseline_no=baseline_no)
                self._append_event(conn, child_id, "INGEST", user_id, from_person=parent["current_custodian"], to_person=user_id, note=f"由证据 #{evidence_id} 派生，SHA-256 {digest}")
                self._audit(conn, parent["case_id"], user_id, "evidence.derive", {"parent_id": evidence_id, "child_id": child_id, "method": method.strip(), "sha256": digest, "baseline_no": baseline_no})
                return {"id": child_id, "parent_id": evidence_id, "label": label.strip(), "sha256": digest, "status": "derivative", "baseline_no": baseline_no}
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError("衍生证据标签已存在", 409, "label_exists")
            except Exception:
                conn.rollback()
                raise

    def set_hold(self, user_id, evidence_id, hold, reason):
        if len(reason.strip()) < 5:
            raise BusinessError("法律保留原因至少 5 字", 422, "reason_required")
        with self.connect() as conn:
            row = self._evidence(conn, evidence_id)
            case = self._case(conn, row["case_id"])
            if user_id != case["created_by"]:
                self._member(conn, row["case_id"], user_id, {"auditor"})
            conn.execute("UPDATE evidence SET legal_hold=? WHERE id=?", (int(bool(hold)), evidence_id))
            event = "HOLD_SET" if hold else "HOLD_CLEARED"
            self._append_event(conn, evidence_id, event, user_id, note=reason.strip())
            self._audit(conn, row["case_id"], user_id, "evidence.hold", {"evidence_id": evidence_id, "hold": bool(hold), "reason": reason.strip()})
            return {"id": evidence_id, "legal_hold": bool(hold)}

    def release(self, user_id, evidence_id, recipient, note="", baseline_no=None):
        if not recipient.strip():
            raise BusinessError("接收方不能为空", 422, "recipient_required")
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._evidence(conn, evidence_id)
                _, member = self._member(conn, row["case_id"], user_id, {"custodian"})
                self._guard_baseline(conn, row["case_id"], evidence_id, baseline_no)
                if row["legal_hold"]:
                    raise BusinessError("存在法律保留，禁止释放证据", 409, "legal_hold_active")
                if row["status"] == "released":
                    raise BusinessError("证据已经释放", 409, "already_released")
                self._append_event(conn, evidence_id, "RELEASE", user_id, from_person=row["current_custodian"], to_person=recipient.strip(), note=note.strip(), baseline_no=baseline_no)
                conn.execute("UPDATE evidence SET status='released' WHERE id=?", (evidence_id,))
                self._audit(conn, row["case_id"], user_id, "evidence.release", {"evidence_id": evidence_id, "recipient": recipient.strip(), "baseline_no": baseline_no})
                return {"id": evidence_id, "status": "released", "recipient": recipient.strip(), "baseline_no": baseline_no}
            except Exception:
                conn.rollback()
                raise

    @staticmethod
    def _summary(evidence, tip_sequence, tip_event_hash):
        """证据摘要：元数据快照加链尖，封进基线。"""
        return {
            "evidence_id": evidence["id"], "label": evidence["label"], "filename": evidence["filename"],
            "sha256": evidence["sha256"], "size": evidence["size"], "status": evidence["status"],
            "current_custodian": evidence["current_custodian"], "legal_hold": int(evidence["legal_hold"]),
            "retention_until": evidence["retention_until"],
            "tip_sequence": tip_sequence, "tip_event_hash": tip_event_hash,
        }

    def _tip(self, conn, evidence_id):
        tip = conn.execute(
            "SELECT sequence,event_hash FROM custody_events WHERE evidence_id=? ORDER BY sequence DESC LIMIT 1",
            (evidence_id,),
        ).fetchone()
        return (tip["sequence"], tip["event_hash"]) if tip else (0, "GENESIS")

    def _snapshot(self, conn, case_id, evidence_ids=None):
        """取证据当前链尖与摘要；evidence_ids 为 None 表示案件全部证据。按编号去重。"""
        wanted = None
        if evidence_ids is not None:
            wanted, seen = [], set()
            for eid in evidence_ids:
                if eid not in seen:
                    seen.add(eid)
                    wanted.append(eid)
        snap = {}
        rows = conn.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
        for row in rows:
            if wanted is not None and row["id"] not in wanted:
                continue
            tip_sequence, tip_hash = self._tip(conn, row["id"])
            snap[row["id"]] = {
                "row": row, "tip_sequence": tip_sequence, "tip_event_hash": tip_hash,
                "summary_hash": self._event_hash(self._summary(row, tip_sequence, tip_hash)),
            }
        if wanted is not None:
            known = {row["id"] for row in rows}
            unknown = [eid for eid in wanted if eid not in known]
            if unknown:
                raise BusinessError(f"证据 {unknown} 不属于该案件", 422, "evidence_not_in_case")
        return snap

    def _latest_baseline(self, conn, case_id):
        return conn.execute(
            "SELECT * FROM baselines WHERE case_id=? ORDER BY baseline_no DESC LIMIT 1", (case_id,)
        ).fetchone()

    def _baseline_entries(self, conn, baseline_id):
        return {
            row["evidence_id"]: row
            for row in conn.execute(
                "SELECT * FROM baseline_entries WHERE baseline_id=? ORDER BY evidence_id", (baseline_id,)
            ).fetchall()
        }

    def _guard_baseline(self, conn, case_id, evidence_id, baseline_no):
        """开箱/移交/派生/释放前的依据基线校验：链尖一变即作废写入。"""
        latest = self._latest_baseline(conn, case_id)
        if latest is None or baseline_no is None:
            raise BusinessError("该操作必须依据一条已封存基线，请先由审计员封存", 409, "baseline_required",
                                {"latest_baseline_no": latest["baseline_no"] if latest else None})
        if baseline_no != latest["baseline_no"]:
            raise BusinessError(
                f"依据的基线 {baseline_no} 不是最新基线，本次写入作废", 409, "baseline_stale",
                {"latest_baseline_no": latest["baseline_no"], "cited_baseline_no": baseline_no},
            )
        entry = conn.execute(
            "SELECT * FROM baseline_entries WHERE baseline_id=? AND evidence_id=?", (latest["id"], evidence_id)
        ).fetchone()
        if entry is None:
            raise BusinessError(
                f"最新基线 {latest['baseline_no']} 未覆盖证据 {evidence_id}，请补封后重试", 409, "baseline_incomplete",
                {"latest_baseline_no": latest["baseline_no"], "missing_evidence_id": evidence_id},
            )
        row = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        tip_sequence, tip_hash = self._tip(conn, evidence_id)
        summary_hash = self._event_hash(self._summary(row, tip_sequence, tip_hash))
        if entry["tip_event_hash"] != tip_hash or entry["tip_sequence"] != tip_sequence or entry["summary_hash"] != summary_hash:
            raise BusinessError(
                f"证据 {evidence_id} 自基线 {latest['baseline_no']} 后链尖已变，本次写入作废", 409, "baseline_tip_changed",
                {"latest_baseline_no": latest["baseline_no"], "evidence_id": evidence_id},
            )
        return latest

    def seal_baseline(self, user_id, case_id, expected_baseline_no=None, evidence_ids=None, note=""):
        """审计员把证据链尖和摘要封成带序号的基线。

        并发封存只认先写入的一条：expected_baseline_no 落后即冲突，返回最新编号。
        同次封存/同批事件按编号去重，不产生第二条基线；中途失败重试只补缺的条目。
        evidence_ids 表示本次提交的批次（按编号去重）；基线最终覆盖案件全部证据。
        """
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                self._member(conn, case_id, user_id, {"auditor"})
                self._case(conn, case_id)
                batch = self._snapshot(conn, case_id, evidence_ids)
                if not batch:
                    raise BusinessError("案件还没有证据，无法封存基线", 422, "no_evidence")
                latest = self._latest_baseline(conn, case_id)
                all_ids = {r["id"] for r in conn.execute("SELECT id FROM evidence WHERE case_id=?", (case_id,)).fetchall()}
                created_at = now()

                if latest is not None and expected_baseline_no is not None and expected_baseline_no != latest["baseline_no"]:
                    raise BusinessError(
                        f"已有更新的基线 {latest['baseline_no']} 先写入，本次封存冲突", 409, "baseline_conflict",
                        {"latest_baseline_no": latest["baseline_no"], "cited_baseline_no": expected_baseline_no},
                    )

                if latest is None:
                    if expected_baseline_no is not None and expected_baseline_no != 1:
                        raise BusinessError("案件尚无基线，首条基线编号必须为 1", 409, "baseline_conflict",
                                            {"latest_baseline_no": None, "cited_baseline_no": expected_baseline_no})
                    self._insert_baseline(conn, case_id, 1, user_id, note, created_at, batch, complete=set(batch) == all_ids)
                    target_no, result = 1, "sealed"
                elif not latest["complete"]:
                    # 上次封存中途失败：重试只补剩下的部分，不另开基线
                    entries = self._baseline_entries(conn, latest["id"])
                    fill = self._snapshot(conn, case_id, [eid for eid in all_ids if eid not in entries])
                    self._add_entries(conn, latest["id"], case_id, fill, created_at)
                    covered = {r["evidence_id"] for r in conn.execute(
                        "SELECT evidence_id FROM baseline_entries WHERE baseline_id=?", (latest["id"],)).fetchall()}
                    now_complete = covered >= all_ids
                    conn.execute("UPDATE baselines SET complete=? WHERE id=?", (1 if now_complete else 0, latest["id"]))
                    target_no = latest["baseline_no"]
                    result = "completed" if now_complete else "filled"
                    self._audit(conn, case_id, user_id, "baseline.complete",
                                {"baseline_no": target_no, "filled": sorted(fill), "complete": now_complete})
                else:
                    entries = self._baseline_entries(conn, latest["id"])
                    # 提交批次中的链尖/摘要与最新基线逐条比对
                    changed = [
                        eid for eid, s in batch.items()
                        if eid not in entries
                        or entries[eid]["tip_event_hash"] != s["tip_event_hash"]
                        or entries[eid]["tip_sequence"] != s["tip_sequence"]
                        or entries[eid]["summary_hash"] != s["summary_hash"]
                    ]
                    if not changed:
                        if expected_baseline_no is None:
                            # 未携带依据编号：另一名审计员已抢先封存同一条
                            raise BusinessError(
                                f"基线 {latest['baseline_no']} 已先写入，本次封存冲突", 409, "baseline_conflict",
                                {"latest_baseline_no": latest["baseline_no"]},
                            )
                        target_no, result = latest["baseline_no"], "dedup"
                    else:
                        if expected_baseline_no is None:
                            raise BusinessError(
                                f"基线 {latest['baseline_no']} 已存在，再封存须携带其编号", 409, "baseline_conflict",
                                {"latest_baseline_no": latest["baseline_no"]},
                            )
                        target_no = latest["baseline_no"] + 1
                        # 链尖已变：以案件全部证据的当前链尖封新基线
                        self._insert_baseline(conn, case_id, target_no, user_id, note, created_at,
                                              self._snapshot(conn, case_id))
                        result = "sealed"

                return {
                    "baseline_no": target_no, "result": result,
                    "evidence_ids": sorted(batch), "sealed_at": created_at,
                }
            except Exception:
                conn.rollback()
                raise

    def _add_entries(self, conn, baseline_id, case_id, snapshot, created_at):
        conn.executemany(
            """INSERT OR IGNORE INTO baseline_entries(baseline_id,case_id,evidence_id,tip_event_hash,tip_sequence,summary_hash,status,created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            [
                (baseline_id, case_id, eid, s["tip_event_hash"], s["tip_sequence"], s["summary_hash"], s["row"]["status"], created_at)
                for eid, s in sorted(snapshot.items())
            ],
        )

    def _insert_baseline(self, conn, case_id, baseline_no, actor, note, created_at, snapshot, complete=None):
        if complete is None:
            all_ids = {r["id"] for r in conn.execute("SELECT id FROM evidence WHERE case_id=?", (case_id,)).fetchall()}
            complete = set(snapshot) == all_ids
        cur = conn.execute(
            "INSERT INTO baselines(case_id,baseline_no,actor_id,note,complete,created_at) VALUES(?,?,?,?,?,?)",
            (case_id, baseline_no, actor, note.strip(), 1 if complete else 0, created_at),
        )
        baseline_id = cur.lastrowid
        self._add_entries(conn, baseline_id, case_id, snapshot, created_at)
        self._audit(conn, case_id, actor, "baseline.seal",
                    {"baseline_no": baseline_no, "evidence_ids": sorted(snapshot), "complete": bool(complete)})

    def list_baselines(self, user_id, case_id):
        with self.connect() as conn:
            self._member(conn, case_id, user_id)
            self._case(conn, case_id)
            out = []
            for b in conn.execute("SELECT * FROM baselines WHERE case_id=? ORDER BY baseline_no", (case_id,)).fetchall():
                entries = [
                    {k: e[k] for k in ("evidence_id", "tip_sequence", "tip_event_hash", "summary_hash", "status")}
                    for e in conn.execute("SELECT * FROM baseline_entries WHERE baseline_id=? ORDER BY evidence_id", (b["id"],)).fetchall()
                ]
                out.append({
                    "baseline_no": b["baseline_no"], "actor_id": b["actor_id"], "note": b["note"],
                    "complete": bool(b["complete"]), "created_at": b["created_at"], "entries": entries,
                })
            return {"case_id": case_id, "latest_baseline_no": out[-1]["baseline_no"] if out else None, "baselines": out}

    def report(self, user_id, case_id):
        with self.connect() as conn:
            self._member(conn, case_id, user_id)
            case = self._case(conn, case_id)
            baselines_rows = conn.execute(
                "SELECT * FROM baselines WHERE case_id=? ORDER BY baseline_no", (case_id,)).fetchall()
            baseline_entries_by_no = {}
            for b in baselines_rows:
                baseline_entries_by_no[b["baseline_no"]] = self._baseline_entries(conn, b["id"])
            latest_no = baselines_rows[-1]["baseline_no"] if baselines_rows else None
            # 证据首次被封入的基线序号（报告按此归集）
            first_baseline = {}
            for b in baselines_rows:
                for eid in baseline_entries_by_no[b["baseline_no"]]:
                    first_baseline.setdefault(eid, b["baseline_no"])
            baselines = [{
                "baseline_no": b["baseline_no"], "actor_id": b["actor_id"], "note": b["note"],
                "complete": bool(b["complete"]), "created_at": b["created_at"],
                "evidence_ids": sorted(baseline_entries_by_no[b["baseline_no"]]),
            } for b in baselines_rows]

            items, all_valid = [], True
            for row in conn.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id", (case_id,)).fetchall():
                hash_valid = hashlib.sha256(row["content"]).hexdigest() == row["sha256"]
                events = conn.execute("SELECT * FROM custody_events WHERE evidence_id=? ORDER BY sequence", (row["id"],)).fetchall()
                expected_prev, chain_valid = "GENESIS", True
                event_dicts = []
                for e in events:
                    payload = {
                        "evidence_id": e["evidence_id"], "sequence": e["sequence"], "event_type": e["event_type"],
                        "actor_id": e["actor_id"], "from_person": e["from_person"], "to_person": e["to_person"],
                        "location": e["location"], "note": e["note"], "previous_hash": e["previous_hash"], "created_at": e["created_at"],
                    }
                    if e["previous_hash"] != expected_prev or self._event_hash(payload) != e["event_hash"]:
                        chain_valid = False
                    expected_prev = e["event_hash"]
                    ed = dict(e)
                    # 基线后新增事件：链尖序号超过最近基线封存位置，或事件显式依据更新的基线
                    sealed_seq = None
                    if latest_no is not None:
                        entry = baseline_entries_by_no.get(latest_no, {}).get(e["evidence_id"])
                        if entry is not None:
                            sealed_seq = entry["tip_sequence"]
                    ed["after_latest_baseline"] = sealed_seq is not None and e["sequence"] > sealed_seq
                    ed["pre_baseline_event"] = e["baseline_no"] is None
                    event_dicts.append(ed)
                all_valid = all_valid and hash_valid and chain_valid
                tip_sequence, tip_hash = self._tip(conn, row["id"])
                summary_hash = self._event_hash(self._summary(row, tip_sequence, tip_hash))
                latest_entry = baseline_entries_by_no.get(latest_no, {}).get(row["id"]) if latest_no else None
                tip_changed_since_latest = (
                    latest_entry is not None
                    and (latest_entry["tip_event_hash"] != tip_hash
                         or latest_entry["tip_sequence"] != tip_sequence
                         or latest_entry["summary_hash"] != summary_hash)
                )
                items.append({
                    "id": row["id"], "label": row["label"], "filename": row["filename"], "sha256": row["sha256"],
                    "size": row["size"], "status": row["status"], "current_custodian": row["current_custodian"],
                    "legal_hold": bool(row["legal_hold"]), "retention_until": row["retention_until"],
                    "hash_valid": hash_valid, "chain_valid": chain_valid,
                    "sealed_in_baseline_no": first_baseline.get(row["id"]),
                    "latest_baseline_tip_sequence": latest_entry["tip_sequence"] if latest_entry else None,
                    "tip_changed_since_latest_baseline": tip_changed_since_latest,
                    "events": event_dicts,
                    "derivatives": [dict(x) for x in conn.execute("SELECT * FROM derivatives WHERE parent_evidence_id=? ORDER BY id", (row["id"],)).fetchall()],
                })
            # 按基线归集：基线序号 -> 该基线首次封存的证据
            grouped = {"unsealed": [], "by_baseline": {}}
            for item in items:
                no = item["sealed_in_baseline_no"]
                if no is None:
                    grouped["unsealed"].append(item["id"])
                else:
                    grouped["by_baseline"].setdefault(str(no), []).append(item["id"])
            audit = conn.execute("SELECT * FROM audit_log WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
            return {
                "case": dict(case), "generated_at": now(), "overall_integrity_valid": all_valid,
                "evidence_count": len(items), "evidence": items,
                "latest_baseline_no": latest_no, "baselines": baselines, "baseline_grouping": grouped,
                "audit": [dict(a) | {"detail": json.loads(a["detail"])} for a in audit],
            }


class Handler(BaseHTTPRequestHandler):
    server_version = "EvidenceCustody/1.0"
    def _store(self): return self.server.store  # type: ignore[attr-defined]
    def _body(self):
        length = int(self.headers.get("Content-Length", "0"))
        try: data = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError): raise BusinessError("请求体必须是合法 JSON", 400, "invalid_json")
        if not isinstance(data, dict): raise BusinessError("JSON 顶层必须是对象", 422, "invalid_json")
        return data
    def _send(self, status, payload):
        body=json.dumps(payload,ensure_ascii=False).encode(); self.send_response(status)
        self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def _dispatch(self, method):
        path=urlparse(self.path).path.rstrip("/") or "/"; parts=[p for p in path.split("/") if p]
        user=self.headers.get("X-User-Id",""); store=self._store()
        if method=="GET" and path=="/":
            body=(BASE_DIR/"web"/"index.html").read_bytes(); self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(body)))
            self.end_headers(); self.wfile.write(body); return
        if method=="GET" and path=="/health": return self._send(200,{"ok":True})
        if parts==["api","cases"] and method=="POST":
            d=self._body(); return self._send(201,store.create_case(user,d.get("case_number",""),d.get("title","")))
        if len(parts)==4 and parts[:2]==["api","cases"] and parts[3]=="members" and method=="POST":
            d=self._body(); return self._send(201,store.add_member(user,int(parts[2]),d.get("user_id",""),d.get("role","")))
        if len(parts)==4 and parts[:2]==["api","cases"] and parts[3]=="evidence" and method=="POST":
            d=self._body(); return self._send(201,store.ingest_evidence(user,int(parts[2]),d.get("label",""),d.get("filename",""),d.get("content_b64",""),d.get("retention_until",""),d.get("custodian")))
        if len(parts)==4 and parts[:2]==["api","cases"] and parts[3]=="report" and method=="GET":
            return self._send(200,store.report(user,int(parts[2])))
        if len(parts)==4 and parts[:2]==["api","cases"] and parts[3]=="baselines" and method=="GET":
            return self._send(200,store.list_baselines(user,int(parts[2])))
        if len(parts)==4 and parts[:2]==["api","cases"] and parts[3]=="seal" and method=="POST":
            d=self._body()
            return self._send(201,store.seal_baseline(user,int(parts[2]),d.get("baseline_no"),d.get("evidence_ids"),d.get("note","")))
        if len(parts)>=3 and parts[:2]==["api","evidence"]:
            evidence_id=int(parts[2])
            if len(parts)==3 and method=="GET": return self._send(200,store.get_evidence(user,evidence_id,bool(urlparse(self.path).query)))
            if len(parts)==4 and method=="POST":
                d=self._body()
                bn=d.get("baseline_no")
                if parts[3]=="transfer": return self._send(200,store.transfer(user,evidence_id,d.get("to_person",""),d.get("location",""),d.get("note",""),bn))
                if parts[3]=="open": return self._send(200,store.open_evidence(user,evidence_id,d.get("location",""),d.get("note",""),bn))
                if parts[3]=="derive": return self._send(201,store.derive(user,evidence_id,d.get("method",""),d.get("label",""),d.get("filename",""),d.get("content_b64",""),bn))
                if parts[3]=="release": return self._send(200,store.release(user,evidence_id,d.get("recipient",""),d.get("note",""),bn))
                if parts[3]=="hold": return self._send(200,store.set_hold(user,evidence_id,bool(d.get("hold")),d.get("reason","")))
        raise BusinessError("接口不存在",404,"not_found")
    def _handle(self, method):
        try: self._dispatch(method)
        except BusinessError as exc:
            err={"code":exc.code,"message":exc.message}
            if exc.details: err.update(exc.details)
            self._send(exc.status,{"error":err})
        except (ValueError,TypeError): self._send(400,{"error":{"code":"invalid_path","message":"路径参数格式错误"}})
        except Exception as exc: self._send(500,{"error":{"code":"internal_error","message":str(exc)}})
    def do_GET(self): self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_DELETE(self): self._send(405,{"error":{"code":"immutable_audit","message":"证据和保管记录不提供删除接口"}})
    def log_message(self, fmt, *args): print(f"{self.address_string()} - {fmt % args}")


class CustodyServer(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,store): self.store=store; super().__init__(address,Handler)


def main():
    parser=argparse.ArgumentParser(description="法律证据保管与流转后台")
    parser.add_argument("--db",default=str(DEFAULT_DB)); parser.add_argument("--port",type=int,default=8105)
    parser.add_argument("--init",action="store_true"); parser.add_argument("--seed",action="store_true")
    args=parser.parse_args(); store=CustodyStore(args.db); store.init_schema()
    if args.seed: store.seed()
    if args.init or args.seed: print(f"数据库已初始化: {args.db}"); return
    server=CustodyServer(("127.0.0.1",args.port),store); print(f"证据保管系统运行于 http://127.0.0.1:{args.port}")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()

if __name__=="__main__": main()
