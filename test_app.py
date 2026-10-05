import base64
import sqlite3
import tempfile
import threading
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import BusinessError, CustodyStore

LEGACY_DDL = """
CREATE TABLE users(
    id TEXT PRIMARY KEY, name TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
);
CREATE TABLE cases(
    id INTEGER PRIMARY KEY AUTOINCREMENT, case_number TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL, created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
);
CREATE TABLE case_members(
    case_id INTEGER NOT NULL REFERENCES cases(id), user_id TEXT NOT NULL REFERENCES users(id),
    role TEXT NOT NULL CHECK(role IN ('custodian','analyst','auditor')),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    granted_by TEXT NOT NULL REFERENCES users(id), granted_at TEXT NOT NULL,
    PRIMARY KEY(case_id,user_id)
);
CREATE TABLE evidence(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id), label TEXT NOT NULL,
    filename TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
    content BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'custody'
        CHECK(status IN ('custody','opened','released','derivative')),
    current_custodian TEXT NOT NULL, legal_hold INTEGER NOT NULL DEFAULT 0 CHECK(legal_hold IN (0,1)),
    retention_until TEXT NOT NULL, created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL, UNIQUE(case_id,label)
);
CREATE TABLE custody_events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id), sequence INTEGER NOT NULL,
    event_type TEXT NOT NULL CHECK(event_type IN ('INGEST','TRANSFER','OPEN','ANALYZE','RELEASE','HOLD_SET','HOLD_CLEARED')),
    actor_id TEXT NOT NULL REFERENCES users(id), from_person TEXT,
    to_person TEXT, location TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
    previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL,
    created_at TEXT NOT NULL, UNIQUE(evidence_id,sequence)
);
CREATE TABLE derivatives(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    child_evidence_id INTEGER NOT NULL UNIQUE REFERENCES evidence(id),
    method TEXT NOT NULL, actor_id TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL, UNIQUE(parent_evidence_id,child_evidence_id)
);
CREATE TABLE audit_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id), actor_id TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL
);
"""


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = CustodyStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        self.case = self.store.create_case("custodian1", "CASE-2026-001", "跨境资金调查")
        self.store.add_member("custodian1", self.case["id"], "custodian2", "custodian")
        self.store.add_member("custodian1", self.case["id"], "analyst1", "analyst")
        self.store.add_member("custodian1", self.case["id"], "auditor1", "auditor")
        self.retention = (date.today() + timedelta(days=3650)).isoformat()

    def tearDown(self):
        self.tmp.cleanup()

    def _ingest(self, label="E-001", raw=b"bank statement original bytes", filename="statement.csv"):
        return self.store.ingest_evidence(
            "custodian1", self.case["id"], label, filename,
            base64.b64encode(raw).decode(), self.retention, "custodian1",
        )

    def _seal(self, expected=None, evidence_ids=None, actor="auditor1"):
        return self.store.seal_baseline(actor, self.case["id"], expected, evidence_ids, "阶段封存")

    def test_full_custody_analysis_release_and_integrity_report(self):
        raw = b"bank statement original bytes"
        item = self._ingest()
        self.assertEqual(self._seal()["baseline_no"], 1)
        opened = self.store.open_evidence("custodian1", item["id"], "A 区证物室", "两名人员在场开箱", baseline_no=1)
        self.assertEqual(opened["status"], "opened")
        # 开箱改变链尖：旧编号作废，重新封存得到 2 号基线，派生依据 2 号
        with self.assertRaises(BusinessError) as ctx:
            self.store.open_evidence("custodian1", item["id"], "A 区证物室", baseline_no=1)
        self.assertEqual(ctx.exception.code, "baseline_tip_changed")
        self.assertEqual(ctx.exception.details["latest_baseline_no"], 1)  # 未再封存，最新仍是 1
        self.assertEqual(self._seal(expected=1)["baseline_no"], 2)
        child = self.store.derive(
            "analyst1", item["id"], "CSV 提取交易记录", "E-001-D1", "transactions.json",
            base64.b64encode(b'[{"amount": 100}]').decode(), baseline_no=2,
        )
        # 派生产生新链尖（父证据 ANALYZE + 新子证据），再封 3 号才能移交
        with self.assertRaises(BusinessError) as ctx:
            self.store.transfer("custodian2", item["id"], "custodian2", "法院证物库", "封存后移交", baseline_no=2)
        self.assertEqual(ctx.exception.code, "baseline_tip_changed")
        self.assertEqual(self._seal(expected=2)["baseline_no"], 3)
        self.store.transfer("custodian2", item["id"], "custodian2", "法院证物库", "封存后移交", baseline_no=3)
        # 移交同样改变链尖，封 4 号后释放
        with self.assertRaises(BusinessError) as ctx:
            self.store.release("custodian2", item["id"], "检察机关", "按调取令释放原件", baseline_no=3)
        self.assertEqual(ctx.exception.code, "baseline_tip_changed")
        self.assertEqual(self._seal(expected=3)["baseline_no"], 4)
        self.store.release("custodian2", item["id"], "检察机关", "按调取令释放原件", baseline_no=4)
        report = self.store.report("auditor1", self.case["id"])
        self.assertTrue(report["overall_integrity_valid"])
        self.assertEqual(report["evidence_count"], 2)
        self.assertEqual(report["latest_baseline_no"], 4)
        original = next(x for x in report["evidence"] if x["id"] == item["id"])
        self.assertEqual(original["status"], "released")
        self.assertTrue(original["chain_valid"])
        self.assertEqual(original["sealed_in_baseline_no"], 1)
        self.assertEqual(child["parent_id"], item["id"])
        # 报告按基线归集证据
        self.assertEqual(report["baseline_grouping"]["by_baseline"]["1"], [item["id"]])
        self.assertEqual(report["baseline_grouping"]["by_baseline"]["3"], [child["id"]])
        # RELEASE 事件依据 4 号基线，INGEST 历史事件无基线编号
        seq_events = {e["sequence"]: e for e in original["events"]}
        self.assertEqual(seq_events[1]["baseline_no"], None)
        self.assertEqual(seq_events[max(seq_events)]["baseline_no"], 4)

    def test_permissions_and_legal_hold_block_release(self):
        item = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-002", "raw.bin",
            base64.b64encode(b"evidence").decode(), self.retention,
        )
        self._seal()
        with self.assertRaises(BusinessError) as ctx:
            self.store.get_evidence("outsider", item["id"])
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(BusinessError) as ctx:
            self.store.release("analyst1", item["id"], "外部机构", baseline_no=1)
        self.assertEqual(ctx.exception.status, 403)
        self.store.set_hold("auditor1", item["id"], True, "诉讼保全要求")
        # 保留设置改变了链尖：重新封存后再释放，先撞法律保留
        self._seal(expected=1)
        with self.assertRaises(BusinessError) as ctx:
            self.store.release("custodian1", item["id"], "外部机构", baseline_no=2)
        self.assertEqual(ctx.exception.code, "legal_hold_active")

    def test_baseline_required_before_any_seal(self):
        item = self._ingest()
        with self.assertRaises(BusinessError) as ctx:
            self.store.open_evidence("custodian1", item["id"], "A 区证物室")
        self.assertEqual(ctx.exception.code, "baseline_required")
        self.assertIsNone(ctx.exception.details["latest_baseline_no"])
        # 只有审计员能封存
        with self.assertRaises(BusinessError) as ctx:
            self.store.seal_baseline("custodian1", self.case["id"])
        self.assertEqual(ctx.exception.status, 403)

    def test_concurrent_first_seals_only_one_wins(self):
        self._ingest()
        barrier = threading.Barrier(2)
        outcomes = []

        def seal():
            barrier.wait()
            try:
                outcomes.append(("ok", self.store.seal_baseline("auditor1", self.case["id"])))
            except BusinessError as exc:
                outcomes.append(("conflict", exc))

        threads = [threading.Thread(target=seal) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        oks = [o for o in outcomes if o[0] == "ok"]
        conflicts = [o for o in outcomes if o[0] == "conflict"]
        self.assertEqual(len(oks), 1)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(oks[0][1]["baseline_no"], 1)
        self.assertEqual(conflicts[0][1].code, "baseline_conflict")
        self.assertEqual(conflicts[0][1].details["latest_baseline_no"], 1)
        # 只产生一条基线
        self.assertEqual(len(self.store.list_baselines("auditor1", self.case["id"])["baselines"]), 1)

    def test_concurrent_reseal_latecomer_gets_conflict_number(self):
        item = self._ingest()
        self.assertEqual(self._seal()["baseline_no"], 1)
        self.store.open_evidence("custodian1", item["id"], "A 区证物室", baseline_no=1)
        barrier = threading.Barrier(2)
        outcomes = []

        def reseal():
            barrier.wait()
            try:
                outcomes.append(("ok", self.store.seal_baseline("auditor1", self.case["id"], 1)))
            except BusinessError as exc:
                outcomes.append(("conflict", exc))

        threads = [threading.Thread(target=reseal) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        oks = [o for o in outcomes if o[0] == "ok"]
        conflicts = [o for o in outcomes if o[0] == "conflict"]
        self.assertEqual(len(oks), 1)
        self.assertEqual(oks[0][1]["baseline_no"], 2)
        self.assertEqual(conflicts[0][1].details["latest_baseline_no"], 2)

    def test_duplicate_seal_and_duplicate_batch_ids_are_deduped(self):
        item = self._ingest()
        first = self._seal(evidence_ids=[item["id"], item["id"]])  # 同批重复编号
        self.assertEqual(first["baseline_no"], 1)
        self.assertEqual(first["evidence_ids"], [item["id"]])
        again = self._seal(expected=1, evidence_ids=[item["id"]])
        self.assertEqual(again["result"], "dedup")
        self.assertEqual(again["baseline_no"], 1)
        baselines = self.store.list_baselines("auditor1", self.case["id"])["baselines"]
        self.assertEqual(len(baselines), 1)  # 没有第二条基线
        self.assertEqual(len(baselines[0]["entries"]), 1)

    def test_failed_partial_seal_retry_only_fills_remaining(self):
        a = self._ingest("E-A", b"aaa", "a.bin")
        b = self._ingest("E-B", b"bbb", "b.bin")
        # 只提交一部分证据：基线不完整
        partial = self._seal(evidence_ids=[a["id"]])
        self.assertEqual(partial["baseline_no"], 1)
        listing = self.store.list_baselines("auditor1", self.case["id"])
        self.assertFalse(listing["baselines"][0]["complete"])
        # 未覆盖证据的写入被守卫挡住
        with self.assertRaises(BusinessError) as ctx:
            self.store.transfer("custodian1", b["id"], "custodian2", "B 库", baseline_no=1)
        self.assertEqual(ctx.exception.code, "baseline_incomplete")
        # 重试补齐：仍然是 1 号基线，没有新增
        retry = self._seal(evidence_ids=[b["id"]])
        self.assertEqual(retry["result"], "completed")
        self.assertEqual(retry["baseline_no"], 1)
        listing = self.store.list_baselines("auditor1", self.case["id"])
        self.assertTrue(listing["baselines"][0]["complete"])
        self.assertEqual(len(listing["baselines"]), 1)

    def test_report_marks_events_added_after_baseline(self):
        item = self._ingest()
        self._seal()
        self.store.open_evidence("custodian1", item["id"], "A 区证物室", baseline_no=1)
        report = self.store.report("auditor1", self.case["id"])
        original = next(x for x in report["evidence"] if x["id"] == item["id"])
        self.assertTrue(original["tip_changed_since_latest_baseline"])
        ingest, opened_event = original["events"]
        self.assertFalse(ingest["after_latest_baseline"])
        self.assertTrue(ingest["pre_baseline_event"])
        self.assertTrue(opened_event["after_latest_baseline"])
        self.assertEqual(opened_event["baseline_no"], 1)

    def test_legacy_database_is_upgraded_with_baseline_but_history_untouched(self):
        db_path = Path(self.tmp.name) / "legacy.db"
        raw = b"legacy evidence bytes"
        digest = __import__("hashlib").sha256(raw).hexdigest()
        created = "2025-01-02T03:04:05+00:00"
        with sqlite3.connect(db_path) as conn:
            conn.executescript(LEGACY_DDL)
            conn.execute("INSERT INTO users(id,name) VALUES(?,?)", ("custodian1", "证据保管员甲"))
            conn.execute("INSERT INTO users(id,name) VALUES(?,?)", ("auditor1", "案件审计员"))
            conn.execute(
                "INSERT INTO cases(id,case_number,title,created_by,created_at) VALUES(1,?, ?,?,?)",
                ("CASE-OLD-1", "旧案", "custodian1", created),
            )
            conn.execute(
                "INSERT INTO case_members(case_id,user_id,role,granted_by,granted_at) VALUES(1,?,'custodian',?,?)",
                ("custodian1", "custodian1", created),
            )
            conn.execute(
                "INSERT INTO case_members(case_id,user_id,role,granted_by,granted_at) VALUES(1,?,'auditor',?,?)",
                ("auditor1", "custodian1", created),
            )
            conn.execute(
                """INSERT INTO evidence(id,case_id,label,filename,sha256,size,content,status,current_custodian,legal_hold,retention_until,created_by,created_at)
                   VALUES(1,1,'OLD-1','old.bin',?,?,?,'custody','custodian1',0,'2099-01-01','custodian1',?)""",
                (digest, len(raw), raw, created),
            )
            payload = {
                "evidence_id": 1, "sequence": 1, "event_type": "INGEST", "actor_id": "custodian1",
                "from_person": None, "to_person": "custodian1", "location": "",
                "note": f"入册 SHA-256 {digest}", "previous_hash": "GENESIS", "created_at": created,
            }
            event_hash = CustodyStore._event_hash(payload)
            conn.execute(
                """INSERT INTO custody_events(id,evidence_id,sequence,event_type,actor_id,from_person,to_person,location,note,previous_hash,event_hash,created_at)
                   VALUES(1,1,1,'INGEST','custodian1',NULL,'custodian1','',?, 'GENESIS',?,?)""",
                (payload["note"], event_hash, created),
            )
            old_hash = event_hash

        store = CustodyStore(db_path)
        store.init_schema()  # 触发升级迁移
        listing = store.list_baselines("auditor1", 1)
        self.assertEqual(listing["latest_baseline_no"], 1)
        self.assertEqual(listing["baselines"][0]["actor_id"], "system-migration")
        self.assertEqual(listing["baselines"][0]["entries"][0]["tip_event_hash"], old_hash)
        report = store.report("auditor1", 1)
        self.assertTrue(report["overall_integrity_valid"])
        item = report["evidence"][0]
        self.assertEqual(item["id"], 1)  # 原编号不变
        self.assertEqual(item["sealed_in_baseline_no"], 1)
        self.assertTrue(item["events"][0]["pre_baseline_event"])
        self.assertIsNone(item["events"][0]["baseline_no"])
        # 升级后即可用 1 号基线继续流转
        opened = store.open_evidence("custodian1", 1, "旧库证物室", baseline_no=1)
        self.assertEqual(opened["status"], "opened")


if __name__ == "__main__":
    unittest.main()
