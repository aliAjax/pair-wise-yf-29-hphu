import base64
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import BusinessError, CustodyStore


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = CustodyStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        self.case = self.store.create_case("custodian1", "CASE-2026-100", "封存基线测试案")
        self.store.add_member("custodian1", self.case["id"], "custodian2", "custodian")
        self.store.add_member("custodian1", self.case["id"], "analyst1", "analyst")
        self.store.add_member("custodian1", self.case["id"], "auditor1", "auditor")
        self.retention = (date.today() + timedelta(days=3650)).isoformat()

    def tearDown(self):
        self.tmp.cleanup()

    def _ingest(self, label="E-001", raw=b"evidence bytes"):
        return self.store.ingest_evidence(
            "custodian1", self.case["id"], label, f"{label}.bin", b64(raw), self.retention, "custodian1"
        )

    def test_seal_captures_chain_tip_and_summary(self):
        item = self._ingest()
        baseline = self.store.seal_baseline("auditor1", self.case["id"], "seal-001")
        self.assertEqual(baseline["id"], 1)
        self.assertEqual(baseline["evidence_count"], 1)
        sealed = baseline["items"][0]
        self.assertEqual(sealed["evidence_id"], item["id"])
        self.assertEqual(sealed["sha256"], item["sha256"])
        # 链尖即入册事件
        self.assertEqual(sealed["chain_tip_sequence"], 1)
        self.assertEqual(sealed["chain_tip_hash"], self._tip(item["id"])[0])

    def test_operations_require_baseline_after_seal(self):
        item = self._ingest()
        self.store.seal_baseline("auditor1", self.case["id"], "seal-001")
        # 未携带基线序号 -> 作废并返回最新基线编号
        with self.assertRaises(BusinessError) as ctx:
            self.store.open_evidence("custodian1", item["id"], "A 区")
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(ctx.exception.code, "baseline_required")
        self.assertEqual(ctx.exception.extra["latest_baseline_id"], 1)
        # 携带基线序号 -> 放行
        opened = self.store.open_evidence("custodian1", item["id"], "A 区", baseline_id=1)
        self.assertEqual(opened["status"], "opened")

    def test_stale_baseline_rejected_with_latest_number(self):
        item = self._ingest()
        self.store.seal_baseline("auditor1", self.case["id"], "seal-001")
        self.store.open_evidence("custodian1", item["id"], "A 区", baseline_id=1)
        # 链尖已变，仍引用旧基线 -> 作废，返回最新基线编号
        with self.assertRaises(BusinessError) as ctx:
            self.store.transfer("custodian2", item["id"], "custodian2", "B 区", baseline_id=1)
        self.assertEqual(ctx.exception.code, "baseline_stale")
        self.assertEqual(ctx.exception.extra["latest_baseline_id"], 1)
        # 重新封存后携带新基线序号 -> 放行
        nb = self.store.seal_baseline("auditor1", self.case["id"], "seal-002")
        self.assertEqual(nb["id"], 2)
        self.store.transfer("custodian2", item["id"], "custodian2", "B 区", baseline_id=2)

    def test_concurrent_seal_only_first_wins_later_gets_conflict(self):
        self._ingest()
        first = self.store.seal_baseline("auditor1", self.case["id"], "seal-A")
        self.assertEqual(first["id"], 1)
        # 几乎同时的另一条封存（不同编号）-> 冲突，拿到先写入的基线编号
        with self.assertRaises(BusinessError) as ctx:
            self.store.seal_baseline("auditor1", self.case["id"], "seal-B")
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(ctx.exception.code, "baseline_conflict")
        self.assertEqual(ctx.exception.extra["latest_baseline_id"], 1)
        listed = self.store.list_baselines("auditor1", self.case["id"])
        self.assertEqual(listed["latest_baseline_id"], 1)
        self.assertEqual(len(listed["baselines"]), 1)

    def test_same_request_no_dedups_and_resumable_items(self):
        self._ingest()
        b1 = self.store.seal_baseline("auditor1", self.case["id"], "seal-001")
        # 同次封存重试 -> 去重，不产生第二条基线
        b1_retry = self.store.seal_baseline("auditor1", self.case["id"], "seal-001")
        self.assertEqual(b1_retry["id"], b1["id"])
        self.assertEqual(len(self.store.list_baselines("auditor1", self.case["id"])["baselines"]), 1)
        # 模拟中途失败：删掉一条封存项，重试只补剩下部分
        with self.store.connect() as conn:
            conn.execute("DELETE FROM baseline_items WHERE baseline_id=?", (b1["id"],))
        self.assertEqual(len(self.store.get_baseline("auditor1", b1["id"])["items"]), 0)
        b1_resume = self.store.seal_baseline("auditor1", self.case["id"], "seal-001")
        self.assertEqual(b1_resume["id"], b1["id"])
        self.assertEqual(len(b1_resume["items"]), 1)
        self.assertEqual(len(self.store.list_baselines("auditor1", self.case["id"])["baselines"]), 1)

    def test_report_marks_events_added_after_baseline(self):
        item = self._ingest()
        self.store.seal_baseline("auditor1", self.case["id"], "seal-001")
        self.store.open_evidence("custodian1", item["id"], "A 区", baseline_id=1)
        report = self.store.report("auditor1", self.case["id"])
        self.assertEqual(report["baseline_count"], 1)
        ev = report["evidence"][0]
        self.assertEqual(ev["baseline_id"], 1)
        self.assertEqual(ev["sealed_chain_tip_sequence"], 1)
        self.assertEqual(ev["events_after_baseline"], 1)
        by_type = {e["event_type"]: e for e in ev["events"]}
        self.assertFalse(by_type["INGEST"]["after_baseline"])
        self.assertTrue(by_type["OPEN"]["after_baseline"])

    def test_upgrade_preserves_history_and_numbers(self):
        item = self._ingest()
        self.store.open_evidence("custodian1", item["id"], "A 区")
        with self.store.connect() as conn:
            before = [dict(r) for r in conn.execute(
                "SELECT id,evidence_id,sequence,event_type,event_hash FROM custody_events ORDER BY id"
            ).fetchall()]
        self.assertEqual(self.store.list_baselines("auditor1", self.case["id"])["baselines"], [])
        result = self.store.upgrade_case_data(self.case["id"])
        self.assertEqual(result["upgraded"], 1)
        with self.store.connect() as conn:
            after = [dict(r) for r in conn.execute(
                "SELECT id,evidence_id,sequence,event_type,event_hash FROM custody_events ORDER BY id"
            ).fetchall()]
        # 历史事件与原编号照旧
        self.assertEqual(before, after)
        report = self.store.report("auditor1", self.case["id"])
        self.assertEqual(report["baseline_count"], 1)
        ev = report["evidence"][0]
        self.assertEqual(ev["baseline_id"], 1)
        # 升级补建基线时链尖未变化，基线后新增事件为 0
        self.assertEqual(ev["events_after_baseline"], 0)
        # 再次升级幂等
        self.assertEqual(self.store.upgrade_case_data(self.case["id"])["upgraded"], 0)

    def test_full_sealed_custody_flow_with_reseal(self):
        item = self._ingest()
        self.store.seal_baseline("auditor1", self.case["id"], "seal-001")
        self.store.open_evidence("custodian1", item["id"], "A 区", baseline_id=1)
        self.store.seal_baseline("auditor1", self.case["id"], "seal-002")
        child = self.store.derive(
            "analyst1", item["id"], "CSV 提取交易记录", "E-001-D1", "transactions.json",
            b64(b'[{"amount": 100}]'), baseline_id=2,
        )
        # 重新封存后，子证据也进入基线
        b3 = self.store.seal_baseline("auditor1", self.case["id"], "seal-003")
        sealed_ids = {it["evidence_id"] for it in b3["items"]}
        self.assertIn(item["id"], sealed_ids)
        self.assertIn(child["id"], sealed_ids)
        self.store.transfer("custodian2", item["id"], "custodian2", "法院证物库", baseline_id=3)
        self.store.seal_baseline("auditor1", self.case["id"], "seal-004")
        self.store.release("custodian2", item["id"], "检察机关", "按调取令释放", baseline_id=4)
        report = self.store.report("auditor1", self.case["id"])
        self.assertTrue(report["overall_integrity_valid"])
        self.assertEqual(report["baseline_count"], 4)
        original = next(x for x in report["evidence"] if x["id"] == item["id"])
        self.assertEqual(original["status"], "released")
        self.assertTrue(original["chain_valid"])

    def _tip(self, evidence_id):
        with self.store.connect() as conn:
            return self.store._current_tip(conn, evidence_id)


if __name__ == "__main__":
    unittest.main()
