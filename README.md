# 法律证据保管与流转后台

仅使用 Python 3.11+ 标准库实现的证据保管项目。支持真实 SHA-256 入册、封存/开箱/移交、分析衍生关系、案件成员权限、法律保留、保留期限、不可变保管事件链和 JSON 报告导出，并提供案件级**封存基线**（链尖快照 + 乐观并发控制）。

## 运行

```bash
python3 app.py --init --seed
python3 app.py
```

访问 <http://127.0.0.1:8105>，默认数据库 `custody.db`。测试：

```bash
python3 -m unittest -v
```

演示身份：`custodian1`、`custodian2`、`analyst1`、`auditor1`、`outsider`。请求使用 `X-User-Id`。

## 主要接口

- `POST /api/cases`：创建案件，创建人自动成为保管员。
- `POST /api/cases/{id}/members`：授予 custodian、analyst 或 auditor 角色。
- `POST /api/cases/{id}/evidence`：以 Base64 入册证据，服务端计算 SHA-256 和大小。
- `GET /api/evidence/{id}`：查看元数据、完整保管事件链、完整性结果和衍生关系。
- `POST /api/evidence/{id}/open`：保管员开箱。
- `POST /api/evidence/{id}/transfer`：移交保管人并记录位置。
- `POST /api/evidence/{id}/derive`：分析员从已开箱证据创建衍生证据。
- `POST /api/cases/{id}/hold`：审计员或案件创建人设置/解除法律保留。
- `POST /api/evidence/{id}/release`：存在法律保留时拒绝释放。
- `GET /api/cases/{id}/report`：校验所有证据哈希和每条事件链，导出完整报告。
- 所有 `DELETE` 请求返回 405；证据和保管记录不提供删除接口。

## 封存基线

审计员把案件内全部证据的**链尖**（最后一条事件哈希与序号）和**摘要**（标签、文件名、SHA-256、大小、状态、保管人、法律保留、保留期限）封成带序号的基线，用于澄清"封存后是否有人补记"：

- `POST /api/cases/{id}/seal`：仅审计员。可选 `baseline_no`（所依据的最新编号）、`evidence_ids`（本次提交批次，编号自动去重）、`note`。
  - 首次封存得到 1 号基线；之后每次链尖变化后再封存序号递增。
  - 两名审计员几乎同时封存时只认先写入的一条：后到者收到 `409 baseline_conflict`，错误体带 `latest_baseline_no`。
  - 同次封存/同批事件按编号去重，完全重复的提交返回 `result: "dedup"`，不会产生第二条基线。
  - 上次封存中途失败留下不完整基线（`complete:false`）时，重试只补剩余条目，沿用原编号。
- 开箱 `open`、移交 `transfer`、派生 `derive`、释放 `release` 请求必须带 `baseline_no`，且它必须是最新基线并覆盖该证据、链尖未变：
  - 未封存返回 `409 baseline_required`；编号过期返回 `409 baseline_stale`；证据不在基线内返回 `409 baseline_incomplete`；封存后链尖被补记/改动返回 `409 baseline_tip_changed`。所有冲突错误体都带 `latest_baseline_no`，客户端应重新封存后重试。
  - 成功写入的事件记录其依据的基线序号（`custody_events.baseline_no`）。
- `GET /api/cases/{id}/baselines`：列出全部基线及其条目。
- 报告新增 `latest_baseline_no`、`baselines`、`baseline_grouping`（证据按首次封存的基线归集，未封存的列在 `unsealed`）；每条证据带 `sealed_in_baseline_no`、`tip_changed_since_latest_baseline`，每条事件带 `after_latest_baseline`/`pre_baseline_event` 标记。
- 旧库升级：启动时自动迁移，给已有证据的案件补封 1 号基线（`system-migration` 执行），历史事件和证据原编号保持不变，历史事件的 `baseline_no` 留空（视为基线前事件）。

保管事件通过前一条事件哈希串联；报告会重新计算文件哈希和事件链。项目适合流程与完整性原型，不涵盖现实中的签名证书、WORM 存储、证据文件加密或司法辖区合规认证。
