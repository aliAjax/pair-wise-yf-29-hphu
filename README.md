# 法律证据保管与流转后台

仅使用 Python 3.11+ 标准库实现的证据保管项目。支持真实 SHA-256 入册、封存/开箱/移交、分析衍生关系、案件成员权限、法律保留、保留期限、不可变保管事件链和 JSON 报告导出。

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
- `POST /api/evidence/{id}/hold`：审计员或案件创建人设置/解除法律保留。
- `POST /api/evidence/{id}/release`：存在法律保留时拒绝释放。
- `POST /api/cases/{id}/baselines`：审计员封存全部证据的链尖与摘要为带序号基线（请求体带 `request_no` 幂等编号）。
- `GET /api/cases/{id}/baselines`：查看案件的基线列表与最新基线编号。
- `GET /api/baselines/{id}`：查看单条基线及其封存项。
- `GET /api/cases/{id}/report`：校验所有证据哈希和每条事件链，按基线归集证据并标出基线后新增事件，导出完整报告。
- 所有 `DELETE` 请求返回 405；证据和保管记录不提供删除接口。

## 封存基线

长期诉讼中，保管员和分析员几乎同时提交证据事件时，封存后容易说不清有没有人补记。为此审计员可把案件全部证据的**链尖**（最新事件哈希与序号）和**摘要**（SHA-256）封成一条带序号的基线：

- `POST /api/cases/{id}/baselines`（仅审计员）：请求体带 `request_no` 幂等编号。同次封存重试按编号去重，不会出现第二条基线；中途失败后重试只补填缺失的封存项。
- 开箱、移交、派生、释放都在请求体带 `baseline_id`（所依据的基线序号）。封存后的操作若未携带基线序号，返回 `baseline_required` 与最新基线编号。
- 链尖一变（或引用了旧基线）即作废本次写入，返回 `baseline_stale` 与最新基线编号；重新封存后携带新基线序号即可继续。
- 两名审计员几乎同时封存时只认先写入的一条：链尖未变化的后到封存返回 `baseline_conflict` 与先写入的基线编号；链尖已变化则允许重新封存。
- 报告按基线归集证据，`evidence[].baseline_id` 标出归集基线，`events_after_baseline` 与每条事件的 `after_baseline` 标出基线后新增事件。
- 旧数据升级：`python3 app.py --db custody.db --upgrade` 为没有基线的案件补建一条封存基线，历史事件与原编号保持不变；重复执行幂等。

封存基线是乐观并发与流程完整性原型，不涵盖现实中的签名证书、WORM 存储或司法辖区合规认证。
