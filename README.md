# 建筑抗震鉴定与加固排序

依据结构、用途、人员密度和历史缺陷生成鉴定与加固优先级。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量；余震预警等级、暂停/重算/双人确认等纯规则。
- `src/repository.py`：SQLite建表、事务、版本控制和审计链；预警、处置、确认和推送批次的存储与原子操作。
- `src/service.py`：权限检查、用例编排、并发控制和审计；预警推送批次、解除确认和风险重算编排。
- `src/http_api.py`：JSON路由和统一错误响应（预警相关入口：`/api/warnings`、`/api/alerts`、`/api/batches`）。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8317
```

默认端口为`8317`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`（支持`?building=`过滤）
- `POST /api/items`（可带`building`）
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `POST /api/items/{id}/risk`，更新风险参数（`severity/quantity/threshold/building`），必须提交`expected_version`
- `GET /api/audit`
- `POST /api/warnings/push`，余震预警/解除消息批次推送
- `POST /api/batches/{id}/retry`，重试批次中失败条目
- `GET /api/batches/{id}`
- `GET /api/alerts`（支持`?building=`过滤）、`GET /api/alerts/{id}`
- `POST /api/alerts/{id}/confirm`，解除消息双人确认

允许角色：assessor, structural_engineer, review_board, viewer。风险分值和人员密度共同影响排序；审核通过前必须完成评估、设计和施工证据登记。

## 余震预警处置规则

- 同一事件（`event_id`）只生成一次结果，重复推送幂等。
- 预警首发时，同楼栋（`building`相同）处于施工状态的在施项目一律先暂停；非在施、其它楼栋项目不受影响。
- 解除消息必须由两名**不同**人员（structural_engineer、review_board）先后确认，第一次确认前项目保持暂停，第二次确认后才恢复。
- 项目风险参数更新后，该项目未完成的恢复立即失效，预警回到活跃态并按新预警重算（等级与风险分值共同决定）；已经复工的处置记录留档，不再重新暂停。
- 并发推送同一事件只保留一份处置（数据库唯一约束 + 事务）。
- 推送按批次执行：单条失败不拖垮整批，批次和失败条目保留，可调用retry重试；成功条目不重复处理。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
