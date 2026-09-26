# 实训学时合规与冻结服务

该服务汇聚学员签到、导师确认和请假修正事件，按培养方案与时区重放学时状态，并保存可追溯的学期冻结快照。项目还提供导师分配、证明材料、豁免复核、规则版本、名额、通知和数据留存等领域模块，供后续业务扩展时复用统一的状态与审计约束。

## 运行方式

默认数据保存在项目目录的 SQLite 文件中。安装依赖后执行 `uvicorn app.main:app --host 127.0.0.1 --port 8000`，健康检查地址为 `/health`，业务接口位于 `/api`。

## 测试

```bash
python3 -m pytest -q
```

## 编译检查

```bash
python3 -m compileall -q app tests
```

测试覆盖事件幂等导入、跨时区与跨日学时合并、实习确认、负向修正、冻结快照和差异查询；运行过程中不需要单独的数据库或网络服务。

## 证据内容指纹

导师确认附带的证明文件以内容寻址方式登记，接口位于 `/api/cases/{case_id}/evidence`：

| 操作 | 接口 |
| --- | --- |
| 登记（自动 SHA-256 指纹、blob 全局去重） | `POST /api/cases/{case_id}/evidence/{ref}/register` |
| 固定到确认事件（不可变、并发唯一） | `POST /api/cases/{case_id}/evidence/{ref}/bindings` |
| 查询确认时固定的版本 | `GET /api/cases/{case_id}/evidence/{ref}/bindings` |
| 案件内授权 | `POST /api/cases/{case_id}/evidence/{ref}/grants` |
| 撤销单个授权 | `POST /api/cases/{case_id}/evidence/{ref}/grants/{grantee}/revoke` |
| 删除请求（只软撤销访问） | `POST /api/cases/{case_id}/evidence/{ref}/revoke` |
| 读取内容（上传人或本案件有效授权） | `POST /api/cases/{case_id}/evidence/{ref}/access` |
| 完整性校验（blob 指纹/绑定版本/审计哈希链） | `POST /api/evidence/integrity/verify` |
| 孤立对象清理 | `POST /api/evidence/integrity/cleanup-orphans` |
| 对象跨案件引用视图 | `GET /api/evidence/objects/{sha256}` |

关键约束：

- 同一证据引用不可被不同内容覆盖，替换内容必须用新引用登记，确认事件固定的永远是当时的版本；
- 删除请求只把本案件链接置为 `revoked`，blob、指纹、历史绑定与哈希链审计一律保留；
- 相同内容跨案件复用同一个 blob，但链接、授权与撤销各自独立、互不影响；
- 清理只删除没有任何案件链接（含已撤销）且没有任何历史绑定的 blob，固定过版本的对象永不清除。
