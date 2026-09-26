# 实训学时合规与冻结服务

该服务汇聚学员签到、导师确认和请假修正事件，按培养方案与时区重放学时状态，并保存可追溯的学期冻结快照。项目还提供导师分配、证明材料、豁免复核、规则版本、名额、通知和数据留存等领域模块，供后续业务扩展时复用统一的状态与审计约束。

## 运行方式

默认数据保存在项目目录的 SQLite 文件中。安装依赖后执行 `uvicorn app.main:app --host 127.0.0.1 --port 8000`，健康检查地址为 `/health`，业务接口位于 `/api`。

## 证据内容寻址

导师确认附带的证明文件按内容指纹（SHA-256）登记，相同内容只保存一份对象；案件与证据之间通过不可变引用关系绑定，确认事件导入时可用 `evidence_hashes` 固定当时的证据版本。删除请求只会撤销访问授权，不会破坏对象与历史指纹；相同内容跨案件复用时，各案件分别维护自己的授权与审计流水。

- `POST /api/evidence/objects` 登记证据（base64 内容，重复上传幂等并累计次数）
- `GET /api/evidence/objects/{content_hash}` 查看对象元数据
- `POST /api/cases/{case_id}/evidence` 绑定证据到案件（并发安全、不可变）
- `GET /api/cases/{case_id}/evidence` 列出案件证据引用
- `POST /api/cases/{case_id}/evidence/{content_hash}/grants` 按案件授权访问
- `POST /api/cases/{case_id}/evidence/{content_hash}/grants/{subject_id}/revoke` 撤销单个授权
- `DELETE /api/cases/{case_id}/evidence/{content_hash}` 删除请求：撤销该案件下全部授权，对象与引用保留
- `GET /api/cases/{case_id}/evidence/{content_hash}/content?subject_id=...` 授权校验后读取内容
- `GET /api/cases/{case_id}/evidence/{content_hash}/history` 查看授权/撤销审计流水
- `POST /api/evidence/integrity` 重算指纹并核对引用关系的完整性检查
- `POST /api/evidence/gc` 清理从未被任何案件引用的孤立对象

## 测试

```bash
python3 -m pytest -q
```

## 编译检查

```bash
python3 -m compileall -q app tests
```

测试覆盖事件幂等导入、跨时区与跨日学时合并、实习确认、负向修正、冻结快照和差异查询，以及证据的重复上传、并发绑定、权限变化和孤立对象清理；运行过程中不需要单独的数据库或网络服务。
