# 从手工 OAuth 客户端迁移到自动发现

本文是运行者的迁移步骤，不是执行记录。本轮文档和代码不表示生产已应用 migration 0015、启用自动注册或完成真实宿主登录。普通用户接入请读 [MCP OAuth setup](mcp-oauth-setup.md)；安全与规范依据见 [客户端发现设计](design/0017-oauth-client-discovery.md)。

## 新版配置契约

新版 native CLI 和 Worker **拒绝仍含 `WAYPOST_OAUTH_CLIENTS` 或 `WAYPOST_OAUTH_CLIENTS_FILE` 的运行配置**，不会静默导入、忽略或把旧列表当运行时授权依据。不要先删除旧配置再考虑数据迁移。

新部署必须在账号/OIDC 配置就绪后显式设置 `WAYPOST_OAUTH_CLIENT_DISCOVERY`。示例为非秘密配置：

```json
{"dynamic_registration":true,"max_clients":1000,"registrations_per_minute":30,"cimd_cache_seconds":3600}
```

- Worker 使用通用 DCR，metadata 提供 `/oauth/register`，不声明 CIMD；普通 Worker fetch 未提供本实现需要的 DNS/IP pinning。
- Native 可在安全 metadata fetcher 可用时声明 CIMD；有 HTTP/HTTPS/ALL proxy 环境变量时不启用该能力，不绕过代理。DCR 仍可用。
- 注册只创建公共客户端 metadata，不建立账号/Space权限；用户仍需网页登录、选择自己的 Space 并明确同意连接。
- 未设置 discovery 配置不代表自动开启；DCR使用安全整数 `9007199254740991` 保存长期 `valid_until`，不是token寿命。注册/CIMD写入事务可清理超过24小时的DCR或缓存已过期的CIMD，但只限未禁用、无任何family、无未过期pending/approved请求且非本次刷新的记录。legacy与历史request保留。总量限制和清理不是完整公开注册运营方案，近期注册或受保护引用仍可耗尽额度。
- Google Web client 的 OIDC secret 是人类登录凭据，与上述公共 MCP 客户端注册无关，不能复制到 DCR 或导入文件。

## 先保存可恢复状态

执行真实部署前，确认目标 Worker、D1、构建版本和变更窗口，并获得该生产操作的授权。保存：

1. 旧 Worker/原生程序的精确版本及构建产物。
2. 旧运行配置的私密备份，包括 OIDC、独立 cursor/CSRF 密钥和旧 OAuth 公共客户端列表。不要把任何 secret 或配置值打印到报告、日志或聊天。
3. 可实际恢复的 D1/SQLite 备份及迁移记录；在隔离副本核对完整性和恢复步骤。不要为了迁移 client metadata 改动 R2 内容或重建 Space。
4. 现有 `oauth_requests`、`oauth_families`、连接与撤销记录的数量/状态基线。即使当前没有活动 OAuth 授权，也核对旧客户端列表，不凭历史报告跳过检查。

先使用数据库副本演练下面所有步骤；不要把本指南中的示例路径替换成生产数据库后直接运行。

## 应用 additive migration 0015

`migrations/0015_oauth_client_registry.sql` 新增：

- `oauth_dynamic_clients`：公共 metadata、来源、revision、有效期、禁用状态与 `allow_loopback_port_variation`。
- `oauth_client_budget`：注册预算状态。
- `oauth_requests.client_revision`、`oauth_families.client_revision`，默认值均为 0。

不删除旧表、历史消息、身份或连接。旧 requests/families 的 client ID 和关联数据保持原值。Native 打开数据库时会自动应用已注册迁移，因此不要用新版程序随意打开生产目录做“只读检查”。D1 通过既有受控迁移流程应用并核对迁移账本，不能只执行 SQL 而漏记 migration。

在隔离的 schema-14 副本上验证新增列默认 0、原有行数与关键内容不变、`PRAGMA foreign_key_check` 无异常。完成后再安排维护窗口，在真实目标上应用同样过程。

## 离线导入旧公共客户端

将原 `WAYPOST_OAUTH_CLIENTS` JSON 或 `WAYPOST_OAUTH_CLIENTS_FILE` 指向的公共 metadata 保存为私密工作目录内的 `legacy-oauth-clients.json`。保留原 `client_id`、`name`、`redirect_uris` 和 `allow_loopback_port_variation`，不重新生成 client ID，不加密码或 client secret。

从仓库根目录生成 SQL，命令只读本地输入并写输出，不访问服务：

```sh
umask 077
python3 scripts/import_legacy_oauth_clients.py /ABS/private/legacy-oauth-clients.json \
  --created-at-ms APPROVED_MIGRATION_UNIX_MILLISECONDS \
  > /ABS/private/import-legacy-oauth-clients.sql
```

将时间占位符替换为该迁移记录的毫秒时间整数。只有脚本退出码为 0，才审查输出。输入允许 1–32 个旧 client；空列表或没有旧配置的部署不必生成导入 SQL，但需明确记录核查结果。

脚本生成 `INSERT ... ON CONFLICT(client_id) DO NOTHING`：

- 来源为 `legacy`，revision 为 **0**，与旧授权新增列的默认值一致。
- client ID、redirect 列表和原 loopback 端口变化布尔值保留。
- 重跑不覆盖已有记录，不更新 redirect，不恢复 disabled client，也不把 DCR/CIMD client 改成 legacy。
- “SQL 执行成功”不代表冲突项已导入。冲突被跳过，必须逐项核对；不要为了让计数匹配删除、覆盖或重新启用现有记录。

先将 SQL 应用于隔离副本，再按已批准的 D1/SQLite变更流程应用真实目标。导入结果应至少核对：

```sql
SELECT client_id, source, revision, disabled, valid_until,
       allow_loopback_port_variation, metadata_json
FROM oauth_dynamic_clients
WHERE source = 'legacy'
ORDER BY client_id;
```

将每个旧 ID 与 registry 的**实际同 ID 记录**比较，不只查询 legacy 总数；任何 missing、source/revision/disabled 或 redirect/loopback policy 冲突都先停止切换并调查。输出仅在受控管理终端核对；不要将用户或设备信息复制到公开报告。

## 切换运行时

在迁移和导入核对通过后，准备同一次受控版本切换的配置：

1. 从**新版本的有效运行配置**移除 `WAYPOST_OAUTH_CLIENTS` 与 `WAYPOST_OAUTH_CLIENTS_FILE`；备份中的旧配置继续保留。
2. 添加明确的 `WAYPOST_OAUTH_CLIENT_DISCOVERY` JSON。保留现有 OIDC、密钥、Space、Actor、Consumer、路由和 bridge 配置，不借此创建新生产凭据。
3. 部署匹配 schema 0015 的新版本，再解除维护。避免在正常流量下先改旧版本环境造成中间状态。
4. 核对 `/health`、受控 readiness、实际版本、AS/Protected Resource metadata。Worker必须不声明 CIMD；DCR endpoint和S256、issuer、resource声明应与配置一致。
5. 使用可回收的验收连接分别测试旧 legacy client（若存在）、无预设 client ID 的自动注册、明确同意、code/token、MCP调用、refresh和撤销。不能用“授权URL打开”代替端到端结果。

旧原生构建、旧 Worker 配置和导入文件在验收完成前保留。OAuth 客户端自动发现与邀请制退役、operator退役、Google登录配置是不同变更，不应在这次切换中未经单独核对一起开启。

## 动态客户端 metadata 的清理与恢复边界

当前 `unreferenced_client_cleanup(now, keep_id)` 在DCR注册或CIMD写入/刷新事务中执行，不是后台cron。实际SQL要求以下条件全部满足：

- `disabled=0`；
- `source=dcr`且创建超过24小时，或`source=cimd`且`valid_until<=now`；
- 没有任何 `oauth_families` 引用，包括已过期或已撤销的family；
- 没有尚未过期的 `pending`/`approved` OAuth request；
- client ID不是当前CIMD刷新的 `keep_id`。

legacy、disabled、存在任何family、有效pending/approved请求及正在刷新中的client不会删除。过期/denied/consumed请求不阻止符合其他条件的metadata清理，**历史request行本身不删除**。最终SQL仍检查client存在、revision及请求状态/有效期，不能通过重新发现或注册恢复旧失效请求。

删除的是可重新注册/发现的公共metadata，不是Space、消息、连接token或已有family。旧DCR ID不重用，客户端需重新DCR注册；不能通过导入伪造原DCR身份。CIMD是URL身份，可重新安全发现，但必须重新验证文档及新授权条件。具体宿主如何处理 `invalid_client` 仍需验收，不假设所有宿主都会无提示恢复。

迁移前的恢复副本仍有价值，但不能为恢复一条已清理metadata而将生产全库恢复到旧快照、覆盖新写入。清理仍不能保证额度不被耗尽：近期DCR、有效pending请求以及任何family引用会保留记录。生命周期管理需独立审查，不应临时扩大删除条件或删除活跃授权来解锁容量。

## 回滚与失败恢复

Migration 0015 是 additive；通常无需删除新表或新增列即可恢复旧程序，但必须先在隔离副本验证具体回滚版本。保留新期间产生的数据，不执行盲目的 down migration 或恢复旧全库快照覆盖新写入。

回滚时：

- 恢复核对过的旧程序/Worker版本及**该版本需要的旧 OAuth 配置**。旧 `WAYPOST_OAUTH_CLIENTS`/FILE 只用于旧版本；新版本存在这些设置会拒绝运行。
- 旧程序不认识新动态 client。新 DCR/CIMD 授权可能暂不可用，不能承诺回滚后所有新连接继续工作；保留 registry、requests、families和撤销状态以供前向恢复。
- 切回新版前再次移除旧运行变量、启用 discovery，并复核 registry/授权状态。导入可以幂等重放，但不应覆盖冲突或撤销记录。
- 导入/部署结果未知时先查数据库和实际部署版本；不要直接重复不确定的外部操作。

部署记录应分别列出：迁移/导入核验、实际运行版本、旧配置保管位置、真实客户端验收、尚未验证项和回滚影响。本指南没有执行上述生产步骤。
