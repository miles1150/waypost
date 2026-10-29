# 个人账号、插件与 OAuth：本地交接

> 历史交接记录：下文静态 `WAYPOST_OAUTH_CLIENTS` 和手工 callback 注册描述旧版本实验，不是当前接入主路径。新版拒绝旧客户端运行变量，需先按[OAuth 客户端迁移指南](../oauth-client-migration.md)导入 registry 并核对，再启用 discovery。本文中的测试与未部署结论仅属于当时版本，不代表本轮自动注册已验收。

本轮交接基于 `30935b6`，分支 `feature/personal-accounts`；功能提交链为 `339b3f5` → `c1b1930` → `9d79df7` → `30935b6`，对比基线为 `e8b7278`。后续交接提交仅补文档和迁移回归断言。没有推送、创建 PR、合并、部署、生产迁移或真实凭据配置。本轮没有删除资源，也没有重新查询生产，因此不能将历史部署记录当作当前生产状态。

## 变更与边界

- 账号：固定 OIDC 提供方、固定验证公钥、浏览器会话、既有 Space 认领/解绑/恢复、身份创建和自定义设备配对。默认不启用；邀请和旧凭据保留。
- OAuth：预注册公共客户端、发现、S256 授权码、标准设备授权、固定 resource、刷新轮换、重放撤销和撤销接口；最终写入复核账号及 Space 权限。原自定义设备协议独立保留。
- 安全修复：HTTPS 账号/登录/OAuth/管理 Cookie 使用 `__Host-`，旧浏览器会话需重新登录；设备轮询竞态修复；Cloudflare OAuth 限流错误保持协议格式。
- 客户端兼容：明确登记的 localhost 回调；字面 loopback IP 的端口变化可按客户端显式启用；相同重复 resource 合并，冲突目标仍拒绝。
- 本地插件仍是 Python stdio 转发及自定义配对原型，没有因 OAuth 实现而自动变成已安装的 Codex/Claude 插件。唤醒、桥、消费幂等与账号授权分开；原并发重复处理问题未修复。

详细实现见 [账号](0009-personal-accounts.md)、[OAuth](0010-mcp-oauth.md)、[独立安全审查](0011-account-oauth-security-review.md)、[客户端互操作](0012-native-oauth-compatibility.md)。

## 提交内容审计

对 `e8b7278..30935b6` 的 53 个变更文件做了路径检查、定向凭据模式扫描及夹具用途核对。未发现真实服务密钥、运行时 token、测试数据库、`.dev.vars`、本地账号配置、CLI 登录存储、日志、Wasm/二进制包或 `var/` 验收产物被纳入 Git。此结论是限定范围的审计，不是扫描器对所有秘密形式的保证。

不能声称“没有测试数据或生成文件”：以下是有意提交并保留的例外。

| 文件 | 用途与边界 |
|---|---|
| `tests/fixtures/oidc-test-private.pem` | 公开合成 RSA 测试私钥，供测试签名；不是 IdP/生产密钥。引用位于 Rust 测试模块或集成测试。绝不能将对应公钥配置进真实服务。SHA-256：`fc19d4b5a1b22d458c77e9135ee833aa8c46d66c679ae83ad2b3711cc192b4fb`。 |
| `tests/fixtures/account-preview-seed.sql` | 明确标注 local-only 的合成账号、Space、Actor、Consumer 和会话。仅供隔离验收，不能用于部署或迁移。 |
| `website/rfc/hosting/index.html`、`website/rfc/source/deployment.md` | 仓库原本跟踪的生成文档，随 `docs/deployment.md` 同步。重新生成无额外差异；并非编译产物。 |

测试源码还包含合成字符串和示例配置，这是回归输入，不是真实用户数据。未删掉这些必要夹具或改写既有提交历史。本地审计报告、测试日志和补丁放在被忽略的 `var/` 下，不属于交付源码。

## 迁移与回滚

当前运行时代码即使不启用账号，也要求 schema 14。不能只应用 0013 就部署当前分支。

1. 先确认目标服务、当前代码版本及 D1 迁移台账。对真实 D1 和 R2 做受控备份并在隔离环境恢复验证，明确备份时间边界和期间写入处理办法。不要把本地合成夹具当恢复证据。
2. 在约定维护/回退窗口按序应用 `0013_personal_accounts.sql`、`0014_mcp_oauth.sql`。两者新增表/索引；0014 另外给 tokens 增加默认 `legacy` 的 `credential_kind`。保留原 Space、Actor、Consumer、消息和旧凭据，不做数据清理。
3. Worker 必须显式应用 D1 迁移；原生启动会自动迁移，所以旧数据目录不能在无备份的情况下用于试跑。先在隔离副本演练。
4. 新运行时先不启用 OIDC/OAuth，检查旧 API、凭据和桥。认证 `/ready` 应报告 schema 14；`/health` 仅证明进程存活。核对实际发布版本与构建提交，再考虑分阶段启用账号。
5. 优先在新运行时关闭新登录入口来排障。**关闭 OIDC 不撤销已有配对 token；移除 OAuth 客户端配置只是暂停，重新加入可恢复尚未撤销的 family。** 永久取消需显式撤销或解绑。
6. 若必须切回不检查账号/OAuth 权限的旧二进制，先停止相关写入/签发，在一个受支持的事务或 D1 batch 中执行 [回滚前撤权 SQL](../../scripts/account-rollback-revoke.sql)，并验证 `active_account_tokens=0`。当前脚本要求 schema 14；schema 13 独立版本必须使用对应旧脚本。
7. 保留新表、授权历史、审计和消息；没有破坏性 down migration。旧 Bearer 凭据保留，账号/配对/OAuth 凭据重新授权。具体旧构建与升级后数据库的完整回退仍须演练，不因 SQL 测试通过就宣称生产回滚已验收。不要用上线前备份覆盖已经有新消息的数据库。

本轮迁移回归在内存数据库中验证：有历史消息和旧凭据的 schema 12 升到 13/14 后，所有旧列值保留、旧 token 标记为 legacy、外键有效；回滚撤权保留旧凭据并撤销配对及 OAuth token（含缺失映射的 OAuth token）。备份恢复测试只覆盖升级前快照，不覆盖生产升级后数据恢复。

## 实际验收证据

| 层次 | 已确认 | 尚未确认 |
|---|---|---|
| 自动化 | 124 项 Rust、此前安全阶段 23 项 Python/22 项 UI；native/Wasm strict Clippy、Worker release build；本轮又通过迁移测试、文档生成与检查 | 不等于覆盖全部并发调度或安全认证 |
| 本地 Workerd/D1 | OAuth、标准设备授权、官方 MCP SDK 调用/刷新/撤销；并发 code/refresh、revoke/refresh 后权限状态 | 远端 D1 故障/副本/未知提交行为，真实免费额度负载 |
| 真实 Codex CLI 0.163.0 | 隔离 scratch 容器内预注册登录成功；缺失/错误 iss 明确被拒 | 真实 IdP/浏览器登录，Codex 自身刷新、模型/工具执行或插件安装 |
| Claude | 后端固定 localhost 回调的完整 HTTP 合约测试；插件任务提供的客户端行为信息 | 本环境未安装 Claude CLI，未做真实端到端验收 |

原生故障注入另验证了最后一条 SQL 失败回滚、事务成功而响应丢失、跨 await 过期/撤权。独立审查和具体剩余风险见安全审查文件。前轮已撤销本地合成凭据并清理任务专属容器；本轮没有重复进行清理或任何资源删除。

## Codex 实验的精确前提

仅以下隔离实验设置被实测，不是生产注册指令：

- Waypost `PUBLIC_ORIGIN=http://127.0.0.1:8793`；resource `http://127.0.0.1:8793/mcp`；合成账号已拥有并选中测试 Space，批准现有测试 Actor/Consumer。
- 服务端公共客户端 ID 为 `local-mcp-test`，无 client secret，`allow_loopback_port_variation=true`。
- 实验登记了 `http://127.0.0.1:8765/callback`、`http://localhost:8766/callback` 供其他回归，以及 Codex 必需的 `http://127.0.0.1:8765/callback/czLXnHJ5DFMw`。
- CLI 成功请求实际使用 `http://127.0.0.1:33597/callback/czLXnHJ5DFMw`。端口变化由显式选项允许；后缀路径仍精确匹配。其他环境不得照搬此后缀，须先观察本机版本及服务地址所生成的回调，再登记对应路径。
- 服务端 metadata 的 issuer 为上述 origin，issuer-response 声明为 true，回调返回同值 `iss`；CLI 提交 S256 PKCE。
- Codex 使用 `mcp login waypost --no-browser`，在隔离合成账号完成明确批准后粘贴完整回调 URL。实验没有向实际模型发送消息。

CLI 的有效配置形状为：

```toml
# 仅在一次性容器内使用文件存储；真实主机应遵循其安全凭据存储设置。
mcp_oauth_credentials_store = "file"
[mcp_servers.waypost]
url = "http://127.0.0.1:8793/mcp"
oauth_resource = "http://127.0.0.1:8793/mcp"
[mcp_servers.waypost.oauth]
client_id = "local-mcp-test"
```

错误的平级 `oauth_client_id` 被此 CLI 忽略，随后尝试不受支持的动态注册。实验显式配置 resource 后出现两个相同 resource，后端已安全合并。即使声明 issuer 支持，此版本/模式仍使用了后缀路径；不要仅据元数据猜测 `/callback`。

## Claude 固定 localhost 边界

允许显式登记 `http://localhost:8766/callback` 并完成授权和兑换；`localhost`、`127.0.0.1`、`[::1]` 不互为回调别名。localhost 的端口、路径必须完全一致；即使启用 `allow_loopback_port_variation`，也不会放宽 localhost 的端口。若真实 Claude 版本不能固定端口，当前方案仍有兼容缺口，需要单独设计和验证，不能声称已支持。服务端 issuer 本身仍要求 HTTPS（仅隔离开发允许字面 `127.0.0.1` HTTP），允许 localhost 回调不等于允许任意 HTTP 服务地址。

## 生产部署前置条件

- 获得目标明确的推送/合并/部署及真实身份配置授权；此前 GitHub 自动审核拒绝没有被重试或绕过，本轮授权仅限本地。
- 核实生产版本、D1/R2 目标、可恢复备份、维护窗口、回退构建和恢复责任人；在真实隔离 staging 演练迁移与回退。
- 决定可信 OIDC 提供方、回调注册、真实公钥轮换/故障处理、账号准入和恢复方式。signup limit 默认 0，不能靠加载测试账号启动。新账号 Space 的恢复依赖人工核验及既有 operator 流程，尚非完整自助找回产品。
- 单独配置 Worker 的 `WAYPOST_OIDC_CONFIG` secret、受控 `WAYPOST_ACCOUNT_SIGNUP_LIMIT` 和公共注册变量 `WAYPOST_OAUTH_CLIENTS`，不用测试密钥/固定会话。每个客户端按实测登记；不启用 DCR/CIMD，不假设 Claude 已兼容。
- 保留生产限流及管理边界。确认公开 client ID 耗尽全局请求上限的风险、token 元数据保留策略和低频个人使用的实际资源开销。
- 通知 HTTPS 浏览器需重新登录；旧桥和 Bearer 兼容需用现有真实身份做独立、可回收的验收。继续保留邀请，不将本轮直接当作邀请退役或账号管理全功能上线。
- 发布后核验部署版本、`/ready`、发现与 issuer、最小权限、撤销/解绑、旧桥收发，以及真实 IdP 与目标宿主；缺失部分必须保持未验收状态。

## R2 恢复脚本编码修正（交接后补充）

Cloudflare OpenAPI 的 `GET /accounts/{account_id}/r2/buckets/{bucket_name}/objects/{object_key}` 参数说明明确要求 key 中的斜杠原样传输，不得编码为 `%2F`，其他保留字符仍须编码。核对发现 `scripts/verify_cloudflare_restore.py` 下载对象时原先使用 `quote(key, safe='')`，判断属实。

现改为独立 `cf_get_object`，使用 `quote(key, safe='/')`；分页 cursor 的查询参数编码不变。新增 `tests/test_cloudflare_restore_urls.py`，通过拦截实际 urllib Request、完全替代网络 I/O 验证多段/重复/首尾斜杠、空格、Unicode、保留字符、字面 `%2F` 与真实 `/` 的区别，以及 key 无法变成新主机、查询或 fragment。3 项隔离测试、脚本编译和差异格式检查通过。

这是本地请求构造回归，不是 Cloudflare 对象下载或生产恢复验收。本轮只查询公共 API 规范，没有运行恢复脚本主流程、读取生产配置/凭据或访问生产资源。生产备份与恢复仍需按前述授权和演练要求另行执行。

后续本地实现提供了默认关闭的[邀请制受控退役模式](0014-invitation-retirement.md)。它没有在生产启用，也没有删除历史表；生产替代闭环与恢复确认仍是切换前置条件。
