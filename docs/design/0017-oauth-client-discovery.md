# OAuth 客户端发现：CIMD 优先与 DCR 兼容

研究与设计日期：2026-10-29。基线为 `fbfcce6`。本文记录本轮实现目标与规范依据，不构成发布证据；生产发布、配置变更和实际验收另行记录。真实 Codex/Claude 注册登录、远端 CIMD 文档和部署验收必须另外记录，不能从源码或模拟测试推断通过。

## 目标与现有基线

目标是让用户在支持 OAuth 的 MCP 宿主中配置 Waypost URL、网页登录并明确批准连接，无需为每种宿主手工填写 client ID、回调端口或回调后缀。客户端注册只确定软件的公共标识和回调，**不授予账号、Space 或 Actor/Consumer 权限**。人类账号认证、选择空间及连接同意仍由现有流程完成。

基线已实现 OIDC 人类账号、Space 认领、MCP OAuth 授权码/S256、resource 绑定、旋转 refresh family、撤销和提交时权限检查。基线客户端来自 `OAuthConfig.clients` 静态预注册，不支持通用 DCR 或 CIMD。旧的 [native 兼容说明](0012-native-oauth-compatibility.md) 和 [部署交接](0013-local-handoff.md)中的手工注册说明描述该基线，不能当作本轮动态注册已上线的证据。

本轮开发使用统一持久 client registry：通用公共客户端 DCR 负责无需预注册的兼容；有安全出站实现时优先启用 CIMD。保留既有空间、消息、Actor、Consumer、bridge 和现存授权的身份，不因插件品牌重新建模。

## 规范基线与要求等级

实际读取的 MCP 最新版本为 **2026-07-28**。当前 IETF CIMD 最新草案为 **draft-ietf-oauth-client-id-metadata-document-02**（2026-07，尚非 RFC）；MCP 页面仍链接 `-00`。下表区分 MCP 明文要求、最新草案要求和 Waypost 本地安全政策，不把草案后续新增条款冒充已被 MCP 全部采纳。

| 主题 | 要求及来源 |
| --- | --- |
| 注册选择 | MCP 客户端支持所有方式时 **SHOULD** 依次使用已有预注册信息、CIMD、DCR、人工配置。CIMD 为 **SHOULD**；DCR 为 **MAY**，已标为 deprecated compatibility。[Client Registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration) |
| 发现 | 服务端 **MUST** 提供 Protected Resource Metadata，其中至少一个 `authorization_servers`；可通过 401 `WWW-Authenticate: Bearer resource_metadata=...` 或 well-known 暴露。客户端 **MUST** 支持两者并按规定查找。[Discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery) |
| CIMD client ID | 草案 §3：**MUST** HTTPS、有 path；**MUST NOT** userinfo、fragment、单点/双点 path segment；query **SHOULD NOT**。原始字符串精确比较，不折叠默认端口、大小写或 percent encoding。[CIMD -02](https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.txt) |
| CIMD 文档 | MCP 要求合法 JSON，至少 `client_id`、`client_name`、`redirect_uris`；`client_id` **MUST** 与 URL 精确相同。草案禁止 client secret 和私钥材料。首版仅支持公共 `none`，不声称支持 `private_key_jwt`。 |
| CIMD 获取 | 草案 §5：**MUST** 200；其他状态视为错误；**MUST NOT** 自动跟随重定向。获取失败 **SHOULD** 中止授权。 |
| 缓存 | §5.2 **MAY** 缓存，**SHOULD** 遵守 HTTP cache headers；可设置本地寿命界限。**MUST NOT** 缓存错误、畸形或无效文档。 |
| SSRF | §8.6：**MUST NOT** 获取解析至 RFC 6890 special-use IP 的文档或嵌套 URL；生产不得使用 loopback 测试例外。 |
| Redirect | 必须注册并精确匹配；[RFC 8252 §7.3](https://www.rfc-editor.org/rfc/rfc8252.html#section-7.3) 对原生 loopback IP 允许动态端口，scheme/host/path 仍匹配。`localhost` 不等于任意 loopback IP；对 localhost 动态端口的额外兼容必须明示为本地政策。 |
| PKCE | MCP 客户端 **MUST** 使用 PKCE、确认 metadata 声明支持；技术可行时 **MUST** S256。Waypost 继续强制 S256，不提供 plain 降级。[Security](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) |
| Resource | authorization/token 请求 **MUST** 带目标 MCP canonical resource；服务端 **MUST** 检查 token 的目标，不接受其他资源 token 或 upstream token passthrough。[Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)、[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) |
| Issuer | client **MUST** 将已验证 issuer 与本次 PKCE/state 绑定。AS **SHOULD** 在成功和错误回调返回 `iss`；返回时 **MUST** 声明 `authorization_response_iss_parameter_supported:true`。声明 true 却缺失 `iss` 必须拒绝，任何出现的 `iss` 必须与记录值精确相同。[RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)、MCP Authorization |
| AS 换绑 | 预注册和 DCR 信息 **MUST** 按 issuer 隔离；AS 改变不得复用另一个 AS 的注册凭据。CIMD URL 可跨 AS 使用，但不意味着 tokens/consent 可以迁移。 |
| 用户展示 | 授权界面 **MUST** 清楚展示 redirect hostname；localhost-only callback **SHOULD** 有额外提示。客户端名称和图标不是身份认证。 |

## Worker 出站安全与宿主无关的边界

Worker 普通 `fetch` 与一次独立 DNS 查询不是同一个连接操作。即使先通过 DoH 检查公共地址，实际 fetch 仍可能重新解析；不能把该方法称为 DNS pinning 或防重绑定证明。

因此 Worker 默认只提供通用 DCR，不声明 `client_id_metadata_document_supported:true`。DCR 不获取调用方提供的 URL，能让支持 DCR 的 Codex、Claude 及其他宿主自动注册，而不是维护宿主品牌列表。公开注册必须有请求大小、redirect 数量、全局记录上限和速率控制；无 secret 的随机 client ID 不是信任凭据。

CIMD 只有配置可审查的安全 fetch 边界后才能声明支持：

- 原生实现：拒绝非 HTTPS 和含糊 URL；解析所有地址并拒绝 special-use；连接固定到检查过的地址，保留原 hostname 的 TLS/SNI 校验；禁止重定向，限制时间和响应大小。
- Worker 可选择经独立审查的 service-binding 出站服务，完成等价检查；仅添加 trait/mock 并不代表已经部署该能力。本轮不自动创建服务、修改网络或绕过代理。
- 精确受信任 URL/origin 政策可以限制可接受 CIMD，但必须标为受限模式，不能宣传为 arbitrary CIMD；域名白名单本身也不是 DNS pinning。
- 首版不获取 logo、`jwks_uri`、`client_uri` 等嵌套 URL，避免引入第二条未审查出站路径；名称和 URL 以纯文本显示。

当 CIMD 不可用时不冒充可用，也不能假设一个客户端在收到 CIMD 错误后一定自动重试 DCR。选择机制必须通过诚实的 metadata capability 引导。

## 持久 registry、metadata revision 与提交边界

实现应将解析后的 client 记录作为后续授权的公共输入，而非把请求中的 `client_name`、URL 或 `client_id` 当授权。静态导入、DCR 和 CIMD 来源必须可区分，不能互相覆盖同一 ID。

授权 request/code 和 refresh family 固定 client ID 与 revision。最后 SQL 提交再次检查 registry 记录未停用、revision 一致，以及原有 account/Space/Actor/Consumer、resource、scope、expiry、PKCE 和 redirect 条件；不只在打开同意页面时检查一次。实际 code 兑换仍要求发起授权时的完整 redirect URI，包括已选动态端口。

CIMD cache 与注册权威不是一回事：

1. 仅存经过完整验证的文档，按 HTTP `Cache-Control`/`Age` 和本地上限计算有效期；不得用过期 metadata 做网络失败兜底。
2. 过期后发起新授权或兑换需要重新确认 metadata；相同安全字段可延长有效期，不应无故使既有记录换身份。
3. 安全字段（redirect、auth method、grant types、keys 等）变化提升 revision；旧 pending 请求、code 和 refresh family不能无声继承新配置。重新 consent。
4. 展示字段变化也不能伪装旧身份；至少更新纯文本展示，按策略重新要求同意。
5. URL 改变就是新 client ID，禁止自动迁移旧 consent 或 token。域名到期/重新分配的风险不能由 URL 相同消除。

上述 revision 撤权策略是 Waypost 的保守实现政策；CIMD 草案 §8.4允许 AS 自行决定 metadata 改变后的处理，不规定唯一策略。缓存失效、临时网络错误和显式 client 撤销应保留不同状态，避免错误恢复时重新放行已撤销 client。

## 本轮代码接口与 schema 对齐（开发中）

设计核对时，工作区已加入 `src/service/oauth_client_registry.rs`、原生 `src/native/oauth_client_metadata.rs` 及 `migrations/0015_oauth_client_registry.sql`。这些是本轮开发文件，不等于已合并、测试通过或部署。具体接口为：

- `OAuthClientDiscoveryConfig`：`dynamic_registration`、`max_clients`、`registrations_per_minute`、`cimd_cache_seconds`；默认分别为 `true`、`1000`、`30`、`3600`。通过可选 JSON 环境变量 `WAYPOST_OAUTH_CLIENT_DISCOVERY` 显式启用；缺省不自动开启新注册。
- `App::with_oauth_client_discovery(config, fetcher)`：要求账号/OIDC 已配置。`fetcher: Option<Rc<dyn OAuthClientMetadataFetcher>>`；trait `fetch(client_id)` 返回 `OAuthClientMetadataDocument { body, max_age_seconds }`。
- Worker 传入 `None`，因此只能声明 DCR；Native 使用 `NativeClientMetadataFetcher`，但有 HTTP/HTTPS/ALL proxy 环境变量时不挂载 CIMD 能力，不清除或绕过平台代理。trait 存在不等于 Worker 已有安全 egress。
- `POST /oauth/register` 成功返回 201，签发服务端随机公共 `client_id`，不签发 client secret；输入上限 16 KiB、最多 8 个 redirect。只支持公共 `none` 的 code/refresh profile。
- `oauth_dynamic_clients` 列为 `client_id`、`source`（`dcr/cimd/legacy`）、`metadata_json`、`security_fingerprint`、`revision`、`valid_until`、`disabled`、`allow_loopback_port_variation`、`created_at`、`updated_at`。`oauth_client_budget` 保存 `bucket/window_start/used/nonce`。`oauth_requests` 与 `oauth_families` 新增 `client_revision DEFAULT 0`。
- 当前本地 CIMD profile 比草案更严格：只接受 canonical HTTPS 443 URL、非根 path、无 query/userinfo/fragment。这些是实现限制，不是草案禁止所有非443端口的规范要求。未知或不支持的 metadata必须明确拒绝，不能静默降低安全要求。
- DCR记录的 `valid_until` 使用 JavaScript/D1 可精确表示的安全整数 `9007199254740991`，不使用 `i64::MAX`；这不是24小时token寿命。`unreferenced_client_cleanup(now, keep_id)` 在DCR注册或CIMD写入/刷新事务中执行，不是后台cron：仅清理 `disabled=0` 且（DCR创建超过24小时，或CIMD缓存已过期）的记录，并要求没有任何family、没有未过期的 pending/approved request，且不是本次刷新的 `keep_id`。legacy、disabled、任何family引用、有效pending/approved请求和正在刷新的client均保留；历史request本身不删除。只有过期/denied/consumed请求且无family的记录不因这些历史请求而免于清理。清理后的DCR ID需重新注册，不承诺恢复相同ID；被清理CIMD需重新安全发现，旧过期请求不能因相同URL再次出现而恢复有效。限额DoS仍有残余：近期注册、有效请求及任何family引用仍占额度。既有CIMD刷新可在总量上限达到时尝试更新原记录，不以删除当前刷新记录来腾空间。

开发中的 final guard 同时检查动态记录来源是否仍启用、revision、disabled 和 valid_until。新版 native/Worker 已拒绝旧 `WAYPOST_OAUTH_CLIENTS`/FILE 运行配置；旧记录必须显式导入为 legacy revision 0。`App.oauth` 静态授权状态及 final guard 的静态 OR 分支已移除；`import_legacy_oauth_clients` 是显式异步导入 helper，供迁移/测试使用，不由 runtime 自动调用。文档中的后续计划不能代替实际代码完成状态。

## 旧静态注册的迁移顺序

本轮新增离线 `scripts/import_legacy_oauth_clients.py`，由旧公共 JSON 生成导入 SQL；先应用 migration 0015，再导入并逐项核对。来源为 `legacy`、revision **0**，保留原 client ID、redirect 和 `allow_loopback_port_variation`。旧 request/family 新增列默认 0，不改 Space 或连接身份。脚本 `ON CONFLICT DO NOTHING` 不覆盖已有记录，也不恢复 disabled client；冲突必须由运行者核对，而非视为导入成功。

新版 native/Worker 不再加载旧手工客户端环境变量：存在 `WAYPOST_OAUTH_CLIENTS` 或 `WAYPOST_OAUTH_CLIENTS_FILE` 就拒绝配置。核对导入后，才从新版本运行配置移除它们并显式设置 `WAYPOST_OAUTH_CLIENT_DISCOVERY`；保留旧版本配置用于回滚。统一 registry 是最终授权权威；原 `with_oauth` 路径替换为显式异步 `import_legacy_oauth_clients`，内部测试/迁移 helper 不是 runtime 手工配置入口。

完整步骤、旧配置保管、additive D1 迁移和回滚限制见[OAuth 客户端迁移指南](../oauth-client-migration.md)。导入顺序不能倒置，不能为通过校验覆盖动态来源或悄悄扩大旧回调政策。本文件不代表已执行生产迁移，也不声称旧授权兼容测试已完成。

## 指定客户端的实际证据

### Codex 0.162.1

读取了[官方 tag 的 oauth_client_registration.rs](https://github.com/openai/codex/blob/rust-v0.162.1/codex-rs/rmcp-client/src/oauth_client_registration.rs)和[当前官方 MCP 文档](https://developers.openai.com/codex/mcp/)：

- 显式 client ID 优先，跳过自动注册。
- `auto` 在 CIMD 声明为 true、token auth methods 包含 `none`、callback满足支持的 loopback形状时选择 CIMD；否则进入 DCR 路径。
- 有有效 issuer 和 issuer-response 声明时使用 `https://chatgpt.com/oauth/codex/client.json` 和 `/callback`。
- 无 issuer-bound response 时使用 `https://chatgpt.com/oauth/codex/<callback_id>/client.json` 及 `/callback/<callback_id>`。
- 支持单次登录选择 `--oauth-client-registration auto|cimd|dcr`。公共 metadata 文档可能使用无端口 loopback URI，AS须按 native port规则核对，不能要求固定端口。

这是精确版本官方源码证据。已有隔离 CLI callback捕获不能替代本轮自动 CIMD/DCR 的真实验收。

### Claude Code 2.1.296

检查了本地该精确版本包和 bundled binary 中的实际代码字符串，观察到：

- CIMD URL 为 `https://claude.ai/oauth/claude-code-client-metadata`。
- `clientMetadataUrl` getter 仅在 callback匹配文档的 loopback `/callback` 时提供该 URL，否则明确走 DCR。
- SDK分支在 server CIMD flag为 true且 clientMetadataUrl可用时选择 CIMD，否则动态注册。
- DCR metadata包含 client_name、实际 redirect_uris、authorization_code/refresh_token、response code、auth none；该分支未观察到 `application_type`。

最新 MCP要求客户端在 DCR提供合适的 application_type；实际旧客户端可能缺失。Waypost 的 OAuth DCR兼容策略不应仅因缺失而套用 OIDC web默认值并拒绝明确的 loopback callback，但仍须限制协议与回调，不推断额外授权。

Claude官方文档页、两家真实 CIMD JSON在本环境被403/代理403拒绝，未绕过。以上 binary inspection不是开放源代码保证，也不是本轮真实 Claude登录或远端文档内容验收。

## 验收计划与发布门槛

本设计不声称以下测试已完成：

- 未配置 client ID 的两个真实宿主在 CIMD关闭时自动 DCR；metadata开启且安全fetch可用时选择CIMD。
- 注册仅创建软件记录，不能越过用户登录、Space选择或显式同意。
- invalid JSON/client_id、重定向、超大响应、special-use地址、DNS重绑定、超时、过期cache失败关闭。
- metadata变更与 code/refresh并发：旧revision不能提交；静态导入冲突不能覆盖动态记录。
- DCR重复注册、配额、恶意client名称、无效redirect、跨client覆盖、public客户端无secret边界。
- PKCE、resource、issuer负例；AS切换不复用另一个AS的授权信息。
- loopback动态端口可用而host/path仍精确；localhost额外政策单列测试。
- 已填充数据库迁移后，旧revision0授权、撤销、账号归属、消息和bridge保留。
- native/Wasm与本地Workerd/D1回归；真实网页登录、客户端token兑换、MCP调用、刷新、撤销分别留证据。拿到授权URL不等于完整登录成功。

任何真实提供方配置、生产迁移、部署、客户端安装或新增持续访问，仍需对应的明确操作范围；本文件及本轮开发不自动完成这些操作。
