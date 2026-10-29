# 网关抽取、CIMD/DCR 与密钥产品

本轮在 `fbfcce6` 之上做三件事：把 MCP 协议层抽成不认识具体工具的网关；OAuth 授权服务器补上 Client ID Metadata Document（CIMD）和动态注册（DCR）；在同一套网关与 OAuth 上增加第二个产品：个人密钥库（keyenv-remote，计划部署在 `https://keys.miles1150.top/mcp`）。Waypost 的工具、Space/Actor/Consumer、邀请和记忆模型不变。方案评审见 personal-plugins 的 `docs/research/agent-secrets-review.md`。

## 结构

```text
src/gateway/mcp.rs            无会话 HTTP MCP：Origin、POST、协议版本、JSON-RPC、202、
                              tools/list、tools/call 信封；ToolCatalog 由调用方注入
src/gateway/oauth_client.rs   CIMD/DCR 的纯校验：URL 与主机策略、文档校验、回调匹配、
                              缓存时长、注册元数据；按运行时实现的受限拉取
src/gateway/cloudflare.rs     D1Store、请求体读取、响应转换、脱敏错误日志（Workers）
src/service/mcp.rs            Waypost 工具目录（WaypostTools）
src/service/oauth*.rs         授权码/PKCE/刷新轮换/撤销状态机；资源、scope、授权绑定按产品参数化
src/service/keys/             密钥产品：表、AES-256-GCM、五个工具、同意页绑定、授权管理
src/cloudflare.rs             Worker 入口：WAYPOST_PRODUCT=waypost|keys 选择产品
```

OAuth 只有一份状态机。产品差异只有三处：`OAuthProfile`（scope、默认 scope、资源名、是否开放设备码），授权绑定（Waypost 绑定 Space/Actor/Consumer；密钥产品绑定账号和按条目的读写许可），以及族表、刷新令牌表、访问令牌表。Waypost 的表和 SQL 原样保留；密钥产品用 `key_oauth_families`、`key_oauth_refresh_tokens`、`key_access_tokens`。两个产品即使共用一个数据库，令牌也查不到对方的表；资源 `<origin>/mcp` 不同、令牌前缀不同（`wpo_`/`wpr_` 与 `kso_`/`ksr_`），scope 互不承认。

## 客户端身份

授权服务器按顺序解析 `client_id`：预注册 → CIMD → DCR。配置在 `WAYPOST_OAUTH_CLIENTS`（Worker）或 `WAYPOST_OAUTH_CLIENTS_FILE`（原生）：

```json
{"clients":[],"client_id_metadata_documents":true,"dynamic_registration":true}
```

两个开关默认关闭，旧配置行为不变。预注册的 `client_id` 不能再以 `https://` 或 `dcr_` 开头，避免与另外两类身份混淆。开启任一项时可以没有预注册客户端。元数据随之声明 `client_id_metadata_document_supported` 和 `registration_endpoint`；`token_endpoint_auth_methods_supported` 仍只有 `none`，令牌端点仍只收公开客户端加 S256 PKCE；`iss` 照旧与 `issuer` 一致。

**CIMD。** `client_id` 必须是带路径的 HTTPS URL，且与解析后的序列化完全一致（拒绝点段、显式端口、大小写归一、查询、片段、用户信息）。主机必须是带点的域名：IP 字面量、`localhost`、`.local`、`.internal`、`.lan`、`.home.arpa` 等直接拒绝。拉取不跟随跳转、5 秒超时、正文上限 5120 字节、`Content-Type` 必须是 JSON。文档必须是无重复键的 JSON 对象，`client_id` 等于 URL，`client_name` 与 1–8 个 `redirect_uris` 必填；`token_endpoint_auth_method` 缺省或为 `none`，声明 `private_key_jwt` 等其他方式的文档按 `invalid_client` 拒绝；带 `client_secret` 的文档拒绝。原生运行时先解析域名，任何一个地址不是全球单播（私网、回环、链路本地、CGNAT、组播、文档段、NAT64/6to4/Teredo 等）就拒绝，然后固定连接到已检查的地址并绕过代理。Worker 无法先解析再连接，那里的边界是主机名策略、Cloudflare 出口，以及这个 Worker 没有任何私网绑定。文档按 `Cache-Control` 缓存于 D1，夹在 60 秒到 24 小时之间，最多 1000 条。

本部署自己托管的 `keyenv-remote` 文档（`/oauth/clients/keyenv-remote.json`）在服务端直接解析，不向自己的域名发子请求。

**DCR。** `POST /oauth/register`（RFC 7591），JSON。只发公开客户端：`token_endpoint_auth_method` 缺省或 `none`，授权类型只能是授权码和刷新，响应类型只能是 `code`，回调必须是 HTTPS 或字面回环 HTTP。返回 `dcr_` 前缀的 ID。注册总数上限 1000；一天内没有任何获批授权的注册会被清理。边缘限流对 `/oauth/` 下除令牌端点外的 POST 使用 `ADMIN_RATE_LIMITER`。DCR 的 `client_name` 由客户端自报，同意页标成未验证。

**回调匹配。** 预注册客户端保持 0012 的规则。CIMD 与 DCR 客户端：精确匹配，或者登记的回调是 `http` 且主机为 `127.0.0.1`、`[::1]`、`localhost` 时，请求可带任意非零端口（RFC 8252 §7.3），主机字面和路径必须完全一致，不允许查询、片段和用户信息。授权码仍绑定本次实际回调。Claude Code 的文档登记的是不带端口的 `http://localhost/callback` 和 `http://127.0.0.1/callback`，Codex 的 CIMD 回调是 `http://127.0.0.1/callback`，都在这条规则内。

**仍然有效的授权。** 认证时的客户端白名单从「配置里的 ID」扩展为「预注册 ∪ 开启 CIMD 时的 HTTPS ID 与自托管文档 ID ∪ 未停用的 DCR 记录」。关掉 CIMD、停用某条 DCR 或移除预注册客户端，已发出的令牌在下一次请求时失效。

**同意页。** 预览增加 `client_kind`、`client_host`（CIMD 文档所在主机）、`redirect_host` 和 `client_warnings`：DCR 名称未验证；只有回环回调的非预注册客户端提示「任何本机进程都可能冒用这个客户端」（MCP 2025-11-25 Localhost Redirect URI Risks）。

## 密钥产品

部署时 `WAYPOST_PRODUCT=keys`。只开放 `/health`、`/oauth/*` 与发现端点、`/mcp`、`/account`（同意页与连接管理）、`/account/login|callback|session`（复用 Google 登录）和 `/account/keys/grants*`。Waypost 的 `/v0`、`/admin`、仪表盘、Space 和设备码路由都不存在。不需要 R2。运营者模式必须为 `disabled`。

**信任边界。** D1 只存 AES-256-GCM 密文和元数据。数据密钥在 Worker Secret `KEYS_DATA_KEYS`（`{"active":"k1","keys":{"k1":"<64 位十六进制>"}}`，最多 8 把）。新写入用当前 kid；旧 kid 只要还在密钥环里就能解密；字段被改写时换成当前 kid。轮换做法：加入新密钥并设为 active，等所有字段都被改写（或重新导入）后再移除旧密钥。AAD 绑定账号、条目、字段名和 kid，一行密文搬到别处不能解密。Cloudflare 能读 Worker Secret，所以这不是零知识库；Worker 请求路径不做 Argon2id，不走 Google Drive。

**工具。** `list_entries`（名称、用途、字段名、禁用/过期、本连接能否读写；不返回值），`fetch_entry`（唯一返回值的工具；禁用或过期的条目拒绝），`create_entry`、`update_entry`（设置/删除字段、用途、过期；乐观并发），`disable_entry`。写入工具只返回成功状态、条目名和字段名；错误信息最多包含条目名和字段名，不含值。条目和字段规则与本机 keyenv 相同（名称 `^[a-z][a-z0-9/_-]{0,79}$`，字段为环境变量名，单值 ≤ 65536 字节，≤ 64 个字段），密钥产品的请求体上限是 256 KiB。每次读取和写入记一条审计（动作、条目名、客户端），不记值；审计写不进去就不返回值。

**授权。** scope 为 `keys:read` 和 `keys:write`，两者分开申请。同意页再按条目勾选「读」「改」，另有「全部条目（含以后新建的）可读/可改」和「可新建」。有效权限是 scope 与勾选的交集；本连接新建的条目自动对它可读可改。未授权的条目在列表里不出现，取用时与不存在无法区分。账户页 `/account` 列出现有连接并可逐个撤销；`/oauth/revoke` 和刷新令牌重放同样撤销整个族。

## 部署（免费额度）

```bash
npx wrangler@4.111.0 d1 create waypost-keys-production
cp wrangler.keys.production.example.toml wrangler.keys.production.toml   # 填 account_id 与 database_id
npx wrangler@4.111.0 d1 migrations apply waypost-keys-production --remote --config wrangler.keys.production.toml
npx wrangler@4.111.0 secret put WAYPOST_OIDC_CONFIG --config wrangler.keys.production.toml
npx wrangler@4.111.0 secret put WAYPOST_CSRF_SECRET --config wrangler.keys.production.toml
npx wrangler@4.111.0 secret put WAYPOST_CURSOR_SECRET --config wrangler.keys.production.toml
npx wrangler@4.111.0 secret put KEYS_DATA_KEYS --config wrangler.keys.production.toml
npx wrangler@4.111.0 deploy --config wrangler.keys.production.toml
```

Google OAuth 客户端的回调是 `https://keys.miles1150.top/account/callback`。`WAYPOST_ACCOUNT_SIGNUP_LIMIT=1`，只允许第一个登录的 Google 账号成为所有者。示例配置关闭 invocation logs，只保留 Worker 自己的脱敏错误日志（`route_label` 已覆盖 OAuth 与密钥路由，条目名从不出现在路径里）。密钥环、OIDC 配置和签名密钥只通过 `wrangler secret` 设置，仓库里只有占位符。数据密钥丢失等于密文全部不可恢复，要另行离线备份。

Waypost 现有部署要启用 CIMD/DCR，在 `WAYPOST_OAUTH_CLIENTS` 里打开两个开关并应用迁移 0015 和 0016（0016 在 Waypost 库里只是空表）。

## 验证

本地自动化：

| 检查 | 结果 |
|---|---|
| `cargo test --all-targets` | 160 项通过，其中新增：CIMD URL/地址/文档/回调/缓存/注册校验 6 项，AES-GCM 2 项，密钥产品 7 项（工具契约不回显值、读写分开授权、刷新/撤销、CIMD 拒绝与回调规则、DCR、跨产品令牌隔离、元数据） |
| `cargo clippy` 原生与 wasm32 `-D warnings`，`cargo fmt --check` | 通过 |
| Python 26 项、UI 38 项、原生 demo 与 participant flows | 通过 |
| 编译后的 Worker 在本地 Workerd 上：`verify_oauth_sdk.mjs`（官方 MCP SDK）、`verify_oauth_preview.py`、`verify_oauth_races.mjs`、`verify_account_preview.py` | 通过；开关 CIMD/DCR 前后都跑过，Waypost 工具行为不变 |
| `verify_codex_login.py`：Codex CLI 0.165.0，配置里只有 `url`，没有 client_id | 自动模式选 CIMD（`https://chatgpt.com/oauth/codex/client.json`，共享 `/callback`，任意端口）登录成功；强制 DCR 登录成功；只开 DCR 时自动回落到 DCR 登录成功 |
| `verify_keys_native.py`：原生与 Workerd 各一遍 | keyenv-remote 经自托管 CIMD 登录、隐藏输入 `set`、`import`、DCR agent 读写、工具契约、读写分离通过；原生库里只有密文 |

本地 Workerd 用 `scripts/serve_local_workerd.mjs` 启动：内存 D1、全部迁移、合成账号会话、外网全部拒绝。沙箱出口拒绝 `chatgpt.com`，所以 Codex 的 CIMD 文档用本地夹具代答（内容按 Codex 源码 `oauth_client_registration.rs` 与 `oauth_callback.rs` 的约定：`client_id` 为该 URL、回调 `http://127.0.0.1/callback`、`none`）。这证明的是服务端对 Codex 实际发出的请求的处理，不证明 chatgpt.com 上那份文档的真实内容。

没有验证：真实 Google 登录、真实 `chatgpt.com` 与 `claude.ai` 文档的线上拉取、Claude Code/Cursor 客户端端到端、Cloudflare 远端 D1 与限流绑定在免费计划上的行为、invocation logs 开关在 Cloudflare 侧的实际效果。
