# 密钥产品与共享 MCP 网关

Waypost 仓库提供无状态 MCP 网关、现有 OAuth 客户端注册表和密钥产品；personal-plugins 提供 `keyenv-remote` CLI、插件和 skill。密钥产品使用独立 Worker 和 D1，接口为 `/mcp`；本机 keyenv 保持独立。服务端使用主线迁移 `0015_oauth_client_registry.sql`，新增 `0016_keys.sql`，不重新定义 0015。升级现有 Waypost 前应先依 `docs/oauth-client-migration.md` 迁移旧注册配置并保留既有授权记录。

## 授权和信任边界

Worker 使用 `WAYPOST_OAUTH_CLIENT_DISCOVERY` 启用 DCR，不使用已经弃用的 `WAYPOST_OAUTH_CLIENTS`。Worker 不声明外部 CIMD：它不能固定经过检查的 DNS 解析结果。原生运行时仅在能够安全固定 DNS 时支持 CIMD。CLI 在 CIMD 不可用时使用 DCR；每个连接仍需要 Google 登录和明确同意。只接受公开客户端和 PKCE S256。授权请求与注册表 revision 绑定；同意、令牌签发、刷新和密钥读取/写入重新检查当前 revision、账号和授权族。访问令牌与 Waypost 分表，不能互用。

必须提前把验证过的 Google OIDC subject 配置为 `KEYS_OWNER_SUBJECT`；单纯设置注册数量上限不能识别所有者。密钥模式要求账号配置、该 subject、禁用 operator、独立的 CSRF 和 cursor 签名密钥以及 `KEYS_DATA_KEYS`。现有非所有者账号和浏览器会话不会成为该产品所有者；在复用现有数据库之前必须另行核实历史授权和升级方案。

条目字段使用 AES-256-GCM 加密，AAD 绑定账号、条目、字段与 key ID。D1 保存密文和元数据，Worker Secret 保存数据密钥；Cloudflare 和有权管理账户的人属于信任边界。密钥丢失后密文无法解密，生产数据密钥必须先离线备份并验证恢复。旧 key 必须保留到全部密文重新加密；目前没有批量重加密工具。agent 通过 `fetch_entry` 读取值时，值会进入宿主的工具结果和模型上下文。读和写分别授权；读取与变更记审计元数据，写入不回显值。

## 部署前置

参照 `wrangler.keys.production.example.toml` 准备独立 D1、真实 Google OAuth 客户端和 `https://keys.miles1150.top/account/callback` 回调。确认准确的 Google subject，设置 `KEYS_OWNER_SUBJECT`，再配置 OIDC、独立 CSRF/cursor 签名密钥和数据密钥；数据密钥先离线备份。部署、创建或修改持久凭据应按操作时的授权执行。应用迁移并核对名称，切勿替换已应用的 0015；最后绑定域名并验证真实 Google 登录、授权撤销、CLI 与各宿主连接。真实服务和 cloud session 的授权复用还需要单独验收。

配置关闭 Workers invocation logs，但日志和免费额度的线上行为仍需实际检查。限流绑定按 Cloudflare 地点近似计数，不保证全局严格限额。
