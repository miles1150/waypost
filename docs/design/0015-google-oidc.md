# Google OIDC：公钥轮换与配置准备

本变更提供可选的 Google 公钥刷新。不会创建 Google 客户端、配置生产秘密、迁移数据库或自动开放注册。真实 Google 登录仍需单独验收。

## 配置与身份

```json
{
  "issuer": "https://accounts.google.com",
  "client_id": "EXISTING-WEB-CLIENT-ID.apps.googleusercontent.com",
  "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_endpoint": "https://oauth2.googleapis.com/token",
  "client_secret": "CONFIGURE-PRIVATELY",
  "google_jwks": true
}
```

以上均为配置模板，不是可部署凭据。Native 通过私有 `WAYPOST_OIDC_CONFIG_FILE` 文件加载；Worker 通过 `WAYPOST_OIDC_CONFIG` secret 加载。原有静态 `keys` 配置默认仍使用固定公钥模式。

Google 模式只信任固定 Google 端点；不从 JWT 的 issuer、jku、x5u 或其他输入选择网络目标。Google 文档允许的两个 issuer 值 `https://accounts.google.com` 和 `accounts.google.com` 归一到前者；其他提供方保持严格匹配。账号仍按 issuer 与 subject 识别，不按邮箱自动合并。

## 公钥缓存与失败行为

缓存只保存公共验证密钥，在同一线程/Worker isolate 中跨请求复用。同一缓存最多执行一个刷新；并发回调可能被拒绝并需要重新登录，不能假设所有请求会等待刷新后自动成功。未知 kid 与失败请求受刷新冷却约束；不宣称跨 isolate 全局限流。冷启动会重新获取公钥。

从固定 `https://www.googleapis.com/oauth2/v3/certs` 获取 JWKS，不跟随重定向，限制响应大小和时间。刷新超时为 10 秒，响应上限 64 KiB，刷新冷却为 30 秒。缓存按 max-age 减去 Age 并扣除获取耗时计算，有效期最长一小时；缺少缓存时长时采用一分钟，no-store/no-cache 或已耗尽有效期的响应被拒绝。缓存有效期受提供方缓存头与本地上限约束，过期密钥不能作为失败兜底。网络故障、异常 JWKS 或无法找到 kid 时登录失败，不能降级成不验证签名。失败后用户需重新发起登录，不能重放已兑换的授权码。

缓存内已知密钥在有效期内可能仍被使用，因此公钥移除并不意味着所有 isolate 即时撤销。需紧急停止登录时关闭该账号入口；已有 Waypost 会话与客户端凭据的撤销另行处理。

## 复用 Google 应用

1. 在 Google Auth Platform → Clients 检查现有 **Web application** 是否适合 Waypost，以及 Branding、Audience、授权域名、发布/测试状态和目标用户。不能仅为省步骤而复用无关应用。
2. 回调精确为 `https://waypost.miles1150.top/account/callback`。保留原有回调；修改应用及配置长期秘密需单独确认。
3. 只请求 `openid`，不需要 Gmail/Drive 权限或 Google refresh token。不要通过聊天交付 client secret。
4. 保持新账号注册默认关闭。确定目标用户准入方式后才设置受控注册上限。上限为 1 并不等于只允许指定 Google 用户，首个符合提供方准入的登录者可能占用该名额。
5. 用真实用户验证登录、原空间认领、恢复、注销，以及 Google 失败时旧客户端可继续工作。生产切换邀请制前必须完成恢复闭环。

Google Web client 只用于人类登录；MCP 宿主通过 Waypost 的客户端发现与自动注册接入，不能共用 Google secret。新版使用显式 `WAYPOST_OAUTH_CLIENT_DISCOVERY`，Worker 默认通用 DCR，安全原生 fetch 可用时支持 CIMD；不是让用户手填 `WAYPOST_OAUTH_CLIENTS`。旧列表须按[客户端迁移指南](../oauth-client-migration.md)离线导入、核对后移除旧运行变量，新版会拒绝仍含旧变量的配置。MCP resource 为该部署的固定 `/mcp` URL；普通宿主接入见[MCP OAuth setup](../mcp-oauth-setup.md)，能力和验收边界见[客户端发现设计](0017-oauth-client-discovery.md)。

## 发布与回滚边界

本变更不增加数据库迁移。生产若仍为 schema 12，部署账号版本前仍须应用 13、14，并验证最新 D1/R2 备份可在持有原加密密钥的可信环境恢复。公钥刷新不能解决缺失生产解密密钥的问题。

优先在新运行时关闭新登录或退回 legacy 邀请入口。回退到缺少账号/OAuth 权限检查的旧运行时前，按[交接说明](0013-local-handoff.md)原子撤销账号/OAuth 授权，保留新表与历史；不能用旧快照覆盖上线后消息。

## 官方依据

- [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)：issuer 两种形式、公钥缓存、回调及授权码流程。
- [Google discovery](https://accounts.google.com/.well-known/openid-configuration)：固定 issuer、端点、RS256 与 client_secret_post。
- 本地测试不等于真实 Google 登录、远端 Worker 故障或全局免费额度负载验收。

## 本轮验证

独立安全审查发现并修正了获取耗时未扣除 TTL 的问题。回归覆盖密钥轮换、未知 kid 冷却、失败与取消、过期缓存、异常公钥、Google issuer 归一、获取过程中 JWT 过期，以及原生 HTTP 的错误状态、重定向、超大响应和停滞响应体。

`node tests/google_jwks_worker.mjs` 使用实际编译 Worker、固定版本 Miniflare、独立 D1/R2 及合成账号。所有出站请求由 mock 拦截：连续独立登录复用缓存，等待真实冷却后替换签名密钥并刷新，未知 kid 与上游 503 被拒绝且受冷却约束。此测试纳入 CI；它不访问真实 Google，也不创建真实凭据。

其他验证包括 Rust 回归、26 项 Python、26 项 UI、native/Wasm 检查、Worker release 构建及文档检查。真实 Google 凭据登录、远端跨 isolate 行为和生产恢复演练仍未完成。
