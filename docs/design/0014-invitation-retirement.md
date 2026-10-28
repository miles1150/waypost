# 邀请制的受控退役

本轮仅本地实现。个人账号替代代码已有本地验收，但真实 IdP、恢复流程和目标宿主的完整生产闭环尚未确认。因此先交付可回退的退役模式；不默认关掉现有服务，不删除邀请历史，不声称已在生产退役。

## 切换契约

原生和 Worker 均支持 `WAYPOST_ONBOARDING_MODE`：

| 值 | 行为 |
|---|---|
| 未配置或 `legacy` | 保持申请/邀请流程；若账号已配置，也显示账号入口。 |
| `accounts` | 必须已配置有效 OIDC，否则运行时配置失败。关闭申请/邀请 UI 和业务 API，保留账号与旧登录/客户端路径。 |
| 其他值 | 配置失败，不静默采用某种权限模式。 |

`accounts` 模式以下入口返回 HTTP 410、`INVITATIONS_RETIRED`，不读写申请/邀请数据：

- `/admin/access-request`：提交申请。
- `/admin/invitation`：兑换邀请，旧有效邀请也不兑换。
- `/admin/v0/access-requests`：申请管理列表。
- `/admin/v0/spaces/{space}/invitations` 及其子路径：创建/撤销邀请，包括尾斜杠变体。

管理员、Space owner、匿名调用者都不能绕过此关闭。已有 owner key、管理登录、Agent Bearer/MCP、账号登录、已有 Space 认领/恢复及消息数据不被撤销或替换。需要撤销个别旧邀请时，在切换前通过受控管理流程处理；退役模式不会为了处理邀请而重新开放端点。

新增无数据库查询的公开 `GET /onboarding`，返回当前两个入口的启用状态及固定 `/account` 链接，响应 no-store，不包含账号、Space 或凭据。Dashboard 每次启动读取一次；加载前和失败时都关闭邀请按钮，保留已有密钥登录。仅在明确允许时显示申请、邀请和审批入口。旧 `#invite`、`#request-access` 在等待网络前清除；退役后给出账号入口提示，不兑换邀请。隐藏按钮的程序化触发和遗留邀请创建任务也不能发起请求。前端控制不能替代服务端 410。

## 向前兼容的数据处理

这是配置和入口迁移，不需要新增空洞的 schema 15。仍要求当前分支的 schema 14；从旧版升级须按顺序应用既有 0013/0014。没有 DROP、DELETE、回填覆盖或自动撤销历史邀请，申请、pending/redeemed/revoked 邀请和既有消息都保留。

因此切回 `legacy` 是明确恢复旧业务入口：尚未过期且未撤销的 pending 邀请可能重新可用；expired/revoked/redeemed 邀请不能因切换复活。若要求永久失效，应在切换前显式撤销并核验，不能将“当前关闭兑换”误称为永久撤销。

配置回退不等于代码回退。切回 `legacy` 仍运行当前账号/OAuth 安全检查。切回旧二进制则依然需要[账号/OAuth 回滚前撤权](../../scripts/account-rollback-revoke.sql)、schema 匹配及备份演练，不能靠配置值跳过这些步骤。

## 合理的上线与最终移除时机

1. **默认兼容阶段（当前交付）**：部署与真实身份配置仍需单独授权。保留 legacy；在 staging 验证真实账号登录、既有 Space 认领、恢复和旧客户端。默认 signup limit 是 0；必须先验证已有账号能够登录，或明确设置有限的新账号准入，不能仅因 OIDC 配置存在就关闭唯一入口。
2. **受控退役阶段**：完成当前用户的登录/恢复安排，告知未兑换邀请持有人如何迁移，明确待处理申请和邀请的保留/撤销政策，再将模式设为 accounts。更新 Static Assets 与 Worker，避免旧版本仍接流量：旧 Worker 不识别本开关，仍可能处理邀请。核对 `/onboarding`、410、真实账号登录和旧桥收发。同步网站/说明中的邀请入口；当前独立营销网站不能因本地代码完成就宣称线上已取消邀请。
3. **永久删除旧实现阶段**：受控模式运行稳定、未兑换邀请已到期或受控撤销、历史申请有处理/留存方案、真实恢复链已通过且不再需要模式回退后，再删除 legacy 申请/签发/兑换实现和 UI 文案。旧 URL 可继续保留无业务能力的 410 墓碑响应。历史表可长期只读留存；是否依法清理是另一个明确授权任务。不要删除仍用于认领/恢复的 owner-key 管理边界。

新账号创建的 Space 没有自动生成 legacy owner key。丢失 IdP 身份时，必须有经人工核验的 operator 恢复流程；保留旧 Space 的 owner-key 恢复并不解决这一类账号找回。未确认此流程前，不适合不可回退地删除旧实现。

## 隔离验证

新增合成数据库回归分别覆盖邀请/申请为空和已存在的情况；已存在情形包含 pending、expired、revoked、redeemed 记录及旧消息。使用有效 operator、owner Bearer、owner cookie 和匿名请求验证退役端点均为 410，且申请/邀请全列快照不变；旧 Agent token 仍能读取原消息，既有空间认领与恢复正常。切回 legacy 后只有原本仍有效的邀请可兑换。无 OIDC、未知模式均拒绝。

前端测试覆盖退役和元数据不可用时的旧链接、程序化点击、遗留邀请任务及账号入口；原 legacy 用例继续通过。此前迁移测试继续验证 schema 12→13→14 历史保留。本地证据不代表真实 IdP 可用、真实用户已迁移、Cloudflare 生产已退役或全部版本并发窗口已消除。

本轮结果：126 项 Rust、26 项 UI 测试通过，迁移历史保留回归、native/Wasm strict Clippy、Worker release build、Static Assets 构建和文档检查通过。`scripts/verify_invitation_retirement.py` 在实际隔离 Workerd/D1/Static Assets 上分别验证 accounts 与回退后的 legacy 模式；accounts 模式下官方 MCP SDK 的授权、调用、刷新和撤销仍通过。全部使用合成账号；未触及生产。默认配置没有改成 accounts。
