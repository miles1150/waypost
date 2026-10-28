# 通用参与方与宿主唤醒适配器

状态：独立设计审查通过，已实现本地适配器与协议验收。用户授权范围为设计、实现与本地验证；本轮不部署、不合并、不修改生产凭据或网络配置。实际证据见[验收记录](../reviews/2026-10-28-participant-acceptance.md)，不宣称 Grok、真实 Codex 或公网 webhook 已接通。

## 1. 问题与目标

当前 `waypost-bridge` 的收件与可靠通知逻辑可以复用，但配置强制要求 `thread_id`、`codex_path`；本地绑定把服务身份和 Codex 目标放在同一个数组中；主循环把扫描直接接到 Codex 投递；自动 reconcile 只认识 Codex 会话。这让本应通用的参与方接入看起来只能接 Codex。

本次把收件、通知账本与宿主投递拆开，支持三种接入方式：

1. 本地桥向既有 Codex 固定会话通知。
2. 本地桥向用户配置、实际支持该契约的 HTTPS webhook 通知。
3. 宿主自带定时任务，直接通过现有 HTTP/MCP 查询信箱，不需要常驻桥或 webhook。

服务端的参与方继续是 Actor；Consumer 负责独立进度；token 负责认证与授权。产品名称、操作系统、webhook 地址和会话 ID 都不是新的服务端身份，也不为此增加新消息协议、服务端适配器注册表或模型调度器。

## 2. Yobiru 源码依据与取舍

研究依据为本地保存的 Yobiru `906ef9698224`，不是 README 推测：

| 真实源码 | 已有行为 | Waypost 采用的边界 |
| --- | --- | --- |
| `tailmsg.py:adapter_cfg` | 接收端配置选择 `exec` 或 `webhook` | 宿主投递作为本地枚举，不写进消息正文或服务端 Actor 类型 |
| `tailmsg.py:Ctx.agent_adapter` / `wake_decision` | 每个目标 agent 可有适配器；接收方限制有效唤醒 | 接收方本地配置决定是否通知和通知哪里，发送者不能改写目标 |
| `tailmsg.py:call_webhook` | 从私密文件／环境读取 URL 和独立 secret；不跟随重定向；限制诊断内容 | 私密配置、独立 webhook secret、受限日志；进一步约束公网 HTTPS 和 DNS 目标 |
| `tailmsg.py:deliver_wake` | 重验接收方权限，适配器成功不等于业务完成 | 投递前重新检查消息可读性，通知不生成业务 ACK |
| `codex_bridge.py` | inbox 为事实来源，SQLite 保存通知状态，未知结果不盲重发 | 通用通知账本与适配器分离，保持发送前持久化和未知状态 |
| `codex_queue_client.py` | 固定原生会话，通过官方 CLI 入队及只读核对 | 保留为一种具体宿主适配器 |

Yobiru 的普通 webhook 重试循环与专用 Codex 未知投递处理不同，不能直接照搬前者来保证通用 webhook 不重复。Waypost webhook 采用保守的未知结果规则。Yobiru 的 Tailscale 接收认证、Friends、任务租约和通用 `exec` 不在本次迁移范围；如后续需要执行任意本地程序，再独立设计受信 argv 适配器。

## 3. 参与方身份与双向通信

每个逻辑助手／客户端在一个 Space 中使用稳定 Actor，持有独立受限连接。需要分别保存收取进度的设备或宿主使用独立 Consumer；如果多个进程使用同一 Consumer，它们共享服务端进度，不自动获得分布式互斥或只执行一次的保证。

桥配置的 Actor/Consumer 必须与 `describe` 返回的 token 身份相符。参与方可以同时具备发送与读取能力，角色不固定成“生产者”或“接收者”。最小授权按需要组合：

桥与宿主可使用关联同一 Actor/Consumer 的不同 token：桥仅有读取权限，宿主持有实际需要的读取、回执和受限发送权限。两者共享逻辑收取身份，但凭据独立轮换和撤销；不能因为通知桥需要运行就给它宿主的全部发送／写入能力。

| 参与行为 | 所需授权及操作 |
| --- | --- |
| 向指定参与方交付 | `message.send` 与允许的 recipient Actor，通过 `waypost_send`／`POST /v0/messages` |
| 收取自己可见消息 | `message.read`，通过 `waypost_inbox`／`POST /v0/inbox/read` 和 `waypost_message_get`／`GET /v0/messages/{id}` |
| 声明可靠收取和完成本轮处理 | `receipt.write`，通过 `waypost_ack`／`POST /v0/receipts` |
| 查询写入结果 | `waypost_status`／`POST /v0/submissions/status` |
| 访问共享资料或附件 | 继续按现有独立资料权限和资源范围授权，不随唤醒自动扩大 |

例：A 发给 B，B 收取后按授权将结果发回 A。B 的回复使用 B 自己的 token、稳定 `request_id`、获准 recipient，并按现有 `thread_id` / `in_reply_to` 关联。原消息或 webhook payload 中的地址不能自行授予 B 回发、执行工具或访问其他资料的权限。

`inbox/read` 是增量 feed，不是待处理列表；ACK 不删除消息，`cursor: null` 从头读取。写入幂等范围是 `(space_id, actor_id, operation, request_id)`；`status` 查询当前 Actor 的提交结果，不是跨宿主业务任务状态。因此处理者自己保存待处理工作，不能根据一次 inbox 为空推断全部业务完成。

**循环控制由真正处理消息的参与方负责。** 桥不自动回复、不互相转发正文、不把 receipt feed 变成新的业务消息。处理者识别 info/result/通知，避免“收到即回复”的无限循环；如用户授权多轮自动对话，由处理者保存轮次预算和结束条件。本次不创建服务器自动对话预算协议。

## 4. 运行分层与最小模块

```text
既有 Waypost HTTP/MCP
       │
       ├─ 宿主定时直接 query → 读取正文 → 保存／处理 → ACK／回复
       │
       └─ Scanner → SQLite notification journal → WakeAdapter
                                               ├─ Codex
                                               └─ Webhook
                                                    │
                                                    └─ 宿主读取正文 → 保存／处理 → ACK／回复
```

独立 Rust bridge crate 保留；拆成小模块不拆进程、不增加本地 HTTP 服务：

- `config`：公共连接与 tagged adapter 配置、旧配置归一化。
- `waypost_client`：既有服务调用、身份核对、游标变化和可读性检查。
- `scanner`：分页读取，事务保存引用及扫描游标，不依赖 Codex/webhook 类型。
- `journal`：稳定引用、发送尝试与结果，单实例锁和 schema 升级。
- `adapters`：本地 `WakeAdapter` 枚举及统一结果；首期 Codex、Webhook 两种，无动态插件加载。
- `cli`：组合命令、退避与输出，不在这里复制授权规则。

建议适配器结果为 `Accepted { evidence }`、`NotAttempted { reason }`、`Unknown { reason }`。明确本地配置错误可进入 blocked；网络或宿主返回的自由文本不作为原因字符串保存。

## 5. 配置与旧版本兼容

以下是供实现者审查的配置契约。公共字段保留现有名称；新版采用 `config_version: 2` 和 `wake_adapter` tagged object。不同类型不要求无关字段。

```json
{
  "config_version": 2,
  "base_url": "https://waypost.example.com",
  "token_file": "/private/waypost/token",
  "state_dir": "/private/waypost/state",
  "space_id": "space_example",
  "actor_id": "actor_example",
  "consumer_id": "consumer_example",
  "wake_adapter": {
    "type": "codex",
    "thread_id": "12345678-1234-1234-1234-123456789abc",
    "codex_path": "/absolute/path/to/codex",
    "codex_remote": null,
    "codex_home": null
  }
}
```

Webhook 只替换 `wake_adapter`：

```json
{
  "type": "webhook",
  "url_file": "/private/waypost/webhook-url",
  "secret_file": "/private/waypost/webhook-secret"
}
```

首期只支持固定 `Authorization: Bearer <secret>`，不提供任意 header 模板、正文模板或消息字段插值。文件必须当前用户所有、私密且普通文件；URL/secret 不进入普通日志或 status。Webhook secret 不得使用 Waypost token；它只认证通知目标，不能让 webhook 反向调用 Waypost。宿主另行配置受限的 Waypost 连接。

配置加载及投递时拒绝 webhook secret 与 Waypost token 指向相同规范化文件路径或具有相同值；比较和错误信息不得打印秘密。仅依靠不同文件名不算独立凭据。

旧无版本、顶层 `thread_id` / `codex_path` / `codex_remote` / `codex_home` 配置仍接受，并在内存中归一化成 Codex 适配器。拒绝旧字段和新 `wake_adapter` 混用、未知类型、未知字段或静默默认回 Codex。旧配置不用手工迁移才可运行。

旧 SQLite `meta.binding` 包含 origin、Space、Actor、Consumer 和 Codex 目标的八元数组。首选兼容策略是旧／新版 Codex 配置都归一化到精确相同的旧八元数组，保留现有 metadata，不为结构拆分强制数据库迁移；Webhook 使用独立带版本的目标 binding。任何确需新增 metadata 的升级必须先验证完整旧绑定并事务性写入，不删除旧 item 状态或扫描游标。旧 `sending` 继续恢复为 unknown，accepted/unknown 不能因升级变成 pending。任何服务、参与身份、Consumer 或通知目标变化都必须失败并提示独立迁移，不能靠新建空账本自动重发历史来“修复”。

公共服务身份与适配器目标在结构上分开，但状态目录仍固定到一个完整组合。首期一个 state_dir 对应一个 Consumer 和一个通知目标，不支持一条消息自动广播多个宿主。目标 URL 更改算目标变化；`allow_loopback_test` 也纳入 Webhook binding，不能对同一账本静默切换网络安全模式。secret 的原地轮换不改变逻辑目标，但下一次发送读取新 secret。每次发送校验私密 URL 的目标指纹仍与账本一致，防止 URL 文件替换把旧队列改投。

## 6. 扫描、稳定标识和通知账本

服务端消息 ID、feed item ID 与 Consumer 分工保持不变。桥的通知唯一键由稳定 `(origin, space_id, actor_id, consumer_id, item_id, adapter_target)` 确定，不使用 scopes、grant 指纹、游标、secret 值或轮询次数。

Webhook 增加稳定 `delivery_id`：对上述规范化身份做带版本前缀的 SHA-256 编码，包含已固定的目标、不包含 secret。算法和 payload 版本固定并测试，重启、重扫、重试保持同一值。ID 是相关性证据，不是认证凭据或远程幂等保证。

一次本地事务写入新引用／待通知记录和下一扫描位置。处理 f3 读取范围变化及旧 f2 失效时清除扫描位置，分页重新发现；相同稳定 item 不重新通知。凭据轮换保持身份时不清账，身份不符停止。

继续活跃 30 秒、空闲 60 秒、少量抖动，每轮最多十页，错误指数退避。空页无远端写入、不发 ACK、不上传心跳。不按适配器增加第二个轮询器。五设备的基本轮询预算仍约 7,200～14,400 次／天，实际还包括消息检查和宿主读取。

receipt、memory_revision 等非 message feed 仍可保存用于扫描完整性，但记录为 ignored 而不是永久 pending，不唤醒任何适配器。这只是桥的范围判断，不等于业务 processed；不得对这些记录自动 ACK。

通知前重新检查当前凭据能读取目标消息；404 进入 blocked，401/403 暂停，不继续派发旧引用。权限重新扩大或操作者明确重试时才能恢复 blocked；不能把 unknown 当作 blocked 重试。无法判定错误是否发生在发出网络／queue 前时，按 unknown 处理。

## 7. Codex 适配器

保留现有官方 CLI、精确 UUID、本机 socket 所有者检查、固定 CODEX_HOME 和严格 queue 回执核对。`accepted` 只表示官方队列接受；通过固定会话 userMessage 中标记核对只能证明通知出现，不表示任务完成。

`reconcile` 的自动模式仅由支持读取证据的适配器提供。Codex 可以使用现有只读 app-server 核对；webhook 首期没有通用状态查询 API，不能借用 Codex 核对逻辑或随意向 URL 添加 `/status`。

## 8. Webhook 适配器与未知结果

Webhook 向经过本地配置验证的目标发送一次 HTTPS POST。示例是自有接收器契约，不是某产品已有 API：

```json
{
  "version": 1,
  "event": "waypost.message.available",
  "delivery_id": "wpwake_v1_example",
  "space_id": "space_example",
  "actor_id": "actor_example",
  "consumer_id": "consumer_example",
  "item_id": "feed_example",
  "message_id": "message_example"
}
```

不发送正文、标题、附件、token、CLI 参数或消息提供的 URL。宿主先核对通知的 Space、Actor、Consumer 与自身受信配置相符，再从自己的配置取得 Waypost 服务地址并以自己的凭据读取；不把 payload 中任意身份当成切换空间或权限的授权。可同时发送同一 `delivery_id` 的 `Idempotency-Key`；接收端应在可靠保存通知后返回成功，但仅有这个 header 不能证明任何任意 webhook 都幂等。

| 观察结果 | 本地状态与动作 |
| --- | --- |
| 配置无效、私密文件不可用、DNS/地址校验失败，明确未调用 HTTP 发送 | blocked 或 NotAttempted，可在修复后尝试 |
| 任意 2xx | accepted，仅说明 endpoint 接受请求；不当作已处理 |
| 已调用发送后的超时、连接中断、进程崩溃 | unknown，不自动重发 |
| 3xx | 不跟随；unknown，不能把另一个地址当作新目标 |
| 4xx/5xx，包括 429 | 默认 unknown；没有端点保证时响应不证明没有发生副作用 |
| 本地 accepted 落盘失败 | 重启从 sending 恢复 unknown，不能为了补账重发 |

HTTP 状态和有限本地错误分类可记录；响应正文不进入日志或 SQLite。`Retry-After` 可以显示为重试提示，但不会把 unknown 自动改成可重发。只有未来为特定端点明确验证幂等与查询协议后，才可扩展自动恢复；首期人工核对 `delivery_id` 后使用既有显式 reconcile accepted/pending。

### 已核对的 Grok 产品差异

独立官方资料研究见 [Grok routines 研究](../reviews/2026-10-28-grok-routines-research.md)：

- [Grok Bot routines webhook](https://docs.x.ai/grok-bot/skills-routines-and-automations#webhooks) 使用 POST、Bearer key 和可选 JSON body，body 与 routine instruction 一起进入宿主上下文；文档未公布固定 JSON schema、幂等保证或投递查询协议。可以把上面的引用 JSON 作为候选输入，但只有真实接入验收后才能标为兼容。200 表示接受／开始，不是完成。
- [Grok.com Automations webhook](https://docs.x.ai/grok/automations/webhooks) 是另一套接口，使用 Standard Webhooks 签名和不同 header，不等同 Bearer webhook。首期这个适配器不声称支持它，不把 HTTP 请求成功或通用 JSON 能力写成“所有 Grok webhook 已接入”。

本次不新增专用 Grok 协议类型。若用户实际目标是签名型 Automations，需要另行设计签名适配器并验收，不能在 Bearer 配置里临时拼 header。

## 9. Webhook 网络安全

Webhook 是本机配置的可出站目标，不从消息中获取。首期默认只接受公网 HTTPS：

- 拒绝用户信息、fragment、query 和非 HTTPS；避免把 URL 当作额外 secret 通道。
- 拒绝 loopback、private、link-local、multicast、unspecified、CGNAT、保留地址及云 metadata 地址；同时处理 IPv4、IPv6 与 IPv4-mapped IPv6。
- DNS 每次尝试重新解析；只要任一结果不允许就拒绝，不只检查第一条。验证后的连接必须固定到该次获准 IP，HTTP Host 与 TLS SNI 保留原域名并验证证书，不能检查后再让 HTTP 库重新解析。
- 禁止重定向。Webhook secret 只发给已固定的目标，不跟随跳转，不复用 Waypost Authorization。
- 代理不能成为绕过地址校验的通道。若当前环境强制使用 egress proxy，而其远端 DNS／CONNECT 路径无法保证连接到已验证的地址，应明确返回不支持安全目标固定，不静默关闭代理或放宽规则。托管 cloud env 的代理政策优先，不能为验收改网络设置。
- 代理检查涵盖实际生效的 `HTTPS_PROXY`、`HTTP_PROXY`、`ALL_PROXY`、`NO_PROXY` 及小写形式。不能仅设置 HTTP 客户端 DNS override 就声称经代理的 CONNECT 仍固定到了获准 IP；实现必须证明实际连接路径，否则对该 webhook 调用失败关闭。
- 使用固定请求超时、发送及响应大小界限，限制响应读取；不把 URL、secret 或远端错误消息放入日志。

为使用真实 binary 完成本地 HTTP 集成验收，可提供配置级 `allow_loopback_test: true`，默认 false，且 true 分支只允许 URL 中显式的 literal `127.0.0.0/8` 或 `::1`，不接受 `localhost`／任何 DNS 名称、一般私网、CGNAT 或 metadata 地址；IPv4-mapped IPv6 首期拒绝，不另开旁路。该例外仅允许本机测试目标的 HTTP，不能变成 `allow_private`；无此标记时 loopback 仍拒绝。选项只能由当前用户所有的私密本机配置指定，外部消息不能启用。仅该 literal-loopback 测试请求可以直连本机，不修改 Waypost 客户端或远端请求的代理设置。默认生产路径继续执行完整公网 HTTPS 和代理限制。真实公网 HTTPS 接收器和受控代理条件下的验收另行记录。是否需要合法的私网 webhook 是后续显式需求，不能因 Yobiru 支持 tailnet 就默认开放。

## 10. 宿主定时直接 query

宿主能运行定时任务并调用 HTTP/MCP 时，直接周期性查询既有 inbox 即可，不必部署 bridge、提供 webhook 或创建伪 Codex 会话。例如已有模型宿主的定时任务可以执行 `waypost_inbox`；是否具备这种能力应由宿主实测确认。

定时处理者遵守现有可靠客户端契约：保存稳定 Consumer 与游标；取得完整内容后先可靠保存内容和待处理记录，再提交 received；处理结果保存后才提交 processed；回复前持久化稳定 request_id 和完整请求，未知写入先查 status，再重放同一请求。若宿主没有持久化能力，只提供只读查询，不宣称可靠收取或自动处理完成。

调度任务不能重叠执行相同待处理工作；由宿主串行调度或自己的持久锁保证。本地桥和定时处理者若同时针对同一业务 Consumer 活跃，必须明确谁负责处理，不能把通知去重当成跨宿主执行互斥。测试可以使用三个独立 Actor／Consumer 表示三类参与方，双向通信按各自权限进行。

可选桥命令 `scan` 只做受限扫描，不调用适配器、不 ACK；它使用桥自己的扫描游标，不替代业务 Consumer 的可靠处理记录。首期可以只输出新增引用计数；如需检查引用，复用 status 的明确只读输出，不为 scan 再创建一套内容导出契约。需要此命令时应明确与现有 `once`（扫描并投递一次）的区别。宿主已有 HTTP/MCP query 时不强制增加或使用该命令。

## 11. 回执、权限与执行边界

唤醒只是一条提示，不是工具执行授权。桥不保存正文因此不发 received，不判断模型完成因此不发 processed，也不发自动回复。HTTP webhook 200、Codex queue receipt、宿主上线状态分别是不同证据，不能归并为业务完成。

连接权限编辑继续使用已经实现的 owner/admin API，保留同一 Actor、Consumer 和 bearer；本次不加权限管理 MCP。参与方按收到的权限错误刷新 describe；新读取权限触发必要的历史补读。撤权后的已交付数据无法撤回，已接受的 webhook/Codex 提示也不保证撤回。

## 12. 实施和验收计划

设计通过独立 review 后按以下顺序实施；本草案本身不授权部署或生产设置变更。

1. 提炼公共 Config、scanner、journal、Waypost client，旧 Codex 配置及数据库回归保持原样。
2. 引入本地 WakeAdapter 枚举，把 Codex 投递／reconcile 移入对应适配器，原有命令行为保持。
3. 实现 webhook 私密配置、稳定通知引用、DNS/目标保护及保守 unknown 状态；不虚构任何 Grok endpoint。
4. 文档补充直接 HTTP/MCP 定时 query 的可靠处理流程；视实际验收需要提供 receive-only scan。
5. 验收三类参与方的双向消息，不以接入方式替代身份或授权。

最低测试矩阵：

| 场景 | 必须观察到 |
| --- | --- |
| 旧 Codex 配置和现有 SQLite 升级 | 绑定不变，accepted/unknown 和游标保留，不重新通知历史 |
| webhook 配置 | 无 Codex 字段也可加载；混用／未知字段拒绝；秘密不输出 |
| A→B→A，分别覆盖三类接入方式 | 发布身份正确，指定获准 recipient，回复相关性保持；不自动无限回复 |
| 稳定 request_id 响应丢失 | 查询恢复或同请求重放，不生成新业务消息 |
| received/processed | 仅真实消费者可靠保存／处理后写入，桥通知不产生回执 |
| 权限扩大、撤销、凭据替换 | 历史补读去重；撤权停止投递；不同身份拒绝复用状态 |
| webhook 2xx、重定向、超时、5xx、崩溃 | 只有 2xx accepted；不跟随跳转，其他不确定结果保持 unknown |
| webhook DNS 含私网／重绑定／mapped IPv6／代理路径 | 目标检查失败关闭，不泄露认证，不绕过环境代理政策 |
| 宿主定时查询 | 无 bridge 也可双向交付；串行恢复，未持久化时不 ACK |
| 空闲五设备轮询 | 本地状态可更新，远端无空 ACK／heartbeat 写入 |

验收报告必须区分本地模拟 webhook、真实 HTTPS webhook、真实 CF API/MCP、模拟 Codex CLI 与真实 Codex 宿主。Grok 或其他品牌只有获得公开或用户提供的真实契约并实际验证后才能标为支持；通用 webhook 能力本身不构成品牌接入证明。

相关历史设计：[本地桥与连接权限](0006-local-bridge-and-connection-permissions.md)。本草案调整的是本地宿主适配边界，不推翻服务端消息、授权和回执的既有职责。
