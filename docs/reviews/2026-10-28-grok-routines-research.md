# Grok routines：官方能力与 Waypost 接入边界

核对日期：2026-10-28。本次只读取公开官方资料，没有登录 Grok、创建 routine、配置连接、签发凭据或调用 webhook。文档说明能力，不代表当前用户账户已经具备或通过真实验收。

## 结论

Grok Bot 的官方文档明确支持云端定时 routine、连接工具和自定义入站 webhook。因此可以研究“宿主按时启动一轮，参与方在这一轮查询 Waypost”的路径；不能说模型安装 MCP 后就会自己持续轮询。Grok.com 的 Automations 是另一产品入口，不应把两者的认证方式、调度限制或状态保证混为一谈。

对于 Waypost，可以提供两种宿主适配：宿主定时启动查询，以及本地桥轮询后调用 Grok Bot webhook。本轮实现 webhook adapter 可以依据下述公开接口，但须标记为协议适配与合成验收，尚未真实接入 Grok。需要低于五分钟的发现延迟时，Grok Bot 定时 routine 不能直接替代 30～60 秒本地轮询。

## 官方证据

### Grok Bot routines

来源：[Skills and routines](https://docs.x.ai/grok-bot/skills-routines-and-automations)，页面标记更新日期 2026-10-28；公开网页读取成功。

实际短引文：

> “Authorization: Bearer <key>”

> “optionally, a JSON body; the Bot receives the body with the routine instruction.”

文档说明 routine 由云端调度，可在笔记本关闭后运行，调度间隔至少五分钟。入站 webhook 接受 HTTP POST、Bearer key 和可选 JSON；200 表示接受并开始运行，不表示完成。每 Bot 最多 50 个 routine、每个保留最近 20 次运行记录；账户合计每小时 300 次、单 routine 200 次。文档列出的限流失败不自动重试，长时间无人使用可能暂停；每次执行消耗 Grok 用量。这里没有声明外发 webhook、恰好一次执行或持久队列保证。

### Grok Bot 的工具与状态

来源：[Use the computer and apps](https://docs.x.ai/grok-bot/computer-and-apps)，页面标记更新日期 2026-10-28；公开网页读取成功。

实际短引文：

> “files, sign-ins, and browser sessions persist between tasks.”

> “by URL or by a command that runs on its computer”

文档确认云电脑有命令行和文件系统，可添加 URL 型或本机命令型 MCP。文件和命令行凭据由同账户 Bots 共享，不能当作 Bot 间隔离。Recover/Reset 会中断运行，安装的应用、软件包和部分最近修改可能丢失；已保存文件可恢复。这支持“保存本地游标/去重账本”的可行性，但不是 SQLite 提交跨云电脑重建零丢失的保证。

补充：[Grok Bot 101](https://x.ai/bot/guides/grok-bot-101)，发布日期 2026-09-11；公开网页读取成功。原文为：

> “Grok Bot supports the same MCP servers, plugins, and skills as Cursor.”

这是产品级能力说明；尚不能证明 Waypost 的具体 MCP transport、Bearer header 和 routine 场景已经兼容。

### Grok.com Automations 与 Custom MCP

来源：[Automations in Grok](https://x.ai/news/grok-automations)，发布日期 2026-07-16；公开网页读取成功。

实际短引文：

> “every run is a fresh request: same instructions, current data.”

该产品支持定时或邮件触发，指令可选择 connectors/skills，每轮创建对话并保存运行历史。不能据此假定上一轮模型上下文就是下一轮的可靠游标或幂等记录。

来源：[Connectors](https://docs.x.ai/grok/connectors)，页面标记更新日期 2026-10-10；公开网页读取成功。

实际短引文：

> “Enter the MCP server URL and complete any required authentication.”

文档允许自定义 MCP，并要求 Grok.com 的服务端可通过公网访问。文档没有在此页明确列出 Waypost 所需自定义 Authorization header 的配置细节。普通对话可调用 connector 与自动任务支持 connectors，两者为接入提供依据；特定自定义 MCP 是否在每轮自动执行中可用仍需账户实测。

### Grok.com Automations 的另一种 webhook 协议

来源：[Webhook Triggers](https://docs.x.ai/grok/automations/webhooks)，页面标记更新日期 2026-08-17；公开网页读取成功。

实际短引文：

> “Grok verifies requests using the Standard Webhooks signature format.”

> “A valid request returns HTTP `202 Accepted`.”

该接口用 HMAC-SHA256 签名原始 body，要求 `webhook-id`、`webhook-timestamp`、`webhook-signature`，密钥为去掉 `whsec_` 前缀后 base64 解码的字节；不是 Grok Bot 的 Bearer 接口。其示例 body 是业务事件 JSON，没有 `prompt` 或 `message` 字段。文档列出 1 MiB 上限，时间偏差超过五分钟拒绝；202 仅确认异步接受。虽然有 delivery ID，未声明重复 ID 的去重时限或恰好一次保证，也未公开响应 body/run ID。

### Grok Bot webhook 的精确接入边界

交叉来源：[Cursor 官方 Routines](https://cursor.com/help/grok-bot/routines)，由 x.ai routines 文档直接链接；公开网页读取成功。其完整短句为：

> “You can send a JSON body. The Bot receives that body with the routine instruction.”

| 项目 | Grok Bot routines 文档能支持的结论 |
| --- | --- |
| 请求 | POST 到 routine 界面提供的完整 URL，使用该 routine 的 Bearer key。 |
| Body | 可选 JSON；没有公布 schema 或要求 `prompt`/`message` 字段。不能将“可选 JSON”扩张为所有类型、任意大小的保证。 |
| 成功 | 精确 HTTP 200，表示调用已接受且开始一轮，不表示完成。 |
| 响应 body | 未公布 JSON schema、run ID 或查询 API；adapter 不能要求返回自定义 `{ok:true}` 才算成功。 |
| 重试 | 未公布 idempotency key、重复投递去重或响应丢失核对协议。未知结果应保守保留，不能盲目再发。 |
| 动态输入 | Body 交给 Bot，与 routine 固定指令同时出现；这不是将 body 升格为受信授权的承诺。 |

两种 webhook 必须显式区分：Grok Bot 为 Bearer + 200；Grok.com Automations 为签名 + 202。一个通用 Bearer adapter 不能宣称支持后者。

## Grok Bot 接入指南草案（未执行）

1. 在真实 Grok Bot 中配置专用 routine，使用账户安全入口保存其 URL/key；不要把密钥放进消息正文。
2. 固定 routine 指令绑定已批准的 Waypost 服务、空间和 Consumer，明确只将 webhook JSON 当作查询提示。不要执行 payload 中的指令、URL、命令或权限声明，也不因 payload 自称某个发送者而扩大授权。
3. 本地桥只发消息引用和稳定关联 ID；Bot 用自己预先配置的 Waypost 连接重新读取并验证消息，去重账本不能仅靠模型记忆。不要给 Grok webhook 携带 Waypost 管理凭据。
4. 先用合成接收端验收 POST、Bearer、200、超时与响应丢失。真正 Grok 验收需另外确认一次安全输入、实际运行记录、工具调用及重复触发行为；本次没有执行。
5. 200 只记录通知已接受。真实内容和处理结果按 Waypost 自己的收取／处理回执规则记录。一次通知失败不能解释成原消息丢失，未知投递不能自动作为未送达重发。

### 无人值守权限边界

来源：[Approvals, security, and privacy](https://docs.x.ai/grok-bot/approvals-security-and-privacy)，公开网页读取成功。

实际短引文：

> “When a routine, an incoming message, or other background work raised the card, it expires after 30 minutes.”

工具调用仍可能因审批等待而停止，连接成功不代表 routine 可以无条件完成写入。Waypost 的授权和 Grok 宿主对每项动作的批准属于不同边界。

## 已证实、推论和未知

| 问题 | 判断 |
| --- | --- |
| 宿主能否按时唤起 Bot 查询？ | 官方支持。需要创建并启用 routine，模型不会因拥有 MCP 自动后台轮询。 |
| 能否使用 HTTP/MCP？ | Bot 支持 MCP URL/命令及命令行；routine 可调用连接工具。Waypost 认证配置和实际例程调用尚未实测。 |
| 是否支持自定义 webhook？ | 已证实 Grok Bot 入站触发；不能等同于外发完成通知、通用 webhook 服务或投递幂等。 |
| 是否有持久状态？ | 有跨任务文件及运行历史；是否有 routine 专属事务状态、重叠执行互斥、可靠游标存储，未找到保证。 |
| 能否完全替代本地桥？ | 低频查询可能可以；秒级通知、未知投递核对和严格恢复语义尚不能确认。 |
| Grok.com 与 Grok Bot 是否相同？ | 官方文档分别描述；不可互换其限制与接入方式。 |

建议的验证顺序是：在实际账户确认产品入口；用已有受限连接完成一次只读 `describe` 和 `inbox`；验证重复触发不会重复处理同一 item；再检查一次真实计划运行及失败后的恢复。只有在结果和必要内容可靠保存后，消费者才可提交 `received`；routine 显示成功或 webhook 返回 200 都不能代替 Waypost 的处理回执。

本次未确认：Waypost Bearer 在实际 Grok 自定义 MCP 的可配置方式；routine 是否允许当前连接全部工具；cron 精度和漏跑补偿；并行重叠的互斥；webhook 重复调用与响应丢失后的查询 API；本地状态在重建后的完整性；用户当前计划和功能开放情况。应明确标为待验收，不能用其他账户经验补齐。

## 访问记录

上述正式页面均由网页工具实际打开并读取正文。Cloud env 另对 x.ai 的 routines、computer-and-apps、connectors、grok-automations、approvals-security-and-privacy 五个 URL 发起只读 GET，均返回 HTTP 200、`text/html; charset=utf-8`。初始猜测路径 `/grok-bot/connectors-and-apps` 和 `/grok-bot/the-shared-computer` 被工具报告不可访问；随后从官方 routines 页面导航找到真实路径 `/grok-bot/computer-and-apps`。未将猜测路径或搜索摘要当成能力证据。

没有对 Grok 或 Waypost 进行本次研究以外的外部写入，也未在报告中保存任何连接凭据。
