# 参与方适配器独立审查（2026-10-28）

状态：现状核查与 `0007` 独立设计审查通过，可进入实现及本地验证。本文不表示新适配器已经实现或验收，不授权部署或生产配置变更。

## 现状核查

核查对象是本仓库当前实现，包括 `0006` 已完成的本地桥和连接权限编辑。结论：webhook agent、既有 Codex 会话和 scheduled agent 可以复用现有 HTTP/MCP 消息协议。宿主唤醒、运行时和调度属于参与方适配，不能从消息发布或通知接受推断业务执行成功。

| 约束 | 已有实现和依据 |
| --- | --- |
| HTTP/MCP 使用同一业务语义 | `src/service/mcp.rs:108` 的 send/message_get/inbox/ack/status 直接调用服务方法。无需为三种参与方新增一套服务端任务协议。 |
| 提交幂等身份 | `src/service/mailbox.rs:9`、`:29`、`:88`：按 Space、Actor、operation、request_id 保存提交；同键不同规范化内容冲突。不是按 token 或 Consumer 去重。 |
| 发送超时恢复 | `src/service/mailbox.rs:578`：status 查询本 Actor 的提交，返回提交状态和已提交结果。它不是另一个 Agent 的执行状态查询，也不是全文消息搜索。 |
| 收件人与消费进度不同 | `src/service/receipts.rs:24`、`:263`：消息交付给 Actor，inbox/ack 必须使用当前凭据绑定的 Consumer。多 Consumer 独立回执。 |
| inbox 是增量 feed | `src/service/receipts.rs:273`：cursor 为 null 时从头读取。ACK 不删除或隐藏旧项，不能把 inbox 当作仅返回未处理消息的任务队列。 |
| 页项不是完整正文 | `src/service/receipts.rs:278`：返回 items/next_cursor/has_more；item_type 包括 message、memory_revision、receipt。消息项仅含摘要，需 message_get 获取正文。 |
| 游标绑定读取范围 | `src/service/mailbox.rs:500`：f3 绑定 Space、Actor、Consumer、视图版本、过滤器和有效读取权限。写权限变化不改变 f3；读取范围变化触发 CURSOR_SCOPE_CHANGED，需要重扫并按稳定 item_id 去重。旧 f2 游标仍受完整授权指纹约束。 |
| 正文访问和撤权 | `src/service/mailbox.rs:461`：message_get 要求读取/观察权限及生产者或收件人关系；`src/service/mod.rs:316` 的 authority_guard/current 再检查凭据、Actor 和视图版本及撤销/过期状态。通知引用不构成读取授权。 |
| 回执只有两阶段 | `src/domain.rs:102`、`src/storage/queries.rs:52`：received/processed 单调推进，可以直接 processed。服务端接受消费者声明，不证明外部工具或业务动作成功。 |
| 回执不会形成无限回执链 | `src/storage/queries.rs:56` 排除为 receipt 项再发布 receipt 事件；`:60` 将原消息的回执交付给原生产者。对应测试 `tests/receipts.rs:6`。 |
| 自发消息和自动回复边界 | `src/service/mailbox.rs:441` 只向配置的收件 Actor 写 feed_recipients，不自动抄送生产者。但获准自发自收仍可能出现，服务端没有通用自动回复预算；适配器不能默认对每个输入都自动回复。 |
| 回复需要明确收件人 | `src/domain.rs:178` 要求 in_reply_to 显式给 recipients；`src/service/mailbox.rs:230` 核对原消息和会话，`:267` 核对参与者关系。正文中的地址或任务引用不是授权。 |
| 服务端没有 webhook 推送 | `src/service/mod.rs:352` 返回 webhook_events:false。只能由参与方主动读，或由本地桥调用配置好的宿主 webhook；不能把通知适配器描述为服务端新增推送订阅。 |

### 三种参与方如何复用

- **Webhook agent**：若接收外部 webhook，适配器将稳定外部事件身份转换成稳定 Waypost request_id，调用 send。若宿主只提供被动唤醒 webhook，由本地桥读取 Waypost 增量并通知固定宿主端点；宿主自行获取获准正文。宿主端点返回 2xx 只能证明通知接受，除非它另有明确、经过验证的交付协议。
- **既有 Codex**：保留固定会话通知适配；实际会话通过现有 MCP 获取消息、记录回执和发送结果。本地桥保存引用时不写 received/processed。
- **Scheduled agent**：定时运行的客户端可以直接 describe/inbox/message_get/ack/send。它必须持久保存游标、处理记录和拟提交请求；只提供临时上下文、每次重新开始的定时模型调用不足以保证恢复。服务端 status 只能核对自己的提交。

### 设计必须保留的验收

1. 同事件重复提交和发送响应丢失只发布一次；恢复保持同一 request_id 与完整请求参数。
2. 同 Actor 的两个 Consumer 独立读取、独立 ACK；不能代写另一个 Consumer 的回执。
3. processed 后 cursor:null 仍读到旧项，客户端去重阻止重新执行。
4. 多页、空页、重启和读取权限扩大后的重扫不重复执行旧消息、不漏掉新可见历史。
5. 通知后撤权时，正文读取被拒绝；通知缓存不绕过当前授权。
6. receipt、结果通知、自发自收和 webhook 回调不被统一解释成新的执行请求，避免自动回复循环。
7. 三种参与方分别验证收取、持久保存、received、处理结果、稳定结果 send、processed 的恢复；只保存引用的桥不声明收取正文。
8. 区分 Waypost committed、Codex queue accepted、webhook accepted 与业务执行结果，不以通知成功推断模型已执行。

## 设计审查

审查对象：[0007 通用参与方与宿主唤醒适配器](../design/0007-participants-and-wake-adapters.md)。审查结论：**通过，可开始实现及本地验证；无剩余设计阻断项。** 实现验收必须逐项证明以下约束，不以设计通过替代代码审查。

| 审查项 | 结论与实现约束 |
| --- | --- |
| 服务端复用与职责 | 三种接入方式复用现有 HTTP/MCP。宿主适配不新增服务端任务、调度或连接身份模型。 |
| Webhook SSRF | 正式路径仅公网 HTTPS、无 URL 用户信息/query/fragment、无重定向；DNS 所有结果均需获准，实际连接固定到已验证地址，保留原 Host/SNI 和证书校验。不能只做一次字符串或 DNS 预检查。 |
| 代理路径 | HTTP 库的本地 DNS override 不证明代理端 CONNECT 目标已固定。若有效环境代理无法保证该约束，则发送前明确拒绝，不关闭远端代理。代理判断需要覆盖库实际支持的 HTTPS_PROXY/HTTP_PROXY/ALL_PROXY/NO_PROXY 及大小写变体。 |
| 同 binary 本地验收 | 接受私密配置中默认关闭的 allow_loopback_test。true 时只允许 literal 127.0.0.0/8 或 ::1，拒绝 localhost/DNS/其他私网/metadata；IPv4-mapped IPv6 明确拒绝或规范化后按相同规则检查。仅本机测试 HTTP 可直连，不修改 Waypost 或公网目标代理。该标记纳入完整目标 binding。没有来自外部消息的目标或开关输入，因此这一受限测试入口不构成新增外部 SSRF 路径。无需另建测试发行版。 |
| 配置与账本兼容 | 旧配置与新 Codex 配置归一化到精确旧八元 binding，避免无必要迁移。保留所有游标与 accepted/unknown，sending 恢复为 unknown。Webhook 独立版本化 binding；更换身份、目标或测试模式不能复用原账本静默重发。 |
| 凭据与目标 | Waypost token 与 webhook secret 分离；拒绝同路径或同值。URL 文件每次投递重新校验与既有目标指纹一致，secret 可轮换。接收器核对配置的 Space/Actor/Consumer，服务 origin 只取自身受信配置。 |
| 投递未知 | 发送前写 sending；只有明确 2xx 记 accepted。已尝试后的非 2xx、超时或崩溃保持 unknown，不因 Retry-After、Idempotency-Key 或缺少查询结果自动重发。 |
| Scheduled direct query | 可以不安装 bridge，但必须自行持久保存游标、业务去重、待处理记录和发送请求；调度需串行或有持久锁。无持久化宿主只提供只读查询。status 仅用于自己的提交恢复。 |
| ACK 边界 | 桥仅保存引用，任何 Codex/webhook 接受都不触发 received/processed。真实消费者保存正文/附件及待处理记录后才声明收取，记录处理结果后才声明处理。 |

审查中要求修订的两处已解决：草案状态不再错误地禁止已获授权的实现；原“仅注入测试 transport”改为受限、显式、同 binary 的 loopback 集成测试入口。设计者已收到代理细节、binding 和接收器身份验证的补充说明，实施者须同时遵守本审查约束。

后续代码验收应优先覆盖 DNS 重绑定、代理不能固定目标、URL 文件替换、secret/token 混用、旧账本未知状态不重发，以及无 bridge 的定时参与方重启恢复。公网 webhook、真实品牌宿主和本地模拟必须分别报告，不把模拟回执冒充真实宿主执行。

## 独立代码审查与本地复核

审查结论：**通过，未发现阻断当前本地交付的安全或恢复问题。** 对象为 `bridge/src/main.rs`、`bridge/src/codex.rs`、`bridge/src/webhook.rs`。桥的公共配置使用 `Adapter` enum，Codex 配置／投递／核对已独立成模块；公共 `send_pending` 负责状态转换，没有为 webhook 填造空 Codex 配置。

- Webhook 将规范化 URL 与测试模式绑定到独立账本；每次准备发送重新读取并核对目标文件。秘密文件限制大小、所有者、权限和普通文件类型；拒绝 token 同路径／同值。响应错误不输出目标或 secret，HTTP 重定向关闭，通知正文只有身份与引用。
- 公网 IPv6 只接受保守的全局单播集合，排除 mapped、文档、6to4、特殊用途段；IPv4 排除私网、CGNAT、链路本地、保留及文档段。域名所有解析结果必须合规，再交给 reqwest 固定地址；字面 IPv6 使用类型化地址避免方括号解析问题。这是代码路径审查，不是实际公网 DNS 重绑定测试。
- HTTP_PROXY、HTTPS_PROXY、ALL_PROXY 的大小写共六种变量均在公网发送准备阶段检查。实现选择更保守的行为：任一非空即拒绝，即使 NO_PROXY 排除该目标也拒绝。因此受代理控制的 cloud env 无法直接验证公网 webhook；没有静默绕过代理。显式 loopback 测试只影响该测试 webhook 客户端。
- 旧 Codex 八元 binding 保留；迁移测试证明 accepted、unknown 与游标保留，sending 变 unknown。发送前落盘 sending；发送后的数据库失败也不会使同进程再次选择该项。只有明确未启动进程才回 pending。Codex stdout 有大小及总超时界限，子进程后代占用 pipe 不能阻塞投递循环。
- `scan` 路径只扫描落盘、不调用适配器；非 message 项不触发通知；引用通知不 ACK。权限在实际投递前通过 describe 和 message_get 复核，授权恢复不会绕过本地去重。

独立执行结果：

1. `cargo test --manifest-path bridge/Cargo.toml`：15 项通过。
2. `python3 scripts/verify_participant_flows.py`：实际 native HTTP/MCP 与临时 SQLite 的 9 对参与方矩阵通过，覆盖响应丢失、稳定 ID、unknown 不自动重发、重启、分页、ACK、权限增减及 scan 边界。Webhook 和 Codex 宿主是明确标识的模拟接收器。
3. 在临时源码副本额外运行单线程独立测试：20 个 IPv4/IPv6 特殊地址全部拒绝；六种代理变量逐个设置、同时 NO_PROXY=*，均在 DNS／发送前明确拒绝。测试仅修改测试子进程环境，不修改运行环境网络政策；该临时测试未加入产品源码。

边界与非阻断限制：secret 轮换必须仍指向同一个逻辑接收者；同一 URL 上由 secret 选择不同租户的变化不能由桥自动识别，宿主必须核对配置的 Space/Actor/Consumer。公网 HTTPS 握手、真实 DNS 重绑定、真实 Codex/Grok 或定时平台执行未作端到端验收，不以本地模拟替代。现有公网地址判断有意保守，部分合法但特殊用途的地址也可能被拒绝。本审查没有部署或外部写入。
