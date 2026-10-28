# v0.1 试用验证记录

验证对象是本次 Rust 实现与 [PR #3](https://github.com/mainline-org/waypost/pull/3)。它提供可以运行的中心层、参考客户端和 demo；验证没有将参考助手身份当作外部产品已安装的连接。

## 自动化检查

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo build --locked
python3 -m unittest discover -s tests -p 'test_*.py' -v
cargo clippy --no-default-features --features cloudflare --target wasm32-unknown-unknown --locked -- -D warnings
```

原有 19 个 Rust 测试覆盖以下公开行为。其中 Blob 字节、随机记忆操作和独立回执三类 proptest 生成器，每类运行 12 组；这不是穷举或正确性证明。

| 范围 | 验证内容 | 测试 |
|---|---|---|
| 消息 | 同键稳定结果、重复内容冲突、线程授权 | `tests/mailbox.rs` |
| Consumer | 独立位置、ACK 幂等与单调推进 | `tests/receipts.rs`、`tests/properties.rs` |
| Blob | 封存、实际长度/摘要、不可变字节 | `tests/blobs.rs` |
| 记忆 | snapshot/delta、完整历史与 Tombstone、CAS、无变化、不混合分页版本 | `tests/memory.rs`、`tests/memory_feed.rs`、`tests/properties.rs` |
| MCP | 11 个工具、初始化协商、通知、公开调用与服务规则一致 | `tests/mcp.rs` |
| Dashboard | 管理会话、退出、CSRF/CSP、检查不推进 ACK | `tests/dashboard.rs` |
| 授权 | 观察权限不读取私有记忆/未分享 Blob，委托写不能读取完整私有 manifest，凭据轮换恢复原回复 | `tests/observer_privacy.rs`、`tests/delegated_memory.rs`、`tests/token_rotation.rs` |
| 隐私 | 选定发信/收信 Agent、正文与资料脱敏、二进制阻止、输出预算、稳定拒绝、策略变化后的成功/拒绝竞态 | `tests/privacy.rs`、`tests/privacy_race.rs`、`tests/submission_failures.rs` |

6 个 Python 测试启动实际原生 HTTP 服务，覆盖：已提交 ACK 的响应丢失与重启；Actor 出站队列在权限丢失和 Consumer 轮换后恢复；固定版本原文件导出；关系参数重放及请求冲突；记忆、ACK 和回执关系查询；旧试用版 JSON 队列的事务升级。

[GitHub Actions](https://github.com/mainline-org/waypost/actions/workflows/ci.yml) 运行原生检查、Wasm 检查、真实 Docker 构建/运行，以及独立 Workerd + D1/R2 runtime 检查。原生与 Worker CI 均运行官方 MCP SDK 和完整 demo；Worker 另检查就绪、会话、Origin 和实际限速。具体交付提交的结果以 PR 对应检查为准。

## 实际试用

- 官方 MCP SDK 在原生服务和本机 Cloudflare Worker 上完成初始化、发现 11 个工具、投递、同键重试与准确正文读取。
- 完整 demo 在本机 Worker + D1 + R2 上执行成功，包含双向通信、隐私过滤、记忆修订与删除、先存 SQLite 后 ACK、processed、重启保留未处理项和完整资料包。
- 隔离 Chrome 验证登录、新建空间、接入 Agent、保存隐私策略、预览和退出；未出现页面异常。桌面与 390px 页面已检查。
- 另模拟服务已经提交、浏览器丢失空间/Actor/凭据创建响应。重试没有重复创建身份；无法重取原始凭据时撤销旧凭据并只保留一枚有效替代凭据。
- Standards 与 Spec 两路只读复核发现的关系化队列和旧策略拒绝竞态已修复并复核关闭。通用 Skill 的官方结构校验和四个前向使用场景检查通过。

## 验证边界

首轮验证使用真实本机 Workerd、D1 和 R2 绑定；后续已经发布独立 Cloudflare 生产实例，运行步骤与版本追溯见 [生产运行](production.md)。本机与线上示例验证的是明确的功能场景，尚未做容量或生产负载基准。原生/Worker 上限见 [部署说明](deployment.md)。

外部助手仍需要用户配置 MCP 和私密凭据；参考客户端按手动调用运行，任务调度与模型执行由宿主提供。服务会检查已配置的本地隐私规则，规则覆盖范围见 [RFC-0003](rfcs/0003-agent-privacy-policies.md)。

## Cloudflare 生产验收（2026-10-12）

生产入口：<https://waypost-production.christopherwuy.workers.dev>。Worker Version 为 `79117c74-ec90-4b41-8864-3b397e1a3d28`；独立 APAC D1/R2 已创建，六个迁移成功，R2 公开 URL 关闭。

已在真实 HTTPS 入口通过以下检查：

- 健康、禁止缓存/CSP/HSTS、production 标记、管理员鉴权的 D1/R2 就绪。
- Origin 拒绝、Secure/HttpOnly/SameSite 管理会话、CSRF 与退出后失效。
- 官方 MCP SDK 的初始化、11 个工具、实际投递、同键稳定结果和完整正文读取。
- 完整双向通信与记忆示例：snapshot/delta/Tombstone、隐私报告、资料 SHA-256、可靠保存后 ACK、显式 processed、重启恢复和完整 SQLite/原文件导出。

参考客户端曾因默认 Python User-Agent 收到 Cloudflare 1010；改为明确的 Waypost 产品标识后，上述真实流程通过。验收脚本见 `scripts/verify_deployment.py`，追加限速检查会消耗检查者的短期 IP 预算。

## 加密、用户隔离与评审改进（2026-10-13）

本次新增 15 个安全回归：`tests/security_hardening.rs` 的八项检查覆盖必需行冲突整体回滚、清理预览/权限/租约/迟到写入、独立游标密钥、空间内序号和路由边界；`tests/encryption_isolation.rs` 的七项检查覆盖消息/附件/记忆字段的实际密文、正常读取、密钥轮换、错钥/密文替换、跨用户访问、用户会话轮换、明文严格模式、可重复迁移和 CLI 运行锁。

已通过原生 fmt/clippy、34 个 Rust 测试、六个真实 HTTP Python 测试，以及 Wasm clippy。独立本机 Workerd/D1/R2 已应用八个迁移，官方 MCP SDK、完整加密示例和七项就绪/会话/Origin/限速验收通过。另直接检查本机存储：四条消息的 D1 主题均为认证密文，九个 R2 对象以加密格式保存；导出仍返回准确原文件。

本段记录最初的本机验证。接入工作开始时，生产已经运行八迁移加密版本；当前九迁移发布与真实验收见本文最后一节和 [生产运行](production.md)。升级旧实例仍需配置加密 keyring、应用迁移并迁移旧内容。尚未做生产负载、CPU/容量基准或外部密码学审计。SQL 已对关键行增加类型解码、收拢认证/回执与插入语句，其余领域语句仍使用绑定参数的 SQL。

## 助手信箱定位与按需接入（2026-10-13）

新增 `tests/assistant_inbox.rs` 两项回归：信箱按当前空间的用户入口筛选，保留全空间消息检查并拒绝游标跨查询复用；仅发信连接能投递和恢复自己的结果，不能收信、上传、写回执或向未授权收件人发送，撤销后失效。管理 token 检查返回真实 scope，排除原始凭据和摘要。

36 项 Rust 测试、原生和 Wasm clippy 已通过。另使用 JSDOM 与隔离的真实本机 HTTP 服务执行登录、默认接入、首次报告、恶意正文纯文本显示、显式六项能力签发、资料集合创建、到期选择、关闭凭据详情和退出清理。默认接入的实际请求只有 `message.send`，没有创建资料集合。官网三个示例的选择、ARIA 与键盘切换检查通过；17 页静态链接、锚点和公开文档快照检查通过。

本轮 Browser 未连接，DOM 检查不等于浏览器视觉验收；新版响应式布局尚未做实际浏览器视口检查。此段是当时网站更新的记录，当前 Dashboard 与管理检查接口已随后续生产发布升级。任务授权与人工批准仍未实现。

## 邀请与主助手接入验证

在独立 worktree 实现，避免覆盖并行 i18n。新增五项 HTTP 回归覆盖默认投递目标与发信范围、主助手选择的版本检查与空间限制、一次性领取与个人会话、邀请撤销/替换/到期/所有者变化、使用申请的隐私与幂等。

44 项 Rust 测试与原生、Wasm clippy 通过。Dashboard DOM 回归在每页 20 条的公开 HTTP 契约下复现并修复了权限面板故障，也验证了后续资料页被保留。真实本机原生服务与 Workerd/D1/R2 的官方 MCP 客户端完成接入助手投递、同键恢复、主助手可靠保存后 received、汇报用户与 processed，发信连接无法读信箱。

两个运行时都通过真实 HTTP + DOM 的申请、审批、邀请领取、清除 URL 片段、个人空间登录、主助手连接预设和接入助手默认投递测试。直接读取隔离 D1 的匿名统计确认申请联系方式为密文。验收模拟协作角色，没有执行实际餐厅预订，也不宣称已验证 Muse 等第三方产品。

双轴评审基线为 8840a0a。评审后的失败测试覆盖两空间同时审批同一申请、同权限换连接后默认收件人重试、联系方式轮换后移除旧密钥、领取后空间加载失败，以及退出与邀请响应在同一回合完成。上述问题均先复现，再修复；前三项增加 Rust 回归，后两项增加 DOM 回归。私密邀请与连接凭据只在原会话展示，领取后的个人凭据先显示，再加载空间。

脚本为 `examples/mcp-client/handoff.mjs`、`examples/mcp-client/onboarding-ui.mjs`，已加入原生与 Worker CI；Worker 启动等待涵盖首次 Wasm 构建，超时明确报告失败。实际 CI 发现领取后空间尚未加载时能够点击接入，已补齐入口等待与空间检查；修复后的 native、Wasm、container 和真实 Worker 四项 CI 全部通过，并在 PR #6 合并 main。

## 九迁移生产验收（2026-10-13）

生产 Worker Version：`35877fca-1f73-4eb8-8cfa-7085c70728af`，运行时代码 `9d989ff`。`verify_deployment.py` 验证真实 HTTPS 安全头、九迁移 D1/R2、Origin、CSRF 与退出失效。

官方 MCP 客户端在生产隔离空间验证同请求稳定结果、接入助手只发信、主助手先保存后 received、向用户汇报与 processed。真实 HTTP + DOM 验证从匿名申请、运行者审批到个人空间领取，以及主助手与接入助手的权限配置。生产网络下的模拟页面关闭等待尚未完成的请求，完整验收进程正常退出。

本轮没有执行真实 Muse 产品集成或实际餐厅订单，没有进行浏览器视觉与负载测试。并行 i18n 尚未提交，本次没有覆盖或发布其未提交文件。

## Dashboard 与主页交互验收（2026-10-14）

PR #8 已合并主线，原生、Wasm、container 和真实 Worker 四项 CI 全部通过。45 项 Rust 测试、原生与 Wasm clippy 通过；本轮另通过五项 Dashboard DOM 回归，覆盖登录重置的明确确认、主助手停用提示和敏感详情清理。

隔离 Chrome 验证了真实 CSS 布局：1280×640 和 1024×480 的侧栏与视口等高，导航独立滚动，退出按钮始终可见；390px 和 320px 页面按正常页面滚动，没有横向溢出。管理入口仅服务运行者可见，邀请说明对方获得独立信箱，登录管理先说明目标空间与重置后果。

主页在 1280px、390px、320px 下验证了信箱、助手、资料三个入口，助手角色选择、附件跳转、资料历史版本和键盘切换。示例只在浏览器内运行，不连接真实账户。布局验收使用隔离浏览器和模拟 API 响应；另用真实本机原生 HTTP 服务完成申请、审批、邀请领取、个人登录、主助手配置，以及仅发信助手投递、主助手保存后 received、向用户汇报与 processed。

Standards 复核补齐安全文档的登录状态字段说明；Spec 复核修正停用主助手后仍要求等待的提示。说明明确保留已有连接的收件人，选定主助手不自动授予权限。23 页静态链接与 13 份公开原文快照检查通过。未执行实际餐厅订单、第三方助手安装或负载测试；并行 i18n 文件保持原样。

## 营销展示与来信接入规划（2026-10-14）

README 缩为 62 行，主页补充 Apache 2.0 开源、自行运行、托管邀请及来信产品关系。四张配图从实际 Dashboard 源码在隔离 Chrome 中截取，使用纯演示 API 数据；三张用于主页，信箱图用于 README。没有使用生产账户内容或凭据，图片不表示真实来信已经接入。

真实 Chrome 在 1280、768、390、320px 下通过首屏、开源/托管卡片、图片加载、来信规划标识、资料版本与键盘操作检查，没有横向溢出。五项 Dashboard DOM 回归、24 页静态链接、14 份原文快照与 JavaScript 语法检查通过。全新加密原生 HTTP 运行时完成邀请领取、个人登录与权限配置；官方 MCP 客户端完成仅发信交付、主助手保存后 received、向用户汇报与 processed，以及同请求恢复。

来信研究核对了用户说明、来信私有源码和 Waypost 公开契约。结论是当前远端文档接口不能直接替换为 Waypost，需要独立原生连接器；私人记忆、共享版本和执行批准分别设计。接入提案保留尚未集成的状态，商业收费归属也保持未定。Spec 复核修正了换空间/Consumer 不自动撤销旧连接的表述，Standards 复核确认公开材料无私密路径或凭据。

本轮未完成来信应用集成，也未用生产业务库写入新的验收数据。实际来信通知、重启恢复与不同模型的执行隔离仍需在接入实现时验证，验收要求见[来信接入提案](design/0005-laixin-waypost-integration.md)。

## Cloudflare 生产只读备份与本地恢复核验（2026-10-15）

`scripts/verify_cloudflare_restore.py` 对生产只读备份并在本地恢复验证，全程零生产写入（D1 `--remote` 导出与 R2 列举/下载均为读操作；未在生产空间创建测试内容）。生产库共 5 个空间、9 条消息、5 个资料对象、4 个资料集合、2 个版本、4 个版本项；R2 共 14 个对象 5905 字节，逐字节下载后大小与库内记录的 blob 校验值全部一致，消息、上传与资料链的引用闭包成立，无悬空暂存引用。

快照恢复到全新本机目录并在本机起服：管理会话登录成功，空间计数一致；9 条消息逐条解密读回（含 7 条旧明文与 2 条密文主题），4 个资料版本项逐项读回并定位来源，附件与资料字节与快照一致。生产消息无附件挂载（`message_attachments` 为空），附件字节核验覆盖 5 个资料对象。加密包为 AES-256-GCM，随机备份密钥与 JSON 报告同目录保存，权限分别为 `0600` 与 `0700`，报告记录包摘要；密钥只经环境变量传入本机服务，从不写入恢复目录或日志。

恢复中发现并已在脚本内处理的三件事：D1 导出只带 Cloudflare 的 `d1_migrations` 台账，必须按同名迁移文件翻译为原生 `schema_migrations` 版本后才能启动，台账不一致时拒绝恢复；生产库新旧字段并存，本地恢复与生产一致开启明文兼容，否则旧行读取失败；此前一次失败源于系统 Node 低于 Wrangler 要求的 v22，脚本现会主动保证 Node 22+。快照边界为“D1 先导出、再完整列举下载 R2”，没有全局写冻结。本轮未改动生产数据与配置。

## Dashboard 自助编辑与收尾核验（2026-10-16）

PR #14（`f5415ba`）已合并自助接入状态、资料编辑、固定版本 ZIP 导出和原生离线备份恢复；PR #15（`926601d`）补齐网站与 Dashboard 中英文。本节区分这两次合并前保存的实测记录，以及本次收尾新增的回归。

原生与本机 Workerd/D1/R2 的真实 HTTP + DOM 均通过邀请领取、个人登录、权限配置、真实投递状态、文本编辑保留历史、固定版本原始字节导出、ZIP CRC 与安全路径、新报告提示和退出。官方 MCP 客户端另完成只发信助手交付、主助手可靠保存后 received、汇报用户与 processed。角色由测试客户端模拟，这些结果不表示真实模型已经完成主子助手协作。

已保存的隔离 Chrome 实测覆盖 1280×640、1024×480、390×844、320×640：侧栏退出可达，无横向溢出，实际编辑、ZIP 下载与退出清理通过。实现阶段的 55 项 Rust 测试及原生/Wasm clippy 已通过；Cookie、加密和 32 项集合下，两个保存 HTTP 阶段分别使用 47 和 32 条 SQL，没有超过 Worker Free 的单次查询预算。原生停服备份恢复验证消息、附件和两个历史版本的准确字节，以及在线备份拒绝、缺钥和错钥行为。

本次新增三项 CLI 回归，通过临时 OpenCode HTTP 状态夹具与真实本机 Waypost 服务验证：空 MCP inventory、仅其他服务器已连接都必须失败，只有具名 Waypost 连接状态可通过。HTTP 200、host location 或空列表均不是 MCP 握手证据。既有真实 OpenCode 尝试未通过连接检查；真实模型主子助手协作仍未通过，不将标准 SDK 的成功替代为 OpenCode 产品集成，也未启用付费后备模型。

另新增四项 DOM 回归，先复现保存期间仍可输入导致丢字的问题，再使编辑框在上传准备和版本发布期间保持只读。保存成功、存储错误、CAS 冲突，以及保存期间返回后继续修改均覆盖；迟到响应不会覆盖新打开的草稿，失败后恢复编辑。完整 Dashboard DOM 组共 14 项通过。指南同步最新内容比较、返回列表恢复草稿和明确核对后变更新基线的操作。

本节依据合成数据的本机记录与新增回归，没有读取生产用户数据、执行生产备份或复验上一节的生产恢复记录。本机恢复结果不代表停写一致的完整生产灾备演练；生产可用性、容量、密码学审计与第三方模型协作仍按各自边界验收。


## 连接权限编辑与本地桥（2026-10-28）

设计与独立审查见 [方案](design/0006-local-bridge-and-connection-permissions.md) 和 [评审记录](reviews/2026-10-28-bridge-permissions-design.md)。由独立子代理审查，后端和 Dashboard 子代理及 Terra 桥接实现，主代理在 cloud env 集成、构建、部署和验收。

### 实际发布

生产入口 `https://waypost.miles1150.top`，Worker `waypost-production`。保存生产 D1 导出后应用兼容迁移 `0011_token_permissions.sql`，保留原 D1/R2、限速绑定与三项生产 secrets。最终 Worker Version 为 `b7e041a7-28f5-40e0-b47c-c368f54180b0`，Deployment 为 `c5638ef2-6945-4e52-9c37-b78fde74b3b6`，100% 流量。原版本 `91925311-7b67-4226-8898-1a7513baa469` 保留用于回滚。

首次发布 `7697b4ad-2688-4ad8-b24b-d3eb73167492` 后，追加审查发现所有者授权需在提交事务内再次校验，立即回退旧版；补上精确凭据/session 校验、撤销/轮换/logout 与真正并发 CAS 测试并独立复核后，才发布最终版本。审计表为添加式迁移，回退代码没有删除它。

### 检查与验收证据

- 全部 native Rust 测试通过；最终权限补充测试包括 4 个模块内测试、4 个接口测试。
- native 与 wasm strict Clippy、格式和 diff 检查通过；最终 owner-fence 变更完成 native Clippy 和实际 wasm release 构建。
- 18 项 Dashboard DOM 测试、11 项 Python 测试通过。
- bridge 的 9 项故障/权限/去重测试与 strict Clippy 通过；构建 Linux x86-64 release 二进制。
- Cloudflare dry-run、实际版本上传通过，最终 Worker 启动时间报告 2 ms；这不是请求 CPU 压测。
- 最终线上 Dashboard 与 HTML 中引用的四个 fingerprinted JS/CSS 资源全部 HTTP 200。
- cloud env 使用真实 HTTPS HTTP/MCP 和 D1，在独立合成 Space 执行旧权限模型脚本 `scripts/verify_bridge_permissions.py`（本轮已由 `scripts/verify_space_membership.py` 替换；此处保留当时验收事实）：同一 bearer 增减权限、历史读取、身份保留、自提权拒绝、CAS、相同请求重放、MCP describe/inbox 全通过。
- 同一验收使用实际 release bridge 二进制与模拟 Codex CLI，确认仅一次通知、重启去重、空 feed、权限视图变化重扫不重复通知。
- 修复 cloud env 实测发现的 TLS `UnknownIssuer`：bridge 改用系统 CA 根，支持 `SSL_CERT_FILE`/`SSL_CERT_DIR`，始终保留证书验证。随后两次真实 HTTPS 空轮询以及完整集成验收通过。
- 完整验收曾遇到一次网络 URLError，后续完整重跑通过；不将该失败计作通过。

合成测试通过独立 owner 夹具初始化，不读取或更改用户消息。脚本撤销自身创建的测试凭据、停用助手；最终清理覆盖整个指定合成 Space，包括所有测试 token、Consumer 与 owner 凭据。保留合成消息和审计用于追溯。部署临时 Cloudflare token 在发布完成后撤销。

### 验收边界

真实 Codex 官方 CLI 已存在于 cloud env，但没有指定可用的真实目标会话，因此不声称实际模型已被唤醒或完成任务。Linux 实际运行；macOS 安装模板/构建矩阵已提供，未在真实 macOS 或 hosted Actions 验收。独立官网指南仅更新源码，未发布其另外的托管站点。

空轮询没有新 feed 项或队列调用，客户端路径只执行读操作；尚未以 Cloudflare D1 billing counters 单独量测零写入，也未进行大量不可见记录扫描或请求 CPU 压测。五设备每 30–60 秒轮询的预算属于设计估算。


## 通用参与方与唤醒适配器（2026-10-28，后续本地实现）

本轮在 `5506799` 基础上继续原工作区，先完成 [0007 设计](design/0007-participants-and-wake-adapters.md) 和[独立审查](reviews/2026-10-28-participant-adapters-review.md)，再由 Terra 实现通用适配器，由另一子代理实现本地集成验收。未修改服务端协议、数据库迁移、生产部署、凭据或网络设置；未合并或推送这些后续改动。

代码将公共 Config、扫描及通知账本与 `Codex` / `Webhook` 目标区分，Codex 进程与核对代码移入独立模块。Webhook 使用私密 URL/独立 Bearer 文件、引用 payload 和稳定 delivery_id；每次投递核对固定目标，公网 HTTPS 地址检查及 DNS 固定，禁止重定向，在无法保证固定目标的环境代理下发送前拒绝。只有显式 literal-loopback 测试配置允许本机 HTTP。旧平铺 Codex 配置与新版配置映射到原有八元绑定，不清空游标、accepted 或 unknown。`scan` 不投递；`status --items` 提供人工核对引用。桥不代发 received/processed。

主代理复跑桥的 15 项 Rust 测试通过，最终格式检查、strict Clippy、debug 构建、完整本地集成脚本和 diff 检查通过。测试覆盖旧配置兼容、权限和游标、sending 恢复为 unknown、只接受 userMessage 核对证据、socket/进程锁、webhook 地址/目标限制及重定向、稳定通知 ID。Codex 子进程输出增加 1 MiB 上限与共享截止时间，实测后代持有 stdout 不会使发送永久阻塞。

[本地集成脚本](../scripts/verify_participant_flows.py) 使用真实 native Waypost HTTP/MCP、临时 SQLite 与独立只读桥凭据，9 种参与方路由、13 项检查通过，并由非实现者独立复跑。覆盖持久保存后 ACK、稳定发送与 ACK 的丢响应恢复、定时处理者重新打开账本后不重复业务、回执不触发通知循环、webhook 接收后断连接进入 unknown 且重启不重发、显式重试保留 delivery_id、待通知记录撤权与恢复。通知和空轮询前后服务端所有应用表内容摘要相同。模拟业务只计算消息字符数，不能当作真实模型或外部动作完成。详细测试与局限见[验收报告](reviews/2026-10-28-participant-acceptance.md)。

Grok 官方文档已实际读取并记录于[调研](reviews/2026-10-28-grok-routines-research.md)：Grok Bot routine 支持 Bearer webhook 和定时执行，Grok.com Automations 使用另一签名协议，当前适配器不实现后者。未创建 routine 或调用真实 Grok webhook，未验证真实 Codex 会话、公网 webhook TLS、真实 DNS 重绑定、断电恢复或 Cloudflare 计费。当前 cloud env 依赖代理，公网 webhook 会按设计拒绝发送，不通过关闭代理来验收。GitHub Actions 已加入本地集成脚本，但未运行 hosted workflow。

## 空间成员模型（2026-10-28，本地实现，未部署）

按用户确认删除连接级消息、资料和附件授权，保留 Space 和管理边界；设计见 [0008](design/0008-space-membership.md)。独立 review 检查运行时已无旧授权表查询，并补管理身份撤销/会话竞争测试。迁移删除旧表会使旧 Worker 不兼容，部署说明已改为备份、停流维护、匹配版本部署与成对恢复；本轮没有执行生产迁移或发布。

验证记录：
- Rust 全量首轮 60 项通过、2 项旧附件保密预期失败；按新的空间共享语义修正后，附件、隐私、空间成员和路由定向 11 项通过。后续新增路由测试使 routing 共 5 项通过。
- 管理事务边界的并发 CAS、owner 凭据撤销、密钥轮换/session logout：3 项测试通过。
- 旧 f2/f3/m1 游标迁移与重扫：2 项通过。填充了凭据、到期/撤销、资料、附件、回执及审计的 schema-11 数据库升级：1 项 Python 测试通过，四张授权表消失而保留数据逐行一致。
- Dashboard jsdom：16 项通过。Python 全套 unittest：16 项通过（含 Consumer 7 项及备份/恢复、部署验证、旧库迁移），包括旧账本拒绝静默迁移且保留待处理和游标。
- `verify_space_membership.py` 使用真实 native HTTP/MCP、SQLite 和实际 bridge binary 验证无白名单双向收发、路由CAS/重放、管理隔离、Consumer绑定、撤销和重启去重。Codex CLI 为模拟。
- `verify_participant_flows.py` 使用真实 native HTTP/MCP 与临时 SQLite，9 种参与方收发组合、13 项检查通过；包括丢失发送/ACK响应恢复、webhook unknown不重发、路由变化保留游标、撤销阻止pending以及同身份替换凭据恢复。Webhook/Codex执行端为模拟。
- Native all-targets 与 Cloudflare wasm32 strict Clippy、格式和 diff 检查通过；修复了只在 Worker streaming upload 路径残留的旧scope检查。未声称运行了本轮生产 D1/R2、真实 Grok routine或真实 Codex会话验收。

空间内封存附件现在共享：发布过滤生成的脱敏副本不会阻止同空间成员凭原blob ID读取原件。隐私测试继续验证发布副本脱敏，不再错误声称原件对空间成员隔离。
