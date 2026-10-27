# Waypost Cloudflare Workers 部署审查

审查日期：2026-10-27。对照清单在 `.agents/skills/cloudflare/`（上游 `cloudflare/skills` 的 `main` @ `86505e44f87d801aa1864a3c4109e9a8ae5c409f`）。重点阅读了 `workers-best-practices`、`wrangler`、`rules/workers.mdc`、`cloudflare/references` 里的 D1、R2、bindings、observability、secrets-store、waf，以及 `durable-objects`、`web-perf`、`turnstile-spin`、`workers-profiling`。

本次只做阅读。没有修改应用代码，没有对线上账户执行 Wrangler，也没有采集浏览器性能追踪或生产 CPU profile。当前线上地址是 https://waypost-production.miles1150.workers.dev 。所有者接下来会把生产主机名换成 https://waypost.miles1150.top ，并关闭 `workers.dev`。实际绑定以部署时的 `wrangler.production.toml` 为准；该文件被 `.gitignore` 排除，仓库里能核对的是 `wrangler.production.example.toml` 与 `DEPLOY-CLOUDFLARE.md`。下文凡是建议改文档或生产配置的地方，都按这个自定义域名来写，不再把 `workers.dev` 当作长期入口。

限额与价格以审查当日检索到的 Cloudflare 文档为准，不沿用技能正文里可能过期的句子。技能自己也要求以文档检索为准。

结论分四档：

- **符合**：当前实现满足该条，或该产品按技能的“不要用”条件正确地没有启用。
- **部分符合**：主路径做对了，仍有一个能在 Free 账户上变成故障、费用或性能问题的缺口。
- **不符合**：与可适用的条款相反，而且有具体后果。
- **不适用**：技能描述的是本部署没有使用的产品。

工作量按改动范围估计：**小**是一条配置、一条索引或一次控制台核对；**中**是一条请求路径或资源交付方式；**大**是换运行时或升级到 Workers Paid。

## 优先发现

1. **R2 是这套 Free 部署里会按量出账的产品。** Workers 请求超额、D1 行数超额、Free 观测额度用尽，文档写的都是拒绝或停收，不是继续扣费。R2 在免费额度之后按存储和操作计费，并且按计费单位向上取整。条件写入返回 412 仍算 Class A。免费额度只覆盖 Standard 存储类。见下文「费用边界」与 R2 各条。
2. **清理和加密迁移用 `messages.body_ref`、`submissions.body_ref` 做关联查找，这两列没有索引。** D1 按扫描行数计 rows read。Workers Free 每日 500 万行读取，2026-09-01 起超额后查询直接失败，直到 UTC 午夜。这是可用性问题。见 D1 索引一节。
3. **生产强制 HPKE，隐私策略打开时每条附件会整包读出、跑正则、再加密写回。** Workers Free 的 CPU 上限是每次请求 10 ms。`DEPLOY-CLOUDFLARE.md` 已经承认加密请求可能超时。仓库里没有生产 profile。见 CPU 一节。
4. **生产模板打开了日志和追踪，采样 10%，应用代码没有结构化错误日志。** 以每日最多 10 万次 Worker 请求估算，100% 采样仍落在 Free 日志额度内，而且 Free 观测超额是停收不是出账。当前采样会让多数失败不可见。
5. **面板静态文件编进 Worker，响应带 `cache-control: no-store`，并且不走限流。** 每次打开面板都消耗 Workers 日请求额度。Workers 静态资源绑定下的请求不计入该额度。
6. **压缩后 3 MB 的脚本上限已在 2026-09-04 取消。** 现行限制是所有套餐未压缩 64 MiB。本仓库没有 `wrangler deploy --dry-run` 的体积记录。
7. **生产模板仍公开 `workers.dev`，并让 `PUBLIC_ORIGIN` 指向 `workers.dev`。** 目标主机名是 `https://waypost.miles1150.top`，`workers.dev` 要关掉。切换时若两个主机名同时开着，它们进入同一个 Worker。见「自定义域名」。

## 费用边界（Workers Free，R2 已启用）

| 产品 | 文档中的 Free 行为 | 会不会在本部署上突然出账 |
| --- | --- | --- |
| Workers 请求 | 10 万次/日，超出返回 Error 1027 | 不会。超额是拒绝 |
| Workers CPU | 每次 HTTP 请求 10 ms，持续超出则终止该请求 | 不会。失败，不出账 |
| D1 | 每次调用 50 次查询；每日 500 万行读、10 万行写；单库 500 MB。2026-09-01 起行数超额后查询失败 | 不会。失败，不出账 |
| Workers Logs | 审查日仍是 20 万条/日、保留 3 天。2026-12-01 起并入观测定价：Free 每日 0.5 GB 摄入，用尽后停止摄入 | Free 上不会。Paid 才会在额度后继续计费 |
| Workers Traces | 默认采样率为 1。2026-12-01 起存储的追踪计入观测摄入 | 模板已把采样设为 0.1。Free 上用尽后停止 |
| R2 Standard | 每月 10 GB-month、100 万次 Class A、1000 万次 Class B，出口免费。超出后存储 $0.015/GB-month，Class A $4.50/百万次，Class B $0.36/百万次 | **会。** 文档写明用量向上取整到下一个计费单位 |
| R2 Infrequent Access | 免费额度不适用，另有取回费和最短存储时长 | **会。** 若桶的默认存储类被改成 IA，本部署的免费额度假设不成立 |
| 速率限制绑定 | 部署文档写明包含在 Workers 内，没有单独产品 | 以现有文档，绑定本身不出账 |
| Containers、Workflows 的长时步骤、Logpush | 需要 Workers Paid | 本部署未启用 |

依据：Workers 限额与价格、D1 限额与 2026-09-01 变更、R2 价格（2026-10-26）、Workers Logs、观测价格（2026-12-01 生效）。R2 Class A 包含 `PutObject`；`DeleteObject` 免费。价格页写明：带 `If-None-Match` 一类条件而返回 HTTP 412 的 `PutObject` 仍按 Class A 计费。

本部署把对象访问收在 Worker 绑定内，没有 R2 API 令牌，也没有 r2.dev。这样不会从绑定之外再产生一组 Class A/B。剩余的出账面是桶里的字节和绑定调用本身。

## workers-best-practices 与 rules/workers.mdc

### 兼容日期保持更新 — 部分符合

`wrangler.toml` 第 5 行与 `wrangler.production.example.toml` 第 5 行都是 `compatibility_date = "2026-07-17"`。`DEPLOY-CLOUDFLARE.md` 第 70 行说明这是适配器的测试日期。两份配置都没有 `compatibility_flags`。

风险：可靠性。从 2026-07-17 到审查日 2026-10-27 之间的运行时默认行为没有被这个日期带上。技能把日期更新当成维护项，只有日期或标志导致功能不可用时才算缺陷。当前代码能在这个日期上运行，所以不是缺陷。

建议：对照兼容日期变更说明，在本地 `wrangler dev` 与 `scripts/verify_deployment.py` 通过后把日期向前推进。不要为了技能示例加上 `nodejs_compat`。Waypost 的正则、加密和随机数都走 Rust/`getrandom` 的 `js` 特性，不依赖 `node:*`。工作量：中。

### `nodejs_compat` — 不适用

技能要求在依赖 Node 内置模块时打开该标志。本 Worker 不引用这些模块。

### `wrangler types` / 手写 Env — 不适用

这是 Rust Worker（`worker` 0.8.7），没有 TypeScript `Env`。绑定名称在代码里手写，和配置的对应关系见下文「绑定一致」。

### 用 Wrangler 秘密保存密钥 — 符合

`WAYPOST_ADMIN_SECRET`、`WAYPOST_ENCRYPTION_KEYS`、`WAYPOST_CURSOR_SECRET` 通过 `env.secret` 读取（`src/cloudflare.rs` 第 368、444、452 行）。`wrangler.toml` 的 `[vars]` 只有 `PUBLIC_ORIGIN`。生产模板的 vars 只有 `DEPLOYMENT_ENV` 和 `PUBLIC_ORIGIN`。`.gitignore` 排除了 `.dev.vars`、`.env.*`、`wrangler.production.toml`、`.env.production`。`.dev.vars.example` 只有占位符。部署步骤用 `umask 077` 和 `--secrets-file`，不把秘密放进命令行。

生产缺少加密密钥或管理员秘密短于 32 字符时，请求在进入业务前失败（`src/cloudflare.rs` 第 373–378、460–461 行）。

风险：若有人把 `ALLOW_LEGACY_PLAINTEXT=1` 写进生产 vars，明文对象会被接受（`src/service/encryption.rs` 第 176–178、191–193 行）。生产模板没有这个变量，默认关闭。

建议：保持秘密只走 `--secrets-file`。确认线上 vars 没有 `ALLOW_LEGACY_PLAINTEXT`。工作量：小。

### `wrangler.jsonc` — 部分符合

技能让新项目用 JSONC，并写明 TOML 在新项目里应被标出。Wrangler 技能同时要求保留既有约定，避免顺手改格式。本仓库已经用 TOML，Wrangler 4.111.0 能读。

建议：没有 JSON-only 字段需求时保持 TOML。工作量：不做。

### 绑定与代码一致 — 符合

| 代码 | 配置 |
| --- | --- |
| `env.d1("DB")` | `binding = "DB"` |
| `env.bucket("OBJECTS")` | `binding = "OBJECTS"` |
| `ADMIN_RATE_LIMITER`、`API_RATE_LIMITER` | 同名 `[[ratelimits]]` |
| `DEPLOYMENT_ENV`、`PUBLIC_ORIGIN` | `[vars]` |
| 三个 `env.secret` | 部署时注入，不在 toml |

生产若缺少任一限流绑定，直接返回配置错误（`src/cloudflare.rs` 第 387–392 行）。非生产缺少绑定时限流器变成 `None`，请求继续。这和“本地可以缺省、生产必须失败关闭”一致。

`namespace_id` 的 `1001` 和 `1002` 在模板里是示例。`DEPLOY-CLOUDFLARE.md` 第 56 行要求换成账户内唯一值。线上 toml 不在仓库里，本次不能证明已经换过。两个 Worker 共用一个 namespace 会互相消耗额度。风险：可靠性。建议：在仪表盘核对生产 namespace。工作量：小。

### 打开日志和追踪 — 部分符合

生产模板（`wrangler.production.example.toml` 第 16–24 行）同时设置了 `observability.enabled`、`observability.traces.enabled` 和两边的 `head_sampling_rate = 0.1`。这符合“顶层开关不会自动打开追踪”。本地 `wrangler.toml` 没有 observability 块，只影响本地。

应用代码没有 `console.log` / `console.error`。`fetch` 把 Worker 运行时错误收成固定的 `"worker request boundary"`（`src/cloudflare.rs` 第 344–346 行），业务错误是 JSON，不会进日志。采样 0.1 时，大约九成调用没有追踪。

风险：可靠性，不是费用。Free 账户每日 10 万请求、每条调用一条 invocation 日志，100% 采样仍低于审查日 20 万条/日的日志额度。2026-12-01 之后 Free 是每日 0.5 GB 摄入，用尽后停止，不转成账单。追踪默认采样率是 1；模板显式写成 0.1，避免了“打开追踪却忘了采样”的默认全量。

建议：把这个低流量 Worker 的日志和追踪采样调到 1。在返回 5xx 和 D1/R2 失败时 `console.error` 一行 JSON：错误码、路由、请求 id。不要写入秘密、令牌、对象字节或原始 IP。工作量：小。

### 不要缓冲无界响应体 — 部分符合

技能允许已知大小的小 body 缓冲。生产限制是 JSON 16 KiB、对象 256 KiB（`src/cloudflare.rs` 第 427–434 行），读 body 时超过即停（第 509–518 行）。

加密打开时，上传和下载不走流（第 488–502 行）。`object_read` 把对象读进 `Vec` 再解密（`src/service/encryption.rs` 第 181–189 行）。`DEPLOY-CLOUDFLARE.md` 第 34 行写明生产必须加密，因此生产路径总是缓冲。256 KiB 低于 128 MB 内存上限，不会把隔离实例撑爆。CPU 见下一节。

未加密的流式下载把 R2 body 直接交给响应（`src/cloudflare.rs` 第 304–310 行），符合流式条款。该路径在生产加密开启时不可达。

建议：保持 256 KiB 上限。不要为了符合流式示例而在 Free 的 10 ms CPU 里做边收边加密。工作量：不做。

### 密钥比较要用固定长度、常数时间 — 符合

管理员认证先对两边做 SHA-256，再按字节异或（`src/service/mod.rs` 第 224–239 行）。长度不匹配不会提前返回。会话和令牌以 SHA-256 摘要进 D1，查询按摘要匹配（`src/storage/queries.rs` 第 1–8 行，`src/service/dashboard.rs` 第 51、83 行）。随机数走 `getrandom`（`src/service/mod.rs` 第 391–394 行），crate 启用了 `js` 特性，在 Worker 里对应 Web Crypto，不是 `Math.random()`。

技能示例是 `crypto.subtle.timingSafeEqual`。这里的异或循环是同一类比较。D1 里的摘要等值比较不在 Worker 进程内逐字节对秘密原文。

### 秘密不要出现在源码或配置里 — 符合

见「用 Wrangler 秘密保存密钥」。错误字符串不回传 D1/R2 的原始错误（`src/cloudflare.rs` 第 52–68、157–162 行）。

### 后台工作必须 await 或 waitUntil — 符合

`fetch` 的 `Context` 未使用，也没有被拆开。请求路径上的 D1、R2 和加密都 `await`。没有浮空任务。没有 `passThroughOnException`。

### 不要把请求状态放在模块全局 — 符合

`App`、D1 会话和 R2 桶都在单次 `handle_fetch` 里构造（`src/cloudflare.rs` 第 424–443 行）。没有 `static mut`。

### 用绑定，不要在 Worker 里调 Cloudflare REST — 符合

仓库的 Worker 代码没有 `api.cloudflare.com` 请求。D1、R2、限流都走绑定。这同时避免了为 R2 签发 API 令牌。

### 长任务放到 Queues 或 Workflows — 部分符合

普通的 MCP 和 HTTP 请求是一次调用内完成，符合 `DEPLOY-CLOUDFLARE.md` 第 9 行的模型。加密迁移和对象清理由管理员请求分页执行（每页最多 4 个对象、8 个清理候选，`src/service/encryption/migration.rs` 第 17 行，`src/service/maintenance.rs` 第 43 行）。它们仍然占满同一次调用的 CPU。

Workflows 在 Free 上每步 CPU 仍是 10 ms，解决不了 HPKE。Queues 消费同样受 Free CPU 限制。把迁移搬上去不能躲开 10 ms，还会引入 Paid 才能舒服使用的长时步骤。

建议：继续用分页管理接口。在 Free 上跑历史加密时把 `limit` 保持为 1，并看 CPU 指标。不要为了这一条上 Workflows。工作量：小（调用方传 `limit`）。

### 服务绑定、Hyperdrive — 不适用

没有第二个 Worker，也没有外部 Postgres/MySQL。

### 平台 CPU 限额 — 不符合（相对 Free 10 ms 的稳定运行）

检索到的限额：Workers Free 每次 HTTP 请求 10 ms CPU；等待 D1/R2 的时间不算 CPU。技能正文仍写着已废弃的 Bundled 10 ms / Unbound 30 s。以限额页为准。Paid 默认 30 秒、最高 5 分钟。`limits.cpu_ms` 只对 Standard（Paid）生效，不能用来给 Free Worker 再加一层更低的保险丝。

生产每次请求都会解析密钥环并做两次 HMAC 派生（`src/service/mod.rs` 第 90–94 行，`src/cloudflare.rs` 第 452–457 行），包括 `/health` 和静态文件。密钥环最多 4 把钥匙，这一段本身不是 10 ms 的主体。

主体在加密和隐私：

- `Encryption::seal` / `open` 做 X25519 与 ChaCha20-Poly1305（`src/service/encryption.rs` 第 79–102、104 行起）。
- 发信时 `policy()` 每次重新编译规则（`src/service/privacy.rs` 第 50–77、197–227 行）。`credential` 规则是一条长正则。管理员还可保存自定义 `regex` 规则。`size_limit(1_048_576)` 限制的是编译内存，不限制匹配时间。
- 隐私命中后，每个附件调用 `read_blob_bytes`（R2 全量读取 + 解密）、对最多 256 KiB 文本跑正则、再 `object_create` 加密写回（`src/service/privacy.rs` 第 291–357 行）。附件上限是 4。
- 收件箱每一条消息对主题做 `open_field`（`src/service/receipts.rs` 第 292–293 行）。页大小上限 20。
- 记忆读取对路径和元数据逐条解密（`src/service/memory.rs` 第 545 行附近）。

`DEPLOY-CLOUDFLARE.md` 第 51 行已经写：加密请求和较大的邮箱写入可能超过 10 ms，应改到 Workers Paid。审查同意这个判断。风险：可靠性。请求被终止，数据不一定处于业务提交点；D1 与 R2 本来就不是同一个事务。

建议：用 Workers 仪表盘的 CPU 时间和 `workers-profiling` 对「隐私打开 + 4 个文本附件」以及「收件箱一页」各采一次 profile，再决定是否升级套餐。在仍使用 Free 时，避免在一次请求里对多个 256 KiB 附件做解密、正则和再加密。自定义正则应限制长度和复杂度。工作量：测量为小，把隐私检查移出热路径为中，升级套餐为账户决定。

### 显式错误处理 — 部分符合

没有 `passThroughOnException`。业务错误返回结构化 JSON。Worker 边界错误没有 `console.error`，见可观测性一节。

### 在 Workers 运行时里测试 — 部分符合

技能推荐 `@cloudflare/vitest-pool-workers`。本仓库是 Rust，测试在原生 SQLite 上跑，另有 `scripts/verify_deployment.py` 和本地 Wrangler。`DEPLOY-CLOUDFLARE.md` 第 21 行记录了 Wrangler 4.111.0 与 Workerd 的本地验证。这覆盖了绑定行为的一部分，覆盖不了 vitest 池那种“测试运行在 workerd 里”。

建议：保留现有的 Wrangler 本地验证。不要为了这条技能把项目改成 vitest。工作量：不做。

## wrangler

### 固定项目里的 Wrangler 版本 — 部分符合

仓库没有把 Wrangler 放进 `package.json`。部署文档固定 `npx wrangler@4.111.0`。这能避免静默升级，也没有锁文件。

Workers Previews 需要项目本地 Wrangler 4.135.0 或更新。本部署把 `preview_urls = false`（生产模板第 7 行），不使用 Previews。版本低于 4.135.0 因此没有当前后果。

建议：继续在文档里钉住 4.111.0，直到有意升级并重跑本地验证。不要为了 Previews 升级，除非准备好隔离的预览资源。预览 URL 默认公开，技能要求先说明这一点。工作量：小。

### 秘密不进命令行、本地文件被忽略 — 符合

见密钥一节。`wrangler secret put` 会立刻部署；文档用 `deploy --secrets-file`，秘密和代码同一次发布。回滚 Worker 不会回滚 D1 和 R2，`DEPLOY-CLOUDFLARE.md` 第 36 行与技能的回滚限制一致。

### 部署前 dry-run — 符合（文档要求如此）

`DEPLOY-CLOUDFLARE.md` 第 121–122 行先 `--dry-run` 再正式 `deploy`。本次审查没有执行它，因此没有新的体积或打包证据。

### 环境继承 — 符合

生产和本地是两个文件，不是 `[env.production]` 继承。这避免了“顶层绑定没有复制到环境”的类问题。代价是两份配置可能漂移：本地没有 observability，名称和数据库 id 也不同。文档要求生产使用 `wrangler.production.toml`。

### 预览与生产资源隔离 — 符合

`preview_urls = false`。没有把预览部署指到生产 D1/R2 的配置。保持预览 URL 关闭。自定义域名切换不要改用 Workers Previews。

### 自定义域名 — 部分符合（相对目标主机名）

当前模板（`wrangler.production.example.toml` 第 6–7、12–14 行）是 `workers_dev = true`，`PUBLIC_ORIGIN` 的示例仍是 `https://waypost-production.<subdomain>.workers.dev`。`DEPLOY-CLOUDFLARE.md` 的部署后检查同样使用 `workers.dev`。代码把浏览器 `Origin` 和 `PUBLIC_ORIGIN` 做全字匹配（`src/cloudflare.rs` 第 371–385 行），并且只在请求本身是 `https` 时下发 HSTS（第 355–358 行）。

目标：

- 对外原点是 `https://waypost.miles1150.top`（scheme + host，没有路径，没有末尾斜杠）。
- `workers.dev` 关闭。

建议改生产配置和 `DEPLOY-CLOUDFLARE.md`、`wrangler.production.example.toml` 时写成：

```toml
workers_dev = false
preview_urls = false

[vars]
DEPLOYMENT_ENV = "production"
PUBLIC_ORIGIN = "https://waypost.miles1150.top"

[[routes]]
pattern = "waypost.miles1150.top"
custom_domain = true
```

切换顺序：先挂上自定义域名并确认 `https://waypost.miles1150.top/health`，再把 `PUBLIC_ORIGIN` 改成这个原点并部署，最后把 `workers_dev` 设为 `false` 再部署一次。`Origin` 检查在 `PUBLIC_ORIGIN` 改掉之后会拒绝来自 `workers.dev` 的浏览器请求。旧主机名在 `workers_dev` 关掉之前仍可被非浏览器客户端直接调用，所以不要把两步隔得太开。本地 `wrangler.toml` 继续用 `http://127.0.0.1:8791`。

风险：安全与可用性。`workers_dev = true` 留着时，自定义域名和 `workers.dev` 是两扇门。`PUBLIC_ORIGIN` 若仍写成 `workers.dev`，面板在新域名上的 `Origin` 检查会失败。

工作量：小。本次不改这些文件。

### 每日请求用尽后的失败模式 — 部分符合

限额页：Free 每日 10 万请求，超出为 Error 1027。路由可以失败打开（当没有 Worker）或失败关闭（返回 1027）。自定义域名挂上之后，失败打开会跳过 Waypost 的鉴权；若该主机名没有源站，请求也不会进到应用。

建议：`waypost.miles1150.top` 这条路由使用失败关闭。工作量：小。

## D1

### 每次调用 50 次查询 — 部分符合

限额页（2026-10-24）：Free 每次 Worker 调用 50 次查询，Paid 1000 次。`db.batch()` 对这个上限算 **一次**，批内语句仍各自受 100 KB SQL 和 100 个参数约束。

`D1Store` 在准备语句时拒绝超过 100 个参数或 100_000 字节的 SQL（`src/cloudflare.rs` 第 24–28 行）。`guarded_inserts` 按参数预算切块（`src/storage/queries.rs` 第 17–49 行）。写路径把多条语句放进 `batch`。

按代码点数的顺序调用（每条 `.query` 或 `.batch` 算 1，R2 另计）：

| 路径 | 大约的 D1 调用次数 | 与 50 的关系 |
| --- | --- | --- |
| `GET /health`、静态文件 | 0 | 安全 |
| `GET /ready` | 1 次迁移计数 + 1 次 R2 head | 安全 |
| 鉴权 | 1 次 `AUTHENTICATE` | 安全，摘要列有唯一索引 |
| 收件箱一页 | 1 次 feed + 1 次收件人 + 1 次 `current` | 安全。页上限 20 |
| 对象清理，非 dry-run，8 个候选 | 1 + 8×（1 batch + 1 query + 1 batch）= 25 | 低于 50 |
| 加密迁移，4 个对象 | 约 1 + 4×5 = 21 | 低于 50 |
| 发信，隐私打开，4 个附件 | 鉴权、预留、策略、每个附件的再次读取和 journal、正文准备、提交，合计大约 40 | 低于 50，余量不大 |

发信路径里每个附件在 `send` 和 `filter_message` 各查一次（`src/service/mailbox.rs` 第 257–258 行，`src/service/privacy.rs` 第 291–292 行）。

风险：可靠性。再增加几次往返就会碰到 `Too many API requests by single Worker invocation`。批内语句再多也不吃这 50 次，所以优化方向是减少往返，而不是把 batch 拆小。

建议：为「隐私打开 + 4 个附件的 message.send」加一个计数测试，断言 D1 调用次数低于 40。工作量：中。

### 按扫描行计费 / 限额，缺索引要标出 — 不符合

D1 按扫描行数计 rows read，不按返回行数。Free 每日 500 万行读、10 万行写，超额后查询失败，已存数据保留。索引本身会增加写入行数；文档说明这通常能换来少得多的读取。

已经对齐查询的索引：

- `tokens.token_digest` 唯一，鉴权走它。
- `submissions (space_id, producer_id, operation, request_id)` 唯一，幂等查找走它。
- `blobs.object_key`、`uploads.object_key` 唯一。
- `feed_items (space_id, space_sequence)` 唯一，收件箱 `ORDER BY space_sequence LIMIT` 走它（`src/service/receipts.rs` 第 232–260 行）。
- `memory_revision_items (space_id, blob_id, collection_id)`。
- `admin_sessions(expires_at)`、`space_admin_credentials.credential_digest` 唯一。

缺索引、而且查询会跟着表变大：

1. `messages.body_ref` 没有索引。清理条件对每一条 `object_writes` 候选执行 `NOT EXISTS (SELECT 1 FROM messages m WHERE m.body_ref = w.object_key)`（`src/service/maintenance.rs` 第 6–8、58 行）。`blobs` 和 `uploads` 的 `object_key` 有唯一索引，`messages` 没有。候选扫描会反复读消息表。
2. `submissions.body_ref` 没有索引。迁移按 `space_id` 和 `body_ref` 查找（`src/service/encryption/migration.rs` 第 90 行）。`space_id` 只是另一条唯一索引的左前缀，`body_ref` 仍要在该空间的提交里过滤。
3. `message_attachments(space_id, blob_id)` 没有索引。按 blob 判断可读性时过滤 `a.blob_id = ?`（`src/service/blobs.rs` 第 315 行），主键是 `(space_id, message_id, position)`。
4. `memory_revisions.manifest_blob_id` 没有索引。同一函数第 322 行从集合出发 `LEFT JOIN` 条目和修订，再过滤 blob。历史修订会留下全部旧行，Worker 的 32 条上限限制的是单次写入，不限制修订总数。

`SELECT * FROM spaces WHERE 1=1 ORDER BY created_at`（`src/service/dashboard.rs` 第 180–207 行）会扫描空间表。单人部署的空间表很小，这一条目前只是排序，不是优先项。

风险：可靠性。一次清理在消息表和对象日志都变大之后，可以在一天内耗尽 500 万行读取，随后所有 D1 查询失败到 UTC 午夜。这不是 R2 那种出账，但会让线上停写停读。

建议：新增迁移，至少包括

```sql
CREATE INDEX messages_body_ref ON messages(body_ref);
CREATE INDEX submissions_body_ref ON submissions(body_ref);
CREATE INDEX message_attachments_blob ON message_attachments(space_id, blob_id);
CREATE INDEX memory_revisions_manifest ON memory_revisions(space_id, manifest_blob_id);
```

用 `EXPLAIN QUERY PLAN` 确认清理语句从 `SCAN` 变为 `SEARCH`。工作量：小。本审查不改迁移。

### 读后写与会话 — 符合

每次请求使用 `with_session(Some("first-primary"))`（`src/cloudflare.rs` 第 425–426 行）。会话内第一条查询在主库，后续查询带着 bookmark。请求之间不传递 bookmark。无状态 API 每次重新 `first-primary`，同一次调用里的写入对后续读取可见。

技能提醒：应用登录会话和 D1 Sessions API 不是一回事。Waypost 的 `admin_sessions` 表是应用会话，D1 session 是读副本约束。两者没有混用。

### 批处理失去跨存储原子性 — 部分符合（已记录）

技能写明：把一个大操作拆成多批后，整次操作不再原子。Waypost 的对象字节在 R2，元数据在 D1，本来就不是一个事务。`DEPLOY-CLOUDFLARE.md` 第 36 行写了 Worker 回滚不回滚 D1 或 R2。`object_writes` 先记账再做对象 IO，清理任务再扫未引用对象（`migrations/0007_object_maintenance.sql` 第 1–2 行，`src/service/maintenance.rs`）。

风险：可靠性。进程在 R2 `put` 成功和 D1 提交之间停住时，会留下对象或悬空键。清理能补，但清理依赖上面缺少的 `body_ref` 索引，而且受 10 ms CPU 和 50 次查询约束。

建议：先补索引，再保持现有的分页清理。不要用一个全局 Durable Object 包住所有空间。工作量：索引为小。

### 外键、类型、迁移 — 符合

迁移 `0001` 到 `0009` 使用整数 0/1 而不是布尔列，时间戳是整数毫秒，落在 D1 的安全整数范围内。`D1Store` 对超过 `2^53-1` 的整数改用字符串绑定（`src/cloudflare.rs` 第 36–41 行）。`/ready` 对照 `d1_migrations` 里这九个名称的数量（第 471–478 行），不在请求路径里重复执行迁移。部署文档要求先 `d1 migrations apply --remote`。

`spaces` 的外键是 `DEFERRABLE INITIALLY DEFERRED`，用于打破 spaces 与 actors 的循环引用。D1 支持延迟外键。本地库和远程库不是自动同步的，文档把本地 `wrangler.toml` 和生产库分开。符合。

### 重试 — 部分符合

D1 技能要求短暂失败要看幂等性再重试。Worker 把多数 D1 错误收成 `storage`，没有在进程内重试。写操作有 `submission_id` / `request_id` 幂等键。客户端可以重放。进程内自动重试写请求可能把一次 412 的 R2 条件写再打一遍（仍计 Class A）。

建议：保持不在 Worker 里自动重试非幂等写。客户端沿用现有的提交状态查询。工作量：不做。

### 结果集有界 — 符合

Worker 配置把页大小压到 20，集合条目 32，内联记忆变更 8（`src/cloudflare.rs` 第 427–434 行）。列表查询带 `LIMIT`。这同时压低了单次 rows read 和 HPKE 次数。

## R2

### 私有桶、绑定访问、不启用 r2.dev — 符合

生产模板只有 `binding = "OBJECTS"`，没有公共域名。部署文档要求关闭 r2.dev 和公共桶域名，并且不要创建 R2 API 令牌。下载响应带 `cache-control: private, no-store`（`src/cloudflare.rs` 第 315 行），外层 `fetch` 再写 `no-store`（第 349 行）。没有预签名 URL。调用方先鉴权再读对象（`readable_blob`、`object_read`）。

这避开了公开桶和额外的 S3 凭证。R2 出口本身免费，公开桶的风险是数据暴露，不是出口账单。

### 条件写入 — 部分符合

`put` 使用 `etag_does_not_match: Some("*")`（`src/cloudflare.rs` 第 150–153 行），即仅当对象不存在时写入。冲突时 `put` 返回空，再 `head`。这符合“只创建一次”的不变性。

价格页写明这种 412 仍是 Class A。竞态下两个并发上传会有一次成功写入和一次计费的失败写入，然后再 `head`（Class B）。加密路径在写入前会 `head`；对象已存在时 `object_inspect` 还会把对象全部读出并解密（`src/service/encryption.rs` 第 196–217、256–258 行），用来确认内容相同。

风险：费用与 CPU。正常的单人用量离 100 万 Class A 很远。重试风暴或把清理误做成反复条件写入才会接近免费额度。文档的取整规则是：操作数落到下一个计费单位就按该单位计。应把用量保持在免费额度以内，并打开账单通知，而不是贴着 100 万次用。

建议：在 Cloudflare 账单里为 R2 设置通知。确认桶的存储类是 Standard。不要启用 Infrequent Access、生命周期转冷、r2.dev、数据目录或 R2 SQL。工作量：小。

### 存储增长与生命周期 — 部分符合

没有生命周期规则。未引用对象靠管理接口 `cleanup` 删除。`DeleteObject` 免费，删除本身不产生 Class A。删除前的列表式扫描在 D1 里，不在 R2 `ListObjects` 里，因此不会按 R2 列表计 Class A。对象在被删除前计入 GB-month。GB-month 按每日峰值平均。10 GB-month 之后 $0.015/GB-month，并向上取整。

单对象上限 256 KiB，要堆到 10 GB 大约需要数万个对象。隐私过滤会为每个附件再写一个新对象，旧对象要等清理。加密迁移同样把新对象写到新键，源对象留到清理（`src/service/encryption/migration.rs` 第 3–5 行）。

风险：费用，节奏较慢。没有告警时，越过 10 GB-month 的第一个计费单位会出现在发票上。

建议：记下桶的存储类和当前 GB-month。清理按页执行，先补 `body_ref` 索引。工作量：小。

### 流式下载与校验 — 部分符合

未加密下载流式返回，并核对大小、SHA-256 和 content type。加密下载必须先解密，因此整包进入内存。校验和用 R2 的 `.sha256` 选项（`src/cloudflare.rs` 第 154 行）。技能要求核对校验和的返回行为；代码在校验和错误字符串里返回 `CHECKSUM_MISMATCH`，其他错误统一为存储失败。

### 位置提示 — 部分符合

`r2 bucket create` 文档没有指定 location hint。桶可能落在默认区域，D1 主库在另一处时，对象往返变长。墙钟等待不算 10 ms CPU，所以这是延迟，不是 CPU 配额。

建议：若仪表盘显示对象延迟明显，再建桶时加上靠近使用者的 location hint。已有桶的搬迁不在这次审查范围内。工作量：中。

### 本地与线上数据 — 符合

`wrangler dev --local` 使用本地 D1/R2。生产部署文档使用 `--remote` 迁移和单独的生产配置。没有 `remote = true` 把本地进程指到生产桶。

## durable-objects

技能写明：无状态请求处理用普通 Worker，不要用 Durable Object；需要协调、强一致或 WebSocket 时才用。

Waypost 每次请求重新校验 bearer，状态在 D1 和 R2。`DEPLOY-CLOUDFLARE.md` 第 11 行的决定与技能的“不要用”一致。**符合。** D1 自己背后是单个 Durable Object，数据库内部已经串行。再套一个全局 DO 会把所有空间挤到一个实例上，违反“按协调单元建模”。

D1 与 R2 的跨存储缺口用 `object_writes` 补偿，见 D1 一节。不建议为了这个缺口引入 Durable Objects。

## turnstile-spin

技能在登录、注册、公开表单需要拦截机器人时适用。本部署没有 Turnstile。**未采用。**

适用的入口：

- `POST /admin/session` 使用 `ADMIN_RATE_LIMITER`，10 次/60 秒（`src/cloudflare.rs` 第 395–398 行，模板第 37–41 行）。
- `POST /admin/invitation` 与 `POST /admin/access-request` 走同一条管理限流。
- 其他 API 为 300 次/60 秒，按 IP 的 SHA-256 分键（第 407–414 行）。限流在 D1 和 R2 之前，被拒绝的请求不产生数据库和对象操作。
- `GET /health` 和面板静态文件不限流（第 399–403 行）。

当前流量在 `workers.dev` 上，区域级 WAF 还盖不住它。自定义域名接到 `miles1150.top` 之后，生产入口变成该区域上的主机名。见 waf 一节。

风险：可靠性。分布式客户端可以打静态文件和 `/health`，消耗每日 10 万次请求。管理登录已被 10 次/60 秒挡住，撞密码的 CPU 成本有限。

建议：若要加 Turnstile，小部件域名包含 `waypost.miles1150.top`。生产 siteverify 只接受主机名 `waypost.miles1150.top`，不要把 `localhost`、`127.0.0.1` 或 `workers.dev` 放进生产允许列表。本地开发用另一套小部件或另一套允许列表。秘密用 `wrangler secret`，不要写进仓库。静态文件更适合静态资源绑定，见 web-perf。工作量：中。

## waf

WAF 技能面向区域上的托管规则和速率限制规则。今天的 `workers.dev` 部署还没有这条区域路径。**部分符合**：应用层限流绑定已经在，区域 WAF 要等自定义域名。

`https://waypost.miles1150.top` 挂到 Cloudflare 区域之后，可以在该主机名上加托管规则。Worker 里的 `ADMIN_RATE_LIMITER` 和 `API_RATE_LIMITER` 继续保留；区域规则挡在前面，绑定负责应用自己的限额。不要为了 WAF 把 `workers.dev` 留着。`workers.dev` 不在这个区域里，关掉它之后公网只剩自定义域名这一扇门。

建议写入部署文档的检查项：域名已代理到该 Worker、`workers_dev = false`、`PUBLIC_ORIGIN` 为 `https://waypost.miles1150.top`。工作量：小。

## web-perf

没有可用的浏览器性能追踪，本次没有 LCP、CLS 或 TTFB 的测量值。下面是代码里能确定的部分。

面板资源用 `include_bytes!` 编进 Worker（`src/service/dashboard.rs` 第 7–42 行）。七个文件合计约 115 KB（`app.js` 42 KB，两个 locale 各约 17 KB）。响应自己的 `cache-control` 是 `no-store`，`fetch` 又对所有响应写 `no-store`（`src/cloudflare.rs` 第 348–350 行）。打开一次面板会请求 HTML、三个脚本、CSS 和两个 locale，大约 7 次 Worker 调用，每次都重新下载。

Workers 价格说明：静态资源请求免费且不计入额度；一旦由 Worker 生成响应，就计入 10 万次/日。当前面板属于后者。

风险：性能与每日请求额度。115 KB 的拷贝不是 CPU 主因，HPKE 才是。无缓存会让每次访问都付一次 Worker 启动和密钥解析。

建议：把 `dashboard/` 放到 Workers 静态资源，并让 HTML 引用带哈希的文件名、使用较长的缓存。API 和对象下载保持 `no-store`。静态资源路径继续不要进需要秘密的业务逻辑。工作量：中。

未测量项：真实用户的 LCP/INP、Brotli 后的传输大小、冷启动 TTFB。

## workers-profiling

技能要求对已部署 Worker 采 CPU 或堆 profile，再改代码。本次没有 profile。**未测量。**

建议的第一枪：隐私策略打开时发送带 4 个文本附件的消息，以及读取一页收件箱。对照仪表盘里的 CPU 时间是否稳定超过 10 ms。工作量：小。有结果后再改，避免在没有 profile 时重写加密。

## observability / secrets-store / 其他产品

### Secrets Store — 不适用

账户级 Secrets Store 用于多消费者共享秘密。本 Worker 用版本级 `env.secret`，符合 workers-best-practices 的秘密条款。不要把密钥环再复制进 Secrets Store，除非出现第二个消费者。

### 观测导出、Tail Worker、Logpush — 符合（未启用会出账的导出）

没有 Logpush，没有 OTEL 导出目的地。Logpush 需要 Paid。模板只打开了包含在 Free 额度内的日志和追踪，并设置了采样。见上文采样建议。

### smart-placement、KV、Queues、Containers、Browser、AI、邮件 — 不适用

未绑定这些产品。Containers 需要 Paid，部署文档已经排除。保持不启用，避免新的计费维度。

### 速率限制绑定的位置 — 符合

限流发生在 `env.d1` 和 `env.bucket` 之前。健康检查和静态文件除外。键是 IP 的十六进制 SHA-256，日志里没有这个值，因为应用没有打访问日志。

## 脚本体积

2026-09-04 的变更：不再检查压缩后 3 MB（Free）或 10 MB（Paid）。所有套餐只检查未压缩包，上限 64 MiB。`wrangler deploy --dry-run` 输出的 `Total Upload` 是这个上限的计量，`gzip` 数字仅供参考。

本仓库的发布配置是 `opt-level = "s"` 和 `lto = true`（`Cargo.toml` 第 53–55 行），并 `include_bytes!` 约 115 KB 的面板文件。依赖含 `regex`、`hpke`、`sha2`。这些通常会让 wasm 到数百 KB 至数 MB，离 64 MiB 很远，但本次没有编译，不能报一个实测数字。

建议：下一次部署按文档执行

```bash
npx wrangler@4.111.0 deploy --dry-run --outdir /tmp/waypost-bundle --config wrangler.production.toml
```

看 `Total Upload`。工作量：小。在看到接近数十 MiB 之前，不需要为体积改依赖。

## 子请求

2026-02-11 的变更：Free 仍是 50 次外部 `fetch` 和 1000 次指向 Cloudflare 服务的子请求。D1 的 50 次查询上限更紧。代码没有向外 `fetch`。R2 与 D1 走的是服务子请求额度。当前设计碰不到外部 50 次上限。**符合。**

## 审查未覆盖的线上事实

- 生产 `wrangler.production.toml` 的 `account_id`、`database_id`、`namespace_id` 是否与示例一致。目标 `PUBLIC_ORIGIN` 是 `https://waypost.miles1150.top`，不是示例里的 `workers.dev`。
- 自定义域名是否已经接上，以及 `workers.dev` 是否已关闭。
- 桶的存储类、当前 GB-month、本月 Class A/B。
- 已部署脚本的 `Total Upload` 和仪表盘 CPU 时间。
- 路由在每日 10 万请求用尽后是失败关闭还是失败打开。
- `EXPLAIN QUERY PLAN` 在真实 D1 上的结果。上面的索引判断来自 SQL 与表定义，上线前应用 `EXPLAIN` 确认。
