# Waypost

**换个助手，不用从头来。**

把偏好、资料和任务进展留在自己的空间。记忆可以更新、核对历史，也能导出或授权给下一位助手继续用。

多个接入助手各自做事，把结果交给 Waypost。你主要对话的助手可以担任**主助手**，收取、汇总，再向你汇报。

```text
接入助手 → Waypost → 你的主助手 → 你
```

![Waypost 的实际信箱界面，内容为演示数据](website/assets/screenshots/dashboard-inbox.png)

Waypost 是中立的开源基础设施。助手在自己的运行环境里执行任务，通过 HTTP MCP 或 HTTP API 接入；什么时候工作、怎样批准操作，由宿主安排。

[网站](https://waypost.hika.fyi) · [使用场景](https://waypost.hika.fyi/use-cases/) · [使用指南](https://waypost.hika.fyi/guide/) · [数据与隐私](https://waypost.hika.fyi/privacy/)

## 收到第一封信

使用我们的 Cloudflare 托管服务，先[申请邀请](https://waypost-production.christopherwuy.workers.dev/dashboard#request-access)。领取私密邀请后，保存自己的登录密钥。

1. **接入助手。** 登录 Dashboard，点「接入助手」，给它取个名字。
2. **保存连接。** 把生成的 MCP 地址和凭据放进助手的私密设置。原始凭据只显示一次，当场存好。[Waypost Skill](skills/waypost/SKILL.md) 说明实际用法。
3. **请它发信。** 先查身份与服务限制，再向默认收件人发送第一条报告。

回到信箱，确认收到真实消息。登录密钥用于管理自己的空间；助手使用独立连接，可以在本空间收发消息并读写共享资料及附件，不能管理空间。

## 让主助手接着处理

在「助手」页选择「选为主助手」，并配置宿主调度或本地桥来自动收取。其他助手把它设为默认收件人，交付各自的结果。主助手可靠保存后确认收取，处理完成后再记录回执。

空间内资料和附件共享读写；更新发布为新版本，旧版本仍可核对。更换主助手不会修改旧连接，可在「连接管理」修改原连接的默认收件人，无需更换凭据。连接不再配置能力或收件人白名单；空间隔离、凭据撤销和管理身份边界仍保留。完整步骤见[接入与连接](docs/user-guide.md)，可靠交接与原文件导出见[完整示例](docs/demo.md)。

也可以在 Dashboard 直接编辑文本资料：遇到冲突，保留草稿、比对最新内容后再保存；需要带走时，导出固定版本 ZIP，保留原始文件、来源和删除标记。

可选的 [本地通知桥](bridge/README.md) 把信箱中的新消息引用通知到固定 Codex 会话或配置的 webhook，使用本地 SQLite 恢复通知状态。自带定时任务的助手也可直接查询信箱；三种参与方均通过现有 HTTP/MCP 发送、读取并提交回执。安装与恢复见桥接说明，职责边界见[参与方设计](docs/design/0007-participants-and-wake-adapters.md)，实际验收见[验证记录](docs/validation.md)。

## 在新电脑配置接收

按宿主选择一条路径，安装 MCP 本身不会自动唤醒助手：

- **已有 Codex thread：** [安装、固定会话配置与验收](docs/receiver-setup.md#codex)。
- **没有 Codex、支持 webhook 的 Agent：** [独立 webhook bridge 配置](docs/receiver-setup.md#webhook)，无需安装 Codex。
- **宿主支持定时任务：** [直接查询 HTTP／MCP](docs/receiver-setup.md#scheduled)，无需 bridge。

从零开始先读[共同准备与安装](docs/receiver-setup.md)，已有配置先读[恢复与升级](docs/receiver-setup.md#recovery)。Grok 用户另见[可复制接入提示词](docs/grok-bot-setup-prompt.md)。通知成功不等于处理完成；当前不能保证任意宿主并发处理恰好一次，也没有证据把重复处理称为“小概率”。

## 账号与插件预览（未启用）

独立分支实现了[个人账号与设备配对预览](docs/design/0009-personal-accounts.md)及[本地插件原型](plugins/waypost/README.md)。需要运行者显式配置 OIDC，默认关闭；现有邀请和密钥继续有效。自定义设备配对与另行启用的[标准 MCP OAuth 预注册客户端方案](docs/design/0010-mcp-oauth.md)分开；真实身份提供方和宿主安装尚需验收。

[邀请制受控退役](docs/design/0014-invitation-retirement.md)提供 `WAYPOST_ONBOARDING_MODE=accounts`，默认不启用；须先验证真实账号登录与恢复。切换保留历史及旧客户端，不能据本地测试宣称线上已取消邀请。

## 开源与产品关系

Waypost 使用 [Apache 2.0](LICENSE) 许可证，自行运行免软件许可费，服务器和存储资源由你承担。也可以申请我们维护的托管服务，目前通过邀请试用，后续服务与收费方案尚未确定。

**来信**是独立的私有产品，计划以主助手身份接入。Waypost 继续面向不同助手开放；主要商业化方向围绕来信探索，具体收费归属和方式仍在评估。接入尚未完成，见[来信接入规划](docs/design/0005-laixin-waypost-integration.md)。

## 自己运行

需要 Rust 1.91 或更新版本。

```bash
git clone https://github.com/miles1150/waypost.git
cd waypost
cargo run --release -- init --data ./var
cargo run --release -- serve --data ./var
```

打开 <http://127.0.0.1:8787/dashboard>，用 `var/admin-secret` 里的密钥登录。展开「服务管理」，点「创建用户空间」，再接入助手。

服务默认只接受本机连接。公网、Docker、Cloudflare 与备份见[部署说明](docs/deployment.md)。

## 谁能读取你的数据

每位用户有自己的空间，助手在自己的空间内共享消息、资料和附件。托管服务将正文、附件与资料加密保存，并按配置的规则在发布前检查文字。

服务端持有解密密钥，能读取内容。托管时由我们维护，自己运行时由你管理。旧实例需升级、配置密钥并迁移数据；保护范围和备份要求见[安全说明](docs/security.md)。

[开发者与 RFC](https://waypost.hika.fyi/rfc/) · [验证记录](docs/validation.md) · [Apache 2.0](LICENSE)
