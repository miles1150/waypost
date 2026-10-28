# 通用参与方本地集成验收

日期：2026-10-28。执行环境：当前 cloud env 内的 Linux 工作区。范围是设计 0007 的本地协议与适配器验收，不是 Cloudflare 发布或真实外部宿主验收。

## 执行方式与结果

```sh
cargo build --locked --bin waypost
cargo build --locked --manifest-path bridge/Cargo.toml
python3 scripts/verify_participant_flows.py
```

2026-10-28 对适配器重构后的 debug 二进制完成复跑，结果 `passed`，9 个发送/接收组合与 13 项检查通过。脚本只接受本地二进制路径，自行启动 loopback Waypost，使用临时 Space、SQLite 和凭据；结束时停止进程、删除临时目录。它不接受生产 URL 或生产凭据。

## 验证到的行为

| 场景 | 证据 |
| --- | --- |
| webhook / Codex / 定时参与方的 3×3 组合 | 三个独立 Actor、Consumer 使用同一真实 HTTP/MCP 消息协议，九条矩阵消息分别到达获准收件人 |
| 稳定发送请求 | 同 request_id 重放保持同 message_id；其中一条在真实服务提交后由客户端测试包装器丢弃响应，随后查询提交状态并重放恢复 |
| 最小桥接权限 | webhook、Codex 桥使用独立的仅 message.read 凭据，与业务处理客户端共享各自 Actor/Consumer；不授予 receipt.write 或 message.send |
| 空轮询与通知边界 | 对服务端所有应用表做只读内容摘要比较，轮询和通知前后持久内容不变；通知成功不生成业务回执 |
| 分页收件 | 每页一条，三个消费者都读取自己的三条矩阵消息 |
| received / processed | 正文与待 ACK 请求先提交到本地 SQLite，再发送 received；确定性模拟处理结果落盘后才提交 processed |
| ACK 响应丢失 | received 已在真实服务提交，但包装器在本地确认前抛出模拟网络错误；重开 SQLite 后复用同 ACK request_id 恢复 |
| 定时重复执行 | 再次打开本地 SQLite 后跳过已处理且 ACK 已确认的项目，处理次数为零，服务端持久内容不变 |
| 回执事件循环 | Consumer 未过滤 item_type；产生真实回执事件后再次运行桥，不增加通知、不回写服务端 |
| webhook 未知结果 | 模拟 endpoint 保存通知后断开连接、不返回响应；桥记录 unknown；再次运行不重发；显式允许重试后保持同 delivery_id |
| 扩权与游标 | 读取 scope 改变使旧游标失效；桥重新读取但不重复通知既有 item |
| 撤权与待发工作 | 先 scan 将新消息保存为 pending，再移除桥接读取权限；真实 bridge 不派发；恢复权限后分别只派发一次 |
| 结果回复 | 显式发送一条带 in_reply_to 的模拟处理结果；稳定 request_id 重放不新增回复，不启用自动回复循环 |

## 证据边界

- Waypost 是实际 native 服务，HTTP/MCP、权限校验、事务、游标与回执均走真实代码。
- webhook endpoint 是本地模拟服务器，Codex CLI 是临时可执行模拟程序；没有调用真实 Grok、Codex 模型、用户会话或外部业务动作。
- 模拟业务处理仅计算正文字符数并持久记录，processed 不代表外部任务执行成功。
- 发送与 ACK 响应丢失由客户端包装器在真实提交后注入；webhook 的响应丢失由实际 TCP 连接关闭产生。数据库重开、子进程重新启动已覆盖，但不声称完成机器断电或真实桌面崩溃验收。
- 服务端内容摘要不变证明没有持久数据变化，不是 Cloudflare D1 rows_written 账单测量。
- URL/IP 拒绝规则、目标变更和重定向防护另有 Rust 测试；此脚本使用明确的 literal-loopback 测试配置。未实际连接公网 HTTPS webhook，也未对真实 DNS 重绑定或生产代理做端到端验收，不能把静态地址规则测试等同于这些验证。
- GitHub Actions 工作流已接入该脚本；本记录只证明 cloud env 本地等价执行，未声称 hosted Actions 已运行。
