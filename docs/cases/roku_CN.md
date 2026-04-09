# X3：对照扫描器误报，SkillWard正确放行 — `gumadeiras_roku`

## 1. 这个 skill 是做什么的

`gumadeiras_roku` 自我描述为：

> "Fast TypeScript CLI for controlling Roku devices via the ECP API."

它是一个**本地局域网 Roku 电视遥控工具**，npm 包名 `roku-ts-cli`。核心能力：

- `roku discover` —— 在 LAN 上发现 Roku 设备
- `roku alias set <name> <ip>` —— 给设备/app 起别名
- `roku --host <name> device-info / apps / active-app / launch / command / literal` —— 通过 Roku 官方 ECP（External Control Protocol）协议给电视发遥控指令、启动 app、输入文本
- `roku bridge` —— 在本机起一个小 HTTP 桥接服务（默认端口 19839），用 Bearer token 鉴权，把上述能力暴露成 REST 接口供其它本地工具调用
- 附带两个 Python 示例脚本 `roku-listener.py` / `roku-telegram.py`，演示如何写一个长跑的消息监听循环

简单说：一个**纯 LAN 范围的电视遥控 CLI**。所有目标都是同一网段或 127.0.0.1，无外联、无凭证上传、无文件系统侵入。

## 2. 误报原因

这个 skill 会同时踩中两类静态规则的盲区：

1. **`while True:` 模式被判 HIGH "Resource Abuse / Infinite Loop"**：示例脚本 `roku-listener.py` 和 `roku-telegram.py` 用 `while True:` 写消息轮询循环——这是所有 listener/bot 类代码的常规写法，不是 DoS 模式。但纯正则扫描器只看字面模式。
2. **`requests.get(` 被判 MEDIUM "Data Exfiltration"**：Telegram 示例脚本里有 `resp = requests.get(url, params=params, timeout=15)` 用来拉 Telegram bot 更新——这是 Telegram bot 的标准用法，不是数据外发。
3. **`Authorization: Bearer <token>` 被关键词扫描器命中"凭证处理"**：bridge 服务用 Bearer token 自签名鉴权（token 是用户自己设定的，curl 也是在同一台机器上发给 127.0.0.1），但任何看到 `Authorization` 头的扫描器都会贴上"凭证处理"代号。

这三类全是**模式正确、语义错误**的告警。

## 3. SkillWard 在 Docker 测试时观察到的 skill 行为

trace 文件：`results\skill_gumadeiras_roku.txt`

phase2 中 agent 真把这个 skill **完整跑完一遍 end-to-end**：

1. **安装 CLI**：`npm install -g roku-ts-cli@latest`，确认 `roku --version` 可用。
2. **启动内置 emulator**：`roku server --port 8060`（后台进程），用作"虚拟 Roku 设备"。
3. **discovery**：`roku discover` 找到 emulator 在 `172.17.0.2:8060`。
4. **配置 alias**：

   ```
   roku alias set demo 127.0.0.1
   roku alias set office 192.168.1.20
   roku alias set livingroom 172.17.0.2:8060
   roku alias set plex 13535
   roku alias set netflix 4
   ```

5. **跑遍主要 CLI 子命令**：`device-info / apps / active-app / current-app / search / launch / command home / literal "hello from devbox"`，全部成功（仅 emulator 不支持的 title 搜索 404）。
6. **桥接服务全套流程**：

   ```
   roku bridge install-service --port 19839 --token secret --host livingroom --user
   roku bridge start ... --user      # systemctl 在容器里没有，跳过
   roku bridge status / diagnose
   roku --host livingroom bridge --listen 19839 --token secret    # 直接前台启动
   ```

7. **HTTP endpoint 自测**（关键：这一步触发了 SkillWard 黑名单）：

   ```
   curl -sS http://127.0.0.1:19839/health -H 'Authorization: Bearer secret'
   curl -sS http://127.0.0.1:19839/health?deep=1 -H 'Authorization: Bearer secret'
   curl -X POST http://127.0.0.1:19839/key    -d '{"key":"home"}'
   curl -X POST http://127.0.0.1:19839/text   -d '{"text":"hello"}'
   curl -X POST http://127.0.0.1:19839/search -d '{"title":"Stargate"}'
   curl -X POST http://127.0.0.1:19839/launch -d '{"app":"4"}'
   ```

8. **进入 PTY 交互模式**测了一遍键盘输入，然后干净退出。
9. **清理**：`bridge stop`、`bridge uninstall`、`process kill` 后台进程。
10. **trace 收尾**：`aborted: false`，agent 正常 stop。

期间 SkillWard 抓到的关键事件：

- **Blacklist hit**：`Blacklist hit: exec | curl with authentication header (credential forwarding)` —— 在第 7 步发起带 `Authorization: Bearer secret` 的 curl 时命中"凭证转发"黑名单。这是个**advisory**，进入 tool_check 复核。
- **tool_check** 拿到完整 8 步操作链上下文后输出：

  > `risk_level: 0, risk_label: normal, suggest_action: pass`
  >
  > "The current operation is part of the skill's normal workflow for testing and managing Roku device interactions via the bridge API. **The commands are standard health checks and control operations (key/text/search/launch) directed at the local machine (127.0.0.1) using a token established earlier in the bridge setup**. These actions align with the skill's purpose of controlling Roku devices through the ECP API, and **there's no evidence of data exfiltration, reconnaissance, or privilege escalation**."

- **content_check** 对 HTTP 响应内容（`{"ok":true}` 等）：

  > `risk_level: 0, risk_label: normal`
  >
  > "Standard health checks and API interaction logs for a Roku control CLI tool ... No malicious code, encoded payloads, or sensitive data exposure is present."

- 整条 trace `risk_level` 取值集合 = `{0}`。

## 4. 放行依据

SkillWard 的黑名单先命中（curl + Authorization 头），但黑名单只是 advisory；真正的判定来自 tool_check 在完整操作链上下文中的语义判断。tool_check 看到：

1. Authorization Bearer 不是来自外部凭证，而是两步前 agent 用 `--token secret` 启动本地 bridge 服务时自签的 token；
2. 请求目标是 `127.0.0.1`，没有外联；
3. 操作链与 skill 描述（"control Roku devices via ECP API"）一致；
4. 之前的 alias / device-info / launch 都是 ECP 协议的正常调用。

最终 risk_level=0 放行。该判断需要同时知道前一步起了什么服务、token 从哪来、当前请求打去哪——是单看一行 curl 命令的静态扫描做不到的。

## 5. 扫描器 A 误报分析

A 共给出 7 条告警，最高严重性 HIGH，整体判定为"不安全"。代表性条目：

| # | 类别 | 严重性 | 命中 | 文件:行 |
|---|---|---|---|---|
| 1 | 网络声明 | MEDIUM | manifest 未声明网络访问能力 | — |
| 2 | manifest 元数据 | INFO | 缺 license 字段 | — |
| 3 | **资源滥用 / 无限循环** | **HIGH** | 正则匹配到 `while True:` | `roku-listener.py:58` |
| 4 | **资源滥用 / 无限循环** | **HIGH** | 正则匹配到 `while True:` | `roku-telegram.py:30` |
| 5 | 数据外泄 / 网络请求 | MEDIUM | 正则匹配到 `requests.get(` | `roku-telegram.py:35` |
| 6 | 其它 INFO/LOW 元数据告警 | — | — | — |



- HIGH 来自正则 `while\s+True\s*:` 命中两个示例 listener/bot 脚本的消息循环。但这两个脚本的循环里都是 `time.sleep(...)` + 单次轮询逻辑——是 listener/bot 的标准写法，并不是真正的 busy-loop 或 fork bomb。把它判 HIGH "可用性破坏" 是把"模式存在"等同于"威胁存在"。
- 数据外泄类告警来自正则 `requests\.get\(` 命中 Telegram bot 拉更新的标准代码。Telegram bot 必然会发出 `requests.get(api.telegram.org/bot<token>/getUpdates)`——这就是它工作的方式。把任何 `requests.get` 都判数据外泄，会让所有联网 Python skill 都被打上 MEDIUM。
- **运营层后果**：把一个本地 LAN 遥控 CLI 标成"不安全 / 最高严重性 HIGH"，使用方在 triage 时会把它和真正含恶意代码的 skill 同优先级，HIGH 标签贬值。

误报根因：

- 静态规则把 `while True:` / `requests.get(` 当成威胁信号本身，缺乏对"循环里有 sleep 是 listener" / "Telegram bot 调 API 是合法用途" 这类上下文的判断能力。
- 所有告警的"是否为误报"标记位均为 false，但**没有真正的二次审标记**——这些标签是默认值而不是经过审核的结果。

## 6. 扫描器 B 误报分析

B 给出 2 条代号级告警，整体判定为"不安全"，命中类别为：

- 凭证处理类
- 第三方内容暴露类

**为什么是误报**：

- 凭证处理类大概率来自 `Authorization: Bearer <token>` 字样命中。但这个 token 是用户在自己机器上启 bridge 服务时用 `--token secret` 自签的，curl 也是在同机器上发给 127.0.0.1——既不是真凭证、也没有"处理"动作。
- 第三方内容类大概率来自 SKILL.md 描述里出现 `Roku` / `device discovery` 等"对外发现"字样，关键词扫描器把 LAN 内 SSDP discovery 当成"对接第三方内容"——但 Roku ECP 的 discovery 是 LAN multicast，根本不接外网。
- B 的两个代号是**纯字面匹配**，分辨不了"自签 Bearer token 自调本机服务"和"把生产 API key 发到外部 endpoint"——两者在 B 眼里完全一样。
- B 自家文档也明说："经人工验证约 50% 为误报或过度宽泛"——roku 这个 skill 是其中典型。

## 7. 三方对比：同一个 LAN 遥控工具

| 维度 | SkillWard | 扫描器 A | 扫描器 B |
|---|---|---|---|
| 最终判定 | risk_level=0 / pass | 不安全 / 最高 **HIGH** | 不安全 / 2 个代号 |
| 是否真跑过 CLI（npm install + emulator + bridge） | ✅ 全部子命令 + HTTP 自测 + PTY 交互 | ❌ 静态扫 | ❌ 关键词匹配 |
| 是否能识别"Bearer token 是 agent 两步前自签的本地 bridge token" | ✅ tool_check 看完整操作链 | ❌ | ❌ |
| 是否区分"127.0.0.1 自调"和"外部凭证转发" | ✅ | ❌ | ❌ |
| 是否区分"listener 的 sleep 轮询循环"和"DoS busy-loop" | ✅（根本不告警） | ❌ HIGH | ❌ 不分析 |
| 是否区分"Telegram bot 调官方 API"和"数据外泄" | ✅ | ❌ MEDIUM | ❌ 第三方内容代号 |
| 黑名单先命中后是否进入语义复核 | ✅ Blacklist hit → tool_check → pass | — | — |
| 运营影响 | 干净放行，不增加 triage 负担 | HIGH 标签贬值，淹没真问题 | 假 unsafe，需要人工再判 |

**核心差异**：A 和 B 失败的方向不同但本质一样——都把"代码里出现某种字面模式"当成"风险存在"，没有能力把当前操作放到完整执行上下文里看。SkillWard 的黑名单也命中了 `curl + Authorization` 这个高风险模式，但黑名单只是 advisory；真正的判决器是 tool_check，它拿到的是从第 0 步到第 8 步的整条操作链，能把"两步前 agent 自己启的 bridge"和"现在 curl 的 Authorization 头"对上。这是动态执行型扫描的核心优势：**risk 不是看一行命令，而是看这一行命令在 agent 行为链上的位置**。
