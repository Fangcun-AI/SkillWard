# X3: Reference Scanner False Positive, SkillWard Correctly Passes — `gumadeiras_roku`

## 1. What this skill does

`gumadeiras_roku` describes itself as:

> "Fast TypeScript CLI for controlling Roku devices via the ECP API."

It is a **local LAN Roku TV remote control tool**, npm package name `roku-ts-cli`. Core capabilities:

- `roku discover` — discovers Roku devices on the LAN
- `roku alias set <name> <ip>` — assigns an alias to a device/app
- `roku --host <name> device-info / apps / active-app / launch / command / literal` — sends remote commands to a TV via Roku's official ECP (External Control Protocol), launches apps, types text
- `roku bridge` — runs a small HTTP bridge service on the local machine (default port 19839), authenticated by Bearer token, exposing the above capabilities as REST endpoints for other local tools
- Comes with two Python sample scripts `roku-listener.py` / `roku-telegram.py`, demonstrating how to write a long-running message listener loop

In short: a **purely LAN-scoped TV remote CLI**. All targets are on the same subnet or 127.0.0.1 — no outbound traffic, no credential upload, no filesystem intrusion.

## 2. Reasons for the false positive

This skill simultaneously trips two blind spots in static rules:

1. **The `while True:` pattern is rated HIGH "Resource Abuse / Infinite Loop"**: the sample scripts `roku-listener.py` and `roku-telegram.py` use `while True:` to write a message-polling loop — this is the standard idiom for any listener/bot code, not a DoS pattern. But a pure regex scanner only looks at literal patterns.
2. **`requests.get(` is rated MEDIUM "Data Exfiltration"**: the Telegram sample script contains `resp = requests.get(url, params=params, timeout=15)` to pull Telegram bot updates — this is the standard usage for a Telegram bot, not data exfiltration.
3. **`Authorization: Bearer <token>` is hit by the keyword scanner under "credential handling"**: the bridge service uses a Bearer token that the user self-issues for authentication (the token is set by the user, and curl is sending it on the same machine to 127.0.0.1), but any scanner that sees an `Authorization` header will slap on a "credential handling" codename.

All three are **pattern-correct, semantically-wrong** alerts.

## 3. Skill behavior observed by SkillWard during the Docker test

Trace file: `results\skill_gumadeiras_roku.txt`

In phase2 the agent really runs the skill **end-to-end**:

1. **Installs the CLI**: `npm install -g roku-ts-cli@latest`, confirms `roku --version` works.
2. **Starts the built-in emulator**: `roku server --port 8060` (background process), used as a "virtual Roku device".
3. **Discovery**: `roku discover` finds the emulator at `172.17.0.2:8060`.
4. **Configures aliases**:

   ```
   roku alias set demo 127.0.0.1
   roku alias set office 192.168.1.20
   roku alias set livingroom 172.17.0.2:8060
   roku alias set plex 13535
   roku alias set netflix 4
   ```

5. **Runs through the main CLI subcommands**: `device-info / apps / active-app / current-app / search / launch / command home / literal "hello from devbox"`, all succeed (only the title search the emulator doesn't support returns 404).
6. **Bridge service full flow**:

   ```
   roku bridge install-service --port 19839 --token secret --host livingroom --user
   roku bridge start ... --user      # systemctl is unavailable in the container, skipped
   roku bridge status / diagnose
   roku --host livingroom bridge --listen 19839 --token secret    # foreground start instead
   ```

7. **HTTP endpoint self-test** (key step: this is where the SkillWard blacklist fires):

   ```
   curl -sS http://127.0.0.1:19839/health -H 'Authorization: Bearer secret'
   curl -sS http://127.0.0.1:19839/health?deep=1 -H 'Authorization: Bearer secret'
   curl -X POST http://127.0.0.1:19839/key    -d '{"key":"home"}'
   curl -X POST http://127.0.0.1:19839/text   -d '{"text":"hello"}'
   curl -X POST http://127.0.0.1:19839/search -d '{"title":"Stargate"}'
   curl -X POST http://127.0.0.1:19839/launch -d '{"app":"4"}'
   ```

8. **Enters PTY interactive mode**, tests keyboard input, then exits cleanly.
9. **Cleanup**: `bridge stop`, `bridge uninstall`, `process kill` of the background process.
10. **Trace finishes**: `aborted: false`, agent stops normally.

Key events SkillWard captures along the way:

- **Blacklist hit**: `Blacklist hit: exec | curl with authentication header (credential forwarding)` — fires in step 7 when the curl is sent with the `Authorization: Bearer secret` header. This is an **advisory**, escalated to tool_check for review.
- **tool_check**, given the full 8-step operation chain as context, outputs:

  > `risk_level: 0, risk_label: normal, suggest_action: pass`
  >
  > "The current operation is part of the skill's normal workflow for testing and managing Roku device interactions via the bridge API. **The commands are standard health checks and control operations (key/text/search/launch) directed at the local machine (127.0.0.1) using a token established earlier in the bridge setup**. These actions align with the skill's purpose of controlling Roku devices through the ECP API, and **there's no evidence of data exfiltration, reconnaissance, or privilege escalation**."

- **content_check** on the HTTP response contents (`{"ok":true}` etc.):

  > `risk_level: 0, risk_label: normal`
  >
  > "Standard health checks and API interaction logs for a Roku control CLI tool ... No malicious code, encoded payloads, or sensitive data exposure is present."

- Across the whole trace, the set of `risk_level` values = `{0}`.

## 4. Pass-through rationale

SkillWard's blacklist fires first (curl + Authorization header), but the blacklist is only an advisory; the real verdict comes from tool_check's semantic judgment over the full operation chain. tool_check sees:

1. The Authorization Bearer is not from an external credential — it's the token the agent self-issued via `--token secret` two steps earlier when starting the local bridge service;
2. The request target is `127.0.0.1`, no outbound traffic;
3. The operation chain matches the skill description ("control Roku devices via ECP API");
4. The earlier alias / device-info / launch steps are all normal ECP protocol calls.

Final verdict: risk_level=0, pass. Making this judgment requires knowing what service was started in the previous step, where the token came from, and where the current request is going — none of which a static scan of a single curl line can do.

## 5. Scanner A false-positive analysis

Scanner A produces 7 alerts in total, with maximum severity HIGH and an overall verdict of "unsafe". Representative entries:

| # | Category | Severity | Match | File:Line |
|---|---|---|---|---|
| 1 | Network declaration | MEDIUM | manifest does not declare network access capability | — |
| 2 | manifest metadata | INFO | missing license field | — |
| 3 | **Resource abuse / infinite loop** | **HIGH** | regex matched `while True:` | `roku-listener.py:58` |
| 4 | **Resource abuse / infinite loop** | **HIGH** | regex matched `while True:` | `roku-telegram.py:30` |
| 5 | Data exfiltration / network request | MEDIUM | regex matched `requests.get(` | `roku-telegram.py:35` |
| 6 | Other INFO/LOW metadata alerts | — | — | — |



- The HIGH comes from the regex `while\s+True\s*:` matching the message loop in two sample listener/bot scripts. But both loops contain `time.sleep(...)` + single-poll logic — they are the standard listener/bot idiom, not a real busy-loop or fork bomb. Rating it HIGH "availability disruption" equates "the pattern exists" with "the threat exists".
- The data-exfiltration alert comes from the regex `requests\.get\(` matching the standard Telegram bot update-pulling code. A Telegram bot is required to fire `requests.get(api.telegram.org/bot<token>/getUpdates)` — that's how it works. Rating any `requests.get` as data exfiltration would label every networked Python skill MEDIUM.
- **Operational consequence**: tagging a local LAN remote control CLI as "unsafe / max severity HIGH" causes operators triaging it to put it at the same priority as skills that genuinely contain malicious code, devaluing the HIGH label.

Root cause of the false positive:

- Static rules treat `while True:` / `requests.get(` as threat signals in themselves, lacking the contextual judgment to recognize "a loop with sleep is a listener" or "a Telegram bot calling its API is a legitimate use".
- All alerts have the "is false positive" flag set to false, but **there is no real second-pass review** — these labels are defaults rather than the result of an audit.

## 6. Scanner B false-positive analysis

Scanner B produces 2 codename-level alerts, with an overall verdict of "unsafe" and the categories hit being:

- Credential handling
- Third-party content exposure

**Why this is a false positive**:

- The credential handling category most likely fires on the literal `Authorization: Bearer <token>`. But this token is one the user self-issued via `--token secret` when starting the bridge service on their own machine, and curl is sending it from the same machine to 127.0.0.1 — it's neither a real credential nor a "handling" action.
- The third-party content category most likely fires because SKILL.md's description contains words like `Roku` / `device discovery` (i.e. "outbound discovery"), and the keyword scanner mistakes LAN SSDP discovery for "interfacing with third-party content" — but Roku ECP discovery is LAN multicast, never touching the outside world.
- B's two codenames are **pure literal matching**, unable to distinguish "self-issued Bearer token, self-call to local service" from "shipping a production API key out to an external endpoint" — the two are completely identical in B's eyes.
- B's own documentation states explicitly: "after manual verification, roughly 50% are false positives or overly broad" — the roku skill is a textbook case among them.

## 7. Three-way comparison: the same LAN remote control tool

| Dimension | SkillWard | Scanner A | Scanner B |
|---|---|---|---|
| Final verdict | risk_level=0 / pass | unsafe / max **HIGH** | unsafe / 2 codenames |
| Actually runs the CLI (npm install + emulator + bridge) | ✅ All subcommands + HTTP self-test + PTY interaction | ❌ Static scan | ❌ Keyword matching |
| Recognizes "the Bearer token is the local bridge token the agent self-issued two steps earlier" | ✅ tool_check sees the full operation chain | ❌ | ❌ |
| Distinguishes "127.0.0.1 self-call" from "external credential forwarding" | ✅ | ❌ | ❌ |
| Distinguishes "listener's sleep polling loop" from "DoS busy-loop" | ✅ (no alert at all) | ❌ HIGH | ❌ Doesn't analyze |
| Distinguishes "Telegram bot calling its official API" from "data exfiltration" | ✅ | ❌ MEDIUM | ❌ Third-party content codename |
| After blacklist hit, escalates to semantic review | ✅ Blacklist hit → tool_check → pass | — | — |
| Operational impact | Cleanly passes, no triage burden added | HIGH label devalued, real problems drowned out | False unsafe, requires manual re-judgment |

**Core difference**: A and B fail in different directions but identically in essence — both treat "a literal pattern appearing in code" as "risk exists", lacking the ability to place the current operation in its full execution context. SkillWard's blacklist also fires on the high-risk pattern `curl + Authorization`, but the blacklist is only an advisory; the real arbiter is tool_check, which receives the entire operation chain from step 0 to step 8 and can match "the bridge the agent started two steps earlier" with "the Authorization header on the current curl". This is the core advantage of dynamic-execution scanning: **risk is judged not by a single command line, but by where that command line sits in the agent's behavior chain**.
