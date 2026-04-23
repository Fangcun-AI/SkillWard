# 更新报告 · 2026-04-10

---

## 变更详情

### 1. 显式启动 Gateway 守护进程

**问题**:Stage C 沙箱在 Phase 2 调用 exec 工具时频繁出现 `exec denied`。根因在于容器启动脚本未显式启动 Gateway 守护进程(`:18789`),Guardian 插件无法与其完成审批握手。

**修复**:

- 在 Phase 1 开始前新增 Gateway 启动逻辑(`node /opt/openclaw/openclaw.mjs gateway --allow-unconfigured`),启动后轮询端口就绪状态,最多等待 10 秒。
- 容器退出前追加清理逻辑,对 `GATEWAY_PID` 执行 `kill` + `wait`,避免残留守护进程。

```bash
# ── Start Gateway daemon (required for exec tool approval RPC) ──
node /opt/openclaw/openclaw.mjs gateway --allow-unconfigured &
GATEWAY_PID=$!
for _i in $(seq 1 10); do
    if ss -tlnp 2>/dev/null | grep -q ':18789 ' \
       || netstat -tlnp 2>/dev/null | grep -q ':18789 '; then
        echo "[guardian] Gateway daemon ready on :18789"
        break
    fi
    sleep 1
done
```

### 2. 拆分 Phase 1 / Phase 2 双 Gateway

**问题**:仅在容器启动时启动一次 Gateway 并不足够。Phase 1 需要 Guardian **关闭**(agent 先自主完成环境准备),Phase 2 才重新启用 Guardian;单实例 Gateway 无法同时覆盖两种加载状态。

**修复**:将 Gateway 同步拆分为两段独立实例。

- **Phase 1 Gateway**:移出 Guardian 扩展目录 → 启动 Gateway(不加载 Guardian) → 完成环境准备 → 终止该 Gateway。
- **Phase 2 Gateway**:还原 Guardian 扩展目录 → 重新启动 Gateway(此次加载 Guardian) → 执行被测 skill。

---

## 效果

- 解决沙箱场景下 Guardian 的 exec 审批失败问题。
- 高风险 skill 不再因此被错判为 `ERROR` 或 `TIMEOUT`。
