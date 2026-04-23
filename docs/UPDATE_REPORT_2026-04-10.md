# Update Report · 2026-04-10

---

## Changes

### 1. Start the Gateway daemon explicitly

**Problem**: In Stage C sandbox runs, Guardian frequently hit `exec denied` when invoking the exec tool during Phase 2. The root cause: the container bootstrap script did not start the Gateway daemon (`:18789`), so the Guardian plugin could not complete the approval handshake.

**Fix**:

- Added Gateway startup logic before Phase 1 (`node /opt/openclaw/openclaw.mjs gateway --allow-unconfigured`), then polled the port until ready (up to 10 seconds).
- Added cleanup before container exit — `kill` + `wait` on `GATEWAY_PID` to avoid leaving orphan daemons.

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

### 2. Split Phase 1 / Phase 2 into two Gateway instances

**Problem**: Starting the Gateway once at container boot is not enough. Phase 1 requires Guardian to be **disabled** (the agent prepares the environment on its own), and Phase 2 re-enables Guardian. A single Gateway instance cannot cover both loading states.

**Fix**: Split the Gateway into two independent lifecycles.

- **Phase 1 Gateway**: move the Guardian extension out of its directory → start Gateway (without Guardian) → complete environment preparation → terminate this Gateway.
- **Phase 2 Gateway**: restore the Guardian extension directory → restart Gateway (this time with Guardian loaded) → execute the target skill.

---

## Outcome

- Resolves Guardian's exec-approval failures in sandbox runs.
- High-risk skills are no longer misclassified as `ERROR` or `TIMEOUT` because of this issue.
