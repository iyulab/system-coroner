#!/bin/bash
# scripts/linux/lateral_movement.sh
#
# Detection: SSH lateral movement, tunneling, remote execution
# MITRE: T1021.004, T1572, T1563
# Requires: Root recommended for log access
# Expected runtime: ~5s

set -o pipefail

# JSON string escape (pure bash, no python3 dependency)
json_str() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '"%s"' "$s"
}

collected_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
hostname=$(hostname 2>/dev/null || echo "unknown")
errors=()

# --- SSH sessions (current) ---
ssh_sessions="[]"
ssh_entries=()
if command -v who &>/dev/null; then
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        user=$(echo "$line" | awk '{print $1}')
        tty=$(echo "$line" | awk '{print $2}')
        source=$(echo "$line" | grep -oP '\(.*?\)' | tr -d '()' || true)
        ssh_entries+=("{\"user\":\"$user\",\"tty\":\"$tty\",\"source\":\"$source\"}")
    done < <(who 2>/dev/null | grep -v "^$")
fi
if [ ${#ssh_entries[@]} -gt 0 ]; then
    ssh_sessions=$(printf '%s,' "${ssh_entries[@]}" | sed 's/,$//')
    ssh_sessions="[${ssh_sessions}]"
fi

# --- Recent SSH logins from auth.log ---
recent_ssh="[]"
authlog=""
for f in /var/log/auth.log /var/log/secure; do
    [ -f "$f" ] && authlog="$f" && break
done
if [ -n "$authlog" ]; then
    ssh_login_entries=()
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        user=$(echo "$line" | grep -oP 'for \K\S+' || true)
        source=$(echo "$line" | grep -oP 'from \K[0-9.]+' || true)
        ssh_login_entries+=("{\"user\":\"$user\",\"source_ip\":\"$source\",\"raw\":$(json_str "$line")}")
    done < <(tail -500 "$authlog" 2>/dev/null | grep "Accepted" | tail -20)
    if [ ${#ssh_login_entries[@]} -gt 0 ]; then
        recent_ssh=$(printf '%s,' "${ssh_login_entries[@]}" | sed 's/,$//')
        recent_ssh="[${recent_ssh}]"
    fi
fi

# --- SSH tunnels / port forwarding ---
ssh_tunnels="[]"
tunnel_entries=()
if command -v ss &>/dev/null; then
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        tunnel_entries+=("{\"raw\":$(json_str "$line")}")
    done < <(ss -tlnp 2>/dev/null | grep ssh | head -10)
fi
if [ ${#tunnel_entries[@]} -gt 0 ]; then
    ssh_tunnels=$(printf '%s,' "${tunnel_entries[@]}" | sed 's/,$//')
    ssh_tunnels="[${ssh_tunnels}]"
fi

# --- Known remote execution tools ---
remote_tools="[]"
rt_entries=()
for tool in pssh ansible-playbook knife salt-call puppet; do
    if command -v "$tool" &>/dev/null; then
        path=$(which "$tool" 2>/dev/null)
        rt_entries+=("{\"tool\":\"$tool\",\"path\":\"$path\"}")
    fi
done
if [ ${#rt_entries[@]} -gt 0 ]; then
    remote_tools=$(printf '%s,' "${rt_entries[@]}" | sed 's/,$//')
    remote_tools="[${remote_tools}]"
fi

# --- Build output ---
err_json="[]"
if [ ${#errors[@]} -gt 0 ]; then
    err_json=$(printf '"%s",' "${errors[@]}" | sed 's/,$//')
    err_json="[${err_json}]"
fi

cat <<JSONEOF
{
  "collected_at": "${collected_at}",
  "hostname": "${hostname}",
  "check": "lateral_movement",
  "ssh_sessions": ${ssh_sessions},
  "recent_ssh_logins": ${recent_ssh},
  "ssh_tunnels": ${ssh_tunnels},
  "remote_tools": ${remote_tools},
  "errors": ${err_json}
}
JSONEOF
