#!/bin/bash
# scripts/linux/c2_connections.sh
#
# Detection: C2 communication, reverse shells, beacon traffic
# MITRE: T1071, T1048, T1095
# Requires: Standard user (root recommended for full process details)
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

# --- External TCP connections with process mapping ---
connections="[]"
if command -v ss &>/dev/null; then
    # ss -tupn: TCP/UDP, show process, numeric, established
    raw=$(ss -tupn state established 2>/dev/null || true)
    connections=$(echo "$raw" | awk 'NR>1 && $5 !~ /^(127\.|::1|0\.0\.0\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/ {
        split($5, remote, ":");
        split($4, local, ":");
        proc = "";
        if (match($0, /users:\(\("([^"]+)",pid=([0-9]+)/, m)) {
            proc = m[1] ":" m[2];
        }
        printf "{\"local_address\":\"%s\",\"local_port\":%s,\"remote_address\":\"%s\",\"remote_port\":%s,\"protocol\":\"%s\",\"process\":\"%s\"},", local[1], local[length(local)], remote[1], remote[length(remote)], $1, proc
    }' 2>/dev/null | sed 's/,$//')
    connections="[${connections}]"
elif command -v netstat &>/dev/null; then
    raw=$(netstat -tupn 2>/dev/null | grep ESTABLISHED || true)
    connections=$(echo "$raw" | awk '$5 !~ /^(127\.|::1|0\.0\.0\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/ {
        split($4, local, ":");
        split($5, remote, ":");
        printf "{\"local_address\":\"%s\",\"local_port\":%s,\"remote_address\":\"%s\",\"remote_port\":%s,\"protocol\":\"%s\",\"process\":\"%s\"},", local[1], local[length(local)], remote[1], remote[length(remote)], $1, $7
    }' 2>/dev/null | sed 's/,$//')
    connections="[${connections}]"
else
    errors+=("no ss or netstat available")
fi

# --- Suspicious listening ports ---
suspicious_listeners="[]"
suspicious_ports="4444|1337|8080|9001|5555|6666|7777|8888|1234|31337"
if command -v ss &>/dev/null; then
    raw=$(ss -tlnp 2>/dev/null | grep -E ":($suspicious_ports) " || true)
    listeners=$(echo "$raw" | awk 'NF>0 {
        split($4, local, ":");
        proc = "";
        if (match($0, /users:\(\("([^"]+)",pid=([0-9]+)/, m)) {
            proc = m[1] ":" m[2];
        }
        printf "{\"port\":%s,\"process\":\"%s\"},", local[length(local)], proc
    }' 2>/dev/null | sed 's/,$//')
    suspicious_listeners="[${listeners}]"
fi

# --- DNS resolution cache (from /etc/hosts and recent resolvectl) ---
dns_info="[]"
if command -v resolvectl &>/dev/null; then
    raw=$(resolvectl statistics 2>/dev/null | head -20 || true)
    if [ -n "$raw" ]; then
        dns_info="[{\"source\":\"resolvectl\",\"data\":$(json_str "$(echo "$raw" | head -5)")}]"
    fi
fi

# --- Build JSON output ---
err_json="[]"
if [ ${#errors[@]} -gt 0 ]; then
    err_json=$(printf '"%s",' "${errors[@]}" | sed 's/,$//')
    err_json="[${err_json}]"
fi

cat <<JSONEOF
{
  "collected_at": "${collected_at}",
  "hostname": "${hostname}",
  "check": "c2_connections",
  "external_connections": ${connections},
  "suspicious_listeners": ${suspicious_listeners},
  "dns_cache": ${dns_info},
  "errors": ${err_json}
}
JSONEOF
