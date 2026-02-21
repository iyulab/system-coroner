#!/bin/bash
# scripts/linux/log_tampering.sh
#
# Detection: Log deletion, rotation manipulation, audit bypass
# MITRE: T1070.001, T1070.002, T1562.001
# Requires: Root recommended for full log access
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

# --- Log file sizes ---
log_sizes="[]"
log_entries=()
for logfile in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure /var/log/kern.log /var/log/daemon.log; do
    if [ -f "$logfile" ]; then
        size=$(stat -c%s "$logfile" 2>/dev/null || echo "0")
        size_mb=$(echo "scale=1; $size / 1048576" | bc 2>/dev/null || echo "0")
        mtime=$(stat -c%Y "$logfile" 2>/dev/null || echo "0")
        mtime_str=$(date -d @"$mtime" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")
        note="normal"
        # Flag if suspiciously small (< 1KB for important logs)
        if [ "$size" -lt 1024 ] 2>/dev/null; then
            note="suspiciously small"
        fi
        log_entries+=("{\"file\":\"$logfile\",\"size_bytes\":$size,\"size_mb\":$size_mb,\"modified\":\"$mtime_str\",\"note\":\"$note\"}")
    fi
done
if [ ${#log_entries[@]} -gt 0 ]; then
    log_sizes=$(printf '%s,' "${log_entries[@]}" | sed 's/,$//')
    log_sizes="[${log_sizes}]"
fi

# --- Empty or missing critical logs ---
missing_logs="[]"
missing_entries=()
for logfile in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure; do
    if [ ! -f "$logfile" ]; then
        missing_entries+=("{\"file\":\"$logfile\",\"status\":\"missing\"}")
    elif [ ! -s "$logfile" ]; then
        missing_entries+=("{\"file\":\"$logfile\",\"status\":\"empty\"}")
    fi
done
if [ ${#missing_entries[@]} -gt 0 ]; then
    missing_logs=$(printf '%s,' "${missing_entries[@]}" | sed 's/,$//')
    missing_logs="[${missing_logs}]"
fi

# --- Last login/reboot/shutdown events ---
last_events="[]"
if command -v last &>/dev/null; then
    raw=$(last -20 -F 2>/dev/null || last -20 2>/dev/null || true)
    if [ -n "$raw" ]; then
        _le=()
        while IFS= read -r _line; do
            [[ -z "$_line" || "$_line" == wtmp* ]] && continue
            _le+=($(json_str "$_line"))
        done < <(echo "$raw" | head -15)
        if [ ${#_le[@]} -gt 0 ]; then
            last_events=$(printf '%s,' "${_le[@]}" | sed 's/,$//')
            last_events="[${last_events}]"
        fi
    fi
fi

# --- Audit daemon status ---
auditd_status="null"
if command -v systemctl &>/dev/null; then
    status=$(systemctl is-active auditd 2>/dev/null || echo "not-installed")
    enabled=$(systemctl is-enabled auditd 2>/dev/null || echo "not-installed")
    auditd_status="{\"active\":\"$status\",\"enabled\":\"$enabled\"}"
fi

# --- journalctl verify (if available) ---
journal_integrity="null"
if command -v journalctl &>/dev/null; then
    verify=$(journalctl --verify 2>&1 | tail -5 || true)
    if echo "$verify" | grep -qi "pass"; then
        journal_integrity="\"pass\""
    elif echo "$verify" | grep -qi "fail"; then
        journal_integrity="\"fail\""
    else
        journal_integrity="\"unknown\""
    fi
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
  "check": "log_tampering",
  "log_sizes": ${log_sizes},
  "missing_logs": ${missing_logs},
  "last_events": ${last_events},
  "auditd_status": ${auditd_status},
  "journal_integrity": ${journal_integrity},
  "errors": ${err_json}
}
JSONEOF
