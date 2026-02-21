#!/bin/bash
# scripts/linux/fileless_attack.sh
#
# Detection: Fileless attacks, memory-only processes, /dev/shm abuse
# MITRE: T1059.004, T1620, T1027
# Requires: Root recommended for /proc access
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

# --- Processes running from deleted files ---
deleted_procs="[]"
del_entries=()
if [ -d /proc ]; then
    for pid_dir in /proc/[0-9]*; do
        pid=$(basename "$pid_dir")
        exe=$(readlink -f "$pid_dir/exe" 2>/dev/null || true)
        if echo "$exe" | grep -q "(deleted)"; then
            cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
            user=$(stat -c%U "$pid_dir" 2>/dev/null || echo "unknown")
            del_entries+=("{\"pid\":$pid,\"exe\":\"$exe\",\"cmdline\":$(json_str "$cmdline"),\"user\":\"$user\"}")
        fi
    done
fi
if [ ${#del_entries[@]} -gt 0 ]; then
    deleted_procs=$(printf '%s,' "${del_entries[@]}" | sed 's/,$//')
    deleted_procs="[${deleted_procs}]"
fi

# --- /dev/shm suspicious files ---
shm_files="[]"
shm_entries=()
if [ -d /dev/shm ]; then
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        size=$(stat -c%s "$f" 2>/dev/null || echo "0")
        owner=$(stat -c%U "$f" 2>/dev/null || echo "unknown")
        perms=$(stat -c%a "$f" 2>/dev/null || echo "unknown")
        shm_entries+=("{\"path\":\"$f\",\"size\":$size,\"owner\":\"$owner\",\"permissions\":\"$perms\"}")
    done < <(find /dev/shm -type f 2>/dev/null | head -20)
fi
if [ ${#shm_entries[@]} -gt 0 ]; then
    shm_files=$(printf '%s,' "${shm_entries[@]}" | sed 's/,$//')
    shm_files="[${shm_files}]"
fi

# --- Processes with suspicious /proc/*/maps (memfd_create) ---
memfd_procs="[]"
memfd_entries=()
if [ -d /proc ]; then
    for pid_dir in /proc/[0-9]*; do
        pid=$(basename "$pid_dir")
        if grep -q "memfd:" "$pid_dir/maps" 2>/dev/null; then
            cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
            user=$(stat -c%U "$pid_dir" 2>/dev/null || echo "unknown")
            memfd_entries+=("{\"pid\":$pid,\"cmdline\":$(json_str "$cmdline"),\"user\":\"$user\"}")
        fi
    done
fi
if [ ${#memfd_entries[@]} -gt 0 ]; then
    memfd_procs=$(printf '%s,' "${memfd_entries[@]}" | sed 's/,$//')
    memfd_procs="[${memfd_procs}]"
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
  "check": "fileless_attack",
  "deleted_exe_processes": ${deleted_procs},
  "shm_files": ${shm_files},
  "memfd_processes": ${memfd_procs},
  "errors": ${err_json}
}
JSONEOF
