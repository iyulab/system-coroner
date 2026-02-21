#!/bin/bash
# scripts/linux/lolbin_abuse.sh
#
# Detection: GTFOBins abuse (curl, wget, python, nc, ncat, socat, etc.)
# MITRE: T1059, T1105, T1218
# Requires: Standard user
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

# --- Running processes with suspicious patterns ---
suspicious_procs="[]"
proc_entries=()
# GTFOBins: common legitimate tools used for malicious purposes
patterns="curl.*http|wget.*http|python.*-c.*import|perl.*-e|ruby.*-e|nc.*-e|ncat.*-e|socat.*exec|php.*-r|lua.*-e|awk.*system|base64.*decode|openssl.*s_client"

if command -v ps &>/dev/null; then
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        pid=$(echo "$line" | awk '{print $1}')
        user=$(echo "$line" | awk '{print $2}')
        cmd=$(echo "$line" | awk '{$1=$2=""; print $0}' | sed 's/^ *//')
        proc_entries+=("{\"pid\":$pid,\"user\":\"$user\",\"command\":$(json_str "$cmd")}")
    done < <(ps aux 2>/dev/null | grep -iE "$patterns" | grep -v grep | awk '{print $2, $1, $0}' | head -20)
fi
if [ ${#proc_entries[@]} -gt 0 ]; then
    suspicious_procs=$(printf '%s,' "${proc_entries[@]}" | sed 's/,$//')
    suspicious_procs="[${suspicious_procs}]"
fi

# --- SUID/SGID binaries in unusual locations ---
suid_binaries="[]"
suid_entries=()
# Check non-standard paths for SUID binaries
for dir in /tmp /var/tmp /dev/shm /home /opt; do
    if [ -d "$dir" ]; then
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            owner=$(stat -c%U "$f" 2>/dev/null || echo "unknown")
            perms=$(stat -c%a "$f" 2>/dev/null || echo "unknown")
            suid_entries+=("{\"path\":\"$f\",\"owner\":\"$owner\",\"permissions\":\"$perms\"}")
        done < <(find "$dir" -perm /6000 -type f 2>/dev/null | head -10)
    fi
done
if [ ${#suid_entries[@]} -gt 0 ]; then
    suid_binaries=$(printf '%s,' "${suid_entries[@]}" | sed 's/,$//')
    suid_binaries="[${suid_binaries}]"
fi

# --- Capabilities on binaries ---
cap_binaries="[]"
cap_entries=()
if command -v getcap &>/dev/null; then
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        path=$(echo "$line" | awk '{print $1}')
        caps=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^ *//')
        cap_entries+=("{\"path\":\"$path\",\"capabilities\":\"$caps\"}")
    done < <(getcap -r /usr /bin /sbin 2>/dev/null | head -20)
fi
if [ ${#cap_entries[@]} -gt 0 ]; then
    cap_binaries=$(printf '%s,' "${cap_entries[@]}" | sed 's/,$//')
    cap_binaries="[${cap_binaries}]"
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
  "check": "lolbin_abuse",
  "suspicious_processes": ${suspicious_procs},
  "suid_binaries": ${suid_binaries},
  "capability_binaries": ${cap_binaries},
  "errors": ${err_json}
}
JSONEOF
