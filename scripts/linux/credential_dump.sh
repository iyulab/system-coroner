#!/bin/bash
# scripts/linux/credential_dump.sh
#
# Detection: Credential dumping, /etc/shadow access, hash extraction tools
# MITRE: T1003.008, T1003, T1552.001
# Requires: Root recommended
# Expected runtime: ~5s

set -o pipefail

collected_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
hostname=$(hostname 2>/dev/null || echo "unknown")
errors=()

# --- /etc/shadow access permissions ---
shadow_info="null"
if [ -f /etc/shadow ]; then
    perms=$(stat -c%a /etc/shadow 2>/dev/null || echo "unknown")
    owner=$(stat -c%U:%G /etc/shadow 2>/dev/null || echo "unknown")
    note="normal"
    # Shadow should be 640 or 000, owned by root
    if [ "$perms" != "640" ] && [ "$perms" != "000" ] && [ "$perms" != "600" ]; then
        note="unusual permissions"
    fi
    shadow_info="{\"permissions\":\"$perms\",\"owner\":\"$owner\",\"note\":\"$note\"}"
fi

# --- Known credential tools in common paths ---
credential_tools="[]"
tool_entries=()
tool_names="mimipenguin john hashcat hydra medusa ncrack ophcrack"
for tool in $tool_names; do
    path=$(which "$tool" 2>/dev/null || true)
    if [ -n "$path" ]; then
        tool_entries+=("{\"name\":\"$tool\",\"path\":\"$path\"}")
    fi
done
# Also check /tmp, /dev/shm for suspicious binaries
for dir in /tmp /dev/shm /var/tmp; do
    if [ -d "$dir" ]; then
        for tool in $tool_names; do
            found=$(find "$dir" -name "$tool*" -type f 2>/dev/null | head -3 || true)
            while IFS= read -r f; do
                [ -z "$f" ] && continue
                tool_entries+=("{\"name\":\"$tool\",\"path\":\"$f\",\"location\":\"temp_directory\"}")
            done <<< "$found"
        done
    fi
done
if [ ${#tool_entries[@]} -gt 0 ]; then
    credential_tools=$(printf '%s,' "${tool_entries[@]}" | sed 's/,$//')
    credential_tools="[${credential_tools}]"
fi

# --- Recently accessed sensitive files ---
sensitive_access="[]"
access_entries=()
for f in /etc/shadow /etc/gshadow /etc/security/opasswd; do
    if [ -f "$f" ]; then
        atime=$(stat -c%X "$f" 2>/dev/null || echo "0")
        atime_str=$(date -d @"$atime" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")
        mtime=$(stat -c%Y "$f" 2>/dev/null || echo "0")
        now=$(date +%s)
        access_age_days=$(( (now - atime) / 86400 ))
        note="normal"
        if [ "$access_age_days" -lt 1 ] 2>/dev/null; then
            note="accessed today"
        fi
        access_entries+=("{\"file\":\"$f\",\"last_accessed\":\"$atime_str\",\"access_age_days\":$access_age_days,\"note\":\"$note\"}")
    fi
done
if [ ${#access_entries[@]} -gt 0 ]; then
    sensitive_access=$(printf '%s,' "${access_entries[@]}" | sed 's/,$//')
    sensitive_access="[${sensitive_access}]"
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
  "check": "credential_dump",
  "shadow_info": ${shadow_info},
  "credential_tools": ${credential_tools},
  "sensitive_file_access": ${sensitive_access},
  "errors": ${err_json}
}
JSONEOF
