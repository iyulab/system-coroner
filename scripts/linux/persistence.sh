#!/bin/bash
# scripts/linux/persistence.sh
#
# Detection: Reboot survival mechanisms (cron, systemd, init, rc.local)
# MITRE: T1053.003, T1543.002, T1037
# Requires: Standard user (root recommended for all crontabs)
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

# --- Cron jobs (user + system) ---
cron_jobs="[]"
cron_entries=()

# Current user crontab
user_cron=$(crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$' || true)
while IFS= read -r line; do
    [ -z "$line" ] && continue
    cron_entries+=("{\"source\":\"user_crontab\",\"user\":\"$(whoami)\",\"entry\":$(json_str "$line")}")
done <<< "$user_cron"

# System cron directories
for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$crondir" ]; then
        for f in "$crondir"/*; do
            [ -f "$f" ] || continue
            cron_entries+=("{\"source\":\"$crondir\",\"file\":\"$f\",\"entry\":\"$(basename "$f")\"}")
        done
    fi
done

# /etc/crontab
if [ -f /etc/crontab ]; then
    sys_cron=$(grep -v '^#' /etc/crontab | grep -v '^$' | grep -v '^[A-Z]' || true)
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        cron_entries+=("{\"source\":\"/etc/crontab\",\"entry\":$(json_str "$line")}")
    done <<< "$sys_cron"
fi

if [ ${#cron_entries[@]} -gt 0 ]; then
    cron_jobs=$(printf '%s,' "${cron_entries[@]}" | sed 's/,$//')
    cron_jobs="[${cron_jobs}]"
fi

# --- Systemd services (non-vendor) ---
systemd_suspicious="[]"
if command -v systemctl &>/dev/null; then
    # Find enabled services not in standard paths
    raw=$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep enabled | awk '{print $1}' || true)
    svc_entries=()
    while IFS= read -r svc; do
        [ -z "$svc" ] && continue
        path=$(systemctl show "$svc" -p FragmentPath --value 2>/dev/null || true)
        # Flag if not in standard vendor paths
        if [ -n "$path" ] && ! echo "$path" | grep -qE '^/usr/lib/systemd|^/lib/systemd'; then
            desc=$(systemctl show "$svc" -p Description --value 2>/dev/null || true)
            svc_entries+=("{\"service\":\"$svc\",\"path\":\"$path\",\"description\":$(json_str "$desc")}")
        fi
    done <<< "$raw"
    if [ ${#svc_entries[@]} -gt 0 ]; then
        systemd_suspicious=$(printf '%s,' "${svc_entries[@]}" | sed 's/,$//')
        systemd_suspicious="[${systemd_suspicious}]"
    fi
fi

# --- rc.local ---
rc_local="null"
if [ -f /etc/rc.local ] && [ -s /etc/rc.local ]; then
    rc_content=$(grep -v '^#' /etc/rc.local | grep -v '^$' | head -20 || true)
    if [ -n "$rc_content" ]; then
        rc_local=$(json_str "$rc_content")
    fi
fi

# --- LD_PRELOAD hijacking (LFC-002 / T1574.006) ---
# /etc/ld.so.preload is rarely used legitimately; any entry is highly suspicious
ld_preload="[]"
if [ -f /etc/ld.so.preload ] && [ -s /etc/ld.so.preload ]; then
    preload_entries=()
    while IFS= read -r lib; do
        [ -z "$lib" ] && continue
        [[ "$lib" == \#* ]] && continue
        lib_exists="false"
        [ -f "$lib" ] && lib_exists="true"
        preload_entries+=("{\"library\":$(json_str "$lib"),\"exists\":${lib_exists}}")
    done < /etc/ld.so.preload
    if [ ${#preload_entries[@]} -gt 0 ]; then
        entries_json=$(printf '%s,' "${preload_entries[@]}" | sed 's/,$//')
        ld_preload="[${entries_json}]"
    fi
fi

# --- Shell profile persistence (LFC-002 / T1546.004) ---
# Detect attacker-inserted commands in shell init files
shell_profiles="[]"
susp_pattern='(curl[[:space:]]|wget[[:space:]]|eval[[:space:]]|base64[[:space:]]|python[[:space:]]|perl[[:space:]]|nc[[:space:]]|ncat[[:space:]]|bash[[:space:]]-c|/tmp/|/dev/shm)'
profile_entries=()

# /etc/profile.d/ — non-standard scripts with suspicious content
if [ -d /etc/profile.d ]; then
    for f in /etc/profile.d/*.sh; do
        [ -f "$f" ] || continue
        if grep -qE "$susp_pattern" "$f" 2>/dev/null; then
            snippet=$(grep -E "$susp_pattern" "$f" 2>/dev/null | head -3 | cut -c1-200 || true)
            profile_entries+=("{\"file\":$(json_str "$f"),\"suspicious\":true,\"snippet\":$(json_str "$snippet")}")
        fi
    done
fi

# Root/service account shell configs
for rcfile in /root/.bashrc /root/.bash_profile /root/.profile /home/*/.bashrc; do
    [ -f "$rcfile" ] || continue
    if grep -qE "$susp_pattern" "$rcfile" 2>/dev/null; then
        snippet=$(grep -E "$susp_pattern" "$rcfile" 2>/dev/null | head -3 | cut -c1-200 || true)
        profile_entries+=("{\"file\":$(json_str "$rcfile"),\"suspicious\":true,\"snippet\":$(json_str "$snippet")}")
    fi
done

if [ ${#profile_entries[@]} -gt 0 ]; then
    prof_json=$(printf '%s,' "${profile_entries[@]}" | sed 's/,$//')
    shell_profiles="[${prof_json}]"
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
  "check": "persistence",
  "cron_jobs": ${cron_jobs},
  "systemd_suspicious": ${systemd_suspicious},
  "rc_local": ${rc_local},
  "ld_preload": ${ld_preload},
  "shell_profiles": ${shell_profiles},
  "errors": ${err_json}
}
JSONEOF
