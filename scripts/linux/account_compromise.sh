#!/bin/bash
# scripts/linux/account_compromise.sh
#
# Detection: Unauthorized accounts, privilege escalation, brute-force
# MITRE: T1136.001, T1098, T1110
# Requires: Root recommended for /etc/shadow access
# Expected runtime: ~5s

set -o pipefail

collected_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
hostname=$(hostname 2>/dev/null || echo "unknown")
errors=()

# --- Users with UID 0 (root equivalents) ---
uid0_users="[]"
uid0=$(awk -F: '$3 == 0 {printf "{\"user\":\"%s\",\"shell\":\"%s\"},", $1, $7}' /etc/passwd 2>/dev/null | sed 's/,$//')
if [ -n "$uid0" ]; then
    uid0_users="[${uid0}]"
fi

# --- Users with login shells (potential interactive accounts) ---
login_users="[]"
logins=$(awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ && $7 != "" {printf "{\"user\":\"%s\",\"uid\":%s,\"home\":\"%s\",\"shell\":\"%s\"},", $1, $3, $6, $7}' /etc/passwd 2>/dev/null | sed 's/,$//')
if [ -n "$logins" ]; then
    login_users="[${logins}]"
fi

# --- sudo/wheel group members ---
admin_members="[]"
admin_groups="sudo wheel"
admin_entries=()
for grp in $admin_groups; do
    members=$(getent group "$grp" 2>/dev/null | cut -d: -f4 || true)
    if [ -n "$members" ]; then
        admin_entries+=("{\"group\":\"$grp\",\"members\":\"$members\"}")
    fi
done
if [ ${#admin_entries[@]} -gt 0 ]; then
    admin_members=$(printf '%s,' "${admin_entries[@]}" | sed 's/,$//')
    admin_members="[${admin_members}]"
fi

# --- Recently modified passwd/shadow ---
passwd_mods="[]"
mod_entries=()
for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers; do
    if [ -f "$f" ]; then
        mtime=$(stat -c%Y "$f" 2>/dev/null || echo "0")
        mtime_str=$(date -d @"$mtime" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")
        now=$(date +%s)
        age_days=$(( (now - mtime) / 86400 ))
        note="normal"
        if [ "$age_days" -lt 7 ] 2>/dev/null; then
            note="recently modified (${age_days}d ago)"
        fi
        mod_entries+=("{\"file\":\"$f\",\"modified\":\"$mtime_str\",\"age_days\":$age_days,\"note\":\"$note\"}")
    fi
done
if [ ${#mod_entries[@]} -gt 0 ]; then
    passwd_mods=$(printf '%s,' "${mod_entries[@]}" | sed 's/,$//')
    passwd_mods="[${passwd_mods}]"
fi

# --- Failed login attempts (from auth.log or secure) ---
failed_logins="[]"
authlog=""
for f in /var/log/auth.log /var/log/secure; do
    [ -f "$f" ] && authlog="$f" && break
done
if [ -n "$authlog" ]; then
    # Count failed attempts per source IP (last 1000 lines)
    raw=$(tail -1000 "$authlog" 2>/dev/null | grep -i "failed\|failure\|invalid user" | grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -rn | head -10 || true)
    fl_entries=()
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        count=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')
        fl_entries+=("{\"source_ip\":\"$ip\",\"count\":$count}")
    done <<< "$raw"
    if [ ${#fl_entries[@]} -gt 0 ]; then
        failed_logins=$(printf '%s,' "${fl_entries[@]}" | sed 's/,$//')
        failed_logins="[${failed_logins}]"
    fi
fi

# --- SSH authorized_keys anomalies (with recent-modification detection) ---
ssh_keys="[]"
key_entries=()
now=$(date +%s)
for home in /root /home/*; do
    akf="$home/.ssh/authorized_keys"
    if [ -f "$akf" ]; then
        count=$(wc -l < "$akf" 2>/dev/null || echo "0")
        user=$(basename "$home")
        [ "$home" = "/root" ] && user="root"
        mtime=$(stat -c%Y "$akf" 2>/dev/null || echo "0")
        mtime_str=$(date -d @"$mtime" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")
        age_hours=$(( (now - mtime) / 3600 ))
        recent="false"
        [ "$age_hours" -lt 48 ] 2>/dev/null && recent="true"
        key_entries+=("{\"user\":\"$user\",\"file\":\"$akf\",\"key_count\":$count,\"mtime\":\"$mtime_str\",\"age_hours\":$age_hours,\"recently_modified\":$recent}")
    fi
done
if [ ${#key_entries[@]} -gt 0 ]; then
    ssh_keys=$(printf '%s,' "${key_entries[@]}" | sed 's/,$//')
    ssh_keys="[${ssh_keys}]"
fi

# --- sudoers.d non-standard files (T1098 privilege escalation) ---
sudoers_d="[]"
if [ -d /etc/sudoers.d ]; then
    sd_entries=()
    for f in /etc/sudoers.d/*; do
        [ -f "$f" ] || continue
        fname=$(basename "$f")
        [[ "$fname" == *~ || "$fname" == *.bak ]] && continue
        has_nopasswd="false"
        grep -qE 'NOPASSWD|ALL=\(ALL\)' "$f" 2>/dev/null && has_nopasswd="true"
        snippet=$(head -3 "$f" 2>/dev/null | cut -c1-150 || true)
        # Escape snippet for JSON
        snippet="${snippet//\\/\\\\}"; snippet="${snippet//\"/\\\"}"; snippet="${snippet//$'\n'/\\n}"
        sd_entries+=("{\"file\":\"$fname\",\"has_nopasswd\":$has_nopasswd,\"snippet\":\"$snippet\"}")
    done
    if [ ${#sd_entries[@]} -gt 0 ]; then
        sd_json=$(printf '%s,' "${sd_entries[@]}" | sed 's/,$//')
        sudoers_d="[${sd_json}]"
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
  "check": "account_compromise",
  "uid0_users": ${uid0_users},
  "login_users": ${login_users},
  "admin_members": ${admin_members},
  "passwd_modifications": ${passwd_mods},
  "failed_logins": ${failed_logins},
  "ssh_authorized_keys": ${ssh_keys},
  "sudoers_d": ${sudoers_d},
  "errors": ${err_json}
}
JSONEOF
