#!/usr/bin/env bash
# scripts/linux/staging_exfiltration.sh
#
# Detection: Data staging and exfiltration artifacts on Linux
# MITRE: T1074 (Data Staged), T1560 (Archive Collected Data),
#        T1048 (Exfiltration Over Alt Protocol)
# Requires: Standard User (root recommended for complete history)
# Expected runtime: ~15s

set -euo pipefail

collect_staging() {
    local hostname
    hostname=$(hostname 2>/dev/null || echo "unknown")

    local collected_at
    collected_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")

    # --- Temp archives in staging directories ---
    local temp_archives='[]'
    local staging_dirs=("/tmp" "/dev/shm" "/var/tmp")
    local archive_exts="*.zip *.7z *.tar.gz *.tgz *.tar.bz2 *.rar *.gz"

    for dir in "${staging_dirs[@]}"; do
        [ -d "$dir" ] || continue
        while IFS= read -r f; do
            [ -f "$f" ] || continue
            local fname size created
            fname=$(basename "$f")
            size=$(stat -c%s "$f" 2>/dev/null || echo "0")
            created=$(stat -c%y "$f" 2>/dev/null | cut -d' ' -f1 || echo "")
            temp_archives=$(printf '%s' "$temp_archives" | python3 -c "
import sys, json
data = json.load(sys.stdin)
data.append({'file_name': '${fname}', 'file_path': '${f}', 'size_bytes': ${size}, 'created': '${created}'})
print(json.dumps(data))
" 2>/dev/null || echo "$temp_archives")
        done < <(find "$dir" -maxdepth 2 -type f \( \
            -name "*.zip" -o -name "*.7z" -o -name "*.tar.gz" -o -name "*.tgz" \
            -o -name "*.rar" -o -name "*.tar.bz2" -o -name "*.gz" \
            \) -newer /tmp -mtime -7 2>/dev/null | head -20)
    done

    # --- Exfiltration commands from bash history ---
    local exfil_cmds='[]'
    local exfil_patterns=(
        'rclone'
        'curl.*-T '
        'wget.*--post-file'
        'nc '
        'scp '
        'rsync.*@'
        'ftp '
        'sftp '
        'tar.*\| *nc'
        '| *nc '
    )

    local history_files=()
    [ -f /root/.bash_history ] && history_files+=("/root/.bash_history")
    while IFS= read -r hf; do history_files+=("$hf"); done < <(
        find /home -maxdepth 2 -name '.bash_history' -readable 2>/dev/null | head -10
    )

    for hfile in "${history_files[@]}"; do
        local user="${hfile//\/home\//}"
        user="${user%%/*}"
        [ "$hfile" = "/root/.bash_history" ] && user="root"

        for pattern in "${exfil_patterns[@]}"; do
            while IFS= read -r cmd; do
                [ -z "$cmd" ] && continue
                local short_cmd="${cmd:0:200}"
                exfil_cmds=$(printf '%s' "$exfil_cmds" | python3 -c "
import sys, json
data = json.load(sys.stdin)
data.append({'command': '''${short_cmd}''', 'user': '${user}'})
print(json.dumps(data))
" 2>/dev/null || echo "$exfil_cmds")
            done < <(grep -iE "${pattern}" "$hfile" 2>/dev/null | head -5)
        done
    done

    # --- USB mount events ---
    local usb_events='[]'
    if [ -f /var/log/syslog ]; then
        while IFS= read -r line; do
            local short="${line:0:200}"
            usb_events=$(printf '%s' "$usb_events" | python3 -c "
import sys, json
data = json.load(sys.stdin)
data.append({'log_line': '''${short}'''})
print(json.dumps(data))
" 2>/dev/null || echo "$usb_events")
        done < <(grep -iE 'usb|storage|mount' /var/log/syslog 2>/dev/null | \
            grep -v 'bluetooth\|mouse\|keyboard\|input' | tail -20)
    fi

    python3 -c "
import json
result = {
    'collected_at': '${collected_at}',
    'hostname': '${hostname}',
    'check': 'staging_exfiltration',
    'temp_archives': ${temp_archives},
    'exfil_commands': ${exfil_cmds},
    'usb_events': ${usb_events},
    'errors': []
}
print(json.dumps(result))
" 2>/dev/null || printf '{"error":"python3 unavailable","check":"staging_exfiltration"}'
}

collect_staging
