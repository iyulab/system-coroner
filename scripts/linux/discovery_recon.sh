#!/usr/bin/env bash
# scripts/linux/discovery_recon.sh
#
# Detection: Internal reconnaissance commands from bash history and process list
# MITRE: T1046 (Network Service Scanning), T1082 (System Info Discovery),
#        T1083 (File/Dir Discovery), T1087 (Account Discovery)
# Requires: Standard User (root recommended for /root history)
# Expected runtime: ~10s

set -euo pipefail

collect_recon() {
    local result
    result=$(cat <<'JSONEOF'
{"collected_at":"","hostname":"","check":"discovery_recon","recon_commands":[],"errors":[]}
JSONEOF
)

    local hostname
    hostname=$(hostname 2>/dev/null || echo "unknown")

    local collected_at
    collected_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")

    # Recon patterns to search in bash history
    local recon_patterns=(
        'id$'
        'whoami'
        'uname -a'
        'cat /etc/passwd'
        'cat /etc/shadow'
        'ss -tulnp'
        'netstat'
        'nmap '
        'masscan '
        'arp -n'
        'arp -a'
        'find / -perm -4000'
        'find / -name \*.conf'
        'find / -name \*.key'
        'find / -name \*.pem'
        'ps aux'
        'ps -ef'
        'lastlog'
        'last '
        'w$'
        'who$'
        'ifconfig'
        'ip addr'
        'ip route'
        'route '
        'env$'
        'printenv'
        'cat /proc/version'
        '/etc/os-release'
        'dpkg -l'
        'rpm -qa'
        'BloodHound'
        'bloodhound'
        'linpeas'
        'LinEnum'
        'linux-exploit'
        'lse.sh'
    )

    local recon_cmds='[]'
    local errors='[]'

    # Search bash history files
    local history_files=()
    # Root history
    if [ -f /root/.bash_history ]; then
        history_files+=("/root/.bash_history")
    fi
    # User histories
    while IFS= read -r hfile; do
        history_files+=("$hfile")
    done < <(find /home -maxdepth 2 -name '.bash_history' -readable 2>/dev/null | head -10)

    if [ ${#history_files[@]} -gt 0 ]; then
        local found_cmds='[]'
        for hfile in "${history_files[@]}"; do
            local user
            user=$(echo "$hfile" | sed 's|/home/\([^/]*\)/.*|\1|; s|/root.*|root|')

            # Search each pattern
            for pattern in "${recon_patterns[@]}"; do
                while IFS= read -r cmd; do
                    # Skip empty lines and comments
                    [ -z "$cmd" ] || [[ "$cmd" == \#* ]] && continue
                    # Truncate long commands
                    local short_cmd="${cmd:0:200}"
                    found_cmds=$(printf '%s' "$found_cmds" | \
                        python3 -c "
import sys, json
data = json.load(sys.stdin)
data.append({'command': '''${short_cmd}''', 'user': '${user}', 'source': '${hfile}'})
print(json.dumps(data))
" 2>/dev/null || echo "$found_cmds")
                    break
                done < <(grep -iE "${pattern}" "$hfile" 2>/dev/null | head -3)
            done
        done
        recon_cmds="$found_cmds"
    fi

    # Output result
    python3 -c "
import json, sys
result = {
    'collected_at': '${collected_at}',
    'hostname': '${hostname}',
    'check': 'discovery_recon',
    'recon_commands': ${recon_cmds},
    'errors': ${errors}
}
print(json.dumps(result))
" 2>/dev/null || printf '{"error":"python3 unavailable","check":"discovery_recon"}'
}

collect_recon
