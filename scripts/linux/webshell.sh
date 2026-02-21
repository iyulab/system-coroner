#!/bin/bash
# scripts/linux/webshell.sh
#
# Detection: Web shells in web server directories
# MITRE: T1505.003
# Requires: Root recommended for full directory access
# Expected runtime: ~10s

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

# --- Web root directories to scan ---
web_roots="/var/www /srv/www /usr/share/nginx /usr/share/apache2 /opt/lampp/htdocs"
active_roots=()
for dir in $web_roots; do
    [ -d "$dir" ] && active_roots+=("$dir")
done

# --- Suspicious files (recently created/modified PHP, JSP, ASP, ASPX, CGI) ---
suspicious_files="[]"
file_entries=()
for dir in "${active_roots[@]}"; do
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        size=$(stat -c%s "$f" 2>/dev/null || echo "0")
        mtime=$(stat -c%Y "$f" 2>/dev/null || echo "0")
        mtime_str=$(date -d @"$mtime" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")
        owner=$(stat -c%U "$f" 2>/dev/null || echo "unknown")
        perms=$(stat -c%a "$f" 2>/dev/null || echo "unknown")
        file_entries+=("{\"path\":\"$f\",\"size\":$size,\"modified\":\"$mtime_str\",\"owner\":\"$owner\",\"permissions\":\"$perms\"}")
    done < <(find "$dir" -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.aspx" -o -name "*.asp" -o -name "*.cgi" \) -mtime -30 2>/dev/null | head -50)
done
if [ ${#file_entries[@]} -gt 0 ]; then
    suspicious_files=$(printf '%s,' "${file_entries[@]}" | sed 's/,$//')
    suspicious_files="[${suspicious_files}]"
fi

# --- Pattern matching for webshell signatures ---
suspicious_patterns="[]"
pattern_entries=()
webshell_patterns="eval\s*\(|base64_decode|system\s*\(|exec\s*\(|passthru|shell_exec|proc_open|popen|assert\s*\(|preg_replace.*e\s*["']|Runtime.getRuntime|ProcessBuilder"

for dir in "${active_roots[@]}"; do
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        file=$(echo "$match" | cut -d: -f1)
        line=$(echo "$match" | cut -d: -f2-)
        pattern_entries+=("{\"file\":\"$file\",\"match\":$(json_str "$(echo "$line" | head -c 200)")}")
    done < <(grep -rlnE "$webshell_patterns" "$dir" --include="*.php" --include="*.jsp" --include="*.aspx" --include="*.asp" 2>/dev/null | head -20)
done
if [ ${#pattern_entries[@]} -gt 0 ]; then
    suspicious_patterns=$(printf '%s,' "${pattern_entries[@]}" | sed 's/,$//')
    suspicious_patterns="[${suspicious_patterns}]"
fi

# --- Web server processes ---
web_processes="[]"
wp_entries=()
for proc in httpd apache2 nginx php-fpm; do
    if pgrep -x "$proc" &>/dev/null; then
        count=$(pgrep -cx "$proc" 2>/dev/null || echo "0")
        user=$(ps -o user= -p "$(pgrep -x "$proc" | head -1)" 2>/dev/null || echo "unknown")
        wp_entries+=("{\"process\":\"$proc\",\"count\":$count,\"user\":\"$user\"}")
    fi
done
if [ ${#wp_entries[@]} -gt 0 ]; then
    web_processes=$(printf '%s,' "${wp_entries[@]}" | sed 's/,$//')
    web_processes="[${web_processes}]"
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
  "check": "webshell",
  "web_roots_scanned": $(printf '"%s",' "${active_roots[@]}" 2>/dev/null | sed 's/,$//' | sed 's/^/[/;s/$/]/' || echo "[]"),
  "suspicious_files": ${suspicious_files},
  "suspicious_patterns": ${suspicious_patterns},
  "web_processes": ${web_processes},
  "errors": ${err_json}
}
JSONEOF
