package platform

import "time"

// LinuxChecks returns the Linux intrusion detection checks.
func LinuxChecks() []Check {
	return []Check{
		{
			ID:            "c2_connections",
			Name:          "C2 Communication & Reverse Shell",
			Description:   "Detect outbound C2 connections, reverse shells, and suspicious listening ports",
			Script:        "linux/c2_connections.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: false,
		},
		{
			ID:            "persistence",
			Name:          "Persistence Mechanisms",
			Description:   "Detect persistence via cron jobs, non-standard systemd services, and rc.local",
			Script:        "linux/persistence.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: false,
		},
		{
			ID:            "log_tampering",
			Name:          "Log Tampering",
			Description:   "Detect log file anomalies, disabled audit daemon, and journal integrity issues",
			Script:        "linux/log_tampering.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "account_compromise",
			Name:          "Account Compromise",
			Description:   "Detect UID 0 accounts, unauthorized SSH keys, brute-force, and recent account file changes",
			Script:        "linux/account_compromise.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "credential_dump",
			Name:          "Credential Dumping",
			Description:   "Detect /etc/shadow access, credential tools, and sensitive file access",
			Script:        "linux/credential_dump.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "fileless_attack",
			Name:          "Fileless Attack",
			Description:   "Detect deleted-executable processes, /dev/shm abuse, and memfd_create usage",
			Script:        "linux/fileless_attack.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "lolbin_abuse",
			Name:          "GTFOBins Abuse",
			Description:   "Detect malicious use of legitimate tools: curl, wget, python, nc, etc.",
			Script:        "linux/lolbin_abuse.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: false,
		},
		{
			ID:            "lateral_movement",
			Name:          "Lateral Movement",
			Description:   "Detect SSH sessions, remote logins, SSH tunneling, and remote execution tools",
			Script:        "linux/lateral_movement.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "webshell",
			Name:          "Webshell Detection",
			Description:   "Detect suspicious scripts in web server directories using webshell pattern matching",
			Script:        "linux/webshell.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: false,
		},
	}
}
