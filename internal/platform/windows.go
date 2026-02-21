package platform

import "time"

// WindowsChecks returns the Windows intrusion detection checks.
func WindowsChecks() []Check {
	return []Check{
		{
			ID:            "c2_connections",
			Name:          "C2 Communication & Reverse Shell",
			Description:   "Detect outbound C2 connections, reverse shells, and beacon traffic",
			Script:        "windows/c2_connections.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: false,
		},
		{
			ID:            "account_compromise",
			Name:          "Account Compromise",
			Description:   "Detect attacker account creation, privilege escalation, and brute-force attacks",
			Script:        "windows/account_compromise.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "persistence",
			Name:          "Persistence Mechanisms",
			Description:   "Detect persistence via registry Run keys, scheduled tasks, and non-standard services",
			Script:        "windows/persistence.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: false,
		},
		{
			ID:            "lolbin_abuse",
			Name:          "Living-off-the-Land Abuse",
			Description:   "Detect abuse of built-in Windows tools: certutil, mshta, regsvr32, etc.",
			Script:        "windows/lolbin_abuse.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "fileless_attack",
			Name:          "Fileless Attack",
			Description:   "Detect WMI event subscriptions, PowerShell script block logging, and memory-based attacks",
			Script:        "windows/fileless_attack.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: false,
		},
		{
			ID:            "log_tampering",
			Name:          "Log Tampering",
			Description:   "Detect Security/System log deletion and audit policy disabling",
			Script:        "windows/log_tampering.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "credential_dump",
			Name:          "Credential Dumping",
			Description:   "Detect LSASS access, SAM hive copying, and Mimikatz traces",
			Script:        "windows/credential_dump.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "lateral_movement",
			Name:          "Lateral Movement",
			Description:   "Detect lateral movement via RDP, PsExec, WinRM, and Pass-the-Hash",
			Script:        "windows/lateral_movement.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "webshell",
			Name:          "Webshell Detection",
			Description:   "Detect new or modified script files in web roots and IIS log anomalies",
			Script:        "windows/webshell.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: false,
		},
		{
			ID:            "discovery_recon",
			Name:          "Internal Reconnaissance",
			Description:   "Detect attacker recon commands: net user, whoami /all, nltest, BloodHound, port scanning",
			Script:        "windows/discovery_recon.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
	}
}
