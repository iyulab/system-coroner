package reporter

// EvidenceGap describes the impact of a failed collection check on the overall assessment.
type EvidenceGap struct {
	CheckID        string `json:"check_id"`
	CheckName      string `json:"check_name"`
	MissingData    string `json:"missing_data"`    // what evidence is absent
	BlindSpots     string `json:"blind_spots"`     // what attack stages become invisible
	Impact         string `json:"impact"`          // how this affects the overall conclusion
	ImpactSeverity string `json:"impact_severity"` // high, medium, low
}

// checkGapDescriptions maps check IDs to their forensic impact descriptions.
var checkGapDescriptions = map[string]struct {
	missingData string
	blindSpots  string
	impact      string
	severity    string
}{
	"c2_connections": {
		missingData: "Active network connections, DNS cache, listening ports, service installations",
		blindSpots:  "Command & Control communication, reverse shells, beacon traffic, C2 persistence",
		impact:      "Cannot determine if the server is actively communicating with attacker infrastructure. A compromised server may appear clean.",
		severity:    "high",
	},
	"account_compromise": {
		missingData: "Failed/successful logon events (4624/4625), new account creation (4720), group membership changes",
		blindSpots:  "Brute-force attacks, unauthorized account creation, privilege escalation",
		impact:      "Cannot determine if attacker accounts exist or if brute-force was successful. Initial access vector assessment is unreliable.",
		severity:    "high",
	},
	"persistence": {
		missingData: "Registry Run keys, scheduled tasks, services, Winlogon/IFEO modifications",
		blindSpots:  "Attacker survival mechanisms, auto-start malware, backdoor services",
		impact:      "Cannot determine if the attacker has established persistence. Even if other threats are remediated, the attacker may return.",
		severity:    "high",
	},
	"lolbin_abuse": {
		missingData: "Process creation events for built-in tools (certutil, mshta, regsvr32, rundll32)",
		blindSpots:  "Living-off-the-Land attacks, tool downloads via legitimate binaries, script execution",
		impact:      "Attacker may be using built-in Windows tools to evade detection — this analysis gap means fileless techniques are not visible.",
		severity:    "medium",
	},
	"fileless_attack": {
		missingData: "WMI event subscriptions, PowerShell script block logs (Event 4104), memory-only processes",
		blindSpots:  "Fileless malware, WMI persistence, in-memory attacks",
		impact:      "Memory-resident threats and WMI-based persistence are invisible. These are among the hardest to detect and most commonly missed.",
		severity:    "high",
	},
	"log_tampering": {
		missingData: "Security log clear events (1102), audit policy changes (4719), EventLog service status",
		blindSpots:  "Anti-forensic activity, evidence destruction, audit evasion",
		impact:      "Cannot determine if logs were cleared. If the attacker cleared logs before this scan, ALL other checks may be operating on incomplete data.",
		severity:    "high",
	},
	"credential_dump": {
		missingData: "LSASS protection status, credential tool execution, registry hive saves, WDigest configuration",
		blindSpots:  "Credential theft, Mimikatz/procdump activity, SAM/SECURITY hive extraction",
		impact:      "Cannot determine if credentials were stolen. Even if the initial breach is contained, stolen credentials may enable re-entry.",
		severity:    "high",
	},
	"lateral_movement": {
		missingData: "Type 3/10 logon events, PsExec traces, WinRM activity, SMB shares",
		blindSpots:  "Attacker movement between servers, pivot points, network spread",
		impact:      "Cannot determine if the attacker moved to other servers. The scope of compromise may be larger than what this single-server analysis shows.",
		severity:    "high",
	},
	"webshell": {
		missingData: "Web root file inventory, script files with suspicious content, IIS logs",
		blindSpots:  "Web shells, uploaded backdoors, web server exploitation",
		impact:      "Cannot determine if a web shell is present. If this server runs web services, the attacker may have persistent web-based access.",
		severity:    "medium",
	},
	"discovery_recon": {
		missingData: "Process creation events for recon commands, RDP client history",
		blindSpots:  "Attacker reconnaissance activity, network enumeration, AD querying",
		impact:      "Cannot determine what information the attacker gathered about the environment. This affects understanding of the attacker's knowledge and next targets.",
		severity:    "medium",
	},
	"process_execution": {
		missingData: "Prefetch files, BAM entries, ShimCache data",
		blindSpots:  "Historical program execution (survives file deletion), attack tool usage timeline",
		impact:      "Cannot correlate execution artifacts with other findings. Deleted attack tools will not be detected.",
		severity:    "medium",
	},
	"file_access": {
		missingData: "Recent Items LNK files, file system access patterns",
		blindSpots:  "Files browsed by the attacker, credential/key file access",
		impact:      "Cannot determine what files the attacker accessed or exfiltrated.",
		severity:    "medium",
	},
	"file_download": {
		missingData: "Zone.Identifier ADS (Mark-of-the-Web), BITS transfer records",
		blindSpots:  "Tools downloaded from the internet, dropper artifacts",
		impact:      "Cannot identify externally downloaded attack tools or malware droppers.",
		severity:    "medium",
	},
	"staging_exfiltration": {
		missingData: "Temp archives, USB device history, VSS deletion events, exfiltration tool traces",
		blindSpots:  "Data staging, data exfiltration, evidence destruction",
		impact:      "Cannot determine if data was stolen. This is critical for breach notification and regulatory compliance.",
		severity:    "high",
	},
}

// CombinedGap describes the compound forensic impact when multiple checks fail simultaneously.
type CombinedGap struct {
	CheckIDs       []string `json:"check_ids"`
	Scenario       string   `json:"scenario"`        // attack scenario that becomes invisible
	KillChainGap   string   `json:"kill_chain_gap"`  // which kill chain phases are blind
	CombinedImpact string   `json:"combined_impact"` // why the combination is worse than individual gaps
}

// combinedGapDefs defines known dangerous combinations of check failures.
// Each entry lists the required failed check IDs and the compound impact description.
var combinedGapDefs = []struct {
	checks         []string
	scenario       string
	killChainGap   string
	combinedImpact string
}{
	{
		checks:       []string{"account_compromise", "fileless_attack"},
		scenario:     "Fileless initial access via compromised credentials",
		killChainGap: "Initial Access, Execution",
		combinedImpact: "The entire kill chain early stage is invisible — from initial access to memory-based execution. " +
			"If the attacker used fileless techniques to gain entry, there is no evidence trail to detect it.",
	},
	{
		checks:       []string{"account_compromise", "process_execution"},
		scenario:     "Credential-based access with deleted attack tools",
		killChainGap: "Initial Access, Execution",
		combinedImpact: "Both who entered and what they executed are unknown. " +
			"Even if attack tools were deleted, Prefetch/BAM could have proven execution — but that data is also missing.",
	},
	{
		checks:       []string{"fileless_attack", "credential_dump"},
		scenario:     "In-memory credential theft (Mimikatz-style)",
		killChainGap: "Execution, Credential Access",
		combinedImpact: "Memory-resident attacks and credential theft are both invisible. " +
			"An attacker could have injected Mimikatz into memory, dumped credentials, and left no trace on disk.",
	},
	{
		checks:       []string{"fileless_attack", "process_execution", "credential_dump"},
		scenario:     "Full fileless attack chain with credential harvesting",
		killChainGap: "Execution, Credential Access, Defense Evasion",
		combinedImpact: "Memory-based attacks, execution artifacts, and credential theft are all invisible. " +
			"This is the worst-case combination for fileless attack detection — " +
			"a Mimikatz memory injection attack would be completely undetectable.",
	},
	{
		checks:       []string{"c2_connections", "lateral_movement"},
		scenario:     "Active C2 with network pivot",
		killChainGap: "Command & Control, Lateral Movement",
		combinedImpact: "Cannot determine if the server is communicating with attacker infrastructure or " +
			"being used as a pivot point. The attacker may be actively controlling this server and moving to others.",
	},
	{
		checks:       []string{"log_tampering", "persistence"},
		scenario:     "Anti-forensic activity with hidden persistence",
		killChainGap: "Defense Evasion, Persistence",
		combinedImpact: "If logs were cleared AND persistence is undetectable, the attacker may have " +
			"established a persistent backdoor and then destroyed the evidence. " +
			"The server cannot be trusted even after remediation.",
	},
	{
		checks:       []string{"c2_connections", "staging_exfiltration"},
		scenario:     "Data exfiltration over C2 channel",
		killChainGap: "Command & Control, Exfiltration",
		combinedImpact: "Both the communication channel and data staging/exfiltration are invisible. " +
			"Cannot determine if sensitive data has been stolen — critical for breach notification decisions.",
	},
	{
		checks:       []string{"account_compromise", "lateral_movement", "persistence"},
		scenario:     "Full domain compromise scenario",
		killChainGap: "Initial Access, Lateral Movement, Persistence",
		combinedImpact: "The attacker's entry point, network spread, and survival mechanisms are all unknown. " +
			"This combination means the scope of compromise cannot be determined and remediation may be incomplete.",
	},
}

// DescribeCombinedGaps identifies dangerous combinations among failed checks and returns
// compound impact descriptions. Only combinations where ALL required checks failed are returned.
func DescribeCombinedGaps(failedChecks []string) []CombinedGap {
	if len(failedChecks) < 2 {
		return nil
	}

	failedSet := make(map[string]bool, len(failedChecks))
	for _, id := range failedChecks {
		failedSet[id] = true
	}

	var results []CombinedGap
	for _, def := range combinedGapDefs {
		if allPresent(def.checks, failedSet) {
			results = append(results, CombinedGap{
				CheckIDs:       def.checks,
				Scenario:       def.scenario,
				KillChainGap:   def.killChainGap,
				CombinedImpact: def.combinedImpact,
			})
		}
	}
	return results
}

// allPresent returns true if all items are in the set.
func allPresent(items []string, set map[string]bool) bool {
	for _, item := range items {
		if !set[item] {
			return false
		}
	}
	return true
}

// AnalyzeEvidenceGaps computes the forensic impact of each collection failure.
func AnalyzeEvidenceGaps(failures []CollectionFailure) []EvidenceGap {
	if len(failures) == 0 {
		return nil
	}

	gaps := make([]EvidenceGap, 0, len(failures))
	for _, f := range failures {
		desc, ok := checkGapDescriptions[f.CheckID]
		if !ok {
			// Unknown check — provide generic gap description
			gaps = append(gaps, EvidenceGap{
				CheckID:        f.CheckID,
				CheckName:      f.CheckName,
				MissingData:    "Data for check '" + f.CheckID + "'",
				BlindSpots:     "Detection capabilities of '" + f.CheckID + "'",
				Impact:         "Analysis coverage is reduced. Findings related to this check may be incomplete.",
				ImpactSeverity: "medium",
			})
			continue
		}

		name := f.CheckName
		if name == "" {
			name = f.CheckID
		}
		gaps = append(gaps, EvidenceGap{
			CheckID:        f.CheckID,
			CheckName:      name,
			MissingData:    desc.missingData,
			BlindSpots:     desc.blindSpots,
			Impact:         desc.impact,
			ImpactSeverity: desc.severity,
		})
	}
	return gaps
}
