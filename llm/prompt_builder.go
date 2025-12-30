// Author: Kaleb Austgen
// Date Created: 12/29/25
// Purpose: Build LLM prompts from vulnerability data

package llm

import (
	"fmt"
	"strings"

	"github.com/kaustgen/Integrating_AI_OSINT/db"
)

// BuildRiskAssessmentPrompt creates a prompt for the LLM to analyze top 5 vulnerable assets
// and provide a complete remediation list for all vulnerabilities
//
// The prompt includes:
//   - Asset details (hostname, IP, type)
//   - CVE information (ID, CVSS, description)
//   - KEV status (if actively exploited)
//   - Shodan exposure data (if indexed)
//   - GreyNoise threat intelligence (if under attack)
//
// Returns a formatted prompt string ready for OpenAI API
func BuildRiskAssessmentPrompt(vulns []db.VulnerableAsset) string {
	// Get top 5 vulnerabilities for detailed analysis
	topVulns := vulns
	if len(topVulns) > 5 {
		topVulns = topVulns[0:5]
	}

	var prompt strings.Builder

	// Header and instructions
	prompt.WriteString("TASK: Write a technical vulnerability remediation report for security analysts.\n\n")
	prompt.WriteString("CONTEXT: You are a senior security engineer preparing a technical action plan.\n")
	prompt.WriteString("The vulnerabilities below are PRE-SORTED by risk score (Entry 1 = HIGHEST PRIORITY).\n\n")
	prompt.WriteString("IMPORTANT:\n")
	prompt.WriteString("- Each entry represents ONE VULNERABILITY on ONE ASSET\n")
	prompt.WriteString("- If the same hostname appears multiple times, those are separate CVEs\n")
	prompt.WriteString("- CRITICAL vulnerabilities (CVSS 9.0+) require immediate attention\n")
	prompt.WriteString("- KEV-listed vulnerabilities are actively exploited in the wild\n\n")
	prompt.WriteString("TOP 5 VULNERABILITIES (Pre-sorted by risk - DO NOT re-rank):\n")
	prompt.WriteString(strings.Repeat("=", 80) + "\n\n")

	// Build detailed context for each vulnerability
	for i, vuln := range topVulns {
		prompt.WriteString(fmt.Sprintf("ENTRY %d (PRIORITY %d):\n", i+1, i+1))
		prompt.WriteString(fmt.Sprintf("Asset: %s (%s) - %s\n", vuln.Hostname, vuln.IPAddress, vuln.AssetType))
		prompt.WriteString(fmt.Sprintf("Vulnerability: %s\n", vuln.CVEID))
		prompt.WriteString(strings.Repeat("-", 80) + "\n")

		// Basic vulnerability information
		prompt.WriteString(fmt.Sprintf("Severity: %s (CVSS %.1f/10.0)\n", vuln.CVSSSeverity, vuln.CVSSScore))
		prompt.WriteString(fmt.Sprintf("Description: %s\n", vuln.Description))

		// Asset context
		if vuln.InternetFacing {
			prompt.WriteString("Internet-facing asset (publicly accessible)\n")
		}
		prompt.WriteString(fmt.Sprintf("Asset Type: %s\n", vuln.AssetType))

		// KEV status (actively exploited)
		if vuln.InKEV {
			prompt.WriteString("\nACTIVELY EXPLOITED (CISA KEV Catalog):\n")
			prompt.WriteString(fmt.Sprintf("  - Date Added: %s\n", vuln.KEVDateAdded))
			prompt.WriteString(fmt.Sprintf("  - Remediation Due: %s\n", vuln.KEVDueDate))
			prompt.WriteString(fmt.Sprintf("  - Required Action: %s\n", vuln.KEVAction))

			if vuln.IsRansomware {
				prompt.WriteString("  - Known ransomware campaign usage\n")
			}
		}

		// Shodan exposure data (verified external visibility)
		if vuln.ShodanIndexed {
			prompt.WriteString("\nSHODAN EXPOSURE:\n")
			prompt.WriteString("  - Asset is indexed in Shodan (publicly discoverable by attackers)\n")
			if len(vuln.ShodanPorts) > 0 {
				prompt.WriteString(fmt.Sprintf("  - Open Ports: %v\n", vuln.ShodanPorts))
			}
		}

		// GreyNoise threat intelligence (active attacks)
		if vuln.GreyNoiseActive {
			prompt.WriteString("\nACTIVE EXPLOITATION ATTEMPTS (GreyNoise):\n")
			prompt.WriteString(fmt.Sprintf("  - %d malicious IPs currently scanning for this vulnerability\n", vuln.GreyNoiseScanCount))

			if vuln.GreyNoiseScanCount > 1000 {
				prompt.WriteString("  - MASS CAMPAIGN (>1000 scanning IPs)\n")
			}

			if vuln.GreyNoiseRecentActivity {
				prompt.WriteString("  - Scanned within last 24 hours (imminent threat)\n")
			}

			if vuln.GreyNoiseRansomware {
				prompt.WriteString("  - Ransomware actors actively scanning\n")
			}

			// Attack tags
			if len(vuln.GreyNoiseTags) > 0 {
				prompt.WriteString(fmt.Sprintf("  - Attack Tags: %s\n", strings.Join(vuln.GreyNoiseTags, ", ")))
			}

			// Top attacking countries
			if len(vuln.GreyNoiseCountries) > 0 {
				prompt.WriteString("  - Attack Origins: ")
				count := 0
				for country, ips := range vuln.GreyNoiseCountries {
					if count > 0 {
						prompt.WriteString(", ")
					}
					prompt.WriteString(fmt.Sprintf("%s (%d IPs)", country, ips))
					count++
					if count >= 3 { // Show top 3 countries
						break
					}
				}
				prompt.WriteString("\n")
			}
		}

		prompt.WriteString("\n")
	}

	// Final instructions
	prompt.WriteString(strings.Repeat("=", 80) + "\n\n")
	prompt.WriteString("OUTPUT FORMAT - Technical Remediation Report:\n\n")

	prompt.WriteString("Write a technical analysis in the following EXACT format:\n\n")
	prompt.WriteString("## CRITICAL VULNERABILITIES (CVSS 9.0+ / KEV-Listed)\n")
	prompt.WriteString("[List all CRITICAL entries from above in this section]\n\n")
	prompt.WriteString("For each CRITICAL vulnerability, provide:\n")
	prompt.WriteString("### [PRIORITY #] [Hostname] - [CVE-ID] (CVSS [Score])\n")
	prompt.WriteString("- **Vulnerability:** [Brief description of the flaw]\n")
	prompt.WriteString("- **Impact:** [What an attacker can achieve - RCE, data breach, etc.]\n")
	prompt.WriteString("- **Exploitation Status:** [KEV status, GreyNoise data, Shodan exposure]\n")
	prompt.WriteString("- **Remediation:** [Specific patch version OR mitigation steps]\n")
	prompt.WriteString("- **Deadline:** [KEV due date OR 'Patch within 24-48 hours for CRITICAL']\n\n")

	prompt.WriteString("## HIGH-PRIORITY VULNERABILITIES\n")
	prompt.WriteString("[List remaining entries here]\n\n")
	prompt.WriteString("For each HIGH vulnerability, provide:\n")
	prompt.WriteString("### [PRIORITY #] [Hostname] - [CVE-ID] (CVSS [Score])\n")
	prompt.WriteString("- **Vulnerability:** [Brief description]\n")
	prompt.WriteString("- **Remediation:** [Specific action required]\n\n")

	prompt.WriteString("## COMPLETE REMEDIATION CHECKLIST\n")
	prompt.WriteString("[THIS SECTION MUST LIST ALL ASSETS FROM THE FULL DATA BELOW - NOT JUST TOP 5]\n\n")
	prompt.WriteString("Format as a simple checklist:\n")
	prompt.WriteString("- [ ] [Hostname] - [CVE-ID] - [Remediation action]\n\n")
	prompt.WriteString("Example:\n")
	prompt.WriteString("- [ ] web-prod-01 - CVE-2021-41773 - Upgrade Apache to 2.4.51+\n")
	prompt.WriteString("- [ ] db-primary - CVE-2021-35624 - Apply Oracle critical patch update\n\n")

	// Add ALL vulnerabilities as reference data for the complete list
	prompt.WriteString(strings.Repeat("=", 80) + "\n")
	prompt.WriteString("FULL VULNERABILITY DATA (for complete checklist generation):\n")
	prompt.WriteString(strings.Repeat("=", 80) + "\n\n")
	
	for i, vuln := range vulns {
		prompt.WriteString(fmt.Sprintf("%d. %s (%s) - %s (CVSS %.1f)", 
			i+1, vuln.Hostname, vuln.IPAddress, vuln.CVEID, vuln.CVSSScore))
		if vuln.InKEV {
			prompt.WriteString(fmt.Sprintf(" [KEV: %s]", vuln.KEVAction))
		}
		prompt.WriteString("\n")
	}
	prompt.WriteString("\n")

	prompt.WriteString(strings.Repeat("=", 80) + "\n\n")
	prompt.WriteString("MANDATORY RULES:\n")
	prompt.WriteString("- Use the EXACT format above with ## and ### headings\n")
	prompt.WriteString("- Always use actual hostnames (e.g., 'web-prod-01') NOT generic 'Asset 1'\n")
	prompt.WriteString("- Include CVE-IDs in every heading (e.g., 'CVE-2021-41773')\n")
	prompt.WriteString("- CRITICAL section = CVSS 9.0+ OR KEV-listed entries (from top 5 only)\n")
	prompt.WriteString("- If KEV: Quote the 'Required Action' field exactly\n")
	prompt.WriteString("- If GreyNoise active: Mention '[X] IPs currently scanning'\n")
	prompt.WriteString("- Prioritize entries 1-3 with more detail than entries 4-5\n")
	prompt.WriteString("- DO NOT re-rank - use the priority order provided above\n")
	prompt.WriteString("- Be technical and specific - this is for security analysts, not executives\n")
	prompt.WriteString("- The COMPLETE REMEDIATION CHECKLIST at the end MUST include ALL vulnerabilities from the full data\n")
	prompt.WriteString("- The checklist is the FINAL section of the report\n\n")

	return prompt.String()
}
