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
	// Get top 5 vulnerabilities (already sorted by priority in db.FindVulnerableAssets)
	topVulns := vulns
	if len(topVulns) > 5 {
		topVulns = topVulns[:5]
	}

	var prompt strings.Builder

	// Header and instructions
	prompt.WriteString("🎯 TASK: Write a 2-paragraph executive security briefing for the board of directors.\n\n")
	prompt.WriteString("📊 DATA: The 5 vulnerability entries below are PRE-SORTED by risk (Entry 1 = MOST CRITICAL).\n\n")
	prompt.WriteString("⚠️  CRITICAL: Each entry is ONE SPECIFIC VULNERABILITY on ONE ASSET.\n")
	prompt.WriteString("   - If you see the same hostname twice, those are 2 separate vulnerabilities on the same server.\n")
	prompt.WriteString("   - Entry 1 is the #1 highest-risk finding in our entire infrastructure.\n")
	prompt.WriteString("   - Prioritize Entry 1 above all others (spend 50% of Paragraph 1 on Entry 1 alone).\n\n")
	prompt.WriteString("TOP 5 VULNERABILITIES (Already sorted - DO NOT re-rank):\n")
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
			prompt.WriteString("\n🔍 SHODAN EXPOSURE:\n")
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
	prompt.WriteString("📝 OUTPUT REQUIREMENTS - READ CAREFULLY:\n\n")

	prompt.WriteString("PARAGRAPH 1 - Current Threat Landscape (5-7 sentences):\n")
	prompt.WriteString("1. FIRST sentence: 'Our most critical vulnerability is [Hostname] running [AssetType] with [CVE-ID], scoring [CVSS]/10 (CRITICAL).'\n")
	prompt.WriteString("   - Use exact data from Entry 1 above\n")
	prompt.WriteString("2. SECOND sentence: Explain WHY Entry 1 is critical:\n")
	prompt.WriteString("   - If KEV: 'CISA confirms this is actively exploited in the wild'\n")
	prompt.WriteString("   - If GreyNoise: '[X] malicious IPs are currently scanning for this vulnerability'\n")
	prompt.WriteString("   - Mention if ransomware-related\n")
	prompt.WriteString("3. THIRD sentence: WHO is attacking (GreyNoise country data if available)\n")
	prompt.WriteString("4. FOURTH sentence: Business impact of Entry 1 (e.g., 'Remote code execution could allow attackers to...')\n")
	prompt.WriteString("5. Remaining sentences: Briefly mention Entries 2-3 as secondary concerns\n\n")

	prompt.WriteString("PARAGRAPH 2 - Immediate Action Plan (5-7 sentences):\n")
	prompt.WriteString("1. FIRST sentence: 'Immediate remediation required in priority order:'\n")
	prompt.WriteString("2. Entry 1 action (2 sentences):\n")
	prompt.WriteString("   - If KEV: Quote the 'Required Action' field verbatim\n")
	prompt.WriteString("   - If not KEV: 'Patch [Hostname] to version X or apply vendor workaround'\n")
	prompt.WriteString("   - State deadline: 'CISA mandates remediation by [KEVDueDate]' OR 'Critical patch required within 24-48 hours'\n")
	prompt.WriteString("3. Entries 2-3 actions (1 sentence each): Brief patch/mitigation steps\n")
	prompt.WriteString("4. LAST sentence: 'All KEV-listed vulnerabilities must be remediated by their due dates to maintain federal compliance.'\n\n")

	prompt.WriteString("🚨 MANDATORY RULES - VIOLATING THESE WILL FAIL THE TASK:\n")
	prompt.WriteString("✓ Entry 1 MUST be mentioned in FIRST sentence of Paragraph 1\n")
	prompt.WriteString("✓ Entry 1 MUST receive 50% of Paragraph 1 content (3-4 sentences)\n")
	prompt.WriteString("✓ Use actual HOSTNAME (e.g., 'web-prod-01') NOT generic terms like 'Asset 1'\n")
	prompt.WriteString("✓ Include actual CVE-ID (e.g., 'CVE-2021-41773') in first sentence\n")
	prompt.WriteString("✓ If Entry 1 has CVSS 9.0+, explicitly say 'CRITICAL severity'\n")
	prompt.WriteString("✓ If Entry 1 is in KEV, quote the 'Required Action' EXACTLY as written above\n")
	prompt.WriteString("✓ DO NOT re-rank or 'choose' entries - use the order given (Entry 1 is already highest priority)\n")
	prompt.WriteString("✓ Each entry is ONE vulnerability on ONE asset - do NOT group by hostname\n\n")

	return prompt.String()
}
