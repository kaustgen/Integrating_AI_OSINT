// Author: Kaleb Austgen
// Date Created: 12/29/25
// Purpose: Report data structures

package report

import (
	"time"

	"github.com/kaustgen/Integrating_AI_OSINT/db"
)

// ReportData contains all information needed to generate a report
type ReportData struct {
	Timestamp       time.Time
	ScanDuration    time.Duration
	AIAnalysis      string
	Vulnerabilities []db.VulnerableAsset
	Summary         ReportSummary
}

// ReportSummary contains aggregate statistics
type ReportSummary struct {
	TotalAssets          int
	TotalVulnerabilities int
	Critical             int
	High                 int
	Medium               int
	Low                  int
	KEVCount             int
	KEVOverdue           int
	ShodanIndexed        int
	GreyNoiseActive      int
	InternetFacing       int
}

// CalculateSummary generates summary statistics from vulnerabilities
func CalculateSummary(vulns []db.VulnerableAsset, inventory []db.Asset) ReportSummary {
	summary := ReportSummary{
		TotalAssets:          len(inventory),
		TotalVulnerabilities: len(vulns),
	}

	// Track unique assets to avoid double-counting
	uniqueAssets := make(map[string]bool)

	for _, v := range vulns {
		// Count by severity
		switch v.CVSSSeverity {
		case "CRITICAL":
			summary.Critical++
		case "HIGH":
			summary.High++
		case "MEDIUM":
			summary.Medium++
		case "LOW":
			summary.Low++
		}

		// Count KEV
		if v.InKEV {
			summary.KEVCount++
		}

		// Count Shodan indexed assets (unique only)
		assetKey := v.Hostname + v.IPAddress
		if v.ShodanIndexed && !uniqueAssets[assetKey] {
			summary.ShodanIndexed++
		}

		// Count internet-facing assets (unique only)
		if v.InternetFacing && !uniqueAssets[assetKey] {
			summary.InternetFacing++
		}

		// Count GreyNoise active
		if v.GreyNoiseActive {
			summary.GreyNoiseActive++
		}

		uniqueAssets[assetKey] = true
	}

	return summary
}
