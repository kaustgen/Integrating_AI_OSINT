package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/kaustgen/Integrating_AI_OSINT/db"
	"github.com/kaustgen/Integrating_AI_OSINT/matcher"
)

func main() {
	// Initialize database
	database := db.InitDB("./vulnerabilities.db")
	defer database.Close()

	fmt.Println("=== Debug CPE Matching ===\n")

	// Get inventory
	inventory, err := db.GetInventory(database)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Checking Apache server:")
	for _, asset := range inventory {
		if strings.Contains(asset.Hostname, "web-prod") {
			fmt.Printf("  Asset: %s\n", asset.Hostname)
			fmt.Printf("  CPE: %s\n\n", asset.CPEString)

			// Extract vendor:product
			parts := strings.Split(asset.CPEString, ":")
			vendorProduct := strings.Join(parts[3:5], ":")
			fmt.Printf("  Looking for: %%:%s:%%\n\n", vendorProduct)

			// Query CVEs
			rows, err := database.Query(`
				SELECT 
					c.cve_id, 
					cm.cpe_criteria,
					cm.vulnerable
				FROM cves c
				JOIN cpe_matches cm ON c.cve_id = cm.cve_id
				WHERE cm.cpe_criteria LIKE ?
				LIMIT 5
			`, "%:"+vendorProduct+":%")

			if err != nil {
				log.Fatal(err)
			}

			fmt.Println("  Found CVEs:")
			for rows.Next() {
				var cveID, cpeCriteria string
				var vulnerable int
				rows.Scan(&cveID, &cpeCriteria, &vulnerable)
				fmt.Printf("    %s | %s | vuln=%d\n", cveID, cpeCriteria, vulnerable)

				// Test matcher
				isMatch, err := matcher.MatchCPE(
					asset.CPEString,
					cpeCriteria,
					"", "", "", "",
				)
				fmt.Printf("      Match result: %v (err: %v)\n", isMatch, err)
			}
			rows.Close()
		}
	}
}
