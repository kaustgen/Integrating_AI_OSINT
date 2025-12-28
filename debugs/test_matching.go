package main

import (
	"fmt"
	"log"

	NVD_API_handler "github.com/kaustgen/Integrating_AI_OSINT/NVD_getters"
	"github.com/kaustgen/Integrating_AI_OSINT/db"
)

func main() {
	// Initialize database
	database := db.InitDB("./vulnerabilities.db")
	defer database.Close()

	fmt.Println("=== Testing Vulnerability Matching ===")

	// Create fake inventory
	fmt.Println("Creating fake inventory...")
	if err := db.CreateFakeInventory(database); err != nil {
		log.Fatal("Failed to create inventory:", err)
	}

	fmt.Println("Fetching CVEs from September 2021 (includes Apache 2.4.49 CVE-2021-41773)")

	// Fetch CVEs from September-October 2021 (Apache CVE-2021-41773 published Oct 5, 2021)
	start := "2021-10-01T00:00:00.000"
	end := "2021-10-10T00:00:00.000"

	cves := NVD_API_handler.GetCVEs(start, end, "2000", true)
	fmt.Printf("Found %d CVEs from Oct 2021\n", len(cves))

	fmt.Println("\nStoring CVEs in database...")
	if err := db.StoreCVEs(database, cves); err != nil {
		log.Fatal("Failed to store CVEs:", err)
	}

	fmt.Println("\nMatching CVEs to inventory...")
	if err := db.PrintVulnerabilityReport(database); err != nil {
		log.Fatal("Failed to generate vulnerability report:", err)
	}
}
