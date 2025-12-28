package main

import (
	"fmt"
	"log"
	"time"

	NVD_API_handler "github.com/kaustgen/Integrating_AI_OSINT/NVD_getters"
	"github.com/kaustgen/Integrating_AI_OSINT/db"
)

func main() {
	// Initialize database
	// Uses db.go InitDB function
	database := db.InitDB("./vulnerabilities.db")
	defer database.Close()

	fmt.Println("=== Initializing Vulnerability Database ===")

	// Create fake inventory
	fmt.Println("\n[1/3] Creating fake inventory...")
	// Uses inventory.go CreateFakeInventory function
	if err := db.CreateFakeInventory(database); err != nil {
		log.Fatal("Failed to create inventory:", err)
	}

	// Display inventory
	inventory, err := db.GetInventory(database)
	if err != nil {
		log.Fatal("Failed to retrieve inventory:", err)
	}

	fmt.Printf("Successfully created %d assets:\n", len(inventory))
	for _, asset := range inventory {
		internetStatus := "Internal"
		if asset.InternetFacing {
			internetStatus = "INTERNET-FACING"
		}
		fmt.Printf("  [%s] %-25s | %-15s | %s | %s\n",
			asset.AssetType,
			asset.Hostname,
			asset.IPAddress,
			internetStatus,
			asset.CPEString,
		)
	}

	// Fetch and store CVEs
	fmt.Println("\n[2/4] Fetching CVEs from NVD...")
	start := time.Now().AddDate(0, 0, -7).Format("2006-01-02T15:04:05.000")
	end := time.Now().Format("2006-01-02T15:04:05.000")

	cves := NVD_API_handler.GetCVEs(start, end, "2000", true)
	fmt.Printf("Found %d CVEs\n", len(cves))

	fmt.Println("\n[3/4] Storing CVEs in database...")
	if err := db.StoreCVEs(database, cves); err != nil {
		log.Fatal("Failed to store CVEs:", err)
	}
	fmt.Println("Successfully stored CVEs!")

	// Match CVEs to inventory
	fmt.Println("\n[4/4] Matching CVEs to inventory...")
	if err := db.PrintVulnerabilityReport(database); err != nil {
		log.Fatal("Failed to generate vulnerability report:", err)
	}

	fmt.Println("\n=== Database Ready ===")
	fmt.Println("Database file: vulnerabilities.db")
	fmt.Println("\nNext steps:")
	fmt.Println("  1. ✅ CPE matching logic implemented")
	fmt.Println("  2. Add KEV integration")
	fmt.Println("  3. Add Shodan integration")
	fmt.Println("  4. Implement RAG with LLM for report generation")
}
