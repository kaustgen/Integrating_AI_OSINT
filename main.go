// Author: Kaleb Austgen
// Date Created: 12/28/25
// Purpose: Main application entry point

package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	NVD_API_handler "github.com/kaustgen/Integrating_AI_OSINT/NVD_getters"
	"github.com/kaustgen/Integrating_AI_OSINT/db"
	"github.com/kaustgen/Integrating_AI_OSINT/greynoise"
	"github.com/kaustgen/Integrating_AI_OSINT/kev"
	"github.com/kaustgen/Integrating_AI_OSINT/llm"
	"github.com/kaustgen/Integrating_AI_OSINT/shodan"
)

func main() {
	// Load environment variables (for Shodan API key)
	// Create a .env file with: SHODAN_API_KEY=your_key_here
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found, Shodan integration will be disabled")
	}

	// Initialize database with schema (includes CVEs, CPE matches, inventory, KEV, and Shodan cache tables)
	database := db.InitDB("./vulnerabilities.db")
	defer database.Close()

	fmt.Println("=== Vulnerability Scanner with KEV + Shodan Integration ===")

	// ==================== STEP 1: Inventory Management ====================
	fmt.Println("\n[1/5] Loading inventory...")
	// Create fake inventory for testing
	// In production, this would load from asset management system
	if err := db.CreateFakeInventory(database); err != nil {
		log.Fatal("Failed to create inventory:", err)
	}

	// Display loaded assets
	inventory, err := db.GetInventory(database)
	if err != nil {
		log.Fatal("Failed to retrieve inventory:", err)
	}

	fmt.Printf("Loaded %d assets:\n", len(inventory))
	for _, asset := range inventory {
		internetStatus := "Internal"
		if asset.InternetFacing {
			internetStatus = "🌐 INTERNET-FACING"
		}
		fmt.Printf("  [%s] %-25s | %-15s | %s\n",
			asset.AssetType,
			asset.Hostname,
			asset.IPAddress,
			internetStatus,
		)
	}

	// ==================== STEP 2: Fetch NVD CVEs ====================
	fmt.Println("\n[2/5] Fetching CVEs from NVD...")
	// Incremental updates based on last_modified date (last 7 days)
	// This fetches CVEs that were published or modified in the last week
	end := time.Now().UTC()
	start := end.AddDate(0, 0, -7) // 7 days ago

	// Format dates for NVD API (ISO 8601 format)
	startStr := start.Format("2006-01-02T15:04:05.000")
	endStr := end.Format("2006-01-02T15:04:05.000")

	// For testing with October 2021 data (Apache 2.4.49 vulnerabilities):
	// Uncomment these lines to test with historical data
	// startStr := "2021-10-01T00:00:00.000"
	// endStr := "2021-10-31T23:59:59.000"

	cves := NVD_API_handler.GetCVEs(startStr, endStr, "2000", true)
	fmt.Printf("Found %d CVEs from last 7 days (%s to %s)\n", len(cves), start.Format("2006-01-02"), end.Format("2006-01-02"))

	// ==================== STEP 3: Store NVD CVEs ====================
	fmt.Println("\n[3/5] Storing CVEs in database...")
	if err := db.StoreCVEs(database, cves); err != nil {
		log.Fatal("Failed to store CVEs:", err)
	}
	fmt.Println("✅ CVEs stored successfully")

	// ==================== STEP 4: Fetch and Store KEV ====================
	fmt.Println("\n[4/5] Fetching Known Exploited Vulnerabilities (KEV) from CISA...")
	// KEV provides prioritization - tells us which CVEs are actively exploited
	kevCatalog, err := kev.FetchKEV()
	if err != nil {
		log.Fatal("Failed to fetch KEV catalog:", err)
	}
	fmt.Printf("Found %d actively exploited CVEs in KEV catalog\n", kevCatalog.Count)

	// Store KEV data in database
	// This will cross-reference with CVEs already stored
	if err := db.StoreKEVCatalog(database, kevCatalog); err != nil {
		log.Fatal("Failed to store KEV data:", err)
	}

	// Verify KEV storage
	kevCount, _ := db.GetKEVCount(database)
	fmt.Printf("✅ Stored %d KEV entries (some may be filtered if CVE not in database)\n", kevCount)

	// ==================== STEP 5: Shodan Exposure Validation ====================
	fmt.Println("\n[5/7] Validating internet exposure via Shodan...")

	shodanAPIKey := os.Getenv("SHODAN_API_KEY")
	var shodanClient *shodan.ShodanClient

	if shodanAPIKey == "" {
		fmt.Println("⚠️  Shodan API key not found - skipping exposure validation")
		fmt.Println("   Set SHODAN_API_KEY in .env file to enable this feature")
		fmt.Println("   Get your API key from: https://account.shodan.io")
	} else {
		shodanClient = shodan.NewShodanClient(shodanAPIKey)

		// Generate Shodan exposure report
		if err := db.GetShodanExposureReport(database, shodanClient); err != nil {
			log.Printf("Warning: Shodan scan failed: %v", err)
		}
	}

	// ==================== STEP 6: GreyNoise Threat Intelligence ====================
	fmt.Println("\n[6/7] Querying GreyNoise for active exploitation attempts...")

	greynoiseAPIKey := os.Getenv("GREYNOISE_API_KEY")
	var greynoiseClient *greynoise.GreyNoiseClient

	if greynoiseAPIKey == "" {
		fmt.Println("⚠️  GreyNoise API key not found - skipping threat intelligence")
		fmt.Println("   Set GREYNOISE_API_KEY in .env file to enable this feature")
		fmt.Println("   Get your API key from: https://www.greynoise.io/")
	} else {
		greynoiseClient = greynoise.NewGreyNoiseClient(greynoiseAPIKey)
		// Tier detection happens in NewGreyNoiseClient
	}

	// ==================== STEP 7: Match and Generate Report ====================
	fmt.Println("\n[7/7] Analyzing vulnerabilities and generating report...")
	// This performs:
	// 1. CPE matching between inventory and CVEs
	// 2. Version range validation
	// 3. KEV cross-referencing for prioritization
	// 4. Risk-based sorting
	vulns, err := db.FindVulnerableAssets(database)
	if err != nil {
		log.Fatal("Failed to find vulnerabilities:", err)
	}

	// Enhance with Shodan data if available
	if shodanClient != nil {
		fmt.Println("Enhancing vulnerability data with Shodan exposure information...")
		vulns, err = db.EnhanceWithShodanData(database, shodanClient, vulns)
		if err != nil {
			log.Printf("Warning: Failed to enhance with Shodan data: %v", err)
		}
	}

	// Enhance with GreyNoise threat intelligence if available
	// This queries only KEV vulnerabilities to minimize API costs
	if greynoiseClient != nil {
		// Count how many KEV vulnerabilities we have
		kevVulns := 0
		uniqueCVEs := make(map[string]bool)
		for _, v := range vulns {
			if v.InKEV {
				kevVulns++
				uniqueCVEs[v.CVEID] = true
			}
		}

		if kevVulns > 0 {
			fmt.Printf("Analyzing %d KEV vulnerabilities (%d unique CVEs)...\n", kevVulns, len(uniqueCVEs))
			vulns, err = db.EnhanceWithGreyNoiseData(database, greynoiseClient, vulns)
			if err != nil {
				log.Printf("Warning: Failed to enhance with GreyNoise data: %v", err)
			} else {
				// Count how many have active exploitation
				activeCount := 0
				for _, v := range vulns {
					if v.GreyNoiseActive {
						activeCount++
					}
				}
				if activeCount > 0 {
					fmt.Printf("🎯 Found active exploitation attempts on %d vulnerabilities\n", activeCount)
				} else {
					fmt.Println("✅ No active exploitation attempts detected")
				}
			}
		} else {
			fmt.Println("No KEV vulnerabilities found - skipping GreyNoise queries")
		}
	}

	// Generate final detailed vulnerability report
	fmt.Println("\nGenerating detailed vulnerability report...")
	if err := db.PrintVulnerabilityReportWithVulns(vulns); err != nil {
		log.Fatal("Failed to generate vulnerability report:", err)
	}

	// ==================== STEP 8: LLM Risk Assessment ====================
	fmt.Println("\n[8/8] Generating AI-powered risk assessment...")

	llmClient := llm.NewLLMClient()
	if llmClient != nil && len(vulns) > 0 {
		fmt.Println("Building risk assessment prompt...")
		prompt := llm.BuildRiskAssessmentPrompt(vulns)

		fmt.Println("Querying OpenAI API...")
		assessment, err := llmClient.GenerateRiskAssessment(prompt)
		if err != nil {
			log.Printf("⚠️  LLM analysis failed: %v", err)
			fmt.Println("   Continuing without AI risk assessment")
		} else {
			// Print AI-generated risk assessment
			fmt.Println("\n" + strings.Repeat("=", 80))
			fmt.Println("🤖 AI-GENERATED RISK ASSESSMENT (Top 5 Critical Assets)")
			fmt.Println(strings.Repeat("=", 80))
			fmt.Println(assessment)
			fmt.Println(strings.Repeat("=", 80))
		}
	} else if llmClient == nil {
		fmt.Println("⚠️  OpenAI API key not found - skipping AI analysis")
		fmt.Println("   Set OPENAI_API_KEY in .env file to enable this feature")
		fmt.Println("   Get your API key from: https://platform.openai.com/api-keys")
	}

	// ==================== Summary ====================
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("=== Analysis Complete ===")
	fmt.Println("\nDatabase: vulnerabilities.db")
	fmt.Println("\nImplemented Features:")
	fmt.Println("  ✅ NVD CVE ingestion with CPE matching")
	fmt.Println("  ✅ KEV integration for exploit prioritization")
	fmt.Println("  ✅ Shodan exposure validation")
	fmt.Println("  ✅ GreyNoise active threat intelligence")
	fmt.Println("  ✅ LLM-powered risk assessment (OpenAI GPT-4o-mini)")
	fmt.Println("  ✅ Semantic version comparison")
	fmt.Println("  ✅ Risk-based vulnerability sorting")
	fmt.Println("\nNote:")
	fmt.Println("  ⚠️  GreyNoise data may be simulated (Community API tier)")
	fmt.Println("     Production deployment requires Researcher tier ($100/month)")
	fmt.Println("\nAPI Costs (per scan):")
	fmt.Println("  - OpenAI: ~$0.001 (GPT-4o-mini)")
	fmt.Println("  - Total: <$0.01 per scan")
}
