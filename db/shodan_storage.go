// Author: Kaleb Austgen
// Date Created: 12/28/25
// Purpose: Shodan cache storage with 7-day TTL to minimize API costs

package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kaustgen/Integrating_AI_OSINT/shodan"
)

// ShodanCacheEntry represents cached Shodan data for an IP
type ShodanCacheEntry struct {
	IPAddress     string
	Indexed       bool
	OpenPorts     []int
	ServiceBanner string
	ShodanCVEs    []string
	LastChecked   time.Time
}

// GetShodanCache retrieves cached Shodan data for an IP
// Returns nil if not cached or cache expired (>7 days old)
//
// Cache TTL Logic:
//   - If last_checked > 7 days ago: Treat as expired (return nil)
//   - Otherwise: Return cached data
//
// This balances freshness vs API cost
func GetShodanCache(db *sql.DB, ip string) (*ShodanCacheEntry, error) {
	var entry ShodanCacheEntry
	var openPortsJSON, shodanCVEsJSON, lastCheckedStr string
	var indexed int

	err := db.QueryRow(`
		SELECT ip_address, indexed, open_ports, service_banner, 
		       shodan_cves, last_checked
		FROM shodan_cache
		WHERE ip_address = ?
	`, ip).Scan(
		&entry.IPAddress,
		&indexed,
		&openPortsJSON,
		&entry.ServiceBanner,
		&shodanCVEsJSON,
		&lastCheckedStr,
	)

	if err == sql.ErrNoRows {
		return nil, nil // Not cached
	}
	if err != nil {
		return nil, err
	}

	// Parse last_checked timestamp
	lastChecked, err := time.Parse(time.RFC3339, lastCheckedStr)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp in cache: %w", err)
	}

	// Check if cache expired (>7 days old)
	if time.Since(lastChecked) > 7*24*time.Hour {
		return nil, nil // Cache expired, treat as not cached
	}

	entry.Indexed = indexed == 1
	entry.LastChecked = lastChecked

	// Parse JSON arrays
	if openPortsJSON != "" {
		json.Unmarshal([]byte(openPortsJSON), &entry.OpenPorts)
	}
	if shodanCVEsJSON != "" {
		json.Unmarshal([]byte(shodanCVEsJSON), &entry.ShodanCVEs)
	}

	return &entry, nil
}

// StoreShodanCache stores Shodan query results in cache
//
// Parameters:
//   - db: Database connection
//   - ip: IP address
//   - host: Shodan host data (nil if IP not indexed)
//
// Uses INSERT OR REPLACE to handle updates (e.g., IP becomes indexed later)
func StoreShodanCache(db *sql.DB, ip string, host *shodan.ShodanHost) error {
	indexed := 0
	var openPortsJSON, shodanCVEsJSON, banner string

	if host != nil {
		indexed = 1

		// Serialize arrays to JSON
		openPortsBytes, _ := json.Marshal(host.Ports)
		openPortsJSON = string(openPortsBytes)

		shodanCVEsBytes, _ := json.Marshal(host.Vulns)
		shodanCVEsJSON = string(shodanCVEsBytes)

		// Extract first service banner (most relevant)
		if len(host.Data) > 0 {
			banner = host.Data[0].Banner
			// Truncate to 1000 chars (banners can be huge)
			if len(banner) > 1000 {
				banner = banner[:1000] + "..."
			}
		}
	}

	// Store in cache
	_, err := db.Exec(`
		INSERT OR REPLACE INTO shodan_cache 
		(ip_address, indexed, open_ports, service_banner, shodan_cves, last_checked)
		VALUES (?, ?, ?, ?, ?, ?)
	`, ip, indexed, openPortsJSON, banner, shodanCVEsJSON, time.Now().Format(time.RFC3339))

	return err
}

// IsShodanIndexed checks if an IP is in Shodan (with caching)
// This is the main function called during vulnerability scanning
//
// Algorithm:
//  1. Check cache (if fresh, return cached result)
//  2. If not cached, query Shodan API
//  3. Store result in cache
//  4. Return indexed status
//
// This minimizes API calls while keeping data reasonably fresh
func IsShodanIndexed(db *sql.DB, shodanClient *shodan.ShodanClient, ip string) (bool, error) {
	// Try cache first
	cached, err := GetShodanCache(db, ip)
	if err != nil {
		return false, err
	}

	if cached != nil {
		// Cache hit - return cached result
		return cached.Indexed, nil
	}

	// Cache miss - query Shodan API
	host, err := shodanClient.QueryHost(ip)
	if err != nil {
		return false, err
	}

	// Store in cache for future queries
	if err := StoreShodanCache(db, ip, host); err != nil {
		// Log error but don't fail - we still got the result
		fmt.Printf("Warning: Failed to cache Shodan result for %s: %v\n", ip, err)
	}

	return host != nil, nil
}

// GetShodanExposureReport generates summary of internet exposure
// Shows which assets are visible on Shodan (discoverable by attackers)
func GetShodanExposureReport(db *sql.DB, shodanClient *shodan.ShodanClient) error {
	// Get all internet-facing assets from inventory
	rows, err := db.Query(`
		SELECT asset_id, hostname, ip_address, cpe_string
		FROM inventory
		WHERE internet_facing = 1
	`)
	if err != nil {
		return err
	}

	// Collect all assets first to avoid database lock during Shodan queries
	type assetInfo struct {
		assetID  string
		hostname string
		ip       string
		cpe      string
	}
	var assets []assetInfo

	for rows.Next() {
		var a assetInfo
		rows.Scan(&a.assetID, &a.hostname, &a.ip, &a.cpe)
		assets = append(assets, a)
	}
	rows.Close() // Close rows before making Shodan queries

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("           SHODAN EXPOSURE ANALYSIS")
	fmt.Println(strings.Repeat("=", 70))

	exposed := 0
	notExposed := 0

	// Now query Shodan and cache results (no database lock issues)
	for _, asset := range assets {
		// Check if indexed (uses cache if available)
		indexed, err := IsShodanIndexed(db, shodanClient, asset.ip)
		if err != nil {
			fmt.Printf("❌ %s (%s): Error querying Shodan: %v\n", asset.hostname, asset.ip, err)
			continue
		}

		if indexed {
			exposed++
			fmt.Printf("🔴 %s (%s): INDEXED BY SHODAN\n", asset.hostname, asset.ip)
			fmt.Printf("   └─ Discoverable by attackers via Shodan search\n")
		} else {
			notExposed++
			fmt.Printf("✅ %s (%s): Not indexed by Shodan\n", asset.hostname, asset.ip)
		}
	}

	fmt.Printf("\nSummary: %d exposed, %d not exposed\n", exposed, notExposed)
	return nil
}

// EnhanceWithShodanData adds Shodan exposure information to vulnerability results
// This provides additional context about which vulnerabilities are externally visible
//
// Algorithm:
//  1. Filter vulnerabilities to only internet-facing assets
//  2. For each asset, check Shodan (with caching)
//  3. Add Shodan metadata to vulnerability struct
//  4. Re-sort by priority (Shodan-indexed vulnerabilities score higher)
//
// This should be called AFTER FindVulnerableAssets but BEFORE PrintVulnerabilityReport
func EnhanceWithShodanData(db *sql.DB, shodanClient *shodan.ShodanClient, vulns []VulnerableAsset) ([]VulnerableAsset, error) {
	enhanced := make([]VulnerableAsset, len(vulns))

	for i, vuln := range vulns {
		enhanced[i] = vuln // Copy existing data

		// Only check Shodan for internet-facing assets
		if !vuln.InternetFacing {
			continue
		}

		// Check cache first, then query Shodan if needed
		cached, err := GetShodanCache(db, vuln.IPAddress)
		if err != nil {
			// Log error but continue (don't break entire scan)
			fmt.Printf("Warning: Shodan cache error for %s: %v\n", vuln.IPAddress, err)
			continue
		}

		if cached != nil {
			// Use cached data
			enhanced[i].ShodanIndexed = cached.Indexed
			enhanced[i].ShodanPorts = cached.OpenPorts
			enhanced[i].ShodanCVEs = cached.ShodanCVEs
		} else {
			// Query Shodan API
			host, err := shodanClient.QueryHost(vuln.IPAddress)
			if err != nil {
				fmt.Printf("Warning: Shodan query failed for %s: %v\n", vuln.IPAddress, err)
				continue
			}

			// Store in cache
			StoreShodanCache(db, vuln.IPAddress, host)

			if host != nil {
				enhanced[i].ShodanIndexed = true
				enhanced[i].ShodanPorts = host.Ports
				enhanced[i].ShodanCVEs = host.Vulns
			}
		}
	}

	return enhanced, nil
}
