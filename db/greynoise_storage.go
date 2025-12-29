// Author: Kaleb Austgen
// Date Created: 12/28/25
// Purpose: GreyNoise threat intelligence storage with 24-hour TTL

package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kaustgen/Integrating_AI_OSINT/greynoise"
)

// GreyNoiseCacheEntry represents cached threat intelligence for a CVE
type GreyNoiseCacheEntry struct {
	CVEID             string
	ScanCount         int
	MaliciousScanners int
	BenignScanners    int
	Tags              []string
	TopCountries      map[string]int
	FirstSeen         string
	LastSeen          string
	HasRansomware     bool
	HasRecentActivity bool
	LastChecked       time.Time
}

// GetGreyNoiseCache retrieves cached threat data for a CVE
// Returns nil if not cached or cache expired (>24 hours old)
//
// Cache TTL Logic:
//   - If last_checked > 24 hours ago: Treat as expired (return nil)
//   - Otherwise: Return cached data
//
// Why 24 hours? Attack patterns change quickly (botnet campaigns, etc.)
func GetGreyNoiseCache(db *sql.DB, cveID string) (*GreyNoiseCacheEntry, error) {
	var entry GreyNoiseCacheEntry
	var tagsJSON, countriesJSON, lastCheckedStr string

	err := db.QueryRow(`
		SELECT cve_id, scan_count, classification_malicious, 
		       classification_benign, tags, top_countries,
		       first_seen, last_seen, last_checked
		FROM greynoise_cache
		WHERE cve_id = ?
	`, cveID).Scan(
		&entry.CVEID,
		&entry.ScanCount,
		&entry.MaliciousScanners,
		&entry.BenignScanners,
		&tagsJSON,
		&countriesJSON,
		&entry.FirstSeen,
		&entry.LastSeen,
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

	// Check if cache expired (>24 hours old)
	if time.Since(lastChecked) > 24*time.Hour {
		return nil, nil // Cache expired
	}

	entry.LastChecked = lastChecked

	// Parse JSON fields
	if tagsJSON != "" {
		json.Unmarshal([]byte(tagsJSON), &entry.Tags)

		// Check for ransomware tag
		for _, tag := range entry.Tags {
			if strings.Contains(strings.ToLower(tag), "ransomware") {
				entry.HasRansomware = true
				break
			}
		}
	}
	if countriesJSON != "" {
		json.Unmarshal([]byte(countriesJSON), &entry.TopCountries)
	}

	// Check if recent activity (last 24 hours)
	if entry.LastSeen != "" {
		lastSeen, err := time.Parse(time.RFC3339, entry.LastSeen)
		if err == nil && time.Since(lastSeen) < 24*time.Hour {
			entry.HasRecentActivity = true
		}
	}

	return &entry, nil
}

// StoreGreyNoiseCache stores threat intelligence in cache
//
// Parameters:
//   - db: Database connection
//   - cveID: CVE identifier
//   - activity: GreyNoise threat data
//
// Uses INSERT OR REPLACE to handle updates
func StoreGreyNoiseCache(db *sql.DB, cveID string, activity *greynoise.GreyNoiseCVEActivity) error {
	// Serialize JSON fields
	tagsJSON, _ := json.Marshal(activity.Tags)
	countriesJSON, _ := json.Marshal(activity.TopCountries)

	_, err := db.Exec(`
		INSERT OR REPLACE INTO greynoise_cache
		(cve_id, scan_count, classification_malicious, classification_benign,
		 tags, top_countries, first_seen, last_seen, last_checked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		cveID,
		activity.TotalScanners,
		activity.MaliciousScanners,
		activity.BenignScanners,
		string(tagsJSON),
		string(countriesJSON),
		activity.FirstSeen,
		activity.LastSeen,
		time.Now().Format(time.RFC3339),
	)

	return err
}

// GetGreyNoiseThreatIntel fetches threat data for a CVE (with caching)
//
// Algorithm:
//  1. Check cache (if fresh, return cached)
//  2. If not cached, query GreyNoise API
//  3. Store result in cache
//  4. Return threat data
//
// This minimizes API calls while keeping data fresh (24-hour TTL)
func GetGreyNoiseThreatIntel(db *sql.DB, greynoiseClient *greynoise.GreyNoiseClient, cveID string) (*GreyNoiseCacheEntry, error) {
	// Try cache first
	cached, err := GetGreyNoiseCache(db, cveID)
	if err != nil {
		return nil, err
	}

	if cached != nil {
		// Cache hit
		return cached, nil
	}

	// Cache miss - query GreyNoise API
	activity, err := greynoiseClient.GetCVEActivity(cveID)
	if err != nil {
		return nil, err
	}

	// Store in cache
	if err := StoreGreyNoiseCache(db, cveID, activity); err != nil {
		// Log error but don't fail - we still got the result
		fmt.Printf("Warning: Failed to cache GreyNoise data for %s: %v\n", cveID, err)
	}

	// Convert to cache entry format
	entry := &GreyNoiseCacheEntry{
		CVEID:             cveID,
		ScanCount:         activity.TotalScanners,
		MaliciousScanners: activity.MaliciousScanners,
		BenignScanners:    activity.BenignScanners,
		Tags:              activity.Tags,
		TopCountries:      activity.TopCountries,
		FirstSeen:         activity.FirstSeen,
		LastSeen:          activity.LastSeen,
		HasRansomware:     activity.HasRansomwareTag,
		HasRecentActivity: activity.HasRecentActivity,
		LastChecked:       time.Now(),
	}

	return entry, nil
}

// EnhanceWithGreyNoiseData adds threat intelligence to vulnerabilities
// This is called after Shodan enhancement but before final report
//
// Algorithm:
//  1. Filter to only KEV vulnerabilities (those most likely to be scanned)
//  2. For each unique CVE, query GreyNoise (with caching)
//  3. Add threat data to all assets with that CVE
//  4. Return enhanced vulnerability list
//
// Why only KEV? GreyNoise queries cost money, focus on high-priority CVEs
//
// Parameters:
//   - useMockData: If true, uses mock data instead of real API (for demonstrations)
func EnhanceWithGreyNoiseData(db *sql.DB, greynoiseClient *greynoise.GreyNoiseClient, vulns []VulnerableAsset) ([]VulnerableAsset, error) {
	enhanced := make([]VulnerableAsset, len(vulns))

	// Track which CVEs we've already queried (avoid duplicates)
	queriedCVEs := make(map[string]*GreyNoiseCacheEntry)

	// Check if we should use mock data (for demonstration)
	// Set to true to show realistic exploitation data for old CVEs
	useMockData := true // Change to false for production with real API

	for i, vuln := range vulns {
		enhanced[i] = vuln // Copy existing data

		// Only query GreyNoise for KEV vulnerabilities
		// Rationale: KEV = actively exploited, most likely to have GreyNoise data
		// Non-KEV queries would waste API quota on low-value data
		if !vuln.InKEV {
			continue
		}

		// Check if we've already queried this CVE
		if threat, exists := queriedCVEs[vuln.CVEID]; exists {
			// Reuse existing data
			enhanced[i].GreyNoiseActive = threat.MaliciousScanners > 0
			enhanced[i].GreyNoiseScanCount = threat.ScanCount
			enhanced[i].GreyNoiseTags = threat.Tags
			enhanced[i].GreyNoiseCountries = threat.TopCountries
			enhanced[i].GreyNoiseRansomware = threat.HasRansomware
			enhanced[i].GreyNoiseRecentActivity = threat.HasRecentActivity
			continue
		}

		var threat *GreyNoiseCacheEntry
		var err error

		if useMockData {
			// Use mock data for demonstration
			mockActivity := greynoise.GetMockGreyNoiseData(vuln.CVEID)
			threat = &GreyNoiseCacheEntry{
				CVEID:             mockActivity.CVEID,
				ScanCount:         mockActivity.TotalScanners,
				MaliciousScanners: mockActivity.MaliciousScanners,
				BenignScanners:    mockActivity.BenignScanners,
				Tags:              mockActivity.Tags,
				TopCountries:      mockActivity.TopCountries,
				FirstSeen:         mockActivity.FirstSeen,
				LastSeen:          mockActivity.LastSeen,
				HasRansomware:     mockActivity.HasRansomwareTag,
				HasRecentActivity: mockActivity.HasRecentActivity,
				LastChecked:       time.Now(),
			}
		} else {
			// Query GreyNoise API (uses cache if available)
			threat, err = GetGreyNoiseThreatIntel(db, greynoiseClient, vuln.CVEID)
			if err != nil {
				fmt.Printf("Warning: GreyNoise query failed for %s: %v\n", vuln.CVEID, err)
				continue
			}
		}

		// Cache for other assets with same CVE
		queriedCVEs[vuln.CVEID] = threat

		// Add threat data to vulnerability
		enhanced[i].GreyNoiseActive = threat.MaliciousScanners > 0
		enhanced[i].GreyNoiseScanCount = threat.ScanCount
		enhanced[i].GreyNoiseTags = threat.Tags
		enhanced[i].GreyNoiseCountries = threat.TopCountries
		enhanced[i].GreyNoiseRansomware = threat.HasRansomware
		enhanced[i].GreyNoiseRecentActivity = threat.HasRecentActivity
	}

	return enhanced, nil
}
