// Author: Kaleb Austgen
// Date Created: 12/28/25
// Purpose: Handler for CISA Known Exploited Vulnerabilities (KEV) catalog ingestion

package kev

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// KEVEntry represents a single Known Exploited Vulnerability from CISA's catalog
// Each entry represents a CVE that has confirmed active exploitation in the wild
type KEVEntry struct {
	CVEID                   string `json:"cveID"`                      // Links to NVD database (e.g., "CVE-2021-41773")
	VendorProject           string `json:"vendorProject"`              // Vendor name (e.g., "Apache")
	Product                 string `json:"product"`                    // Product name (e.g., "HTTP Server")
	VulnerabilityName       string `json:"vulnerabilityName"`          // Human-readable name
	DateAdded               string `json:"dateAdded"`                  // When CISA confirmed exploitation (YYYY-MM-DD)
	ShortDescription        string `json:"shortDescription"`           // Brief vulnerability summary
	RequiredAction          string `json:"requiredAction"`             // Remediation steps (e.g., "Apply updates per vendor instructions")
	DueDate                 string `json:"dueDate"`                    // Federal agency compliance deadline (YYYY-MM-DD)
	KnownRansomwareCampaign string `json:"knownRansomwareCampaignUse"` // "Known" or "Unknown" - indicates ransomware usage
}

// KEVCatalog represents the full CISA KEV catalog
// Updated weekly (typically Tuesdays) with new actively exploited vulnerabilities
type KEVCatalog struct {
	Title           string     `json:"title"`           // Catalog title
	CatalogVersion  string     `json:"catalogVersion"`  // Date-based version (YYYY.MM.DD)
	DateReleased    string     `json:"dateReleased"`    // When this version was released
	Count           int        `json:"count"`           // Total number of KEV entries (~1,100 as of Dec 2024)
	Vulnerabilities []KEVEntry `json:"vulnerabilities"` // Array of all KEV entries
}

// FetchKEV retrieves the latest Known Exploited Vulnerabilities catalog from CISA
//
// This function downloads the complete KEV catalog which contains CVEs that are
// actively being exploited in the wild. These represent the highest-priority
// vulnerabilities that should be remediated immediately.
//
// Returns:
//   - *KEVCatalog: Parsed catalog containing all KEV entries
//   - error: Network errors, parsing errors, or API issues
//
// API Details:
//   - Endpoint: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
//   - No authentication required (public data)
//   - Updated weekly (typically Tuesdays)
//   - File size: ~1.5MB (~1,100 entries as of Dec 2024)
//   - No rate limiting
//
// Example usage:
//
//	catalog, err := kev.FetchKEV()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d actively exploited vulnerabilities\n", catalog.Count)
func FetchKEV() (*KEVCatalog, error) {
	// CISA KEV catalog URL - public, no authentication needed
	const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// Create HTTP client with 30-second timeout
	// KEV file is large (~1.5MB) and CISA servers can be slow
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Make GET request to CISA API
	resp, err := client.Get(kevURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch KEV from CISA: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KEV API returned unexpected status %d", resp.StatusCode)
	}

	// Parse JSON directly from response body (memory efficient)
	// JSON decoder streams the data rather than loading it all into memory
	var catalog KEVCatalog
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("failed to parse KEV JSON: %w", err)
	}

	// Sanity check: KEV catalog should always have entries
	// If count is 0, something is wrong with the API or our parsing
	if catalog.Count == 0 {
		return nil, fmt.Errorf("KEV catalog is empty - possible API issue")
	}

	return &catalog, nil
}

// GetKEVByCVEID searches the KEV catalog for a specific CVE
//
// This function fetches the full KEV catalog and searches for a specific CVE ID.
// Useful for checking if a single CVE is actively exploited without storing
// the entire catalog in memory.
//
// Parameters:
//   - cveID: CVE identifier to search for (e.g., "CVE-2021-41773")
//
// Returns:
//   - *KEVEntry: Matching KEV entry if found, nil if not in catalog
//   - error: Network or parsing errors
//
// Example usage:
//
//	entry, err := kev.GetKEVByCVEID("CVE-2021-41773")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if entry != nil {
//	    fmt.Printf("CVE is actively exploited! Due date: %s\n", entry.DueDate)
//	} else {
//	    fmt.Println("CVE is not in KEV catalog")
//	}
func GetKEVByCVEID(cveID string) (*KEVEntry, error) {
	// Fetch the complete KEV catalog
	catalog, err := FetchKEV()
	if err != nil {
		return nil, err
	}

	// Linear search through KEV entries
	// This is acceptable since KEV only has ~1,100 entries (fast enough)
	for _, entry := range catalog.Vulnerabilities {
		if entry.CVEID == cveID {
			return &entry, nil
		}
	}

	// CVE not found in KEV catalog
	return nil, nil
}
