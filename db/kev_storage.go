// Author: Kaleb Austgen
// Date Created: 12/28/25
// Purpose: Database storage and retrieval for CISA Known Exploited Vulnerabilities (KEV) catalog

package db

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/kaustgen/Integrating_AI_OSINT/kev"
)

// StoreKEVCatalog stores the complete CISA KEV catalog in the database
//
// This function should be called AFTER storing NVD CVEs, as KEV entries
// reference the cves table via foreign key constraint. Any KEV entry
// without a matching CVE in the database will be skipped.
//
// The function uses a transaction to ensure atomicity - either all KEV
// entries are stored successfully, or none are stored.
//
// Parameters:
//   - db: Database connection
//   - catalog: KEV catalog from CISA (obtained via kev.FetchKEV())
//
// Returns:
//   - error: Database errors or transaction failures
//
// Database behavior:
//   - Uses INSERT OR REPLACE for idempotency (can be run multiple times)
//   - Skips KEV entries if corresponding CVE doesn't exist (foreign key constraint)
//   - Converts CISA's "Known"/"Unknown" ransomware string to boolean (0/1)
//
// Example usage:
//
//	catalog, _ := kev.FetchKEV()
//	if err := db.StoreKEVCatalog(database, catalog); err != nil {
//	    log.Fatal("Failed to store KEV:", err)
//	}
func StoreKEVCatalog(db *sql.DB, catalog *kev.KEVCatalog) error {
	// Begin transaction for atomicity
	// If any insertion fails, all changes are rolled back
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}

	// Prepare SQL statement for reuse (more efficient than preparing for each row)
	// INSERT OR REPLACE allows idempotent operations - can run multiple times safely
	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO kev_catalog 
		(cve_id, vendor_project, product, vulnerability_name, 
		 date_added, short_description, required_action, due_date, 
		 known_ransomware)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to prepare KEV insert statement: %w", err)
	}
	defer stmt.Close()

	// Track statistics for reporting
	inserted := 0
	skipped := 0

	// Insert each KEV entry into the database
	for _, entry := range catalog.Vulnerabilities {
		// Convert CISA's ransomware indicator to boolean
		// CISA uses "Known" or "Unknown" strings
		// We store as 0 (not used in ransomware) or 1 (used in ransomware)
		isRansomware := 0
		if strings.EqualFold(entry.KnownRansomwareCampaign, "Known") {
			isRansomware = 1
		}

		// Execute insertion
		_, err := stmt.Exec(
			entry.CVEID,
			entry.VendorProject,
			entry.Product,
			entry.VulnerabilityName,
			entry.DateAdded,
			entry.ShortDescription,
			entry.RequiredAction,
			entry.DueDate,
			isRansomware,
		)

		if err != nil {
			// Check if error is due to foreign key constraint
			// This happens when CVE doesn't exist in the cves table yet
			// This is acceptable - skip this KEV entry and continue
			if strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
				skipped++
				continue
			}

			// Other errors are fatal - rollback transaction
			tx.Rollback()
			return fmt.Errorf("failed to insert KEV %s: %w", entry.CVEID, err)
		}

		inserted++
	}

	// Commit transaction - all insertions successful
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit KEV transaction: %w", err)
	}

	// Log statistics (optional, but helpful for debugging)
	if skipped > 0 {
		fmt.Printf("   Note: Skipped %d KEV entries (CVEs not in database)\n", skipped)
	}

	return nil
}

// GetKEVCount returns the total number of KEV entries in the database
//
// Useful for verification after importing KEV data. Should typically
// be close to the Count field from the KEV catalog (~1,100).
//
// Returns:
//   - int: Number of KEV entries stored
//   - error: Database query errors
func GetKEVCount(db *sql.DB) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM kev_catalog").Scan(&count)
	return count, err
}

// IsInKEV checks if a specific CVE is in the KEV catalog
//
// This is a quick lookup function to determine if a CVE has
// confirmed active exploitation.
//
// Parameters:
//   - db: Database connection
//   - cveID: CVE identifier to check (e.g., "CVE-2021-41773")
//
// Returns:
//   - bool: true if CVE is in KEV, false otherwise
//   - error: Database query errors
//
// Example usage:
//
//	isExploited, _ := db.IsInKEV(database, "CVE-2021-41773")
//	if isExploited {
//	    fmt.Println("⚠️ This CVE is actively exploited!")
//	}
func IsInKEV(db *sql.DB, cveID string) (bool, error) {
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS(SELECT 1 FROM kev_catalog WHERE cve_id = ?)
	`, cveID).Scan(&exists)

	return exists, err
}

// GetKEVEntryByCVE retrieves full KEV details for a specific CVE
//
// Returns all KEV metadata including due date, required action, and
// ransomware status for a given CVE.
//
// Parameters:
//   - db: Database connection
//   - cveID: CVE identifier to look up
//
// Returns:
//   - *KEVEntry: KEV entry if found, nil if not in KEV
//   - error: Database query errors
func GetKEVEntryByCVE(db *sql.DB, cveID string) (*kev.KEVEntry, error) {
	var entry kev.KEVEntry
	var ransomware int

	err := db.QueryRow(`
		SELECT cve_id, vendor_project, product, vulnerability_name,
		       date_added, short_description, required_action, due_date,
		       known_ransomware
		FROM kev_catalog
		WHERE cve_id = ?
	`, cveID).Scan(
		&entry.CVEID,
		&entry.VendorProject,
		&entry.Product,
		&entry.VulnerabilityName,
		&entry.DateAdded,
		&entry.ShortDescription,
		&entry.RequiredAction,
		&entry.DueDate,
		&ransomware,
	)

	if err == sql.ErrNoRows {
		return nil, nil // Not in KEV
	}
	if err != nil {
		return nil, err
	}

	// Convert ransomware int back to CISA's string format
	if ransomware == 1 {
		entry.KnownRansomwareCampaign = "Known"
	} else {
		entry.KnownRansomwareCampaign = "Unknown"
	}

	return &entry, nil
}
