package db

import (
	"database/sql"

	NVD_API_handler "github.com/kaustgen/Integrating_AI_OSINT/NVD_getters"
)

func StoreCVE(db *sql.DB, cve NVD_API_handler.FlattenedCVE) error {
	// Get first description (usually English)
	desc := ""
	if len(cve.Descriptions) > 0 {
		desc = cve.Descriptions[0]
	}

	// Get CVSS data if available
	var score float32
	var severity, vector string
	if len(cve.CVSSData) > 0 {
		score = cve.CVSSData[0].BaseScore
		severity = cve.CVSSData[0].BaseSeverity
		vector = cve.CVSSData[0].VectorString
	}

	// Insert CVE
	_, err := db.Exec(`
        INSERT OR REPLACE INTO cves 
        (cve_id, published, last_modified, description, cvss_score, cvss_severity, cvss_vector)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		cve.ID, cve.Published, cve.LastModified, desc, score, severity, vector,
	)

	if err != nil {
		return err
	}

	// Insert CPE matches
	for _, node := range cve.Nodes {
		vulnerable := 0
		if node.Vulnerable {
			vulnerable = 1
		}
		_, err := db.Exec(`
            INSERT INTO cpe_matches 
            (cve_id, cpe_criteria, vulnerable, version_start_including, version_end_including, version_start_excluding, version_end_excluding)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
			cve.ID, node.Criteria, vulnerable,
			node.VersionStartIncluding, node.VersionEndIncluding,
			node.VersionStartExcluding, node.VersionEndExcluding,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func StoreCVEs(db *sql.DB, cves []NVD_API_handler.FlattenedCVE) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	for _, cve := range cves {
		if err := StoreCVE(db, cve); err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}
