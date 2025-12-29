// Author: Kaleb Austgen
// Date Created: 12/28/25
// Purpose: Fake inventory creation

package db

import (
	"database/sql"
	"fmt"
)

type Asset struct {
	AssetID        string
	Hostname       string
	IPAddress      string
	CPEString      string
	AssetType      string
	InternetFacing bool
}

func InsertAsset(db *sql.DB, asset Asset) error {
	internetFacing := 0
	if asset.InternetFacing {
		internetFacing = 1
	}

	_, err := db.Exec(`
        INSERT OR REPLACE INTO inventory 
        (asset_id, hostname, ip_address, cpe_string, asset_type, internet_facing)
        VALUES (?, ?, ?, ?, ?, ?)`,
		asset.AssetID, asset.Hostname, asset.IPAddress, asset.CPEString, asset.AssetType, internetFacing,
	)
	return err
}

func CreateFakeInventory(db *sql.DB) error {
	assets := []Asset{
		// 5 Windows 11 endpoints (latest)
		{
			AssetID:        "WIN-001",
			Hostname:       "ws-finance-01",
			IPAddress:      "10.0.10.15",
			CPEString:      "cpe:2.3:o:microsoft:windows_11:23h2:*:*:*:*:*:*:*",
			AssetType:      "endpoint",
			InternetFacing: false,
		},
		{
			AssetID:        "WIN-002",
			Hostname:       "ws-hr-02",
			IPAddress:      "10.0.10.22",
			CPEString:      "cpe:2.3:o:microsoft:windows_11:23h2:*:*:*:*:*:*:*",
			AssetType:      "endpoint",
			InternetFacing: false,
		},
		{
			AssetID:        "WIN-003",
			Hostname:       "ws-exec-01",
			IPAddress:      "10.0.10.35",
			CPEString:      "cpe:2.3:o:microsoft:windows_11:23h2:*:*:*:*:*:*:*",
			AssetType:      "endpoint",
			InternetFacing: false,
		},
		{
			AssetID:        "WIN-004",
			Hostname:       "ws-marketing-03",
			IPAddress:      "10.0.10.48",
			CPEString:      "cpe:2.3:o:microsoft:windows_11:23h2:*:*:*:*:*:*:*",
			AssetType:      "endpoint",
			InternetFacing: false,
		},
		{
			AssetID:        "WIN-005",
			Hostname:       "ws-it-admin",
			IPAddress:      "10.0.10.100",
			CPEString:      "cpe:2.3:o:microsoft:windows_11:23h2:*:*:*:*:*:*:*",
			AssetType:      "endpoint",
			InternetFacing: false,
		},

		// 5 Ubuntu endpoints (latest - 24.04 LTS)
		{
			AssetID:        "UBU-001",
			Hostname:       "dev-workstation-01",
			IPAddress:      "10.0.20.10",
			CPEString:      "cpe:2.3:o:canonical:ubuntu_linux:24.04:*:*:*:lts:*:*:*",
			AssetType:      "endpoint",
			InternetFacing: false,
		},
		{
			AssetID:        "UBU-002",
			Hostname:       "dev-workstation-02",
			IPAddress:      "10.0.20.11",
			CPEString:      "cpe:2.3:o:canonical:ubuntu_linux:24.04:*:*:*:lts:*:*:*",
			AssetType:      "endpoint",
			InternetFacing: false,
		},
		{
			AssetID:        "UBU-003",
			Hostname:       "qa-workstation-01",
			IPAddress:      "10.0.20.15",
			CPEString:      "cpe:2.3:o:canonical:ubuntu_linux:24.04:*:*:*:lts:*:*:*",
			AssetType:      "endpoint",
			InternetFacing: false,
		},
		{
			AssetID:        "UBU-004",
			Hostname:       "data-analysis-01",
			IPAddress:      "10.0.20.20",
			CPEString:      "cpe:2.3:o:canonical:ubuntu_linux:24.04:*:*:*:lts:*:*:*",
			AssetType:      "endpoint",
			InternetFacing: false,
		},
		{
			AssetID:        "UBU-005",
			Hostname:       "security-analyst-ws",
			IPAddress:      "10.0.20.30",
			CPEString:      "cpe:2.3:o:canonical:ubuntu_linux:24.04:*:*:*:lts:*:*:*",
			AssetType:      "endpoint",
			InternetFacing: false,
		},

		// 3 Web servers (outdated - vulnerable)
		// For the first web server I am using a real Amazon server I found in Shodan for testing purposes
		{
			AssetID:        "WEB-001",
			Hostname:       "web-prod-01",
			IPAddress:      "18.169.92.178",
			CPEString:      "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
			AssetType:      "web_server",
			InternetFacing: true,
		},

		// This IP is from a server in the netherlands, also indexed in Shodan
		{
			AssetID:        "WEB-002",
			Hostname:       "api-gateway-01",
			IPAddress:      "31.57.152.121",
			CPEString:      "cpe:2.3:a:igor_sysoev:nginx:1.18.0:*:*:*:*:*:*:*",
			AssetType:      "web_server",
			InternetFacing: true,
		},
		{
			AssetID:        "WEB-003",
			Hostname:       "portal-web-02",
			IPAddress:      "203.0.113.52",
			CPEString:      "cpe:2.3:a:igor_sysoev:nginx:1.18.0:*:*:*:*:*:*:*",
			AssetType:      "web_server",
			InternetFacing: true,
		},

		// 2 Cisco routers
		{
			AssetID:        "RTR-001",
			Hostname:       "core-router-01",
			IPAddress:      "10.0.1.1",
			CPEString:      "cpe:2.3:o:cisco:ios:15.2\\(4\\)m11:*:*:*:*:*:*:*",
			AssetType:      "router",
			InternetFacing: true,
		},
		{
			AssetID:        "RTR-002",
			Hostname:       "edge-router-02",
			IPAddress:      "10.0.1.2",
			CPEString:      "cpe:2.3:o:cisco:ios_xe:17.3.4:*:*:*:*:*:*:*",
			AssetType:      "router",
			InternetFacing: true,
		},

		// 2 Databases (outdated)
		{
			AssetID:        "DB-001",
			Hostname:       "postgres-prod-01",
			IPAddress:      "10.0.30.10",
			CPEString:      "cpe:2.3:a:postgresql:postgresql:12.2:*:*:*:*:*:*:*",
			AssetType:      "database",
			InternetFacing: false,
		},
		{
			AssetID:        "DB-002",
			Hostname:       "mysql-analytics-01",
			IPAddress:      "10.0.30.15",
			CPEString:      "cpe:2.3:a:oracle:mysql:5.7.30:*:*:*:*:*:*:*",
			AssetType:      "database",
			InternetFacing: false,
		},

		// 1 Inventory management system
		{
			AssetID:        "INV-001",
			Hostname:       "asset-mgmt-01",
			IPAddress:      "10.0.40.5",
			CPEString:      "cpe:2.3:a:snipe-it_project:snipe-it:5.3.0:*:*:*:*:*:*:*",
			AssetType:      "inventory_system",
			InternetFacing: false,
		},

		// Bonus: Add the vulnerable Log4j for testing (common vulnerable library)
		{
			AssetID:        "APP-001",
			Hostname:       "java-app-server-01",
			IPAddress:      "10.0.50.10",
			CPEString:      "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
			AssetType:      "application_server",
			InternetFacing: true,
		},
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}

	for _, asset := range assets {
		if err := InsertAsset(db, asset); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to insert asset %s: %v", asset.AssetID, err)
		}
	}

	return tx.Commit()
}

func GetInventory(db *sql.DB) ([]Asset, error) {
	rows, err := db.Query(`
        SELECT asset_id, hostname, ip_address, cpe_string, asset_type, internet_facing
        FROM inventory
        ORDER BY asset_type, hostname
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []Asset
	for rows.Next() {
		var asset Asset
		var internetFacing int
		err := rows.Scan(
			&asset.AssetID,
			&asset.Hostname,
			&asset.IPAddress,
			&asset.CPEString,
			&asset.AssetType,
			&internetFacing,
		)
		if err != nil {
			return nil, err
		}
		asset.InternetFacing = internetFacing == 1
		assets = append(assets, asset)
	}

	return assets, nil
}
