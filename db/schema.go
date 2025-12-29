// Author: Kaleb Austgen
// Date Created: 12/28/25
// Purpose: Database schema definition

package db

const Schema = `
-- CVEs Table: Stores all vulnerabilities from NVD
-- Contains base vulnerability information including CVSS scores and descriptions
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,        -- Unique CVE identifier (e.g., "CVE-2021-41773")
    published TEXT,                 -- When CVE was first published (ISO 8601 format)
    last_modified TEXT,             -- Last modification date (for tracking updates)
    description TEXT,               -- Vulnerability description (usually English)
    cvss_score REAL,                -- CVSS base score (0.0 - 10.0)
    cvss_severity TEXT,             -- Severity rating (LOW/MEDIUM/HIGH/CRITICAL)
    cvss_vector TEXT                -- Full CVSS vector string for detailed analysis
);

-- CPE Matches Table: Links CVEs to affected software/hardware
-- One CVE can affect multiple CPE configurations (one-to-many relationship)
-- This is where version ranges are stored for precise matching
CREATE TABLE IF NOT EXISTS cpe_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT,                    -- References cves.cve_id
    cpe_criteria TEXT,              -- CPE 2.3 string (e.g., "cpe:2.3:a:apache:http_server:2.4.49")
    vulnerable INTEGER,             -- Boolean: 1 if this config is vulnerable, 0 if safe
    version_start_including TEXT,   -- Lower bound of vulnerable versions (inclusive)
    version_end_including TEXT,     -- Upper bound of vulnerable versions (inclusive)
    version_start_excluding TEXT,   -- Lower bound of vulnerable versions (exclusive)
    version_end_excluding TEXT,     -- Upper bound of vulnerable versions (exclusive)
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

-- Inventory Table: Stores organization's assets
-- Each asset has a CPE string that will be matched against cpe_matches
CREATE TABLE IF NOT EXISTS inventory (
    asset_id TEXT PRIMARY KEY,      -- Unique asset identifier
    hostname TEXT,                  -- Asset hostname or name
    ip_address TEXT,                -- IP address (IPv4 or IPv6)
    cpe_string TEXT,                -- CPE 2.3 string describing the asset's software/OS
    asset_type TEXT,                -- Asset category (endpoint/server/router/etc.)
    internet_facing INTEGER DEFAULT 0  -- Boolean: 1 if exposed to internet, 0 if internal
);

-- KEV Catalog Table: Stores Known Exploited Vulnerabilities from CISA
-- This is a subset of CVEs that have CONFIRMED active exploitation in the wild
-- These represent the highest priority vulnerabilities to remediate
CREATE TABLE IF NOT EXISTS kev_catalog (
    cve_id TEXT PRIMARY KEY,        -- Links to cves.cve_id
    vendor_project TEXT,            -- Vendor name (e.g., "Apache")
    product TEXT,                   -- Product name (e.g., "HTTP Server")
    vulnerability_name TEXT,        -- Human-readable vulnerability name
    date_added TEXT,                -- When CISA confirmed active exploitation (YYYY-MM-DD)
    short_description TEXT,         -- Brief vulnerability summary
    required_action TEXT,           -- Remediation instructions from CISA
    due_date TEXT,                  -- Federal agency compliance deadline (YYYY-MM-DD)
    known_ransomware INTEGER DEFAULT 0,  -- Boolean: 1 if used in ransomware campaigns
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

-- Performance Indexes
-- These indexes dramatically speed up JOIN operations and WHERE clauses

-- Index for CPE matching (used in vulnerability_matcher.go)
-- Speeds up LIKE queries on cpe_criteria
CREATE INDEX IF NOT EXISTS idx_cpe_criteria ON cpe_matches(cpe_criteria);

-- Index for tracking CVE updates
-- Useful for incremental updates (fetch only CVEs modified since last run)
CREATE INDEX IF NOT EXISTS idx_cve_modified ON cves(last_modified);

-- Index for inventory lookups
-- Speeds up asset queries by CPE string
CREATE INDEX IF NOT EXISTS idx_inventory_cpe ON inventory(cpe_string);

-- Index for KEV lookups
-- Speeds up JOINs between cves and kev_catalog
CREATE INDEX IF NOT EXISTS idx_kev_cve ON kev_catalog(cve_id);

-- Index for KEV date queries
-- Useful for finding recently added KEV entries
CREATE INDEX IF NOT EXISTS idx_kev_date_added ON kev_catalog(date_added);

-- Shodan Cache Table: Stores Shodan query results to minimize API calls
-- TTL: 7 days (re-query after this period)
-- This dramatically reduces API costs by caching exposure data
CREATE TABLE IF NOT EXISTS shodan_cache (
    ip_address TEXT PRIMARY KEY,           -- IP address queried
    indexed INTEGER NOT NULL DEFAULT 0,    -- Boolean: Is IP in Shodan?
    open_ports TEXT,                       -- JSON array: [80, 443, 3306]
    service_banner TEXT,                   -- Service version info visible to attackers
    shodan_cves TEXT,                      -- JSON array: CVEs Shodan detected
    last_checked TEXT NOT NULL             -- ISO 8601 timestamp for cache expiration
);

-- Index for timestamp-based cache invalidation
-- Allows efficient cleanup of expired cache entries
CREATE INDEX IF NOT EXISTS idx_shodan_last_checked ON shodan_cache(last_checked);
`
