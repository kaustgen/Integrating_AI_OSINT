package db

const Schema = `
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    published TEXT,
    last_modified TEXT,
    description TEXT,
    cvss_score REAL,
    cvss_severity TEXT,
    cvss_vector TEXT
);

CREATE TABLE IF NOT EXISTS cpe_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT,
    cpe_criteria TEXT,
    vulnerable INTEGER,
    version_start_including TEXT,
    version_end_including TEXT,
    version_start_excluding TEXT,
    version_end_excluding TEXT,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

CREATE TABLE IF NOT EXISTS inventory (
    asset_id TEXT PRIMARY KEY,
    hostname TEXT,
    ip_address TEXT,
    cpe_string TEXT,
    asset_type TEXT,
    internet_facing INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_cpe_criteria ON cpe_matches(cpe_criteria);
CREATE INDEX IF NOT EXISTS idx_cve_modified ON cves(last_modified);
CREATE INDEX IF NOT EXISTS idx_inventory_cpe ON inventory(cpe_string);
`
