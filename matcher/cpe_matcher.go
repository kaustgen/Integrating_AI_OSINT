// Author: Kaleb Austgen
// Date Created: 12/15/25
// Purpose: CPE matching logic between inventory assets and CVE entries

package matcher

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-version"
)

// ParseCPE extracts vendor, product, and version from CPE 2.3 string
// CPE format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
func ParseCPE(cpe string) (vendor, product, ver string, err error) {
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 {
		return "", "", "", fmt.Errorf("invalid CPE format: %s", cpe)
	}

	return parts[3], parts[4], parts[5], nil
}

// MatchCPE checks if inventory CPE matches CVE CPE criteria with version range support
func MatchCPE(inventoryCPE, cveCPE, versionStartIncluding, versionEndIncluding, versionStartExcluding, versionEndExcluding string) (bool, error) {
	invVendor, invProduct, invVersion, err := ParseCPE(inventoryCPE)
	if err != nil {
		return false, err
	}

	cveVendor, cveProduct, cveVersion, err := ParseCPE(cveCPE)
	if err != nil {
		return false, err
	}

	// Vendor must match (or be wildcard)
	if cveVendor != "*" && invVendor != cveVendor {
		return false, nil
	}

	// Product must match (or be wildcard)
	if cveProduct != "*" && invProduct != cveProduct {
		return false, nil
	}

	// Version matching logic
	if cveVersion == "*" || cveVersion == "-" {
		// Wildcard version - check if version ranges are specified
		if versionStartIncluding != "" || versionEndIncluding != "" ||
			versionStartExcluding != "" || versionEndExcluding != "" {
			return checkVersionRange(invVersion, versionStartIncluding, versionEndIncluding,
				versionStartExcluding, versionEndExcluding)
		}
		// No version specified means all versions are vulnerable
		return true, nil
	}

	// Exact version match
	if invVersion == cveVersion {
		return true, nil
	}

	// If there are version ranges even with specific version, check them
	if versionStartIncluding != "" || versionEndIncluding != "" ||
		versionStartExcluding != "" || versionEndExcluding != "" {
		return checkVersionRange(invVersion, versionStartIncluding, versionEndIncluding,
			versionStartExcluding, versionEndExcluding)
	}

	return false, nil
}

// checkVersionRange validates if current version falls within the specified range
func checkVersionRange(current, startIncluding, endIncluding, startExcluding, endExcluding string) (bool, error) {
	// Can't match if inventory version is wildcard
	if current == "*" || current == "-" || current == "" {
		return false, nil
	}

	// Clean version string (remove leading/trailing whitespace)
	current = strings.TrimSpace(current)

	// Parse current version
	curVer, err := version.NewVersion(current)
	if err != nil {
		// If version parsing fails, it might be a non-standard format
		// Fall back to string comparison
		return stringVersionCheck(current, startIncluding, endIncluding, startExcluding, endExcluding), nil
	}

	// Check start including
	if startIncluding != "" {
		startVer, err := version.NewVersion(startIncluding)
		if err != nil {
			return false, fmt.Errorf("invalid start version: %s", startIncluding)
		}
		if curVer.LessThan(startVer) {
			return false, nil
		}
	}

	// Check end including
	if endIncluding != "" {
		endVer, err := version.NewVersion(endIncluding)
		if err != nil {
			return false, fmt.Errorf("invalid end version: %s", endIncluding)
		}
		if curVer.GreaterThan(endVer) {
			return false, nil
		}
	}

	// Check start excluding
	if startExcluding != "" {
		startVer, err := version.NewVersion(startExcluding)
		if err != nil {
			return false, fmt.Errorf("invalid start excluding version: %s", startExcluding)
		}
		if curVer.LessThanOrEqual(startVer) {
			return false, nil
		}
	}

	// Check end excluding
	if endExcluding != "" {
		endVer, err := version.NewVersion(endExcluding)
		if err != nil {
			return false, fmt.Errorf("invalid end excluding version: %s", endExcluding)
		}
		if curVer.GreaterThanOrEqual(endVer) {
			return false, nil
		}
	}

	return true, nil
}

// stringVersionCheck performs simple string comparison as fallback
func stringVersionCheck(current, startIncluding, endIncluding, startExcluding, endExcluding string) bool {
	// This is a simplified fallback - may not be 100% accurate for all version formats
	if startIncluding != "" && current < startIncluding {
		return false
	}
	if endIncluding != "" && current > endIncluding {
		return false
	}
	if startExcluding != "" && current <= startExcluding {
		return false
	}
	if endExcluding != "" && current >= endExcluding {
		return false
	}
	return true
}
