// Author: Kaleb Austgen
// Date Created: 12/29/25
// Purpose: HTML report generator

package report

import (
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"
)

// HTMLTemplate defines the structure of the HTML report
const HTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Assessment Report - {{.Timestamp.Format "2006-01-02"}}</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🛡️ Vulnerability Assessment Report</h1>
            <div class="metadata">
                <span><strong>Generated:</strong> {{.Timestamp.Format "January 2, 2006 at 3:04 PM MST"}}</span>
                <span><strong>Scan Duration:</strong> {{.ScanDuration.Round (index . "DurationPrecision")}}</span>
                <span><strong>Total Assets:</strong> {{.Summary.TotalAssets}}</span>
            </div>
        </div>

        <!-- Summary Statistics -->
        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="number">{{.Summary.Critical}}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="number">{{.Summary.High}}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="number">{{.Summary.Medium}}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card kev">
                <div class="number">{{.Summary.KEVCount}}</div>
                <div class="label">KEV (Exploited)</div>
            </div>
            <div class="summary-card">
                <div class="number">{{.Summary.ShodanIndexed}}</div>
                <div class="label">Shodan Indexed</div>
            </div>
            <div class="summary-card">
                <div class="number">{{.Summary.GreyNoiseActive}}</div>
                <div class="label">Active Attacks</div>
            </div>
        </div>

        {{if .AIAnalysis}}
        <!-- AI-Generated Analysis -->
        <div class="ai-section">
            <h2>🤖 AI-Generated Technical Analysis</h2>
            <div class="content">{{.AIAnalysis}}</div>
        </div>
        {{end}}

        <!-- Detailed Vulnerability List -->
        <div class="vulnerabilities-section">
            <h2>Detailed Vulnerability Assessment</h2>
            {{range .Vulnerabilities}}
            <div class="vuln-card">
                <div class="vuln-card-header {{.CVSSSeverity | lower}}">
                    <div class="vuln-card-title">
                        <h3>{{.CVEID}} - {{.Hostname}}</h3>
                        <div class="vuln-badges">
                            <span class="badge {{.CVSSSeverity | lower}}">{{.CVSSSeverity}}</span>
                            {{if .InKEV}}<span class="badge kev">KEV</span>{{end}}
                            {{if .ShodanIndexed}}<span class="badge shodan">SHODAN</span>{{end}}
                            {{if .GreyNoiseActive}}<span class="badge greynoise">ACTIVE ATTACK</span>{{end}}
                        </div>
                    </div>
                </div>
                <div class="vuln-card-body">
                    <div class="vuln-meta">
                        <div class="vuln-meta-item">
                            <div class="vuln-meta-label">Asset</div>
                            <div class="vuln-meta-value">{{.Hostname}} ({{.IPAddress}})</div>
                        </div>
                        <div class="vuln-meta-item">
                            <div class="vuln-meta-label">Asset Type</div>
                            <div class="vuln-meta-value">{{.AssetType}}</div>
                        </div>
                        <div class="vuln-meta-item">
                            <div class="vuln-meta-label">CVSS Score</div>
                            <div class="vuln-meta-value">{{printf "%.1f" .CVSSScore}} / 10.0</div>
                        </div>
                        {{if .InKEV}}
                        <div class="vuln-meta-item">
                            <div class="vuln-meta-label">KEV Due Date</div>
                            <div class="vuln-meta-value">{{.KEVDueDate}}</div>
                        </div>
                        {{end}}
                    </div>

                    <div class="vuln-description">
                        <strong>Description:</strong> {{.Description}}
                    </div>

                    {{if .InKEV}}
                    <div class="vuln-threat-intel">
                        <h4>🔥 KEV - Actively Exploited</h4>
                        <div class="threat-detail"><strong>Date Added:</strong> {{.KEVDateAdded}}</div>
                        <div class="threat-detail"><strong>Required Action:</strong> {{.KEVAction}}</div>
                        {{if .IsRansomware}}<div class="threat-detail">⚠️ <strong>Known ransomware campaign usage</strong></div>{{end}}
                    </div>
                    {{end}}

                    {{if .ShodanIndexed}}
                    <div class="vuln-threat-intel">
                        <h4>🔍 Shodan Exposure</h4>
                        <div class="threat-detail">Asset is indexed in Shodan (publicly discoverable)</div>
                        {{if .ShodanPorts}}<div class="threat-detail"><strong>Open Ports:</strong> {{range .ShodanPorts}}{{.}} {{end}}</div>{{end}}
                    </div>
                    {{end}}

                    {{if .GreyNoiseActive}}
                    <div class="vuln-threat-intel">
                        <h4>🎯 Active Exploitation (GreyNoise)</h4>
                        <div class="threat-detail"><strong>Scanning IPs:</strong> {{.GreyNoiseScanCount}}</div>
                        {{if .GreyNoiseTags}}<div class="threat-detail"><strong>Attack Tags:</strong> {{range .GreyNoiseTags}}{{.}} {{end}}</div>{{end}}
                        {{if .GreyNoiseCountries}}
                        <div class="threat-detail"><strong>Top Attack Origins:</strong>
                        {{range $country, $count := .GreyNoiseCountries}}{{$country}} ({{$count}} IPs) {{end}}
                        </div>
                        {{end}}
                        {{if .GreyNoiseRansomware}}<div class="threat-detail">⚠️ <strong>Ransomware actors actively scanning</strong></div>{{end}}
                        {{if .GreyNoiseRecentActivity}}<div class="threat-detail">🔴 <strong>Scanned within last 24 hours</strong></div>{{end}}
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>Generated by Vulnerability Scanner with AI-Enhanced Risk Assessment</p>
            <p>NVD + KEV + Shodan + GreyNoise + OpenAI Integration</p>
        </div>
    </div>
</body>
</html>`

// GenerateHTML creates an HTML report file
func GenerateHTML(filename string, data ReportData) error {
	// Create template with custom functions
	funcMap := template.FuncMap{
		"lower": strings.ToLower,
	}

	// Add duration precision to template data
	templateData := map[string]interface{}{
		"Timestamp":         data.Timestamp,
		"ScanDuration":      data.ScanDuration,
		"DurationPrecision": time.Second,
		"AIAnalysis":        data.AIAnalysis,
		"Summary":           data.Summary,
		"Vulnerabilities":   data.Vulnerabilities,
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(HTMLTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Create HTML file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Execute template
	if err := tmpl.Execute(file, templateData); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

// CopyStylesheet creates the CSS file in the specified directory
func CopyStylesheet(reportDir string) error {
	// CSS content (embedded)
	cssContent := []byte(`/* Author: Kaleb Austgen
   Date Created: 12/29/25
   Purpose: Stylesheet for vulnerability assessment reports */

:root {
    --color-critical: #dc3545;
    --color-high: #fd7e14;
    --color-medium: #ffc107;
    --color-low: #28a745;
    --color-kev: #e83e8c;
    --color-primary: #007bff;
    --color-secondary: #6c757d;
    --color-bg: #f8f9fa;
    --color-border: #dee2e6;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: var(--color-bg);
    padding: 20px;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    background: white;
    padding: 40px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    border-radius: 8px;
}

.header {
    border-bottom: 3px solid var(--color-primary);
    padding-bottom: 20px;
    margin-bottom: 30px;
}

.header h1 {
    color: var(--color-primary);
    font-size: 2.5em;
    margin-bottom: 10px;
}

.header .metadata {
    color: var(--color-secondary);
    font-size: 0.9em;
}

.header .metadata span {
    margin-right: 20px;
}

.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin-bottom: 40px;
}

.summary-card {
    background: var(--color-bg);
    padding: 20px;
    border-radius: 8px;
    border-left: 4px solid var(--color-primary);
}

.summary-card.critical { border-left-color: var(--color-critical); }
.summary-card.high { border-left-color: var(--color-high); }
.summary-card.medium { border-left-color: var(--color-medium); }
.summary-card.kev { border-left-color: var(--color-kev); }

.summary-card .number {
    font-size: 2.5em;
    font-weight: bold;
    color: var(--color-primary);
}

.summary-card.critical .number { color: var(--color-critical); }
.summary-card.high .number { color: var(--color-high); }
.summary-card.medium .number { color: var(--color-medium); }
.summary-card.kev .number { color: var(--color-kev); }

.summary-card .label {
    font-size: 0.9em;
    color: var(--color-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.ai-section {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 30px;
    border-radius: 8px;
    margin-bottom: 40px;
}

.ai-section h2 {
    margin-bottom: 20px;
    font-size: 1.8em;
}

.ai-section .content {
    background: rgba(255, 255, 255, 0.1);
    padding: 20px;
    border-radius: 4px;
    white-space: pre-wrap;
    font-family: 'Courier New', monospace;
    font-size: 0.95em;
    line-height: 1.8;
}

.vulnerabilities-section h2 {
    color: var(--color-primary);
    border-bottom: 2px solid var(--color-border);
    padding-bottom: 10px;
    margin-bottom: 30px;
}

.vuln-card {
    border: 1px solid var(--color-border);
    border-radius: 8px;
    margin-bottom: 20px;
    overflow: hidden;
}

.vuln-card-header {
    background: var(--color-bg);
    padding: 15px 20px;
    border-left: 5px solid var(--color-secondary);
}

.vuln-card-header.critical {
    border-left-color: var(--color-critical);
    background: rgba(220, 53, 69, 0.1);
}

.vuln-card-header.high {
    border-left-color: var(--color-high);
    background: rgba(253, 126, 20, 0.1);
}

.vuln-card-header.medium {
    border-left-color: var(--color-medium);
    background: rgba(255, 193, 7, 0.1);
}

.vuln-card-header.low {
    border-left-color: var(--color-low);
    background: rgba(40, 167, 69, 0.1);
}

.vuln-card-title {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
}

.vuln-card-title h3 {
    margin: 0;
    color: #333;
    font-size: 1.3em;
}

.vuln-badges {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}

.badge {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 0.85em;
    font-weight: bold;
    text-transform: uppercase;
}

.badge.critical { background: var(--color-critical); color: white; }
.badge.high { background: var(--color-high); color: white; }
.badge.medium { background: var(--color-medium); color: #333; }
.badge.low { background: var(--color-low); color: white; }
.badge.kev { background: var(--color-kev); color: white; }
.badge.shodan { background: #dc143c; color: white; }
.badge.greynoise { background: #ff6b6b; color: white; }

.vuln-card-body {
    padding: 20px;
}

.vuln-meta {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin-bottom: 20px;
}

.vuln-meta-item {
    display: flex;
    flex-direction: column;
}

.vuln-meta-label {
    font-size: 0.8em;
    color: var(--color-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 5px;
}

.vuln-meta-value {
    font-weight: 600;
    color: #333;
}

.vuln-description {
    background: var(--color-bg);
    padding: 15px;
    border-radius: 4px;
    margin-bottom: 15px;
}

.vuln-threat-intel {
    background: #fff3cd;
    border-left: 4px solid #ffc107;
    padding: 15px;
    margin-top: 15px;
}

.vuln-threat-intel h4 {
    margin-bottom: 10px;
    color: #856404;
}

.threat-detail {
    margin-bottom: 8px;
    font-size: 0.95em;
}

.footer {
    margin-top: 40px;
    padding-top: 20px;
    border-top: 2px solid var(--color-border);
    text-align: center;
    color: var(--color-secondary);
    font-size: 0.9em;
}

@media print {
    body { background: white; padding: 0; }
    .container { box-shadow: none; padding: 20px; }
    .vuln-card { page-break-inside: avoid; }
}
`)

	cssPath := reportDir + "/styles.css"
	return os.WriteFile(cssPath, cssContent, 0644)
}
