/* 	Author: Kaleb Austgen
Date Created: 9-19-25
Last Modified: 9-19-25
Purpose:
Ingestion from the National Vulnerability Database -> takes a date filter on CVSS and reads it into a struct

Will later feed this into regex that takes an inventory alongside keyword heuristics and an LLM to determine relevant CVEs to our inventory
Will also be coupled with several hardware OSINT systems to find vulnerabilities for those systems automatically
*/

package NVD_API_handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
)

// Struct defining the structure of the json - essentially structs of structs to define the lists within the json dict
type CVEResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`    // or the actual JSON path
			LastModified string `json:"lastModified"` // same
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSv40 []struct {
					Source   string `json:"source"`
					Type     string `json:"type"`
					CVSSData struct {
						Version      string  `json:"version"`
						VectorString string  `json:"vectorString"`
						BaseScore    float32 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					}
				} `json:"cvssMetricV40"`
			} `json:"metrics"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Vulnerable      bool   `json:"vulnerable"`
						Criteria        string `json:"criteria"`
						MatchCriteriaID string `json:"matchCriteriaId"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
		} `json:"cve"`
		// You can define more fields as needed: metrics, references, etc.
	} `json:"vulnerabilities"`
}

// Flattened CVE response struct for more processing later
type FlattenedCVE struct {
	ID           string
	Published    string
	LastModified string
	Descriptions []string
	Nodes        []CPEMatch
	CVSSData     []CVSSData
}

type CPEMatch struct {
	Vulnerable      bool
	Criteria        string
	MatchCriteriaID string
}

type CVSSv40 struct {
	Source   string
	Type     string
	CVSSData CVSSData
}

type CVSSData struct {
	Source       string
	Type         string
	Version      string
	VectorString string
	BaseScore    float32
	BaseSeverity string
}

// Func to print out/retrieve the data in the CVE according to our struct
func retrieveStructJSON(cveResp CVEResponse) []FlattenedCVE {
	var result []FlattenedCVE

	// For the vulnerabilities struct
	for _, v := range cveResp.Vulnerabilities {
		f := FlattenedCVE{
			ID:           v.CVE.ID,
			Published:    v.CVE.Published,
			LastModified: v.CVE.LastModified,
		}

		// For the descriptions struct
		for _, desc := range v.CVE.Descriptions {
			f.Descriptions = append(f.Descriptions, desc.Value)
		}

		// For the metrics struct
		for _, cvss := range v.CVE.Metrics.CVSSv40 {
			f.CVSSData = append(f.CVSSData, CVSSData{
				Source:       cvss.Source,
				Type:         cvss.Type,
				Version:      cvss.CVSSData.Version,
				VectorString: cvss.CVSSData.VectorString,
				BaseScore:    cvss.CVSSData.BaseScore,
				BaseSeverity: cvss.CVSSData.BaseSeverity,
			})
		}
		// }

		// For the configureations
		for _, cpe := range v.CVE.Configurations {
			for _, node := range cpe.Nodes {
				for _, m := range node.CPEMatch {
					f.Nodes = append(f.Nodes, CPEMatch{
						Vulnerable:      m.Vulnerable,
						Criteria:        m.Criteria,
						MatchCriteriaID: m.MatchCriteriaID,
					})
				}
			}
		}

		result = append(result, f)
	}
	return result
}

// Takes a start time, end time, total CVE and then allows users to use an API
// Then calls retrieveStructJSON and returns a JSON that can be parsed by Go
func GetCVEs(start string, end string, count string, api ...bool) []FlattenedCVE {
	// Default is no API
	api_select := false

	// If the user didn't input anything we default to false, otherwise we use the api
	if len(api) > 0 {
		api_select = api[0]
	}

	// Retriev items from the API
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=%s&pubEndDate=%s&resultsPerPage=%s", start, end, count)

	// Handle the response error
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}

	// If there is an API_key
	if api_select {
		// Get the API from the .env
		err := godotenv.Load()
		if err != nil {
			log.Fatal("Error loading .env file")
		}

		// Read the API key
		NVD_API := os.Getenv("NVD_API")

		if NVD_API == "" {
			log.Fatal("NVD_API is not set in .env")
		}
		req.Header.Add("apiKey", NVD_API)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	// Close the response body after the function
	defer resp.Body.Close()

	// If there is an error, print it out
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Unexpected status: %d\n", resp.StatusCode)
		bodyBytes, _ := io.ReadAll(resp.Body)
		fmt.Println("Body:", string(bodyBytes))
		panic("Error Code")
	}

	// Put the reponse into our struct
	var cveResp CVEResponse
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&cveResp); err != nil {
		panic(err)
	}

	flatCVE := retrieveStructJSON(cveResp)

	return flatCVE
}

// CVE's must be coupled with CPEs
// CPE - one to CVE - many relationship
// Must maintain a database of CPEs (inventory) and have a tag in the CVE table telling which CPE it belongs to
// Once we determine which CVEs belong to which CPEs and that automation is completed we can start analysis
// The analysis will leverage LLMs to generate a report which will be sent to an admin
// Report will consist of - changes today regarding our security posture (new CVEs etc.)
// If I have the time, will consist of an OSINT leveraging Shodan etc. that will grab hardware and tell you what things are vulnerable instantly
// Attempting to automate vulnerability research
func PrintCVEs() {

	// Vars for the NVD CVE API
	var start string = time.Now().AddDate(0, 0, -7).Format("2006-01-02T15:04:05.000")
	var end string = time.Now().Format("2006-01-02T15:04:05.000")
	var count string = "2000"

	// Create a struct with certain fields from the CVSS
	var flatCVE []FlattenedCVE = GetCVEs(start, end, count)

	// How to access all the values in flatCVE
	for _, v := range flatCVE { // List of vulnerabilities
		fmt.Println(v.ID)           // Specific ID
		fmt.Println(v.Published)    // Published Date
		fmt.Println(v.LastModified) // Mod. date (important)
		fmt.Println(v.Descriptions) // Description (important)

		for _, nodes := range v.Nodes { // List of affected nodes
			fmt.Println(nodes.Vulnerable)      // True/False bool
			fmt.Println(nodes.Criteria)        // Criteria - cpe value
			fmt.Println(nodes.MatchCriteriaID) // UUID for the cpe, not useful outside NVD

		}

		for _, cvss := range v.CVSSData { //CVSS4.0 raw data
			fmt.Println(cvss.Source)       // Source (usually an email alert)
			fmt.Println(cvss.Type)         // Primary or secondary
			fmt.Println(cvss.Version)      // 4.0
			fmt.Println(cvss.VectorString) // The CVSS alert string - can be parsed for all informatio we want
			fmt.Println(cvss.BaseScore)    // Base score calculated using the 4.0 algorithm
			fmt.Println(cvss.BaseSeverity) // Severity level based on the basescore, low, medium, high, critical
		}
		fmt.Println()
	}
}
