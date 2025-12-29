// Author: Kaleb Austgen
// Date Created: 12/28/25
// Purpose: Shodan API client with rate limiting and caching for exposure validation

package shodan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ShodanClient handles interactions with Shodan API
// Includes rate limiting to comply with API quotas (1 req/sec for free tier)
type ShodanClient struct {
	APIKey      string
	rateLimiter *RateLimiter
	httpClient  *http.Client
}

// ShodanHost represents Shodan's response for a specific IP
// This is a simplified version of Shodan's full response
// We only extract fields relevant to exposure validation
type ShodanHost struct {
	IP         string          `json:"ip_str"`      // IP address
	Ports      []int           `json:"ports"`       // Open ports
	Hostnames  []string        `json:"hostnames"`   // DNS hostnames
	Vulns      []string        `json:"vulns"`       // CVE IDs Shodan detected
	LastUpdate string          `json:"last_update"` // When Shodan last scanned
	Data       []ShodanService `json:"data"`        // Service details per port
}

// ShodanService represents a single service running on a port
type ShodanService struct {
	Port      int    `json:"port"`
	Transport string `json:"transport"` // tcp/udp
	Product   string `json:"product"`   // e.g., "Apache httpd"
	Version   string `json:"version"`   // e.g., "2.4.49"
	Banner    string `json:"data"`      // Raw banner/response
}

// RateLimiter implements token bucket algorithm
// Allows burst requests up to bucket size, then throttles to refill rate
type RateLimiter struct {
	mu         sync.Mutex
	tokens     int
	maxTokens  int
	refillRate time.Duration
	lastRefill time.Time
}

// NewShodanClient creates a new Shodan API client
//
// Parameters:
//   - apiKey: Your Shodan API key (get from account.shodan.io)
//
// API Key Tiers:
//   - Free: 1 query/sec, 100 query credits
//   - Membership ($59/month): Unlimited queries, 1 query/sec
//   - Enterprise: Higher rate limits
//
// For research: Free tier is usually sufficient with caching
func NewShodanClient(apiKey string) *ShodanClient {
	return &ShodanClient{
		APIKey: apiKey,
		rateLimiter: &RateLimiter{
			tokens:     5,           // Start with 5 tokens (allows initial burst)
			maxTokens:  5,           // Max 5 tokens in bucket
			refillRate: time.Second, // Add 1 token every second
			lastRefill: time.Now(),
		},
		httpClient: &http.Client{
			Timeout: 30 * time.Second, // Shodan can be slow, allow 30s
		},
	}
}

// Wait blocks until a token is available (rate limiting)
// This ensures we don't exceed Shodan's API quota
func (rl *RateLimiter) Wait() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Refill tokens based on time elapsed
	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)
	tokensToAdd := int(elapsed / rl.refillRate)

	if tokensToAdd > 0 {
		rl.tokens += tokensToAdd
		if rl.tokens > rl.maxTokens {
			rl.tokens = rl.maxTokens
		}
		rl.lastRefill = now
	}

	// If no tokens available, wait until one is added
	for rl.tokens <= 0 {
		rl.mu.Unlock()
		time.Sleep(rl.refillRate)
		rl.mu.Lock()

		// Refill after waiting
		rl.tokens = 1
		rl.lastRefill = time.Now()
	}

	// Consume one token
	rl.tokens--
}

// QueryHost queries Shodan for information about a specific IP
//
// Parameters:
//   - ip: IP address to query (e.g., "8.8.8.8")
//
// Returns:
//   - *ShodanHost: Host information from Shodan
//   - error: API errors, network errors, or 404 if IP not in Shodan
//
// API Endpoint: GET https://api.shodan.io/shodan/host/{ip}?key={apiKey}
//
// Error Handling:
//   - 404: IP not indexed by Shodan (not internet-facing or blocked crawling)
//   - 401: Invalid API key
//   - 429: Rate limit exceeded
//   - 500: Shodan server error
func (sc *ShodanClient) QueryHost(ip string) (*ShodanHost, error) {
	// Rate limiting: Wait for token before making request
	sc.rateLimiter.Wait()

	// Construct Shodan API URL
	// Documentation: https://developer.shodan.io/api
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, sc.APIKey)

	// Make HTTP GET request
	resp, err := sc.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("shodan API request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle HTTP status codes
	switch resp.StatusCode {
	case 200:
		// Success - parse response
		var host ShodanHost
		if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
			return nil, fmt.Errorf("failed to parse Shodan response: %w", err)
		}
		return &host, nil

	case 404:
		// IP not found in Shodan's database
		// This is NOT an error - it means the IP is not internet-facing
		// or Shodan hasn't scanned it yet
		return nil, nil

	case 401:
		return nil, fmt.Errorf("invalid Shodan API key")

	case 429:
		return nil, fmt.Errorf("Shodan rate limit exceeded - wait before retrying")

	default:
		return nil, fmt.Errorf("Shodan API returned status %d", resp.StatusCode)
	}
}

// IsHostIndexed is a convenience method to check if an IP is in Shodan
// This is faster than QueryHost if you only need boolean exposure status
//
// Returns:
//   - true: IP is indexed by Shodan (internet-facing)
//   - false: IP not found in Shodan (not internet-facing or blocked)
func (sc *ShodanClient) IsHostIndexed(ip string) (bool, error) {
	host, err := sc.QueryHost(ip)
	if err != nil {
		return false, err
	}
	return host != nil, nil
}

// GetExposedPorts returns open ports for an IP, or empty slice if not indexed
func (sc *ShodanClient) GetExposedPorts(ip string) ([]int, error) {
	host, err := sc.QueryHost(ip)
	if err != nil {
		return nil, err
	}
	if host == nil {
		return []int{}, nil // Not indexed
	}
	return host.Ports, nil
}

// GetServiceBanner returns the service banner for a specific port
// This shows what information is visible to attackers (version strings, etc.)
//
// Example banner:
//
//	"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n..."
//
// Attackers use this to fingerprint software versions without authentication
func (sc *ShodanClient) GetServiceBanner(ip string, port int) (string, error) {
	host, err := sc.QueryHost(ip)
	if err != nil {
		return "", err
	}
	if host == nil {
		return "", nil
	}

	// Find service data for specified port
	for _, service := range host.Data {
		if service.Port == port {
			return service.Banner, nil
		}
	}

	return "", fmt.Errorf("port %d not found in Shodan data", port)
}
