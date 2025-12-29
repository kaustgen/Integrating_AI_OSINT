// Author: Kaleb Austgen
// Date Created: 12/29/25
// Purpose: OpenAI API client for vulnerability analysis

package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// LLMClient handles OpenAI API interactions
type LLMClient struct {
	APIKey     string
	Model      string
	httpClient *http.Client
}

// NewLLMClient creates an OpenAI client
// API Key should be set in .env as OPENAI_API_KEY
// Returns nil if API key is not configured
func NewLLMClient() *LLMClient {
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		return nil
	}

	return &LLMClient{
		APIKey: apiKey,
		Model:  "gpt-4o-mini", // Cost-effective model ($0.15/1M input tokens, $0.60/1M output)
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// GenerateRiskAssessment sends prompt to OpenAI and returns the risk assessment
//
// Parameters:
//   - prompt: The formatted vulnerability data prompt
//
// Returns:
//   - Risk assessment text (2 paragraphs)
//   - Error if API call fails
//
// Cost: ~$0.001 per call (typical prompt = 2000 tokens, response = 500 tokens)
func (c *LLMClient) GenerateRiskAssessment(prompt string) (string, error) {
	// Construct API request
	reqBody := OpenAIRequest{
		Model: c.Model,
		Messages: []OpenAIMessage{
			{
				Role:    "user",
				Content: prompt,
			},
		},
		MaxTokens: 1200,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Make HTTP POST to OpenAI
	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Handle HTTP errors
	if resp.StatusCode != 200 {
		var errResp OpenAIResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != nil {
			return "", fmt.Errorf("OpenAI API error: %s", errResp.Error.Message)
		}
		return "", fmt.Errorf("OpenAI API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse successful response
	var apiResp OpenAIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(apiResp.Choices) == 0 {
		return "", fmt.Errorf("no response from OpenAI")
	}

	return apiResp.Choices[0].Message.Content, nil
}
