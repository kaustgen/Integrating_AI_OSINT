// Author: Kaleb Austgen
// Date Created: 12/29/25
// Purpose: Type definitions for LLM package

package llm

// OpenAIRequest represents the request structure for OpenAI Chat Completions API
type OpenAIRequest struct {
	Model     string          `json:"model"`
	Messages  []OpenAIMessage `json:"messages"`
	MaxTokens int             `json:"max_tokens"`
}

// OpenAIMessage represents a message in the conversation
type OpenAIMessage struct {
	Role    string `json:"role"`    // "system", "user", or "assistant"
	Content string `json:"content"` // Message content
}

// OpenAIResponse represents the response from OpenAI API
type OpenAIResponse struct {
	Choices []struct {
		Message OpenAIMessage `json:"message"`
	} `json:"choices"`
	Error *OpenAIError `json:"error,omitempty"`
}

// OpenAIError represents error details from OpenAI API
type OpenAIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}
