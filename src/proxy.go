package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type Proxy struct {
	store     *Store
	inspector *Inspector
	client    *http.Client
}

func NewProxy(store *Store, inspector *Inspector) *Proxy {
	return &Proxy{
		store:     store,
		inspector: inspector,
		client:    &http.Client{},
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/chat":
		p.handleChat(w, r)
	case "/api/generate":
		p.handleGenerate(w, r)
	default:
		// Pass through all other requests (e.g. /api/tags, /api/show)
		_, _ = p.forward(w, r, nil)
	}
}

func (p *Proxy) handleChat(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	var req struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Extract all message content for inspection
	var parts []string
	fromTool := false
	for _, msg := range req.Messages {
		if msg.Role == "user" || msg.Role == "system" {
			parts = append(parts, msg.Content)
		} else if msg.Role == "tool" {
			parts = append(parts, msg.Content)
			fromTool = true
		}
	}
	content := strings.Join(parts, "\n\n")

	p.inspectAndForward(w, r, body, content, req.Model, fromTool)
}

func (p *Proxy) handleGenerate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	var req struct {
		Model  string `json:"model"`
		Prompt string `json:"prompt"`
		System string `json:"system"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	content := req.Prompt
	if req.System != "" {
		content = req.System + "\n\n" + content
	}

	p.inspectAndForward(w, r, body, content, req.Model, false)
}

func (p *Proxy) inspectAndForward(w http.ResponseWriter, r *http.Request, body []byte, content string, model string, fromTool bool) {
	totalStart := time.Now()
	cfg := p.store.GetConfig()

	inspectStart := time.Now()
	result, err := p.inspector.Inspect(content)
	inspectMs := time.Since(inspectStart).Milliseconds()

	if err != nil {
		log.Printf("inspection error (%dms): %v", inspectMs, err)
		logEntry := InspectionLog{
			Content:        truncate(content, 100),
			RiskLevel:      "unknown",
			Score:          -1,
			Explanation:    fmt.Sprintf("inspection failed: %v", err),
			Action:         "forwarded (inspection error)",
			InspectorModel: cfg.InspectorModel,
			BackendModel:   model,
			FromTool:       fromTool,
			InspectTimeMs:  inspectMs,
		}
		p.store.AddLog(logEntry)
		_, _ = p.forward(w, r, body)
		logEntry.TotalTimeMs = time.Since(totalStart).Milliseconds()
		return
	}

	action := "forwarded"
	if result.Score >= cfg.Threshold {
		action = "blocked"
	}

	logEntry := InspectionLog{
		Content:             truncate(content, 100),
		RiskLevel:           result.RiskLevel,
		Score:               result.Score,
		Explanation:         result.Explanation,
		Action:              action,
		InspectorModel:      cfg.InspectorModel,
		BackendModel:        model,
		FromTool:            fromTool,
		InspectPromptTokens: result.PromptTokens,
		InspectEvalTokens:   result.EvalTokens,
		InspectTimeMs:       inspectMs,
	}

	if action == "blocked" {
		logEntry.TotalTimeMs = time.Since(totalStart).Milliseconds()
		p.store.AddLog(logEntry)
		log.Printf("BLOCKED request (score %d > threshold %d, inspect %dms, total %dms): %s",
			result.Score, cfg.Threshold, inspectMs, logEntry.TotalTimeMs, truncate(content, 80))
		p.respondBlocked(w, r, result, model)
		return
	}

	backendStart := time.Now()
	backendPrompt, backendEval := p.forward(w, r, body)
	backendMs := time.Since(backendStart).Milliseconds()

	logEntry.BackendPromptTokens = backendPrompt
	logEntry.BackendEvalTokens = backendEval
	logEntry.BackendTimeMs = backendMs
	logEntry.TotalTimeMs = time.Since(totalStart).Milliseconds()
	p.store.AddLog(logEntry)

	log.Printf("FORWARDED request (score %d, inspect %dms, backend %dms, total %dms): %s",
		result.Score, inspectMs, backendMs, logEntry.TotalTimeMs, truncate(content, 80))
}

func (p *Proxy) respondBlocked(w http.ResponseWriter, r *http.Request, result *InspectionResult, model string) {
	// Check if the original request was for /api/chat or /api/generate to return the right format
	msg := fmt.Sprintf("[BLOCKED by AI Context Firewall] Risk score: %d/100 (%s). %s", result.Score, result.RiskLevel, result.Explanation)

	if r.URL.Path == "/api/chat" {
		resp := map[string]any{
			"model":      model,
			"created_at": "0001-01-01T00:00:00Z",
			"message": map[string]string{
				"role":    "assistant",
				"content": msg,
			},
			"done":        true,
			"done_reason": "blocked",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	} else {
		resp := map[string]any{
			"model":       model,
			"created_at":  "0001-01-01T00:00:00Z",
			"response":    msg,
			"done":        true,
			"done_reason": "blocked",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func extractTokens(data []byte) (prompt, eval int) {
	var chunk struct {
		PromptEvalCount int `json:"prompt_eval_count"`
		EvalCount       int `json:"eval_count"`
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		json.Unmarshal(line, &chunk)
	}
	return chunk.PromptEvalCount, chunk.EvalCount
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte) (int, int) {
	cfg := p.store.GetConfig()
	targetURL := cfg.BackendURL + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	} else {
		bodyReader = r.Body
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bodyReader)
	if err != nil {
		http.Error(w, "failed to create proxy request", http.StatusInternalServerError)
		return 0, 0
	}

	// Copy headers
	for key, values := range r.Header {
		for _, v := range values {
			proxyReq.Header.Add(key, v)
		}
	}

	resp, err := p.client.Do(proxyReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("backend error: %v", err), http.StatusBadGateway)
		return 0, 0
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Tee response so we can extract token counts while streaming
	var buf bytes.Buffer
	io.Copy(w, io.TeeReader(resp.Body, &buf))
	return extractTokens(buf.Bytes())
}


func truncate(s string, maxLen int) string {
	// Replace newlines for log readability
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
