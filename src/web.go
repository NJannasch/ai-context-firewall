package main

import (
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

type WebServer struct {
	store     *Store
	dashboard *template.Template
	config    *template.Template
	mux       *http.ServeMux
}

func NewWebServer(store *Store) (*WebServer, error) {
	dashboardTmpl, err := template.ParseFS(templateFS, "templates/layout.html", "templates/dashboard.html")
	if err != nil {
		return nil, err
	}
	configTmpl, err := template.ParseFS(templateFS, "templates/layout.html", "templates/config.html")
	if err != nil {
		return nil, err
	}

	ws := &WebServer{
		store:     store,
		dashboard: dashboardTmpl,
		config:    configTmpl,
		mux:       http.NewServeMux(),
	}

	ws.mux.HandleFunc("/", ws.handleDashboard)
	ws.mux.HandleFunc("/config", ws.handleConfig)
	ws.mux.HandleFunc("/api/logs", ws.handleAPILogs)
	ws.mux.HandleFunc("/api/logs/delete", ws.handleAPIDeleteLog)
	ws.mux.HandleFunc("/api/logs/clear", ws.handleAPIClearLogs)
	ws.mux.HandleFunc("/api/config", ws.handleAPIConfig)
	ws.mux.HandleFunc("/api/models", ws.handleAPIModels)

	return ws, nil
}

func (ws *WebServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ws.mux.ServeHTTP(w, r)
}

func (ws *WebServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data := struct {
		Title  string
		Nav    string
		Config Config
		Logs   []InspectionLog
	}{
		Title:  "Dashboard",
		Nav:    "dashboard",
		Config: ws.store.GetConfig(),
		Logs:   ws.store.GetLogs(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	ws.dashboard.ExecuteTemplate(w, "layout.html", data)
}

func (ws *WebServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	saved := false

	if r.Method == http.MethodPost {
		r.ParseForm()

		threshold, _ := strconv.Atoi(r.FormValue("threshold"))
		if threshold < 0 {
			threshold = 0
		}
		if threshold > 100 {
			threshold = 100
		}

		cfg := Config{
			BackendURL:     r.FormValue("backend_url"),
			InspectorURL:   r.FormValue("inspector_url"),
			InspectorModel: r.FormValue("inspector_model"),
			Threshold:      threshold,
			ActivePrompt:   r.FormValue("active_prompt"),
			CustomPrompt:   r.FormValue("custom_prompt"),
		}

		ws.store.SetConfig(cfg)
		saved = true
	}

	data := struct {
		Title   string
		Nav     string
		Config  Config
		Saved   bool
		Presets map[string]string
	}{
		Title:   "Configuration",
		Nav:     "config",
		Config:  ws.store.GetConfig(),
		Saved:   saved,
		Presets: presetPrompts,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	ws.config.ExecuteTemplate(w, "layout.html", data)
}

func (ws *WebServer) handleAPILogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ws.store.GetLogs())
}

func (ws *WebServer) handleAPIDeleteLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	ws.store.DeleteLog(id)
	w.WriteHeader(http.StatusNoContent)
}

func (ws *WebServer) handleAPIClearLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ws.store.ClearLogs()
	w.WriteHeader(http.StatusNoContent)
}

func (ws *WebServer) handleAPIConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ws.store.GetConfig())
		return
	}

	if r.Method == http.MethodPost {
		var cfg Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := ws.store.SetConfig(cfg); err != nil {
			http.Error(w, "failed to save config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
		return
	}

	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (ws *WebServer) handleAPIModels(w http.ResponseWriter, r *http.Request) {
	// Fetch from the specified URL, or fall back to inspector URL
	ollamaURL := r.URL.Query().Get("url")
	if ollamaURL == "" {
		ollamaURL = ws.store.GetConfig().InspectorURL
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ollamaURL+"/api/tags", nil)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"models": []any{}, "error": "invalid URL"})
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"models": []any{}, "error": "cannot reach Ollama at " + ollamaURL})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"models": []any{}, "error": "unexpected response from Ollama"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}
