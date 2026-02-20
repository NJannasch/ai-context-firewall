package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type Config struct {
	BackendURL     string `json:"backend_url"`
	InspectorURL   string `json:"inspector_url"`
	InspectorModel string `json:"inspector_model"`
	Threshold      int    `json:"threshold"`
	ActivePrompt   string `json:"active_prompt"`
	CustomPrompt   string `json:"custom_prompt"`
}

type InspectionLog struct {
	ID            int           `json:"id"`
	Timestamp     time.Time     `json:"timestamp"`
	Content       string        `json:"content"`
	RiskLevel     string        `json:"risk_level"`
	Score         int           `json:"score"`
	Explanation   string        `json:"explanation"`
	Action        string        `json:"action"`
	Model         string        `json:"model"`
	InspectTimeMs int64         `json:"inspect_time_ms"`
	BackendTimeMs int64         `json:"backend_time_ms"`
	TotalTimeMs   int64         `json:"total_time_ms"`
}

const maxLogs = 200

type Store struct {
	mu         sync.RWMutex
	logs       []InspectionLog
	nextID     int
	config     Config
	configPath string
}

func NewStore(configPath string) (*Store, error) {
	s := &Store{
		configPath: configPath,
		nextID:     1,
		config: Config{
			BackendURL:     "http://localhost:11434",
			InspectorURL:   "http://localhost:11434",
			InspectorModel: "llama3.2:3b",
			Threshold:      70,
			ActivePrompt:   "standard",
		},
	}

	data, err := os.ReadFile(configPath)
	if err == nil {
		if err := json.Unmarshal(data, &s.config); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func (s *Store) GetConfig() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

func (s *Store) SetConfig(cfg Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = cfg

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.configPath, data, 0644)
}

func (s *Store) AddLog(log InspectionLog) {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.ID = s.nextID
	s.nextID++
	log.Timestamp = time.Now()

	s.logs = append(s.logs, log)
	if len(s.logs) > maxLogs {
		s.logs = s.logs[len(s.logs)-maxLogs:]
	}
}

func (s *Store) GetLogs() []InspectionLog {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return in reverse chronological order
	result := make([]InspectionLog, len(s.logs))
	for i, l := range s.logs {
		result[len(s.logs)-1-i] = l
	}
	return result
}

func (s *Store) DeleteLog(id int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, l := range s.logs {
		if l.ID == id {
			s.logs = append(s.logs[:i], s.logs[i+1:]...)
			return true
		}
	}
	return false
}

func (s *Store) ClearLogs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = nil
}
