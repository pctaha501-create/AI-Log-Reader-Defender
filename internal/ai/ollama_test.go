package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

func TestAnalyzeUsesLocalOllama(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" { t.Fatalf("unexpected path: %s", r.URL.Path) }
		var req chatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { t.Fatal(err) }
		if req.Model != "test-model" || req.Stream { t.Fatalf("unexpected request: %#v", req) }
		_ = json.NewEncoder(w).Encode(chatResponse{Message:chatMessage{Content:"No confirmed compromise; review the denied traffic."}})
	}))
	defer server.Close()
	events := []model.Event{{Message:"action=deny src=198.51.100.1"}}
	got, err := Analyze(context.Background(), server.URL, "test-model", events, model.Report{EventCount:1})
	if err != nil { t.Fatal(err) }
	if !strings.Contains(got, "No confirmed compromise") { t.Fatalf("unexpected analysis: %q", got) }
}

func TestAnalyzeRejectsRemoteEndpoint(t *testing.T) {
	_, err := Analyze(context.Background(), "https://example.com", "model", nil, model.Report{})
	if err == nil { t.Fatal("remote endpoint was accepted") }
}
