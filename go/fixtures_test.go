package graylog

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// fixture is a request/response pair recorded from the real Graylog 7.0.16
// container (testdata/fixtures, recorded by the prep verify harness).
type fixture struct {
	Function string `json:"function"`
	Case     string `json:"case"`
	Request  struct {
		Method string          `json:"method"`
		Path   string          `json:"path"`
		Body   json.RawMessage `json:"body"`
	} `json:"request"`
	Response struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    json.RawMessage   `json:"body"`
	} `json:"response"`
}

func loadFixture(t *testing.T, name string) fixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "fixtures", name+".json"))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	var f fixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return f
}

// body returns the recorded response body bytes (JSON strings are unquoted).
func (f fixture) body() []byte {
	raw := f.Response.Body
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []byte(s)
	}
	return raw
}

// write serves the recorded response.
func (f fixture) write(w http.ResponseWriter) {
	for k, v := range f.Response.Headers {
		if k != "content-length" {
			w.Header().Set(k, v)
		}
	}
	status := f.Response.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(f.body())
}

// fixtureRoutes serves fixtures by "METHOD /path" (query ignored); unknown
// routes answer 404 with a Graylog ApiError.
func fixtureRoutes(t *testing.T, routes map[string]string) func(w http.ResponseWriter, r *http.Request, n int) {
	t.Helper()
	loaded := map[string]fixture{}
	for route, name := range routes {
		loaded[route] = loadFixture(t, name)
	}
	return func(w http.ResponseWriter, r *http.Request, _ int) {
		if f, ok := loaded[r.Method+" "+r.URL.Path]; ok {
			f.write(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"type":"ApiError","message":"no route ` + r.Method + " " + r.URL.Path + `"}`))
	}
}

// decodeBody decodes a recorded request's JSON body.
func decodeBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	return m
}
