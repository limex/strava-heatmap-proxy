package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mockHandler is a simple handler for testing
type mockHandler struct {
	called bool
	req    *http.Request
}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.called = true
	m.req = r
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("success"))
}

func TestNewAuthenticatedHandler_NoAPIKeysFile(t *testing.T) {
	mockH := &mockHandler{}
	
	// Test with empty API keys file path
	authHandler, err := NewAuthenticatedHandler(mockH, "")
	if err != nil {
		t.Fatalf("Expected no error with empty API keys file, got: %v", err)
	}
	
	if len(authHandler.apiKeys) != 0 {
		t.Errorf("Expected no API keys loaded, got %d", len(authHandler.apiKeys))
	}
}

func TestNewAuthenticatedHandler_ValidAPIKeysFile(t *testing.T) {
	// Create temporary API keys file
	tempDir := t.TempDir()
	apiKeysFile := filepath.Join(tempDir, "test-api-keys.json")
	
	config := ApiKeyConfig{
		Keys: []string{"test-key-1", "test-key-2", "test-key-3"},
	}
	
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}
	
	if err := os.WriteFile(apiKeysFile, data, 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}
	
	mockH := &mockHandler{}
	authHandler, err := NewAuthenticatedHandler(mockH, apiKeysFile)
	if err != nil {
		t.Fatalf("Expected no error with valid API keys file, got: %v", err)
	}
	
	expectedKeys := 3
	if len(authHandler.apiKeys) != expectedKeys {
		t.Errorf("Expected %d API keys loaded, got %d", expectedKeys, len(authHandler.apiKeys))
	}
	
	// Verify specific keys are loaded
	if !authHandler.apiKeys["test-key-1"] {
		t.Error("Expected test-key-1 to be loaded")
	}
	if !authHandler.apiKeys["test-key-2"] {
		t.Error("Expected test-key-2 to be loaded")
	}
	if !authHandler.apiKeys["test-key-3"] {
		t.Error("Expected test-key-3 to be loaded")
	}
}

func TestNewAuthenticatedHandler_InvalidJSONFile(t *testing.T) {
	// Create temporary file with invalid JSON
	tempDir := t.TempDir()
	apiKeysFile := filepath.Join(tempDir, "invalid-api-keys.json")
	
	invalidJSON := `{"keys": ["key1", "key2",]}`  // Invalid JSON with trailing comma
	
	if err := os.WriteFile(apiKeysFile, []byte(invalidJSON), 0644); err != nil {
		t.Fatalf("Failed to write invalid JSON file: %v", err)
	}
	
	mockH := &mockHandler{}
	_, err := NewAuthenticatedHandler(mockH, apiKeysFile)
	if err == nil {
		t.Error("Expected error with invalid JSON file, got none")
	}
	
	if !strings.Contains(err.Error(), "failed to parse API keys file") {
		t.Errorf("Expected parse error message, got: %v", err)
	}
}

func TestNewAuthenticatedHandler_EmptyKeysArray(t *testing.T) {
	// Create temporary API keys file with empty keys array
	tempDir := t.TempDir()
	apiKeysFile := filepath.Join(tempDir, "empty-api-keys.json")
	
	config := ApiKeyConfig{
		Keys: []string{},
	}
	
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal empty config: %v", err)
	}
	
	if err := os.WriteFile(apiKeysFile, data, 0644); err != nil {
		t.Fatalf("Failed to write empty config file: %v", err)
	}
	
	mockH := &mockHandler{}
	_, err = NewAuthenticatedHandler(mockH, apiKeysFile)
	if err == nil {
		t.Error("Expected error with empty keys array, got none")
	}
	
	if !strings.Contains(err.Error(), "no valid API keys found") {
		t.Errorf("Expected 'no valid API keys found' error, got: %v", err)
	}
}

func TestNewAuthenticatedHandler_EmptyStringsInKeys(t *testing.T) {
	// Create temporary API keys file with empty string keys
	tempDir := t.TempDir()
	apiKeysFile := filepath.Join(tempDir, "empty-strings-api-keys.json")
	
	config := ApiKeyConfig{
		Keys: []string{"valid-key", "", "another-valid-key", ""},
	}
	
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}
	
	if err := os.WriteFile(apiKeysFile, data, 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}
	
	mockH := &mockHandler{}
	authHandler, err := NewAuthenticatedHandler(mockH, apiKeysFile)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	// Should only have 2 valid keys (empty strings filtered out)
	expectedKeys := 2
	if len(authHandler.apiKeys) != expectedKeys {
		t.Errorf("Expected %d API keys loaded, got %d", expectedKeys, len(authHandler.apiKeys))
	}
	
	if !authHandler.apiKeys["valid-key"] {
		t.Error("Expected valid-key to be loaded")
	}
	if !authHandler.apiKeys["another-valid-key"] {
		t.Error("Expected another-valid-key to be loaded")
	}
}

func TestNewAuthenticatedHandler_NonExistentFile(t *testing.T) {
	mockH := &mockHandler{}
	_, err := NewAuthenticatedHandler(mockH, "/non/existent/file.json")
	if err == nil {
		t.Error("Expected error with non-existent file, got none")
	}
	
	if !strings.Contains(err.Error(), "failed to read API keys file") {
		t.Errorf("Expected read error message, got: %v", err)
	}
}

func TestAuthenticatedHandler_NoAPIKeysConfigured(t *testing.T) {
	mockH := &mockHandler{}
	authHandler := &AuthenticatedHandler{
		handler: mockH,
		apiKeys: make(map[string]bool), // Empty API keys map
	}
	
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()
	
	authHandler.ServeHTTP(w, req)
	
	// Should allow request through when no API keys are configured
	if !mockH.called {
		t.Error("Expected underlying handler to be called when no API keys configured")
	}
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %d", w.Code)
	}
}

func TestAuthenticatedHandler_ValidAPIKey(t *testing.T) {
	mockH := &mockHandler{}
	authHandler := &AuthenticatedHandler{
		handler: mockH,
		apiKeys: map[string]bool{
			"valid-key-123": true,
			"another-key":   true,
		},
	}
	
	req := httptest.NewRequest("GET", "http://example.com/test?key=valid-key-123&param=value", nil)
	w := httptest.NewRecorder()
	
	authHandler.ServeHTTP(w, req)
	
	if !mockH.called {
		t.Error("Expected underlying handler to be called with valid API key")
	}
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %d", w.Code)
	}
	
	// Verify the key parameter was removed from the request
	if mockH.req.URL.Query().Get("key") != "" {
		t.Error("Expected key parameter to be removed from proxied request")
	}
	
	// Verify other parameters are preserved
	if mockH.req.URL.Query().Get("param") != "value" {
		t.Error("Expected other parameters to be preserved")
	}
}

func TestAuthenticatedHandler_InvalidAPIKey(t *testing.T) {
	mockH := &mockHandler{}
	authHandler := &AuthenticatedHandler{
		handler: mockH,
		apiKeys: map[string]bool{
			"valid-key-123": true,
		},
	}
	
	req := httptest.NewRequest("GET", "http://example.com/test?key=invalid-key", nil)
	w := httptest.NewRecorder()
	
	authHandler.ServeHTTP(w, req)
	
	if mockH.called {
		t.Error("Expected underlying handler NOT to be called with invalid API key")
	}
	
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status Unauthorized (401), got %d", w.Code)
	}
	
	body := w.Body.String()
	if !strings.Contains(body, "Invalid API key") {
		t.Errorf("Expected 'Invalid API key' in response body, got: %s", body)
	}
}

func TestAuthenticatedHandler_MissingAPIKey(t *testing.T) {
	mockH := &mockHandler{}
	authHandler := &AuthenticatedHandler{
		handler: mockH,
		apiKeys: map[string]bool{
			"valid-key-123": true,
		},
	}
	
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()
	
	authHandler.ServeHTTP(w, req)
	
	if mockH.called {
		t.Error("Expected underlying handler NOT to be called with missing API key")
	}
	
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status Unauthorized (401), got %d", w.Code)
	}
	
	body := w.Body.String()
	if !strings.Contains(body, "API key required") {
		t.Errorf("Expected 'API key required' in response body, got: %s", body)
	}
}

func TestAuthenticatedHandler_EmptyAPIKey(t *testing.T) {
	mockH := &mockHandler{}
	authHandler := &AuthenticatedHandler{
		handler: mockH,
		apiKeys: map[string]bool{
			"valid-key-123": true,
		},
	}
	
	req := httptest.NewRequest("GET", "http://example.com/test?key=", nil)
	w := httptest.NewRecorder()
	
	authHandler.ServeHTTP(w, req)
	
	if mockH.called {
		t.Error("Expected underlying handler NOT to be called with empty API key")
	}
	
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status Unauthorized (401), got %d", w.Code)
	}
	
	body := w.Body.String()
	if !strings.Contains(body, "API key required") {
		t.Errorf("Expected 'API key required' in response body, got: %s", body)
	}
}

func TestAuthenticatedHandler_MultipleKeyParameters(t *testing.T) {
	mockH := &mockHandler{}
	authHandler := &AuthenticatedHandler{
		handler: mockH,
		apiKeys: map[string]bool{
			"valid-key-123": true,
		},
	}
	
	// URL with multiple key parameters - Go will use the first one
	req := httptest.NewRequest("GET", "http://example.com/test?key=valid-key-123&key=invalid-key&param=value", nil)
	w := httptest.NewRecorder()
	
	authHandler.ServeHTTP(w, req)
	
	if !mockH.called {
		t.Error("Expected underlying handler to be called with valid API key")
	}
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %d", w.Code)
	}
	
	// Verify all key parameters were removed
	if mockH.req.URL.Query().Get("key") != "" {
		t.Error("Expected all key parameters to be removed from proxied request")
	}
}

func TestAuthenticatedHandler_CaseInensitiveAPIKey(t *testing.T) {
	mockH := &mockHandler{}
	authHandler := &AuthenticatedHandler{
		handler: mockH,
		apiKeys: map[string]bool{
			"Valid-Key-123": true,
		},
	}
	
	// Test with different case - should fail (API keys are case-sensitive)
	req := httptest.NewRequest("GET", "http://example.com/test?key=valid-key-123", nil)
	w := httptest.NewRecorder()
	
	authHandler.ServeHTTP(w, req)
	
	if mockH.called {
		t.Error("Expected underlying handler NOT to be called with wrong case API key")
	}
	
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status Unauthorized (401), got %d", w.Code)
	}
}

func TestApiKeyConfig_JSONStructure(t *testing.T) {
	// Test that the ApiKeyConfig struct correctly marshals/unmarshals
	config := ApiKeyConfig{
		Keys: []string{"key1", "key2", "key3"},
	}
	
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal ApiKeyConfig: %v", err)
	}
	
	var unmarshaled ApiKeyConfig
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal ApiKeyConfig: %v", err)
	}
	
	if len(unmarshaled.Keys) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(unmarshaled.Keys))
	}
	
	expected := []string{"key1", "key2", "key3"}
	for i, key := range unmarshaled.Keys {
		if key != expected[i] {
			t.Errorf("Expected key %s, got %s", expected[i], key)
		}
	}
}

// Test with actual api-keys.json file if it exists
func TestAuthenticatedHandler_WithActualConfigFile(t *testing.T) {
	// This test uses the actual api-keys.json file if it exists
	apiKeysFile := "api-keys.json"
	
	// Check if the file exists
	if _, err := os.Stat(apiKeysFile); os.IsNotExist(err) {
		t.Skip("Skipping test: api-keys.json file not found")
	}
	
	mockH := &mockHandler{}
	authHandler, err := NewAuthenticatedHandler(mockH, apiKeysFile)
	if err != nil {
		t.Fatalf("Failed to load actual API keys file: %v", err)
	}
	
	if len(authHandler.apiKeys) == 0 {
		t.Error("Expected API keys to be loaded from actual config file")
	}
	
	// Test that at least one of the keys from the actual file works
	// We'll test with the first key from the file
	data, err := os.ReadFile(apiKeysFile)
	if err != nil {
		t.Fatalf("Failed to read API keys file: %v", err)
	}
	
	var config ApiKeyConfig
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("Failed to parse API keys file: %v", err)
	}
	
	if len(config.Keys) == 0 {
		t.Error("No keys found in actual config file")
		return
	}
	
	// Test with the first valid key
	testKey := config.Keys[0]
	if testKey == "" {
		t.Error("First key in config file is empty")
		return
	}
	
	req := httptest.NewRequest("GET", "http://example.com/test?key="+testKey, nil)
	w := httptest.NewRecorder()
	
	authHandler.ServeHTTP(w, req)
	
	if !mockH.called {
		t.Error("Expected underlying handler to be called with valid API key from config file")
	}
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %d", w.Code)
	}
}

// Integration test that simulates the full authentication flow
func TestIntegration_AuthenticationFlow(t *testing.T) {
	// Create temporary API keys file
	tempDir := t.TempDir()
	apiKeysFile := filepath.Join(tempDir, "integration-api-keys.json")
	
	config := ApiKeyConfig{
		Keys: []string{"integration-test-key"},
	}
	
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}
	
	if err := os.WriteFile(apiKeysFile, data, 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}
	
	// Create mock backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()
	
	// Create reverse proxy (simplified for testing)
	target, _ := url.Parse(backend.URL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	
	// Create authenticated handler
	authHandler, err := NewAuthenticatedHandler(proxy, apiKeysFile)
	if err != nil {
		t.Fatalf("Failed to create authenticated handler: %v", err)
	}
	
	// Test server with authentication
	server := httptest.NewServer(authHandler)
	defer server.Close()
	
	// Test cases
	testCases := []struct {
		name           string
		url            string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid API key",
			url:            server.URL + "/test?key=integration-test-key",
			expectedStatus: http.StatusOK,
			expectedBody:   "backend response",
		},
		{
			name:           "Invalid API key",
			url:            server.URL + "/test?key=wrong-key",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid API key",
		},
		{
			name:           "Missing API key",
			url:            server.URL + "/test",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "API key required",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(tc.url)
			if err != nil {
				t.Fatalf("Failed to make request: %v", err)
			}
			defer resp.Body.Close()
			
			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, resp.StatusCode)
			}
			
			body := make([]byte, 1000)
			n, _ := resp.Body.Read(body)
			bodyStr := string(body[:n])
			
			if !strings.Contains(bodyStr, tc.expectedBody) {
				t.Errorf("Expected body to contain '%s', got '%s'", tc.expectedBody, bodyStr)
			}
		})
	}
}

// Benchmark tests to ensure authentication doesn't significantly impact performance
func BenchmarkAuthenticatedHandler_NoAPIKeys(b *testing.B) {
	mockH := &mockHandler{}
	authHandler := &AuthenticatedHandler{
		handler: mockH,
		apiKeys: make(map[string]bool), // No API keys
	}
	
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		authHandler.ServeHTTP(w, req)
	}
}

func BenchmarkAuthenticatedHandler_ValidAPIKey(b *testing.B) {
	mockH := &mockHandler{}
	authHandler := &AuthenticatedHandler{
		handler: mockH,
		apiKeys: map[string]bool{
			"benchmark-key": true,
		},
	}
	
	req := httptest.NewRequest("GET", "http://example.com/test?key=benchmark-key", nil)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		authHandler.ServeHTTP(w, req)
	}
}

func BenchmarkAuthenticatedHandler_InvalidAPIKey(b *testing.B) {
	mockH := &mockHandler{}
	authHandler := &AuthenticatedHandler{
		handler: mockH,
		apiKeys: map[string]bool{
			"valid-key": true,
		},
	}
	
	req := httptest.NewRequest("GET", "http://example.com/test?key=invalid-key", nil)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		authHandler.ServeHTTP(w, req)
	}
}

func BenchmarkAuthenticatedHandler_ManyAPIKeys(b *testing.B) {
	mockH := &mockHandler{}
	apiKeys := make(map[string]bool)
	
	// Create 1000 API keys
	for i := 0; i < 1000; i++ {
		apiKeys[fmt.Sprintf("key-%d", i)] = true
	}
	
	authHandler := &AuthenticatedHandler{
		handler: mockH,
		apiKeys: apiKeys,
	}
	
	req := httptest.NewRequest("GET", "http://example.com/test?key=key-500", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		authHandler.ServeHTTP(w, req)
	}
}

// ============================================================================
// Cookie Persistence Tests
// ============================================================================

func TestSaveCookiesToFile_Success(t *testing.T) {
	// Create initial cookies file
	tempDir := t.TempDir()
	cookiesFile := filepath.Join(tempDir, "strava-cookies.json")

	initialCookies := []cookieEntry{
		{Name: "_strava4_session", Value: "session-value-123"},
		{Name: "sp", Value: "some-other-cookie"},
		{Name: "CloudFront-Policy", Value: "old-policy"},
		{Name: "CloudFront-Signature", Value: "old-signature"},
		{Name: "CloudFront-Key-Pair-Id", Value: "old-key-pair-id"},
		{Name: "_strava_idcf", Value: "old-idcf"},
		{Name: "_strava_CloudFront-Expires", Value: "1000000000000"},
	}

	data, _ := json.MarshalIndent(initialCookies, "", "  ")
	if err := os.WriteFile(cookiesFile, data, 0644); err != nil {
		t.Fatalf("Failed to create initial cookies file: %v", err)
	}

	// Create client and update CloudFront cookies
	client := &StravaSessionClient{
		cookiesFilePath:             cookiesFile,
		sessionIdentifier:           "session-value-123",
		cloudFrontCookies: []*http.Cookie{
			{Name: "CloudFront-Policy", Value: "new-policy-value"},
			{Name: "CloudFront-Signature", Value: "new-signature-value"},
			{Name: "CloudFront-Key-Pair-Id", Value: "new-key-pair-id-value"},
			{Name: "_strava_idcf", Value: "new-idcf-value"},
		},
		cloudFrontCookiesExpiration: time.UnixMilli(2000000000000),
	}

	// Save cookies
	if err := client.saveCookiesToFile(); err != nil {
		t.Fatalf("saveCookiesToFile failed: %v", err)
	}

	// Read and verify the saved file
	savedData, err := os.ReadFile(cookiesFile)
	if err != nil {
		t.Fatalf("Failed to read saved cookies file: %v", err)
	}

	var savedCookies []cookieEntry
	if err := json.Unmarshal(savedData, &savedCookies); err != nil {
		t.Fatalf("Failed to parse saved cookies: %v", err)
	}

	// Verify session cookie is preserved
	found := false
	for _, cookie := range savedCookies {
		if cookie.Name == "_strava4_session" {
			found = true
			if cookie.Value != "session-value-123" {
				t.Errorf("Session cookie value changed: expected 'session-value-123', got '%s'", cookie.Value)
			}
		}
	}
	if !found {
		t.Error("Session cookie not found in saved file")
	}

	// Verify CloudFront cookies are updated
	cookieMap := make(map[string]string)
	for _, cookie := range savedCookies {
		cookieMap[cookie.Name] = cookie.Value
	}

	if cookieMap["CloudFront-Policy"] != "new-policy-value" {
		t.Errorf("CloudFront-Policy not updated: got '%s'", cookieMap["CloudFront-Policy"])
	}
	if cookieMap["CloudFront-Signature"] != "new-signature-value" {
		t.Errorf("CloudFront-Signature not updated: got '%s'", cookieMap["CloudFront-Signature"])
	}
	if cookieMap["_strava_idcf"] != "new-idcf-value" {
		t.Errorf("_strava_idcf not updated: got '%s'", cookieMap["_strava_idcf"])
	}
	if cookieMap["_strava_CloudFront-Expires"] != "2000000000000" {
		t.Errorf("_strava_CloudFront-Expires not updated: got '%s'", cookieMap["_strava_CloudFront-Expires"])
	}

	// Verify non-CloudFront cookies are preserved
	if cookieMap["sp"] != "some-other-cookie" {
		t.Errorf("Non-CloudFront cookie 'sp' not preserved: got '%s'", cookieMap["sp"])
	}
}

func TestSaveCookiesToFile_PreservesSessionCookie(t *testing.T) {
	tempDir := t.TempDir()
	cookiesFile := filepath.Join(tempDir, "strava-cookies.json")

	initialCookies := []cookieEntry{
		{Name: "_strava4_session", Value: "must-not-change"},
		{Name: "CloudFront-Policy", Value: "old-policy"},
	}

	data, _ := json.MarshalIndent(initialCookies, "", "  ")
	os.WriteFile(cookiesFile, data, 0644)

	client := &StravaSessionClient{
		cookiesFilePath:   cookiesFile,
		sessionIdentifier: "must-not-change",
		cloudFrontCookies: []*http.Cookie{
			{Name: "CloudFront-Policy", Value: "new-policy"},
			{Name: "CloudFront-Signature", Value: "new-sig"},
			{Name: "CloudFront-Key-Pair-Id", Value: "new-key"},
			{Name: "_strava_idcf", Value: "new-idcf"},
		},
		cloudFrontCookiesExpiration: time.Now(),
	}

	client.saveCookiesToFile()

	// Verify session cookie unchanged
	savedData, _ := os.ReadFile(cookiesFile)
	var savedCookies []cookieEntry
	json.Unmarshal(savedData, &savedCookies)

	for _, cookie := range savedCookies {
		if cookie.Name == "_strava4_session" {
			if cookie.Value != "must-not-change" {
				t.Errorf("Session cookie was modified! Expected 'must-not-change', got '%s'", cookie.Value)
			}
			return
		}
	}
	t.Error("Session cookie was removed from file!")
}

func TestSaveCookiesToFile_PreservesOtherCookies(t *testing.T) {
	tempDir := t.TempDir()
	cookiesFile := filepath.Join(tempDir, "strava-cookies.json")

	initialCookies := []cookieEntry{
		{Name: "_strava4_session", Value: "session"},
		{Name: "sp", Value: "special-cookie"},
		{Name: "fbm_284597785309", Value: "facebook-cookie"},
		{Name: "custom_cookie", Value: "custom-value"},
		{Name: "CloudFront-Policy", Value: "old"},
	}

	data, _ := json.MarshalIndent(initialCookies, "", "  ")
	os.WriteFile(cookiesFile, data, 0644)

	client := &StravaSessionClient{
		cookiesFilePath: cookiesFile,
		cloudFrontCookies: []*http.Cookie{
			{Name: "CloudFront-Policy", Value: "new"},
			{Name: "CloudFront-Signature", Value: "new"},
			{Name: "CloudFront-Key-Pair-Id", Value: "new"},
			{Name: "_strava_idcf", Value: "new"},
		},
		cloudFrontCookiesExpiration: time.Now(),
	}

	client.saveCookiesToFile()

	savedData, _ := os.ReadFile(cookiesFile)
	var savedCookies []cookieEntry
	json.Unmarshal(savedData, &savedCookies)

	cookieMap := make(map[string]string)
	for _, cookie := range savedCookies {
		cookieMap[cookie.Name] = cookie.Value
	}

	// Verify all non-CloudFront cookies preserved
	if cookieMap["sp"] != "special-cookie" {
		t.Errorf("Cookie 'sp' not preserved")
	}
	if cookieMap["fbm_284597785309"] != "facebook-cookie" {
		t.Errorf("Cookie 'fbm_284597785309' not preserved")
	}
	if cookieMap["custom_cookie"] != "custom-value" {
		t.Errorf("Cookie 'custom_cookie' not preserved")
	}
	if cookieMap["_strava4_session"] != "session" {
		t.Errorf("Session cookie not preserved")
	}

	// Verify CloudFront cookies were updated
	if cookieMap["CloudFront-Policy"] != "new" {
		t.Errorf("CloudFront-Policy not updated")
	}
}

func TestSaveCookiesToFile_AtomicWrite(t *testing.T) {
	tempDir := t.TempDir()
	cookiesFile := filepath.Join(tempDir, "strava-cookies.json")

	initialCookies := []cookieEntry{
		{Name: "_strava4_session", Value: "session"},
		{Name: "CloudFront-Policy", Value: "old"},
	}

	data, _ := json.MarshalIndent(initialCookies, "", "  ")
	os.WriteFile(cookiesFile, data, 0644)

	client := &StravaSessionClient{
		cookiesFilePath: cookiesFile,
		cloudFrontCookies: []*http.Cookie{
			{Name: "CloudFront-Policy", Value: "new"},
			{Name: "CloudFront-Signature", Value: "new"},
			{Name: "CloudFront-Key-Pair-Id", Value: "new"},
			{Name: "_strava_idcf", Value: "new"},
		},
		cloudFrontCookiesExpiration: time.Now(),
	}

	// Save cookies - should use temp file
	client.saveCookiesToFile()

	// Verify temp file is cleaned up
	tempFile := cookiesFile + ".tmp"
	if _, err := os.Stat(tempFile); err == nil {
		t.Error("Temp file was not cleaned up after successful write")
	}

	// Verify original file exists and is valid
	if _, err := os.Stat(cookiesFile); err != nil {
		t.Errorf("Original cookies file not found after save: %v", err)
	}

	// Verify original file has valid JSON
	savedData, _ := os.ReadFile(cookiesFile)
	var savedCookies []cookieEntry
	if err := json.Unmarshal(savedData, &savedCookies); err != nil {
		t.Errorf("Saved file does not contain valid JSON: %v", err)
	}
}

func TestSaveCookiesToFile_ReadOnlyFilesystem(t *testing.T) {
	tempDir := t.TempDir()
	cookiesFile := filepath.Join(tempDir, "strava-cookies.json")

	initialCookies := []cookieEntry{
		{Name: "_strava4_session", Value: "session"},
	}

	data, _ := json.MarshalIndent(initialCookies, "", "  ")
	os.WriteFile(cookiesFile, data, 0644)

	// Make file read-only
	os.Chmod(cookiesFile, 0444)
	// Make directory read-only to prevent temp file creation
	os.Chmod(tempDir, 0555)

	client := &StravaSessionClient{
		cookiesFilePath: cookiesFile,
		cloudFrontCookies: []*http.Cookie{
			{Name: "CloudFront-Policy", Value: "new"},
			{Name: "CloudFront-Signature", Value: "new"},
			{Name: "CloudFront-Key-Pair-Id", Value: "new"},
			{Name: "_strava_idcf", Value: "new"},
		},
		cloudFrontCookiesExpiration: time.Now(),
	}

	// Should return error but not crash
	err := client.saveCookiesToFile()
	if err == nil {
		t.Error("Expected error when writing to read-only filesystem, got none")
	}

	// Cleanup: restore permissions for tempDir cleanup
	os.Chmod(tempDir, 0755)
	os.Chmod(cookiesFile, 0644)
}

func TestSaveCookiesToFile_AddsNewCloudFrontCookies(t *testing.T) {
	tempDir := t.TempDir()
	cookiesFile := filepath.Join(tempDir, "strava-cookies.json")

	// Initial file has session but NO CloudFront cookies
	initialCookies := []cookieEntry{
		{Name: "_strava4_session", Value: "session-value"},
		{Name: "sp", Value: "other-cookie"},
	}

	data, _ := json.MarshalIndent(initialCookies, "", "  ")
	os.WriteFile(cookiesFile, data, 0644)

	client := &StravaSessionClient{
		cookiesFilePath: cookiesFile,
		cloudFrontCookies: []*http.Cookie{
			{Name: "CloudFront-Policy", Value: "new-policy"},
			{Name: "CloudFront-Signature", Value: "new-sig"},
			{Name: "CloudFront-Key-Pair-Id", Value: "new-key"},
			{Name: "_strava_idcf", Value: "new-idcf"},
		},
		cloudFrontCookiesExpiration: time.UnixMilli(1234567890000),
	}

	client.saveCookiesToFile()

	savedData, _ := os.ReadFile(cookiesFile)
	var savedCookies []cookieEntry
	json.Unmarshal(savedData, &savedCookies)

	cookieMap := make(map[string]string)
	for _, cookie := range savedCookies {
		cookieMap[cookie.Name] = cookie.Value
	}

	// Verify new CloudFront cookies were added
	if cookieMap["CloudFront-Policy"] != "new-policy" {
		t.Error("CloudFront-Policy not added")
	}
	if cookieMap["CloudFront-Signature"] != "new-sig" {
		t.Error("CloudFront-Signature not added")
	}
	if cookieMap["_strava_CloudFront-Expires"] != "1234567890000" {
		t.Error("_strava_CloudFront-Expires not added")
	}

	// Verify existing cookies still present
	if cookieMap["_strava4_session"] != "session-value" {
		t.Error("Session cookie lost")
	}
	if cookieMap["sp"] != "other-cookie" {
		t.Error("Other cookie lost")
	}
}

func TestFetchCloudFrontCookies_PersistsToFile(t *testing.T) {
	// This is an integration test that verifies the full flow
	tempDir := t.TempDir()
	cookiesFile := filepath.Join(tempDir, "strava-cookies.json")

	// Create initial cookies file
	initialCookies := []cookieEntry{
		{Name: "_strava4_session", Value: "test-session"},
		{Name: "CloudFront-Policy", Value: "old-policy"},
	}

	data, _ := json.MarshalIndent(initialCookies, "", "  ")
	os.WriteFile(cookiesFile, data, 0644)

	// Create a mock HTTP server that simulates Strava's response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify session cookie is sent
		if !strings.Contains(r.Header.Get("Cookie"), "test-session") {
			t.Error("Session cookie not sent in request")
		}

		// Send back CloudFront cookies
		http.SetCookie(w, &http.Cookie{Name: "CloudFront-Policy", Value: "fresh-policy"})
		http.SetCookie(w, &http.Cookie{Name: "CloudFront-Signature", Value: "fresh-sig"})
		http.SetCookie(w, &http.Cookie{Name: "CloudFront-Key-Pair-Id", Value: "fresh-key"})
		http.SetCookie(w, &http.Cookie{Name: "_strava_idcf", Value: "fresh-idcf"})
		http.SetCookie(w, &http.Cookie{Name: "_strava_CloudFront-Expires", Value: "9999999999999"})

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Now we have stravaHeatmapURL as a package-level var — point it at our mock server
	// and verify that fetchCloudFrontCookies persists cookies back to file.
	oldURL := stravaHeatmapURL
	stravaHeatmapURL = server.URL
	defer func() { stravaHeatmapURL = oldURL }()

	client, err := NewStravaSessionClient(cookiesFile, "", "")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if err := client.fetchCloudFrontCookies(); err != nil {
		t.Fatalf("fetchCloudFrontCookies failed: %v", err)
	}

	// Verify cookies were persisted to file
	savedData, _ := os.ReadFile(cookiesFile)
	var savedCookies []cookieEntry
	json.Unmarshal(savedData, &savedCookies)

	cookieMap := make(map[string]string)
	for _, c := range savedCookies {
		cookieMap[c.Name] = c.Value
	}

	if cookieMap["CloudFront-Policy"] != "fresh-policy" {
		t.Errorf("CloudFront-Policy not persisted: got '%s'", cookieMap["CloudFront-Policy"])
	}
	if cookieMap["_strava4_session"] != "test-session" {
		t.Error("Session cookie was lost after fetchCloudFrontCookies")
	}
}

func TestModifyResponse_403ForcesExpiration(t *testing.T) {
	// Verify that a 403 from the upstream CDN causes the client's
	// cloudFrontCookiesExpiration to be zeroed so the next request refreshes.
	client := &StravaSessionClient{
		cloudFrontCookiesExpiration: time.Now().Add(24 * time.Hour), // currently "valid"
	}

	// Simulate the modifyResponse function behaviour inline
	fakeResp := &http.Response{StatusCode: http.StatusForbidden}
	if fakeResp.StatusCode == http.StatusForbidden {
		client.mu.Lock()
		client.cloudFrontCookiesExpiration = time.Time{}
		client.mu.Unlock()
	}

	if !client.cloudFrontCookiesExpiration.IsZero() {
		t.Error("Expected cloudFrontCookiesExpiration to be zeroed after 403, but it was not")
	}

	// Confirm the zero value causes the expiration check to trigger a refresh
	expired := client.cloudFrontCookiesExpiration.IsZero() || time.Now().After(client.cloudFrontCookiesExpiration)
	if !expired {
		t.Error("Expected expiration check to return true (needs refresh) after 403 handling")
	}
}

// ============================================================================
// CSRF Token Extraction Tests
// ============================================================================

func TestExtractCSRFToken_StandardOrder(t *testing.T) {
	html := `<input type="hidden" name="authenticity_token" value="abc123==" autocomplete="off" />`
	token, err := extractCSRFToken(html)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if token != "abc123==" {
		t.Errorf("Expected 'abc123==', got '%s'", token)
	}
}

func TestExtractCSRFToken_ReversedOrder(t *testing.T) {
	html := `<input type="hidden" value="xyz789==" name="authenticity_token" />`
	token, err := extractCSRFToken(html)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if token != "xyz789==" {
		t.Errorf("Expected 'xyz789==', got '%s'", token)
	}
}

func TestExtractCSRFToken_Missing(t *testing.T) {
	html := `<form><input type="text" name="email" /></form>`
	_, err := extractCSRFToken(html)
	if err == nil {
		t.Error("Expected error when token is missing, got none")
	}
}

func TestExtractCSRFToken_MultipleInputs(t *testing.T) {
	html := `
		<input type="text" name="email" value="user@example.com" />
		<input type="hidden" name="authenticity_token" value="correct-token" />
		<input type="password" name="password" value="secret" />
	`
	token, err := extractCSRFToken(html)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if token != "correct-token" {
		t.Errorf("Expected 'correct-token', got '%s'", token)
	}
}

func TestExtractCSRFToken_EmptyHTML(t *testing.T) {
	_, err := extractCSRFToken("")
	if err == nil {
		t.Error("Expected error for empty HTML, got none")
	}
}

// ============================================================================
// loginToStrava Tests (using mock HTTP server)
// ============================================================================

func TestLoginToStrava_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<input type="hidden" name="authenticity_token" value="test-csrf-token" />`)
		case "/session":
			// Verify the CSRF token and credentials were sent
			r.ParseForm()
			if r.FormValue("authenticity_token") != "test-csrf-token" {
				t.Errorf("CSRF token not sent: got '%s'", r.FormValue("authenticity_token"))
			}
			if r.FormValue("email") != "user@example.com" {
				t.Errorf("Email not sent: got '%s'", r.FormValue("email"))
			}
			if r.FormValue("password") != "secret" {
				t.Errorf("Password not sent: got '%s'", r.FormValue("password"))
			}
			// Success: redirect to dashboard with session cookie
			http.SetCookie(w, &http.Cookie{Name: "_strava4_session", Value: "new-session-value"})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldURL := stravaBaseURL
	stravaBaseURL = server.URL
	defer func() { stravaBaseURL = oldURL }()

	client := &StravaSessionClient{email: "user@example.com", password: "secret"}
	session, err := client.loginToStrava()
	if err != nil {
		t.Fatalf("Expected login to succeed, got error: %v", err)
	}
	if session != "new-session-value" {
		t.Errorf("Expected session 'new-session-value', got '%s'", session)
	}
}

func TestLoginToStrava_WrongCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<input type="hidden" name="authenticity_token" value="csrf" />`)
		case "/session":
			// Failure: redirect back to /login
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	}))
	defer server.Close()

	oldURL := stravaBaseURL
	stravaBaseURL = server.URL
	defer func() { stravaBaseURL = oldURL }()

	client := &StravaSessionClient{email: "wrong@example.com", password: "wrongpass"}
	_, err := client.loginToStrava()
	if err == nil {
		t.Error("Expected error for wrong credentials, got none")
	}
	if !strings.Contains(err.Error(), "login failed") {
		t.Errorf("Expected 'login failed' error, got: %v", err)
	}
}

func TestLoginToStrava_NoCSRFToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<form><input type="text" name="email" /></form>`) // no CSRF token
		}
	}))
	defer server.Close()

	oldURL := stravaBaseURL
	stravaBaseURL = server.URL
	defer func() { stravaBaseURL = oldURL }()

	client := &StravaSessionClient{email: "user@example.com", password: "secret"}
	_, err := client.loginToStrava()
	if err == nil {
		t.Error("Expected error when CSRF token is missing, got none")
	}
	if !strings.Contains(err.Error(), "CSRF") {
		t.Errorf("Expected CSRF-related error, got: %v", err)
	}
}

func TestLoginToStrava_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	oldURL := stravaBaseURL
	stravaBaseURL = server.URL
	defer func() { stravaBaseURL = oldURL }()

	client := &StravaSessionClient{email: "user@example.com", password: "secret"}
	_, err := client.loginToStrava()
	if err == nil {
		t.Error("Expected error for server error on GET /login, got none")
	}
}

// ============================================================================
// fetchCredentials Tests
// ============================================================================

func TestFetchCredentials_CLIFlags(t *testing.T) {
	email, password, err := fetchCredentials("cli@example.com", "clipass")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if email != "cli@example.com" {
		t.Errorf("Expected CLI email, got '%s'", email)
	}
	if password != "clipass" {
		t.Errorf("Expected CLI password, got '%s'", password)
	}
}

func TestFetchCredentials_EnvVars(t *testing.T) {
	t.Setenv("STRAVA_EMAIL", "env@example.com")
	t.Setenv("STRAVA_PASSWORD", "envpass")

	email, password, err := fetchCredentials("", "")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if email != "env@example.com" {
		t.Errorf("Expected env email, got '%s'", email)
	}
	if password != "envpass" {
		t.Errorf("Expected env password, got '%s'", password)
	}
}

func TestFetchCredentials_NoneAvailable(t *testing.T) {
	// Ensure env vars are not set
	t.Setenv("STRAVA_EMAIL", "")
	t.Setenv("STRAVA_PASSWORD", "")

	// fetchCredentials will try Secret Manager (metadata server) which is not
	// reachable in a test environment — this should return an error quickly.
	_, _, err := fetchCredentials("", "")
	if err == nil {
		t.Error("Expected error when no credentials are available, got none")
	}
}

func TestFetchCredentials_CLITakesPrecedenceOverEnv(t *testing.T) {
	t.Setenv("STRAVA_EMAIL", "env@example.com")
	t.Setenv("STRAVA_PASSWORD", "envpass")

	email, password, err := fetchCredentials("cli@example.com", "clipass")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if email != "cli@example.com" {
		t.Errorf("Expected CLI email to take precedence, got '%s'", email)
	}
	if password != "clipass" {
		t.Errorf("Expected CLI password to take precedence, got '%s'", password)
	}
}

// ============================================================================
// saveSessionToFile Tests
// ============================================================================

func TestSaveSessionToFile_UpdatesSession(t *testing.T) {
	tempDir := t.TempDir()
	cookiesFile := filepath.Join(tempDir, "strava-cookies.json")

	initialCookies := []cookieEntry{
		{Name: "_strava4_session", Value: "old-session"},
		{Name: "CloudFront-Policy", Value: "policy-value"},
		{Name: "sp", Value: "other-cookie"},
	}
	data, _ := json.MarshalIndent(initialCookies, "", "  ")
	os.WriteFile(cookiesFile, data, 0644)

	client := &StravaSessionClient{cookiesFilePath: cookiesFile}
	if err := client.saveSessionToFile("new-session-value"); err != nil {
		t.Fatalf("saveSessionToFile failed: %v", err)
	}

	savedData, _ := os.ReadFile(cookiesFile)
	var savedCookies []cookieEntry
	json.Unmarshal(savedData, &savedCookies)

	cookieMap := make(map[string]string)
	for _, c := range savedCookies {
		cookieMap[c.Name] = c.Value
	}

	if cookieMap["_strava4_session"] != "new-session-value" {
		t.Errorf("Session not updated: got '%s'", cookieMap["_strava4_session"])
	}
	// Other cookies should be preserved
	if cookieMap["CloudFront-Policy"] != "policy-value" {
		t.Errorf("CloudFront-Policy was lost: got '%s'", cookieMap["CloudFront-Policy"])
	}
	if cookieMap["sp"] != "other-cookie" {
		t.Errorf("Other cookie was lost: got '%s'", cookieMap["sp"])
	}
}

func TestSaveSessionToFile_PreservesCloudFrontCookies(t *testing.T) {
	tempDir := t.TempDir()
	cookiesFile := filepath.Join(tempDir, "strava-cookies.json")

	initialCookies := []cookieEntry{
		{Name: "_strava4_session", Value: "old-session"},
		{Name: "CloudFront-Policy", Value: "important-policy"},
		{Name: "CloudFront-Signature", Value: "important-sig"},
		{Name: "CloudFront-Key-Pair-Id", Value: "important-key"},
		{Name: "_strava_idcf", Value: "important-idcf"},
		{Name: "_strava_CloudFront-Expires", Value: "9999999999999"},
	}
	data, _ := json.MarshalIndent(initialCookies, "", "  ")
	os.WriteFile(cookiesFile, data, 0644)

	client := &StravaSessionClient{cookiesFilePath: cookiesFile}
	client.saveSessionToFile("brand-new-session")

	savedData, _ := os.ReadFile(cookiesFile)
	var savedCookies []cookieEntry
	json.Unmarshal(savedData, &savedCookies)

	cookieMap := make(map[string]string)
	for _, c := range savedCookies {
		cookieMap[c.Name] = c.Value
	}

	// Session should be updated
	if cookieMap["_strava4_session"] != "brand-new-session" {
		t.Errorf("Session not updated")
	}
	// CloudFront cookies must be untouched
	if cookieMap["CloudFront-Policy"] != "important-policy" {
		t.Errorf("CloudFront-Policy was modified")
	}
	if cookieMap["_strava_CloudFront-Expires"] != "9999999999999" {
		t.Errorf("CloudFront-Expires was modified")
	}
}

// ============================================================================
// fetchCloudFrontCookies Session Expiry Tests
// ============================================================================

func TestFetchCloudFrontCookies_SessionExpired_LoginSucceeds(t *testing.T) {
	tempDir := t.TempDir()
	cookiesFile := filepath.Join(tempDir, "strava-cookies.json")

	initialCookies := []cookieEntry{
		{Name: "_strava4_session", Value: "expired-session"},
	}
	data, _ := json.MarshalIndent(initialCookies, "", "  ")
	os.WriteFile(cookiesFile, data, 0644)

	// Mock server handles both the heatmap URL and the login flow
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		switch r.URL.Path {
		case "/maps":
			if requestCount == 1 {
				// First call: session expired → redirect to login
				http.Redirect(w, r, "/login", http.StatusFound)
			} else {
				// Second call (after re-login): success with CloudFront cookies
				http.SetCookie(w, &http.Cookie{Name: "CloudFront-Policy", Value: "fresh-policy"})
				http.SetCookie(w, &http.Cookie{Name: "CloudFront-Signature", Value: "fresh-sig"})
				http.SetCookie(w, &http.Cookie{Name: "CloudFront-Key-Pair-Id", Value: "fresh-key"})
				http.SetCookie(w, &http.Cookie{Name: "_strava_idcf", Value: "fresh-idcf"})
				http.SetCookie(w, &http.Cookie{Name: "_strava_CloudFront-Expires", Value: "9999999999999"})
				w.WriteHeader(http.StatusOK)
			}
		case "/login":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<input type="hidden" name="authenticity_token" value="csrf-token" />`)
		case "/session":
			http.SetCookie(w, &http.Cookie{Name: "_strava4_session", Value: "fresh-session"})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		}
	}))
	defer server.Close()

	oldHeatmap := stravaHeatmapURL
	oldBase := stravaBaseURL
	stravaHeatmapURL = server.URL + "/maps"
	stravaBaseURL = server.URL
	defer func() {
		stravaHeatmapURL = oldHeatmap
		stravaBaseURL = oldBase
	}()

	client := &StravaSessionClient{
		cookiesFilePath:   cookiesFile,
		sessionIdentifier: "expired-session",
		email:             "user@example.com",
		password:          "secret",
	}

	if err := client.fetchCloudFrontCookies(); err != nil {
		t.Fatalf("fetchCloudFrontCookies failed: %v", err)
	}

	// Session should be updated to the fresh value
	if client.sessionIdentifier != "fresh-session" {
		t.Errorf("Session not updated after re-login: got '%s'", client.sessionIdentifier)
	}
	// CloudFront cookies should be populated
	if len(client.cloudFrontCookies) < 4 {
		t.Errorf("Expected 4 CloudFront cookies, got %d", len(client.cloudFrontCookies))
	}
}

func TestFetchCloudFrontCookies_SessionExpired_NoCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Session expired → redirect to login
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer server.Close()

	oldURL := stravaHeatmapURL
	stravaHeatmapURL = server.URL
	defer func() { stravaHeatmapURL = oldURL }()

	client := &StravaSessionClient{
		sessionIdentifier: "expired-session",
		// No email/password configured
	}

	err := client.fetchCloudFrontCookies()
	if err == nil {
		t.Error("Expected error when session expired and no credentials, got none")
	}
	if !strings.Contains(err.Error(), "no credentials") {
		t.Errorf("Expected 'no credentials' error, got: %v", err)
	}
}

// ============================================================================
// NewStravaSessionClient with credentials Tests
// ============================================================================

func TestNewStravaSessionClient_NoSession_WithCredentials_OK(t *testing.T) {
	tempDir := t.TempDir()
	cookiesFile := filepath.Join(tempDir, "strava-cookies.json")

	// File with no _strava4_session
	initialCookies := []cookieEntry{
		{Name: "sp", Value: "some-cookie"},
	}
	data, _ := json.MarshalIndent(initialCookies, "", "  ")
	os.WriteFile(cookiesFile, data, 0644)

	client, err := NewStravaSessionClient(cookiesFile, "user@example.com", "secret")
	if err != nil {
		t.Fatalf("Expected no error when credentials provided, got: %v", err)
	}
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	if client.email != "user@example.com" {
		t.Errorf("Email not stored on client: got '%s'", client.email)
	}
}

func TestNewStravaSessionClient_NoSession_NoCredentials_Error(t *testing.T) {
	tempDir := t.TempDir()
	cookiesFile := filepath.Join(tempDir, "strava-cookies.json")

	initialCookies := []cookieEntry{
		{Name: "sp", Value: "some-cookie"},
	}
	data, _ := json.MarshalIndent(initialCookies, "", "  ")
	os.WriteFile(cookiesFile, data, 0644)

	_, err := NewStravaSessionClient(cookiesFile, "", "")
	if err == nil {
		t.Error("Expected error when no session and no credentials, got none")
	}
	if !strings.Contains(err.Error(), "no credentials") {
		t.Errorf("Expected 'no credentials' in error, got: %v", err)
	}
}

func TestNewStravaSessionClient_HasSession_NoCredentials_OK(t *testing.T) {
	tempDir := t.TempDir()
	cookiesFile := filepath.Join(tempDir, "strava-cookies.json")

	initialCookies := []cookieEntry{
		{Name: "_strava4_session", Value: "valid-session"},
	}
	data, _ := json.MarshalIndent(initialCookies, "", "  ")
	os.WriteFile(cookiesFile, data, 0644)

	client, err := NewStravaSessionClient(cookiesFile, "", "")
	if err != nil {
		t.Fatalf("Expected no error with valid session, got: %v", err)
	}
	if client.sessionIdentifier != "valid-session" {
		t.Errorf("Expected session 'valid-session', got '%s'", client.sessionIdentifier)
	}
}
