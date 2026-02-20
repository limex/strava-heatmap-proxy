package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Package-level URL variables — overridden in tests to point at mock servers.
var stravaBaseURL    = "https://www.strava.com"
var stravaHeatmapURL = "https://www.strava.com/maps"

// Compiled regexps for CSRF token extraction (both attribute orderings).
var csrfRe1 = regexp.MustCompile(`name="authenticity_token"[^>]*value="([^"]+)"`)
var csrfRe2 = regexp.MustCompile(`value="([^"]+)"[^>]*name="authenticity_token"`)

type Param struct {
	CookiesFile *string
	Port        *string
	Target      *string
	ApiKeysFile *string
	Email       *string
	Password    *string
}

func getParam() *Param {
	cookiesfile, err := os.UserHomeDir()
	if err != nil {
		cookiesfile = "cookies.json"
	} else {
		cookiesfile = path.Join(cookiesfile, ".config", "strava-heatmap-proxy", "strava-cookies.json")
	}

	apikeysfile, err := os.UserHomeDir()
	if err != nil {
		apikeysfile = "api-keys.json"
	} else {
		apikeysfile = path.Join(apikeysfile, ".config", "strava-heatmap-proxy", "api-keys.json")
	}

	param := &Param{
		CookiesFile: flag.String("cookies", cookiesfile, "Path to the cookies file"),
		Port:        flag.String("port", "8080", "Local proxy port"),
		Target:      flag.String("target", "https://content-a.strava.com/", "Heatmap provider URL"),
		ApiKeysFile: flag.String("apikeys", apikeysfile, "Path to the optional API keys file"),
		Email:       flag.String("email", "", "Strava login email (optional; falls back to STRAVA_EMAIL env var or Secret Manager)"),
		Password:    flag.String("password", "", "Strava login password (optional; falls back to STRAVA_PASSWORD env var or Secret Manager)"),
	}
	flag.Parse()
	return param
}

type cookieEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ApiKeyConfig struct {
	Keys []string `json:"keys"`
}

type AuthenticatedHandler struct {
	handler http.Handler
	apiKeys map[string]bool
}

func NewAuthenticatedHandler(handler http.Handler, apiKeysFile string) (*AuthenticatedHandler, error) {
	apiKeys := make(map[string]bool)

	if apiKeysFile != "" {
		data, err := os.ReadFile(apiKeysFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read API keys file: %w", err)
		}

		var config ApiKeyConfig
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse API keys file: %w", err)
		}

		for _, key := range config.Keys {
			if key != "" {
				apiKeys[key] = true
			}
		}

		if len(apiKeys) == 0 {
			return nil, fmt.Errorf("no valid API keys found in config file")
		}

		log.Printf("Loaded %d API keys from %s", len(apiKeys), apiKeysFile)
	}

	return &AuthenticatedHandler{
		handler: handler,
		apiKeys: apiKeys,
	}, nil
}

func (a *AuthenticatedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if API key authentication is required
	if len(a.apiKeys) == 0 {
		// No API keys configured, allow all requests
		a.handler.ServeHTTP(w, r)
		return
	}

	// Get API key from query parameter
	apiKey := r.URL.Query().Get("key")
	if apiKey == "" {
		http.Error(w, "API key required.", http.StatusUnauthorized)
		return
	}

	// Validate API key
	if !a.apiKeys[apiKey] {
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
		return
	}

	// Remove the key parameter before proxying to avoid leaking it
	values := r.URL.Query()
	values.Del("key")
	r.URL.RawQuery = values.Encode()

	// API key is valid, proceed with the request
	a.handler.ServeHTTP(w, r)
}

type StravaSessionClient struct {
	sessionIdentifier           string
	cloudFrontCookies           []*http.Cookie
	cloudFrontCookiesExpiration time.Time
	cookiesFilePath             string
	mu                          sync.Mutex
	refreshing                  atomic.Bool
	email                       string
	password                    string
}

func NewStravaSessionClient(cookiesFilePath, email, password string) (*StravaSessionClient, error) {
	file, err := os.Open(cookiesFilePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	var entries []cookieEntry
	if err := json.NewDecoder(file).Decode(&entries); err != nil {
		return nil, fmt.Errorf("error decoding json: %w", err)
	}

	client := &StravaSessionClient{
		cookiesFilePath: cookiesFilePath,
		email:           email,
		password:        password,
	}
	for _, entry := range entries {
		if entry.Name == "_strava4_session" {
			client.sessionIdentifier = entry.Value
			break
		}
	}
	// Session required unless credentials are provided for auto-login
	if client.sessionIdentifier == "" && (email == "" || password == "") {
		return nil, fmt.Errorf("_strava4_session not found in cookies file and no credentials for auto-login")
	}

	if err := client.readCloudFrontCookiesFromFile(entries); err != nil {
		log.Printf("No valid CloudFront cookies found in file: %v", err)
	}

	return client, nil
}

func (c *StravaSessionClient) readCloudFrontCookiesFromFile(entries []cookieEntry) error {
	var cookies []*http.Cookie
	var expiration int64

	for _, entry := range entries {
		switch entry.Name {
		case "CloudFront-Signature", "CloudFront-Policy", "CloudFront-Key-Pair-Id", "_strava_idcf":
			cookies = append(cookies, &http.Cookie{
				Name:  entry.Name,
				Value: entry.Value,
			})
		case "_strava_CloudFront-Expires":
			var err error
			expiration, err = strconv.ParseInt(entry.Value, 10, 64)
			if err != nil {
				log.Printf("Invalid timestamp value for %s: %s", entry.Name, entry.Value)
			}
		}
	}

	if len(cookies) < 4 {
		return fmt.Errorf("not all required CloudFront cookies found in file")
	}

	c.cloudFrontCookies = cookies
	if expiration != 0 {
		c.cloudFrontCookiesExpiration = time.UnixMilli(expiration)
		log.Printf("CloudFront cookies from file will expire at %s", c.cloudFrontCookiesExpiration)
	}

	return nil
}

// saveCookieOverridesToFile merges overrides into the JSON file atomically.
// Keys in the overrides map replace existing entries with the same name;
// keys not already in the file are appended. All other entries are preserved.
// Uses atomic write (temp file + rename) to prevent corruption.
func (c *StravaSessionClient) saveCookieOverridesToFile(overrides map[string]string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Read existing cookies from file
	data, err := os.ReadFile(c.cookiesFilePath)
	if err != nil {
		return fmt.Errorf("failed to read existing cookies file: %w", err)
	}

	var existingEntries []cookieEntry
	if err := json.Unmarshal(data, &existingEntries); err != nil {
		return fmt.Errorf("failed to parse existing cookies file: %w", err)
	}

	// Make a mutable copy of overrides to track which ones have been applied
	remaining := make(map[string]string, len(overrides))
	for k, v := range overrides {
		remaining[k] = v
	}

	// Merge: update entries whose name is in overrides; preserve everything else
	var mergedEntries []cookieEntry
	for _, entry := range existingEntries {
		if newValue, ok := remaining[entry.Name]; ok {
			mergedEntries = append(mergedEntries, cookieEntry{Name: entry.Name, Value: newValue})
			delete(remaining, entry.Name)
		} else {
			mergedEntries = append(mergedEntries, entry)
		}
	}

	// Append any override keys that were not already in the file
	for name, value := range remaining {
		mergedEntries = append(mergedEntries, cookieEntry{Name: name, Value: value})
	}

	// Marshal with pretty formatting (matches browser extension output)
	jsonData, err := json.MarshalIndent(mergedEntries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cookies to JSON: %w", err)
	}

	// Atomic write: write to temp file first, then rename
	tempFile := c.cookiesFilePath + ".tmp"
	if err := os.WriteFile(tempFile, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write temp cookies file: %w", err)
	}
	if err := os.Rename(tempFile, c.cookiesFilePath); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to rename temp cookies file: %w", err)
	}

	return nil
}

// saveCookiesToFile persists the current CloudFront cookies to the JSON file.
// It preserves all other cookies (including the session cookie) unchanged.
func (c *StravaSessionClient) saveCookiesToFile() error {
	overrides := make(map[string]string)
	c.mu.Lock()
	for _, cookie := range c.cloudFrontCookies {
		overrides[cookie.Name] = cookie.Value
	}
	if !c.cloudFrontCookiesExpiration.IsZero() {
		overrides["_strava_CloudFront-Expires"] = strconv.FormatInt(c.cloudFrontCookiesExpiration.UnixMilli(), 10)
	}
	c.mu.Unlock()

	if err := c.saveCookieOverridesToFile(overrides); err != nil {
		return err
	}
	log.Printf("Successfully persisted updated CloudFront cookies to %s", c.cookiesFilePath)
	return nil
}

// saveSessionToFile updates only the _strava4_session value in the JSON file.
func (c *StravaSessionClient) saveSessionToFile(newSession string) error {
	return c.saveCookieOverridesToFile(map[string]string{
		"_strava4_session": newSession,
	})
}

// extractCSRFToken extracts the Rails authenticity_token from an HTML login page.
// Handles both attribute orderings (name before value, or value before name).
func extractCSRFToken(html string) (string, error) {
	if m := csrfRe1.FindStringSubmatch(html); len(m) >= 2 {
		return m[1], nil
	}
	if m := csrfRe2.FindStringSubmatch(html); len(m) >= 2 {
		return m[1], nil
	}
	return "", fmt.Errorf("authenticity_token not found in login page HTML")
}

// loginToStrava performs the full Strava web login flow and returns a new
// _strava4_session cookie value. Uses only stdlib HTTP — no external deps.
func (c *StravaSessionClient) loginToStrava() (string, error) {
	noRedirect := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}

	// Step 1: GET the login page to obtain the CSRF token
	getResp, err := noRedirect.Get(stravaBaseURL + "/login")
	if err != nil {
		return "", fmt.Errorf("failed to GET login page: %w", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login page returned unexpected status: %d", getResp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(getResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read login page body: %w", err)
	}

	csrfToken, err := extractCSRFToken(string(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to extract CSRF token: %w", err)
	}

	// Step 2: POST credentials to /session
	formData := url.Values{
		"authenticity_token": {csrfToken},
		"email":              {c.email},
		"password":           {c.password},
		"remember_me":        {"on"},
	}

	postReq, err := http.NewRequest("POST", stravaBaseURL+"/session",
		strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create POST request: %w", err)
	}
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Referer", stravaBaseURL+"/login")
	postReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; strava-heatmap-proxy)")

	// Replay cookies from the GET response
	for _, ck := range getResp.Cookies() {
		postReq.AddCookie(ck)
	}

	postResp, err := noRedirect.Do(postReq)
	if err != nil {
		return "", fmt.Errorf("failed to POST login: %w", err)
	}
	defer postResp.Body.Close()

	// Step 3: Detect success vs. failure
	// Success: 302 redirect to dashboard (not back to /login)
	// Failure: 302 redirect back to /login
	if postResp.StatusCode != http.StatusFound {
		return "", fmt.Errorf("unexpected login POST status: %d", postResp.StatusCode)
	}

	location := postResp.Header.Get("Location")
	if strings.Contains(location, "/login") {
		return "", fmt.Errorf("login failed: invalid credentials or account issue (redirected to %s)", location)
	}

	for _, ck := range postResp.Cookies() {
		if ck.Name == "_strava4_session" {
			return ck.Value, nil
		}
	}
	return "", fmt.Errorf("login redirect to %s succeeded but no _strava4_session cookie in response", location)
}

// fetchGCPAccessToken fetches a GCP service account access token from the metadata server.
// Returns an error if not running on GCP (fast 500ms timeout).
func fetchGCPAccessToken() (string, error) {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	req, err := http.NewRequest("GET",
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata server not reachable (not on GCP?): %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode access token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access token from metadata server")
	}
	return tokenResp.AccessToken, nil
}

// fetchGCPProjectID fetches the GCP project ID from the metadata server.
func fetchGCPProjectID() (string, error) {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	req, err := http.NewRequest("GET",
		"http://metadata.google.internal/computeMetadata/v1/project/project-id", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch project ID: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read project ID response: %w", err)
	}
	return strings.TrimSpace(string(body)), nil
}

// fetchSecretFromGCP retrieves a secret value from Google Secret Manager via REST API.
func fetchSecretFromGCP(token, projectID, secretName string) (string, error) {
	apiURL := fmt.Sprintf(
		"https://secretmanager.googleapis.com/v1/projects/%s/secrets/%s/versions/latest:access",
		projectID, secretName)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch secret %s: %w", secretName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Secret Manager returned status %d for secret %s", resp.StatusCode, secretName)
	}

	var smResp struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&smResp); err != nil {
		return "", fmt.Errorf("failed to decode Secret Manager response: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(smResp.Payload.Data)
	if err != nil {
		return "", fmt.Errorf("failed to base64-decode secret value: %w", err)
	}
	return string(decoded), nil
}

// fetchCredentials resolves Strava credentials via (in priority order):
// 1. CLI flags (cliEmail / cliPassword)
// 2. Environment variables STRAVA_EMAIL / STRAVA_PASSWORD
// 3. Google Secret Manager (GCP only)
func fetchCredentials(cliEmail, cliPassword string) (email, password string, err error) {
	// 1. CLI flags
	if cliEmail != "" && cliPassword != "" {
		return cliEmail, cliPassword, nil
	}

	// 2. Environment variables
	e := os.Getenv("STRAVA_EMAIL")
	p := os.Getenv("STRAVA_PASSWORD")
	if e != "" && p != "" {
		return e, p, nil
	}

	// 3. Secret Manager (only reachable on GCP)
	token, err := fetchGCPAccessToken()
	if err != nil {
		return "", "", fmt.Errorf("no credentials available (not on GCP or no env vars set)")
	}

	projectID, err := fetchGCPProjectID()
	if err != nil {
		return "", "", fmt.Errorf("failed to get GCP project ID: %w", err)
	}

	e, err = fetchSecretFromGCP(token, projectID, "STRAVA_EMAIL")
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch STRAVA_EMAIL from Secret Manager: %w", err)
	}

	p, err = fetchSecretFromGCP(token, projectID, "STRAVA_PASSWORD")
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch STRAVA_PASSWORD from Secret Manager: %w", err)
	}

	return e, p, nil
}

func (c *StravaSessionClient) fetchCloudFrontCookies() error {
	return c.fetchCloudFrontCookiesInternal(false)
}

func (c *StravaSessionClient) fetchCloudFrontCookiesInternal(retried bool) error {
	req, err := http.NewRequest("HEAD", stravaHeatmapURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Cookie", fmt.Sprintf("_strava4_session=%s;", c.sessionIdentifier))

	// Use a no-redirect client so we can detect session expiry (302 → /login)
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		loc := resp.Header.Get("Location")
		// Detect session expiry: Strava redirects to /login when the session is invalid
		if !retried &&
			(resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently) &&
			(strings.Contains(loc, "/login") || strings.Contains(loc, "/session")) {

			if c.email == "" || c.password == "" {
				return fmt.Errorf("session expired (redirected to %s) and no credentials configured for auto-login", loc)
			}

			log.Printf("Session expired (redirected to %s), attempting re-login...", loc)
			newSession, loginErr := c.loginToStrava()
			if loginErr != nil {
				return fmt.Errorf("session expired and re-login failed: %w", loginErr)
			}

			c.mu.Lock()
			c.sessionIdentifier = newSession
			c.mu.Unlock()

			log.Printf("Re-login successful, persisting new session and retrying...")
			if saveErr := c.saveSessionToFile(newSession); saveErr != nil {
				log.Printf("Warning: Failed to persist new session to file: %v", saveErr)
			}

			return c.fetchCloudFrontCookiesInternal(true)
		}
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var cookies []*http.Cookie
	var expiration int64

	for _, cookie := range resp.Cookies() {
		if cookie.Value == "" {
			continue // skip deletion cookies (Max-Age=-1 with empty value)
		}
		switch cookie.Name {
		case "CloudFront-Signature", "CloudFront-Policy", "CloudFront-Key-Pair-Id", "_strava_idcf":
			cookies = append(cookies, cookie)
		case "_strava_CloudFront-Expires":
			expiration, err = strconv.ParseInt(cookie.Value, 10, 64)
			if err != nil {
				log.Printf("Invalid timestamp value for %s: %s", cookie.Name, cookie.Value)
			}
		}
	}

	if len(cookies) < 4 {
		return fmt.Errorf("not all required CloudFront cookies received")
	}

	c.cloudFrontCookies = cookies
	if expiration != 0 {
		c.cloudFrontCookiesExpiration = time.UnixMilli(expiration)
		log.Printf("New CloudFront cookies will expire at %s", c.cloudFrontCookiesExpiration)
	}

	// Persist updated cookies to file
	if err := c.saveCookiesToFile(); err != nil {
		// Log warning but don't fail - proxy continues with in-memory cookies
		log.Printf("Warning: Failed to persist cookies to file: %v", err)
		log.Printf("Proxy will continue operating with in-memory cookies only")
	}

	return nil
}

func main() {
	param := getParam()
	target, err := url.Parse(*param.Target)
	if err != nil {
		log.Fatalf("Could not parse target url: %s", err)
	}

	// Resolve Strava credentials (CLI → env vars → Secret Manager)
	email, password, credErr := fetchCredentials(*param.Email, *param.Password)
	if credErr != nil {
		log.Printf("No Strava credentials available: %v", credErr)
		log.Printf("Auto-login disabled; proxy requires a valid _strava4_session in the cookies file")
		email, password = "", ""
	} else {
		log.Printf("Strava credentials loaded — auto-login enabled")
	}

	client, err := NewStravaSessionClient(*param.CookiesFile, email, password)
	if err != nil {
		log.Fatalf("Could not initialize Strava client: %s", err)
	}

	// If no session cookie in file but credentials are available, login now
	if client.sessionIdentifier == "" {
		log.Printf("No session cookie found in cookies file; performing initial login...")
		newSession, loginErr := client.loginToStrava()
		if loginErr != nil {
			log.Fatalf("Initial login failed: %v", loginErr)
		}
		client.mu.Lock()
		client.sessionIdentifier = newSession
		client.mu.Unlock()
		log.Printf("Initial login successful")
		if saveErr := client.saveSessionToFile(newSession); saveErr != nil {
			log.Printf("Warning: Failed to persist initial session: %v", saveErr)
		}
	}

	if len(client.cloudFrontCookies) == 0 || time.Now().After(client.cloudFrontCookiesExpiration) {
		log.Printf("Fetching new CloudFront cookies...")
		if err := client.fetchCloudFrontCookies(); err != nil {
			log.Fatalf("Warning: Failed to fetch CloudFront cookies: %s", err)
		}
	}

	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
		// refresh expired CloudFront cookies before forwarding the request
		if client.cloudFrontCookiesExpiration.IsZero() || time.Now().After(client.cloudFrontCookiesExpiration) {
			if client.refreshing.CompareAndSwap(false, true) {
				defer client.refreshing.Store(false)
				log.Printf("CloudFront cookies have expired, refreshing...")
				if err := client.fetchCloudFrontCookies(); err != nil {
					log.Fatalf("Warning: Failed to fetch CloudFront cookies: %s", err)
				}
			}
		}
		// add CloudFront cookies to the request
		for _, c := range client.cloudFrontCookies {
			req.AddCookie(c)
		}
	}

	modifyResponse := func(resp *http.Response) error {
		if resp.StatusCode == http.StatusForbidden {
			if client.refreshing.CompareAndSwap(false, true) {
				defer client.refreshing.Store(false)
				log.Printf("Received 403 from Strava CDN - CloudFront cookies rejected early, forcing refresh...")
				client.mu.Lock()
				client.cloudFrontCookiesExpiration = time.Time{}
				client.mu.Unlock()
				if err := client.fetchCloudFrontCookies(); err != nil {
					log.Printf("Warning: Failed to refresh CloudFront cookies after 403: %v", err)
				}
			}
		}
		return nil
	}

	proxy := httputil.ReverseProxy{Director: director, ModifyResponse: modifyResponse}

	// Health endpoint: returns cookie expiry time and proactively refreshes
	// cookies when within 4h of expiry. Hit by Cloud Scheduler every 20h.
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if time.Until(client.cloudFrontCookiesExpiration) < 4*time.Hour {
			if client.refreshing.CompareAndSwap(false, true) {
				go func() {
					defer client.refreshing.Store(false)
					log.Printf("Health check triggering proactive cookie refresh...")
					if err := client.fetchCloudFrontCookies(); err != nil {
						log.Printf("Warning: Proactive refresh failed: %v", err)
					}
				}()
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","cookies_expire":"%s"}`,
			client.cloudFrontCookiesExpiration.UTC().Format(time.RFC3339))
	})

	// Create authenticated handler wrapper
	authHandler, err := NewAuthenticatedHandler(&proxy, *param.ApiKeysFile)
	if err != nil {
		log.Printf("Warning: Failed to load API keys: %v", err)
		log.Printf("Proceeding without API key authentication")
		http.Handle("/", &proxy)
	} else {
		http.Handle("/", authHandler)
	}

	log.Printf("Starting proxy for target %s on http://localhost:%s/ ..", *param.Target, *param.Port)
	log.Fatal(http.ListenAndServe(":"+*param.Port, nil))
}
