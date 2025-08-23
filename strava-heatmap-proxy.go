package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"time"
)

type Param struct {
	CookiesFile *string
	Port        *string
	Target      *string
	ApiKeysFile *string
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
}

func NewStravaSessionClient(cookiesFilePath string) (*StravaSessionClient, error) {
	file, err := os.Open(cookiesFilePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	var entries []cookieEntry
	if err := json.NewDecoder(file).Decode(&entries); err != nil {
		return nil, fmt.Errorf("error decoding json: %w", err)
	}

	client := &StravaSessionClient{}
	for _, entry := range entries {
		if entry.Name == "_strava4_session" {
			client.sessionIdentifier = entry.Value
			break
		}
	}
	if client.sessionIdentifier == "" {
		return nil, fmt.Errorf("_strava4_session not found in cookies file")
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

func (c *StravaSessionClient) fetchCloudFrontCookies() error {
	req, err := http.NewRequest("HEAD", "https://www.strava.com/maps", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Cookie", fmt.Sprintf("_strava4_session=%s;", c.sessionIdentifier))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var cookies []*http.Cookie
	var expiration int64

	for _, cookie := range resp.Cookies() {
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

	return nil
}

func main() {
	param := getParam()
	target, err := url.Parse(*param.Target)
	if err != nil {
		log.Fatalf("Could not parse target url: %s", err)
	}

	client, err := NewStravaSessionClient(*param.CookiesFile)
	if err != nil {
		log.Fatalf("Could not initialize Strava client: %s", err)
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
			log.Printf("CloudFront cookies have expired, refreshing...")
			if err := client.fetchCloudFrontCookies(); err != nil {
				log.Fatalf("Warning: Failed to fetch CloudFront cookies: %s", err)
			}
		}
		// add CloudFront cookies to the request
		for _, c := range client.cloudFrontCookies {
			req.AddCookie(c)
		}
		// log.Printf("Got request: %s", req.URL)
	}

	proxy := httputil.ReverseProxy{Director: director}
	
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
