# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based HTTP reverse proxy server that enables GIS clients (QGIS, QMapShack, JOSM) to access Strava's Global Heatmap tiles without implementing Strava's authentication and session management. The proxy intercepts requests, adds necessary authentication cookies (CloudFront tokens and Strava session), and forwards them to Strava's content servers.

## Build and Run Commands

### Local Development

Build the executable:
```bash
make install          # Creates ./build/strava-heatmap-proxy
```

Build to system location:
```bash
make install-system   # Installs to ~/.local/bin/strava-heatmap-proxy
```

Run the proxy server:
```bash
./build/strava-heatmap-proxy -cookies ~/.config/strava-heatmap-proxy/strava-cookies.json -port 8080
```

Run with API key authentication:
```bash
./build/strava-heatmap-proxy -cookies <cookies-file> -apikeys <api-keys-file> -port 8080
```

Clean build artifacts:
```bash
make clean
```

### Testing

Run all tests:
```bash
go test -v
```

Run tests with coverage:
```bash
go test -v -cover
```

Run benchmarks:
```bash
go test -bench=. -benchmem
```

### Google Cloud Run Deployment

Deploy to Google Cloud Run:
```bash
./deploy.sh
```

Manual deployment:
```bash
# Build and push Docker image
gcloud builds submit --tag gcr.io/${PROJECT_ID}/strava-heatmap-proxy .

# Deploy to Cloud Run
gcloud run deploy strava-heatmap-proxy \
  --image=gcr.io/${PROJECT_ID}/strava-heatmap-proxy \
  --platform=managed \
  --region=europe-north2 \
  --allow-unauthenticated
```

## Architecture

### Core Components

**Single-file Go application** ([strava-heatmap-proxy.go](strava-heatmap-proxy.go)): The entire proxy logic is in one file with these key components:

1. **StravaSessionClient** (lines 126-239): Manages Strava authentication
   - Reads cookies from JSON file (extracted via browser extension)
   - Maintains CloudFront authentication tokens (Policy, Signature, Key-Pair-Id, _strava_idcf)
   - Automatically refreshes expired CloudFront tokens using the session identifier (_strava4_session)
   - CloudFront tokens expire after 24 hours, but can be auto-refreshed while session is valid

2. **AuthenticatedHandler** (lines 58-124): Optional API key authentication wrapper
   - Validates API keys from query parameter `?key=<api-key>`
   - Strips the key parameter before proxying to Strava (security)
   - If no API keys file exists or is empty, runs without authentication (backward compatible)

3. **Reverse Proxy Director** (lines 260-276): Request transformation logic
   - Rewrites incoming requests from localhost to content-a.strava.com
   - Injects CloudFront cookies before forwarding
   - Triggers token refresh if CloudFront cookies have expired

### Authentication Flow

```
Browser Extension → strava-cookies.json → StravaSessionClient
                                              ↓
GIS Client → AuthenticatedHandler (optional) → Director → Strava
             (validates API key)                (adds cookies)
```

### Configuration Files

All config files use JSON format:

**strava-cookies.json** (required): Contains authentication cookies from Strava
- `_strava4_session`: Main session identifier (required for token refresh)
- CloudFront cookies: `CloudFront-Policy`, `CloudFront-Signature`, `CloudFront-Key-Pair-Id`, `_strava_idcf`
- `_strava_CloudFront-Expires`: Timestamp for CloudFront token expiration
- Default location: `~/.config/strava-heatmap-proxy/strava-cookies.json`

**api-keys.json** (optional): API key authentication configuration
- Format: `{"keys": ["key1", "key2", ...]}`
- Default location: `~/.config/strava-heatmap-proxy/api-keys.json`
- If file doesn't exist or is empty, proxy runs without authentication

**For Docker/Cloud Run deployment**: These files must be in `build/` directory and are baked into the container image at build time.

### Command-line Arguments

- `-cookies <file>`: Path to cookies JSON file
- `-port <port>`: Local proxy port (default: 8080)
- `-target <url>`: Target Strava heatmap URL (default: https://content-a.strava.com/)
- `-apikeys <file>`: Optional API keys configuration file

### Docker Multi-stage Build

The [Dockerfile](Dockerfile) uses a two-stage build:
1. **Builder stage**: golang:1.25-alpine with full build environment
2. **Runtime stage**: alpine:latest with minimal dependencies (ca-certificates only)
   - Runs as non-root user (appuser:appgroup, UID/GID 1001)
   - Configuration files copied from `build/` directory into container

## Testing Strategy

Comprehensive test coverage in [strava-heatmap-proxy_test.go](strava-heatmap-proxy_test.go):

- **API key authentication tests**: Validates loading, validation, empty keys, missing keys, invalid JSON
- **HTTP handler tests**: Tests all authentication flows (valid/invalid keys, missing keys, parameter stripping)
- **Integration tests**: Full end-to-end authentication flow with mock backend
- **Benchmark tests**: Performance testing with 0 keys, 1 key, 1000 keys

## Important Implementation Details

### Cookie Refresh Logic

The proxy automatically refreshes CloudFront tokens by making a HEAD request to `https://www.strava.com/maps` with the session identifier. This happens:
- On startup if tokens are expired or missing
- Before each proxied request if tokens have expired
- Response cookies are parsed to extract new CloudFront tokens

### Security Considerations

- API keys are stripped from the URL query before proxying to prevent leaking them to Strava
- Docker container runs as non-root user for security
- Sensitive files (cookies, API keys) are baked into Docker image (not ideal for production - consider Google Secret Manager for cloud deployments)
- API key validation uses map lookup (O(1) performance even with many keys)

### Known Limitations

- Session identifier (_strava4_session) cannot be obtained programmatically; must use browser extension
- Session expiration time is unknown and depends on Strava's configuration
- CloudFront tokens expire after 24 hours
- API keys are case-sensitive

## Browser Extension

The repository includes a browser extension in `strava-cookie-exporter/` directory (not built by default with `make install`). To build:
```bash
7z a strava-cookie-exporter.zip ./strava-cookie-exporter/*
```

Published on Mozilla Add-ons and Chrome Web Store.

## Common URL Patterns

Example TMS tile URLs (replace localhost:8080 with your deployment URL):
- All activities: `http://localhost:8080/identified/globalheat/all/bluered/{z}/{x}/{y}.png?v=19`
- Hiking: `http://localhost:8080/identified/globalheat/sport_Hike/hot/{z}/{x}/{y}.png?v=19`
- Road cycling: `http://localhost:8080/identified/globalheat/sport_Ride/hot/{z}/{x}/{y}.png?v=19`
- Mountain biking: `http://localhost:8080/identified/globalheat/sport_MountainBikeRide/hot/{z}/{x}/{y}.png?v=19`

With API key authentication:
```
http://localhost:8080/identified/globalheat/all/bluered/{z}/{x}/{y}.png?v=19&key=your-api-key
```
