# Google Cloud Run Deployment Guide

This guide explains how to deploy the Strava Heatmap Proxy to Google Cloud Run.

## Prerequisites

1. **Google Cloud Account**: Ensure you have a Google Cloud account and a project set up. You assign a ProjectID, that is needed later.

2. **Google Cloud CLI**: Install the Google Cloud CLI:
   ```bash
   # macOS (using Homebrew)
   brew install google-cloud-sdk

   # Or download from: https://cloud.google.com/sdk/docs/install
   ```

3. **Authentication**: Authenticate with Google Cloud:
   ```bash
   gcloud auth login
   gcloud config set project YOUR_PROJECT_ID
   ```

4. **Enable Required APIs**:
   ```bash
   gcloud services enable cloudbuild.googleapis.com
   gcloud services enable run.googleapis.com
   gcloud services enable containerregistry.googleapis.com
   gcloud services enable cloudscheduler.googleapis.com
   gcloud services enable secretmanager.googleapis.com
   ```

## Configuration Files

Before deploying, ensure you have the required configuration files in the `build/` directory:

- `build/strava-cookies.json`: Contains Strava authentication cookies
- `build/api-keys.json`: Contains API keys (if needed)

## Quick Deployment

1. **Edit the deploy.sh File, if needed**:
   ```bash
    PROJECT_ID="strava-heatmap-proxy"
    SERVICE_NAME="strava-heatmap-proxy"
    REGION="europe-north2"
    SCHEDULER_REGION="europe-west3"   # Cloud Scheduler does not support europe-north2
   ```

2. **Run the deployment script**:
   ```bash
   ./deploy.sh
   ```

   The script will:
   - Build and push the Docker image
   - Deploy to Cloud Run
   - Create (or update) a Cloud Scheduler job that hits `/health` every 20h to proactively refresh CloudFront cookies before Strava's 24h expiry window

## Manual Deployment

If you prefer to deploy manually:

1. **Build and push the Docker image**:
   ```bash
   PROJECT_ID=your-project-id
   gcloud builds submit --tag gcr.io/${PROJECT_ID}/strava-heatmap-proxy .
   ```

2. **Deploy to Cloud Run**:
   ```bash
   gcloud run deploy strava-heatmap-proxy \
     --image=gcr.io/${PROJECT_ID}/strava-heatmap-proxy \
     --platform=managed \
     --region=europe-north2 \
     --allow-unauthenticated \
     --port=8080 \
     --memory=512Mi \
     --cpu=1 \
     --min-instances=0 \
     --max-instances=10 \
     --timeout=300 \
     --concurrency=100
   ```

3. **Set up Cloud Scheduler** (proactive cookie refresh every 20h):
   ```bash
   SERVICE_URL=$(gcloud run services describe strava-heatmap-proxy \
     --platform=managed --region=europe-north2 --format="value(status.url)")

   # europe-north2 is not supported by Cloud Scheduler; use europe-west3
   gcloud scheduler jobs create http strava-cookie-refresh \
     --location=europe-west3 \
     --schedule="0 */20 * * *" \
     --uri="${SERVICE_URL}/health" \
     --http-method=GET \
     --time-zone="Europe/Vienna" \
     --description="Proactively refresh Strava CloudFront cookies before 24h expiry" \
     --attempt-deadline=30s
   ```

## Monitoring and Logs

- **Check proxy health and cookie expiry**:
  ```bash
  curl https://<your-service-url>/health
  # Returns: {"status":"ok","cookies_expire":"2026-02-19T12:00:00Z"}
  ```

- **View logs**: `gcloud logs tail --service=strava-heatmap-proxy`

- **Monitor in Console**: Go to Google Cloud Console > Cloud Run > strava-heatmap-proxy

- **Manage the Cloud Scheduler job** (note: different region from Cloud Run):
  ```bash
  gcloud scheduler jobs list --location=europe-west3
  gcloud scheduler jobs run strava-cookie-refresh --location=europe-west3
  ```

## Cookie Refresh Strategy

The proxy uses a two-layer approach to keep CloudFront cookies fresh:

1. **Reactive (403 detection)**: If Strava CDN returns a 403, the proxy immediately forces a cookie refresh via the `ModifyResponse` hook. The next request will use fresh cookies.

2. **Proactive (Cloud Scheduler)**: A Cloud Scheduler job hits `/health` every 20h. If cookies are within 4h of their 24h expiry, a background goroutine fetches fresh cookies — avoiding any outage window.

Refreshed cookies are atomically written back to `strava-cookies.json` so they survive container restarts within the same deployment.

## Automatic Re-Login on Session Expiry

The proxy automatically re-logs in when `_strava4_session` expires. No manual steps are needed as long as credentials are configured in Secret Manager (done by `deploy.sh`).

**How it works**: When the HEAD request to `strava.com/maps` returns a redirect to `/login`, the proxy detects session expiry, performs the full Strava web login flow (GET CSRF token → POST credentials), and retries the CloudFront cookie fetch with the new session.

**Signs that auto-login is working:**
- Logs show: `Session expired, attempting re-login...`
- Logs show: `Re-login successful, persisting new session and retrying...`

**If auto-login fails repeatedly**, check:
- Secrets `STRAVA_EMAIL` and `STRAVA_PASSWORD` exist in Secret Manager and are correct
- Cloud Run service account has `roles/secretmanager.secretAccessor` on both secrets
- Strava has not added CAPTCHA or IP-based bot protection to the login flow

## Local Development with Credentials

Pass credentials via flags:
```bash
./build/strava-heatmap-proxy \
    -cookies ~/.config/strava-heatmap-proxy/strava-cookies.json \
    -email your@email.com -password yourpassword \
    -port 8080
```

Or via environment variables:
```bash
export STRAVA_EMAIL=your@email.com
export STRAVA_PASSWORD=yourpassword
./build/strava-heatmap-proxy -cookies ~/.config/strava-heatmap-proxy/strava-cookies.json -port 8080
```

Without credentials, the proxy still works as long as `_strava4_session` in the cookies file is valid. Auto-login will be disabled and you'll need to re-export cookies manually if the session expires.

## Security Considerations

- The service is deployed with `--allow-unauthenticated` for easy access. Use `api-keys.json` to add API key authentication if needed.
- Configuration files containing sensitive data (cookies, API keys) are baked into the container image.
- For production use, consider using Google Secret Manager to store sensitive data.

## Cleanup

To delete the deployed service:
```bash
gcloud run services delete strava-heatmap-proxy --region=europe-north2
```

To delete the Cloud Scheduler job:
```bash
gcloud scheduler jobs delete strava-cookie-refresh --location=europe-west3
```

## Troubleshooting

- **Build fails**: Check that all required files are present in `build/` and the Dockerfile syntax is correct
- **Service fails to start**: Check the logs — likely missing or invalid `strava-cookies.json`
- **Tiles return 403**: CloudFront cookies rejected by Strava CDN. Check `/health` for expiry time. If session cookie expired, re-export from browser and redeploy.
- **Scheduler job not found**: Remember it lives in `europe-west3`, not `europe-north2`

## Cost Optimization

Cloud Run pricing is based on CPU and memory allocation, number of requests, and request duration. The current configuration uses `min-instances=0` (scale to zero when idle) with minimal resources (512Mi memory, 1 CPU) to keep costs near zero.

The Cloud Scheduler job (20h ping) wakes the instance briefly to refresh cookies — this cold start (~1-2s) is acceptable and the request cost is negligible.

## Docs

https://cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-go-service
