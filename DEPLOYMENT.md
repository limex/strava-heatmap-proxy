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
   ```

2. **Run the deployment script**:
   ```bash
   ./deploy.sh
   ```

## Manual Deployment (not tested so far)

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
     --region=us-central1 \
     --allow-unauthenticated \
     --port=8080 \
     --memory=512Mi \
     --cpu=1 \
     --max-instances=10
   ```

## Environment Variables

The application supports the following environment variables:

- `PORT`: The port to run the application on (automatically set by Cloud Run)

## Security Considerations

- The service is deployed with `--allow-unauthenticated` for easy access. Consider adding authentication if needed.
- Configuration files containing sensitive data (cookies, API keys) are baked into the container image.
- For production use, consider using Google Secret Manager to store sensitive data.

## Monitoring and Logs

- **View logs**: `gcloud logs tail --service=strava-heatmap-proxy`
- **Monitor in Console**: Go to Google Cloud Console > Cloud Run > strava-heatmap-proxy

## Cleanup

To delete the deployed service:
```bash
gcloud run services delete strava-heatmap-proxy --region=us-central1
```

## Troubleshooting

- **Build fails**: Check that all required files are present and the Dockerfile syntax is correct
- **Service fails to start**: Check the logs for error messages
- **Authentication issues**: Ensure cookies and API keys are valid and properly formatted

## Cost Optimization

Cloud Run pricing is based on:
- CPU and memory allocation
- Number of requests
- Request duration

The current configuration uses minimal resources (512Mi memory, 1 CPU) to keep costs low.

## Docs

https://cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-go-service
