#!/bin/bash

# Strava Heatmap Proxy - Google Cloud Run Deployment Script
#
# Prerequisites:
# 1. Install Google Cloud CLI: https://cloud.google.com/sdk/docs/install
# 2. Authenticate with Google Cloud: gcloud auth login
# 3. Set your project: gcloud config set project YOUR_PROJECT_ID
# 4. Enable required APIs:
#    - gcloud services enable cloudbuild.googleapis.com
#    - gcloud services enable run.googleapis.com
#    - gcloud services enable containerregistry.googleapis.com

set -e

# Configuration variables
# PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-your-project-id}"
PROJECT_ID="strava-heatmap-proxy"
SERVICE_NAME="strava-heatmap-proxy"
# REGION="${GOOGLE_CLOUD_REGION:-us-central1}"
REGION="europe-north2"
# Cloud Scheduler does not support europe-north2; use nearest supported region
SCHEDULER_REGION="europe-west3"
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

echo "🚀 Deploying Strava Heatmap Proxy to Google Cloud Run"
echo "Project: ${PROJECT_ID}"
echo "Region: ${REGION}"
echo "Scheduler Region: ${SCHEDULER_REGION}"
echo "Service: ${SERVICE_NAME}"
echo "Image: ${IMAGE_NAME}"
echo

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "❌ Error: gcloud CLI is not installed. Please install it first."
    echo "   https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Check if user is authenticated
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
    echo "❌ Error: Not authenticated with Google Cloud. Please run:"
    echo "   gcloud auth login"
    exit 1
fi

# Validate project ID
if [ "${PROJECT_ID}" = "your-project-id" ]; then
    echo "❌ Error: Please set your Google Cloud Project ID:"
    echo "   export GOOGLE_CLOUD_PROJECT=your-actual-project-id"
    echo "   Or edit this script to set PROJECT_ID variable"
    exit 1
fi

# Set the project
gcloud config set project "${PROJECT_ID}"

echo "🔐 Setting up Secret Manager for Strava credentials..."
gcloud services enable secretmanager.googleapis.com

# Prompt for credentials if not passed as environment variables
if [ -z "${STRAVA_EMAIL}" ]; then
    read -rp "Enter Strava email: " STRAVA_EMAIL
fi
if [ -z "${STRAVA_PASSWORD}" ]; then
    read -rsp "Enter Strava password: " STRAVA_PASSWORD
    echo
fi

# Create or update STRAVA_EMAIL secret (idempotent)
echo -n "${STRAVA_EMAIL}" | gcloud secrets create STRAVA_EMAIL \
    --data-file=- \
    --replication-policy=automatic \
    2>/dev/null || \
echo -n "${STRAVA_EMAIL}" | gcloud secrets versions add STRAVA_EMAIL \
    --data-file=-

# Create or update STRAVA_PASSWORD secret (idempotent)
echo -n "${STRAVA_PASSWORD}" | gcloud secrets create STRAVA_PASSWORD \
    --data-file=- \
    --replication-policy=automatic \
    2>/dev/null || \
echo -n "${STRAVA_PASSWORD}" | gcloud secrets versions add STRAVA_PASSWORD \
    --data-file=-

# Grant the Cloud Run default service account access to read the secrets
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")
SERVICE_ACCOUNT="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
gcloud secrets add-iam-policy-binding STRAVA_EMAIL \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/secretmanager.secretAccessor" \
    --quiet
gcloud secrets add-iam-policy-binding STRAVA_PASSWORD \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/secretmanager.secretAccessor" \
    --quiet

echo "✅ Secrets configured in Secret Manager"
echo

echo "📦 Building and pushing Docker image..."
gcloud builds submit --tag "${IMAGE_NAME}" .

echo "🚢 Deploying to Cloud Run..."
gcloud run deploy "${SERVICE_NAME}" \
    --image="${IMAGE_NAME}" \
    --platform=managed \
    --region="${REGION}" \
    --allow-unauthenticated \
    --port=8080 \
    --memory=512Mi \
    --cpu=1 \
    --min-instances=0 \
    --max-instances=10 \
    --timeout=300 \
    --concurrency=100

# Get the service URL
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
    --platform=managed \
    --region="${REGION}" \
    --format="value(status.url)")

echo "⏰ Setting up Cloud Scheduler for proactive cookie refresh..."
gcloud services enable cloudscheduler.googleapis.com
# Create job if it doesn't exist, otherwise update it (idempotent)
gcloud scheduler jobs create http strava-cookie-refresh \
    --location="${SCHEDULER_REGION}" \
    --schedule="0 */20 * * *" \
    --uri="${SERVICE_URL}/health" \
    --http-method=GET \
    --time-zone="Europe/Vienna" \
    --description="Proactively refresh Strava CloudFront cookies before 24h expiry" \
    --attempt-deadline=30s \
    2>/dev/null || \
gcloud scheduler jobs update http strava-cookie-refresh \
    --location="${SCHEDULER_REGION}" \
    --schedule="0 */20 * * *" \
    --uri="${SERVICE_URL}/health" \
    --http-method=GET \
    --time-zone="Europe/Vienna" \
    --attempt-deadline=30s

echo
echo "✅ Deployment completed successfully!"
echo "🌐 Service URL: ${SERVICE_URL}"
echo
echo "To test your deployment:"
echo "curl ${SERVICE_URL}/health"
echo
echo "To view logs:"
echo "gcloud logs tail --service=${SERVICE_NAME}"
echo
echo "To delete the service:"
echo "gcloud run services delete ${SERVICE_NAME} --region=${REGION}"
echo
echo "To manage the cookie refresh scheduler job (note: different region):"
echo "gcloud scheduler jobs list --location=${SCHEDULER_REGION}"
echo "gcloud scheduler jobs run strava-cookie-refresh --location=${SCHEDULER_REGION}"
