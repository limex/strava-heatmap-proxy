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
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

echo "🚀 Deploying Strava Heatmap Proxy to Google Cloud Run"
echo "Project: ${PROJECT_ID}"
echo "Region: ${REGION}"
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
