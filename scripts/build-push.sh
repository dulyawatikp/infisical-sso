#!/usr/bin/env bash
# ============================================================================
# build-push.sh — Build Infisical standalone Docker image (portal SSO) & push to GHCR
# ============================================================================
# Usage:
#   ./scripts/build-push.sh 1.0.0-portal-sso
#   VERSION=1.0.0-portal-sso ./scripts/build-push.sh
# ============================================================================
# Prerequisites:
#   docker buildx available
#   Logged into ghcr.io before running:
#     echo $CR_PAT | docker login ghcr.io -u dulyawatikp --password-stdin
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKERFILE="$PROJECT_ROOT/Dockerfile.standalone-infisical"

# --- Version resolution ------------------------------------------------------
VERSION="${1:-${VERSION:-}}"

if [ -z "$VERSION" ]; then
  echo "ERROR: No version specified."
  echo "Usage: $0 <VERSION>"
  echo "   or: VERSION=<VERSION> $0"
  exit 1
fi

# --- Pre-flight checks -------------------------------------------------------
if [ ! -f "$DOCKERFILE" ]; then
  echo "ERROR: Dockerfile not found at $DOCKERFILE"
  exit 1
fi

if ! command -v docker &>/dev/null; then
  echo "ERROR: docker not found in PATH"
  exit 1
fi

IMAGE_TAG="ghcr.io/dulyawatikp/infisical-standalone:${VERSION}"

# --- Build & push ------------------------------------------------------------
echo "==> Building and pushing: $IMAGE_TAG"
echo "==> Using Dockerfile: $DOCKERFILE"

docker buildx build \
  --platform linux/amd64 \
  --build-arg PORTAL_SSO_ENABLED=true \
  --build-arg PORTAL_SSO_NAVBAR_HOST=https://sso-navbar.portal.ikp.rke2 \
  --build-arg POSTHOG_HOST=https://app.posthog.com \
  --build-arg POSTHOG_API_KEY=posthog-api-key \
  --build-arg INTERCOM_ID=intercom-id \
  --build-arg CAPTCHA_SITE_KEY=captcha-site-key \
  -t "$IMAGE_TAG" \
  -f "$DOCKERFILE" \
  --push \
  .

echo "==> Successfully built and pushed: $IMAGE_TAG"
