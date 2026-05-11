#!/usr/bin/env bash
set -euo pipefail

# deploy.sh — Deploy Infisical portal SSO to infisical-sso namespace
#
# Prerequisites:
#   - kubectl context set to ikp-harvester
#   - helm installed
#   - GHCR pull secret available (set CR_PAT env var or create secret manually)
#
# Usage:
#   ./scripts/deploy.sh [version]
#   e.g. ./scripts/deploy.sh 1.0.0-portal-sso

VERSION="${1:-${VERSION:-1.0.0-portal-sso}}"
NAMESPACE="infisical-sso"
CHART_DIR="$(cd "$(dirname "$0")/../helm-charts/infisical-standalone-postgres" && pwd)"
VALUES_FILE="${CHART_DIR}/values-portal-sso.yaml"

echo "========================================"
echo "Deploying Infisical Portal SSO"
echo "Version:  ${VERSION}"
echo "Namespace: ${NAMESPACE}"
echo "Chart:     ${CHART_DIR}"
echo "========================================"

# Step 1: Verify prerequisites
echo ""
echo "[1/5] Checking prerequisites..."
command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl not found"; exit 1; }
command -v helm >/dev/null 2>&1 || { echo "ERROR: helm not found"; exit 1; }

CTX=$(kubectl config current-context 2>/dev/null || echo "none")
echo "  Current kubecontext: ${CTX}"
if [[ "${CTX}" != "ikp-harvester" ]]; then
  echo "  WARNING: Expected context 'ikp-harvester', got '${CTX}'"
fi

# Step 2: Create namespace
echo ""
echo "[2/5] Creating namespace ${NAMESPACE}..."
kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 || \
  kubectl create namespace "${NAMESPACE}"
echo "  Namespace ready"

# Step 3: Create GHCR pull secret (if CR_PAT is set)
echo ""
echo "[3/5] Setting up GHCR pull secret..."
if [[ -n "${CR_PAT:-}" ]]; then
  kubectl delete secret ghcr-pull-secret -n "${NAMESPACE}" --ignore-not-found=true >/dev/null 2>&1
  kubectl create secret docker-registry ghcr-pull-secret \
    -n "${NAMESPACE}" \
    --docker-server=ghcr.io \
    --docker-username=dulyawatikp \
    --docker-password="${CR_PAT}"
  echo "  GHCR pull secret created"
else
  echo "  CR_PAT not set — skipping pull secret creation"
  echo "  Run: kubectl create secret docker-registry ghcr-pull-secret -n ${NAMESPACE} --docker-server=ghcr.io --docker-username=dulyawatikp --docker-password=<token>"
fi

# Step 4: Update Helm dependencies
echo ""
echo "[4/5] Updating Helm dependencies..."
cd "${CHART_DIR}"
helm dependency update

# Step 5: Deploy via Helm
echo ""
echo "[5/5] Deploying via Helm..."
helm upgrade --install infisical-sso "${CHART_DIR}" \
  -f "${VALUES_FILE}" \
  --set infisical.image.tag="${VERSION}" \
  -n "${NAMESPACE}" \
  --create-namespace \
  --wait \
  --timeout 10m

echo ""
echo "========================================"
echo "Deployment complete!"
echo "Infisical URL: https://infisical.portal.ikp.rke2"
echo ""
echo "Check status:"
echo "  kubectl get pods -n ${NAMESPACE}"
echo "  kubectl logs -n ${NAMESPACE} deployment/infisical-sso"
echo "========================================"
