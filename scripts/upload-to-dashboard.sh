#!/usr/bin/env bash
#
# Uploads a built release zip + its changelog notes to the Lyzerslab dashboard
# as a new ProductVersion, so a client with an active license immediately sees
# the new version and can download it -- no manual upload through the admin UI.
#
# Called from .github/workflows/release.yml after the zip is built and the
# changelog notes are extracted; safe to run manually too.
#
# Usage: scripts/upload-to-dashboard.sh <version> <zip-path> <changelog-notes-path>
#
# Required env vars:
#   DASHBOARD_URL             e.g. https://www.lyzerslab.com
#   DASHBOARD_PRODUCT_ID      Product.id for "MuRu Guard Security Scanner" on the dashboard
#   DASHBOARD_RELEASE_TOKEN   shared secret matching RELEASE_API_TOKEN on the dashboard

set -euo pipefail

VERSION="${1:-}"
ZIP_PATH="${2:-}"
NOTES_PATH="${3:-}"

if [[ -z "$VERSION" || -z "$ZIP_PATH" || -z "$NOTES_PATH" ]]; then
  echo "Usage: $0 <version> <zip-path> <changelog-notes-path>" >&2
  exit 1
fi
if [[ ! -f "$ZIP_PATH" ]]; then
  echo "Error: zip not found at $ZIP_PATH" >&2
  exit 1
fi
if [[ ! -f "$NOTES_PATH" ]]; then
  echo "Error: changelog notes not found at $NOTES_PATH" >&2
  exit 1
fi

: "${DASHBOARD_URL:?DASHBOARD_URL is not set}"
: "${DASHBOARD_PRODUCT_ID:?DASHBOARD_PRODUCT_ID is not set}"
: "${DASHBOARD_RELEASE_TOKEN:?DASHBOARD_RELEASE_TOKEN is not set}"

echo "Uploading $ZIP_PATH as v$VERSION to $DASHBOARD_URL..."

http_code="$(curl -sS -o /tmp/dashboard-upload-response.json -w "%{http_code}" \
  -X POST "$DASHBOARD_URL/api/dashboard/products/$DASHBOARD_PRODUCT_ID/versions" \
  -H "Authorization: Bearer $DASHBOARD_RELEASE_TOKEN" \
  -F "version=$VERSION" \
  -F "changelog=<$NOTES_PATH" \
  -F "file=@$ZIP_PATH")"

cat /tmp/dashboard-upload-response.json
echo ""

if [[ "$http_code" -lt 200 || "$http_code" -ge 300 ]]; then
  echo "::error::Dashboard upload failed with HTTP $http_code"
  exit 1
fi

echo "Uploaded v$VERSION to the dashboard successfully."
