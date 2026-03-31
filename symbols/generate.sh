#!/usr/bin/env bash
set -euo pipefail

# Usage: ./symbols/generate.sh [version]
#
# Downloads Matter cluster XML definitions from connectedhomeip and regenerates
# Go symbols (symbols/info.go) and metadata (symbols/info.json).
#
# The version maps to data_model/{version}/clusters/ inside the repo (master branch).
#
# Examples:
#   ./symbols/generate.sh        # uses latest version (1.6)
#   ./symbols/generate.sh 1.5
#   ./symbols/generate.sh 1.6

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="project-chip/connectedhomeip"
VERSION="${1:-1.6}"
CLUSTERS_PATH="data_model/${VERSION}/clusters"
XML_DIR="${SCRIPT_DIR}/xml"

echo "==> Fetching Matter cluster XML from ${REPO} (data_model/${VERSION}/clusters)"
mkdir -p "$XML_DIR"

# Use git sparse-checkout to download only the clusters directory (no API rate limits)
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

git clone --depth 1 --filter=blob:none --sparse \
    "https://github.com/${REPO}.git" "$TMPDIR" --quiet
git -C "$TMPDIR" sparse-checkout set "$CLUSTERS_PATH"

xml_files=("$TMPDIR/$CLUSTERS_PATH"/*.xml)
if [[ ! -e "${xml_files[0]}" ]]; then
    echo "ERROR: No XML files found at data_model/${VERSION}/clusters. Check the version number." >&2
    exit 1
fi

cp "${xml_files[@]}" "$XML_DIR/"
count=${#xml_files[@]}
echo "==> Copied ${count} XML files to ${XML_DIR}"
echo "==> Running code generator..."
cd "${SCRIPT_DIR}/gen" && go run process.go

echo "==> Done. Generated:"
echo "    symbols/info.go"
echo "    symbols/info.json"
