#!/usr/bin/env bash
# Build the oktopus standalone image from the repo root.
# Usage: ./deploy/standalone/build.sh [TAG]
set -euo pipefail

TAG="${1:-oktopusp/standalone:latest}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "Building $TAG from $REPO_ROOT"

docker build \
    --file "$REPO_ROOT/deploy/standalone/Dockerfile" \
    --tag "$TAG" \
    "$REPO_ROOT"
