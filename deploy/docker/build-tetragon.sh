#!/bin/bash
# Build Tetragon image with environment variable support

set -e

REGISTRY=${REGISTRY:-"ghcr.io/tensorchord"}
IMAGE_NAME=${IMAGE_NAME:-"watchu-tetragon"}
TAG=${TAG:-"latest"}
FULL_IMAGE="${REGISTRY}/${IMAGE_NAME}:${TAG}"

echo "Building Tetragon image with environment variable support..."
echo "Image: ${FULL_IMAGE}"

cd "$(dirname "$0")"

# Build the image
docker build \
    -f tetragon.Dockerfile \
    -t "${FULL_IMAGE}" \
    -t "watchu-tetragon:local" \
    .

echo "✅ Image built successfully: ${FULL_IMAGE}"
echo "✅ Also tagged as: watchu-tetragon:local (for docker-compose)"

# Optionally push to registry
if [ "${PUSH}" = "true" ]; then
    echo "Pushing image to registry..."
    docker push "${FULL_IMAGE}"
    echo "✅ Image pushed successfully"
fi

echo ""
echo "Usage:"
echo "  - Docker Compose: docker-compose up (uses watchu-tetragon:local)"
echo "  - Kubernetes: kubectl apply -f ../k8s/collector.yaml (uses ${FULL_IMAGE})"
echo ""
echo "To push to ghcr.io:"
echo "  PUSH=true ./build-tetragon.sh"
