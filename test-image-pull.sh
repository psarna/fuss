#!/bin/bash
#
# Demo script that pulls a Docker image and shows you
# how to run it with fuss to "chroot" into its filesystem
# in a local path.
#
set -euo pipefail

IMAGE="${1:-}"

if [[ -z "$IMAGE" ]]; then
    echo "Usage: $0 <image[:tag]> [output_dir]"
    echo "Example: $0 alpine:latest"
    exit 1
fi

if [[ "$IMAGE" != */* ]]; then
    IMAGE="library/$IMAGE"
fi

if [[ "$IMAGE" != *:* ]]; then
    IMAGE="$IMAGE:latest"
fi

REGISTRY="https://registry-1.docker.io"
REPO="${IMAGE%:*}"
TAG="${IMAGE##*:}"

DEFAULT_DIR="${REPO##*/}-${TAG}"
DEFAULT_DIR="${DEFAULT_DIR//[:\/]/-}"
OUTPUT_DIR="${2:-/tmp/$DEFAULT_DIR}"

echo "Pulling $REPO:$TAG from Docker Hub"

mkdir -p "$OUTPUT_DIR/layers"
cd "$OUTPUT_DIR"

get_token() {
    curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:$REPO:pull" | \
        jq -r '.token'
}

echo "Authenticating..."
TOKEN=$(get_token)

echo "Fetching manifest..."
MANIFEST=$(curl -s -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json" \
    "$REGISTRY/v2/$REPO/manifests/$TAG")

MEDIA_TYPE=$(echo "$MANIFEST" | jq -r '.mediaType // .schemaVersion')

if echo "$MANIFEST" | jq -e '.manifests' > /dev/null 2>&1; then
    echo "Multi-arch manifest detected, selecting linux/amd64..."
    DIGEST=$(echo "$MANIFEST" | jq -r '.manifests[] | select(.platform.architecture=="amd64" and .platform.os=="linux") | .digest' | head -1)
    if [[ -z "$DIGEST" || "$DIGEST" == "null" ]]; then
        DIGEST=$(echo "$MANIFEST" | jq -r '.manifests[0].digest')
    fi
    MANIFEST=$(curl -s -H "Authorization: Bearer $TOKEN" \
        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        "$REGISTRY/v2/$REPO/manifests/$DIGEST")
fi

echo "$MANIFEST" > manifest.json

CONFIG_DIGEST=$(echo "$MANIFEST" | jq -r '.config.digest')
echo "Fetching config $CONFIG_DIGEST..."
curl -s -H "Authorization: Bearer $TOKEN" \
    "$REGISTRY/v2/$REPO/blobs/$CONFIG_DIGEST" > config.json

LAYERS=$(echo "$MANIFEST" | jq -r '.layers[].digest')
LAYER_COUNT=$(echo "$LAYERS" | wc -l)

echo "Downloading $LAYER_COUNT layers..."

LAYER_NUM=0
LAYER_ORDER_FILE="layers/order.txt"
> "$LAYER_ORDER_FILE"

for LAYER_DIGEST in $LAYERS; do
    LAYER_NUM=$((LAYER_NUM + 1))
    LAYER_SHORT="${LAYER_DIGEST#sha256:}"
    LAYER_SHORT="${LAYER_SHORT:0:12}"
    LAYER_DIR="layers/$LAYER_NUM-$LAYER_SHORT"

    echo "[$LAYER_NUM/$LAYER_COUNT] Downloading $LAYER_SHORT..."

    mkdir -p "$LAYER_DIR"

    curl -s -L -H "Authorization: Bearer $TOKEN" \
        "$REGISTRY/v2/$REPO/blobs/$LAYER_DIGEST" > "$LAYER_DIR/layer.tar.gz"

    echo "[$LAYER_NUM/$LAYER_COUNT] Extracting..."
    mkdir -p "$LAYER_DIR/rootfs"
    tar -xzf "$LAYER_DIR/layer.tar.gz" -C "$LAYER_DIR/rootfs" 2>/dev/null || \
        tar -xf "$LAYER_DIR/layer.tar.gz" -C "$LAYER_DIR/rootfs" 2>/dev/null || true

    echo "$LAYER_DIR" >> "$LAYER_ORDER_FILE"
done

echo ""
echo "========================================="
echo "Download complete!"
echo "========================================="
echo ""
echo "Layers in order (bottom to top):"
echo ""
cat "$LAYER_ORDER_FILE"
echo ""
echo "========================================="
echo "To run with fuss:"
echo "========================================="
echo ""

LOWERDIRS=""
while IFS= read -r layer; do
    if [[ -z "$LOWERDIRS" ]]; then
        LOWERDIRS="$PWD/$layer/rootfs"
    else
        LOWERDIRS="$PWD/$layer/rootfs:$LOWERDIRS"
    fi
done < "$LAYER_ORDER_FILE"

echo "fuss --mountpoint=/ \\"
echo "     --lowerdir=$LOWERDIRS \\"
echo "     --upperdir=/tmp/upper \\"
echo "     -- /bin/sh"
echo ""
