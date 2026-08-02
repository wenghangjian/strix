#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
IMAGE_TAG=${FIRMWARE_WORKER_IMAGE_TAG:-strix-firmware-worker:p2a}
BASE_IMAGE_REFERENCE="gcr.io/distroless/base-debian12@sha256:63f52bd27b6aa6555f5d56500b70d7bb0afe51c654905be88a2c1cf967a77b1a"
BASE_IMAGE_DIGEST="sha256:63f52bd27b6aa6555f5d56500b70d7bb0afe51c654905be88a2c1cf967a77b1a"
PROJECT_PYTHON=${PROJECT_PYTHON:-"$REPOSITORY_ROOT/.venv/bin/python"}

if [ ! -x "$PROJECT_PYTHON" ]; then
  printf 'run uv sync --frozen before building the worker image\n' >&2
  exit 1
fi

DEPENDENCY_DIR=$(mktemp -d)
trap 'rm -rf "$DEPENDENCY_DIR"' EXIT INT TERM
SITE_PACKAGES=$(
  "$PROJECT_PYTHON" -c 'import site; print(site.getsitepackages()[0])'
)

for dependency in \
  annotated_types \
  annotated_types-0.7.0.dist-info \
  pydantic \
  pydantic-2.13.4.dist-info \
  pydantic_core \
  pydantic_core-2.46.4.dist-info \
  typing_extensions.py \
  typing_extensions-4.15.0.dist-info \
  typing_inspection \
  typing_inspection-0.4.2.dist-info
do
  if [ ! -e "$SITE_PACKAGES/$dependency" ]; then
    printf 'locked worker dependency is missing: %s\n' "$dependency" >&2
    exit 1
  fi
  cp -R "$SITE_PACKAGES/$dependency" "$DEPENDENCY_DIR/"
done
find "$DEPENDENCY_DIR" -type d -name __pycache__ -prune -exec rm -rf '{}' +

WORKER_SOURCE_DIGEST=$(
  python3 "$SCRIPT_DIR/verify-image.py" --print-source-digest
)

docker build \
  --file "$SCRIPT_DIR/Dockerfile" \
  --build-context "worker_deps=$DEPENDENCY_DIR" \
  --build-arg "WORKER_SOURCE_DIGEST=$WORKER_SOURCE_DIGEST" \
  --tag "$IMAGE_TAG" \
  "$REPOSITORY_ROOT"

IMAGE_DIGEST=$(docker image inspect --format '{{.Id}}' "$IMAGE_TAG")
BUILT_AT_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
LOCK_TMP="$SCRIPT_DIR/worker-image.lock.tmp"

{
  printf 'image_tag=%s\n' "$IMAGE_TAG"
  printf 'image_digest=%s\n' "$IMAGE_DIGEST"
  printf 'base_image_reference=%s\n' "$BASE_IMAGE_REFERENCE"
  printf 'base_image_digest=%s\n' "$BASE_IMAGE_DIGEST"
  printf 'worker_source_digest=%s\n' "$WORKER_SOURCE_DIGEST"
  printf 'protocol_version=1.0\n'
  printf 'manifest_schema_version=p2a-manifest-1\n'
  printf 'built_at_utc=%s\n' "$BUILT_AT_UTC"
} > "$LOCK_TMP"
mv "$LOCK_TMP" "$SCRIPT_DIR/worker-image.lock"

python3 "$SCRIPT_DIR/verify-image.py" --image "$IMAGE_TAG"
