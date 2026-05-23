#!/bin/bash
# Launch the SGX dev container for running tee-crafter --tee-platform sgx-azure on macOS.
# Usage:
#   ./scripts/sgx-dev.sh              # interactive shell
#   ./scripts/sgx-dev.sh <command>    # run a single command
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_NAME="tee-crafter-sgx-dev"
DOCKERFILE="$PROJECT_DIR/scripts/run_sgx/Dockerfile.sgx-dev"

# Rebuild image if it doesn't exist or the Dockerfile changed since last build
NEEDS_BUILD=0
if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    NEEDS_BUILD=1
else
    IMAGE_CREATED=$(docker image inspect "$IMAGE_NAME" --format '{{.Created}}' 2>/dev/null)
    IMAGE_TS=$(date -j -f "%Y-%m-%dT%H:%M:%S" "${IMAGE_CREATED%%.*}" "+%s" 2>/dev/null \
             || date -d "${IMAGE_CREATED%%.*}" "+%s" 2>/dev/null || echo 0)
    DOCKERFILE_TS=$(stat -f "%m" "$DOCKERFILE" 2>/dev/null \
                  || stat -c "%Y" "$DOCKERFILE" 2>/dev/null || echo 0)
    ENTRYPOINT_TS=$(stat -f "%m" "$PROJECT_DIR/scripts/run_sgx/docker-sgx-entrypoint.sh" 2>/dev/null \
                  || stat -c "%Y" "$PROJECT_DIR/scripts/run_sgx/docker-sgx-entrypoint.sh" 2>/dev/null || echo 0)
    if [ "$DOCKERFILE_TS" -gt "$IMAGE_TS" ] || [ "$ENTRYPOINT_TS" -gt "$IMAGE_TS" ]; then
        NEEDS_BUILD=1
    fi
fi

PLAT_FLAG=()
HOST_ARCH="$(uname -m)"
if [ "$HOST_ARCH" != "x86_64" ]; then
    # SGX workloads are x86_64-only; cross-compile when host is ARM
    PLAT_FLAG=(--platform linux/amd64)
fi

if [ "$NEEDS_BUILD" -eq 1 ]; then
    echo "Building $IMAGE_NAME…"
    docker build "${PLAT_FLAG[@]}" -t "$IMAGE_NAME" -f "$DOCKERFILE" "$PROJECT_DIR"
fi

ENV_FILE_ARGS=()
if [ -f "$PROJECT_DIR/.env" ]; then
    ENV_FILE_ARGS=(--env-file "$PROJECT_DIR/.env")
fi

AWS_MOUNT_ARGS=()
if [ -d "$HOME/.aws" ]; then
    AWS_MOUNT_ARGS=(-v "$HOME/.aws:/root/.aws:ro")
fi

# Rewrite LLAMA_SERVER_BASE_URL so container can reach host's llama-server
# (127.0.0.1 inside container = container itself; host.docker.internal = host)
LLAMA_HOST_OVERRIDE_ARGS=()
if [ -f "$PROJECT_DIR/.env" ]; then
    url=$(grep -E '^LLAMA_SERVER_BASE_URL=' "$PROJECT_DIR/.env" 2>/dev/null | cut -d= -f2- | tr -d '"' | tr -d "'" || true)
    if [[ -n "$url" ]] && { [[ "$url" == *"127.0.0.1"* ]] || [[ "$url" == *"localhost"* ]]; }; then
        new_url="${url/127.0.0.1/host.docker.internal}"
        new_url="${new_url/localhost/host.docker.internal}"
        LLAMA_HOST_OVERRIDE_ARGS=(-e "LLAMA_SERVER_BASE_URL=$new_url")
    fi
fi

# Disallow using the Nitro backend from this SGX-specific helper
for arg in "$@"; do
    if [ "$arg" = "--tee-platform" ]; then
        NEXT_IS_PLATFORM=1
        continue
    fi
    if [ "$NEXT_IS_PLATFORM" = "1" ]; then
        if [ "$arg" = "nitro-aws" ]; then
            echo "Error: scripts/sgx-dev.sh is SGX-only. Use --tee-platform sgx-azure (or omit to let this script set it)."
            exit 1
        fi
        NEXT_IS_PLATFORM=0
    fi
    if [ "$arg" = "--tee-platform=nitro-aws" ]; then
        echo "Error: scripts/sgx-dev.sh is SGX-only. Use --tee-platform sgx-azure (or omit to let this script set it)."
        exit 1
    fi
done

# If caller did not specify a tee platform, force SGX
EXTRA_ARGS=()
HAS_TEE_PLATFORM=0
for arg in "$@"; do
    case "$arg" in
        --tee-platform|--tee-platform=*)
            HAS_TEE_PLATFORM=1
            break
            ;;
    esac
done
if [ "$HAS_TEE_PLATFORM" -eq 0 ]; then
    EXTRA_ARGS=(--tee-platform sgx-azure)
fi

exec docker run "${PLAT_FLAG[@]}" -it --rm \
    -v "$PROJECT_DIR":/workspace \
    "${AWS_MOUNT_ARGS[@]}" \
    "${ENV_FILE_ARGS[@]}" \
    "${LLAMA_HOST_OVERRIDE_ARGS[@]}" \
    "$IMAGE_NAME" \
    "$@" "${EXTRA_ARGS[@]}"
