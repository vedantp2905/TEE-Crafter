# --- Build and install nitro-tpm-attest (static, via upstream's builder) ---
#
# Shared by the two AWS bakes that need a NitroTPM attestation document:
# ``setup_snp_aws.sh`` (measurement-gated BYOK key release) and
# ``setup_gpu_cc_aws.sh`` (CPU-side evidence in the RA-TLS certificate). One
# copy, because the alternative was two that drift -- and the gpu-cc-aws bake
# originally had none at all, which is why that platform reported its CPU
# evidence as self-asserted.
#
# AWS ships this as the `aws-nitro-tpm-tools` yum package on Amazon Linux 2023
# only, and these images are Ubuntu 22.04 (Jammy). Building it natively does not
# work, and the failure is specific: nitro-tpm-attest's build.rs requires the
# TPM2 Software Stack at ^4.0.0 while Jammy's libtss2-dev is 3.2.0, so the build
# aborts with "TSS version 3.2.0 not supported". Noble carries 4.0.1, but a
# binary dynamically linked against it would not run on this image either.
#
# So use the Docker-based static builder the upstream repo ships for exactly
# this case: Alpine + musl + tpm2-tss 4.1.3 configured --disable-shared
# --enable-nodl. The result has no libtss2 runtime dependency at all. Verified
# on arm64 and amd64: `file` reports "static-pie linked".
#
# Must be placed AFTER the Docker Engine block in the including script, because
# it needs a working daemon.
#
# Individually non-fatal so the failure text and build log survive; the
# including script's tooling gate is what refuses to mark the image baked.
NITROTPM_TOOLS_COMMIT="441fe310cce206efc79d88287fa2ee00355f5ce3"
if command -v nitro-tpm-attest >/dev/null 2>&1; then
    echo "✓ nitro-tpm-attest already installed"
elif ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "WARNING: no working Docker daemon; skipping nitro-tpm-attest."
else
    echo "Building nitro-tpm-attest (commit ${NITROTPM_TOOLS_COMMIT:0:12}) via upstream static builder..."
    NTPM_DIR=$(mktemp -d)
    git clone -q https://github.com/aws/NitroTPM-Tools.git "$NTPM_DIR" >/dev/null 2>&1 || true
    if [ -d "$NTPM_DIR/.git" ]; then
        ( cd "$NTPM_DIR" && git checkout -q "$NITROTPM_TOOLS_COMMIT" ) >/dev/null 2>&1 || true
        ACTUAL_NTPM_COMMIT=$( (cd "$NTPM_DIR" && git rev-parse HEAD) 2>/dev/null || echo none )
        if [ "$ACTUAL_NTPM_COMMIT" != "$NITROTPM_TOOLS_COMMIT" ]; then
            echo "WARNING: NitroTPM-Tools commit mismatch (expected $NITROTPM_TOOLS_COMMIT, got $ACTUAL_NTPM_COMMIT) — refusing to build an unpinned revision."
        else
            NTPM_LOG=$(mktemp)
            if docker build --file "$NTPM_DIR/docker/builder.Dockerfile" --tag tee-crafter-ntpm-builder "$NTPM_DIR" > "$NTPM_LOG" 2>&1 \
               && docker run --rm -v "$NTPM_DIR:/mnt" -w /mnt tee-crafter-ntpm-builder cargo build --bin nitro-tpm-attest --release >> "$NTPM_LOG" 2>&1 \
               && [ -f "$NTPM_DIR/target/release/nitro-tpm-attest" ]; then
                install -m 0755 "$NTPM_DIR/target/release/nitro-tpm-attest" /usr/bin/nitro-tpm-attest
                echo "✓ nitro-tpm-attest installed: $(file -b /usr/bin/nitro-tpm-attest 2>/dev/null || echo static)"
                docker image rm -f tee-crafter-ntpm-builder >/dev/null 2>&1 || true
            else
                echo "WARNING: nitro-tpm-attest static build failed."
                tail -25 "$NTPM_LOG"
                mkdir -p /var/log/tee-crafter
                cp "$NTPM_LOG" /var/log/tee-crafter/nitrotpm-build-failed.log || true
            fi
            rm -f "$NTPM_LOG"
        fi
    else
        echo "WARNING: git clone for NitroTPM-Tools failed; continuing without nitro-tpm-attest."
    fi
    rm -rf "$NTPM_DIR"
fi
