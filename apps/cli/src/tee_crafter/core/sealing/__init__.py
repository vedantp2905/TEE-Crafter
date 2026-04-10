"""Sealed input bundles.

The plaintext ``--input-dir`` upload to S3/SCP en route to a TEE is a
recurring blocker for regulated buyers: the operator's cloud account
sees the bytes before the enclave does.

This package lets the operator (or a remote data owner) wrap an input
bundle to the *enclave's attested public key* before it ever leaves the
build host.  The resulting ``.sealed`` artifact is opaque to the cloud
operator; only an enclave whose attestation matches the manifest's
``target_spki_sha256`` and whose private key matches the wrapped DEK can
read it.

Wire shape (versioned, JSON-keyed binary):

    SEALED_BUNDLE_V1 := {
        "v": 1,
        "alg": "RSA-OAEP-SHA256+AES-256-GCM",
        "target_spki_sha256": "<hex>",  # binds bundle to the enclave key
        "build_id": "<sha256 of build dir>",
        "wrapped_dek_b64": "<base64>",  # KEM-wrapped 32-byte DEK
        "iv_b64": "<base64>",            # 12 bytes
        "aad_b64": "<base64>",           # AAD covers manifest fields
        "ciphertext_b64": "<base64>",    # AES-GCM(DEK, iv, plaintext, aad)
        "tag_b64": "<base64>",           # included for clarity (already in ciphertext)
        "plaintext_sha256": "<hex>",
        "size_bytes": N,
        "timestamp": "<ISO-8601 UTC>"
    }

The plaintext layer is a deterministic ``tar.gz`` of the input directory;
the unseal step extracts the tarball into ``BATCH_INPUT_DIR`` exactly
the way the existing ``--input-dir`` upload does.
"""
from tee_crafter.core.sealing.seal import seal_input_directory, SealedBundle
from tee_crafter.core.sealing.unseal import unseal_to_directory, UnsealError

__all__ = [
    "SealedBundle",
    "UnsealError",
    "seal_input_directory",
    "unseal_to_directory",
]
