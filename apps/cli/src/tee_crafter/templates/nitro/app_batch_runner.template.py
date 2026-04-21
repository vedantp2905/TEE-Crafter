"""In-enclave batch runner for AWS Nitro Enclaves.

Wraps :mod:`batch_runner` so the enclave can execute the operator's
``--batch-entrypoint`` command (or, in container batch mode, the user image's
own entrypoint via the EIF), then stream the resulting ``output.tar.gz`` over
vsock to the host collector listening on port 5006.

Nitro Enclaves have no host filesystem visibility, which is why the standard
``ExecStopPost`` capture path used on CVMs cannot work here: the bundle has
to leave the enclave the same way every other enclave artifact does — over
a vsock socket the host is already trusted to read.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import sys
import tarfile
import tempfile
import time

# These constants get template-substituted by tee-crafter at build time.
HOST_CID = 3
OUTPUT_VSOCK_PORT = 5006
RUNTIME = "/workspace/runtime"
SCRATCH = "/workspace/scratch_tmp"
OUTPUT = "/var/lib/tee_crafter/output"


def _ensure_dirs() -> None:
    for d in (RUNTIME, SCRATCH, OUTPUT,
              os.path.join(OUTPUT, "files"),
              os.path.join(OUTPUT, "_logs"),
              os.path.join(OUTPUT, "_meta")):
        os.makedirs(d, exist_ok=True)


def _run_user_command() -> int:
    """Delegate to the shared snapshot/diff runner so the capture semantics
    are identical to the CVM path."""
    from batch_runner import main as runner_main  # type: ignore
    return runner_main()


def _bundle_output() -> str:
    """Tar everything under OUTPUT into a temp file and return its path."""
    fd, path = tempfile.mkstemp(prefix="tee_crafter_batch_", suffix=".tar.gz")
    os.close(fd)
    with tarfile.open(path, "w:gz") as tf:
        tf.add(OUTPUT, arcname=".")
    return path


def _stream_to_host(bundle_path: str) -> None:
    """Send the bundle to the host collector with a tiny framing header.

    Wire format (big-endian):
        u64 size_bytes
        u32 sha256_hex_len           # always 64
        bytes sha256_hex_len         # ascii hex digest
        bytes size_bytes             # tarball bytes
    """
    size = os.path.getsize(bundle_path)
    h = hashlib.sha256()
    with open(bundle_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    sha_hex = h.hexdigest().encode("ascii")

    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.settimeout(120.0)
    deadline = time.time() + 600
    while True:
        try:
            sock.connect((HOST_CID, OUTPUT_VSOCK_PORT))
            break
        except OSError as e:
            if time.time() > deadline:
                raise
            print(f"[batch] waiting for host collector on vsock {OUTPUT_VSOCK_PORT}: {e}",
                  file=sys.stderr)
            time.sleep(2)

    try:
        sock.sendall(struct.pack(">QI", size, len(sha_hex)))
        sock.sendall(sha_hex)
        with open(bundle_path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                sock.sendall(chunk)
        sock.shutdown(socket.SHUT_WR)
        ack = sock.recv(64)
        if not ack.startswith(b"OK"):
            print(f"[batch] host collector ack failed: {ack!r}", file=sys.stderr)
    finally:
        sock.close()


def main() -> int:
    _ensure_dirs()
    rc = _run_user_command()
    bundle = _bundle_output()
    try:
        _stream_to_host(bundle)
    finally:
        try:
            os.unlink(bundle)
        except OSError:
            pass
    print(json.dumps({"event": "batch_done", "runner_rc": rc}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
