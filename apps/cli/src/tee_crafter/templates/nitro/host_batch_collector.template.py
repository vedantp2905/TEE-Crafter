"""Host-side vsock collector for AWS Nitro Enclaves batch mode.

Replaces ``host_proxy.py`` whenever ``__BATCH_MODE__`` is true: in batch mode
there are no per-request RA-TLS handshakes to forward, only a single tarball
that the in-enclave runner streams when the user command finishes.

Wire format matches :mod:`app_batch_runner.template` exactly:
    u64 size_bytes
    u32 sha256_hex_len           # always 64
    bytes sha256_hex_len         # ascii hex digest
    bytes size_bytes             # tarball bytes

After a successful receive we write the bundle to
``/var/lib/tee_crafter/output.tar.gz`` and its sidecar ``.sha256`` so the
existing :mod:`tee_crafter.cli.deployment.common.file_download` transport
selector can pull it down via SSM/S3 with no Nitro-specific code path.
"""
from __future__ import annotations

import hashlib
import logging
import os
import socket
import struct
import sys

OUTPUT_VSOCK_PORT = 5006
BUNDLE_PATH = "/var/lib/tee_crafter/output.tar.gz"
SHA_PATH = BUNDLE_PATH + ".sha256"

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("nitro_batch_collector")


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(1 << 20, n - len(buf)))
        if not chunk:
            raise IOError(f"connection closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def _serve_once(srv: socket.socket) -> bool:
    log.info("Waiting for in-enclave batch runner to connect...")
    conn, _addr = srv.accept()
    conn.settimeout(900.0)
    try:
        header = _recv_exact(conn, 8 + 4)
        size, sha_len = struct.unpack(">QI", header)
        if sha_len != 64:
            raise IOError(f"unexpected sha length {sha_len}")
        expected_sha = _recv_exact(conn, sha_len).decode("ascii")
        log.info("Receiving %d bytes (expected sha=%s)", size, expected_sha)

        os.makedirs(os.path.dirname(BUNDLE_PATH), exist_ok=True)
        h = hashlib.sha256()
        with open(BUNDLE_PATH, "wb") as f:
            remaining = size
            while remaining > 0:
                chunk = conn.recv(min(1 << 20, remaining))
                if not chunk:
                    raise IOError(f"stream truncated: {remaining} bytes missing")
                f.write(chunk)
                h.update(chunk)
                remaining -= len(chunk)
        actual_sha = h.hexdigest()
        if actual_sha.lower() != expected_sha.lower():
            log.error("sha mismatch: expected=%s actual=%s", expected_sha, actual_sha)
            conn.sendall(b"ERR-SHA")
            try:
                os.unlink(BUNDLE_PATH)
            except OSError:
                pass
            return False
        with open(SHA_PATH, "w", encoding="utf-8") as f:
            f.write(actual_sha + "\n")
        try:
            os.chmod(BUNDLE_PATH, 0o644)
            os.chmod(SHA_PATH, 0o644)
        except OSError:
            pass
        conn.sendall(b"OK")
        log.info("Bundle written: %s (%d bytes, sha=%s)",
                 BUNDLE_PATH, size, actual_sha)
        return True
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> int:
    srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((socket.VMADDR_CID_ANY, OUTPUT_VSOCK_PORT))
    srv.listen(1)
    log.info("Listening on vsock port %d for enclave batch output...",
             OUTPUT_VSOCK_PORT)
    try:
        while True:
            try:
                ok = _serve_once(srv)
                if ok:
                    return 0
            except Exception as e:
                log.exception("collector iteration failed: %s", e)
    finally:
        try:
            srv.close()
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
