"""Static invariants for the Nitro host-proxy systemd unit.

The host-proxy service is locked down with ``IPAddressDeny=any`` plus a
small allowlist.  Without an explicit 169.254.169.254/32 entry, IMDSv2
calls from boto3 are silently dropped at the IP filter, which surfaces
as a 503 / 500 on every request that needs AWS credentials.
"""
from __future__ import annotations

from pathlib import Path

import pytest

UNIT_PATH = (
    Path(__file__).resolve().parents[2]
    / "src" / "tee_crafter" / "resources" / "systemd" / "nitro-aws.service"
)


@pytest.fixture(scope="module")
def unit_text() -> str:
    return UNIT_PATH.read_text(encoding="utf-8")


def test_unit_file_exists() -> None:
    assert UNIT_PATH.is_file(), f"missing nitro-aws unit file: {UNIT_PATH}"


def test_loopback_allow_present(unit_text: str) -> None:
    """Loopback is the SSM tunnel entry path; without it the proxy is unreachable."""
    assert "127.0.0.0/8" in unit_text


def test_imdsv2_allowlisted(unit_text: str) -> None:
    """IMDSv2 endpoint must be reachable so boto3 can resolve instance-role creds."""
    assert "169.254.169.254/32" in unit_text, (
        "host-proxy.service must allow 169.254.169.254/32 for IMDSv2; "
        "without it every cred-requiring request fails at the IP filter."
    )


def test_ip_deny_default(unit_text: str) -> None:
    """Outbound must default to deny — only the explicit allowlist may talk."""
    assert "IPAddressDeny=any" in unit_text


def test_restrict_address_families(unit_text: str) -> None:
    """vsock is mandatory (enclave comms); AF_INET/UNIX are loopback + IMDS."""
    line = next(
        (l for l in unit_text.splitlines()
         if l.strip().startswith("RestrictAddressFamilies=")),
        "",
    )
    assert "AF_VSOCK" in line
    assert "AF_INET" in line
