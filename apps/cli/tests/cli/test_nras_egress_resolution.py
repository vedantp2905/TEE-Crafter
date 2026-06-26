"""Strict NRAS egress resolves the endpoint instead of giving up.

The behaviour under test replaces a genuine dead end. Strict mode used to mean
"no CIDRs supplied, so create no rule and let GPU attestation fail", on the
stated grounds that NVIDIA publishes no NRAS ranges and the endpoint sits behind
a rotating CDN. The first half holds; the second did not survive a lookup --
``nras.attestation.nvidia.com`` answers with a single address in Google's global
load-balancer range, identically from independent resolvers.

What matters in these tests is that making strict mode *usable* did not make it
*permissive*: a failed lookup must still produce no rule, an operator's own list
must still win, and nothing here may quietly reach for the Internet tag.
"""
from __future__ import annotations

import socket

import pytest

from tee_crafter.cli.deployment.common import nras_egress

NRAS_ENV = (
    "TF_VAR_nras_egress_cidrs",
    "TF_VAR_allow_nras_broad_internet",
    "TEE_CRAFTER_NRAS_CIDRS",
    "TEE_CRAFTER_NRAS_STRICT",
    "TEE_CRAFTER_NRAS_RESOLVE",
    "TEE_CRAFTER_NRAS_HOSTS",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in NRAS_ENV:
        monkeypatch.delenv(name, raising=False)


class _Console:
    def __init__(self):
        self.lines = []

    def print(self, text=""):
        self.lines.append(str(text))

    @property
    def text(self):
        return "\n".join(self.lines)


class _Audit:
    def __init__(self):
        self.records = []

    def record(self, phase, step, status, **fields):
        self.records.append({"step": step, "status": status, **fields})


def _resolver(mapping):
    """Stand in for ``socket.getaddrinfo``."""
    def lookup(host, port, family=0, socktype=0):
        if host not in mapping:
            raise socket.gaierror(f"no such host {host}")
        return [(socket.AF_INET, socktype, 6, "", (addr, port))
                for addr in mapping[host]]
    return lookup


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------

def test_host_routes_not_the_enclosing_allocation():
    """NRAS lives in 34.64.0.0/10 -- four million Google addresses. Widening to
    the parent block would allow most of GCP and call it an allowlist."""
    cidrs = nras_egress.resolve_host_cidrs(
        ["nras.attestation.nvidia.com"],
        resolver=_resolver({"nras.attestation.nvidia.com": ["34.120.45.54"]}))
    assert cidrs == ["34.120.45.54/32"]


def test_multiple_addresses_are_sorted_for_determinism():
    cidrs = nras_egress.resolve_host_cidrs(
        ["rim.attestation.nvidia.com"],
        resolver=_resolver({
            "rim.attestation.nvidia.com": ["166.117.155.59", "166.117.56.89"]}))
    assert cidrs == ["166.117.155.59/32", "166.117.56.89/32"]


def test_ipv6_answers_become_128_prefixes():
    def lookup(host, port, family=0, socktype=0):
        return [(socket.AF_INET6, socktype, 6, "", ("2600::1", port, 0, 0))]

    assert nras_egress.resolve_host_cidrs(["h"], resolver=lookup) == ["2600::1/128"]


def test_resolution_failure_returns_empty_rather_than_raising():
    """A DNS hiccup must not abort a deploy midway through writing an NSG."""
    assert nras_egress.resolve_host_cidrs(
        ["nope.invalid"], resolver=_resolver({})) == []


def test_one_host_failing_does_not_discard_the_others():
    cidrs = nras_egress.resolve_host_cidrs(
        ["good.example", "bad.example"],
        resolver=_resolver({"good.example": ["1.2.3.4"]}))
    assert cidrs == ["1.2.3.4/32"]


def test_hosts_default_to_the_nras_endpoint():
    assert nras_egress.nras_hosts() == ("nras.attestation.nvidia.com",)


def test_hosts_are_overridable(monkeypatch):
    """Needed for the local verifier, which talks to RIM and OCSP, not NRAS."""
    monkeypatch.setenv("TEE_CRAFTER_NRAS_HOSTS", "a.example, b.example")
    assert nras_egress.nras_hosts() == ("a.example", "b.example")


def test_local_verifier_hosts_are_recorded():
    """Documented so nobody concludes local mode removes the egress hole: it
    swaps one hostname for two, and OCSP has no skip flag."""
    assert nras_egress.LOCAL_VERIFIER_HOSTS == (
        "rim.attestation.nvidia.com", "ocsp.ndis.nvidia.com")


# --------------------------------------------------------------------------
# Policy decision
# --------------------------------------------------------------------------

def test_strict_default_resolves_and_pins(monkeypatch):
    monkeypatch.setattr(nras_egress, "resolve_host_cidrs",
                        lambda *a, **k: ["34.120.45.54/32"])
    console, audit = _Console(), _Audit()

    policy = nras_egress.apply_nras_egress_policy(console, "azure", audit)

    assert policy == "resolved_cidr_allowlist"
    import os
    assert os.environ["TF_VAR_nras_egress_cidrs"] == '["34.120.45.54/32"]'
    assert os.environ["TF_VAR_allow_nras_broad_internet"] == "false"


def test_strict_resolution_never_widens_to_the_internet_tag(monkeypatch):
    monkeypatch.setattr(nras_egress, "resolve_host_cidrs",
                        lambda *a, **k: ["34.120.45.54/32"])
    nras_egress.apply_nras_egress_policy(_Console(), "azure", None)
    import os
    assert os.environ["TF_VAR_allow_nras_broad_internet"] == "false"


def test_failed_resolution_stays_fail_closed(monkeypatch):
    monkeypatch.setattr(nras_egress, "resolve_host_cidrs", lambda *a, **k: [])
    console = _Console()

    policy = nras_egress.apply_nras_egress_policy(console, "azure", None)

    import os
    assert policy == "strict_no_egress"
    assert os.environ["TF_VAR_allow_nras_broad_internet"] == "false"
    assert not os.environ.get("TF_VAR_nras_egress_cidrs")
    assert "will not be created" in console.text


def test_resolution_can_be_disabled(monkeypatch):
    """An air-gapped deploy, or one using a pre-pinned mirror, wants the old
    behaviour back without reaching for the dev hatch."""
    monkeypatch.setenv("TEE_CRAFTER_NRAS_RESOLVE", "0")
    called = []
    monkeypatch.setattr(nras_egress, "resolve_host_cidrs",
                        lambda *a, **k: called.append(1) or ["1.2.3.4/32"])

    policy = nras_egress.apply_nras_egress_policy(_Console(), "azure", None)

    assert policy == "strict_no_egress"
    assert not called


def test_explicit_operator_cidrs_still_win(monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_NRAS_CIDRS", "10.0.0.0/8")
    resolved = []
    monkeypatch.setattr(nras_egress, "resolve_host_cidrs",
                        lambda *a, **k: resolved.append(1) or [])

    policy = nras_egress.apply_nras_egress_policy(_Console(), "azure", None)

    import os
    assert policy == "explicit_cidr_allowlist"
    assert os.environ["TF_VAR_nras_egress_cidrs"] == '["10.0.0.0/8"]'
    assert not resolved


def test_dev_hatch_still_widens_and_says_so(monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_NRAS_STRICT", "0")
    console = _Console()

    policy = nras_egress.apply_nras_egress_policy(console, "azure", None)

    import os
    assert policy == "widened_to_internet_default"
    assert os.environ["TF_VAR_allow_nras_broad_internet"] == "true"
    assert "TEE_CRAFTER_NRAS_STRICT=0" in console.text


def test_audit_entry_records_which_addresses_were_trusted(monkeypatch):
    """A reader six months later needs the addresses, not just the verdict."""
    monkeypatch.setattr(nras_egress, "resolve_host_cidrs",
                        lambda *a, **k: ["34.120.45.54/32"])
    audit = _Audit()

    nras_egress.apply_nras_egress_policy(_Console(), "azure", audit)

    assert len(audit.records) == 1
    entry = audit.records[0]
    assert entry["policy"] == "resolved_cidr_allowlist"
    assert entry["nras_egress_cidrs"] == '["34.120.45.54/32"]'


def test_console_warns_the_pin_is_point_in_time(monkeypatch):
    monkeypatch.setattr(nras_egress, "resolve_host_cidrs",
                        lambda *a, **k: ["34.120.45.54/32"])
    console = _Console()
    nras_egress.apply_nras_egress_policy(console, "azure", None)
    assert "re-run the deploy to re-resolve" in console.text
