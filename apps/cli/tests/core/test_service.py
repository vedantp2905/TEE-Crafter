"""Unit tests for tee_crafter.core.service (persistent RA-TLS service mode)."""
from __future__ import annotations

import threading
import time

import pytest

from tee_crafter.core.service import (
    CertRotator, CertRotationConfig, RotatedCert,
    ConnectionAttestor, ServicePolicy, OnAttestationFailure,
)


# ---------- ServicePolicy ----------

class TestServicePolicy:
    def test_default_is_valid(self):
        p = ServicePolicy()
        assert p.is_valid(), p.validate()

    def test_grace_must_be_less_than_ttl(self):
        p = ServicePolicy(cert_ttl_seconds=300, cert_grace_seconds=600)
        errs = p.validate()
        assert any("grace" in e for e in errs)

    def test_reattest_interval_must_not_outlive_cert(self):
        p = ServicePolicy(cert_ttl_seconds=600, reattest_interval_seconds=900)
        errs = p.validate()
        assert any("reattest_interval_seconds" in e for e in errs)

    def test_describe_does_not_crash(self):
        assert "ServicePolicy" in ServicePolicy().describe()

    def test_env_round_trip(self):
        p = ServicePolicy(cert_ttl_seconds=120, cert_grace_seconds=10,
                          reattest_interval_seconds=60, reattest_grace_seconds=5,
                          max_concurrent_connections=8,
                          on_failure=OnAttestationFailure.HARD_STOP,
                          advertise_keepalive=False, streaming_enabled=True)
        env = p.to_env()
        assert env["TEE_CRAFTER_CERT_TTL_SEC"] == "120"
        assert env["TEE_CRAFTER_ON_ATTEST_FAIL"] == "hard_stop"
        assert env["TEE_CRAFTER_KEEPALIVE"] == "0"
        assert env["TEE_CRAFTER_STREAMING"] == "1"
        round_tripped = ServicePolicy.from_env(env)
        assert round_tripped == p


# ---------- CertRotator ----------

def _fake_attest(spki_digest: bytes) -> bytes:
    # Pretend attestation: SPKI binding tagged with a constant prefix.
    return b"FAKE_QUOTE:" + spki_digest


def _make_issuer(spki_seed: bytes = b""):
    """Create a deterministic cert-issuer closure.

    The "cert" is just a marker bytes blob containing the seed so tests can
    distinguish rotations from each other; the SPKI bytes are derived
    deterministically from the seed.
    """
    def issuer(seed: bytes, _spki_digest: bytes):
        spki_bytes = b"PK:" + seed
        cert_pem = b"CERT:" + seed
        return cert_pem, spki_bytes
    return issuer


class TestCertRotator:
    def test_initial_validation(self):
        with pytest.raises(ValueError):
            CertRotator(_fake_attest, _make_issuer(),
                        CertRotationConfig(ttl_seconds=0))
        with pytest.raises(ValueError):
            CertRotator(_fake_attest, _make_issuer(),
                        CertRotationConfig(ttl_seconds=300, pre_rotate_seconds=300))

    def test_rotate_now_produces_attested_cert(self):
        clock_t = [1000.0]
        r = CertRotator(_fake_attest, _make_issuer(),
                        CertRotationConfig(ttl_seconds=600),
                        clock=lambda: clock_t[0])
        rc = r.rotate_now(seed=b"seed-1")
        assert isinstance(rc, RotatedCert)
        assert rc.cert_pem == b"CERT:seed-1"
        assert rc.spki_sha256 != ""
        assert rc.attestation_blob.startswith(b"FAKE_QUOTE:")
        assert rc.attestation_sha256 == __import__("hashlib").sha256(rc.attestation_blob).hexdigest()
        assert rc.is_active(now=clock_t[0])
        assert r.current() is rc

    def test_history_bounded(self):
        clock_t = [1000.0]
        r = CertRotator(_fake_attest, _make_issuer(),
                        CertRotationConfig(ttl_seconds=600, max_history=2),
                        clock=lambda: clock_t[0])
        for i in range(5):
            r.rotate_now(seed=f"s-{i}".encode())
            clock_t[0] += 1.0
        h = r.history()
        assert len(h) == 2
        assert h[-1].cert_pem == b"CERT:s-4"

    def test_is_acceptable_grace_window(self):
        clock_t = [1000.0]
        r = CertRotator(_fake_attest, _make_issuer(),
                        CertRotationConfig(ttl_seconds=10, grace_seconds=5,
                                            pre_rotate_seconds=1, max_history=3),
                        clock=lambda: clock_t[0])
        rc1 = r.rotate_now(seed=b"a")
        clock_t[0] += 5  # mid-life
        assert r.is_acceptable(rc1.spki_sha256, now=clock_t[0])
        clock_t[0] += 5  # exactly expired -> grace begins
        rc2 = r.rotate_now(seed=b"b")
        # rc1 should now be in grace
        assert r.is_acceptable(rc1.spki_sha256, now=rc1.expires_at + 1)
        # rc1 outside grace -> rejected
        assert not r.is_acceptable(rc1.spki_sha256, now=rc1.expires_at + 100)
        # rc2 still active
        assert r.is_acceptable(rc2.spki_sha256, now=clock_t[0])

    def test_on_rotate_callback_fires(self):
        events = []
        r = CertRotator(_fake_attest, _make_issuer(),
                        CertRotationConfig(ttl_seconds=600))
        r.on_rotate(lambda rc: events.append(rc.seq))
        r.rotate_now(seed=b"x")
        r.rotate_now(seed=b"y")
        assert events == [0, 1]

    def test_background_thread_rotates(self):
        events = []
        cfg = CertRotationConfig(ttl_seconds=2, pre_rotate_seconds=1,
                                  grace_seconds=1, max_history=4)
        r = CertRotator(_fake_attest, _make_issuer(), cfg)
        r.on_rotate(lambda rc: events.append(rc.seq))
        r.start()
        try:
            # Wait for at least 2 rotations; cap at 6 sec.
            deadline = time.time() + 6
            while time.time() < deadline and len(events) < 2:
                time.sleep(0.1)
        finally:
            r.stop()
        assert len(events) >= 2

    def test_thread_safe_rotate_now(self):
        r = CertRotator(_fake_attest, _make_issuer(),
                        CertRotationConfig(ttl_seconds=600, max_history=1024))

        def _spam():
            for i in range(20):
                r.rotate_now(seed=f"t{threading.get_ident()}-{i}".encode())

        ts = [threading.Thread(target=_spam) for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert len(r.history()) == min(80, 1024)


# ---------- ConnectionAttestor ----------

class TestConnectionAttestor:
    def test_register_and_within_interval(self):
        clock_t = [1000.0]
        a = ConnectionAttestor(attest_now=lambda: True, interval_seconds=60,
                                clock=lambda: clock_t[0])
        a.register("conn1")
        clock_t[0] += 30
        r = a.check("conn1")
        assert r.ok and not r.refreshed

    def test_check_triggers_refresh_after_interval(self):
        clock_t = [1000.0]
        called = [0]

        def attest():
            called[0] += 1
            return True
        a = ConnectionAttestor(attest_now=attest, interval_seconds=60,
                                clock=lambda: clock_t[0])
        a.register("c1")
        clock_t[0] += 90
        r = a.check("c1")
        assert r.ok and r.refreshed
        assert called[0] == 1

    def test_check_failure_returns_not_ok(self):
        a = ConnectionAttestor(attest_now=lambda: False, interval_seconds=10)
        r = a.check("c1")
        assert not r.ok and r.refreshed

    def test_check_handles_attest_exceptions(self):
        def boom():
            raise RuntimeError("platform busy")
        a = ConnectionAttestor(attest_now=boom, interval_seconds=10)
        r = a.check("c1")
        assert not r.ok
        assert "platform busy" in r.reason

    def test_grace_allows_one_more_round(self):
        clock_t = [1000.0]
        results = []
        a = ConnectionAttestor(
            attest_now=lambda: True, interval_seconds=10, grace_seconds=5,
            clock=lambda: clock_t[0])
        a.register("c1")
        clock_t[0] += 12  # past interval, inside grace
        r = a.check("c1")
        assert r.ok and r.refreshed
        results.append(r)

    def test_unknown_connection_triggers_first_attestation(self):
        called = [0]

        def attest():
            called[0] += 1
            return True
        a = ConnectionAttestor(attest_now=attest, interval_seconds=10)
        r = a.check("never-seen")
        assert r.ok and r.refreshed
        assert called[0] == 1

    def test_max_tracked_evicts_oldest(self):
        a = ConnectionAttestor(attest_now=lambda: True, interval_seconds=10,
                                max_tracked_connections=3)
        a.register("a")
        a.register("b")
        a.register("c")
        a.register("d")  # should evict 'a'
        assert "a" not in a._last  # type: ignore[attr-defined]
        assert "d" in a._last       # type: ignore[attr-defined]

    def test_invalid_construction(self):
        with pytest.raises(ValueError):
            ConnectionAttestor(attest_now=lambda: True, interval_seconds=0)
        with pytest.raises(ValueError):
            ConnectionAttestor(attest_now=lambda: True, interval_seconds=10,
                                grace_seconds=-1)
        with pytest.raises(ValueError):
            ConnectionAttestor(attest_now=lambda: True, interval_seconds=10,
                                max_tracked_connections=0)

    def test_last_global_age(self):
        clock_t = [1000.0]
        a = ConnectionAttestor(attest_now=lambda: True, interval_seconds=10,
                                clock=lambda: clock_t[0])
        assert a.last_global_attestation_age() is None
        a.check("c1")
        clock_t[0] += 7
        age = a.last_global_attestation_age()
        assert age is not None
        assert abs(age - 7) < 1e-6
