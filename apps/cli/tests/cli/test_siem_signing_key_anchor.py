"""``verify-siem-chain`` must have a trust anchor that is actually obtainable.

The command was right to refuse: verifying an event against the key embedded in
that same event proves the stream is self-consistent, and anyone who can inject
into a SIEM can produce a self-consistent stream signed by their own key. But
nothing in the pipeline ever produced an out-of-band key, so the refusal had no
escape hatch. The documented one — ``--pubkey-file ./build_provenance.pub`` —
named the long-lived *build* signing key, which never signs an event; running it
that way failed every event with ``InvalidSignature`` (reproduced against the
real Datadog export of the 2026-08-23 ``snp-aws`` run).

Worse, that wrong key was auto-discovered. Any ``build_provenance.pub`` beside
the events file or in the CWD was loaded even when the operator had passed
``--pinned-pubkey-sha256``, so dropping an export into its own build directory
turned a pass into a hard failure naming neither cause nor file.

The fix has three joints, and the middle one is the only interesting test here:
the exporter publishes its key fingerprint in the SIEM-SEC-4 health file, the
deploy copies it into the signed provenance ledger, and the verifier reads it
back. If the producer and the verifier disagree about how a key is fingerprinted
the whole chain is silently useless, so that round trip is asserted directly
rather than with two hand-written constants.
"""
from __future__ import annotations

import json


from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from tee_crafter.cli.commands.verify_siem_chain import (
    _signing_keys_in_provenance, pubkey_sha256,
)
from tee_crafter.cli.deployment.common.siem_sidecar import (
    parse_signing_key_fingerprint,
)

_FPR = "c" * 64


def _pem(key) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def write_chain(path, n=2):
    """Write *n* genuinely valid, signed, hash-linked events.

    Built with the producer's own ``compute_digest`` so these tests exercise
    real signature verification rather than a re-implementation of it.
    Returns the signing key's fingerprint, ready to pass to
    ``--pinned-pubkey-sha256``.
    """
    from tee_crafter.templates.common.siem_export import (
        GENESIS_PREV_DIGEST, compute_digest,
    )

    key = Ed25519PrivateKey.generate()
    pem = _pem(key)
    prev = GENESIS_PREV_DIGEST
    lines = []
    for seq in range(n):
        ev = {
            "event_id": f"evt{seq}", "seq": seq,
            "event_type": "attestation_boot" if seq == 0 else "attestation_refresh",
            "timestamp": f"2026-08-23T00:0{seq}:00Z",
            "pipeline_version": "test", "instance_id": "i-1",
            "tee_platform": "snp-aws",
            "measurement_sha256": "a" * 96, "attestation_sha256": "b" * 64,
            "attestation_size_bytes": 1184, "status": "pass",
            "prev_digest": prev, "schema_version": 2,
            "digest": "", "signature": "", "public_key_pem": pem, "extra": {},
        }
        ev["digest"] = compute_digest(ev)
        ev["signature"] = key.sign(ev["digest"].encode("ascii")).hex()
        prev = ev["digest"]
        lines.append(json.dumps(ev))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return pubkey_sha256(pem)


class TestProducerAndVerifierAgree:
    """The join that makes the anchor mean anything."""

    def test_health_file_fingerprint_matches_pubkey_sha256(self):
        """``AttestationLoop`` computes the fingerprint itself; the verifier
        computes it from the PEM. Same key must give the same 64 hex."""
        from tee_crafter.templates.common import siem_export

        key = Ed25519PrivateKey.generate()
        # Mirror exactly what AttestationLoop.__init__ does.
        producer = siem_export.hashlib.sha256(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()
        assert producer == pubkey_sha256(_pem(key))

    def test_loop_publishes_a_fingerprint_for_its_own_key(self):
        from tee_crafter.templates.common.siem_export import AttestationLoop

        loop = object.__new__(AttestationLoop)
        AttestationLoop.__init__(
            loop, exporter=None, interval_seconds=60, instance_id="i-1",
            tee_platform="snp-aws", pipeline_version="v1", attest_provider=None,
        )
        assert loop.public_key_sha256 == pubkey_sha256(loop.public_pem)
        assert len(loop.public_key_sha256) == 64


class TestTheDeployReadsItOffTheHealthFile:
    def test_it_is_parsed_from_the_catted_health_json(self):
        text = (
            "SIEM-SEC: tee-crafter-siem state=active restarts=0->0 export=pass\n"
            + json.dumps({"last_export_status": "pass",
                          "signing_key_sha256": _FPR})
            + "\njournal line noise\n"
        )
        assert parse_signing_key_fingerprint(text) == _FPR

    def test_an_older_sidecar_without_the_field_yields_empty(self):
        text = json.dumps({"last_export_status": "pass"})
        assert parse_signing_key_fingerprint(text) == ""

    def test_a_malformed_value_is_not_recorded(self):
        """A short value is a broken sidecar, not an anchor."""
        text = json.dumps({"signing_key_sha256": "deadbeef"})
        assert parse_signing_key_fingerprint(text) == ""

    def test_uppercase_is_normalised(self):
        text = json.dumps({"signing_key_sha256": _FPR.upper()})
        assert parse_signing_key_fingerprint(text) == _FPR

    def test_empty_input_is_safe(self):
        assert parse_signing_key_fingerprint("") == ""
        assert parse_signing_key_fingerprint(None) == ""


class TestTheLedgerReader:
    def _doc(self, *values):
        return {"entries": [
            {"details": {"siem_signing_key_sha256": v}} for v in values]}

    def test_it_finds_a_recorded_fingerprint(self):
        assert _signing_keys_in_provenance(self._doc(_FPR)) == [_FPR]

    def test_it_dedupes_repeats(self):
        assert _signing_keys_in_provenance(self._doc(_FPR, _FPR)) == [_FPR]

    def test_it_returns_both_when_they_disagree(self):
        """The caller must refuse rather than guess; it can only do that if
        this reports every distinct value."""
        other = "d" * 64
        assert set(_signing_keys_in_provenance(self._doc(_FPR, other))) == {
            _FPR, other}

    def test_a_malformed_entry_is_ignored(self):
        assert _signing_keys_in_provenance(self._doc("nope")) == []

    def test_a_ledger_without_entries_is_ignored(self):
        assert _signing_keys_in_provenance({}) == []
        assert _signing_keys_in_provenance({"entries": "not a list"}) == []


class TestTheWrongKeyIsNoLongerAutoDiscovered:
    def test_the_helper_is_gone(self):
        """Pinned by name: reintroducing it silently re-breaks every operator
        who keeps a SIEM export beside their build artefacts."""
        from tee_crafter.cli.commands import verify_siem_chain as m
        assert not hasattr(m, "_default_pubkey_path")

    def test_a_stray_provenance_pub_does_not_override_a_pinned_key(self, tmp_path):
        """The exact trap: `build_provenance.pub` next to the events used to
        win over `--pinned-pubkey-sha256` and fail every signature."""
        from click.testing import CliRunner
        from tee_crafter.cli.commands.verify_siem_chain import (
            register as _register,
        )
        import click

        events = tmp_path / "events.jsonl"
        fpr = write_chain(events, n=2)
        # A provenance key that signed nothing in this stream.
        (tmp_path / "build_provenance.pub").write_text(
            _pem(Ed25519PrivateKey.generate()), encoding="utf-8")

        @click.group()
        def cli():
            pass
        _register(cli)

        res = CliRunner().invoke(cli, [
            "verify-siem-chain", "--file", str(events),
            "--pinned-pubkey-sha256", fpr, "--no-require-chain-commitment",
        ])
        assert res.exit_code == 0, res.output
        assert "VERIFIED" in res.output


class TestStillRefusesWithNoAnchorAtAll:
    def test_no_anchor_and_no_ledger_is_still_refused(self, tmp_path):
        from click.testing import CliRunner
        from tee_crafter.cli.commands.verify_siem_chain import (
            register as _register,
        )
        import click

        events = tmp_path / "events.jsonl"
        write_chain(events, n=2)

        @click.group()
        def cli():
            pass
        _register(cli)

        res = CliRunner().invoke(cli, [
            "verify-siem-chain", "--file", str(events),
            "--no-require-chain-commitment",
        ])
        assert res.exit_code == 2
        assert "no out-of-band signing key" in res.output


class TestSiemsThatDropEmptyFields:
    """A SIEM eliding `extra: {}` must not read as tampering.

    Datadog's Logs intake omits empty objects. Every host-sidecar event has an
    empty `extra` — `chain_key_commitment` is only attached when a workload
    process shares the sidecar's namespace — so those events come back out of
    the API with the key gone. The producer hashed `"extra":{}` into the
    digest, so recomputing without it fails on a stream that is intact.

    Found reading real `nitro-aws` events back out of Datadog on 2026-08-23:
    chain linked, signatures valid, digests unreproducible.
    """

    def _events(self, path, drop_extra):
        import json as _json
        fpr = write_chain(path, n=2)
        if drop_extra:
            out = []
            for line in path.read_text().splitlines():
                ev = _json.loads(line)
                ev.pop("extra", None)          # what the SIEM did
                out.append(_json.dumps(ev))
            path.write_text("\n".join(out) + "\n", encoding="utf-8")
        return fpr

    def _verify(self, tmp_path, drop_extra):
        import click
        from click.testing import CliRunner
        from tee_crafter.cli.commands.verify_siem_chain import register as _register

        events = tmp_path / "events.jsonl"
        fpr = self._events(events, drop_extra)

        @click.group()
        def cli():
            pass
        _register(cli)
        return CliRunner().invoke(cli, [
            "verify-siem-chain", "--file", str(events),
            "--pinned-pubkey-sha256", fpr, "--no-require-chain-commitment",
        ])

    def test_an_intact_stream_verifies_with_extra_dropped(self, tmp_path):
        res = self._verify(tmp_path, drop_extra=True)
        assert res.exit_code == 0, res.output

    def test_it_still_verifies_when_extra_is_present(self, tmp_path):
        res = self._verify(tmp_path, drop_extra=False)
        assert res.exit_code == 0, res.output

    def test_a_tampered_event_still_fails(self, tmp_path):
        """The restore must not become a licence to accept edits."""
        import json as _json
        import click
        from click.testing import CliRunner
        from tee_crafter.cli.commands.verify_siem_chain import register as _register

        events = tmp_path / "events.jsonl"
        fpr = write_chain(events, n=2)
        lines = events.read_text().splitlines()
        ev = _json.loads(lines[0])
        ev.pop("extra", None)
        ev["measurement_sha256"] = "de" * 48      # the actual tamper
        lines[0] = _json.dumps(ev)
        events.write_text("\n".join(lines) + "\n", encoding="utf-8")

        @click.group()
        def cli():
            pass
        _register(cli)
        res = CliRunner().invoke(cli, [
            "verify-siem-chain", "--file", str(events),
            "--pinned-pubkey-sha256", fpr, "--no-require-chain-commitment",
        ])
        assert res.exit_code == 2

    def test_only_provably_neutral_defaults_are_restored(self):
        """`extra: {}` and absent mean the same thing. A missing `status` and
        `"pass"` do not — nothing like that may be added here."""
        from tee_crafter.cli.commands.verify_siem_chain import _EMPTY_DEFAULTS
        assert _EMPTY_DEFAULTS == {"extra": {}}
