"""``verify-siem-chain`` reads the attested chain commitment automatically.

Before this, an operator had to pass ``--expect-chain-commitment <hex>`` by
hand.  Nobody does that on a cron job, so in practice the SIEM check ran
*without* the one comparison that makes it more than self-consistent: the
commitment travels inside the very event stream it is meant to authenticate, so
comparing events against each other proves only that whoever produced them was
consistent.

The value is now discovered from the signed ``build_provenance.json`` the
deploy pipeline already writes.  These tests pin the three behaviours that make
that safe to rely on:

* it is found and used when present;
* a ledger whose chain or signature does not verify is **refused**, not
  silently ignored — otherwise tampering with the ledger would *weaken* the
  check the ledger exists to strengthen;
* two disagreeing ledgers are refused rather than guessed between.
"""
from __future__ import annotations

import json

import click
import pytest
from click.testing import CliRunner

from tee_crafter.cli.audit_helpers import save_audit_trail
from tee_crafter.cli.commands.verify_siem_chain import (
    OPERATOR_FLAG_SOURCE,
    discover_attested_chain_commitment,
    register,
    resolve_expected_commitment,
)
from tee_crafter.cli.constants import console as cli_console
from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.core.audit import build_layout as _layout

COMMITMENT = "ab" * 32
OTHER_COMMITMENT = "cd" * 32


@pytest.fixture
def cli_app():
    @click.group()
    def cli():
        pass

    register(cli)
    return cli


@pytest.fixture
def signing_key(tmp_path, monkeypatch):
    """Give the build ledger a real Ed25519 signing key.

    Without this the ledger is written UNSIGNED, and an unsigned ledger is
    deliberately not trusted for pinning — so every "it works" test here has
    to sign, or it would be asserting the wrong path.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    monkeypatch.setenv("TEE_CRAFTER_PROVENANCE_SIGNING_KEY", pem)
    return pem


def _emit_provenance(dest, commitment=COMMITMENT, *, entries=None):
    """Write a build ledger carrying *commitment*.

    Mirrors what ``client_step.py`` does on a successful verify: the fields
    ``extract_attestation_report`` harvested from the client are splatted into
    ``BuildAuditTrail.record``, so the commitment lands in an entry's
    ``details``.

    Whether the result is *signed* depends on the ``signing_key`` fixture being
    active, which is exactly the distinction the code under test cares about.
    """
    audit = BuildAuditTrail()
    audit.set_metadata("0.1.0", str(dest))
    audit.set_tee_platform("snp-aws")
    for value in (entries if entries is not None else [commitment]):
        audit.record(
            "Phase 5: Post-Deploy", "End-to-end client verification", "pass",
            attestation_verified=True,
            chain_key_commitment=value,
        )
    save_audit_trail(audit, str(dest), cli_console)
    return _layout.provenance_json(str(dest))


def _events_file(tmp_path, name="events.ndjson"):
    path = tmp_path / name
    path.write_text("", encoding="utf-8")
    return str(path)


@pytest.fixture
def no_signing_key(tmp_path, monkeypatch):
    """Guarantee the build ledger comes out UNSIGNED.

    Tests that assert the unsigned path must not depend on the developer's
    machine. `load_signing_key` tries four resolvers in order -- env PEM, env
    path, OS keyring, then the module-level `_DEFAULT_KEY_PATH`
    (`~/.tee-crafter/provenance-signing-key.pem`, computed at import time, so
    patching HOME is too late). Anyone who has run
    `tee-crafter audit-gen-signing-key` has that file, and this test then saw a
    *signed* ledger and failed -- passing only on machines with no key
    configured. Neutralise all four.
    """
    from tee_crafter.core.audit import signing as _signing

    monkeypatch.delenv("TEE_CRAFTER_PROVENANCE_SIGNING_KEY", raising=False)
    monkeypatch.delenv("TEE_CRAFTER_PROVENANCE_SIGNING_KEY_FILE", raising=False)
    monkeypatch.delenv("TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL", raising=False)
    monkeypatch.setattr(_signing, "_from_keyring", lambda: None)
    monkeypatch.setattr(_signing, "_DEFAULT_KEY_PATH",
                        tmp_path / "absent" / "provenance-signing-key.pem")
    return None


class TestDiscovery:
    def test_finds_the_commitment_in_a_signed_ledger(self, tmp_path, signing_key):
        _emit_provenance(tmp_path)
        found, source, warning = discover_attested_chain_commitment(
            _events_file(tmp_path))
        assert found == COMMITMENT
        assert source.endswith("build_provenance.json")
        assert warning == ""

    def test_unsigned_ledger_is_not_used_but_warns(self, tmp_path, no_signing_key):
        """No signing key configured, so the ledger is written unsigned.

        This is the common development case, and it must neither be trusted
        (an attacker who rewrites the ledger can also delete the signature)
        nor be fatal (it would break every unsigned build). The commitment is
        skipped and the operator is told why.
        """
        _emit_provenance(tmp_path)
        found, source, warning = discover_attested_chain_commitment(
            _events_file(tmp_path))
        assert found is None
        assert source == ""
        assert "UNSIGNED" in warning
        assert "--expect-chain-commitment" in warning

    def test_absent_ledger_is_not_an_error(self, tmp_path):
        """No ledger means behave exactly as before this lookup existed."""
        found, source, warning = discover_attested_chain_commitment(
            _events_file(tmp_path))
        assert found is None
        assert source == ""
        assert warning == ""

    def test_ledger_without_a_commitment_is_not_an_error(self, tmp_path,
                                                         signing_key):
        audit = BuildAuditTrail()
        audit.set_metadata("0.1.0", str(tmp_path))
        audit.set_tee_platform("snp-aws")
        audit.record("Build", "no attestation fields here", "pass")
        save_audit_trail(audit, str(tmp_path), cli_console)
        found, _, warning = discover_attested_chain_commitment(
            _events_file(tmp_path))
        assert found is None
        assert warning == ""

    def test_broken_hash_chain_is_refused_not_ignored(self, tmp_path,
                                                      signing_key):
        """The important one.

        If a broken ledger fell back to "no expected value", an attacker who
        could edit the ledger would *remove* the pinning rather than fail it.
        """
        prov = _emit_provenance(tmp_path)
        doc = json.loads(open(prov, encoding="utf-8").read())
        # Alter a field that feeds the entry digest but is NOT the commitment,
        # so the refusal cannot be attributed to the commitment being
        # unreadable — the chain itself has to be what fails.
        doc["entries"][0]["step"] = "tampered"
        with open(prov, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)

        with pytest.raises(click.ClickException) as exc:
            discover_attested_chain_commitment(_events_file(tmp_path))
        message = str(exc.value)
        # Assert on the *hash chain* specifically. Asserting only the generic
        # "Refusing to pin" let a mutant that skipped the chain check survive:
        # the tampered document also fails its signature check, so the generic
        # phrase still appeared and the test passed for the wrong reason.
        assert "hash chain does not verify" in message, message
        assert "--expect-chain-commitment" in message

    def test_signed_ledger_with_a_wrong_signature_is_refused(self, tmp_path,
                                                             signing_key):
        """A present-but-invalid signature is tampering, not a dev build.

        Distinct from the unsigned case above: here the ledger claims to be
        signed, so degrading to a warning would let an attacker who corrupts
        the signature silently remove the pinning.
        """
        _emit_provenance(tmp_path)
        from tee_crafter.core.audit import build_layout as layout
        sig_path = layout.resolve_provenance_sig(str(tmp_path))
        with open(sig_path, "w", encoding="utf-8") as f:
            f.write("00" * 64)

        with pytest.raises(click.ClickException) as exc:
            discover_attested_chain_commitment(_events_file(tmp_path))
        assert "signature does not verify" in str(exc.value)

    def test_two_disagreeing_commitments_are_refused(self, tmp_path, signing_key):
        _emit_provenance(tmp_path, entries=[COMMITMENT, OTHER_COMMITMENT])

        with pytest.raises(click.ClickException) as exc:
            discover_attested_chain_commitment(_events_file(tmp_path))
        assert "more than one attested chain-key commitment" in str(exc.value)

    def test_malformed_commitment_values_are_skipped(self, tmp_path, signing_key):
        """Not 64 hex characters is a malformed ledger, not a commitment.

        The clients reject any other width, so accepting a looser value here
        would mean the one place an operator looks to confirm the value
        disagrees with the code that enforces it.
        """
        _emit_provenance(tmp_path, entries=["abcd", "z" * 64])
        found, _, _ = discover_attested_chain_commitment(_events_file(tmp_path))
        assert found is None


class TestPrecedence:
    """Which value gets compared, asserted directly rather than through output.

    Driving this through the Click command could not distinguish the cases: on
    a failing run the success panel is never printed, and when it is printed it
    shows only the first 16 characters of the commitment. A mutant that let
    discovery override an explicit ``--expect-chain-commitment`` survived a
    test written that way.
    """

    def test_explicit_flag_wins_over_discovery(self, tmp_path, signing_key):
        """An operator who names a value must get exactly that value compared.

        Discovery silently overriding the flag would report a pass against a
        commitment the operator never asked for.
        """
        _emit_provenance(tmp_path)  # records COMMITMENT, not OTHER_COMMITMENT
        value, source, _ = resolve_expected_commitment(
            _events_file(tmp_path), OTHER_COMMITMENT)
        assert value == OTHER_COMMITMENT
        assert source == OPERATOR_FLAG_SOURCE

    def test_discovery_fills_in_when_no_flag_given(self, tmp_path, signing_key):
        _emit_provenance(tmp_path)
        value, source, _ = resolve_expected_commitment(
            _events_file(tmp_path), None)
        assert value == COMMITMENT
        assert source.endswith("build_provenance.json")

    def test_no_auto_skips_discovery(self, tmp_path, signing_key):
        _emit_provenance(tmp_path)
        value, source, _ = resolve_expected_commitment(
            _events_file(tmp_path), None, no_auto=True)
        assert value is None
        assert source == ""

    def test_dropping_the_requirement_skips_discovery(self, tmp_path, signing_key):
        """``--no-require-chain-commitment`` means there is nothing to pin."""
        _emit_provenance(tmp_path)
        value, _, _ = resolve_expected_commitment(
            _events_file(tmp_path), None, no_require=True)
        assert value is None

    def test_explicit_flag_is_honoured_even_with_a_broken_ledger(
            self, tmp_path, signing_key):
        """The documented escape hatch must actually work.

        Every refusal message tells the operator to pass
        --expect-chain-commitment; if discovery still ran and raised, that
        advice would be a dead end.
        """
        prov = _emit_provenance(tmp_path)
        doc = json.loads(open(prov, encoding="utf-8").read())
        doc["entries"][0]["step"] = "tampered"
        with open(prov, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)

        value, source, _ = resolve_expected_commitment(
            _events_file(tmp_path), OTHER_COMMITMENT)
        assert value == OTHER_COMMITMENT
        assert source == OPERATOR_FLAG_SOURCE


class TestCommandWiring:

    def test_opt_out_flag_disables_discovery(self, cli_app, tmp_path,
                                             signing_key):
        """A tampered ledger must not block an operator who never asked for it."""
        prov = _emit_provenance(tmp_path)
        doc = json.loads(open(prov, encoding="utf-8").read())
        doc["entries"][0]["hash"] = "00" * 32
        with open(prov, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)

        events = tmp_path / "events.ndjson"
        events.write_text("", encoding="utf-8")
        runner = CliRunner()
        res = runner.invoke(cli_app, [
            "verify-siem-chain", "--file", str(events),
            "--no-auto-chain-commitment",
            "--pinned-pubkey-sha256", "ef" * 32,
        ], catch_exceptions=False)
        # Exit 2 for the empty window, NOT a ClickException about the ledger.
        assert res.exit_code == 2
        assert "Refusing to pin" not in res.output
