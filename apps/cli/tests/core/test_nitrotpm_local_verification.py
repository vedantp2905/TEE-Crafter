"""Local verification of a NitroTPM attestation document.

The premise this file rests on was established by measurement, not by reading
docs: a NitroTPM attestation document's ``cabundle`` roots at
``CN=aws.nitro-enclaves``, byte-for-byte the certificate already pinned at
``certs/nitro-root.pem``. Verified 2026-08-24 against a real 5163-byte document
from ``i-093b73bbc84395289`` -- five-certificate chain, every link's signature
valid, COSE_Sign1 signature verifying under the TPM leaf's P-384 key.

Three places in the tree previously asserted the opposite, that the Nitro
Enclaves root "endorses a different key hierarchy" so the document could only be
checked by delegating to AWS KMS. That claim was the sole stated reason
``gpu-cc-aws`` reported its CPU evidence as ``SELF-REPORTED, UNVERIFIED``.

The chains below are synthetic but the cryptography is real: actual EC keys,
actual certificate signatures, actual COSE_Sign1 signing. A test built on mocks
would have happily passed against the broken belief too.
"""
from __future__ import annotations

import datetime

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

from tee_crafter.core.keys.nitrotpm import (
    NitroTpmError,
    parse_document,
    verify_document_locally,
)

PCR4 = "aa" * 48
PCR7 = "bb" * 48
BINDING = b"\x11" * 32


def _cert(subject_cn, issuer_cn, issuer_key, *, ca, key=None,
          not_before=None, not_after=None):
    key = key or ec.generate_private_key(ec.SECP384R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or (now - datetime.timedelta(days=1)))
        .not_valid_after(not_after or (now + datetime.timedelta(days=1)))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    return key, builder.sign(issuer_key, hashes.SHA384())


class Chain:
    """A synthetic stand-in for AWS's root -> region -> instance -> TPM chain."""

    def __init__(self, *, leaf_not_after=None):
        # The root is self-signed, so it signs with its own key.
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        _, self.root = _cert(
            "aws.nitro-enclaves", "aws.nitro-enclaves", self.root_key,
            ca=True, key=self.root_key)
        self.mid_key, self.mid = _cert(
            "region.aws.nitro-enclaves", "aws.nitro-enclaves", self.root_key,
            ca=True)
        self.leaf_key, self.leaf = _cert(
            "i-0abc-tpm0000000000000000", "region.aws.nitro-enclaves",
            self.mid_key, ca=False, not_after=leaf_not_after)

    @property
    def root_pem(self) -> str:
        return self.root.public_bytes(serialization.Encoding.PEM).decode()

    def document(self, *, pcrs=None, user_data=BINDING, alg=-35,
                 break_signature=False, cabundle=None):
        pcrs = pcrs if pcrs is not None else {4: bytes.fromhex(PCR4),
                                              7: bytes.fromhex(PCR7)}
        payload = {
            "cabundle": cabundle if cabundle is not None else [
                self.root.public_bytes(serialization.Encoding.DER),
                self.mid.public_bytes(serialization.Encoding.DER),
            ],
            "certificate": self.leaf.public_bytes(serialization.Encoding.DER),
            "digest": "SHA384",
            "module_id": "i-0abc-tpm0000000000000000",
            "nitrotpm_pcrs": pcrs,
            "nonce": None,
            "public_key": b"\x30\x82",
            "timestamp": 1787557586488,
            "user_data": user_data,
        }
        payload_bytes = cbor2.dumps(payload)
        protected = cbor2.dumps({1: alg})
        sig_structure = cbor2.dumps(["Signature1", protected, b"", payload_bytes])
        der = self.leaf_key.sign(sig_structure, ec.ECDSA(hashes.SHA384()))
        r, s = utils.decode_dss_signature(der)
        raw = r.to_bytes(48, "big") + s.to_bytes(48, "big")
        if break_signature:
            raw = bytes(b ^ 0xFF for b in raw[:1]) + raw[1:]
        return cbor2.dumps([protected, {}, payload_bytes, raw])


@pytest.fixture
def chain():
    return Chain()


# --------------------------------------------------------------------------
# parse_document
# --------------------------------------------------------------------------

def test_parse_normalises_pcrs_to_hex(chain):
    payload = parse_document(chain.document())
    assert payload["nitrotpm_pcrs"] == {4: PCR4, 7: PCR7}
    assert payload["digest"] == "SHA384"


def test_parse_refuses_truncated_cbor():
    # 0x9f opens an indefinite-length array that never terminates.  Note that
    # b"definitely not cbor" would *not* work here: its leading 0x64 is a
    # valid 4-character text-string header, so cbor2 decodes it happily and
    # the failure surfaces one check later as "not a COSE_Sign1 4-tuple".
    with pytest.raises(NitroTpmError, match="not valid CBOR"):
        parse_document(b"\x9f\x01\x02")


def test_parse_refuses_a_document_that_decodes_to_a_scalar():
    with pytest.raises(NitroTpmError, match="COSE_Sign1 4-tuple"):
        parse_document(b"definitely not cbor at all")


def test_parse_refuses_a_non_cose_shape():
    with pytest.raises(NitroTpmError, match="COSE_Sign1 4-tuple"):
        parse_document(cbor2.dumps({"not": "a cose array"}))


# --------------------------------------------------------------------------
# The happy path
# --------------------------------------------------------------------------

def test_valid_document_verifies_against_the_pinned_root(chain):
    payload = verify_document_locally(chain.document(), chain.root_pem)
    assert payload["nitrotpm_pcrs"][4] == PCR4
    assert payload["module_id"] == "i-0abc-tpm0000000000000000"


def test_matching_pcr_pin_is_accepted(chain):
    verify_document_locally(chain.document(), chain.root_pem,
                            expected_pcrs={"PCR4": PCR4, 7: PCR7})


def test_matching_channel_binding_is_accepted(chain):
    verify_document_locally(chain.document(), chain.root_pem,
                            expected_user_data=BINDING)


def test_pcr_comparison_is_case_insensitive(chain):
    verify_document_locally(chain.document(), chain.root_pem,
                            expected_pcrs={4: PCR4.upper()})


# --------------------------------------------------------------------------
# Negatives -- each is a way the old "delegate to KMS" design could be lied to
# --------------------------------------------------------------------------

def test_a_different_root_is_refused(chain):
    """The whole point of pinning: another self-signed root must not pass."""
    other = Chain()
    with pytest.raises(NitroTpmError, match="not the pinned AWS Nitro root"):
        verify_document_locally(chain.document(), other.root_pem)


def test_no_root_at_all_is_refused(chain):
    with pytest.raises(NitroTpmError, match="refusing to 'verify'"):
        verify_document_locally(chain.document(), "   ")


def test_tampered_pcr_is_refused(chain):
    doc = chain.document(pcrs={4: bytes.fromhex("cc" * 48),
                               7: bytes.fromhex(PCR7)})
    with pytest.raises(NitroTpmError, match="PCR4 mismatch"):
        verify_document_locally(doc, chain.root_pem,
                                expected_pcrs={4: PCR4, 7: PCR7})


def test_absent_pcr_is_refused_rather_than_skipped(chain):
    """A register the operator asked to pin must not silently go unchecked."""
    doc = chain.document(pcrs={7: bytes.fromhex(PCR7)})
    with pytest.raises(NitroTpmError, match="PCR4 mismatch"):
        verify_document_locally(doc, chain.root_pem, expected_pcrs={4: PCR4})


def test_broken_cose_signature_is_refused(chain):
    with pytest.raises(NitroTpmError, match="COSE_Sign1 signature does not verify"):
        verify_document_locally(chain.document(break_signature=True),
                                chain.root_pem)


def test_payload_tampering_after_signing_is_refused(chain):
    """Re-writing the PCRs without re-signing must break the signature."""
    doc = cbor2.loads(chain.document())
    payload = cbor2.loads(doc[2])
    payload["nitrotpm_pcrs"] = {4: b"\xcc" * 48, 7: b"\xcc" * 48}
    doc[2] = cbor2.dumps(payload)
    with pytest.raises(NitroTpmError, match="signature does not verify"):
        verify_document_locally(cbor2.dumps(doc), chain.root_pem)


def test_wrong_channel_binding_is_refused(chain):
    """A document valid for another session must not attest this one."""
    with pytest.raises(NitroTpmError, match="user_data does not match"):
        verify_document_locally(chain.document(user_data=b"\x22" * 32),
                                chain.root_pem, expected_user_data=BINDING)


def test_absent_user_data_is_refused_when_a_binding_is_required(chain):
    with pytest.raises(NitroTpmError, match="user_data does not match"):
        verify_document_locally(chain.document(user_data=None),
                                chain.root_pem, expected_user_data=BINDING)


def test_expired_leaf_is_refused(chain):
    stale = Chain(leaf_not_after=datetime.datetime.now(datetime.timezone.utc)
                  - datetime.timedelta(minutes=5))
    with pytest.raises(NitroTpmError, match="validity window"):
        verify_document_locally(stale.document(), stale.root_pem)


def test_a_leaf_not_issued_by_the_chain_is_refused(chain):
    """Splice another chain's leaf in: name chaining must catch it."""
    other = Chain()
    doc = other.document(cabundle=[
        chain.root.public_bytes(serialization.Encoding.DER),
        chain.mid.public_bytes(serialization.Encoding.DER),
    ])
    with pytest.raises(NitroTpmError, match="chain broken|signature invalid"):
        verify_document_locally(doc, chain.root_pem)


def test_missing_leaf_certificate_is_refused(chain):
    doc = cbor2.loads(chain.document())
    payload = cbor2.loads(doc[2])
    del payload["certificate"]
    doc[2] = cbor2.dumps(payload)
    with pytest.raises(NitroTpmError, match="no leaf certificate"):
        verify_document_locally(cbor2.dumps(doc), chain.root_pem)


def test_unsupported_cose_algorithm_is_refused(chain):
    """Not an accepted algorithm rather than falling back to a default."""
    with pytest.raises(NitroTpmError, match="unsupported"):
        verify_document_locally(chain.document(alg=-8), chain.root_pem)
