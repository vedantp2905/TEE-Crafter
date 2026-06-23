"""B8: a >100-byte length-prefixed ``user_data`` must reach the hardware as 64 bytes.

The attestation-binding preimage the SNP servers hash is

    lp(label) || uint32be(field_count) || lp(nonce) || lp(tls_spki_der) || lp(commitment)

with ``lp(x) == uint32be(len(x)) || x``.  Two things about that shape drove this
file:

* **It is always over 100 bytes.**  The label alone is 29 bytes, a P-256
  SubjectPublicKeyInfo is 91, and the chain-key commitment is 64 hex
  characters — so even an *empty* nonce yields a 204-byte preimage.  The
  ">100 byte user_data" case is not an edge case anyone has to opt into, it is
  what every single attestation does.
* **The nonce is client-supplied.**  A caller chooses its length, so the
  preimage length is attacker-controlled.  Nothing may depend on it.

``_generate_snp_report_data`` collapses the preimage with SHA-256 and
zero-pads to the 64 bytes ``SNP_GET_REPORT`` accepts, so the ioctl never sees
the long buffer.  These tests pin that: any input length, from 0 to 1 MiB, must
produce exactly 64 bytes whose upper half is zero, and distinct inputs must stay
distinct.  Observed live on real AMD Milan silicon as well (AMD EPYC 7R13,
kernel 6.8.0-1061-aws, via SNP_GET_EXT_REPORT) across preimages from 233 bytes
to 1 MiB; see the commit that introduced this file for the full run.

The expected bytes are rebuilt below by ``_lp``/``_v2_preimage`` using
``int.to_bytes`` where the templates use ``struct.pack``, following the
convention in ``test_chain_commitment_binding.py``: an independent
re-implementation cannot silently track a change made to both sides at once.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import textwrap

import pytest

from tee_crafter.core.builder import platforms

REPO_TEMPLATES = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(platforms.__file__)), "..", "..", "templates"))

#: Only these three derive report_data from a user_data preimage; the TDX and
#: GPU-CC platforms take a 64-byte report_data straight from their own paths.
SNP_APP_TEMPLATES = {
    "snp-aws": "snp/aws/app.template.py",
    "snp-azure": "snp/azure/app.template.py",
    "snp-gcp": "snp/gcp/app.template.py",
}

_V2_LABEL = b"tee-crafter/attest-binding/v2"

#: Real field sizes, measured against a live snp-aws VM on 2026-08-21 rather
#: than assumed: the client sends 32 random bytes base64'd (44), the RA-TLS key
#: is EC P-384 so its SubjectPublicKeyInfo DER is 120 bytes (not the 91 a P-256
#: key would give), and the chain-key commitment is 64 hex characters.
PROD_NONCE_LEN = 44
PROD_SPKI_LEN = 120
PROD_COMMIT_LEN = 64

#: 0 and 1 bracket the degenerate end; 44 is production; the rest push well past
#: any plausible internal buffer.  1 MiB stays under the server's 64 MB
#: MAX_PAYLOAD_SIZE so it exercises the hash, not the frame limit.
NONCE_LENGTHS = [0, 1, 44, 100, 101, 1024, 65536, 1048576]


def _lp(field: bytes) -> bytes:
    return len(field).to_bytes(4, "big") + field


def _v2_preimage(*fields: bytes) -> bytes:
    body = _lp(_V2_LABEL) + len(fields).to_bytes(4, "big")
    for field in fields:
        body += _lp(field)
    return body


def _expected_report_data(preimage: bytes) -> bytes:
    return hashlib.sha256(preimage).digest().ljust(64, b"\x00")[:64]


# ---------------------------------------------------------------------------
# Producer side: drive the real template functions in a subprocess
# ---------------------------------------------------------------------------
# Importing an app template puts templates/common on sys.path and mints a
# process-wide audit-log HMAC key; keep both out of the test session.
_PROBE = r'''
import importlib.util, json, os, sys, uuid

common, tpl_root, workdir, out_path = sys.argv[1:5]
sys.path.insert(0, common)
os.environ["TEE_CRAFTER_CHAIN_COMMITMENT_PATH"] = os.path.join(
    workdir, "run", "chain_key_commitment")
os.environ["TEE_AUDIT_LOG_DIR"] = os.path.join(workdir, "log")

apps = json.loads(sys.argv[5])
lengths = json.loads(sys.argv[6])
results = {}
for label, rel in apps.items():
    src = open(os.path.join(tpl_root, rel)).read()
    src = src.replace("{user_imports}", "").replace("{user_logic}", "    return data")
    mod_path = os.path.join(workdir, "app_%s.py" % label.replace("-", "_"))
    with open(mod_path, "w") as fh:
        fh.write(src)
    name = "_probe_" + uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(name, mod_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    entry = {}
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        entry["import_error"] = "%s: %s" % (type(exc).__name__, exc)
        results[label] = entry
        continue
    entry["user_data_size"] = getattr(mod, "_SNP_REPORT_USER_DATA_SIZE", None)
    rows = {}
    for n in lengths:
        nonce = b"A" * n
        spki = b"S" * 91
        commit = b"c" * 64
        pre = mod._attest_binding_preimage(nonce, spki, commit)
        rd = mod._generate_snp_report_data(pre)
        rows[str(n)] = {"preimage_len": len(pre), "preimage_sha256":
                        __import__("hashlib").sha256(pre).hexdigest(),
                        "report_data": rd.hex()}
    entry["rows"] = rows
    results[label] = entry

with open(out_path, "w") as fh:
    json.dump(results, fh)
'''


@pytest.fixture(scope="module")
def probe(tmp_path_factory):
    workdir = tmp_path_factory.mktemp("b8_long_user_data")
    script = workdir / "probe.py"
    script.write_text(textwrap.dedent(_PROBE), encoding="utf-8")
    out = workdir / "probe.json"
    proc = subprocess.run(
        [sys.executable, str(script),
         os.path.join(REPO_TEMPLATES, "common"), REPO_TEMPLATES, str(workdir),
         str(out), json.dumps(SNP_APP_TEMPLATES), json.dumps(NONCE_LENGTHS)],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, f"probe failed:\n{proc.stdout}\n{proc.stderr}"
    data = json.loads(out.read_text())
    for label, entry in data.items():
        assert "import_error" not in entry, f"{label}: {entry['import_error']}"
    return data


@pytest.mark.parametrize("label", sorted(SNP_APP_TEMPLATES))
class TestReportDataShape:
    def test_user_data_size_is_64(self, probe, label):
        """The SNP ABI field is 64 bytes; everything else keys off this."""
        assert probe[label]["user_data_size"] == 64

    def test_always_exactly_64_bytes(self, probe, label):
        for n in NONCE_LENGTHS:
            rd = bytes.fromhex(probe[label]["rows"][str(n)]["report_data"])
            assert len(rd) == 64, f"nonce={n} produced {len(rd)} bytes"

    def test_upper_32_bytes_are_zero(self, probe, label):
        """SHA-256 fills 32 bytes; the rest must be zero padding, not garbage."""
        for n in NONCE_LENGTHS:
            rd = bytes.fromhex(probe[label]["rows"][str(n)]["report_data"])
            assert rd[32:] == b"\x00" * 32, f"nonce={n} padded with {rd[32:].hex()}"

    def test_lower_32_bytes_are_sha256_of_the_preimage(self, probe, label):
        """Recomputed independently, so both sides changing at once still fails."""
        for n in NONCE_LENGTHS:
            row = probe[label]["rows"][str(n)]
            expected = _v2_preimage(b"A" * n, b"S" * 91, b"c" * 64)
            assert row["preimage_len"] == len(expected), (
                f"nonce={n}: template preimage {row['preimage_len']} bytes, "
                f"independent encoding {len(expected)}")
            assert row["preimage_sha256"] == hashlib.sha256(expected).hexdigest()
            assert bytes.fromhex(row["report_data"]) == _expected_report_data(expected)

    def test_over_100_bytes_is_the_normal_case_not_an_edge_case(self, probe, label):
        """Even an empty nonce clears 100 bytes, so B8's scenario is unavoidable."""
        assert probe[label]["rows"]["0"]["preimage_len"] > 100
        prod = probe[label]["rows"][str(PROD_NONCE_LEN)]["preimage_len"]
        assert prod > 100, f"production preimage only {prod} bytes"

    def test_distinct_lengths_stay_distinct(self, probe, label):
        """No truncation: a longer preimage must not collide with a shorter one."""
        seen = {}
        for n in NONCE_LENGTHS:
            rd = probe[label]["rows"][str(n)]["report_data"]
            assert rd not in seen, (
                f"nonce={n} collides with nonce={seen[rd]} — report_data is "
                f"not a function of the whole preimage")
            seen[rd] = n


class TestProductionPreimageLength:
    """Arithmetic on the real field sizes, independent of any template."""

    def test_empty_nonce_still_exceeds_100_bytes(self):
        pre = _v2_preimage(b"", b"S" * PROD_SPKI_LEN, b"c" * PROD_COMMIT_LEN)
        # 4 + 29 label, 4 count, 4 + 0 nonce, 4 + 120 spki, 4 + 64 commitment
        assert len(pre) == 233
        assert len(pre) > 100

    def test_production_nonce_yields_277_bytes(self):
        """Matches the 277 observed on live hardware for the standard nonce."""
        pre = _v2_preimage(b"A" * PROD_NONCE_LEN, b"S" * PROD_SPKI_LEN,
                           b"c" * PROD_COMMIT_LEN)
        assert len(pre) == 277


@pytest.mark.parametrize("label", sorted(SNP_APP_TEMPLATES))
class TestIoctlTruncatesDefensively:
    """The ioctl request buffer must slice to 64 even if report_data grew."""

    def _source(self, label):
        with open(os.path.join(REPO_TEMPLATES, SNP_APP_TEMPLATES[label])) as fh:
            return fh.read()

    def test_request_assignment_is_sliced(self, label):
        src = self._source(label)
        needle = ("req[:_SNP_REPORT_USER_DATA_SIZE] = "
                  "report_data[:_SNP_REPORT_USER_DATA_SIZE]")
        assert needle in src, (
            f"{label}: the ioctl request no longer clamps report_data to "
            f"_SNP_REPORT_USER_DATA_SIZE; an over-long buffer could overrun "
            f"the struct or be silently mis-parsed")

    def test_configfs_inblob_write_is_clamped(self, label):
        """configfs-TSM takes bytes straight from us, so it clamps too.

        Conditional on the platform having that path at all: ``snp-azure``
        reaches the PSP through the GHCB ioctl and IMDS/THIM only, and has no
        configfs-TSM reader to clamp.  Written as a presence check rather than
        a hardcoded skip so that adding the path to any platform later
        immediately requires the clamp with it.
        """
        src = self._source(label)
        if "_get_report_and_certs_via_configfs_tsm" not in src:
            pytest.skip(f"{label} has no configfs-TSM report path")
        assert "report_data[:64].ljust(64, b'\\x00')" in src, (
            f"{label}: the configfs-TSM inblob write no longer clamps to 64")

    def test_report_data_derivation_hashes_before_use(self, label):
        """The long preimage must be hashed, never passed through raw."""
        src = self._source(label)
        assert "def _generate_snp_report_data(user_data: bytes) -> bytes:" in src
        assert "hashlib.sha256(user_data).digest()" in src
