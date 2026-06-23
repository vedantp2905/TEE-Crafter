"""``gpu-cc-azure`` must fail closed when its TPM quoting key is not AMD-rooted.

``snp-azure`` and ``gpu-cc-azure`` run on the same Azure paravisor and face the
same problem: there is no ``/dev/sev-guest``, the Hyper-V compatibility layer
fixes ``REPORT_DATA``, and the only thing tying the TPM's quoting key to
AMD-signed evidence is the HCL runtime data — ``REPORT_DATA[:32]`` is
``sha256(runtime_data)``, and that JSON names the key under ``HCLAkPub``.

Both clients grew ``verify_hcl_ak_binding`` and both servers grew the matching
``_tpm_hcl_ak``. Only ``snp-azure`` grew the gate. So on ``gpu-cc-azure`` a
server that presented no usable runtime data printed "NOT ESTABLISHED" and the
client carried on — which means an attacker replaying a captured SNP report from
any other Azure CVM could mint their own attestation key, sign a quote
committing to their own ECDH key and container digest, and be accepted on the
CPU side. (The GPU side is unaffected; NVIDIA signs that and it is enforced
separately.)

These tests read the rendered client template as source. That is deliberate: the
gate is a handful of lines inside ``main()`` after a live TLS handshake, and the
thing worth pinning is that the decision exists, keys on the binding mode, and
defaults to on — not the plumbing around it.
"""
from __future__ import annotations

import ast
import os

import pytest

_TEMPLATES = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "src", "tee_crafter", "templates")

STRICT_ENV = "TEE_CRAFTER_STRICT_SNP_AK_BINDING"

#: The two binding modes that root the quoting key in AMD's signature. They
#: differ only in *where* the key commitment sits: directly in REPORT_DATA on a
#: bare-metal SNP guest, or in the JSON that REPORT_DATA is the digest of on
#: Azure's HCL.
AMD_ROOTED_MODES = ("report_data_strong", "hcl_runtime_data_strong")

#: Both Azure clients must carry the same gate; the platform differs, the
#: paravisor and the attack do not.
CLIENTS = {
    "gpu-cc-azure": os.path.join(_TEMPLATES, "gpu_cc", "azure", "client.template.py"),
    "snp-azure": os.path.join(_TEMPLATES, "snp", "azure", "client.template.py"),
}


def _source(platform: str) -> str:
    with open(CLIENTS[platform], "r", encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(params=sorted(CLIENTS))
def platform(request):
    return request.param


class TestTheGateExistsOnBothAzureClients:

    def test_it_reads_the_strict_env_var(self, platform):
        assert STRICT_ENV in _source(platform)

    def test_it_defaults_to_on(self, platform):
        """The default is the whole point: an operator who sets nothing must get
        the fail-closed behaviour, not the permissive one."""
        src = _source(platform)
        idx = src.index(STRICT_ENV)
        window = src[idx:idx + 200]
        assert '"1"' in window, (
            f"{platform}: the strict gate must default to \"1\"; found: {window!r}")

    def test_it_exits_nonzero_rather_than_warning(self, platform):
        """A gate that prints and continues is not a gate. Whatever the message
        says, there has to be a sys.exit on the failing branch."""
        src = _source(platform)
        idx = src.index(STRICT_ENV)
        window = src[idx:idx + 1600]
        assert "sys.exit(1)" in window

    def test_both_amd_rooted_modes_satisfy_it(self, platform):
        """`hcl_runtime_data_strong` must be accepted alongside
        `report_data_strong`. Accepting only the latter made the gate
        unsatisfiable on every Azure SEV-SNP SKU, because no Azure SKU exposes
        /dev/sev-guest."""
        src = _source(platform)
        idx = src.index(STRICT_ENV)
        window = src[idx:idx + 600]
        for mode in AMD_ROOTED_MODES:
            assert mode in window, f"{platform}: {mode} not accepted by the gate"

    def test_the_source_parses(self, platform):
        """The templates are rendered and executed verbatim on the VM, so a
        syntax error here is a deploy that dies after the spend."""
        ast.parse(_source(platform))


class TestTheGpuCcClientKeysOnABindingMode:
    """The gpu-cc client previously had no `binding_mode` at all — it printed
    ESTABLISHED / NOT ESTABLISHED and fell through either way. The variable is
    what lets a decision be made instead of a message printed."""

    def test_it_assigns_a_binding_mode(self):
        src = _source("gpu-cc-azure")
        assert "binding_mode = " in src

    def test_the_unrooted_path_is_named(self):
        """The failing case needs its own label. Leaving it as None would make
        'no TPM quote at all' and 'a quote signed by an unvouched key' the same
        value, and they are different failures."""
        assert "tpm_quote_unrooted" in _source("gpu-cc-azure")

    def test_the_unrooted_mode_is_not_in_the_accepted_set(self):
        assert "tpm_quote_unrooted" not in AMD_ROOTED_MODES

    def test_the_hcl_check_still_runs_before_the_gate(self):
        """Ordering matters: the gate reads a binding mode that
        verify_hcl_ak_binding is responsible for upgrading. Gate first and it
        would reject every healthy deploy."""
        src = _source("gpu-cc-azure")
        assert src.index("verify_hcl_ak_binding") < src.index(STRICT_ENV)


class TestTheServerSideHalfIsPresent:
    """Rule 1 of not wasting a live run: a verifier-side check can be correct,
    tested, and inert because the server never presents its input. The gpu-cc
    app must actually prefer the HCL-vouched key, or the gate above turns a
    working platform into a hard failure."""

    def test_the_app_prefers_the_hcl_vouched_key(self):
        app = os.path.join(_TEMPLATES, "gpu_cc", "azure", "app.template.py")
        with open(app, "r", encoding="utf-8") as fh:
            src = fh.read()
        assert "_tpm_hcl_ak" in src
        assert src.index("_tpm_hcl_ak") < src.index("tpm2_createprimary"), (
            "the ephemeral fallback must come after the HCL AK attempt")

    def test_the_app_publishes_the_runtime_data(self):
        """Without the runtime data in the certificate extension the client has
        nothing to check the AK against, and the gate would fail closed on a
        healthy VM."""
        app = os.path.join(_TEMPLATES, "gpu_cc", "azure", "app.template.py")
        with open(app, "r", encoding="utf-8") as fh:
            src = fh.read()
        assert "_get_hcl_runtime_data()" in src
        assert "extension_blob +=" in src

    def test_the_app_comment_no_longer_calls_the_ak_unanchored(self):
        """The app used to state that the quote's AK is 'an ephemeral
        owner-hierarchy primary key with no certificate chain, so it is not an
        independent anchor'. That was true before `_tpm_hcl_ak` and false after.
        A stale comment describing the opposite of the code is how the next
        person concludes the gate is wrong and turns it off."""
        app = os.path.join(_TEMPLATES, "gpu_cc", "azure", "app.template.py")
        with open(app, "r", encoding="utf-8") as fh:
            src = fh.read()
        assert "so it is not an independent anchor" not in src
