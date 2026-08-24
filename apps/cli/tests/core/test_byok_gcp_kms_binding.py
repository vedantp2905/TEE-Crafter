"""BYOK on GCP must authorize the CVM, not merely reach Cloud KMS.

Found on 2026-08-21 while driving the first real ``snp-gcp`` / ``tdx-gcp``
deploys.  ``export_byok_tf_vars`` exported exactly one thing for
``--byok gcp-kms``: ``TF_VAR_byok_gcp_kms=true``, a *boolean* whose only effect
is publishing a private ``googleapis.com`` DNS zone so Cloud KMS is reachable
under deny-all egress.  The customer's key id was never passed to Terraform,
and the CVM service account -- created in the same template with a
``random_id`` suffix, so no operator could pre-grant it -- received
``storage.objectViewer``, ``logging.logWriter`` and ``monitoring.metricWriter``
and no Cloud KMS role at all.

Reachability without authorization: the in-TEE unwrap would reach Cloud KMS and
be refused ``PERMISSION_DENIED`` with BYOK fully configured.  That is precisely
the failure the AWS path documents and prevents via
``TF_VAR_byok_aws_kms_arn`` (see ``export_byok_tf_vars``' own docstring), and
``DH-016`` -- the check that catches the AWS gap -- carried
``platform_filter={"snp-aws", "gpu-cc-aws"}``, so neither the control nor its
detector existed on GCP.

The assertions below pin the whole chain: the CLI exports the key id, the
templates consume that exact variable name, the binding is decrypt-only, and
the count conditional really does gate on emptiness.
"""

import json
import os
import shutil
import subprocess

import pytest

REPO_TEMPLATES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "src", "tee_crafter", "templates",
)

GCP_TEMPLATES = [
    "snp/gcp/main.template.tf",
    "tdx/gcp/main.template.tf",
    "gpu_cc/gcp/main.template.tf",
]

#: The single name the CLI and all three templates must agree on.
KEY_ID_VAR = "byok_gcp_kms_key_id"


def _read(rel: str) -> str:
    with open(os.path.join(REPO_TEMPLATES, rel), "r", encoding="utf-8") as f:
        return f.read()


class TestCliExportsTheKeyId:
    def _export(self, provider, platform, key_id="projects/p/locations/l/"
                                                 "keyRings/r/cryptoKeys/k"):
        from tee_crafter.cli.commands.deploy.byok_mode import export_byok_tf_vars

        class _Cfg:
            pass
        cfg = _Cfg()
        cfg.provider = provider
        cfg.key_id = key_id
        return export_byok_tf_vars(cfg, platform)

    @pytest.fixture(autouse=True)
    def _clean_env(self, monkeypatch):
        # export_byok_tf_vars never overwrites an operator-supplied value, so a
        # leaked var from another test would make these assertions vacuous.
        for name in ("TF_VAR_byok_gcp_kms", "TF_VAR_byok_gcp_kms_key_id",
                     "TF_VAR_byok_aws_kms_arn", "TF_VAR_byok_azure_kv"):
            monkeypatch.delenv(name, raising=False)

    @pytest.mark.parametrize("platform", ["snp-gcp", "tdx-gcp", "gpu-cc-gcp"])
    def test_key_id_is_exported_for_every_gcp_platform(self, platform):
        out = self._export("gcp-kms", platform)
        expected = "projects/p/locations/l/keyRings/r/cryptoKeys/k"
        # The returned dict is only an audit record.  Terraform reads the
        # *process environment*, so asserting on the dict alone passes even
        # when the os.environ write is deleted -- which a mutant proved.
        assert os.environ[f"TF_VAR_{KEY_ID_VAR}"] == expected
        assert out[f"TF_VAR_{KEY_ID_VAR}"] == expected

    @pytest.mark.parametrize("platform", ["snp-gcp", "tdx-gcp", "gpu-cc-gcp"])
    def test_reachability_flag_alone_is_not_enough(self, platform):
        """Both must be exported: the bool routes, the key id authorizes."""
        out = self._export("gcp-kms", platform)
        assert out["TF_VAR_byok_gcp_kms"] == "true"
        assert f"TF_VAR_{KEY_ID_VAR}" in out

    def test_no_key_id_exported_without_byok(self):
        class _Cfg:
            provider = "none"
            key_id = ""
        from tee_crafter.cli.commands.deploy.byok_mode import export_byok_tf_vars
        assert export_byok_tf_vars(_Cfg(), "snp-gcp") == {}

    def test_aws_platform_does_not_get_the_gcp_var(self):
        out = self._export("aws-kms", "snp-aws")
        assert f"TF_VAR_{KEY_ID_VAR}" not in out
        assert "TF_VAR_byok_aws_kms_arn" in out

    def test_operator_value_is_not_overwritten(self, monkeypatch):
        monkeypatch.setenv(f"TF_VAR_{KEY_ID_VAR}", "operator/choice")
        out = self._export("gcp-kms", "snp-gcp")
        assert f"TF_VAR_{KEY_ID_VAR}" not in out
        assert os.environ[f"TF_VAR_{KEY_ID_VAR}"] == "operator/choice"


class TestTemplatesConsumeTheSameName:
    """The drift this guards against: rename one side, not the other.

    A mismatch is silent -- Terraform simply uses the variable's ``""``
    default, the ``count`` evaluates to 0, no binding is created, and the
    deploy succeeds right up to the in-TEE decrypt.
    """

    @pytest.mark.parametrize("rel", GCP_TEMPLATES)
    def test_variable_is_declared(self, rel):
        assert f'variable "{KEY_ID_VAR}"' in _read(rel)

    @pytest.mark.parametrize("rel", GCP_TEMPLATES)
    def test_binding_exists_and_is_decrypt_only(self, rel):
        src = _read(rel)
        assert 'resource "google_kms_crypto_key_iam_member" "vm_byok_decrypt"' in src
        # Decrypt only.  encrypterDecrypter would hand the TEE authority to
        # wrap new DEKs under the customer's key, which it never needs.
        block = src.split('"vm_byok_decrypt"', 1)[1].split("\n}", 1)[0]
        assert 'roles/cloudkms.cryptoKeyDecrypter' in block
        assert 'cryptoKeyEncrypterDecrypter' not in block

    @pytest.mark.parametrize("rel", GCP_TEMPLATES)
    def test_binding_targets_the_vm_service_account(self, rel):
        block = _read(rel).split('"vm_byok_decrypt"', 1)[1].split("\n}", 1)[0]
        assert "google_service_account.vm_sa.email" in block
        assert f"var.{KEY_ID_VAR}" in block

    @pytest.mark.parametrize("rel", GCP_TEMPLATES)
    def test_instance_waits_for_the_binding(self, rel):
        """The VM decrypts during its own boot, so the grant must precede it.

        Scoped to the ``google_compute_instance`` block on purpose: the file
        has several ``depends_on`` lists and matching the first one found
        asserted nothing about the VM.
        """
        src = _read(rel)
        assert 'resource "google_compute_instance"' in src
        instance_block = src.split('resource "google_compute_instance"', 1)[1]
        depends = instance_block.split("depends_on = [", 1)[1].split("]", 1)[0]
        assert "vm_byok_decrypt" in depends


#: These cases drive the real `terraform console`, so they need the binary.
#: The CI unit-test job installs no Terraform, which surfaced as six
#: FileNotFoundError failures rather than skips.  Same guard as
#: test_s3_gateway_endpoint_policy.py.
HAVE_TERRAFORM = shutil.which("terraform") is not None


@pytest.mark.skipif(not HAVE_TERRAFORM,
                    reason="terraform binary not on PATH")
class TestCountConditionalEvaluates:
    """Evaluate the real HCL rather than asserting about its text.

    A text test passes just as happily on ``count = 1`` (always bind, breaking
    every non-BYOK deploy because the empty key id is not a valid resource id)
    or ``count = 0`` (never bind, the original bug).  Offline: the extracted
    snippet declares no providers.
    """

    def _count_expr(self, rel: str) -> str:
        """Lift the binding's own ``count`` expression out of the template.

        Writing the ternary into the harness by hand tested Terraform's
        conditional operator, not this repo: a mutant that pinned the real
        template to ``count = 0`` left the harness untouched and survived.
        """
        block = _read(rel).split('"vm_byok_decrypt"', 1)[1].split("\n}", 1)[0]
        for line in block.splitlines():
            if line.strip().startswith("count"):
                return line.split("=", 1)[1].strip()
        raise AssertionError(f"no count line in vm_byok_decrypt of {rel}")

    def _count(self, tmp_path, rel: str, key_id: str) -> int:
        work = tmp_path / ("count_" + rel.replace("/", "_"))
        work.mkdir(parents=True, exist_ok=True)
        (work / "main.tf").write_text(
            f'variable "{KEY_ID_VAR}" {{\n'
            '  type    = string\n'
            '  default = ""\n'
            '}\n',
            encoding="utf-8",
        )
        subprocess.run(
            ["terraform", "init", "-backend=false", "-input=false", "-no-color"],
            cwd=work, check=True, capture_output=True, timeout=180,
        )
        res = subprocess.run(
            ["terraform", "console", "-no-color",
             f"-var={KEY_ID_VAR}={key_id}"],
            cwd=work, input=self._count_expr(rel) + "\n",
            capture_output=True, text=True, check=True, timeout=180,
        )
        return json.loads(res.stdout.strip().splitlines()[-1])

    @pytest.mark.parametrize("rel", GCP_TEMPLATES)
    def test_empty_key_id_creates_no_binding(self, rel, tmp_path):
        assert self._count(tmp_path, rel, "") == 0

    @pytest.mark.parametrize("rel", GCP_TEMPLATES)
    def test_real_key_id_creates_one_binding(self, rel, tmp_path):
        assert self._count(
            tmp_path, rel,
            "projects/p/locations/us-central1/keyRings/r/cryptoKeys/k") == 1


class TestDh019DetectsTheGap:
    """DH-016's GCP twin.  Checking the boolean instead would pass while the
    in-TEE decrypt still fails, so the check must read the key id."""

    def test_spec_is_registered_for_gcp_platforms(self):
        from tee_crafter.core.audit.checks import CHECKS, GCP_PLATFORMS

        spec = CHECKS["DH-019"]
        assert spec.platform_filter == GCP_PLATFORMS
        assert "byok_gcp_kms_key_id" in spec.title

    def test_dh019_reads_the_key_id_not_the_bool(self):
        """Assert on the actual call, not a text window.

        Searching a window after ``DH-019`` matched the explanatory comment
        above the code, so the assertion held even when the lookup was
        switched to the boolean ``TF_VAR_byok_gcp_kms``.
        """
        import inspect
        from tee_crafter.cli.commands.deploy import flag_audit

        src = inspect.getsource(flag_audit)
        assert '_raw_env("TF_VAR_byok_gcp_kms_key_id")' in src
        assert '_raw_env("TF_VAR_byok_gcp_kms")' not in src
