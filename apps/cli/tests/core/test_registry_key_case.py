"""One image must be one registry key, whatever case the caller spells it in.

Azure resource ids are case-insensitive; filenames are not. The bake takes the
image id from the Azure API and the deploy takes it from ``.env`` or
``--ami-id``, and those really do disagree — on 2026-08-22 ``az`` returned the
resource group as ``TEE-CRAFTER-IMAGES-SNP-RG`` while ``.env`` carried
``tee-crafter-images-snp-rg``. Case-sensitively that is two keys for one image,
so ``lookup`` misses and ``deploy`` refuses sealed ``--secrets-env`` and BYOK on
an image that *is* pinned.

The reason this is worth a dedicated test file rather than one assertion: the
bug is **invisible on the machine most likely to run the tests**. macOS is
case-insensitive by default, so a case-only mismatch resolves to the same file
and everything passes; it only breaks on Linux — CI, and the CLI's own
container. So the tests below never rely on the filesystem to make the
distinction. They assert on ``_sanitize``'s output directly, and where they do
touch disk they check that *one* file exists rather than that a read succeeded.
"""
from __future__ import annotations

import json

import pytest

from tee_crafter.core.measurements import registry

SUB = "060b9553-c6f3-43f4-a6bd-00943d41d0d7"


def _azure_id(rg: str, provider: str = "Microsoft.Compute",
              subs: str = "subscriptions", rgs: str = "resourceGroups") -> str:
    return (f"/{subs}/{SUB}/{rgs}/{rg}/providers/{provider}"
            f"/galleries/tee_crafter_snp_gallery/images/tee_crafter_snp_ubuntu"
            f"/versions/2026.0822.065045")


class TestSanitizeIsCaseFolding:
    """Asserted on the string, not the filesystem — see the module docstring."""

    def test_output_is_lowercase(self):
        s = registry._sanitize(_azure_id("TEE-CRAFTER-IMAGES-SNP-RG"))
        assert s == s.lower()
        assert "TEE-CRAFTER" not in s
        assert "Microsoft.Compute" not in s

    def test_the_two_real_world_spellings_collide(self):
        """The exact pair observed on 2026-08-22."""
        from_api = registry._sanitize(_azure_id("TEE-CRAFTER-IMAGES-SNP-RG"))
        from_env = registry._sanitize(_azure_id("tee-crafter-images-snp-rg"))
        assert from_api == from_env

    @pytest.mark.parametrize("variant", [
        {"rg": "TEE-CRAFTER-IMAGES-SNP-RG"},
        {"rg": "tee-crafter-images-snp-rg"},
        {"rg": "Tee-Crafter-Images-Snp-Rg"},
        {"rg": "TEE-CRAFTER-IMAGES-SNP-RG", "provider": "MICROSOFT.COMPUTE"},
        {"rg": "tee-crafter-images-snp-rg", "provider": "microsoft.compute"},
        {"rg": "tee-crafter-images-snp-rg", "subs": "SUBSCRIPTIONS",
         "rgs": "RESOURCEGROUPS"},
    ])
    def test_every_casing_maps_to_one_key(self, variant):
        canonical = registry._sanitize(_azure_id("tee-crafter-images-snp-rg"))
        assert registry._sanitize(_azure_id(**variant)) == canonical

    def test_case_is_the_only_thing_folded(self):
        """Distinct images must stay distinct — folding must not over-collapse."""
        a = registry._sanitize(_azure_id("rg-one"))
        b = registry._sanitize(_azure_id("rg-two"))
        assert a != b

    def test_different_versions_stay_distinct(self):
        one = registry._sanitize(_azure_id("rg").replace("065045", "065045"))
        two = registry._sanitize(_azure_id("rg").replace("065045", "075741"))
        assert one != two

    def test_aws_ami_ids_are_unaffected(self):
        assert registry._sanitize("ami-0dc3a149b36b33fff") == "ami-0dc3a149b36b33fff"

    def test_gcp_uris_are_unaffected(self):
        uri = ("projects/project-39cf1aef-7543-4f99-84a/global/images/"
               "tee-crafter-tdx-gcp-20260821-204732")
        assert registry._sanitize(uri) == uri.replace("/", "_")

    def test_empty_and_junk_still_degrade_safely(self):
        assert registry._sanitize("") == "unknown"
        assert registry._sanitize("///") == "unknown"
        assert registry._sanitize("   ") == "unknown"


class TestStoreAndLookupAgree(object):
    """Round-trip through a temporary registry root."""

    @pytest.fixture(autouse=True)
    def _tmp_registry(self, tmp_path, monkeypatch):
        monkeypatch.setattr(registry, "_REGISTRY_DIR", str(tmp_path))
        self.root = tmp_path

    def test_store_then_lookup_with_other_casing(self):
        stored = _azure_id("TEE-CRAFTER-IMAGES-SNP-RG")
        queried = _azure_id("tee-crafter-images-snp-rg")
        registry.store("snp-azure", stored, "ab" * 48)
        rec = registry.lookup("snp-azure", queried)
        assert rec is not None, (
            "pinned under the API's casing, looked up with .env's casing — this "
            "is the miss that made a pinned image look unpinned")
        assert rec["measurements"] == ["ab" * 48]

    def test_only_one_file_is_ever_created(self):
        """The filesystem-independent check: count files, don't read them."""
        for rg in ("TEE-CRAFTER-IMAGES-SNP-RG", "tee-crafter-images-snp-rg",
                   "Tee-Crafter-Images-Snp-Rg"):
            registry.store("snp-azure", _azure_id(rg), "cd" * 48)
        files = list((self.root / "snp-azure").glob("*.json"))
        assert len(files) == 1, (
            f"{len(files)} files for one image: {[f.name for f in files]}")
        assert files[0].name == files[0].name.lower()

    def test_stored_image_id_keeps_the_original_spelling(self):
        """Fold the key, not the payload — the record should stay faithful."""
        stored = _azure_id("TEE-CRAFTER-IMAGES-SNP-RG")
        registry.store("snp-azure", stored, "ef" * 48)
        path = list((self.root / "snp-azure").glob("*.json"))[0]
        rec = json.loads(path.read_text())
        assert rec["image_id"] == stored, (
            "the record should record what the caller actually passed")

    def test_distinct_images_still_get_distinct_files(self):
        registry.store("snp-azure", _azure_id("rg-one"), "11" * 48)
        registry.store("snp-azure", _azure_id("rg-two"), "22" * 48)
        assert len(list((self.root / "snp-azure").glob("*.json"))) == 2


class TestShippedRegistryIsNormalised:
    """The files committed to the repo must already be in canonical form.

    Scoped to ``<platform>/<image>.json``, which is the only shape
    ``registry._path`` ever builds.  These used to ``rglob`` the whole tree and
    assume every JSON file under the root was a pin; that broke the moment a
    non-pin file appeared beside them (``aws_ebs_snapshots.json``, the EBS
    snapshot ledger, which is a list rather than a record).  Globbing the exact
    depth the registry uses is both narrower and closer to what is being
    claimed.
    """

    @staticmethod
    def _pin_files():
        import pathlib
        return sorted(pathlib.Path(registry.registry_dir()).glob("*/*.json"))

    def test_no_shipped_pin_has_uppercase_in_its_name(self):
        offenders = [p.name for p in self._pin_files()
                     if p.stem != p.stem.lower()]
        assert not offenders, (
            f"these pins are unreachable on a case-sensitive filesystem: {offenders}")

    def test_every_shipped_pin_is_reachable_by_its_own_image_id(self):
        """Read each record's image_id back and confirm it resolves."""
        checked = 0
        for p in self._pin_files():
            rec = json.loads(p.read_text())
            if not isinstance(rec, dict):
                continue
            image_id, platform = rec.get("image_id"), rec.get("platform")
            if not image_id or not platform:
                continue
            assert registry.lookup(platform, image_id) is not None, (
                f"{p.name} stores image_id {image_id!r} but lookup misses it")
            checked += 1
        assert checked > 0, "no shipped pins found to check"
