"""Tests for the launch-measurement registry + capture parsers."""
from __future__ import annotations


import pytest

from tee_crafter.core.measurements import capture, registry


class TestRegistry:
    def test_store_lookup_round_trip(self, tmp_path, monkeypatch):
        monkeypatch.setattr(registry, "_REGISTRY_DIR", str(tmp_path))
        meas = "ab" * 48
        path = registry.store("snp-aws", "ami-0123", meas)
        assert path.endswith("snp-aws/ami-0123.json")
        rec = registry.lookup("snp-aws", "ami-0123")
        assert rec["measurement"] == meas
        assert rec["field"] == "measurement"
        assert registry.measurement_value("snp-aws", "ami-0123") == meas

    def test_lookup_miss_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(registry, "_REGISTRY_DIR", str(tmp_path))
        assert registry.lookup("snp-aws", "ami-nope") is None
        assert registry.measurement_value("snp-aws", "ami-nope") is None

    def test_tdx_uses_mrtd_field(self, tmp_path, monkeypatch):
        monkeypatch.setattr(registry, "_REGISTRY_DIR", str(tmp_path))
        registry.store("tdx-gcp", "img-x", "cd" * 48)
        rec = registry.lookup("tdx-gcp", "img-x")
        assert rec["field"] == "mrtd"
        assert rec["mrtd"] == "cd" * 48
        assert registry.measurement_value("tdx-gcp", "img-x") == "cd" * 48

    def test_image_id_sanitised(self, tmp_path, monkeypatch):
        monkeypatch.setattr(registry, "_REGISTRY_DIR", str(tmp_path))
        gcp_id = "projects/p/global/images/tee-crafter-snp-123"
        registry.store("snp-gcp", gcp_id, "11" * 48)
        # Round-trips through the same sanitiser.
        assert registry.measurement_value("snp-gcp", gcp_id) == "11" * 48

    def test_store_many_round_trip(self, tmp_path, monkeypatch):
        monkeypatch.setattr(registry, "_REGISTRY_DIR", str(tmp_path))
        m1, m2 = "ab" * 48, "cd" * 48
        registry.store_many("snp-aws", "ami-99", [m1, m2])
        assert registry.measurement_values("snp-aws", "ami-99") == [m1, m2]
        assert registry.measurement_value("snp-aws", "ami-99") == m1
        rec = registry.lookup("snp-aws", "ami-99")
        assert rec["measurements"] == [m1, m2]

    def test_accepts_shape_vcpu_sensitive_per_gen(self, tmp_path, monkeypatch):
        monkeypatch.setattr(registry, "_REGISTRY_DIR", str(tmp_path))
        # Milan captured at 2+4 vCPU; Genoa not captured at all.
        registry.store_many("snp-aws", "ami-g", ["aa" * 48, "bb" * 48], variants=[
            {"instance_type": "m6a.large", "vcpu": 2, "cpu_gen": "milan", "measurement": "aa" * 48},
            {"instance_type": "m6a.xlarge", "vcpu": 4, "cpu_gen": "milan", "measurement": "bb" * 48},
        ])
        assert registry.accepts_shape("snp-aws", "ami-g", "milan", 2) is True
        assert registry.accepts_shape("snp-aws", "ami-g", "milan", 4) is True
        assert registry.accepts_shape("snp-aws", "ami-g", "milan", 8) is False  # tier not captured
        assert registry.accepts_shape("snp-aws", "ami-g", "genoa", 2) is False  # gen not captured

    def test_accepts_shape_vcpu_independent_gen(self, tmp_path, monkeypatch):
        monkeypatch.setattr(registry, "_REGISTRY_DIR", str(tmp_path))
        registry.store_many(
            "snp-gcp", "img-i", ["cc" * 48],
            variants=[
                {"machine_type": "n2d-standard-2", "vcpu": 2, "cpu_gen": "milan", "measurement": "cc" * 48},
                {"machine_type": "n2d-standard-4", "vcpu": 4, "cpu_gen": "milan", "measurement": "cc" * 48},
            ],
            vcpu_independent_gens=["milan"],
        )
        # Independent gen: any vCPU accepted; other gens still rejected.
        assert registry.accepts_shape("snp-gcp", "img-i", "milan", 64) is True
        assert registry.accepts_shape("snp-gcp", "img-i", "genoa", 2) is False

    def test_accepts_shape_legacy_pin_permissive(self, tmp_path, monkeypatch):
        monkeypatch.setattr(registry, "_REGISTRY_DIR", str(tmp_path))
        # A bare manual pin (no variants) is not retroactively blocked.
        registry.store("snp-aws", "ami-legacy", "ee" * 48)
        assert registry.accepts_shape("snp-aws", "ami-legacy", "milan", 96) is True

    def test_empty_measurement_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setattr(registry, "_REGISTRY_DIR", str(tmp_path))
        with pytest.raises(ValueError):
            registry.store("snp-aws", "ami-x", "")
        with pytest.raises(ValueError):
            registry.store("snp-aws", "ami-x", "unknown")


class TestCaptureParsers:
    def test_parse_snp_measurement(self):
        report = bytes(0x90) + bytes.fromhex("ab" * 48) + bytes(1184 - 0x90 - 48)
        assert capture.parse_snp_measurement(report) == "ab" * 48

    def test_parse_snp_too_short(self):
        with pytest.raises(ValueError):
            capture.parse_snp_measurement(b"\x00" * 16)

    def test_parse_tdx_mrtd(self):
        # Default offset matches the configfs-tsm quote framing (48 + 136 = 184)
        # used by the runtime TDX client and the on-instance reader snippet.
        off = 48 + 136
        quote = bytes(off) + bytes.fromhex("cd" * 48) + bytes(64)
        assert capture.parse_tdx_mrtd(quote) == "cd" * 48
        # An explicit offset still works (e.g. a raw TDREPORT MRTD field).
        raw = bytes(0x130) + bytes.fromhex("ef" * 48) + bytes(64)
        assert capture.parse_tdx_mrtd(raw, offset=0x130) == "ef" * 48

    def test_capture_command_dispatch(self):
        # The SSM channel already runs as root, so the un-sudo'd form must not
        # shell out through sudo.  Asserted by absence rather than by a string
        # prefix: the readers are wrapped in subshells (see
        # ``snp_capture_command``), so the command no longer *starts* with
        # "python3" even though it still drives it.
        aws_cmd = capture.capture_command("snp-aws")
        assert "python3" in aws_cmd
        assert "sudo" not in aws_cmd
        assert "sudo python3" in capture.capture_command("snp-azure", sudo=True)
        assert "configfs-tsm" in capture.capture_command("tdx-gcp")
        assert "configfs-tsm" in capture.capture_command("gpu-cc-gcp")
        assert "0x90" in capture.capture_command("gpu-cc-azure")
        with pytest.raises(ValueError):
            capture.capture_command("nitro-aws")
        with pytest.raises(ValueError):
            capture.capture_command("sgx-azure")

    def test_parse_measurement_line(self):
        text = "noise\nTEE_CRAFTER_MEASUREMENT=" + "ab" * 48 + "\nmore"
        assert capture.parse_measurement_line(text) == "ab" * 48

    def test_parse_measurement_line_none(self):
        assert capture.parse_measurement_line("nothing here") is None

    def test_snp_capture_command_contains_reader(self):
        cmd = capture.snp_capture_command()
        assert "/dev/sev-guest" in cmd
        assert "snpguest" in cmd
