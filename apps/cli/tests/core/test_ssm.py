"""Tests for `core/remote/ssm.py`: SSMPortForward, _find_free_port."""

import socket


from tee_crafter.core.remote.ssm import SSMPortForward, _find_free_port


class TestFindFreePort:
    def test_returns_valid_port(self):
        port = _find_free_port()
        assert isinstance(port, int)
        assert 1024 <= port <= 65535

    def test_port_is_available(self):
        port = _find_free_port()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", port))


class TestSSMPortForwardInit:
    def test_attributes(self):
        tunnel = SSMPortForward("i-12345", 5005, "us-east-1")
        assert tunnel.instance_id == "i-12345"
        assert tunnel.remote_port == 5005
        assert tunnel.region == "us-east-1"
        assert tunnel.local_port == 0

    def test_context_manager_protocol(self):
        tunnel = SSMPortForward("i-12345", 5005, "us-east-1")
        assert hasattr(tunnel, "__enter__")
        assert hasattr(tunnel, "__exit__")

    def test_stop_no_proc(self):
        tunnel = SSMPortForward("i-12345", 5005, "us-east-1")
        tunnel.stop()
