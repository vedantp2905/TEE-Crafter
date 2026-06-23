"""Tests for `core/remote/azure_ssh.py`: BastionTunnel, SSHPortForward, helpers."""

import socket


from tee_crafter.core.remote.azure_ssh import (
    BastionTunnel,
    SSHPortForward,
    _ssh_key_args,
)
from tee_crafter.core.remote.azure_ssh_tunnel import _find_free_port


class TestFindFreePort:
    def test_returns_valid_port(self):
        port = _find_free_port()
        assert isinstance(port, int)
        assert 1024 <= port <= 65535

    def test_port_is_available(self):
        port = _find_free_port()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", port))

    def test_different_ports(self):
        ports = {_find_free_port() for _ in range(5)}
        assert len(ports) >= 2


class TestSshKeyArgs:
    def test_returns_list(self):
        args = _ssh_key_args("/path/to/key")
        assert args == ["-i", "/path/to/key"]


class TestBastionTunnelInit:
    def test_attributes(self):
        tunnel = BastionTunnel("bastion1", "rg1", "/subscriptions/.../vm1", 22)
        assert tunnel.bastion_name == "bastion1"
        assert tunnel.resource_group == "rg1"
        assert tunnel.resource_port == 22
        assert tunnel.local_port == 0

    def test_context_manager_protocol(self):
        tunnel = BastionTunnel("b", "rg", "vm", 22)
        assert hasattr(tunnel, "__enter__")
        assert hasattr(tunnel, "__exit__")


class TestSSHPortForwardInit:
    def test_attributes(self):
        fwd = SSHPortForward("/key", "azureuser", 2222, 5005)
        assert fwd.ssh_key == "/key"
        assert fwd.user == "azureuser"
        assert fwd.ssh_tunnel_port == 2222
        assert fwd.remote_port == 5005
        assert fwd.local_port == 0

    def test_context_manager_protocol(self):
        fwd = SSHPortForward("/key", "user", 22, 5005)
        assert hasattr(fwd, "__enter__")
        assert hasattr(fwd, "__exit__")

    def test_stop_no_proc(self):
        fwd = SSHPortForward("/key", "user", 22, 5005)
        fwd.stop()
