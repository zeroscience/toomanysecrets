"""SSH audit: banner + KEXINIT weak-algorithm detection."""
import struct

from redness.engines import SshEngine
from redness.engines.base import Target
from redness.engines.ssh_audit import parse_banner, parse_kexinit, weak_algorithms
from redness.findings import Category, Severity


def _namelist(s):
    return struct.pack(">I", len(s)) + s.encode()


def _kexinit(kex, hostkey, enc, mac):
    payload = bytes([0x14]) + b"\x00" * 16          # msg type + cookie
    lists = [kex, hostkey, enc, enc, mac, mac, "none", "none", "", ""]
    for s in lists:
        payload += _namelist(s)
    payload += b"\x00" + b"\x00" * 4                # first_kex_follows + reserved
    return struct.pack(">I", 1 + len(payload) + 4) + bytes([4]) + payload + b"\x00" * 4


_WEAK = _kexinit(
    kex="curve25519-sha256,diffie-hellman-group14-sha1",
    hostkey="ssh-ed25519,ssh-rsa",
    enc="aes256-ctr,3des-cbc,aes128-cbc",
    mac="hmac-sha2-256,hmac-md5,hmac-sha1")
_STRONG = _kexinit(
    kex="curve25519-sha256",
    hostkey="ssh-ed25519,rsa-sha2-512",
    enc="aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
    mac="hmac-sha2-256-etm@openssh.com")


def test_parse_banner():
    assert parse_banner(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n") == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
    assert parse_banner(b"not ssh") is None


def test_parse_kexinit_name_lists():
    k = parse_kexinit(_WEAK)
    assert "diffie-hellman-group14-sha1" in k["kex"]
    assert "ssh-rsa" in k["host_key"] and "3des-cbc" in k["enc_c2s"]
    assert parse_kexinit(b"\x00" * 10) is None


def test_weak_algorithms():
    w = weak_algorithms(parse_kexinit(_WEAK))
    assert "diffie-hellman-group14-sha1" in w["kex"]
    assert set(w["ciphers"]) == {"3des-cbc", "aes128-cbc"}
    assert "hmac-md5" in w["macs"] and "hmac-sha1" in w["macs"]
    assert w["host_key"] == ["ssh-rsa"]
    # a modern offer flags nothing
    assert all(not v for v in weak_algorithms(parse_kexinit(_STRONG)).values())


def test_ssh_engine_flags_weak():
    fs = SshEngine(probe=lambda h: (b"SSH-2.0-OpenSSH_7.4\r\n", _WEAK)).run(Target(host="10.0.0.1"))
    assert [f.id for f in fs] == ["ssh-server", "ssh-weak-crypto"]
    assert fs[0].severity is Severity.INFO and fs[1].severity is Severity.MEDIUM
    assert fs[1].category is Category.CONFIG


def test_ssh_engine_strong_only_banner():
    fs = SshEngine(probe=lambda h: (b"SSH-2.0-OpenSSH_9.6\r\n", _STRONG)).run(Target(host="h"))
    assert [f.id for f in fs] == ["ssh-server"]


def test_ssh_engine_no_banner_no_findings():
    assert SshEngine(probe=lambda h: (b"", b"")).run(Target(host="h")) == []


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            passed += 1
    print(f"{passed} passed")
