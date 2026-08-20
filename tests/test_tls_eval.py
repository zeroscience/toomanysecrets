"""TLS analysis tests - pure eval functions, no network/server needed.

Run:  python tests/test_tls_eval.py    (or)   python -m pytest -q
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.engines import tls  # noqa: E402
from redness.findings import Category, Severity  # noqa: E402


def _ids(findings):
    return {f.id: f for f in findings}


def test_legacy_protocol_flagged():
    f = _ids(tls.eval_protocols("dc01", 636, {"TLSv1": True, "TLSv1.2": True, "TLSv1.3": True}))
    assert "tls-legacy-protocol" in f
    assert f["tls-legacy-protocol"].category is Category.TLS
    assert f["tls-legacy-protocol"].affected == ["dc01:636"]


def test_modern_only_no_finding():
    assert tls.eval_protocols("dc01", 636, {"TLSv1.2": True, "TLSv1.3": True}) == []


def test_weak_cipher_rc4_and_bits():
    assert _ids(tls.eval_cipher("h", 443, ("ECDHE-RSA-RC4-SHA", "TLSv1.2", 128)))
    assert _ids(tls.eval_cipher("h", 443, ("AES128-CBC-SHA", "TLSv1.2", 128)))     # CBC
    low = tls.eval_cipher("h", 443, ("DES-CBC3-SHA", "TLSv1.0", 112))              # 3DES, <128
    assert low and low[0].id == "tls-weak-cipher"


def test_strong_cipher_no_finding():
    assert tls.eval_cipher("h", 443, ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)) == []


def test_expired_cert():
    past = time.time() - 86400
    f = _ids(tls.eval_certificate("dc", 636, not_after_epoch=past))
    assert "tls-cert-expired" in f
    assert f["tls-cert-expired"].severity is Severity.HIGH


def test_expiring_cert():
    soon = time.time() + 5 * 86400
    f = _ids(tls.eval_certificate("dc", 636, not_after_epoch=soon))
    assert "tls-cert-expiring" in f
    assert "tls-cert-expired" not in f


def test_valid_cert_no_expiry_finding():
    later = time.time() + 200 * 86400
    f = _ids(tls.eval_certificate("dc", 636, not_after_epoch=later))
    assert "tls-cert-expired" not in f and "tls-cert-expiring" not in f


def test_self_signed_weak_sig_and_key():
    f = _ids(tls.eval_certificate(
        "dc", 636, self_signed=True, sig_alg="sha1", key_bits=1024,
        not_after_epoch=time.time() + 999 * 86400,
    ))
    assert "tls-cert-self-signed" in f
    assert "tls-weak-cert-sig" in f
    assert "tls-weak-cert-key" in f


def test_engine_always_available():
    assert tls.TLSEngine().is_available() is True


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
