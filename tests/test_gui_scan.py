"""GUI bridge tests — CSRF token, POST /scan hook, token injection. No browser needed.

Run:  python tests/test_gui_scan.py    (or)   python -m pytest -q
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.events import EventBus  # noqa: E402
from redness.live.bridge import LiveServer  # noqa: E402


def _post(url, data, headers=None):
    req = urllib.request.Request(url, data=json.dumps(data).encode(),
                                method="POST", headers=headers or {})
    return urllib.request.urlopen(req, timeout=3)


def test_index_injects_token_and_scan_flag():
    got = {}
    srv = LiveServer(EventBus(), port=0, on_scan=lambda p: got.update(p))
    url = srv.start()
    try:
        html = urllib.request.urlopen(url, timeout=3).read().decode()
        assert "__CSRF_TOKEN__" not in html            # placeholder replaced
        assert srv.token in html
        assert 'name="scan-enabled" content="1"' in html
    finally:
        srv.stop()


def test_scan_requires_token():
    srv = LiveServer(EventBus(), port=0, on_scan=lambda p: None)
    url = srv.start()
    try:
        try:
            _post(url + "scan", {"targets": ["10.0.0.1"]})   # no token header
            assert False, "should have been rejected"
        except urllib.error.HTTPError as e:
            assert e.code == 403
    finally:
        srv.stop()


def test_scan_runs_handler_with_token():
    seen = {}
    ev = []
    done = []

    def handler(params):
        seen.update(params)
        done.append(True)

    srv = LiveServer(EventBus(), port=0, on_scan=handler)
    url = srv.start()
    try:
        resp = _post(url + "scan", {"targets": ["10.0.0.9"], "domain": "acme"},
                     {"Content-Type": "application/json", "X-REDNESS-Token": srv.token})
        assert resp.status == 202
        for _ in range(30):
            if done:
                break
            time.sleep(0.05)
        assert seen.get("targets") == ["10.0.0.9"]
        assert seen.get("domain") == "acme"
    finally:
        srv.stop()


def test_scan_disabled_when_no_handler():
    srv = LiveServer(EventBus(), port=0)          # on_scan=None -> disabled
    url = srv.start()
    try:
        html = urllib.request.urlopen(url, timeout=3).read().decode()
        assert 'name="scan-enabled" content="0"' in html
        try:
            _post(url + "scan", {"targets": ["x"]},
                  {"X-REDNESS-Token": srv.token})
            assert False, "should be disabled"
        except urllib.error.HTTPError as e:
            assert e.code == 403
    finally:
        srv.stop()


def test_logo_served():
    srv = LiveServer(EventBus(), port=0)
    url = srv.start()
    try:
        body = urllib.request.urlopen(url + "logo.svg", timeout=3).read().decode()
        assert "<svg" in body and "ZeroScience" in body
    finally:
        srv.stop()


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
