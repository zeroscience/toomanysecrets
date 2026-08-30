"""Offensive /action bridge - token gating, loopback guard, arm/execute routing, catalog.

Spins a real LiveServer on 127.0.0.1:0 and drives it over HTTP with stubbed on_arm/on_execute
(the action logic itself is tested in test_actions_offensive). Run:
    python tests/test_bridge_offensive.py   (or)   python -m pytest -q
"""
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from redness.events import EventBus  # noqa: E402
from redness.live import LiveServer  # noqa: E402

OFF_CATALOG = [
    {"id": "enum-smb", "label": "Enumerate SMB", "node_types": ["host"], "offensive": False},
    {"id": "kerberoast-user", "label": "Kerberoast", "node_types": ["user"], "offensive": True},
]


def _post(url, data, headers):
    req = urllib.request.Request(
        url, data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json", **headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, None


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, json.loads(r.read() or b"{}")


def _serve(**kw):
    s = LiveServer(EventBus(), host="127.0.0.1", port=0, **kw)
    s.start()
    return s


def test_loopback_guard_refuses_non_loopback():
    with pytest.raises(RuntimeError):
        LiveServer(EventBus(), host="0.0.0.0", enable_offensive=True)


def test_offensive_disabled_returns_403():
    s = _serve(on_arm=lambda p: {}, on_execute=lambda p: None)   # not enabled
    try:
        code, _ = _post(s.url + "action/arm", {"action": "kerberoast-user", "target": "svc"},
                        {"X-Redness-Offensive": "whatever"})
        assert code == 403
    finally:
        s.stop()


def test_bad_offensive_token_returns_403():
    s = _serve(on_arm=lambda p: {"arm_token": "T"}, enable_offensive=True)
    try:
        code, _ = _post(s.url + "action/arm", {"action": "kerberoast-user", "target": "svc"},
                        {"X-Redness-Offensive": "wrong-token"})
        assert code == 403
    finally:
        s.stop()


def test_arm_ok_with_correct_token():
    s = _serve(on_arm=lambda p: {"arm_token": "TOK", "expires_in": 120, "banner": "OFFENSIVE ..."},
               enable_offensive=True)
    try:
        code, body = _post(s.url + "action/arm", {"action": "kerberoast-user", "target": "svc"},
                           {"X-Redness-Offensive": s.offensive_token})
        assert code == 200 and body["arm_token"] == "TOK" and "banner" in body
    finally:
        s.stop()


def test_arm_rate_limited_maps_to_429():
    def boom(p):
        raise Exception("rate limited: too many arm requests")
    s = _serve(on_arm=boom, enable_offensive=True)
    try:
        code, _ = _post(s.url + "action/arm", {"action": "kerberoast-user", "target": "svc"},
                        {"X-Redness-Offensive": s.offensive_token})
        assert code == 429
    finally:
        s.stop()


def test_execute_routes_with_confirm_header():
    seen = {}

    def on_exec(p):
        seen.update(p)

    s = _serve(on_execute=on_exec, enable_offensive=True)
    try:
        code, _ = _post(s.url + "action/execute",
                        {"action": "kerberoast-user", "target": "svc", "arm_token": "TOK"},
                        {"X-Redness-Offensive": s.offensive_token, "X-Redness-Confirm": "kerberoast-user"})
        assert code == 202
        import time
        for _ in range(50):                       # on_execute runs on a worker thread
            if seen:
                break
            time.sleep(0.02)
        assert seen.get("confirm") == "kerberoast-user" and seen.get("arm_token") == "TOK"
    finally:
        s.stop()


def test_catalog_hides_offensive_unless_enabled():
    s = _serve(on_action=lambda p: None, action_catalog=OFF_CATALOG)   # offensive disabled
    try:
        _, cat = _get(s.url + "actions")
        assert [a["id"] for a in cat] == ["enum-smb"]     # offensive hidden
    finally:
        s.stop()


def test_catalog_shows_offensive_when_enabled():
    s = _serve(on_action=lambda p: None, action_catalog=OFF_CATALOG,
               on_arm=lambda p: {}, on_execute=lambda p: None, enable_offensive=True)
    try:
        _, cat = _get(s.url + "actions")
        assert {"enum-smb", "kerberoast-user"} == {a["id"] for a in cat}
        assert s.offensive_token and len(s.offensive_token) >= 20
    finally:
        s.stop()


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
            except Exception as e:
                print(f"  FAIL {name}: {e}")
                continue
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
