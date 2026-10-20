"""Brute (hydra/medusa) tests - pure output parsing, argv, lockout gate, findings, run.

No hydra/medusa needed.  Run:  python -m pytest tests/test_brute.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.findings import Category, Severity  # noqa: E402
from redness import brute  # noqa: E402

HYDRA = """Hydra v9.5 starting
[DATA] attacking ssh://10.0.0.5:22/
[22][ssh] host: 10.0.0.5   login: root   password: toor
[22][ssh] host: 10.0.0.5   login: admin   password: admin123
1 of 1 target successfully completed, 2 valid passwords found
"""

MEDUSA = """Medusa v2.2
ACCOUNT FOUND: [ssh] Host: 10.0.0.9 User: svc Password: Summer2025 [SUCCESS]
ACCOUNT CHECK: [ssh] Host: 10.0.0.9 User: bob Password: nope
"""


def test_parse_hydra_hits():
    hits = brute.parse_hydra(HYDRA)
    assert len(hits) == 2
    assert hits[0].service == "ssh" and hits[0].host == "10.0.0.5"
    assert (hits[0].username, hits[0].password) == ("root", "toor")
    assert hits[0].port == "22"


def test_parse_medusa_only_success():
    hits = brute.parse_medusa(MEDUSA)
    assert len(hits) == 1 and hits[0].username == "svc" and hits[0].password == "Summer2025"


def test_parse_empty():
    assert brute.parse_hydra("") == [] and brute.parse_medusa("") == []


def test_lockout_gate_counts():
    assert brute.count_passwords("single", None) == 1
    assert brute.lockout_risk(1, 5) is False
    assert brute.lockout_risk(6, 5) is True


def test_hydra_argv_shape():
    argv = brute.hydra_argv("10.0.0.5", "ssh", user_file="u.txt", password="pass", tasks=4, port="2222")
    assert "-L" in argv and "u.txt" in argv and "-p" in argv and "pass" in argv
    assert "-s" in argv and "2222" in argv
    assert argv[-1] == "ssh://10.0.0.5"


def test_medusa_argv_maps_smb_module():
    argv = brute.medusa_argv("10.0.0.5", "smb", user="admin", password="x")
    assert "-M" in argv and argv[argv.index("-M") + 1] == "smbnt"   # smb -> smbnt
    assert "-h" in argv and "10.0.0.5" in argv


def test_build_findings_critical():
    f = brute.build_findings(brute.parse_hydra(HYDRA), "hydra")[0]
    assert f.severity is Severity.CRITICAL and f.category is Category.PASSWORD
    assert f.meta["username"] == "root" and f.meta["password"] == "toor"


def test_run_brute_with_injected_runner(tmp_path):
    rep, res = brute.run_brute("10.0.0.5", "ssh", tool="hydra", user_file="u.txt", password="toor",
                               loot_dir=str(tmp_path), runner=lambda argv: HYDRA)
    assert len(res.hits) == 2 and len(rep.findings) == 2
    loot = (tmp_path / "brute_hits.txt").read_text()
    assert "10.0.0.5:22:ssh:root:toor" in loot


if __name__ == "__main__":
    import tempfile, pathlib
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
            except TypeError:
                fn(pathlib.Path(tempfile.mkdtemp()))
            print(f"  ok  {name}")
    print("done")
