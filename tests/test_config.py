"""Tool-path config tests - load/save, PATH apply, resolve, status. Uses $REDNESS_CONFIG.

Run:  python -m pytest tests/test_config.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness import config  # noqa: E402


def test_load_default_when_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("REDNESS_CONFIG", str(tmp_path / "nope.json"))
    assert config.load() == {"tool_paths": {}}


def test_update_save_and_resolve(tmp_path, monkeypatch):
    monkeypatch.setenv("REDNESS_CONFIG", str(tmp_path / "cfg.json"))
    fake = tmp_path / "nxc.exe"
    fake.write_text("x")                                  # a real file so isfile() is True
    config.update_tool_paths({"nxc": str(fake)})
    assert (tmp_path / "cfg.json").exists()
    assert config.resolve("nxc") == str(fake)             # exact configured path wins
    assert config.load()["tool_paths"]["nxc"] == str(fake)


def test_apply_prepends_dir_to_path(tmp_path, monkeypatch):
    monkeypatch.setenv("REDNESS_CONFIG", str(tmp_path / "cfg.json"))
    monkeypatch.setenv("PATH", "/usr/bin")
    fake = tmp_path / "john"
    fake.write_text("x")
    added = config.apply({"tool_paths": {"john": str(fake)}})
    assert str(tmp_path) in added
    assert os.environ["PATH"].split(os.pathsep)[0] == str(tmp_path)


def test_blank_clears_entry(tmp_path, monkeypatch):
    monkeypatch.setenv("REDNESS_CONFIG", str(tmp_path / "cfg.json"))
    fake = tmp_path / "hashcat"
    fake.write_text("x")
    config.update_tool_paths({"hashcat": str(fake)})
    assert "hashcat" in config.load()["tool_paths"]
    config.update_tool_paths({"hashcat": ""})             # blank removes it
    assert "hashcat" not in config.load()["tool_paths"]


def test_status_shape(tmp_path, monkeypatch):
    monkeypatch.setenv("REDNESS_CONFIG", str(tmp_path / "cfg.json"))
    st = config.status()
    names = {t["name"] for t in st}
    assert {"nxc", "nmap", "john", "hydra"}.issubset(names)
    for t in st:
        assert set(t) == {"name", "label", "configured", "resolved", "available"}


def test_ignores_nonexistent_configured_path(tmp_path, monkeypatch):
    monkeypatch.setenv("REDNESS_CONFIG", str(tmp_path / "cfg.json"))
    config.update_tool_paths({"nmap": str(tmp_path / "ghost")})   # path does not exist
    # resolve falls back to PATH (which() may be None), never the bogus path
    assert config.resolve("nmap") != str(tmp_path / "ghost")


if __name__ == "__main__":
    import tempfile, pathlib

    class _MP:
        def setenv(self, k, v): os.environ[k] = v
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(pathlib.Path(tempfile.mkdtemp()), _MP())
            print(f"  ok  {name}")
    print("done")
