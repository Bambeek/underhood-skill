import importlib.util
import json
import os
import random
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from uh import cli, probe  # noqa: E402


def _state():
    spec = importlib.util.spec_from_file_location("uh_state", ROOT / "underhood-shared" / "state.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- probe

def test_probe_plain_text(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("hello world, this is a config file\n" * 200)
    r = probe.probe(f)
    assert r["magic"] == [] and r["entropy"]["max"] < 5 and r["verdict"].startswith("plain (text")


def test_probe_random_bytes_look_encrypted(tmp_path):
    f = tmp_path / "blob.bin"
    f.write_bytes(random.Random(1).randbytes(256 * 1024))
    r = probe.probe(f)
    assert r["entropy"]["min"] > 7.9 and r["verdict"].startswith("encrypted or compressed")
    assert r["aligned16"] and r["zlib_at"] == []


def test_probe_finds_magic_and_footer(tmp_path):
    png = tmp_path / "a.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    assert "PNG" in probe.probe(png)["magic"]
    pak = tmp_path / "game.pak"
    pak.write_bytes(os.urandom(4096) + b"\x00" * 20 + b"\xe1\x12\x6f\x5a" + b"\x00" * 40)
    assert any("Unreal pak" in m for m in probe.probe(pak)["magic"])
    meta = tmp_path / "global-metadata.dat"
    meta.write_bytes(b"\xaf\x1b\xb1\xfa" + b"\x1d\x00\x00\x00" + b"\x00" * 64)
    assert probe.probe(meta)["magic"] == ["IL2CPP global-metadata.dat"]


def test_probe_mixed_archive_with_zlib_streams(tmp_path):
    index = b"FILE0001 data/items.json\n" * 400
    body = zlib.compress(json.dumps([{"id": i, "name": f"item {i}"} for i in range(4000)]).encode())
    f = tmp_path / "custom.dat"
    f.write_bytes(index + body)
    r = probe.probe(f, block=4096)
    assert r["zlib_at"] and r["zlib_at"][0] == len(index)
    assert "mixed" in r["verdict"] and "zlib streams inside" in r["verdict"]


def test_probe_xor_key_from_known_plaintext(tmp_path):
    key = b"\x5a\xc3\x11"
    plain = b'{"gold": 1200, "level": 7, "name": "hero"}'
    f = tmp_path / "save.dat"
    f.write_bytes(bytes(c ^ key[i % 3] for i, c in enumerate(plain)))
    r = probe.probe(f, known=plain[:9].hex())
    assert r["xor"]["key"] == key.hex(" ") and r["xor"]["period"] == 3


def test_probe_cli_summary_is_short(tmp_path, capsys):
    f = tmp_path / "x.bin"
    f.write_bytes(b"MZ" + bytes(1000))
    cli.main(["probe", str(f)])
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) <= 10 and "Windows PE" in out[2]


# --------------------------------------------------------------------------- state.py

def test_state_init_show_done_unknowns(tmp_path, capsys):
    st = _state()
    root = str(tmp_path)
    assert st.main(["--root", root, "show"]) == 1
    assert st.main(["--root", root, "init", "--target", "Terraria", "--idea", "homing missiles"]) == 0
    assert st.main(["--root", root, "init", "--target", "Other"]) == 1          # no silent overwrite
    st.main(["--root", root, "set", "engine", "XNA/FNA"])
    st.main(["--root", root, "unknown", "who writes HP?"])
    st.main(["--root", root, "done", "recon", "--next", "underhood-dig"])
    data = json.loads((tmp_path / "underhood" / "state.json").read_text(encoding="utf-8"))
    assert data["step"] == "dig" and data["facts"]["engine"] == "XNA/FNA" and data["done"] == ["recon"]
    assert st.main(["--root", root, "resolve", "1", "Player.Hurt"]) == 0
    assert st.main(["--root", root, "resolve", "9", "x"]) == 1
    capsys.readouterr()
    st.main(["--root", root, "show"])
    out = capsys.readouterr().out
    assert "Terraria (game)" in out and "next:   underhood-dig" in out and "?" not in out.split("engine")[1]
    assert len(out.strip().splitlines()) <= 10
