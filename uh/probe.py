"""What are these bytes? Magic, entropy per block, embedded zlib streams and a verdict, in a few lines.

    uh probe data.pak                       # plain, compressed, encrypted or mixed? known container?
    uh probe save.dat --known 7B22          # XOR key from known plaintext ('{"') at offset 0
    uh probe image.bin --known 89504E470D0A1A0A --at 16
    uh probe big.bin --json                 # the same, machine-readable

Read-only and standard library only. Big files are sampled (up to --samples blocks spread across the
file), so it stays fast on multi-GB archives. Entropy is bits per byte: text/code 4-6.5, compressed
7.5-8, encrypted ~8 everywhere. See underhood-dig/references/primer.md for what to do next.
"""
from __future__ import annotations

import json
import math
import re
import zlib
from pathlib import Path

from uh.common import die

# (offset, bytes, name); offset -1 means "anywhere in the last 256 bytes"
MAGIC = [
    (0, b"MZ", "Windows PE (exe/dll)"),
    (0, b"\x7fELF", "ELF executable"),
    (0, b"\xcf\xfa\xed\xfe", "Mach-O 64"),
    (0, b"\xca\xfe\xba\xbe", "Mach-O universal or Java class"),
    (0, b"PK\x03\x04", "ZIP (jar/apk/custom pack)"),
    (0, b"UnityFS", "Unity asset bundle"),
    (0, b"UnityWeb", "Unity web bundle"),
    (0, b"GDPC", "Godot pck"),
    (0, b"\xaf\x1b\xb1\xfa", "IL2CPP global-metadata.dat"),
    (0, b"\x1bLJ", "LuaJIT bytecode"),
    (0, b"\x1bLua", "Lua bytecode"),
    (0, b"\x1f\x8b", "gzip"),
    (0, b"\x28\xb5\x2f\xfd", "zstd"),
    (0, b"\x04\x22\x4d\x18", "LZ4 frame"),
    (0, b"\xfd7zXZ\x00", "xz"),
    (0, b"BZh", "bzip2"),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (0, b"Rar!", "RAR"),
    (0, b"\x89PNG\r\n\x1a\n", "PNG"),
    (0, b"\xff\xd8\xff", "JPEG"),
    (0, b"DDS ", "DDS texture"),
    (0, b"OggS", "Ogg"),
    (0, b"RIFF", "RIFF (WAV/AVI/WebP)"),
    (0, b"FSB5", "FMOD sound bank"),
    (0, b"BKHD", "Wwise sound bank"),
    (0, b"SQLite format 3\x00", "SQLite database"),
    (0, b"BSA\x00", "Bethesda BSA"),
    (0, b"BTDX", "Bethesda BA2"),
    (0, b"\x34\x12\xaa\x55", "Valve VPK"),
    (0, b"\xc1\x83\x2a\x9e", "Unreal package (.uasset/.upk)"),
    (-1, b"\xe1\x12\x6f\x5a", "Unreal pak (footer magic 0x5A6F12E1)"),
]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def magic(head: bytes, tail: bytes) -> list[str]:
    hits = []
    for off, sig, name in MAGIC:
        if off == 0 and head.startswith(sig):
            hits.append(name)
        elif off == -1 and sig in tail:
            hits.append(name)
    return hits


def sample_blocks(path: Path, size: int, block: int, samples: int) -> list[tuple[int, bytes]]:
    """Up to `samples` blocks spread evenly across the file (all blocks for small files)."""
    n = max(1, math.ceil(size / block))
    picks = range(n) if n <= samples else sorted({round(i * (n - 1) / (samples - 1)) for i in range(samples)})
    out = []
    with open(path, "rb") as f:
        for i in picks:
            f.seek(i * block)
            out.append((i * block, f.read(block)))
    return out


def zlib_streams(blocks: list[tuple[int, bytes]], limit: int = 5) -> list[int]:
    """File offsets where a zlib stream really starts (it inflates at least 64 bytes)."""
    found = []
    for base, data in blocks:
        for m in re.finditer(b"\\x78[\\x01\\x5e\\x9c\\xda]", data):
            try:
                d = zlib.decompressobj()
                if len(d.decompress(data[m.start():m.start() + 4096], 64)) >= 64:
                    found.append(base + m.start())
            except zlib.error:
                continue
            if len(found) >= limit:
                return found
    return found


def xor_key(data: bytes, known: bytes) -> tuple[bytes, int]:
    """XOR known plaintext against the data; return the raw key bytes and the shortest repeating period."""
    raw = bytes(a ^ b for a, b in zip(data, known))
    for p in range(1, len(raw) + 1):
        if all(raw[i] == raw[i % p] for i in range(len(raw))):
            return raw, p
    return raw, len(raw)


def verdict(ents: list[float], hits: list[str], streams: list[int], printable: float) -> str:
    lo, hi = min(ents), max(ents)
    if hits:
        kind = "known container"
    elif hi < 6.5:
        kind = "plain (text, code or uncompressed data)" if printable > 0.6 else "plain binary (tables, raw data)"
    elif lo > 7.9:
        kind = "encrypted or compressed throughout (no structure seen: look for a key or a codec)"
    elif lo > 7.5:
        kind = "compressed throughout"
    else:
        kind = "mixed: readable index or header plus compressed/encrypted entries"
    if streams and not hits:
        kind += "; zlib streams inside"
    return kind


def probe(path: str | Path, block: int = 65536, samples: int = 64, known: str | None = None, at: int = 0) -> dict:
    p = Path(path)
    if not p.is_file():
        die(f"no such file: {p}")
    size = p.stat().st_size
    blocks = sample_blocks(p, size, block, samples)
    with open(p, "rb") as f:
        head = f.read(64)
        f.seek(max(0, size - 256))
        tail = f.read(256)
    ents = [entropy(b) for _, b in blocks if b] or [0.0]
    first = blocks[0][1] if blocks else b""
    printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in first) / max(1, len(first))
    streams = zlib_streams(blocks)
    hits = magic(head, tail)
    res = dict(file=str(p), size=size, head=head[:16].hex(" "), magic=hits,
               entropy=dict(min=round(min(ents), 2), median=round(sorted(ents)[len(ents) // 2], 2), max=round(max(ents), 2),
                            blocks=len(ents), block=block),
               printable=round(printable, 2), zlib_at=streams, aligned16=size % 16 == 0,
               verdict=verdict(ents, hits, streams, printable))
    if known:
        try:
            kb = bytes.fromhex(known.replace(" ", ""))
        except ValueError:
            die(f"--known must be hex, got {known!r}")
        with open(p, "rb") as f:
            f.seek(at)
            data = f.read(len(kb))
        raw, period = xor_key(data, kb)
        res["xor"] = dict(at=at, key=raw[:period].hex(" "), period=period, raw=raw.hex(" "))
    return res


def report(r: dict) -> list[str]:
    e = r["entropy"]
    lines = [f"{r['file']}  {r['size']:,} bytes{'  (multiple of 16)' if r['aligned16'] else ''}",
             f"head: {r['head']}",
             f"magic: {', '.join(r['magic']) or 'none known'}",
             f"entropy: min {e['min']}  median {e['median']}  max {e['max']}  ({e['blocks']} x {e['block'] // 1024} KB blocks)",
             f"zlib streams at: {', '.join(hex(o) for o in r['zlib_at'])}" if r["zlib_at"] else "zlib streams: none found",
             f"verdict: {r['verdict']}"]
    if "xor" in r:
        x = r["xor"]
        rep = "repeats, likely the key" if x["period"] < len(x["raw"].split()) else "no repeat inside the known bytes: longer key or not XOR"
        lines.append(f"xor @ {x['at']}: key {x['key']} (period {x['period']}, {rep})")
    return lines


def main(a):
    r = probe(a.file, a.block * 1024, a.samples, a.known, a.at)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print("\n".join(report(r)))


def register(sub):
    import argparse
    p = sub.add_parser("probe", help="identify a file: magic, entropy, zlib streams, XOR key from known plaintext",
                       description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("file")
    p.add_argument("--block", type=int, default=64, help="block size in KB for entropy (default 64)")
    p.add_argument("--samples", type=int, default=64, help="max blocks sampled across the file (default 64)")
    p.add_argument("--known", help="known plaintext as hex, to recover a XOR key")
    p.add_argument("--at", type=int, default=0, help="file offset of the known plaintext (default 0)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=main)
