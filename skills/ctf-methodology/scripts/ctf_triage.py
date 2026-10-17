#!/usr/bin/env python3
"""Triage a CTF challenge: classify it by signals, print the opening moves, and
validate a flag's format. A fast first-step helper for authorized CTF / exam /
lab challenges — it reads a local artifact's header and known signals only; it
never attacks anything and never leaves the machine.

Categories: web, crypto, pwn, reversing, forensics, stego, osint, network, misc.

Usage:
  ctf_triage.py classify [--file PATH] [--url URL] [--port N] [--hint TEXT]
  ctf_triage.py playbook <category>
  ctf_triage.py flag-check "FLAG{...}" [--format REGEX]
Exit: 0 ok / valid flag; 1 invalid flag; 3 usage error. Stdlib only, offline.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DEFAULT_FLAG_RE = r"^[A-Za-z0-9_]{1,20}\{[ -~]+\}$"   # e.g. FLAG{...}, picoCTF{...}

# Per-category playbook: the tell, the opening moves, go-to tools, classic traps.
PLAYBOOKS: dict[str, dict] = {
    "web": {
        "moves": ["Map the app + params (burp/ffuf); read JS and comments",
                  "Test by class: authn/JWT/OAuth, injection (SQLi/NoSQL/SSTI/XXE),"
                  " SSRF, IDOR, XSS, deserialization, request smuggling",
                  "Check robots.txt, /.git, backups, source maps, error leaks"],
        "tools": ["burpsuite", "ffuf/gobuster", "curl", "jwt_tool", "sqlmap (lab only)"],
        "traps": ["client-side 'auth' / hidden fields", "verb tampering",
                  "second-order injection", "flag behind a header/cookie"],
    },
    "crypto": {
        "moves": ["Identify the scheme + encoding (base64/hex/ascii)",
                  "RSA: try small-e/Håstad, common modulus, Wiener, Fermat close primes",
                  "Block: ECB cut-and-paste, CBC bit-flip, padding oracle",
                  "Hash: length-extension; PRNG: predict/seed recovery; XOR: known-plaintext"],
        "tools": ["python+pycryptodome", "sage", "RsaCtfTool", "CyberChef", "hashcat/john"],
        "traps": ["nonce/IV reuse", "textbook RSA", "weak/low entropy keys",
                  "home-rolled 'encryption' that is really encoding"],
    },
    "pwn": {
        "moves": ["`checksec` the binary; find the bug (overflow/fmt-string/UAF)",
                  "ret2win → ret2libc/ROP; leak libc then one_gadget/system",
                  "Defeat canary (leak), PIE/ASLR (leak), NX (ROP)"],
        "tools": ["pwntools", "gdb+pwndbg/gef", "ropper/ROPgadget", "one_gadget", "checksec"],
        "traps": ["off-by-one / null-byte", "partial overwrite", "stack alignment (movaps)",
                  "format string both leak AND write"],
    },
    "reversing": {
        "moves": ["`file`/`strings`/`checksec`; triage packer (UPX?)",
                  "Static: Ghidra/radare2 decompile the check routine",
                  "Dynamic: gdb/ltrace to watch the comparison; or angr to solve it"],
        "tools": ["ghidra", "radare2/rizin", "gdb", "ltrace/strace", "angr", "dnSpy/jadx"],
        "traps": ["anti-debug/ptrace", "obfuscation/VM", "self-modifying code",
                  "the check is in a thread / constructor"],
    },
    "forensics": {
        "moves": ["`file` + `binwalk` + `strings`; carve embedded data (foremost)",
                  "pcap → follow streams in wireshark/tshark, extract files/creds",
                  "memory → Volatility (pslist/filescan/dumpfiles); disk → Sleuthkit/Autopsy"],
        "tools": ["binwalk", "foremost", "wireshark/tshark", "volatility3", "exiftool", "xxd"],
        "traps": ["data appended past EOF", "wrong/forged file header",
                  "flag split across packets", "deleted-but-recoverable files"],
    },
    "stego": {
        "moves": ["exiftool + strings first; check LSB and bit-planes",
                  "images: zsteg/stegsolve/steghide; audio: spectrogram (Sonic Visualiser)",
                  "Try known passphrases from the prompt for steghide/outguess"],
        "tools": ["exiftool", "zsteg", "stegsolve", "steghide", "binwalk", "sonic-visualiser"],
        "traps": ["password hidden in metadata", "data in alpha channel",
                  "multi-layer (zip inside image inside audio)", "QR in a bit-plane"],
    },
    "osint": {
        "moves": ["Pivot on usernames/emails/handles; reverse-image search",
                  "Metadata (exif/geolocation), cached pages, archives, certs",
                  "Public records: crt.sh, DNS, WHOIS, code repos, social graph"],
        "tools": ["passive-reconnaissance skill", "exiftool", "sherlock", "theHarvester"],
        "traps": ["decoy profiles", "timezone from timestamps",
                  "the answer is in an image's EXIF GPS", "stale vs current data"],
    },
    "network": {
        "moves": ["Scope-gated nmap of the given target; enumerate services/versions",
                  "Hand off to the matching skill (web/pwn) per service",
                  "Grab banners, default creds, exposed admin"],
        "tools": ["nmap", "network-service-discovery skill", "netcat", "curl"],
        "traps": ["non-standard ports", "UDP-only service", "rate limits that look like 'down'"],
    },
    "misc": {
        "moves": ["Decode layers (CyberChef 'magic'); identify esolang/encoding",
                  "pyjail: escape the sandbox (builtins, dunder traversal) — in-challenge only",
                  "QR/barcode, audio, spreadsheets, git history"],
        "tools": ["CyberChef", "python", "zbarimg", "git", "xxd"],
        "traps": ["nested encodings", "red-herring rabbit holes",
                  "the flag is the decoding process itself"],
    },
}

# Header magic / extension -> candidate categories (heuristic, ranked by order).
_MAGIC = [
    (b"\x7fELF", ["pwn", "reversing"]),
    (b"MZ", ["reversing"]),
    (b"%PDF", ["forensics"]),
    (b"PK\x03\x04", ["forensics"]),                 # zip / office / jar / apk
    (b"\x89PNG", ["stego", "forensics"]),
    (b"\xff\xd8\xff", ["stego", "forensics"]),       # jpeg
    (b"GIF8", ["stego", "forensics"]),
    (b"\xd4\xc3\xb2\xa1", ["forensics"]),            # pcap
    (b"\x0a\x0d\x0d\x0a", ["forensics"]),            # pcapng
    (b"ID3", ["stego"]),                             # mp3
    (b"RIFF", ["stego", "forensics"]),               # wav/avi
]
_EXT = {
    ".php": ["web"], ".js": ["web"], ".html": ["web"],
    ".py": ["misc", "reversing"], ".pcap": ["forensics"], ".pcapng": ["forensics"],
    ".png": ["stego"], ".jpg": ["stego"], ".jpeg": ["stego"], ".gif": ["stego"],
    ".wav": ["stego"], ".mp3": ["stego"], ".zip": ["forensics"], ".pdf": ["forensics"],
    ".exe": ["reversing"], ".dll": ["reversing"], ".elf": ["pwn", "reversing"],
    ".bin": ["pwn", "reversing"], ".pem": ["crypto"], ".enc": ["crypto"],
}
_HINT = {
    "crypto": ["rsa", "aes", "cipher", "encrypt", "decrypt", "xor", "key", "hash", "oracle"],
    "web": ["http", "login", "cookie", "url", "api", "jwt", "sql", "xss", "site"],
    "pwn": ["overflow", "shell", "libc", "rop", "buffer", "pwn", "binary exploit"],
    "reversing": ["reverse", "decompile", "license", "keygen", "crackme", "obfus"],
    "forensics": ["pcap", "memory dump", "disk", "carve", "recover", "volatility", "capture"],
    "stego": ["hidden", "steg", "spectrogram", "lsb", "image", "audio"],
    "osint": ["osint", "find the person", "location", "username", "social", "geolocate"],
    "network": ["nmap", "port", "service", "scan", "server"],
}


def read_magic(path: Path, n: int = 16) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def classify(file=None, url=None, port=None, hint=None) -> list[tuple[str, int, str]]:
    """Rank candidate categories from the available signals. Heuristic, not proof."""
    scores: dict[str, int] = {}
    reasons: dict[str, str] = {}

    def bump(cat, pts, why):
        scores[cat] = scores.get(cat, 0) + pts
        reasons.setdefault(cat, why)

    if url:
        bump("web", 5, "a URL/service was given")
    if port is not None:
        bump("network", 3, f"a port ({port}) was given")
        if port in (80, 443, 8080, 8000, 8443):
            bump("web", 3, f"port {port} is HTTP(S)")
    if file:
        p = Path(file)
        magic = read_magic(p)
        for sig, cats in _MAGIC:
            if magic.startswith(sig):
                for i, c in enumerate(cats):
                    bump(c, 5 - i, f"file header matches {sig!r}")
        for c in _EXT.get(p.suffix.lower(), []):
            bump(c, 2, f"extension {p.suffix}")
    if hint:
        h = hint.lower()
        for cat, words in _HINT.items():
            for w in words:
                if w in h:
                    bump(cat, 2, f"hint mentions '{w}'")
                    break
    ranked = sorted(((c, s, reasons[c]) for c, s in scores.items()),
                    key=lambda t: (-t[1], t[0]))
    return ranked


def flag_valid(candidate: str, pattern: str = DEFAULT_FLAG_RE) -> bool:
    try:
        return re.match(pattern, candidate.strip()) is not None
    except re.error:
        return False


def _print_playbook(cat: str) -> int:
    pb = PLAYBOOKS.get(cat)
    if not pb:
        print(f"error: unknown category '{cat}'. Known: {', '.join(sorted(PLAYBOOKS))}",
              file=sys.stderr)
        return 3
    print(f"[{cat}] opening moves:")
    for m in pb["moves"]:
        print(f"  - {m}")
    print(f"  tools: {', '.join(pb['tools'])}")
    print(f"  watch for: {', '.join(pb['traps'])}")
    return 0


def cmd_classify(args) -> int:
    ranked = classify(args.file, args.url, args.port, args.hint)
    if not ranked:
        print("no signals — give --file/--url/--port/--hint. Known categories: "
              + ", ".join(sorted(PLAYBOOKS)), file=sys.stderr)
        return 3
    print("likely categories (heuristic — confirm by inspection):")
    for cat, score, why in ranked[:3]:
        print(f"  {cat:<10} (score {score}; {why})")
    top = ranked[0][0]
    print()
    return _print_playbook(top)


def cmd_playbook(args) -> int:
    return _print_playbook(args.category.lower())


def cmd_flag_check(args) -> int:
    ok = flag_valid(args.candidate, args.format)
    print(("VALID" if ok else "INVALID") + f"  {args.candidate.strip()}")
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CTF challenge triage helper")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("classify")
    c.add_argument("--file"); c.add_argument("--url")
    c.add_argument("--port", type=int); c.add_argument("--hint")
    p = sub.add_parser("playbook"); p.add_argument("category")
    f = sub.add_parser("flag-check")
    f.add_argument("candidate"); f.add_argument("--format", default=DEFAULT_FLAG_RE)
    args = ap.parse_args(argv)
    if args.cmd == "classify":
        return cmd_classify(args)
    if args.cmd == "playbook":
        return cmd_playbook(args)
    return cmd_flag_check(args)


if __name__ == "__main__":
    raise SystemExit(main())
