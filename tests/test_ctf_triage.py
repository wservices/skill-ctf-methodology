"""Tests for ctf_triage. Stdlib + pytest; offline, no challenge files needed."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "ctf-methodology" / "scripts" / "ctf_triage.py"


def _load():
    spec = importlib.util.spec_from_file_location("ctf_triage", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ctf_triage"] = mod
    spec.loader.exec_module(mod)
    return mod


ct = _load()


def test_all_categories_have_playbooks():
    for cat in ("web", "crypto", "pwn", "reversing", "forensics", "stego",
                "osint", "network", "misc"):
        pb = ct.PLAYBOOKS[cat]
        assert pb["moves"] and pb["tools"] and pb["traps"]


def test_classify_elf_is_pwn_or_rev(tmp_path):
    f = tmp_path / "chall"
    f.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 20)
    ranked = ct.classify(file=str(f))
    cats = [c for c, _, _ in ranked]
    assert cats[0] in ("pwn", "reversing") and "pwn" in cats


def test_classify_pcap_is_forensics(tmp_path):
    f = tmp_path / "capture.pcap"
    f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 16)
    assert ct.classify(file=str(f))[0][0] == "forensics"


def test_classify_png_is_stego(tmp_path):
    f = tmp_path / "img.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 8)
    assert ct.classify(file=str(f))[0][0] == "stego"


def test_classify_url_and_http_port_is_web():
    ranked = ct.classify(url="http://chall.example/", port=8080)
    assert ranked[0][0] == "web"


def test_classify_hint_crypto():
    ranked = ct.classify(hint="recover the RSA private key to decrypt")
    assert "crypto" in [c for c, _, _ in ranked]


def test_classify_no_signals_empty():
    assert ct.classify() == []


def test_flag_valid_default():
    assert ct.flag_valid("FLAG{he110_w0rld}")
    assert ct.flag_valid("picoCTF{a-b_c}")
    assert not ct.flag_valid("just some text")
    assert not ct.flag_valid("FLAG{unclosed")


def test_flag_valid_custom_format():
    assert ct.flag_valid("HTB{x}", r"^HTB\{.+\}$")
    assert not ct.flag_valid("FLAG{x}", r"^HTB\{.+\}$")


def test_flag_valid_bad_regex_is_false():
    assert ct.flag_valid("FLAG{x}", "(") is False


def test_cli_classify_prints_playbook(tmp_path, capsys):
    f = tmp_path / "chall"
    f.write_bytes(b"\x7fELF" + b"\x00" * 20)
    rc = ct.main(["classify", "--file", str(f)])
    out = capsys.readouterr().out
    assert rc == 0 and "likely categories" in out and "opening moves" in out


def test_cli_playbook_unknown_exit_3(capsys):
    assert ct.main(["playbook", "nope"]) == 3


def test_cli_flag_check_exit_codes(capsys):
    assert ct.main(["flag-check", "FLAG{ok}"]) == 0
    assert ct.main(["flag-check", "nope"]) == 1
