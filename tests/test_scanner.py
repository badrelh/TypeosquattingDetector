import pytest

from typosquatting import scanner
from typosquatting.scanner import ScanError, Scanner, is_registered


FAKE_RESULTS = [
    {"domain": "example.com", "fuzzer": "*original", "dns_a": ["93.184.216.34"]},
    {"domain": "exampl.com", "fuzzer": "omission", "dns_a": ["1.2.3.4"]},
    {"domain": "exampel.com", "fuzzer": "transposition", "dns_mx": ["mx.example.net"]},
    {"domain": "example.net", "fuzzer": "tld-swap", "dns_ns": ["ns1.example.net"]},
    {"domain": "exmple.com", "fuzzer": "omission"},
]


def test_is_registered_accepts_any_dns_record():
    assert is_registered({"dns_a": ["1.2.3.4"]})
    assert is_registered({"dns_aaaa": ["::1"]})
    assert is_registered({"dns_mx": ["mx.example.net"]})
    assert is_registered({"dns_ns": ["ns1.example.net"]})


def test_is_registered_rejects_variant_without_records():
    assert not is_registered({"domain": "exmple.com", "fuzzer": "omission"})
    assert not is_registered({"dns_a": []})


def test_scan_keeps_only_registered_variants_and_drops_original(monkeypatch):
    monkeypatch.setattr(scanner.dnstwist, "run", lambda **options: FAKE_RESULTS)

    domains = [v["domain"] for v in Scanner().scan("example.com")]

    assert domains == ["exampl.com", "exampel.com", "example.net"]


def test_scan_passes_lsh_and_phash_options(monkeypatch):
    calls = []

    def fake_run(**options):
        calls.append(options)
        return []

    monkeypatch.setattr(scanner.dnstwist, "run", fake_run)

    Scanner(lsh="tlsh", phash=True).scan("example.com")
    Scanner().scan("example.com")

    assert calls[0] == {"domain": "example.com", "format": "json", "registered": True, "lsh": "tlsh", "phash": True}
    assert calls[1] == {"domain": "example.com", "format": "json", "registered": True}


def test_scan_wraps_dnstwist_errors(monkeypatch):
    def boom(**options):
        raise RuntimeError("no network")

    monkeypatch.setattr(scanner.dnstwist, "run", boom)

    with pytest.raises(ScanError, match="no network"):
        Scanner().scan("example.com")


def test_invalid_lsh_method_is_rejected():
    with pytest.raises(ValueError):
        Scanner(lsh="md5")


def test_scan_wraps_argparse_exit_from_dnstwist(monkeypatch):
    # dnstwist calls argparse's error(), which exits instead of raising.
    def exit_like_argparse(**options):
        raise SystemExit(2)

    monkeypatch.setattr(scanner.dnstwist, "run", exit_like_argparse)

    with pytest.raises(ScanError, match="refused the options"):
        Scanner(phash=True).scan("example.com")


def test_scan_passes_thread_count(monkeypatch):
    calls = []
    monkeypatch.setattr(scanner.dnstwist, "run", lambda **options: calls.append(options) or [])

    Scanner(phash=True, threads=2).scan("example.com")

    assert calls[0]["threads"] == 2
