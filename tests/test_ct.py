import urllib.error

import pytest

from typosquatting import ct


ROWS = [
    {"name_value": "example-login.com\nwww.example-login.com", "not_before": "2026-10-01T00:00:00"},
    {"name_value": "*.example-login.com", "not_before": "2026-09-01T00:00:00"},
    {"name_value": "example.com\nmail.example.com", "not_before": "2026-01-01T00:00:00"},
    {"name_value": "partner.example.org", "not_before": "2026-02-01T00:00:00"},
    {"name_value": "unrelated.net", "not_before": "2026-03-01T00:00:00"},
    {"name_value": "example.ci.some-company.net", "not_before": "2026-04-01T00:00:00"},
    {"name_value": "example technologies, llc\nadmin@example-corp.com", "not_before": "2026-05-01T00:00:00"},
]


@pytest.mark.parametrize(
    "domain, keyword",
    [("example.com", "example"), ("www.example.com", "example"), ("example.co.uk", "example"), ("localhost", "localhost")],
)
def test_brand_keyword(domain, keyword):
    assert ct.brand_keyword(domain) == keyword


def test_search_returns_lookalikes_with_their_earliest_certificate(monkeypatch):
    monkeypatch.setattr(ct, "fetch", lambda keyword, timeout: ROWS)

    found = ct.search("example.com")

    by_name = {entry["domain"]: entry for entry in found}
    assert set(by_name) == {"example-login.com", "www.example-login.com", "partner.example.org"}
    assert by_name["example-login.com"]["ct_not_before"] == "2026-09-01T00:00:00"
    assert all(entry["fuzzer"] == "ct-log" for entry in found)


def test_search_keeps_hostnames_only(monkeypatch):
    monkeypatch.setattr(ct, "fetch", lambda keyword, timeout: ROWS)

    names = {entry["domain"] for entry in ct.search("example.com")}

    assert names == {"example-login.com", "www.example-login.com", "partner.example.org"}


@pytest.mark.parametrize("name", ["example.com", "xn--exmple-cua.com", "a.b-c.example.org"])
def test_valid_hostnames_are_accepted(name):
    assert ct.HOSTNAME.match(name)


@pytest.mark.parametrize("name", ["example technologies, llc", "admin@example.com", "-bad.example.com", "example", "a..b.com"])
def test_invalid_hostnames_are_rejected(name):
    assert not ct.HOSTNAME.match(name)


def test_search_ignores_names_where_the_brand_is_only_in_a_subdomain(monkeypatch):
    monkeypatch.setattr(ct, "fetch", lambda keyword, timeout: ROWS)

    names = {entry["domain"] for entry in ct.search("example.com")}

    assert "example.ci.some-company.net" not in names


@pytest.mark.parametrize(
    "name, expected",
    [("www.example-login.com", "example-login.com"), ("a.b.example.co.uk", "example.co.uk"), ("example.com", "example.com")],
)
def test_registrable_part(name, expected):
    assert ct.registrable_part(name) == expected


def test_search_skips_the_protected_domain_its_subdomains_and_allowed_domains(monkeypatch):
    monkeypatch.setattr(ct, "fetch", lambda keyword, timeout: ROWS)

    names = {entry["domain"] for entry in ct.search("example.com", allowed=["example.org"])}

    assert "example.com" not in names
    assert "mail.example.com" not in names
    assert "partner.example.org" not in names


def test_search_returns_none_when_crt_sh_fails(monkeypatch):
    def down(keyword, timeout):
        raise urllib.error.URLError("timed out")

    monkeypatch.setattr(ct, "fetch", down)

    assert ct.search("example.com") is None


def test_search_caps_the_number_of_results(monkeypatch):
    rows = [{"name_value": f"example{i:04}.net", "not_before": "2026-01-01T00:00:00"} for i in range(ct.MAX_RESULTS + 50)]
    monkeypatch.setattr(ct, "fetch", lambda keyword, timeout: rows)

    assert len(ct.search("example.com")) == ct.MAX_RESULTS
