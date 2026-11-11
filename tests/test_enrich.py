import http.client
import io
import json
import urllib.error
from datetime import datetime, timezone
from unittest import mock

import pytest

from typosquatting import enrich

NOW = datetime(2026, 11, 11, tzinfo=timezone.utc)


def rdap_response(events):
    return io.BytesIO(json.dumps({"events": events}).encode("utf-8"))


def test_parse_date_handles_z_suffix_and_missing_timezone():
    assert enrich.parse_date("2026-01-02T03:04:05Z") == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert enrich.parse_date("2026-01-02T03:04:05") == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert enrich.parse_date("not a date") is None


def test_registration_date_reads_the_registration_event():
    events = [
        {"eventAction": "last changed", "eventDate": "2026-05-01T00:00:00Z"},
        {"eventAction": "registration", "eventDate": "2026-01-02T00:00:00Z"},
    ]
    with mock.patch.object(enrich.urllib.request, "urlopen", return_value=rdap_response(events)):
        assert enrich.registration_date("example.com") == datetime(2026, 1, 2, tzinfo=timezone.utc)


def test_registration_date_is_none_without_registration_event():
    with mock.patch.object(enrich.urllib.request, "urlopen", return_value=rdap_response([])):
        assert enrich.registration_date("example.com") is None


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(enrich.time, "sleep", lambda seconds: None)


def test_registration_date_is_none_when_rdap_is_unreachable():
    with mock.patch.object(enrich.urllib.request, "urlopen", side_effect=urllib.error.URLError("down")) as urlopen:
        assert enrich.registration_date("example.com") is None

    assert urlopen.call_count == enrich.ATTEMPTS


def test_registration_date_retries_after_a_dropped_connection():
    events = [{"eventAction": "registration", "eventDate": "2026-01-02T00:00:00Z"}]
    answers = [urllib.error.URLError("reset"), rdap_response(events)]

    with mock.patch.object(enrich.urllib.request, "urlopen", side_effect=answers) as urlopen:
        assert enrich.registration_date("example.com") == datetime(2026, 1, 2, tzinfo=timezone.utc)

    assert urlopen.call_count == 2


def test_registration_date_retries_when_rate_limited_but_not_on_404():
    def http_error(code):
        return urllib.error.HTTPError("https://rdap.org", code, "error", {}, None)

    with mock.patch.object(enrich.urllib.request, "urlopen", side_effect=http_error(429)) as urlopen:
        assert enrich.registration_date("example.com") is None
    assert urlopen.call_count == enrich.ATTEMPTS

    with mock.patch.object(enrich.urllib.request, "urlopen", side_effect=http_error(404)) as urlopen:
        assert enrich.registration_date("example.com") is None
    assert urlopen.call_count == 1


def test_registration_date_survives_malformed_requests():
    with mock.patch.object(enrich.urllib.request, "urlopen", side_effect=http.client.InvalidURL("bad")):
        assert enrich.registration_date("slack technologies, llc") is None


def test_registration_date_quotes_the_domain_in_the_url():
    with mock.patch.object(enrich.urllib.request, "urlopen", return_value=rdap_response([])) as urlopen:
        enrich.registration_date("odd name.com")

    assert urlopen.call_args.args[0].full_url == "https://rdap.org/domain/odd%20name.com"


def test_add_ages_computes_days_and_skips_undated_domains():
    dates = {"new.com": datetime(2026, 11, 1, tzinfo=timezone.utc), "unknown.com": None}
    variants = [{"domain": "new.com"}, {"domain": "unknown.com"}]

    dated = enrich.add_ages(variants, lookup=dates.get, now=NOW)

    assert dated == 1
    assert variants[0]["age_days"] == 10
    assert variants[0]["registered"] == "2026-11-01"
    assert "age_days" not in variants[1]


def test_add_ages_falls_back_to_the_certificate_date():
    variants = [{"domain": "login-example.com", "ct_not_before": "2026-11-06T00:00:00"}]

    enrich.add_ages(variants, lookup=lambda domain: None, now=NOW)

    assert variants[0]["age_days"] == 5


def test_add_ages_never_returns_a_negative_age():
    variants = [{"domain": "future.com"}]

    enrich.add_ages(variants, lookup=lambda domain: datetime(2027, 1, 1, tzinfo=timezone.utc), now=NOW)

    assert variants[0]["age_days"] == 0
