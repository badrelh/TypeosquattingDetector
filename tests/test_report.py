import json
from email.message import EmailMessage
from unittest import mock

import pytest

from typosquatting import report
from typosquatting.metrics import summarize


VARIANTS = [
    {"domain": "exampl.com", "fuzzer": "omission", "dns_a": ["1.2.3.4"], "tlsh": 80},
]


def test_format_text_lists_totals_techniques_and_closest():
    text = report.format_text(summarize("example.com", VARIANTS))

    assert "Typosquatting report for example.com" in text
    assert "Registered look-alike domains: 1" in text
    assert "omission: 1" in text
    assert "exampl.com (score 80)" in text


def test_format_text_handles_no_results():
    text = report.format_text(summarize("example.com", []))

    assert "Registered look-alike domains: 0" in text
    assert "(none)" in text


def test_build_message_has_body_and_json_attachment():
    message = report.build_message(summarize("example.com", VARIANTS), "bot@example.org", "me@example.org")

    assert message["Subject"] == "Typosquatting report: example.com"
    assert message["From"] == "bot@example.org"
    assert message["To"] == "me@example.org"
    attachments = list(message.iter_attachments())
    assert len(attachments) == 1
    assert attachments[0].get_filename() == "example.com-typosquatting.json"
    assert json.loads(attachments[0].get_content())["registered_count"] == 1


def test_smtp_settings_read_from_environment():
    env = {
        "TYPOSQUAT_SMTP_HOST": "smtp.example.org",
        "TYPOSQUAT_SMTP_FROM": "bot@example.org",
        "TYPOSQUAT_SMTP_USER": "bot",
        "TYPOSQUAT_SMTP_PASSWORD": "secret",
    }

    settings = report.smtp_settings_from_env(env)

    assert settings == {
        "host": "smtp.example.org",
        "port": 587,
        "user": "bot",
        "password": "secret",
        "sender": "bot@example.org",
    }


def test_smtp_settings_require_host_and_sender():
    with pytest.raises(ValueError, match="TYPOSQUAT_SMTP_HOST"):
        report.smtp_settings_from_env({"TYPOSQUAT_SMTP_FROM": "bot@example.org"})


def test_send_message_uses_starttls_and_login():
    server = mock.MagicMock()
    smtp = mock.MagicMock()
    smtp.return_value.__enter__.return_value = server

    with mock.patch.object(report.smtplib, "SMTP", smtp):
        report.send_message(EmailMessage(), "smtp.example.org", 587, "bot", "secret")

    smtp.assert_called_once_with("smtp.example.org", 587, timeout=30)
    server.starttls.assert_called_once()
    server.login.assert_called_once_with("bot", "secret")
    server.send_message.assert_called_once()


def test_send_message_skips_login_without_credentials():
    server = mock.MagicMock()
    smtp = mock.MagicMock()
    smtp.return_value.__enter__.return_value = server

    with mock.patch.object(report.smtplib, "SMTP", smtp):
        report.send_message(EmailMessage(), "localhost", 25, None, None)

    server.login.assert_not_called()


def test_format_text_lists_new_lookalikes():
    summary = summarize("example.com", VARIANTS)
    summary["new"], summary["baseline"] = ["exampl.com"], False

    text = report.format_text(summary)

    assert "New since the last scan: 1" in text
    assert "  exampl.com\n" in text


def test_format_text_explains_a_baseline_scan():
    summary = summarize("example.com", VARIANTS)
    summary["new"], summary["baseline"] = [], True

    assert "baseline recorded" in report.format_text(summary)


def test_alert_subject_counts_new_lookalikes():
    summary = summarize("example.com", VARIANTS)
    summary["new"], summary["baseline"] = ["exampl.com", "exampel.com"], False

    message = report.build_message(summary, "bot@example.org", "me@example.org")

    assert message["Subject"] == "Typosquatting alert: 2 new look-alike(s) of example.com"
