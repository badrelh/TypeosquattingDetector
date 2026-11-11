import json
from unittest import mock

from typosquatting import cli, scanner


FAKE_RESULTS = [
    {"domain": "example.com", "fuzzer": "*original", "dns_a": ["93.184.216.34"]},
    {"domain": "exampl.com", "fuzzer": "omission", "dns_a": ["1.2.3.4"], "tlsh": 70},
]


def test_cli_prints_report_and_writes_json(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(scanner.dnstwist, "run", lambda **options: FAKE_RESULTS)
    output = tmp_path / "out.json"

    code = cli.main(["example.com", "--lsh", "tlsh", "-o", str(output)])

    assert code == 0
    assert "exampl.com (score 70)" in capsys.readouterr().out
    assert json.loads(output.read_text(encoding="utf-8"))["registered_count"] == 1


def test_cli_returns_error_code_when_scan_fails(monkeypatch, caplog):
    def boom(**options):
        raise RuntimeError("resolver down")

    monkeypatch.setattr(scanner.dnstwist, "run", boom)

    assert cli.main(["example.com"]) == 1
    assert "resolver down" in caplog.text


def test_cli_sends_email_when_requested(monkeypatch):
    monkeypatch.setattr(scanner.dnstwist, "run", lambda **options: FAKE_RESULTS)
    monkeypatch.setenv("TYPOSQUAT_SMTP_HOST", "smtp.example.org")
    monkeypatch.setenv("TYPOSQUAT_SMTP_FROM", "bot@example.org")
    send = mock.MagicMock()
    monkeypatch.setattr(cli.report, "send_message", send)

    code = cli.main(["example.com", "--email-to", "me@example.org"])

    assert code == 0
    message, host, port, user, password = send.call_args.args
    assert message["To"] == "me@example.org"
    assert (host, port, user, password) == ("smtp.example.org", 587, None, None)


def test_cli_reports_missing_smtp_settings(monkeypatch, caplog):
    monkeypatch.setattr(scanner.dnstwist, "run", lambda **options: FAKE_RESULTS)
    for name in ("TYPOSQUAT_SMTP_HOST", "TYPOSQUAT_SMTP_FROM"):
        monkeypatch.delenv(name, raising=False)

    assert cli.main(["example.com", "--email-to", "me@example.org"]) == 1
    assert "Missing SMTP settings" in caplog.text
