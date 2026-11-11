import json
from unittest import mock

import pytest

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
    summaries = json.loads(output.read_text(encoding="utf-8"))
    assert [s["domain"] for s in summaries] == ["example.com"]
    assert summaries[0]["registered_count"] == 1


def test_cli_scans_several_domains_and_keeps_going_after_a_failure(monkeypatch, tmp_path, caplog):
    def fake_run(**options):
        if options["domain"] == "broken.example":
            raise RuntimeError("resolver down")
        return FAKE_RESULTS

    monkeypatch.setattr(scanner.dnstwist, "run", fake_run)
    output = tmp_path / "out.json"

    code = cli.main(["one.example", "broken.example", "two.example", "-o", str(output)])

    assert code == 1
    assert "resolver down" in caplog.text
    assert [s["domain"] for s in json.loads(output.read_text(encoding="utf-8"))] == ["one.example", "two.example"]


def test_cli_first_scan_with_state_only_records_a_baseline(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(scanner.dnstwist, "run", lambda **options: FAKE_RESULTS)
    state_file = tmp_path / "state.json"

    assert cli.main(["example.com", "--state", str(state_file)]) == 0

    assert "baseline recorded" in capsys.readouterr().out
    assert json.loads(state_file.read_text(encoding="utf-8")) == {"example.com": ["exampl.com"]}


def test_cli_state_reports_only_new_lookalikes_and_emails_only_then(monkeypatch, tmp_path, capsys):
    results = [*FAKE_RESULTS]
    monkeypatch.setattr(scanner.dnstwist, "run", lambda **options: results)
    monkeypatch.setenv("TYPOSQUAT_SMTP_HOST", "smtp.example.org")
    monkeypatch.setenv("TYPOSQUAT_SMTP_FROM", "bot@example.org")
    send = mock.MagicMock()
    monkeypatch.setattr(cli.report, "send_message", send)
    state_file = tmp_path / "state.json"
    arguments = ["example.com", "--state", str(state_file), "--email-to", "me@example.org"]

    cli.main(arguments)  # baseline
    cli.main(arguments)  # nothing new
    send.assert_not_called()

    results.append({"domain": "exampel.com", "fuzzer": "transposition", "dns_a": ["5.6.7.8"]})
    capsys.readouterr()
    assert cli.main(arguments) == 0

    assert "New since the last scan: 1" in capsys.readouterr().out
    send.assert_called_once()
    assert "1 new look-alike" in send.call_args.args[0]["Subject"]


def test_cli_rejects_a_corrupt_state_file(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(scanner.dnstwist, "run", lambda **options: FAKE_RESULTS)
    state_file = tmp_path / "state.json"
    state_file.write_text("not json", encoding="utf-8")

    assert cli.main(["example.com", "--state", str(state_file)]) == 1
    assert "not valid JSON" in caplog.text


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


def run_with(monkeypatch, results=None):
    calls = []

    def fake_run(**options):
        calls.append(options)
        return FAKE_RESULTS if results is None else results

    monkeypatch.setattr(scanner.dnstwist, "run", fake_run)
    return calls


def test_cli_ignores_allowed_domains(monkeypatch, capsys):
    run_with(monkeypatch)

    assert cli.main(["example.com", "--allow", "exampl.com"]) == 0

    assert "Registered look-alike domains: 0" in capsys.readouterr().out


def test_cli_reads_the_allowlist_file(monkeypatch, tmp_path, capsys):
    run_with(monkeypatch)
    allow_file = tmp_path / "allow.txt"
    allow_file.write_text("exampl.com # ours\n", encoding="utf-8")

    cli.main(["example.com", "--allow-file", str(allow_file)])

    assert "Registered look-alike domains: 0" in capsys.readouterr().out


def test_cli_fails_cleanly_on_a_missing_allowlist_file(monkeypatch, caplog):
    run_with(monkeypatch)

    assert cli.main(["example.com", "--allow-file", "/nonexistent/allow.txt"]) == 1
    assert "allow.txt" in caplog.text


def test_cli_report_lists_the_riskiest_lookalikes_with_reasons(monkeypatch, capsys):
    run_with(monkeypatch, [{"domain": "exampl.com", "fuzzer": "omission", "dns_a": ["1.2.3.4"], "dns_mx": ["mx.example.net"]}])

    cli.main(["example.com"])

    out = capsys.readouterr().out
    assert "Highest risk" in out
    assert "exampl.com (score 2): can receive and send e-mail (MX record)" in out


def test_cli_ct_adds_new_names_without_duplicating_known_ones(monkeypatch, tmp_path):
    run_with(monkeypatch)
    found = [
        {"domain": "exampl.com", "fuzzer": "ct-log", "ct_not_before": "2026-01-01T00:00:00"},
        {"domain": "example-login.com", "fuzzer": "ct-log", "ct_not_before": "2026-01-01T00:00:00"},
    ]
    monkeypatch.setattr(cli.ct, "search", lambda domain, allowed: found)
    output = tmp_path / "out.json"

    cli.main(["example.com", "--ct", "-o", str(output)])

    summary = json.loads(output.read_text(encoding="utf-8"))[0]
    assert sorted(v["domain"] for v in summary["variants"]) == ["exampl.com", "example-login.com"]
    assert summary["by_technique"] == {"omission": 1, "ct-log": 1}


def test_cli_ct_failure_does_not_stop_the_scan(monkeypatch, capsys):
    run_with(monkeypatch)
    monkeypatch.setattr(cli.ct, "search", lambda domain, allowed: None)

    assert cli.main(["example.com", "--ct"]) == 0
    assert "Registered look-alike domains: 1" in capsys.readouterr().out


def test_cli_enrich_raises_the_risk_of_recent_registrations(monkeypatch, capsys):
    run_with(monkeypatch)

    def fake_add_ages(variants):
        for variant in variants:
            variant["age_days"] = 4

    monkeypatch.setattr(cli.enrich, "add_ages", fake_add_ages)

    cli.main(["example.com", "--enrich"])

    assert "registered 4 days ago" in capsys.readouterr().out


def test_cli_combo_passes_the_bundled_word_list_to_dnstwist(monkeypatch):
    calls = run_with(monkeypatch)

    cli.main(["example.com", "--combo"])

    assert calls[0]["dictionary"] == str(cli.COMBO_WORDS)
    assert cli.COMBO_WORDS.read_text(encoding="utf-8").split()


def test_cli_dictionary_passes_the_given_file_to_dnstwist(monkeypatch):
    calls = run_with(monkeypatch)

    cli.main(["example.com", "--dictionary", "words.txt"])

    assert calls[0]["dictionary"] == "words.txt"


def test_cli_rejects_dictionary_together_with_combo():
    with pytest.raises(SystemExit):
        cli.main(["example.com", "--dictionary", "words.txt", "--combo"])
