"""Format scan summaries as text and e-mail them over SMTP."""

import json
import os
import smtplib
from email.message import EmailMessage
from typing import Any, Mapping

SMTP_ENV = {
    "host": "TYPOSQUAT_SMTP_HOST",
    "port": "TYPOSQUAT_SMTP_PORT",
    "user": "TYPOSQUAT_SMTP_USER",
    "password": "TYPOSQUAT_SMTP_PASSWORD",
    "sender": "TYPOSQUAT_SMTP_FROM",
}


def format_text(summary: dict[str, Any]) -> str:
    """Human-readable report, one section per part of the summary."""
    lines = [
        f"Typosquatting report for {summary['domain']}",
        f"Registered look-alike domains: {summary['registered_count']}",
    ]
    if summary.get("baseline"):
        lines.append("First scan of this domain: baseline recorded, nothing to compare with yet.")
    elif "new" in summary:
        lines.append(f"New since the last scan: {len(summary['new'])}")
        lines += [f"  {name}" for name in summary["new"]]
    if summary.get("riskiest"):
        lines += ["", "Highest risk (heuristic score, see README):"]
        for entry in summary["riskiest"]:
            lines.append(f"  {entry['domain']} (score {entry['score']}): {'; '.join(entry['reasons'])}")
    lines += ["", "By technique:"]
    lines += [f"  {name}: {count}" for name, count in summary["by_technique"].items()] or ["  (none)"]

    for metric, entries in summary["closest"].items():
        lines += ["", f"Closest by {metric}:"]
        lines += [f"  {e['domain']} (score {e['score']})" for e in entries] or ["  (none)"]

    return "\n".join(lines) + "\n"


def build_message(summary: dict[str, Any], sender: str, recipient: str) -> EmailMessage:
    """E-mail with the text report in the body and the full results as JSON attached."""
    message = EmailMessage()
    new = summary.get("new")
    if new:
        message["Subject"] = f"Typosquatting alert: {len(new)} new look-alike(s) of {summary['domain']}"
    else:
        message["Subject"] = f"Typosquatting report: {summary['domain']}"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(format_text(summary))
    message.add_attachment(
        json.dumps(summary, indent=2, ensure_ascii=False).encode("utf-8"),
        maintype="application",
        subtype="json",
        filename=f"{summary['domain']}-typosquatting.json",
    )
    return message


def smtp_settings_from_env(environ: Mapping[str, str] = os.environ) -> dict[str, Any]:
    """Read SMTP settings from environment variables, so no credential lives in the code."""
    missing = [name for name in ("host", "sender") if not environ.get(SMTP_ENV[name])]
    if missing:
        raise ValueError(f"Missing SMTP settings: {', '.join(SMTP_ENV[m] for m in missing)}")
    return {
        "host": environ[SMTP_ENV["host"]],
        "port": int(environ.get(SMTP_ENV["port"], "587")),
        "user": environ.get(SMTP_ENV["user"]),
        "password": environ.get(SMTP_ENV["password"]),
        "sender": environ[SMTP_ENV["sender"]],
    }


def send_message(message: EmailMessage, host: str, port: int, user: str | None, password: str | None) -> None:
    """Send the message over STARTTLS, logging in only when credentials are given."""
    with smtplib.SMTP(host, port, timeout=30) as server:
        server.starttls()
        if user and password:
            server.login(user, password)
        server.send_message(message)
