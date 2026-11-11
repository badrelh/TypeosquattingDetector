"""Command-line entry point: scan domains, print the reports, optionally save or e-mail them."""

import argparse
import json
import logging
import sys
from typing import Any, Optional

from typosquatting import report, state
from typosquatting.metrics import summarize
from typosquatting.scanner import LSH_METHODS, ScanError, Scanner

logger = logging.getLogger("typosquatting")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="typosquatting",
        description="Find registered look-alike domains of one or more domains using dnstwist.",
    )
    parser.add_argument("domains", nargs="+", metavar="domain", help="domains to protect, e.g. example.com")
    parser.add_argument(
        "--lsh",
        choices=LSH_METHODS,
        help="compare the HTML of each look-alike with the original using this fuzzy hash",
    )
    parser.add_argument(
        "--phash",
        action="store_true",
        help="take screenshots and compare them with the original (needs a browser, see README)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        help="number of parallel DNS/HTTP workers; lower it with --phash to save memory (default: dnstwist's)",
    )
    parser.add_argument("--limit", type=int, default=5, help="number of closest look-alikes per metric (default: 5)")
    parser.add_argument("-o", "--output", help="write the full results of every domain to this JSON file")
    parser.add_argument(
        "--state",
        help="JSON file remembering known look-alikes: the report then lists only the new ones, "
        "and e-mails are sent only when there are new ones",
    )
    parser.add_argument("--email-to", help="send the report to this address (SMTP settings come from the environment)")
    parser.add_argument("-v", "--verbose", action="store_true", help="log progress")
    return parser


def send_report(summary: dict[str, Any], recipient: str) -> None:
    settings = report.smtp_settings_from_env()
    message = report.build_message(summary, settings["sender"], recipient)
    report.send_message(message, settings["host"], settings["port"], settings["user"], settings["password"])


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")

    try:
        known = state.load_state(args.state) if args.state else None
    except ValueError as exc:
        logger.error("%s", exc)
        return 1

    scanner = Scanner(lsh=args.lsh, phash=args.phash, threads=args.threads)
    summaries: list[dict[str, Any]] = []
    failed = False

    # One failing domain must not stop the others; the exit code still reports it.
    for domain in args.domains:
        try:
            variants = scanner.scan(domain)
        except ScanError as exc:
            logger.error("%s", exc)
            failed = True
            continue

        summary = summarize(domain, variants, limit=args.limit)
        if known is not None:
            summary["new"], summary["baseline"] = state.find_new(domain, variants, known)
            state.update_state(domain, variants, known)
        summaries.append(summary)
        print(report.format_text(summary), end="\n" if len(args.domains) > 1 else "")

        if args.email_to and (known is None or summary["new"]):
            try:
                send_report(summary, args.email_to)
            except (ValueError, OSError) as exc:
                logger.error("Could not send the report for %s: %s", domain, exc)
                failed = True
            else:
                logger.info("Report for %s sent to %s", domain, args.email_to)

    if known is not None:
        state.save_state(args.state, known)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(summaries, f, indent=2, ensure_ascii=False)
        logger.info("Results written to %s", args.output)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
