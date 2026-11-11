"""Command-line entry point: scan a domain, print the report, optionally save or e-mail it."""

import argparse
import json
import logging
import sys
from typing import Optional

from typosquatting import report
from typosquatting.metrics import summarize
from typosquatting.scanner import LSH_METHODS, ScanError, Scanner

logger = logging.getLogger("typosquatting")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="typosquatting",
        description="Find registered look-alike domains of a domain using dnstwist.",
    )
    parser.add_argument("domain", help="domain to protect, e.g. example.com")
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
    parser.add_argument("-o", "--output", help="write the full results to this JSON file")
    parser.add_argument("--email-to", help="send the report to this address (SMTP settings come from the environment)")
    parser.add_argument("-v", "--verbose", action="store_true", help="log progress")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")

    try:
        variants = Scanner(lsh=args.lsh, phash=args.phash, threads=args.threads).scan(args.domain)
    except ScanError as exc:
        logger.error("%s", exc)
        return 1

    summary = summarize(args.domain, variants, limit=args.limit)
    print(report.format_text(summary), end="")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        logger.info("Results written to %s", args.output)

    if args.email_to:
        try:
            settings = report.smtp_settings_from_env()
            message = report.build_message(summary, settings["sender"], args.email_to)
            report.send_message(message, settings["host"], settings["port"], settings["user"], settings["password"])
        except (ValueError, OSError) as exc:
            logger.error("Could not send the report: %s", exc)
            return 1
        logger.info("Report sent to %s", args.email_to)

    return 0


if __name__ == "__main__":
    sys.exit(main())
