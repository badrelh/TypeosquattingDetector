"""Command-line entry point: scan domains, print the reports, optionally save or e-mail them."""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Optional

from typosquatting import ct, enrich, filters, report, risk, state
from typosquatting.metrics import summarize
from typosquatting.scanner import LSH_METHODS, ScanError, Scanner

logger = logging.getLogger("typosquatting")

COMBO_WORDS = Path(__file__).parent / "data" / "combo-words.txt"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="typosquatting",
        description="Find registered look-alike domains of one or more domains using dnstwist.",
    )
    parser.add_argument("domains", nargs="+", metavar="domain", help="domains to protect, e.g. example.com")

    finding = parser.add_argument_group("finding look-alikes")
    words = finding.add_mutually_exclusive_group()
    words.add_argument("--dictionary", metavar="FILE", help="also try the domain combined with each word of FILE (one per line)")
    words.add_argument("--combo", action="store_true", help="also try the domain combined with common words such as login or secure")
    finding.add_argument("--ct", action="store_true", help="also search certificate logs (crt.sh) for names containing the brand")
    finding.add_argument("--allow", action="append", default=[], metavar="DOMAIN", help="legitimate domain to ignore, with its subdomains (repeatable)")
    finding.add_argument("--allow-file", metavar="FILE", help="file of legitimate domains to ignore, one per line")

    judging = parser.add_argument_group("judging look-alikes")
    judging.add_argument("--lsh", choices=LSH_METHODS, help="compare the HTML of each look-alike with the original using this fuzzy hash")
    judging.add_argument("--phash", action="store_true", help="take screenshots and compare them with the original (needs a browser, see README)")
    judging.add_argument("--enrich", action="store_true", help="look up each look-alike's registration date (RDAP) to raise the risk of recent ones")
    judging.add_argument("--threads", type=int, help="number of parallel DNS/HTTP workers; lower it with --phash to save memory (default: dnstwist's)")

    output = parser.add_argument_group("output")
    output.add_argument("--limit", type=int, default=5, help="number of entries per section of the report (default: 5)")
    output.add_argument("-o", "--output", help="write the full results of every domain to this JSON file")
    output.add_argument(
        "--state",
        help="JSON file remembering known look-alikes: the report then lists only the new ones, "
        "and e-mails are sent only when there are new ones",
    )
    output.add_argument("--email-to", help="send the report to this address (SMTP settings come from the environment)")
    output.add_argument("-v", "--verbose", action="store_true", help="log progress")
    return parser


def send_report(summary: dict[str, Any], recipient: str) -> None:
    settings = report.smtp_settings_from_env()
    message = report.build_message(summary, settings["sender"], recipient)
    report.send_message(message, settings["host"], settings["port"], settings["user"], settings["password"])


def collect(domain: str, scanner: Scanner, args: argparse.Namespace, allowed: list[str]) -> list[dict]:
    """Every look-alike of the domain, filtered, optionally dated, and scored."""
    variants = scanner.scan(domain)

    if args.ct:
        found = ct.search(domain, allowed)
        if found is not None:
            known = {v["domain"] for v in variants}
            variants += [v for v in found if v["domain"] not in known]

    variants = filters.apply_allowlist(variants, allowed)
    if args.enrich:
        enrich.add_ages(variants)
    risk.apply_risk(variants)
    return variants


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")

    try:
        known = state.load_state(args.state) if args.state else None
        allowed = [entry.lower() for entry in args.allow]
        if args.allow_file:
            allowed += filters.load_allowlist(args.allow_file)
    except (ValueError, OSError) as exc:
        logger.error("%s", exc)
        return 1

    dictionary = str(COMBO_WORDS) if args.combo else args.dictionary
    scanner = Scanner(lsh=args.lsh, phash=args.phash, threads=args.threads, dictionary=dictionary)
    summaries: list[dict[str, Any]] = []
    failed = False

    # One failing domain must not stop the others; the exit code still reports it.
    for domain in args.domains:
        try:
            variants = collect(domain, scanner, args, allowed)
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
