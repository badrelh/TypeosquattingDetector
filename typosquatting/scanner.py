"""Generate typosquatting variants of a domain and keep the ones that are registered."""

import contextlib
import io
import logging
from typing import Optional

import dnstwist

logger = logging.getLogger(__name__)

REGISTERED_KEYS = ("dns_a", "dns_aaaa", "dns_mx", "dns_ns")
ORIGINAL_FUZZER = "*original"
LSH_METHODS = ("tlsh", "ssdeep")


class ScanError(RuntimeError):
    """Raised when dnstwist cannot scan a domain."""


def is_registered(variant: dict) -> bool:
    """A variant is registered when at least one DNS record exists for it."""
    return any(variant.get(key) for key in REGISTERED_KEYS)


class Scanner:
    """Run dnstwist on a domain and return its registered look-alike domains."""

    def __init__(
        self,
        lsh: Optional[str] = None,
        phash: bool = False,
        threads: Optional[int] = None,
        dictionary: Optional[str] = None,
    ) -> None:
        if lsh is not None and lsh not in LSH_METHODS:
            raise ValueError(f"lsh must be one of {LSH_METHODS}, got {lsh!r}")
        self.lsh = lsh
        self.phash = phash
        # --phash starts one browser per thread, so the thread count bounds memory use.
        self.threads = threads
        # Word list that dnstwist combines with the domain (login, secure, ...).
        self.dictionary = dictionary

    def scan(self, domain: str) -> list[dict]:
        options = {"domain": domain, "format": "json", "registered": True}
        if self.lsh:
            options["lsh"] = self.lsh
        if self.phash:
            options["phash"] = True
        if self.threads:
            options["threads"] = self.threads
        if self.dictionary:
            options["dictionary"] = str(self.dictionary)

        logger.info("Scanning %s (lsh=%s, phash=%s)", domain, self.lsh, self.phash)
        try:
            # dnstwist prints its own report to stdout; keep it out of our output.
            with contextlib.redirect_stdout(io.StringIO()):
                variants = dnstwist.run(**options)
        except Exception as exc:
            raise ScanError(f"dnstwist failed for {domain}: {exc}") from exc
        except SystemExit as exc:
            # dnstwist reports bad options and missing browsers through argparse, which exits.
            raise ScanError(f"dnstwist refused the options for {domain} (missing dependency?)") from exc

        registered = [
            v for v in variants
            if v.get("fuzzer") != ORIGINAL_FUZZER and is_registered(v)
        ]
        logger.info("%d registered variants found for %s", len(registered), domain)
        return registered
