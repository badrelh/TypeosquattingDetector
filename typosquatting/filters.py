"""Allowlist: legitimate domains that must not be reported as look-alikes."""

from pathlib import Path
from typing import Iterable, Union

PathLike = Union[str, Path]


def is_allowed(domain: str, allowed: Iterable[str]) -> bool:
    """True when the domain is an allowed domain or one of its subdomains."""
    domain = domain.lower()
    return any(domain == entry or domain.endswith("." + entry) for entry in allowed)


def apply_allowlist(variants: list[dict], allowed: Iterable[str]) -> list[dict]:
    allowed = list(allowed)
    return [v for v in variants if not is_allowed(v["domain"], allowed)]


def load_allowlist(path: PathLike) -> list[str]:
    """One domain per line; blank lines and everything after `#` are ignored."""
    entries = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        entry = line.split("#", 1)[0].strip().lower()
        if entry:
            entries.append(entry)
    return entries
