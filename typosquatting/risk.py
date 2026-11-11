"""Heuristic risk score: why a registered look-alike deserves attention.

The weights are judgement calls, not measured values. Each point comes with a reason
so the score can be checked and questioned instead of trusted blindly.
"""

from typing import Any

SIMILARITY_METRICS = ("tlsh", "ssdeep", "phash")
VISUAL_FUZZERS = {"homoglyph", "cyrillic"}
CT_FUZZER = "ct-log"


def has_records(variant: dict, key: str) -> bool:
    """True when dnstwist found real records; its '!ServFail' markers are not records."""
    return any(not str(record).startswith("!") for record in variant.get(key) or ())


def assess(variant: dict[str, Any]) -> tuple[int, list[str]]:
    """Return the risk points of one look-alike and the reasons behind them."""
    points = 0
    reasons: list[str] = []

    age = variant.get("age_days")
    if age is not None:
        if age < 30:
            points += 3
            reasons.append(f"registered {age} days ago")
        elif age < 90:
            points += 2
            reasons.append(f"registered {age} days ago")
        elif age < 365:
            points += 1
            reasons.append(f"registered {age} days ago")

    if has_records(variant, "dns_mx"):
        points += 2
        reasons.append("can receive and send e-mail (MX record)")

    similarity = max((variant.get(metric) or 0 for metric in SIMILARITY_METRICS), default=0)
    if similarity >= 70:
        points += 3
        reasons.append(f"content {similarity}% similar to the original")
    elif similarity >= 40:
        points += 2
        reasons.append(f"content {similarity}% similar to the original")
    elif similarity > 0:
        points += 1
        reasons.append(f"content {similarity}% similar to the original")

    fuzzer = variant.get("fuzzer")
    if fuzzer in VISUAL_FUZZERS:
        points += 1
        reasons.append("characters that look identical to the original")
    elif fuzzer == CT_FUZZER:
        points += 2
        reasons.append("a TLS certificate was issued for it")

    return points, reasons


def apply_risk(variants: list[dict]) -> None:
    """Add `risk_score` and `risk_reasons` to every variant, in place."""
    for variant in variants:
        variant["risk_score"], variant["risk_reasons"] = assess(variant)
