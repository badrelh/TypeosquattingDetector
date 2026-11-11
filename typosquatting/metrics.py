"""Summarise scan results: counts per technique and the closest look-alikes."""

from collections import Counter
from typing import Any

# dnstwist scores are similarity percentages: 0 means no similarity, 100 means identical.
SIMILARITY_KEYS = ("tlsh", "ssdeep", "phash")


def top_similar(variants: list[dict], metric: str, limit: int = 5) -> list[dict]:
    """Return the variants most similar to the original for one metric, best first."""
    scored = [v for v in variants if v.get(metric)]
    scored.sort(key=lambda v: v[metric], reverse=True)
    return scored[:limit]


def summarize(domain: str, variants: list[dict], limit: int = 5) -> dict[str, Any]:
    """Build the summary used by the text report, the JSON output and the e-mail."""
    by_technique = Counter(v.get("fuzzer", "unknown") for v in variants)
    return {
        "domain": domain,
        "registered_count": len(variants),
        "by_technique": dict(by_technique.most_common()),
        "closest": {
            metric: [
                {"domain": v["domain"], "score": v[metric]}
                for v in top_similar(variants, metric, limit)
            ]
            for metric in SIMILARITY_KEYS
            if any(v.get(metric) is not None for v in variants)
        },
        "variants": variants,
    }
