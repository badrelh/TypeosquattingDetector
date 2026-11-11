from typosquatting.metrics import summarize, top_similar


VARIANTS = [
    {"domain": "a.com", "fuzzer": "omission", "dns_a": ["1.1.1.1"], "tlsh": 40, "phash": 12},
    {"domain": "b.com", "fuzzer": "omission", "dns_a": ["1.1.1.2"], "tlsh": 90, "phash": 3},
    {"domain": "c.com", "fuzzer": "homoglyph", "dns_a": ["1.1.1.3"], "ssdeep": 75},
]


def test_higher_similarity_ranks_first_for_every_metric():
    assert [v["domain"] for v in top_similar(VARIANTS, "tlsh")] == ["b.com", "a.com"]
    assert [v["domain"] for v in top_similar(VARIANTS, "ssdeep")] == ["c.com"]
    assert [v["domain"] for v in top_similar(VARIANTS, "phash")] == ["a.com", "b.com"]


def test_zero_similarity_is_not_listed():
    variants = [{"domain": "a.com", "fuzzer": "omission", "phash": 0}]

    assert top_similar(variants, "phash") == []


def test_top_similar_respects_limit():
    assert len(top_similar(VARIANTS, "tlsh", limit=1)) == 1


def test_summarize_counts_techniques_and_lists_closest():
    summary = summarize("example.com", VARIANTS, limit=2)

    assert summary["registered_count"] == 3
    assert summary["by_technique"] == {"omission": 2, "homoglyph": 1}
    assert summary["closest"]["tlsh"][0] == {"domain": "b.com", "score": 90}
    assert set(summary["closest"]) == {"tlsh", "ssdeep", "phash"}


def test_summarize_omits_metrics_nobody_measured():
    summary = summarize("example.com", [{"domain": "a.com", "fuzzer": "omission", "dns_a": ["1"]}])

    assert summary["closest"] == {}
