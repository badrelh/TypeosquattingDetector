from typosquatting.filters import apply_allowlist, is_allowed, load_allowlist


def test_allowed_domain_and_its_subdomains_match():
    assert is_allowed("example.org", ["example.org"])
    assert is_allowed("mail.Example.org", ["example.org"])


def test_similar_names_are_not_allowed_by_accident():
    assert not is_allowed("badexample.org", ["example.org"])
    assert not is_allowed("example.org.evil.com", ["example.org"])


def test_apply_allowlist_drops_only_allowed_variants():
    variants = [{"domain": "example.org"}, {"domain": "exampl.com"}, {"domain": "shop.example.org"}]

    assert apply_allowlist(variants, ["example.org"]) == [{"domain": "exampl.com"}]


def test_load_allowlist_ignores_comments_and_blank_lines(tmp_path):
    path = tmp_path / "allow.txt"
    path.write_text("# our own domains\nExample.org  # main site\n\nexample.net\n", encoding="utf-8")

    assert load_allowlist(path) == ["example.org", "example.net"]
