import json

import pytest

from typosquatting.state import find_new, load_state, save_state, update_state


def variants(*names):
    return [{"domain": name, "fuzzer": "omission", "dns_a": ["1.2.3.4"]} for name in names]


def test_load_state_of_a_missing_file_is_empty(tmp_path):
    assert load_state(tmp_path / "missing.json") == {}


def test_save_then_load_round_trips_without_leaving_a_temporary_file(tmp_path):
    path = tmp_path / "state.json"

    save_state(path, {"example.com": ["b.com", "a.com"]})

    assert load_state(path) == {"example.com": ["b.com", "a.com"]}
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]


@pytest.mark.parametrize("content", ["not json", "[1, 2]"])
def test_load_state_rejects_invalid_content(tmp_path, content):
    path = tmp_path / "state.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError):
        load_state(path)


def test_first_scan_is_a_baseline_with_nothing_new():
    assert find_new("example.com", variants("a.com", "b.com"), {}) == ([], True)


def test_find_new_lists_only_unseen_lookalikes_sorted():
    state = {"example.com": ["a.com"]}

    assert find_new("example.com", variants("c.com", "a.com", "b.com"), state) == (["b.com", "c.com"], False)


def test_other_domains_in_the_state_do_not_count_as_known():
    state = {"other.com": ["a.com"]}

    assert find_new("example.com", variants("a.com"), state) == ([], True)


def test_update_state_keeps_names_that_disappeared():
    state = {"example.com": ["a.com", "gone.com"]}

    update_state("example.com", variants("a.com", "b.com"), state)

    assert state == {"example.com": ["a.com", "b.com", "gone.com"]}
    assert find_new("example.com", variants("gone.com"), state) == ([], False)


def test_state_file_is_plain_json(tmp_path):
    path = tmp_path / "state.json"
    save_state(path, {"example.com": ["a.com"]})

    assert json.loads(path.read_text(encoding="utf-8")) == {"example.com": ["a.com"]}
