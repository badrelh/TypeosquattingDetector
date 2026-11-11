from typosquatting.risk import apply_risk, assess, has_records


def test_variant_with_no_signal_scores_zero():
    assert assess({"domain": "a.com", "fuzzer": "omission", "dns_a": ["1.2.3.4"]}) == (0, [])


def test_recent_registration_scores_by_age_band():
    assert assess({"age_days": 5})[0] == 3
    assert assess({"age_days": 60})[0] == 2
    assert assess({"age_days": 200})[0] == 1
    assert assess({"age_days": 800})[0] == 0


def test_mail_server_adds_risk():
    points, reasons = assess({"dns_mx": ["mail.example.net"]})

    assert points == 2
    assert "MX" in reasons[0]


def test_servfail_marker_is_not_a_mail_server():
    assert not has_records({"dns_mx": ["!ServFail"]}, "dns_mx")
    assert assess({"dns_mx": ["!ServFail"]}) == (0, [])


def test_content_similarity_uses_the_best_metric():
    assert assess({"tlsh": 80, "phash": 10})[0] == 3
    assert assess({"ssdeep": 45})[0] == 2
    assert assess({"phash": 5})[0] == 1


def test_visual_and_certificate_origins_add_risk():
    assert assess({"fuzzer": "homoglyph"})[0] == 1
    assert assess({"fuzzer": "ct-log"})[0] == 2


def test_signals_add_up_with_one_reason_each():
    variant = {"age_days": 3, "dns_mx": ["mx.example.net"], "tlsh": 90, "fuzzer": "cyrillic"}

    points, reasons = assess(variant)

    assert points == 3 + 2 + 3 + 1
    assert len(reasons) == 4


def test_apply_risk_stores_score_and_reasons_in_place():
    variants = [{"domain": "a.com", "dns_mx": ["mx.example.net"]}]

    apply_risk(variants)

    assert variants[0]["risk_score"] == 2
    assert variants[0]["risk_reasons"] == ["can receive and send e-mail (MX record)"]
