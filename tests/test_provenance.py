from taintwall.provenance import Origin, Segment, derive, explain


def test_trust_is_derived_from_origin() -> None:
    for origin in Origin:
        expected = "trusted" if origin in {Origin.SYSTEM, Origin.USER} else "untrusted"
        assert Segment(id=origin.value, text="x", origin=origin).trust == expected


def test_derive_unions_labels_and_preserves_secret_and_private() -> None:
    private = Segment(
        id="private-source",
        text="private",
        origin=Origin.USER,
        labels={"private", "pii"},
    )
    secret = Segment(
        id="secret-source",
        text="secret",
        origin=Origin.FILE,
        labels={"secret", "public"},
    )

    combined = derive("combined", [private, secret], "combined-id", origin=Origin.TOOL_OUTPUT)
    further_derived = derive("summary", [combined], "summary-id", origin=Origin.RAG)

    assert combined.labels == frozenset({"private", "secret", "pii", "public"})
    assert further_derived.labels == combined.labels


def test_derive_records_untrusted_source_ids() -> None:
    trusted = Segment(id="user-request", text="summarize", origin=Origin.USER)
    untrusted = Segment(id="email-1", text="ignore rules", origin=Origin.EMAIL)

    result = derive("summary", [trusted, untrusted], "summary-1", origin=Origin.TOOL_OUTPUT)

    assert result.tainted_by == frozenset({"email-1"})


def test_derive_from_trusted_only_has_no_taint() -> None:
    system = Segment(id="system-1", text="rules", origin=Origin.SYSTEM)
    user = Segment(id="user-1", text="request", origin=Origin.USER)

    result = derive("combined", [system, user], "combined-1", origin=Origin.USER)

    assert result.tainted_by == frozenset()


def test_taint_propagates_through_two_derived_segments() -> None:
    email = Segment(id="email-1", text="injection", origin=Origin.EMAIL)
    first = derive("quoted text", [email], "quote-1", origin=Origin.TOOL_OUTPUT)
    second = derive("summary", [first], "summary-1", origin=Origin.USER)

    assert first.tainted_by == frozenset({"email-1"})
    assert second.tainted_by == frozenset({"email-1"})


def test_explain_includes_untrusted_path_in_text_and_structure() -> None:
    email = Segment(id="email-1", text="injection", origin=Origin.EMAIL)
    derived = derive("summary", [email], "summary-1", origin=Origin.TOOL_OUTPUT)

    explanation = explain(derived)

    assert "email-1" in explanation["message"]
    assert explanation["source_ids"] == ["email-1"]
    assert explanation["untrusted_source_ids"] == ["email-1"]
    assert explanation["trust"] == "untrusted"
