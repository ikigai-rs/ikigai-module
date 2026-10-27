//! The abi crate's mirrors and this crate's session types are ONE wire.
//!
//! For every variant of both session enums, a real value is built twice: once with this
//! crate's types (ikigai-core inside) and once, by hand and independently, with the mirrors in
//! `ikigai_module::abi`. Then, for each pair:
//!
//! - both encode the same bytes;
//! - the core bytes decode as the mirror and re-encode identically, and the mirror's bytes
//!   decode as the core type and re-encode identically;
//! - the `From`/`TryFrom` conversions land on those same bytes.
//!
//! The cases include the awkward ones: an IRI with `%` and `#`, a URI template, empty and
//! non-empty arguments, every `ArgRef` form, every `Expiry`, every capability shape, threads
//! on `ResolvedThreaded`, and a card whose description leaves `skip_serializing_if` fields
//! out. One value per variant is also checked in as hex, in `tests/vectors/module-abi.txt`,
//! for the Python, Deno and .NET faces to pin; `IKIGAI_WRITE_VECTORS=1 cargo test --test
//! abi_compat` rewrites it, and the diff is then the review.

use ikigai_core::{
    ArgRef, ArgSpec, Capability, ContentId, Description, Expiry, Iri, ReprType, Representation,
    Request, SpaceEntry, Time, Verb,
};
use ikigai_module::abi::{
    AbiArgRef, AbiCapability, AbiCapabilityKind, AbiExpiry, AbiModuleCall, AbiModuleCard,
    AbiModuleError, AbiModuleManifest, AbiModuleReply, AbiModuleRewrite, AbiReprType,
    AbiRepresentation, AbiRequest, AbiSpaceEntry, AbiVerb,
};
use ikigai_module::{
    ModuleCall, ModuleCard, ModuleError, ModuleManifest, ModuleReply, ModuleRewrite,
};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Shared fixtures, each in both shapes.
// ---------------------------------------------------------------------------

/// `%`, `#` and a query: what an `Iri` holds that a careless string mirror might mangle.
const AWKWARD_IRI: &str = "urn:ikigai:test:a%20b?x=1#frag";
/// A URI template: not an IRI (oxiri refuses `{`), so it rides where the wire holds one, a
/// binding's pattern.
const TEMPLATE: &str = "urn:ikigai:test:item:{id}";
const CONTENT: &str = "b3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

fn iri(text: &str) -> Iri {
    Iri::parse(text).expect("a valid IRI")
}

fn content_id() -> ContentId {
    ContentId::parse(CONTENT).expect("a content id")
}

fn core_request_bare() -> Request {
    Request::new(Verb::Source, iri("urn:m:hello"))
}

fn abi_request_bare() -> AbiRequest {
    AbiRequest {
        verb: AbiVerb::Source,
        target: "urn:m:hello".to_string(),
        args: BTreeMap::new(),
    }
}

/// Every `ArgRef` form, an empty inline value among them, on a verb other than `Source`.
fn core_request_full() -> Request {
    Request::new(Verb::Sink, iri(AWKWARD_IRI))
        .with_arg("content", ArgRef::Inline(b"caf\xc3\xa9".to_vec()))
        .with_arg("empty", ArgRef::Inline(Vec::new()))
        .with_arg("ref", ArgRef::Reference(iri("urn:host:name#x")))
        .with_arg("stored", ArgRef::Content(content_id()))
}

fn abi_request_full() -> AbiRequest {
    AbiRequest::new(AbiVerb::Sink, AWKWARD_IRI)
        .with_arg("content", AbiArgRef::Inline(b"caf\xc3\xa9".to_vec()))
        .with_arg("empty", AbiArgRef::Inline(Vec::new()))
        .with_arg("ref", AbiArgRef::Reference("urn:host:name#x".to_string()))
        .with_arg("stored", AbiArgRef::Content(CONTENT.to_string()))
}

fn core_scoped() -> Capability {
    // A grant and a deny-shaped exclusion: the set crosses whole.
    Capability::scoped(["urn:cap:fs:read:/root", "urn:cap:fs:read:-/root/secret"])
}

fn abi_scoped() -> AbiCapability {
    AbiCapability {
        kind: AbiCapabilityKind::Scoped(
            ["urn:cap:fs:read:/root", "urn:cap:fs:read:-/root/secret"]
                .into_iter()
                .map(String::from)
                .collect(),
        ),
    }
}

fn core_repr(expiry: Expiry) -> Representation {
    Representation::new(
        ReprType::new("text/plain").with_param("charset", "utf-8"),
        b"hello, world".to_vec(),
    )
    .with_expiry(expiry)
}

fn abi_repr(expiry: AbiExpiry) -> AbiRepresentation {
    AbiRepresentation {
        repr_type: AbiReprType {
            media_type: "text/plain".to_string(),
            params: [("charset".to_string(), "utf-8".to_string())].into(),
        },
        bytes: b"hello, world".to_vec(),
        expiry,
    }
}

fn core_repr_plain() -> Representation {
    Representation::new(ReprType::new("application/octet-stream"), Vec::new())
}

fn abi_repr_plain() -> AbiRepresentation {
    AbiRepresentation::new("application/octet-stream", Vec::new())
}

const DEADLINE: u64 = 1_793_000_000_123;

fn core_entries() -> Vec<SpaceEntry> {
    vec![
        SpaceEntry::new("urn:m:hello", "hello"),
        SpaceEntry::new(TEMPLATE, "item").with_origin("beefybox"),
    ]
}

fn abi_entries() -> Vec<AbiSpaceEntry> {
    vec![
        AbiSpaceEntry {
            pattern: "urn:m:hello".to_string(),
            endpoint: "hello".to_string(),
            origin: None,
        },
        AbiSpaceEntry {
            pattern: TEMPLATE.to_string(),
            endpoint: "item".to_string(),
            origin: Some("beefybox".to_string()),
        },
    ]
}

fn core_errors() -> Vec<ModuleError> {
    vec![
        ModuleError::Unresolved(AWKWARD_IRI.to_string()),
        ModuleError::MissingArgument("content".to_string()),
        ModuleError::InvalidArgument {
            name: "n".to_string(),
            detail: "not a number".to_string(),
        },
        ModuleError::Endpoint("boom".to_string()),
        ModuleError::Denied("not yours".to_string()),
        ModuleError::NotFound("gone".to_string()),
        ModuleError::Timeout("slow".to_string()),
        ModuleError::Unavailable("".to_string()),
    ]
}

fn abi_errors() -> Vec<AbiModuleError> {
    vec![
        AbiModuleError::Unresolved(AWKWARD_IRI.to_string()),
        AbiModuleError::MissingArgument("content".to_string()),
        AbiModuleError::InvalidArgument {
            name: "n".to_string(),
            detail: "not a number".to_string(),
        },
        AbiModuleError::Endpoint("boom".to_string()),
        AbiModuleError::Denied("not yours".to_string()),
        AbiModuleError::NotFound("gone".to_string()),
        AbiModuleError::Timeout("slow".to_string()),
        AbiModuleError::Unavailable("".to_string()),
    ]
}

fn core_rewrites() -> Vec<ModuleRewrite> {
    vec![
        ModuleRewrite::None,
        ModuleRewrite::Table("exact urn:xslt:render urn:xslt:transform\n".to_string()),
        ModuleRewrite::Undeclarable("a closure".to_string()),
        ModuleRewrite::Unknown,
    ]
}

fn abi_rewrites() -> Vec<AbiModuleRewrite> {
    vec![
        AbiModuleRewrite::None,
        AbiModuleRewrite::Table("exact urn:xslt:render urn:xslt:transform\n".to_string()),
        AbiModuleRewrite::Undeclarable("a closure".to_string()),
        AbiModuleRewrite::Unknown,
    ]
}

/// A bare card: every `skip_serializing_if` field of `Description` left at its default, so
/// the JSON text omits them.
fn bare_description() -> Description {
    Description::new("echo")
}

/// A rich card: inputs, an output, a requirement.
fn rich_description() -> Description {
    Description::new("upper")
        .title("Upper")
        .summary("Upper-cases its input.")
        .verb(Verb::Source)
        .input(ArgSpec::new("in").class("http://www.w3.org/2001/XMLSchema#string"))
        .output("text/plain")
        .requires("urn:cap:test:read")
}

fn json(description: &Description) -> String {
    serde_json::to_string(description).expect("a description is JSON")
}

// ---------------------------------------------------------------------------
// Every variant, both shapes. The first case of each variant is its checked-in vector.
// ---------------------------------------------------------------------------

struct Case<C, A> {
    name: String,
    core: C,
    abi: A,
}

fn case<C, A>(name: impl Into<String>, core: C, abi: A) -> Case<C, A> {
    Case {
        name: name.into(),
        core,
        abi,
    }
}

fn calls() -> Vec<Case<ModuleCall, AbiModuleCall>> {
    let mut cases = vec![
        case(
            "ModuleCall.Invoke",
            ModuleCall::Invoke {
                request: core_request_bare(),
                capability: Capability::root(),
            },
            AbiModuleCall::Invoke {
                request: abi_request_bare(),
                capability: AbiCapability::root(),
            },
        ),
        case(
            "ModuleCall.Invoke (every ArgRef, awkward IRI, scoped with an exclusion)",
            ModuleCall::Invoke {
                request: core_request_full(),
                capability: core_scoped(),
            },
            AbiModuleCall::Invoke {
                request: abi_request_full(),
                capability: abi_scoped(),
            },
        ),
        case(
            "ModuleCall.Invoke (empty scope set)",
            ModuleCall::Invoke {
                request: Request::new(Verb::Meta, iri("urn:m:hello")),
                capability: Capability::scoped(Vec::<String>::new()),
            },
            AbiModuleCall::Invoke {
                request: AbiRequest::new(AbiVerb::Meta, "urn:m:hello"),
                capability: AbiCapability::scoped(Vec::<String>::new()),
            },
        ),
        case(
            "ModuleCall.HostResult",
            ModuleCall::HostResult(Ok(core_repr(Expiry::Always))),
            AbiModuleCall::HostResult(Ok(abi_repr(AbiExpiry::Always))),
        ),
        case(
            "ModuleCall.HostResult (At)",
            ModuleCall::HostResult(Ok(core_repr(Expiry::At(Time::from_millis(DEADLINE))))),
            AbiModuleCall::HostResult(Ok(abi_repr(AbiExpiry::At(DEADLINE)))),
        ),
        case(
            "ModuleCall.HostResult (Never, empty bytes)",
            ModuleCall::HostResult(Ok(core_repr_plain().with_expiry(Expiry::Never))),
            AbiModuleCall::HostResult(Ok(AbiRepresentation {
                expiry: AbiExpiry::Never,
                ..abi_repr_plain()
            })),
        ),
        case(
            "ModuleCall.HostResult (Err)",
            ModuleCall::HostResult(Err("endpoint failed".to_string())),
            AbiModuleCall::HostResult(Err("endpoint failed".to_string())),
        ),
        case(
            "ModuleCall.Describe",
            ModuleCall::Describe,
            AbiModuleCall::Describe,
        ),
        case(
            "ModuleCall.Manifest",
            ModuleCall::Manifest,
            AbiModuleCall::Manifest,
        ),
    ];
    for (i, (core, abi)) in core_errors().into_iter().zip(abi_errors()).enumerate() {
        let name = if i == 0 {
            "ModuleCall.HostError".to_string()
        } else {
            format!("ModuleCall.HostError ({core:?})")
        };
        cases.push(case(
            name,
            ModuleCall::HostError(core),
            AbiModuleCall::HostError(abi),
        ));
    }
    cases.push(case(
        "ModuleCall.Cards",
        ModuleCall::Cards,
        AbiModuleCall::Cards,
    ));
    cases
}

fn replies() -> Vec<Case<ModuleReply, AbiModuleReply>> {
    let mut cases = vec![
        case(
            "ModuleReply.HostCall",
            ModuleReply::HostCall {
                request: Request::new(Verb::Source, iri("urn:host:name")),
                capability: Capability::scoped(["urn:cap:test:read"]),
            },
            AbiModuleReply::HostCall {
                request: AbiRequest::new(AbiVerb::Source, "urn:host:name"),
                capability: AbiCapability::scoped(["urn:cap:test:read"]),
            },
        ),
        case(
            "ModuleReply.HostCall (every ArgRef, root claim)",
            ModuleReply::HostCall {
                request: core_request_full(),
                capability: Capability::root(),
            },
            AbiModuleReply::HostCall {
                request: abi_request_full(),
                capability: AbiCapability::root(),
            },
        ),
        case(
            "ModuleReply.Resolved",
            ModuleReply::Resolved(core_repr(Expiry::Never)),
            AbiModuleReply::Resolved(abi_repr(AbiExpiry::Never)),
        ),
        case(
            "ModuleReply.Resolved (empty, no params)",
            ModuleReply::Resolved(core_repr_plain()),
            AbiModuleReply::Resolved(abi_repr_plain()),
        ),
        case(
            "ModuleReply.Error",
            ModuleReply::Error("no such endpoint: urn:m:nope".to_string()),
            AbiModuleReply::Error("no such endpoint: urn:m:nope".to_string()),
        ),
        case(
            "ModuleReply.Bindings",
            ModuleReply::Bindings(Some(core_entries())),
            AbiModuleReply::Bindings(Some(abi_entries())),
        ),
        case(
            "ModuleReply.Bindings (None)",
            ModuleReply::Bindings(None),
            AbiModuleReply::Bindings(None),
        ),
        case(
            "ModuleReply.Bindings (empty)",
            ModuleReply::Bindings(Some(Vec::new())),
            AbiModuleReply::Bindings(Some(Vec::new())),
        ),
    ];
    for (i, (core, abi)) in core_rewrites().into_iter().zip(abi_rewrites()).enumerate() {
        let (name, core_entries, abi_entries) = if i == 0 {
            (
                "ModuleReply.Manifest".to_string(),
                Some(core_entries()),
                Some(abi_entries()),
            )
        } else {
            (format!("ModuleReply.Manifest ({core:?})"), None, None)
        };
        cases.push(case(
            name,
            ModuleReply::Manifest(ModuleManifest::new(core_entries, core)),
            AbiModuleReply::Manifest(AbiModuleManifest {
                entries: abi_entries,
                rewrite: abi,
            }),
        ));
    }
    for (i, (core, abi)) in core_errors().into_iter().zip(abi_errors()).enumerate() {
        let name = if i == 0 {
            "ModuleReply.ErrorTyped".to_string()
        } else {
            format!("ModuleReply.ErrorTyped ({core:?})")
        };
        cases.push(case(
            name,
            ModuleReply::ErrorTyped(core),
            AbiModuleReply::ErrorTyped(abi),
        ));
    }
    cases.push(case(
        "ModuleReply.ResolvedThreaded",
        ModuleReply::ResolvedThreaded {
            representation: core_repr(Expiry::At(Time::from_millis(DEADLINE))),
            threads: vec!["urn:file:notes.txt".to_string(), AWKWARD_IRI.to_string()],
        },
        AbiModuleReply::ResolvedThreaded {
            representation: abi_repr(AbiExpiry::At(DEADLINE)),
            threads: vec!["urn:file:notes.txt".to_string(), AWKWARD_IRI.to_string()],
        },
    ));
    cases.push(case(
        "ModuleReply.Cards",
        ModuleReply::Cards(vec![ModuleCard {
            entry: SpaceEntry::new("urn:m:echo", "echo"),
            description: bare_description(),
        }]),
        AbiModuleReply::Cards(vec![AbiModuleCard {
            entry: AbiSpaceEntry {
                pattern: "urn:m:echo".to_string(),
                endpoint: "echo".to_string(),
                origin: None,
            },
            description: json(&bare_description()),
        }]),
    ));
    cases.push(case(
        "ModuleReply.Cards (rich, templated, and none)",
        ModuleReply::Cards(vec![
            ModuleCard {
                entry: SpaceEntry::new(TEMPLATE, "upper").with_origin("beefybox"),
                description: rich_description(),
            },
            ModuleCard {
                entry: SpaceEntry::new("urn:m:echo", "echo"),
                description: bare_description(),
            },
        ]),
        AbiModuleReply::Cards(vec![
            AbiModuleCard {
                entry: AbiSpaceEntry {
                    pattern: TEMPLATE.to_string(),
                    endpoint: "upper".to_string(),
                    origin: Some("beefybox".to_string()),
                },
                description: json(&rich_description()),
            },
            AbiModuleCard {
                entry: AbiSpaceEntry {
                    pattern: "urn:m:echo".to_string(),
                    endpoint: "echo".to_string(),
                    origin: None,
                },
                description: json(&bare_description()),
            },
        ]),
    ));
    cases.push(case(
        "ModuleReply.Cards (empty)",
        ModuleReply::Cards(Vec::new()),
        AbiModuleReply::Cards(Vec::new()),
    ));
    cases
}

fn encode<T: serde::Serialize>(value: &T) -> Vec<u8> {
    postcard::to_allocvec(value).expect("encodes")
}

// ---------------------------------------------------------------------------
// The proofs.
// ---------------------------------------------------------------------------

#[test]
fn every_variant_is_covered() {
    // A variant appended to either enum must get a case here: the names cover all of them.
    let names: Vec<String> = calls()
        .into_iter()
        .map(|c| c.name)
        .chain(replies().into_iter().map(|c| c.name))
        .collect();
    for variant in [
        "ModuleCall.Invoke",
        "ModuleCall.HostResult",
        "ModuleCall.Describe",
        "ModuleCall.Manifest",
        "ModuleCall.HostError",
        "ModuleCall.Cards",
        "ModuleReply.HostCall",
        "ModuleReply.Resolved",
        "ModuleReply.Error",
        "ModuleReply.Bindings",
        "ModuleReply.Manifest",
        "ModuleReply.ErrorTyped",
        "ModuleReply.ResolvedThreaded",
        "ModuleReply.Cards",
    ] {
        assert!(names.iter().any(|n| n == variant), "no case for {variant}");
    }
    // And the variant counts the matches below are exhaustive over, so a new variant fails
    // to compile here before it can slip past the list above.
    for case in calls() {
        match case.core {
            ModuleCall::Invoke { .. }
            | ModuleCall::HostResult(_)
            | ModuleCall::Describe
            | ModuleCall::Manifest
            | ModuleCall::HostError(_)
            | ModuleCall::Cards => {}
        }
    }
    for case in replies() {
        match case.core {
            ModuleReply::HostCall { .. }
            | ModuleReply::Resolved(_)
            | ModuleReply::Error(_)
            | ModuleReply::Bindings(_)
            | ModuleReply::Manifest(_)
            | ModuleReply::ErrorTyped(_)
            | ModuleReply::ResolvedThreaded { .. }
            | ModuleReply::Cards(_) => {}
        }
    }
}

#[test]
fn both_shapes_encode_the_same_bytes() {
    for case in calls() {
        assert_eq!(encode(&case.core), encode(&case.abi), "{}", case.name);
    }
    for case in replies() {
        assert_eq!(encode(&case.core), encode(&case.abi), "{}", case.name);
    }
}

#[test]
fn core_bytes_decode_as_the_mirror_and_re_encode_identically() {
    for case in calls() {
        let bytes = encode(&case.core);
        let mirror = AbiModuleCall::decode(&bytes).unwrap_or_else(|e| panic!("{}: {e}", case.name));
        assert_eq!(mirror, case.abi, "{}", case.name);
        assert_eq!(mirror.encode().unwrap(), bytes, "{}", case.name);
    }
    for case in replies() {
        let bytes = encode(&case.core);
        let mirror =
            AbiModuleReply::decode(&bytes).unwrap_or_else(|e| panic!("{}: {e}", case.name));
        assert_eq!(mirror, case.abi, "{}", case.name);
        assert_eq!(mirror.encode().unwrap(), bytes, "{}", case.name);
    }
}

#[test]
fn mirror_bytes_decode_as_core_and_re_encode_identically() {
    for case in calls() {
        let bytes = case.abi.encode().unwrap();
        let core: ModuleCall =
            postcard::from_bytes(&bytes).unwrap_or_else(|e| panic!("{}: {e}", case.name));
        assert_eq!(encode(&core), bytes, "{}", case.name);
    }
    for case in replies() {
        let bytes = case.abi.encode().unwrap();
        let core: ModuleReply =
            postcard::from_bytes(&bytes).unwrap_or_else(|e| panic!("{}: {e}", case.name));
        assert_eq!(encode(&core), bytes, "{}", case.name);
    }
}

#[test]
fn the_conversions_land_on_the_same_bytes() {
    for case in calls() {
        let bytes = encode(&case.core);
        let mirrored = AbiModuleCall::from(case.core.clone());
        assert_eq!(mirrored, case.abi, "{}", case.name);
        let back =
            ModuleCall::try_from(case.abi.clone()).unwrap_or_else(|e| panic!("{}: {e}", case.name));
        assert_eq!(encode(&back), bytes, "{}", case.name);
    }
    for case in replies() {
        let bytes = encode(&case.core);
        let mirrored = AbiModuleReply::try_from(case.core.clone())
            .unwrap_or_else(|e| panic!("{}: {e}", case.name));
        assert_eq!(mirrored, case.abi, "{}", case.name);
        let back = ModuleReply::try_from(case.abi.clone())
            .unwrap_or_else(|e| panic!("{}: {e}", case.name));
        assert_eq!(encode(&back), bytes, "{}", case.name);
    }
}

#[test]
fn a_threaded_result_keeps_its_threads_through_the_conversion() {
    // `Representation::threads` is not serialized; `ResolvedThreaded` carries them beside it,
    // and the conversion carries that list as it is, in order.
    let reply = ModuleReply::ResolvedThreaded {
        representation: core_repr(Expiry::Never).depends_on("urn:ignored:by:the:wire"),
        threads: vec!["urn:a".to_string(), "urn:b".to_string()],
    };
    let AbiModuleReply::ResolvedThreaded { threads, .. } =
        AbiModuleReply::try_from(reply).expect("converts")
    else {
        panic!("expected ResolvedThreaded");
    };
    assert_eq!(threads, ["urn:a", "urn:b"]);
}

#[test]
fn a_mirror_string_is_checked_when_it_becomes_a_core_type() {
    // The mirrors validate nothing a string can hold; the conversion does, as decoding would.
    let not_an_iri = AbiModuleCall::Invoke {
        request: AbiRequest::new(AbiVerb::Source, "not an iri"),
        capability: AbiCapability::root(),
    };
    assert!(ModuleCall::try_from(not_an_iri.clone()).is_err());
    assert!(postcard::from_bytes::<ModuleCall>(&not_an_iri.encode().unwrap()).is_err());

    let not_content = AbiModuleCall::Invoke {
        request: AbiRequest::new(AbiVerb::Source, "urn:a")
            .with_arg("x", AbiArgRef::Content("md5:nope".to_string())),
        capability: AbiCapability::root(),
    };
    assert!(ModuleCall::try_from(not_content.clone()).is_err());
    assert!(postcard::from_bytes::<ModuleCall>(&not_content.encode().unwrap()).is_err());

    let not_json = AbiModuleReply::Cards(vec![AbiModuleCard {
        entry: AbiSpaceEntry {
            pattern: "urn:a".to_string(),
            endpoint: "a".to_string(),
            origin: None,
        },
        description: "{not json".to_string(),
    }]);
    assert!(ModuleReply::try_from(not_json.clone()).is_err());
    assert!(postcard::from_bytes::<ModuleReply>(&not_json.encode().unwrap()).is_err());
}

#[test]
fn a_template_is_not_an_iri() {
    // Why the template case rides in a binding's pattern rather than a request's target.
    assert!(Iri::parse(TEMPLATE).is_err());
    assert!(Iri::parse(AWKWARD_IRI).is_ok());
}

#[test]
fn the_error_mirror_round_trips_every_variant() {
    for (core, abi) in core_errors().into_iter().zip(abi_errors()) {
        assert_eq!(AbiModuleError::from(core.clone()), abi);
        assert_eq!(ModuleError::from(abi), core);
    }
    for (core, abi) in core_rewrites().into_iter().zip(abi_rewrites()) {
        assert_eq!(AbiModuleRewrite::from(core.clone()), abi);
        assert_eq!(ModuleRewrite::from(abi), core);
    }
}

// ---------------------------------------------------------------------------
// The checked-in vectors.
// ---------------------------------------------------------------------------

const VECTORS: &str = "tests/vectors/module-abi.txt";

const VECTORS_HEADER: &str = "\
# ikigai module session: one postcard encoding per message variant, for other-language faces.
# Generated by ikigai-module's tests/abi_compat.rs from values built twice, with ikigai-core's
# types and with ikigai-module-abi's mirrors; both encode exactly these bytes.
# Rewrite: IKIGAI_WRITE_VECTORS=1 cargo test --test abi_compat
# Format: <Enum>.<Variant> <lowercase hex>
";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn vector_text() -> String {
    let mut text = VECTORS_HEADER.to_string();
    let mut seen = std::collections::BTreeSet::new();
    let calls = calls()
        .into_iter()
        .map(|c| (c.name, encode(&c.core), c.abi.encode().unwrap()));
    let replies = replies()
        .into_iter()
        .map(|c| (c.name, encode(&c.core), c.abi.encode().unwrap()));
    for (name, core, abi) in calls.chain(replies) {
        // The first case of each variant (its name has no parenthesized qualifier).
        if name.contains(' ') || !seen.insert(name.clone()) {
            continue;
        }
        assert_eq!(core, abi, "{name}");
        text.push_str(&format!("{name} {}\n", hex(&core)));
    }
    text
}

#[test]
fn the_checked_in_vectors_are_what_both_shapes_encode() {
    let expected = vector_text();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTORS);
    if std::env::var_os("IKIGAI_WRITE_VECTORS").is_some() {
        std::fs::write(&path, &expected).expect("write the vectors");
    }
    let on_disk = std::fs::read_to_string(&path).expect("read the vectors");
    assert_eq!(
        on_disk, expected,
        "{VECTORS} is stale; rewrite it with IKIGAI_WRITE_VECTORS=1 and review the diff"
    );
    // Fourteen variants, one line each.
    assert_eq!(on_disk.lines().filter(|l| !l.starts_with('#')).count(), 14);
}
