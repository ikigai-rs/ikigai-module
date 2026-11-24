//! Audit of the module boundary. The ignored test records a protocol change still needed.
use ikigai_core::{Denial, Error};
use ikigai_module::{abi::AbiModuleError, ModuleError};

#[test]
#[ignore = "structured denial scopes are not represented in the current module protocol"]
fn structured_denial_preserves_lacking_scopes_across_abi() {
    let original = Error::Denied(Denial::lacking(
        "permission required",
        vec!["urn:cap:read".into(), "urn:cap:write:*".into()],
    ));
    let wire: AbiModuleError = ModuleError::from(&original).into();
    let back: Error = ModuleError::from(wire).into();
    assert_eq!(back, original);
}

#[test]
fn generated_requests_and_representations_round_trip() {
    use ikigai_core::{
        ArgRef, Capability, ContentId, Expiry, Iri, ReprType, Representation, Request, Time, Verb,
    };
    use ikigai_module::{
        abi::{AbiModuleCall, AbiModuleReply},
        ModuleCall, ModuleReply,
    };

    let id =
        ContentId::parse("b3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
            .unwrap();
    for verb in [
        Verb::Source,
        Verb::Sink,
        Verb::Exists,
        Verb::Delete,
        Verb::Meta,
    ] {
        for size in [0, 1, 127, 128, 1024] {
            let request = Request::new(verb, Iri::parse("urn:test:a%20b#c").unwrap())
                .with_arg("inline", ArgRef::Inline(vec![0xff; size]))
                .with_arg(
                    "reference",
                    ArgRef::Reference(Iri::parse("urn:test:ref").unwrap()),
                )
                .with_arg("stored", ArgRef::Content(id));
            let original = ModuleCall::Invoke {
                request,
                capability: Capability::scoped(["urn:cap:read"]),
            };
            let bytes = postcard::to_allocvec(&original).unwrap();
            let abi = AbiModuleCall::from(original);
            assert_eq!(abi.encode().unwrap(), bytes);
            let back = ModuleCall::try_from(AbiModuleCall::decode(&bytes).unwrap()).unwrap();
            assert_eq!(postcard::to_allocvec(&back).unwrap(), bytes);
        }
    }
    for expiry in [
        Expiry::Always,
        Expiry::Never,
        Expiry::At(Time::from_millis(u64::MAX)),
    ] {
        for size in [0, 1, 127, 128, 1024] {
            let repr = Representation::new(
                ReprType::new("text/plain").with_param("charset", "utf-8"),
                vec![42; size],
            )
            .with_expiry(expiry);
            let original = ModuleReply::ResolvedThreaded {
                representation: repr,
                threads: vec!["urn:thread:1".into(), "urn:thread:2".into()],
            };
            let bytes = postcard::to_allocvec(&original).unwrap();
            let abi = AbiModuleReply::try_from(original).unwrap();
            assert_eq!(abi.encode().unwrap(), bytes);
            let back = ModuleReply::try_from(AbiModuleReply::decode(&bytes).unwrap()).unwrap();
            assert_eq!(postcard::to_allocvec(&back).unwrap(), bytes);
        }
    }
}

#[test]
fn malformed_lengths_and_utf8_are_rejected() {
    use ikigai_module::abi::AbiModuleCall;
    // Invoke, Source, then an invalid or truncated length-prefixed target string.
    for bytes in [
        &[0, 0, 2, b'a'][..],
        &[0, 0, 1, 0xff][..],
        &[
            0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ][..],
    ] {
        assert!(AbiModuleCall::decode(bytes).is_err(), "accepted {bytes:?}");
    }
}
