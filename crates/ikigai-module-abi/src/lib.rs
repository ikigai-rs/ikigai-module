//! `ikigai-module-abi`: the ikigai module session's wire types, with no ikigai crate under them.
//!
//! A module session is a conversation of [`AbiModuleCall`]s (host to module) and
//! [`AbiModuleReply`]s (module to host), each one postcard-encoded. `ikigai-module` defines that
//! session over ikigai-core's own types (`Request`, `Capability`, `Representation`, ...), which
//! is right for a host and costly for a guest: deserializing an `Iri` runs the full RFC 3987
//! parser, and a card's description goes through `serde_json`, so a minimal wasm guest built on
//! those types is about three times the size of one that only speaks the bytes.
//!
//! This crate is the second shape of the same session: **wire-only mirrors**, variant for
//! variant and field for field, in the same order, with `String` where core has an `Iri` or a
//! content id, the card's description as the JSON text it already is on the wire, and
//! `Vec<u8>` for bytes. On postcard an `Iri` IS a string and that description IS JSON text, so
//! a mirror encodes the same bytes as the type it mirrors, and either side can decode the
//! other's. `ikigai-module`'s `tests/abi_compat.rs` proves it for every variant of both enums,
//! in both directions, and its `tests/vectors/module-abi.txt` holds one checked-in encoding per
//! variant for other-language peers to pin.
//!
//! Who it is for:
//!
//! - **wasm guests**, which want the session and nothing else (`no_std + alloc` is enough);
//! - **peers in other languages**, for whom these definitions are the readable statement of
//!   the wire, and the vectors the test of it.
//!
//! A host written in Rust keeps using `ikigai-module`, which re-exports this crate as
//! `ikigai_module::abi` and converts between the two shapes.
//!
//! ## What a mirror does not do
//!
//! A mirror validates nothing a string can hold: an [`AbiRequest`]'s `target` is not checked
//! as an IRI, and an [`AbiArgRef::Content`] is not checked as a content id. The receiver that
//! turns them into ikigai-core's types checks them then, exactly as decoding into those types
//! would have. The one check kept is the one that changes what a valid encoding means: an
//! argument map that names an argument twice is refused, as core refuses it, rather than
//! narrowed to its last value.
//!
//! ★ **An [`AbiCapability`] is a claim, never authority.** A guest writes its own
//! `HostCall` bytes, capability included. A host maps a guest's call to the capability of the
//! session the guest was invoked under (`ikigai_module::serve_host_call` clamps it), never to
//! the one the guest carried.
//!
//! ## The wire, as bytes
//!
//! postcard keys an enum on its variant index (a varint), writes a string or a byte vector as
//! a varint length and its bytes, and writes a struct as its fields in order. So the session's
//! smallest message is one byte, and an `Invoke` reads straight off its definition:
//!
//! ```
//! use ikigai_module_abi::{AbiCapability, AbiModuleCall, AbiRequest, AbiVerb};
//!
//! // `Describe` is variant 2 of `AbiModuleCall`.
//! assert_eq!(AbiModuleCall::Describe.encode().unwrap(), [2]);
//!
//! let invoke = AbiModuleCall::Invoke {
//!     request: AbiRequest::new(AbiVerb::Source, "urn:a"),
//!     capability: AbiCapability::root(),
//! };
//! assert_eq!(
//!     invoke.encode().unwrap(),
//!     [
//!         0, // Invoke
//!         0, // verb: Source
//!         5, b'u', b'r', b'n', b':', b'a', // target: a length-prefixed string
//!         0, // args: an empty map
//!         0, // capability: Root
//!     ]
//! );
//! assert_eq!(AbiModuleCall::decode(&invoke.encode().unwrap()).unwrap(), invoke);
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};

/// The codec's error: what [`AbiModuleCall::decode`] and the other codec helpers return.
pub use postcard::Error as CodecError;

// ---------------------------------------------------------------------------
// The session.
//
// ⚠ Variant ORDER is the wire contract (postcard keys an enum on its index): append only,
// in step with ikigai-module, whose types these mirror.
// ---------------------------------------------------------------------------

/// Host to module: mirrors `ikigai_module::ModuleCall`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbiModuleCall {
    /// Begin an invocation of one of the module's endpoints, under `capability`.
    Invoke {
        /// What to do.
        request: AbiRequest,
        /// The authority the invocation runs under, as the host states it.
        capability: AbiCapability,
    },
    /// The host's answer to an [`AbiModuleReply::HostCall`]: `Ok` for every success, `Err`
    /// for a failure that was an endpoint error (the one kind a bare string carries
    /// losslessly). Any other failure arrives as [`HostError`](AbiModuleCall::HostError).
    HostResult(Result<AbiRepresentation, String>),
    /// Ask for the module's bound entries.
    Describe,
    /// Ask for the module's [`AbiModuleManifest`]: its bindings and how it rewrites names.
    Manifest,
    /// The host's answer to an [`AbiModuleReply::HostCall`] that failed, with the failure's
    /// type intact.
    HostError(AbiModuleError),
    /// Ask for every bound entry's [`AbiModuleCard`].
    Cards,
}

/// Module to host: mirrors `ikigai_module::ModuleReply`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbiModuleReply {
    /// The module needs a resource resolved on the host; the host answers with an
    /// [`AbiModuleCall::HostResult`] or [`AbiModuleCall::HostError`].
    ///
    /// The `capability` is a CLAIM: the host holds the call to the capability of the
    /// session the module was invoked under, and a module can narrow it, never widen it.
    HostCall {
        /// What the module wants resolved.
        request: AbiRequest,
        /// The authority the module asks to use, never more than its session's.
        capability: AbiCapability,
    },
    /// The invocation finished with a representation that declares no golden thread.
    Resolved(AbiRepresentation),
    /// The invocation failed with an endpoint error (the message).
    Error(String),
    /// The answer to an [`AbiModuleCall::Describe`]: the bound entries, or `None` when the
    /// module cannot enumerate them.
    Bindings(Option<Vec<AbiSpaceEntry>>),
    /// The answer to an [`AbiModuleCall::Manifest`].
    Manifest(AbiModuleManifest),
    /// The invocation failed, and the failure keeps its type.
    ErrorTyped(AbiModuleError),
    /// The invocation finished with a representation and the golden threads its endpoint
    /// declared on it. Sent only when there are any; a threadless result is
    /// [`Resolved`](AbiModuleReply::Resolved).
    ResolvedThreaded {
        /// The result.
        representation: AbiRepresentation,
        /// The names of the threads the endpoint declared on it.
        threads: Vec<String>,
    },
    /// The answer to an [`AbiModuleCall::Cards`].
    Cards(Vec<AbiModuleCard>),
}

impl AbiModuleCall {
    /// This call as postcard bytes, the form the session carries.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        postcard::to_allocvec(self)
    }

    /// Decode a call from postcard bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        postcard::from_bytes(bytes)
    }
}

impl AbiModuleReply {
    /// This reply as postcard bytes, the form the session carries.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        postcard::to_allocvec(self)
    }

    /// Decode a reply from postcard bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        postcard::from_bytes(bytes)
    }
}

/// The error taxonomy on the module wire: mirrors `ikigai_module::ModuleError`, itself a
/// mirror of ikigai-core's `Error`. Variant order is the contract: append only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbiModuleError {
    /// The space found no binding for the target (the IRI, as text).
    Unresolved(String),
    /// A required argument was absent (its name).
    MissingArgument(String),
    /// An argument was present but unusable.
    InvalidArgument {
        /// The argument name.
        name: String,
        /// What was wrong with it.
        detail: String,
    },
    /// The endpoint failed while producing its representation.
    Endpoint(String),
    /// Permanent: the capability did not authorize it.
    Denied(String),
    /// Permanent: a bound endpoint reports the thing it fronts absent.
    NotFound(String),
    /// Transient.
    Timeout(String),
    /// Transient.
    Unavailable(String),
}

// ---------------------------------------------------------------------------
// What the session carries: mirrors of ikigai-core's wire types.
// ---------------------------------------------------------------------------

/// A verb: mirrors ikigai-core's `Verb`. On the wire it is the variant INDEX (`Source` is 0),
/// not core's `#[repr(u8)]` discriminant (`Source = 1`), which serde does not read.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum AbiVerb {
    /// Read a resource's representation.
    Source,
    /// Write or replace a resource's representation.
    Sink,
    /// Test for a resource's existence.
    Exists,
    /// Remove a resource.
    Delete,
    /// Read a resource's self-description.
    Meta,
}

/// How an argument value is supplied: mirrors ikigai-core's `ArgRef`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum AbiArgRef {
    /// A reference to another resource, by IRI (unchecked here).
    Reference(String),
    /// A literal value carried inline.
    Inline(Vec<u8>),
    /// A value in a content store, by its content id (`b3:<hex>`, unchecked here).
    Content(String),
}

/// A request: mirrors ikigai-core's `Request`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AbiRequest {
    /// The verb.
    pub verb: AbiVerb,
    /// The target resource's IRI (unchecked here).
    pub target: String,
    /// Named arguments, sorted by name. A map that names an argument twice is refused on
    /// decode, as core refuses it, so no valid encoding means anything different here.
    #[serde(default, deserialize_with = "unique_args")]
    pub args: BTreeMap<String, AbiArgRef>,
}

impl AbiRequest {
    /// A request with no arguments.
    pub fn new(verb: AbiVerb, target: impl Into<String>) -> Self {
        AbiRequest {
            verb,
            target: target.into(),
            args: BTreeMap::new(),
        }
    }

    /// Add or replace an argument (builder style).
    pub fn with_arg(mut self, name: impl Into<String>, arg: AbiArgRef) -> Self {
        self.args.insert(name.into(), arg);
        self
    }
}

/// Decode an argument map, refusing a repeated name rather than keeping the last value of it
/// (ikigai-core's rule, ledger #1731).
fn unique_args<'de, D>(deserializer: D) -> Result<BTreeMap<String, AbiArgRef>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Unique;
    impl<'de> serde::de::Visitor<'de> for Unique {
        type Value = BTreeMap<String, AbiArgRef>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map of argument names to values, each name once")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut args = BTreeMap::new();
            while let Some((name, value)) = map.next_entry::<String, AbiArgRef>()? {
                if args.contains_key(&name) {
                    return Err(serde::de::Error::custom(GivenTwice(&name)));
                }
                args.insert(name, value);
            }
            Ok(args)
        }
    }
    deserializer.deserialize_map(Unique)
}

/// Core's refusal text for a repeated argument, written without allocating.
struct GivenTwice<'a>(&'a str);

impl fmt::Display for GivenTwice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid argument `{}`: given twice; an argument takes one value, so name it once",
            self.0
        )
    }
}

/// A capability as the wire carries it: mirrors ikigai-core's `Capability`, a struct of one
/// field, `kind`.
///
/// ★ A CLAIM, never authority: see the crate docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiCapability {
    /// Root, or exactly these scopes.
    pub kind: AbiCapabilityKind,
}

/// What an [`AbiCapability`] claims: mirrors ikigai-core's private `Kind`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbiCapabilityKind {
    /// Every scope.
    Root,
    /// Exactly these `urn:cap:` scopes, grants and exclusions together.
    Scoped(BTreeSet<String>),
}

impl AbiCapability {
    /// The root claim.
    pub fn root() -> Self {
        AbiCapability {
            kind: AbiCapabilityKind::Root,
        }
    }

    /// A claim of exactly `scopes`.
    pub fn scoped<I, S>(scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        AbiCapability {
            kind: AbiCapabilityKind::Scoped(scopes.into_iter().map(Into::into).collect()),
        }
    }
}

/// A representation type: mirrors ikigai-core's `ReprType`.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct AbiReprType {
    /// The media type, e.g. `text/turtle`.
    pub media_type: String,
    /// Parameters, sorted by key.
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}

impl AbiReprType {
    /// A representation type with no parameters.
    pub fn new(media_type: impl Into<String>) -> Self {
        AbiReprType {
            media_type: media_type.into(),
            params: BTreeMap::new(),
        }
    }
}

/// How long a representation stays valid: mirrors ikigai-core's `Expiry`. Core's `At` holds
/// a `Time`, a newtype over milliseconds since the Unix epoch, which postcard encodes as the
/// `u64` it wraps.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum AbiExpiry {
    /// Never cached (the default).
    #[default]
    Always,
    /// Cached until this deadline, in milliseconds since the Unix epoch.
    At(u64),
    /// Never expires.
    Never,
}

/// A representation: mirrors ikigai-core's `Representation<Vec<u8>>` as it crosses a wire.
/// Core's golden threads are not serialized, so there is no field for them here;
/// [`AbiModuleReply::ResolvedThreaded`] carries a result's threads beside it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AbiRepresentation {
    /// The representation type.
    pub repr_type: AbiReprType,
    /// The bytes.
    pub bytes: Vec<u8>,
    /// Cache validity.
    #[serde(default)]
    pub expiry: AbiExpiry,
}

impl AbiRepresentation {
    /// A representation of `bytes` as `media_type`, uncacheable.
    pub fn new(media_type: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        AbiRepresentation {
            repr_type: AbiReprType::new(media_type),
            bytes: bytes.into(),
            expiry: AbiExpiry::Always,
        }
    }
}

/// One binding in a space: mirrors ikigai-core's `SpaceEntry`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiSpaceEntry {
    /// The pattern: an exact IRI, or a URI template like `urn:x:{id}`.
    pub pattern: String,
    /// The bound endpoint's name.
    pub endpoint: String,
    /// Where the binding came from in a federated catalog; `None` for the module's own.
    pub origin: Option<String>,
}

/// How a module rewrites the names it is given: mirrors `ikigai_module::ModuleRewrite`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbiModuleRewrite {
    /// Every target resolves under the name it was given.
    None,
    /// Rewritten through this table, in ikigai-core's `AliasTable` text form.
    Table(String),
    /// The module rewrites in a way it cannot write down (the reason).
    Undeclarable(String),
    /// No claim was made. Not the same as [`None`](AbiModuleRewrite::None).
    Unknown,
}

/// A module's self-description: mirrors `ikigai_module::ModuleManifest`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiModuleManifest {
    /// The module's bound entries.
    pub entries: Option<Vec<AbiSpaceEntry>>,
    /// How the module rewrites names.
    pub rewrite: AbiModuleRewrite,
}

/// One bound entry and its endpoint's card: mirrors `ikigai_module::ModuleCard` as it crosses
/// the wire.
///
/// The description is ikigai-core's `Description` as **JSON text**, which is what
/// `ModuleCard` puts in the postcard frame; producing or reading that JSON is the caller's
/// business, so a guest that never sends cards links no JSON code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiModuleCard {
    /// The binding.
    pub entry: AbiSpaceEntry,
    /// The endpoint's self-description, as JSON text.
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn a_repeated_argument_is_refused_not_narrowed() {
        // Hand-built: Invoke, Source, "urn:a", a map of TWO entries both named "x".
        let bytes = [
            0, 0, 5, b'u', b'r', b'n', b':', b'a', 2, // two args
            1, b'x', 1, 1, b'1', // x = Inline("1")
            1, b'x', 1, 1, b'2', // x = Inline("2")
            0,
        ];
        assert!(AbiModuleCall::decode(&bytes).is_err());
    }

    #[test]
    fn every_reply_round_trips() {
        let representation = AbiRepresentation {
            repr_type: AbiReprType {
                media_type: "text/plain".into(),
                params: [("charset".into(), "utf-8".into())].into(),
            },
            bytes: vec![1, 2, 3],
            expiry: AbiExpiry::At(42),
        };
        for reply in [
            AbiModuleReply::HostCall {
                request: AbiRequest::new(AbiVerb::Meta, "urn:x")
                    .with_arg("a", AbiArgRef::Content("b3:00".into())),
                capability: AbiCapability::scoped(["urn:cap:x"]),
            },
            AbiModuleReply::Resolved(representation.clone()),
            AbiModuleReply::Error("no".into()),
            AbiModuleReply::Bindings(None),
            AbiModuleReply::Manifest(AbiModuleManifest {
                entries: Some(vec![]),
                rewrite: AbiModuleRewrite::Unknown,
            }),
            AbiModuleReply::ErrorTyped(AbiModuleError::Timeout("slow".into())),
            AbiModuleReply::ResolvedThreaded {
                representation,
                threads: vec!["urn:t".into()],
            },
            AbiModuleReply::Cards(vec![]),
        ] {
            let bytes = reply.encode().unwrap();
            assert_eq!(AbiModuleReply::decode(&bytes).unwrap(), reply);
        }
    }
}
