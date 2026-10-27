//! Conversions between this crate's typed session and its wire-only mirrors in
//! [`ikigai_module_abi`] (re-exported as [`crate::abi`]).
//!
//! The two shapes encode the same bytes (`tests/abi_compat.rs`), so each conversion here is
//! exactly what encoding one and decoding the other would do, without the bytes. Toward the
//! mirrors nothing can fail but a card, whose description becomes JSON text; away from them a
//! string becomes an [`Iri`] or a [`ContentId`] and is checked as one, and a card's JSON text
//! becomes a `Description` again.
//!
//! Only the session's own types convert publicly. The pieces they carry (`Request`,
//! `Capability`, `Representation`, ...) are ikigai-core's on one side and the abi crate's on
//! the other, and Rust's orphan rule lets neither crate implement `From` between two types it
//! does not own; they convert through the private helpers below.
//!
//! ★ There is deliberately no conversion from an [`AbiCapability`] to a [`Capability`] of its
//! own. The two places one is built are an `Invoke` (a capability the HOST stated) and a
//! `HostCall` (a module's CLAIM, exactly what decoding a `ModuleReply` from the module's bytes
//! has always produced). A host runs a host call through [`serve_host_call`](crate::serve_host_call)
//! or a native transport, which clamp the claim to the session's capability (ledger #83);
//! nothing here treats it as authority.

use crate::abi::{
    AbiArgRef, AbiCapability, AbiCapabilityKind, AbiExpiry, AbiModuleCall, AbiModuleCard,
    AbiModuleError, AbiModuleManifest, AbiModuleReply, AbiModuleRewrite, AbiReprType,
    AbiRepresentation, AbiRequest, AbiSpaceEntry, AbiVerb,
};
use crate::{ModuleCall, ModuleCard, ModuleError, ModuleManifest, ModuleReply, ModuleRewrite};
use ikigai_core::{
    ArgRef, Capability, ContentId, Expiry, Iri, ReprType, Representation, Request, SpaceEntry,
    Time, Verb,
};
use std::fmt;

/// Why a value could not cross from one session shape to the other: a string that is not
/// the IRI or content id it stands for, or a card whose description is not the JSON of a
/// `Description`. Each is exactly the failure decoding the same bytes would have reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbiConversionError(String);

impl AbiConversionError {
    /// What was wrong.
    pub fn detail(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AbiConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AbiConversionError {}

type Converted<T> = std::result::Result<T, AbiConversionError>;

// ---------------------------------------------------------------------------
// The pieces (private: both sides are foreign to this crate).
// ---------------------------------------------------------------------------

fn verb_to_abi(verb: Verb) -> AbiVerb {
    match verb {
        Verb::Source => AbiVerb::Source,
        Verb::Sink => AbiVerb::Sink,
        Verb::Exists => AbiVerb::Exists,
        Verb::Delete => AbiVerb::Delete,
        Verb::Meta => AbiVerb::Meta,
    }
}

fn verb_from_abi(verb: AbiVerb) -> Verb {
    match verb {
        AbiVerb::Source => Verb::Source,
        AbiVerb::Sink => Verb::Sink,
        AbiVerb::Exists => Verb::Exists,
        AbiVerb::Delete => Verb::Delete,
        AbiVerb::Meta => Verb::Meta,
    }
}

fn iri(text: String) -> Converted<Iri> {
    Iri::parse(text.as_str()).map_err(|e| AbiConversionError(format!("not an IRI: {text:?}: {e}")))
}

fn arg_to_abi(arg: ArgRef) -> AbiArgRef {
    match arg {
        ArgRef::Reference(iri) => AbiArgRef::Reference(iri.as_str().to_string()),
        ArgRef::Inline(bytes) => AbiArgRef::Inline(bytes),
        ArgRef::Content(id) => AbiArgRef::Content(id.to_string()),
    }
}

fn arg_from_abi(arg: AbiArgRef) -> Converted<ArgRef> {
    Ok(match arg {
        AbiArgRef::Reference(text) => ArgRef::Reference(iri(text)?),
        AbiArgRef::Inline(bytes) => ArgRef::Inline(bytes),
        AbiArgRef::Content(text) => ArgRef::Content(
            ContentId::parse(&text)
                .map_err(|e| AbiConversionError(format!("not a content id: {text:?}: {e}")))?,
        ),
    })
}

fn request_to_abi(request: Request) -> AbiRequest {
    AbiRequest {
        verb: verb_to_abi(request.verb),
        target: request.target.as_str().to_string(),
        args: request
            .args
            .into_iter()
            .map(|(name, arg)| (name, arg_to_abi(arg)))
            .collect(),
    }
}

fn request_from_abi(request: AbiRequest) -> Converted<Request> {
    let mut built = Request::new(verb_from_abi(request.verb), iri(request.target)?);
    for (name, arg) in request.args {
        built.args.insert(name, arg_from_abi(arg)?);
    }
    Ok(built)
}

fn capability_to_abi(capability: &Capability) -> AbiCapability {
    match capability.scopes() {
        None => AbiCapability::root(),
        Some(scopes) => AbiCapability {
            kind: AbiCapabilityKind::Scoped(scopes.clone()),
        },
    }
}

/// The capability a message states. Private on purpose: see the module docs.
fn capability_from_abi(capability: AbiCapability) -> Capability {
    match capability.kind {
        AbiCapabilityKind::Root => Capability::root(),
        AbiCapabilityKind::Scoped(scopes) => Capability::scoped(scopes),
    }
}

fn expiry_to_abi(expiry: Expiry) -> AbiExpiry {
    match expiry {
        Expiry::Always => AbiExpiry::Always,
        Expiry::At(time) => AbiExpiry::At(time.as_millis()),
        Expiry::Never => AbiExpiry::Never,
    }
}

fn expiry_from_abi(expiry: AbiExpiry) -> Expiry {
    match expiry {
        AbiExpiry::Always => Expiry::Always,
        AbiExpiry::At(millis) => Expiry::At(Time::from_millis(millis)),
        AbiExpiry::Never => Expiry::Never,
    }
}

/// The representation as the wire carries it: its golden threads are not part of it (core
/// serializes none), exactly as encoding drops them.
fn representation_to_abi(representation: Representation) -> AbiRepresentation {
    AbiRepresentation {
        repr_type: AbiReprType {
            media_type: representation.repr_type.media_type,
            params: representation.repr_type.params,
        },
        bytes: representation.bytes,
        expiry: expiry_to_abi(representation.expiry),
    }
}

fn representation_from_abi(representation: AbiRepresentation) -> Representation {
    let mut repr_type = ReprType::new(representation.repr_type.media_type);
    repr_type.params = representation.repr_type.params;
    Representation::new(repr_type, representation.bytes)
        .with_expiry(expiry_from_abi(representation.expiry))
}

fn entry_to_abi(entry: SpaceEntry) -> AbiSpaceEntry {
    AbiSpaceEntry {
        pattern: entry.pattern,
        endpoint: entry.endpoint,
        origin: entry.origin,
    }
}

fn entry_from_abi(entry: AbiSpaceEntry) -> SpaceEntry {
    SpaceEntry {
        pattern: entry.pattern,
        endpoint: entry.endpoint,
        origin: entry.origin,
    }
}

fn entries_to_abi(entries: Option<Vec<SpaceEntry>>) -> Option<Vec<AbiSpaceEntry>> {
    entries.map(|entries| entries.into_iter().map(entry_to_abi).collect())
}

fn entries_from_abi(entries: Option<Vec<AbiSpaceEntry>>) -> Option<Vec<SpaceEntry>> {
    entries.map(|entries| entries.into_iter().map(entry_from_abi).collect())
}

// ---------------------------------------------------------------------------
// The session's own types (public: one side of each is this crate's).
// ---------------------------------------------------------------------------

impl From<ModuleError> for AbiModuleError {
    fn from(error: ModuleError) -> Self {
        match error {
            ModuleError::Unresolved(iri) => AbiModuleError::Unresolved(iri),
            ModuleError::MissingArgument(name) => AbiModuleError::MissingArgument(name),
            ModuleError::InvalidArgument { name, detail } => {
                AbiModuleError::InvalidArgument { name, detail }
            }
            ModuleError::Endpoint(message) => AbiModuleError::Endpoint(message),
            ModuleError::Denied(message) => AbiModuleError::Denied(message),
            ModuleError::NotFound(message) => AbiModuleError::NotFound(message),
            ModuleError::Timeout(message) => AbiModuleError::Timeout(message),
            ModuleError::Unavailable(message) => AbiModuleError::Unavailable(message),
        }
    }
}

impl From<AbiModuleError> for ModuleError {
    fn from(error: AbiModuleError) -> Self {
        match error {
            AbiModuleError::Unresolved(iri) => ModuleError::Unresolved(iri),
            AbiModuleError::MissingArgument(name) => ModuleError::MissingArgument(name),
            AbiModuleError::InvalidArgument { name, detail } => {
                ModuleError::InvalidArgument { name, detail }
            }
            AbiModuleError::Endpoint(message) => ModuleError::Endpoint(message),
            AbiModuleError::Denied(message) => ModuleError::Denied(message),
            AbiModuleError::NotFound(message) => ModuleError::NotFound(message),
            AbiModuleError::Timeout(message) => ModuleError::Timeout(message),
            AbiModuleError::Unavailable(message) => ModuleError::Unavailable(message),
        }
    }
}

impl From<ModuleRewrite> for AbiModuleRewrite {
    fn from(rewrite: ModuleRewrite) -> Self {
        match rewrite {
            ModuleRewrite::None => AbiModuleRewrite::None,
            ModuleRewrite::Table(text) => AbiModuleRewrite::Table(text),
            ModuleRewrite::Undeclarable(reason) => AbiModuleRewrite::Undeclarable(reason),
            ModuleRewrite::Unknown => AbiModuleRewrite::Unknown,
        }
    }
}

impl From<AbiModuleRewrite> for ModuleRewrite {
    fn from(rewrite: AbiModuleRewrite) -> Self {
        match rewrite {
            AbiModuleRewrite::None => ModuleRewrite::None,
            AbiModuleRewrite::Table(text) => ModuleRewrite::Table(text),
            AbiModuleRewrite::Undeclarable(reason) => ModuleRewrite::Undeclarable(reason),
            AbiModuleRewrite::Unknown => ModuleRewrite::Unknown,
        }
    }
}

impl From<ModuleManifest> for AbiModuleManifest {
    fn from(manifest: ModuleManifest) -> Self {
        AbiModuleManifest {
            entries: entries_to_abi(manifest.entries),
            rewrite: manifest.rewrite.into(),
        }
    }
}

impl From<AbiModuleManifest> for ModuleManifest {
    fn from(manifest: AbiModuleManifest) -> Self {
        ModuleManifest {
            entries: entries_from_abi(manifest.entries),
            rewrite: manifest.rewrite.into(),
        }
    }
}

impl TryFrom<ModuleCard> for AbiModuleCard {
    type Error = AbiConversionError;

    /// The card as it crosses the wire: its description becomes the JSON text
    /// [`ModuleCard`]'s own `Serialize` writes.
    fn try_from(card: ModuleCard) -> Converted<Self> {
        let description = serde_json::to_string(&card.description)
            .map_err(|e| AbiConversionError(format!("card description as JSON: {e}")))?;
        Ok(AbiModuleCard {
            entry: entry_to_abi(card.entry),
            description,
        })
    }
}

impl TryFrom<AbiModuleCard> for ModuleCard {
    type Error = AbiConversionError;

    fn try_from(card: AbiModuleCard) -> Converted<Self> {
        let description = serde_json::from_str(&card.description)
            .map_err(|e| AbiConversionError(format!("card description is not JSON: {e}")))?;
        Ok(ModuleCard {
            entry: entry_from_abi(card.entry),
            description,
        })
    }
}

impl From<ModuleCall> for AbiModuleCall {
    fn from(call: ModuleCall) -> Self {
        match call {
            ModuleCall::Invoke {
                request,
                capability,
            } => AbiModuleCall::Invoke {
                request: request_to_abi(request),
                capability: capability_to_abi(&capability),
            },
            ModuleCall::HostResult(result) => {
                AbiModuleCall::HostResult(result.map(representation_to_abi))
            }
            ModuleCall::Describe => AbiModuleCall::Describe,
            ModuleCall::Manifest => AbiModuleCall::Manifest,
            ModuleCall::HostError(error) => AbiModuleCall::HostError(error.into()),
            ModuleCall::Cards => AbiModuleCall::Cards,
        }
    }
}

impl TryFrom<AbiModuleCall> for ModuleCall {
    type Error = AbiConversionError;

    fn try_from(call: AbiModuleCall) -> Converted<Self> {
        Ok(match call {
            AbiModuleCall::Invoke {
                request,
                capability,
            } => ModuleCall::Invoke {
                request: request_from_abi(request)?,
                capability: capability_from_abi(capability),
            },
            AbiModuleCall::HostResult(result) => {
                ModuleCall::HostResult(result.map(representation_from_abi))
            }
            AbiModuleCall::Describe => ModuleCall::Describe,
            AbiModuleCall::Manifest => ModuleCall::Manifest,
            AbiModuleCall::HostError(error) => ModuleCall::HostError(error.into()),
            AbiModuleCall::Cards => ModuleCall::Cards,
        })
    }
}

impl TryFrom<ModuleReply> for AbiModuleReply {
    type Error = AbiConversionError;

    fn try_from(reply: ModuleReply) -> Converted<Self> {
        Ok(match reply {
            ModuleReply::HostCall {
                request,
                capability,
            } => AbiModuleReply::HostCall {
                request: request_to_abi(request),
                capability: capability_to_abi(&capability),
            },
            ModuleReply::Resolved(representation) => {
                AbiModuleReply::Resolved(representation_to_abi(representation))
            }
            ModuleReply::Error(message) => AbiModuleReply::Error(message),
            ModuleReply::Bindings(entries) => AbiModuleReply::Bindings(entries_to_abi(entries)),
            ModuleReply::Manifest(manifest) => AbiModuleReply::Manifest(manifest.into()),
            ModuleReply::ErrorTyped(error) => AbiModuleReply::ErrorTyped(error.into()),
            ModuleReply::ResolvedThreaded {
                representation,
                threads,
            } => AbiModuleReply::ResolvedThreaded {
                representation: representation_to_abi(representation),
                threads,
            },
            ModuleReply::Cards(cards) => AbiModuleReply::Cards(
                cards
                    .into_iter()
                    .map(AbiModuleCard::try_from)
                    .collect::<Converted<_>>()?,
            ),
        })
    }
}

impl TryFrom<AbiModuleReply> for ModuleReply {
    type Error = AbiConversionError;

    /// The reply a module's bytes would decode to. A `HostCall`'s capability is the module's
    /// CLAIM, as it is when decoded: run the call through
    /// [`serve_host_call`](crate::serve_host_call) or a native transport, which hold it to the
    /// session's capability, never issue under it directly.
    fn try_from(reply: AbiModuleReply) -> Converted<Self> {
        Ok(match reply {
            AbiModuleReply::HostCall {
                request,
                capability,
            } => ModuleReply::HostCall {
                request: request_from_abi(request)?,
                capability: capability_from_abi(capability),
            },
            AbiModuleReply::Resolved(representation) => {
                ModuleReply::Resolved(representation_from_abi(representation))
            }
            AbiModuleReply::Error(message) => ModuleReply::Error(message),
            AbiModuleReply::Bindings(entries) => ModuleReply::Bindings(entries_from_abi(entries)),
            AbiModuleReply::Manifest(manifest) => ModuleReply::Manifest(manifest.into()),
            AbiModuleReply::ErrorTyped(error) => ModuleReply::ErrorTyped(error.into()),
            AbiModuleReply::ResolvedThreaded {
                representation,
                threads,
            } => ModuleReply::ResolvedThreaded {
                representation: representation_from_abi(representation),
                threads,
            },
            AbiModuleReply::Cards(cards) => ModuleReply::Cards(
                cards
                    .into_iter()
                    .map(ModuleCard::try_from)
                    .collect::<Converted<_>>()?,
            ),
        })
    }
}
