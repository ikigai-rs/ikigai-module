//! `ikigai-module` — the dynamically-loadable module format (**Phase 1: in-process proof**).
//!
//! A *module* is an independently-compiled `space()` + endpoints (e.g. `ikigai-xslt`)
//! that the host routes a few IRIs to, but whose endpoints must resolve their
//! `src`/`stylesheet` *resource references* against the **host's** kernel (the host owns
//! the catalog, the cache, the other spaces). So unlike the remote-kernel transports
//! (IPC/QUIC, which resolve every sub-request server-side), a module needs to call
//! **back** to the host mid-invocation. That callback lands on a seam that already
//! exists: an `Invocation` reaches the kernel through the [`Issuer`] trait.
//!
//! This crate is the runtime for that:
//!
//! - [`ModuleSpace`] (host side) routes IRIs by prefix to a module over a
//!   [`ModuleTransport`]; it slots into the kernel's root `Fallback` where a
//!   statically-linked `space()` would go.
//! - [`InProcessTransport`] (Phase 1) runs the module in-process: it resolves the
//!   request in the module's space and invokes the endpoint **with the host as its
//!   issuer** — so the endpoint's `inv.source`/`inv.issue` cross back to the host
//!   kernel, exercising the full callback machinery with zero transport risk.
//! - [`ModuleCall`] / [`ModuleReply`] define the *wire session* a real transport
//!   (a second wasm instance, or an embedded wasmtime, or a socket) marshals.
//! - [`LoopbackTransport`] runs that session **through the codec** — every message is
//!   `postcard`-encoded over an in-memory byte channel, both ends in-process — so it
//!   proves the protocol (the session state machine + `Request`/`Capability`/
//!   `Representation` marshalling) without any socket or wasm plumbing.
//! - [`UdsTransport`] + [`serve`] (Unix only) are the first *real home*: the module runs
//!   as an out-of-process peer behind a Unix-domain socket (peercred-guarded, same user),
//!   and the host drives the same session over framed socket I/O. Same loop, same issuer
//!   as the loopback — only the pipe changed.
//! - [`run_session`] is the transport-agnostic *module side* on its own: given the host's
//!   encoded `Invoke` and a closure that pumps one `HostCall`→`HostResult` exchange, it
//!   runs the endpoint and returns the encoded reply. The caller supplies the pump, so a
//!   wasm host can drive a module over a JS byte-channel without this crate touching wasm.
//! - [`wasm_module!`] + [`WasmModuleSpace`] / [`serve_host_call`] make a lazy *browser*
//!   module nearly free: the macro emits a module's cdylib glue (one line per artifact), and
//!   the host registers it with one `WasmModuleSpace::new` + a `serve_host_call` in its
//!   `hostCall` export — no hand-written wrapper crate or per-module endpoint.
//!
//! ## The module says what it does; the host says what it may do
//!
//! The kernel enforces exactly what `Endpoint::describe()` returns (*declared capabilities =
//! enforced capabilities*), and across this boundary that card must be authored by the
//! **host**. The module is the untrusted party: were its own `requires` the source of the
//! enforced requirement, a module declaring none would thereby become ungated and
//! under-declaring would be the escape hatch. Authority is never self-asserted by the thing
//! being gated.
//!
//! So every mount carries a [`ModuleFloor`] — the scopes every non-`Meta` verb under it
//! requires, folded into every card the mount hands the kernel (the enumerated ones from
//! [`ModuleSpace::with_endpoint`] *and* the generic prefix fallback) and checked host-side
//! before anything crosses the boundary. A card refines the floor; it never lowers it, an
//! IRI nobody enumerated is gated exactly as strictly as one that was, and the ungated mount
//! is a sentence a host writes ([`ModuleFloor::public`]) rather than one it omits.
//!
//! Beside it, the module **honors its own card** at every dispatch site
//! (`refuse_unsatisfied_declaration`), which can only ever deny *more* than the floor — so
//! one `.requires(..)` declaration means the same thing whether an endpoint is linked or
//! loaded.
//!
//! ## What crosses the boundary, and how it stays whole
//!
//! Three things a module boundary used to drop, each carried since 0.3 by an **appended**
//! message, so every earlier message keeps its bytes:
//!
//! - **The error's type.** A failure crosses as [`ModuleError`] — the taxonomy mirror
//!   `ikigai-wire` adopted in v7 — in both directions ([`ModuleReply::ErrorTyped`],
//!   [`ModuleCall::HostError`]), so a module-side `Denied` is permanent at the host and a
//!   host resource's `NotFound` is `NotFound` inside the module.
//! - **The result's declared golden threads.** `Representation::threads` is `serde(skip)`, so
//!   [`ModuleReply::ResolvedThreaded`] carries their names beside the bytes and the host
//!   re-attaches them; a module endpoint's `depends_on` cuts over a socket exactly as it does
//!   in-process. (The threads of host resources a module resolves through its callbacks never
//!   needed to cross — the host records those on the outer invocation.)
//! - **The module's cards.** [`ModuleSpace::connect`] asks for every binding's `describe()`
//!   ([`ModuleCall::Cards`]) and installs them beside the host's own, so an endpoint describes
//!   itself through the mount — inputs, outputs, its own `requires` — exactly as it would
//!   linked, the floor folded in. A mount made with [`ModuleSpace::new`] never asks, and
//!   describes an IRI the host declared nothing for with its generic card.
//!
//! `tests/conformance.rs` holds all three to the linked case: one fixture module walked bare
//! and through every mount, every report the bare one's.
//!
//! ## A module may compose a rewriting space
//!
//! Any space should be composable in any module — including one that resolves one name
//! under another ([`Alias`](ikigai_core::Alias), [`Rewrite`](ikigai_core::Rewrite), anything
//! reporting `Resolved::canonical`). That report is what makes a logical name and its
//! backing name ONE resource, and it cannot ride the resolution across the boundary: the
//! host never asks the module to resolve, and `Space::resolve` is synchronous while a real
//! transport is not.
//!
//! So the module **declares** its canonicalization ([`ModuleRewrite`], carried on
//! [`ModuleCall::Manifest`]) and the host installs it in its own `AliasTable`
//! ([`ModuleSpace::connect`]) — self-description reaching one layer further, applied
//! host-side at resolve time by machinery the kernel already ships. What cannot be
//! declared is said out loud rather than silently split: see [`ModuleRewrite::Undeclarable`]
//! and [`OnUndeclarable`].
//!
//! See `ikigai-cli/docs/module-format-design.md`.

// `deny`, not `forbid`, so the UDS server's peercred check (and only it) can opt into the
// `libc` FFI it needs via a scoped `#[allow(unsafe_code)]`; everything else stays unsafe-free.
#![deny(unsafe_code)]

use async_trait::async_trait;
use futures::channel::mpsc;
use futures::lock::Mutex as AsyncMutex;
use futures::StreamExt;
use ikigai_core::{
    AliasParseError, AliasTable, Bindings, Canonical, Capability, Description, Endpoint, Error,
    Expiry, FnEndpoint, Grammar, Invocation, Iri, Issuer, Representation, Request, Resolution,
    Resolved, Result, Scope, Space, SpaceEntry, Thread, UriTemplate, Verb,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// The wire session protocol (Phase 2+).
//
// `ikigai-wire`'s Call/Reply is one round-trip; a module invocation is a *session*
// — the module may interleave host callbacks before it replies. These types pin that
// contract. The in-process transport below doesn't serialize them (it calls directly),
// but a wasm/socket transport marshals them as postcard bytes, exactly like the kernel
// wire protocol.
// ---------------------------------------------------------------------------

/// host → module.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ModuleCall {
    /// Begin an invocation of one of the module's endpoints.
    Invoke {
        request: Request,
        capability: Capability,
    },
    /// The host's answer to a [`ModuleReply::HostCall`] the module made — `Ok` for every
    /// success, `Err` for a failure that was an [`Error::Endpoint`] (the one variant a bare
    /// string carries losslessly). Any other failure is answered with
    /// [`HostError`](ModuleCall::HostError), typed; a host older than that variant answers
    /// `Err(text)` for everything, which a module reads as `Error::Endpoint`.
    HostResult(std::result::Result<Representation, String>),
    /// Ask for the module's bound entries (for `entries()` / the catalog).
    Describe,
    /// Ask for the module's full [`ModuleManifest`] — its bindings **and how it
    /// rewrites names**. `Describe` one layer further, and the message a host sends
    /// once, at mount time, so it can install the module's canonicalization in its own
    /// table before the first resolution. See [`ModuleRewrite`].
    ///
    /// Appended after `Describe` on purpose: postcard keys an enum on its variant
    /// index, so every 0.1.9 message keeps its bytes. A 0.1.9 module receiving this
    /// fails to decode the call and answers [`ModuleReply::Error`], which a host reads
    /// as "cannot say" — [`ModuleRewrite::Unknown`], never "does not rewrite".
    Manifest,
    /// The host's answer to a [`ModuleReply::HostCall`] that **failed**, with the failure's
    /// type intact — so a module's `inv.source` of a host resource that is denied sees
    /// [`Error::Denied`] (permanent), not an `Endpoint` string it might retry. Appended, so
    /// every earlier message keeps its bytes; a module older than this variant cannot decode
    /// it and its callback fails with a decode error where it used to get the text — on the
    /// failure path only, since a success still rides [`HostResult`](ModuleCall::HostResult).
    HostError(ModuleError),
    /// Ask the module for every bound entry's [`ModuleCard`] — each endpoint's own
    /// `describe()`, which [`ModuleSpace::connect`] installs host-side so an endpoint
    /// describes itself through the mount exactly as it would linked. Appended; a module
    /// older than this variant fails to decode it and answers [`ModuleReply::Error`] (or
    /// drops the connection), which a host reads as "no cards", never as a failure.
    Cards,
}

/// module → host.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ModuleReply {
    /// The module needs a sub-resource resolved on the host kernel; the host replies
    /// with a [`ModuleCall::HostResult`].
    HostCall {
        request: Request,
        capability: Capability,
    },
    /// The invocation finished with a representation that declares no golden thread of its
    /// own. (`Representation::threads` is `serde(skip)`, so this shape cannot carry one; a
    /// result that declares threads crosses as
    /// [`ResolvedThreaded`](ModuleReply::ResolvedThreaded) instead.)
    Resolved(Representation),
    /// The invocation failed with an [`Error::Endpoint`] — the one variant a bare string
    /// carries losslessly, so a current module still answers it this way and a 0.2 host reads
    /// it unchanged. Every other failure crosses as [`ErrorTyped`](ModuleReply::ErrorTyped).
    ///
    /// Before 0.3 this was the only failure shape: a module-side denial arrived at the host
    /// as `Error::Endpoint`, and only `Denied` is permanent, so a retrying caller could treat
    /// a capability refusal as transient.
    Error(String),
    /// The answer to a [`ModuleCall::Describe`].
    Bindings(Option<Vec<SpaceEntry>>),
    /// The answer to a [`ModuleCall::Manifest`]. Appended after `Bindings`, for the same
    /// index-stability reason `Manifest` was.
    Manifest(ModuleManifest),
    /// The invocation failed, and the failure keeps its **type**: the host rebuilds the same
    /// [`Error`] variant the module's endpoint raised, so a module-side denial is a permanent
    /// `Denied` at the host, a module's timeout stays transient, and the conformance suite's
    /// ENFORCED check holds across the boundary. The shape `ikigai-wire` adopted in v7.
    /// Appended; a host older than this variant cannot decode it and reports a decode error
    /// where it used to get the text — on the failure path only.
    ErrorTyped(ModuleError),
    /// The invocation finished with a representation **and the golden threads its endpoint
    /// declared on it** (`Representation::threads` is `serde(skip)` — cache provenance is a
    /// per-kernel concern in core — so the module protocol carries them beside it). The host
    /// re-attaches them, so a module endpoint's `depends_on` cuts through every transport as
    /// it does in-process. Sent only when the set is non-empty; a threadless result still
    /// rides [`Resolved`](ModuleReply::Resolved), which an older host decodes.
    ResolvedThreaded {
        /// The result, its threads stripped by the codec.
        representation: Representation,
        /// The names of the threads the endpoint declared on it.
        threads: Vec<String>,
    },
    /// The answer to a [`ModuleCall::Cards`].
    Cards(Vec<ModuleCard>),
}

// ---------------------------------------------------------------------------
// ★ Failures keep their type across the boundary.
//
// `ModuleReply::Error(String)` was the only failure shape through 0.2, and it dropped the
// one thing the other side needs: the TYPE. A module-side capability refusal arrived at the
// host as `Error::Endpoint`, which is neither permanent nor transient in the kernel's
// taxonomy — so a Retry overlay could re-issue a denial forever, a Failover could paper
// over it, and the conformance suite's ENFORCED check (which wants a typed `Denied`) could
// never pass for a loaded endpoint. The host→module direction had the same hole in
// `HostResult(Err(String))`: a module resolving a host resource that is `NotFound` saw an
// endpoint string.
//
// `ModuleError` is the taxonomy on this wire, the shape `ikigai-wire` adopted in v7: a
// module-local mirror of `ikigai_core::Error`, so a core taxonomy addition is a PROTOCOL
// event here (a socket or wasm peer implements this codec independently), not a silent
// cascade. Both directions send the old untyped message whenever it is lossless — an
// `Error::Endpoint` is exactly a string — and the typed one only when the old would lose
// something, so a mixed-version pairing degrades on the failure path alone. The same rule
// carries a result's declared golden threads: `ResolvedThreaded` only when there are any.
// ---------------------------------------------------------------------------

/// The error taxonomy on the module wire — a field-for-field mirror of [`Error`], kept
/// module-local so a taxonomy addition in core is a module-protocol event, never a silent
/// cascade. Variant order is the postcard contract: append only.
///
/// A failure crosses and comes back as the variant it was, transience included:
///
/// ```
/// use ikigai_core::Error;
/// use ikigai_module::ModuleError;
///
/// let denied = Error::Denied("not yours".to_string());
/// let back: Error = ModuleError::from(&denied).into();
/// assert_eq!(back, denied);
/// assert!(!back.is_transient(), "a denial stays permanent across the boundary");
///
/// let timeout = Error::Timeout("slow".to_string());
/// let back: Error = ModuleError::from(&timeout).into();
/// assert_eq!(back, timeout);
/// assert!(back.is_transient());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleError {
    /// The module's space found no binding for the target (the IRI, as text).
    Unresolved(String),
    /// A required argument was absent.
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

impl From<&Error> for ModuleError {
    fn from(error: &Error) -> Self {
        match error {
            Error::Unresolved(iri) => ModuleError::Unresolved(iri.as_str().to_string()),
            Error::MissingArgument(name) => ModuleError::MissingArgument(name.clone()),
            Error::InvalidArgument { name, detail } => ModuleError::InvalidArgument {
                name: name.clone(),
                detail: detail.clone(),
            },
            Error::Endpoint(message) => ModuleError::Endpoint(message.clone()),
            Error::Denied(message) => ModuleError::Denied(message.clone()),
            Error::NotFound(message) => ModuleError::NotFound(message.clone()),
            Error::Timeout(message) => ModuleError::Timeout(message.clone()),
            Error::Unavailable(message) => ModuleError::Unavailable(message.clone()),
            // `Error` is `non_exhaustive`: a variant newer than this protocol revision
            // degrades to `Endpoint` (message preserved) until the protocol catches up — a
            // taxonomy addition is a protocol event, and an older peer meanwhile sees a
            // correct-if-untyped failure.
            other => ModuleError::Endpoint(other.to_string()),
        }
    }
}

impl From<ModuleError> for Error {
    fn from(error: ModuleError) -> Self {
        match error {
            // The IRI crossed the wire FROM an `Iri`, so a parse failure here is corruption;
            // degrade to `Endpoint` rather than panic.
            ModuleError::Unresolved(iri) => match Iri::parse(&iri) {
                Ok(iri) => Error::Unresolved(iri),
                Err(_) => Error::Endpoint(format!("no endpoint resolved for {iri}")),
            },
            ModuleError::MissingArgument(name) => Error::MissingArgument(name),
            ModuleError::InvalidArgument { name, detail } => {
                Error::InvalidArgument { name, detail }
            }
            ModuleError::Endpoint(message) => Error::Endpoint(message),
            ModuleError::Denied(message) => Error::Denied(message),
            ModuleError::NotFound(message) => Error::NotFound(message),
            ModuleError::Timeout(message) => Error::Timeout(message),
            ModuleError::Unavailable(message) => Error::Unavailable(message),
        }
    }
}

/// One bound entry of a module and the card its endpoint answers `Meta` with — what a
/// [`ModuleCall::Cards`] returns per binding, and what [`ModuleSpace::connect`] installs
/// host-side so the mount describes the module's endpoints as the module does.
///
/// The card is the module's word about what it DOES — inputs, outputs, verbs, and any
/// `requires` of its own. The host folds its [`ModuleFloor`] into it before the kernel sees
/// it, so a module's card can only ever add to what the mount enforces, never lower it.
///
/// On the wire the description crosses as **JSON text** inside the postcard frame: core's
/// `Description` derives serde for JSON (`skip_serializing_if` on its optional fields), and
/// postcard is not self-describing, so a skipped field reads as "end of buffer" on the way
/// back. The text form is the same choice [`ModuleRewrite::Table`] makes for the alias
/// table. `card_survives_the_codec` pins the round trip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleCard {
    /// The binding: its pattern (an exact IRI or a URI template) and the endpoint's name.
    pub entry: SpaceEntry,
    /// The endpoint's self-description, as `describe()` answers it inside the module.
    pub description: Description,
}

/// [`ModuleCard`]'s wire shape: the entry as it is, the description as JSON text.
#[derive(Serialize, Deserialize)]
struct ModuleCardWire {
    entry: SpaceEntry,
    description: String,
}

impl Serialize for ModuleCard {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let description =
            serde_json::to_string(&self.description).map_err(serde::ser::Error::custom)?;
        ModuleCardWire {
            entry: self.entry.clone(),
            description,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ModuleCard {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let wire = ModuleCardWire::deserialize(deserializer)?;
        let description =
            serde_json::from_str(&wire.description).map_err(serde::de::Error::custom)?;
        Ok(ModuleCard {
            entry: wire.entry,
            description,
        })
    }
}

/// The module's reply for an endpoint's outcome: the 0.2 shape whenever it is lossless (a
/// threadless result, an `Endpoint` error), the threaded or typed one otherwise.
fn reply_for(result: Result<Representation>) -> ModuleReply {
    match result {
        Ok(representation) => {
            let threads: Vec<String> = representation
                .threads()
                .iter()
                .map(|thread| thread.as_str().to_string())
                .collect();
            if threads.is_empty() {
                ModuleReply::Resolved(representation)
            } else {
                ModuleReply::ResolvedThreaded {
                    representation,
                    threads,
                }
            }
        }
        Err(Error::Endpoint(message)) => ModuleReply::Error(message),
        Err(other) => ModuleReply::ErrorTyped(ModuleError::from(&other)),
    }
}

/// What a module's final reply means to the host: the representation with its declared
/// threads re-attached, or the failure — typed where the wire carried the type.
fn outcome_from(reply: ModuleReply) -> Result<Representation> {
    match reply {
        ModuleReply::Resolved(representation) => Ok(representation),
        ModuleReply::ResolvedThreaded {
            representation,
            threads,
        } => Ok(threads
            .into_iter()
            .fold(representation, |representation, thread| {
                representation.depends_on(thread)
            })),
        ModuleReply::Error(message) => Err(Error::Endpoint(message)),
        ModuleReply::ErrorTyped(error) => Err(error.into()),
        ModuleReply::HostCall { .. } => Err(Error::Endpoint(
            "module made a HostCall where a final reply was expected".to_string(),
        )),
        ModuleReply::Bindings(_) | ModuleReply::Manifest(_) | ModuleReply::Cards(_) => Err(
            Error::Endpoint("module answered Invoke with a description".to_string()),
        ),
    }
}

/// The host's answer to one callback: `HostResult` whenever it is lossless, `HostError` for
/// a failure whose type a string would drop.
fn host_answer(result: Result<Representation>) -> ModuleCall {
    match result {
        Ok(representation) => ModuleCall::HostResult(Ok(representation)),
        Err(Error::Endpoint(message)) => ModuleCall::HostResult(Err(message)),
        Err(other) => ModuleCall::HostError(ModuleError::from(&other)),
    }
}

/// What the host's answer to a callback means to the module's issuer.
fn answer_from(call: ModuleCall) -> Result<Representation> {
    match call {
        ModuleCall::HostResult(Ok(representation)) => Ok(representation),
        ModuleCall::HostResult(Err(message)) => Err(Error::Endpoint(message)),
        ModuleCall::HostError(error) => Err(error.into()),
        ModuleCall::Invoke { .. }
        | ModuleCall::Describe
        | ModuleCall::Manifest
        | ModuleCall::Cards => Err(Error::Endpoint(
            "expected HostResult answering a HostCall".to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// ★ The module's self-description of its own NAMING — the part `Describe` was missing.
//
// A module may compose any space, and some spaces RESOLVE ONE NAME UNDER ANOTHER: an
// `Alias` (a table), a `Rewrite` (a closure), anything that reports
// `Resolved::canonical`. That report is what makes a logical name and its backing name
// ONE resource in a kernel — one cache entry, one golden thread, one capability floor.
//
// It cannot cross the module boundary by riding on the resolution, because the host
// never asks the module to resolve: `ModuleSpace::resolve` is a prefix match, and by the
// time `ModuleCall::Invoke` is sent the host has already keyed its cache. Nor can a
// resolve round trip simply be added — `Space::resolve` is SYNCHRONOUS and a Phase-2
// transport (a second wasm instance, a socket) is not.
//
// So the module DECLARES its canonicalization and the host applies it locally: `Meta`
// ("describe yourself") reaching one layer further, answered once at mount time, and
// evaluated at resolve time by `AliasTable`, which the kernel already ships and tests.
//
// The residual is honest and NAMED rather than silent: what can be declared is what can
// be written down — an exact or prefix table. An arbitrary hand-written rewriting space
// cannot be, and a module that rewrites that way must say `Undeclarable` so the host can
// refuse or accept it deliberately. Two things stop the undeclared case from becoming the
// next quiet bug: a `ModuleRewrite::Unknown` is never read as "does not rewrite", and the
// module side REFUSES an invocation whose resolution reports a canonical the host did not
// already apply (`refuse_undeclared_rewrite`) — a split identity fails loudly at the one
// moment it is knowable, instead of returning a right-looking answer filed under the
// wrong name.
// ---------------------------------------------------------------------------

/// How a module rewrites the names it is given: the module's own answer to "does anything
/// under my prefix resolve under a *different* name?"
///
/// A host installs what this declares in its own [`AliasTable`], so the rewrite is applied
/// **host-side, synchronously, at resolve time** and reported on
/// [`Resolved::canonical`](ikigai_core::Resolved::canonical) — after which the kernel's
/// cache key, golden-thread cut and capability floor all name the backing resource, exactly
/// as they would for a rewriting space composed locally.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleRewrite {
    /// Every target resolves under the name it was given. The overwhelmingly common
    /// case, and a positive claim: the host installs nothing and the module-side guard
    /// stays armed.
    None,
    /// Rewritten through this table, in [`AliasTable`]'s line-oriented text form
    /// (`prefix urn:a: urn:b:` / `exact urn:x urn:y`). Build it from the very table the
    /// module's `Alias` uses, with [`ModuleRewrite::from_table`], so the declaration and
    /// the behaviour cannot drift.
    Table(String),
    /// The module rewrites in a way it **cannot** write down — a `Rewrite` over an
    /// arbitrary closure, or any hand-rolled rewriting space. The string is the reason,
    /// for the operator.
    ///
    /// This is the honest residual of crossing a process boundary: the far side can only
    /// share identity to the extent it can describe itself. Declaring it is what makes
    /// the residual *visible* — the host then refuses (the default) or accepts it with a
    /// warning, rather than splitting identity without anyone noticing.
    Undeclarable(String),
    /// No claim was made: the module was never asked, or is older than
    /// [`ModuleCall::Manifest`] and could not answer.
    ///
    /// ★ **Not the same as [`None`](ModuleRewrite::None).** `None` is a module saying it
    /// does not rewrite; this is the absence of a statement. A host must not read it as
    /// permission to key identity under the name it was given — it is exactly the state
    /// 0.1.9 was always in, and the module-side guard is what covers it.
    Unknown,
}

impl ModuleRewrite {
    /// Declare `table` — the very table the module's own
    /// [`Alias`](ikigai_core::Alias) rewrites through.
    ///
    /// ```
    /// use ikigai_core::AliasTable;
    /// use ikigai_module::ModuleRewrite;
    ///
    /// let table = AliasTable::new().exact("urn:xslt:render", "urn:xslt:transform");
    /// assert_eq!(
    ///     ModuleRewrite::from_table(&table),
    ///     ModuleRewrite::Table("exact urn:xslt:render urn:xslt:transform\n".to_string()),
    /// );
    /// ```
    pub fn from_table(table: &AliasTable) -> Self {
        ModuleRewrite::Table(table.to_text())
    }

    /// The declared table, parsed. `Ok(None)` for every variant that declares no table —
    /// including [`Undeclarable`](ModuleRewrite::Undeclarable) and
    /// [`Unknown`](ModuleRewrite::Unknown), which are handled by policy, not by rewriting.
    pub fn table(&self) -> std::result::Result<Option<AliasTable>, AliasParseError> {
        match self {
            ModuleRewrite::Table(text) => AliasTable::parse(text).map(Some),
            _ => Ok(None),
        }
    }

    /// Whether the module actually stated how it names things — `None` or `Table`. A
    /// declaration is what lets the host share identity across the boundary; the other two
    /// variants are the cases where it provably cannot.
    pub fn is_declared(&self) -> bool {
        matches!(self, ModuleRewrite::None | ModuleRewrite::Table(_))
    }
}

/// A module's self-description: its bindings, and how it rewrites names.
///
/// One message rather than two because a host asks both questions at the same moment (it
/// is mounting the module) and a real transport charges a round trip for each.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleManifest {
    /// The module's bound entries — the same answer [`ModuleCall::Describe`] gives.
    pub entries: Option<Vec<SpaceEntry>>,
    /// How the module rewrites names. See [`ModuleRewrite`].
    pub rewrite: ModuleRewrite,
}

impl ModuleManifest {
    /// A manifest declaring `rewrite`.
    pub fn new(entries: Option<Vec<SpaceEntry>>, rewrite: ModuleRewrite) -> Self {
        ModuleManifest { entries, rewrite }
    }

    /// What a host records for a module that could not be asked — a peer older than
    /// [`ModuleCall::Manifest`], or a transport that cannot carry it. The bindings may
    /// still be known (`Describe` is 0.1.9 vocabulary); the naming is not.
    pub fn unknown(entries: Option<Vec<SpaceEntry>>) -> Self {
        ModuleManifest {
            entries,
            rewrite: ModuleRewrite::Unknown,
        }
    }
}

/// What a host does about a module that declares
/// [`ModuleRewrite::Undeclarable`] — a rewrite whose identity provably cannot be shared
/// across the boundary.
///
/// The signal has to be a *choice*, because both answers are legitimate: a host that
/// caches and invalidates around this module wants the refusal, and a host that only ever
/// reads through it once may not care. What is never legitimate is neither — which is
/// what 0.1.9 did.
#[derive(Default)]
pub enum OnUndeclarable {
    /// Refuse: every target under the module's prefixes resolves to an endpoint that
    /// fails on invoke, naming the module's reason. The default, because a split identity
    /// is a wrong answer wearing a right answer's face — a `Sink` through one name leaves
    /// the other serving stale bytes, and both look plausible.
    #[default]
    Refuse,
    /// Resolve anyway, handing the host's sink a one-line description of what it is
    /// accepting — once per resolution routed to this module, because which targets are
    /// affected is exactly what "undeclarable" means the host cannot know. Identity
    /// splits: this is 0.1.9's behaviour, still reachable, never implicit.
    Warn(Arc<dyn Fn(&str) + Send + Sync>),
}

impl fmt::Debug for OnUndeclarable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OnUndeclarable::Refuse => f.write_str("Refuse"),
            OnUndeclarable::Warn(_) => f.write_str("Warn(..)"),
        }
    }
}

/// ★ The module side's identity guard: refuse an invocation whose resolution **reports a
/// rewrite the host did not already apply**, and say exactly what went wrong.
///
/// A module reaching this point has resolved under a name the host has never seen. The
/// host has already keyed its representation cache, fired its golden-thread cut and
/// evaluated the declared-capability floor under the name it *was* given, so serving the
/// answer files it under the wrong name — the identity split `Resolved::canonical` exists
/// to close, reintroduced at the boundary. That is not repairable after the fact (the
/// cache key exists before the first byte crosses), so it is refused.
///
/// Returns the refusal message, or `None` when there is nothing to refuse:
///
/// - the resolution reported no rewrite, or reported the name the host already used
///   (the host applied the declaration; the module's own `Alias` re-canonicalizing an
///   already-canonical target is a no-op) — the overwhelmingly common path;
/// - the module declared [`ModuleRewrite::Undeclarable`], which means the host was told
///   and made its choice through [`OnUndeclarable`]. Not the guard's call to overturn.
fn refuse_undeclared_rewrite(
    request: &Request,
    resolved: &Resolved,
    declared: &ModuleRewrite,
) -> Option<String> {
    if matches!(declared, ModuleRewrite::Undeclarable(_)) {
        return None;
    }
    let canonical = resolved.canonical.as_ref()?;
    if canonical == &request.target {
        return None;
    }
    Some(format!(
        "module resolved {logical} under {canonical}, a rewrite it never declared: the host \
         has already keyed its cache, cut its golden thread and checked the capability floor \
         under {logical}, so the two names would be two resources. Declare the rewrite \
         (`ModuleRewrite::from_table`) so the host can apply it before it resolves, or — if \
         it cannot be written as a table — declare `ModuleRewrite::Undeclarable` so the host \
         refuses or accepts it deliberately.",
        logical = request.target.as_str(),
        canonical = canonical.as_str(),
    ))
}

/// The endpoint a refused resolution resolves to: it fails on invoke with `message`. A
/// `Space` cannot return an error and a refusal must not read as a miss ("nothing is bound
/// there" is a different, misleading fact), so the refusal becomes an endpoint — the idiom
/// `Alias` and `RateLimit` already use.
fn refusing_endpoint(message: String) -> Arc<dyn Endpoint> {
    Arc::new(FnEndpoint::new("module-refused", move |_inv| {
        Err(Error::Endpoint(message.clone()))
    }))
}

// ---------------------------------------------------------------------------
// ★ The capability floor — the HOST's answer to "what may this module do?"
//
// The kernel enforces exactly what `Endpoint::describe()` returns (`declared = enforced`),
// and for a module endpoint that card must be authored by the HOST, not the module. A
// module is the untrusted party across this boundary: were its own `requires` the source of
// the enforced requirement, a module declaring none would thereby become ungated and
// under-declaring would be the escape hatch. So the division is the one `Minter` already
// uses everywhere else — the module says what it DOES; the host says what it MAY DO. A
// module's self-description is fine for the catalog and for display, never as the source of
// an enforced requirement.
//
// The hole this closes: a prefix mount resolved every IRI under it to an endpoint whose card
// carried no `requires` at all — `ModuleSpace`'s endpoint had no `describe()` override
// whatsoever (so it answered the `Endpoint` trait default, which declares no verbs and
// therefore no actions), and `WasmModuleSpace` fell back to the generic prefix card. Either
// way omission failed OPEN: an endpoint declaring `.requires("urn:cap:demo:greet")` resolved
// under a capability granting only `urn:cap:demo:read`, while the identical declaration on a
// linked endpoint was correctly denied.
//
// A floor is a mount-time host declaration: the scopes every non-`Meta` verb under the mount
// requires. A per-endpoint card (`with_endpoint`) REFINES it — it can add scopes, never
// remove them — so absence of a card still gates, which is what keeps a prefix mount usable
// (not enumerating endpoints is its whole point) without leaving it a hole. `ModuleFloor`
// has no `Default` and every mount constructor takes one by value, so the ungated mount is
// not reachable by omission: it has to be written down, `ModuleFloor::public()`.
// ---------------------------------------------------------------------------

/// The capability floor a host imposes on a module mount: the scopes every non-`Meta` verb
/// under it requires, whatever the module says about itself.
///
/// Passed by value to [`ModuleSpace::new`] / [`ModuleSpace::connect`] /
/// [`WasmModuleSpace::new`], so mounting a module is always an explicit authority decision:
///
/// ```
/// use ikigai_module::ModuleFloor;
///
/// // Everything under this mount needs the module's own grant…
/// let gated = ModuleFloor::requiring("urn:cap:xslt");
/// // …or some grant under a parameterized family (the wildcard form the manifold uses).
/// let net = ModuleFloor::requiring("urn:cap:net:*").and("urn:cap:xslt");
/// // A module that genuinely needs no authority says so out loud.
/// let open = ModuleFloor::public();
/// assert!(open.scopes().is_empty());
/// assert_eq!(net.scopes(), ["urn:cap:net:*", "urn:cap:xslt"]);
/// # let _ = gated;
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleFloor {
    /// Empty ⇔ [`public`](Self::public). Private, and the only zero-scope constructor is
    /// `public()` — [`requiring`](Self::requiring) takes its first scope by value — so "no
    /// floor" is a sentence a host can write but never one it can omit.
    scopes: Vec<String>,
}

impl ModuleFloor {
    /// The host asserts this mount needs no authority: endpoints under it are as public as a
    /// public linked endpoint, and a module endpoint's own `requires` (which can only ever
    /// deny *more*, see `refuse_unsatisfied_declaration`, crate-private) is all that gates it.
    ///
    /// The deliberate, named form of the behavior this crate used to have by accident.
    pub fn public() -> Self {
        ModuleFloor { scopes: Vec::new() }
    }

    /// Every non-`Meta` verb under this mount requires `scope`. Chain
    /// [`and`](Self::and) for more.
    ///
    /// Scopes are the same IRIs the manifold speaks, wildcard form included
    /// (`urn:cap:net:*` = "holds some grant under this prefix").
    pub fn requiring(scope: impl Into<String>) -> Self {
        ModuleFloor {
            scopes: vec![scope.into()],
        }
    }

    /// Add another required scope (builder). All of them must be held.
    pub fn and(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// The scopes this floor demands — empty exactly for [`public`](Self::public).
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// The first floor scope `capability` does not hold, or `None` when the floor is met.
    pub fn unsatisfied(&self, capability: &Capability) -> Option<&str> {
        self.scopes
            .iter()
            .map(String::as_str)
            .find(|scope| !cap_satisfies(capability, scope))
    }

    /// The floor folded into `card` — the manifold's half of `declared = enforced`, so what
    /// a catalog offers under this mount is what the mount admits.
    ///
    /// Unioned into the flat `requires` (which every *synthesized* per-verb spec inherits)
    /// **and** into each explicitly declared non-`Meta` action, because an explicit action
    /// wins over the flat fields for its verb and would otherwise advertise — and be checked
    /// against — a smaller requirement than the mount enforces.
    ///
    /// It never invents a verb. A card declaring none synthesizes no action specs, so the
    /// kernel's pre-dispatch check finds nothing to enforce on it; that is precisely why the
    /// floor is *also* checked at invoke, where no card is required for it to bite.
    fn applied_to(&self, mut card: Description) -> Description {
        if self.scopes.is_empty() {
            return card;
        }
        for scope in &self.scopes {
            if !card.requires.contains(scope) {
                card.requires.push(scope.clone());
            }
        }
        for action in card.actions.iter_mut().filter(|a| a.verb != Verb::Meta) {
            for scope in &self.scopes {
                if !action.requires.contains(scope) {
                    action.requires.push(scope.clone());
                }
            }
        }
        card
    }

    /// The denial for an invocation that does not clear this floor. Says what to add,
    /// because a denial alone does not tell an operator where the requirement lives.
    fn denial(&self, scope: &str, target: &str) -> Error {
        Error::Denied(format!(
            "capability does not grant `{scope}` (the capability floor of the module mount \
             serving `{target}`). Grant the scope, or mount the module with a floor the \
             caller clears — `ModuleFloor::requiring(..)` at the mount, refined per endpoint \
             with `with_endpoint(iri, Description::new(..).verb(..).requires(..))`."
        ))
    }
}

/// Whether `capability` satisfies a declared scope, wildcard form included.
///
/// ⚠ A mirror of `ikigai_core`'s `cap_satisfies`, which is `pub(crate)` there. The kernel's
/// pre-dispatch floor, `urn:kernel:actions` and `urn:kernel:validate` agree because they
/// share that one predicate; a host-side gate *outside* core cannot reach it, so this
/// restates it. `capability_scopes_match_the_kernels_predicate` pins the four cases (root,
/// exact, wildcard held, wildcard not held); if core ever exports the predicate, delete this
/// and call it.
fn cap_satisfies(capability: &Capability, scope: &str) -> bool {
    match scope.strip_suffix('*') {
        Some(prefix) => match capability.scopes() {
            // Root holds every scope; `scopes()` is `None` exactly for root.
            None => true,
            Some(held) => held.iter().any(|s| s.starts_with(prefix)),
        },
        None => capability.allows(scope),
    }
}

/// The first scope `description` declares for `verb` that `capability` lacks — this crate's
/// mirror of the kernel's pre-dispatch floor check, for the module side of the boundary.
///
/// `Meta` is exempt exactly as it is in core (`action_specs()` carries no `Meta` spec), so a
/// module endpoint's self-description stays readable wherever the catalog offers it.
fn unsatisfied_scope(
    description: &Description,
    verb: Verb,
    capability: &Capability,
) -> Option<String> {
    description
        .action_specs()
        .into_iter()
        .filter(|spec| spec.verb == verb)
        .flat_map(|spec| spec.requires)
        .find(|scope| !cap_satisfies(capability, scope))
}

/// Refuse an invocation the module's OWN card says it lacks the authority for — the second
/// guard beside [`refuse_undeclared_rewrite`], at every module-side dispatch site.
///
/// This is **not** the authoritative gate; [`ModuleFloor`] is, host-side, because the module
/// is the untrusted party and authority must never be self-asserted by the thing being
/// gated. This is the module *honoring its own declaration*, and it can only ever deny
/// **more** than the floor already denies: a module that declares nothing is still gated by
/// the mount, so under-declaring buys nothing. What it buys everyone else is that
/// `.requires(..)` on a module endpoint stops being decoration — one declaration means the
/// same thing whether that endpoint is linked or loaded.
fn refuse_unsatisfied_declaration(
    request: &Request,
    resolved: &Resolved,
    capability: &Capability,
) -> Option<String> {
    let scope = unsatisfied_scope(&resolved.endpoint.describe(), request.verb, capability)?;
    Some(format!(
        "capability does not grant `{scope}` (declared by `{target}`, inside the module)",
        target = request.target.as_str(),
    ))
}

/// The value a template variable is probed with to reach the endpoint behind a template
/// binding for its card — what core's (private) `describe_entry` does.
const PROBE: &str = "probe";

/// The card of one bound entry, as the module's own space answers it: a `Meta` resolution
/// of the pattern (an exact IRI), or of the template expanded with a probe value — guarded,
/// as core guards it, against a shorter sibling swallowing the probe.
fn describe_entry(space: &dyn Space, entry: &SpaceEntry) -> Option<Description> {
    let (target, templated) = match Iri::parse(&entry.pattern) {
        Ok(iri) => (iri, false),
        Err(_) => {
            let template = UriTemplate::parse(&entry.pattern).ok()?;
            let mut bindings = Bindings::new();
            for var in template.variables() {
                bindings.insert(var, PROBE);
            }
            if bindings.is_empty() {
                return None; // no variables ⇒ a malformed IRI, not a template
            }
            (Iri::parse(template.expand(&bindings)?).ok()?, true)
        }
    };
    let Resolution::Hit(resolved) =
        space.resolve(&Request::new(Verb::Meta, target), &Scope::empty())
    else {
        return None;
    };
    let description = resolved.endpoint.describe();
    if templated && resolved.endpoint.name() != entry.endpoint && description.id != entry.endpoint {
        return None;
    }
    Some(description)
}

/// Every bound entry's card — the module side of [`ModuleCall::Cards`].
fn cards_of(space: &dyn Space) -> Vec<ModuleCard> {
    space
        .entries()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| {
            describe_entry(space, &entry).map(|description| ModuleCard { entry, description })
        })
        .collect()
}

/// The first card whose pattern matches `target` — an exact IRI or a URI template, in
/// declaration order, the precedence `EndpointSpace` gives its bindings. Each item is
/// `(pattern, endpoint name, card)`.
fn match_card<'a>(
    cards: impl IntoIterator<Item = (&'a str, &'a str, &'a Description)>,
    target: &Iri,
) -> Option<(&'a str, &'a Description)> {
    cards
        .into_iter()
        .find(|(pattern, _, _)| {
            *pattern == target.as_str()
                || UriTemplate::parse(*pattern)
                    .ok()
                    .is_some_and(|template| template.match_iri(target).is_some())
        })
        .map(|(_, name, card)| (name, card))
}

/// The module side of one `Invoke`, over whatever issuer carries its callbacks: resolve in
/// the module's space, apply the two guards, invoke, and shape the reply. One place, so the
/// transports (direct call, byte channel, socket, closure pump) cannot drift on what crosses.
async fn dispatch(
    space: &dyn Space,
    rewrite: &ModuleRewrite,
    request: &Request,
    capability: &Capability,
    issuer: &dyn Issuer,
) -> ModuleReply {
    match space.resolve(request, &Scope::empty()) {
        Resolution::Hit(resolved) => {
            // The identity guard: a rewrite the host was never told about would file this
            // answer under the wrong name. Refuse rather than serve it.
            if let Some(message) = refuse_undeclared_rewrite(request, &resolved, rewrite) {
                return ModuleReply::Error(message);
            }
            // The authority guard: the module honoring its own card. The mount's floor has
            // already gated this host-side and is the authoritative floor; this can only
            // ever deny more — and it crosses typed, so the host sees a permanent `Denied`.
            if let Some(message) = refuse_unsatisfied_declaration(request, &resolved, capability) {
                return ModuleReply::ErrorTyped(ModuleError::Denied(message));
            }
            let inv = Invocation::with_issuer(request, &resolved.bindings, capability, issuer);
            reply_for(resolved.endpoint.invoke(&inv).await)
        }
        Resolution::Miss => {
            ModuleReply::ErrorTyped(ModuleError::Unresolved(request.target.as_str().to_string()))
        }
    }
}

/// What routing a target through a module's declared canonicalization decided.
enum Routing {
    /// Resolve under the name as given.
    Direct,
    /// Resolve under this name instead, and report it to the kernel.
    Canonical(Iri),
    /// Do not resolve: hand back an endpoint that fails with this message.
    Refuse(String),
}

/// The host's local copy of a module's declared canonicalization — the whole point of the
/// declaration, held on the host side of the boundary where `Space::resolve` can consult it
/// **synchronously**, which is the constraint that rules out asking the module per-request.
struct ModuleAliases {
    /// What the module said (or the absence of a statement).
    rewrite: ModuleRewrite,
    /// The parsed table, when one was declared. Parsed once, at mount time: a malformed
    /// table fails when it is read, not on the one request that hits the bad rule.
    table: Option<AliasTable>,
    /// What to do about [`ModuleRewrite::Undeclarable`].
    policy: OnUndeclarable,
}

impl ModuleAliases {
    /// Nothing declared — the state a host is in when it never asked. Resolves every
    /// target under the name it was given, which is 0.1.9's behaviour exactly.
    fn unknown() -> Self {
        ModuleAliases {
            rewrite: ModuleRewrite::Unknown,
            table: None,
            policy: OnUndeclarable::default(),
        }
    }

    /// Validate `rewrite` against the prefixes the module is mounted at and install it.
    ///
    /// ★ **A module may only canonicalize inside its own mounted namespace.** The rewrite
    /// the host installs decides the kernel's *identity* for the request — its cache key,
    /// its golden thread, the scope its capability floor is evaluated against. A rule
    /// pointing outside the prefixes the host routed to this module is a claim on a name
    /// the module was never given: it would collide the module's cache entry with another
    /// space's resource under a name that space owns. So it is refused at mount time,
    /// where an operator is watching, rather than becoming a resolution-time surprise.
    /// (`urn:kernel:` is called out separately only so the message says why; the kernel
    /// namespace is unaliasable in core for the same shadowing reason.)
    fn install(prefixes: &[String], rewrite: ModuleRewrite) -> Result<Self> {
        let table = rewrite.table().map_err(|e| {
            Error::Endpoint(format!("module declared an unparseable rewrite table: {e}"))
        })?;
        if let Some(table) = &table {
            for rule in table.rules() {
                for (side, value) in [("from", rule.from()), ("to", rule.to())] {
                    if value.starts_with("urn:kernel:") {
                        return Err(Error::Endpoint(format!(
                            "module rewrite rule `{} {} {}` names the reserved kernel \
                             namespace on the {side} side; `urn:kernel:*` is resolved by the \
                             kernel ahead of any space and cannot be aliased",
                            rule.kind().keyword(),
                            rule.from(),
                            rule.to(),
                        )));
                    }
                    if !prefixes.iter().any(|p| value.starts_with(p.as_str())) {
                        return Err(Error::Endpoint(format!(
                            "module rewrite rule `{} {} {}` has a {side} outside the prefixes \
                             this module is mounted at ({}); a module may only canonicalize \
                             names the host routed to it",
                            rule.kind().keyword(),
                            rule.from(),
                            rule.to(),
                            prefixes.join(", "),
                        )));
                    }
                }
            }
        }
        Ok(ModuleAliases {
            rewrite,
            table,
            policy: OnUndeclarable::default(),
        })
    }

    /// Route one target: rewrite it if the module declared how, refuse it if the module
    /// declared that it cannot say, pass it through otherwise.
    fn route(&self, target: &Iri) -> Routing {
        if let ModuleRewrite::Undeclarable(reason) = &self.rewrite {
            let message = format!(
                "module may rewrite {target} in a way it cannot declare ({reason}), so the \
                 host cannot give a logical name and its backing name one identity: they \
                 would be two cache entries and two golden threads over one resource. \
                 Which targets are affected is exactly what the module could not say.",
                target = target.as_str(),
            );
            return match &self.policy {
                OnUndeclarable::Refuse => Routing::Refuse(format!(
                    "{message} Refused. Express the rewrite as an alias table and declare it, \
                     or set `OnUndeclarable::Warn` to accept the split deliberately."
                )),
                OnUndeclarable::Warn(sink) => {
                    sink(&format!("{message} Accepted (OnUndeclarable::Warn)."));
                    Routing::Direct
                }
            };
        }
        // `None` and `Unknown` alike install no table — nothing to apply, and nothing
        // known to apply, respectively. Both resolve under the name as given; where they
        // differ is what the module side does, see `refuse_undeclared_rewrite`.
        let Some(table) = &self.table else {
            return Routing::Direct;
        };
        match table.canonicalize(target) {
            Canonical::Direct => Routing::Direct,
            Canonical::Aliased(hop) => Routing::Canonical(hop.canonical().clone()),
            // A cycle or an over-long chain: refused, never half-applied. Core's decision
            // 5, on the host's side of the boundary.
            Canonical::Refused(refusal) => {
                Routing::Refuse(format!("module alias rewrite refused: {refusal}"))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The transport seam.
// ---------------------------------------------------------------------------

/// How a host reaches a module. The in-process impl ([`InProcessTransport`]) calls the
/// module's endpoint directly; a Phase-2 impl (a second wasm instance, embedded
/// wasmtime, or a socket) would marshal [`ModuleCall`]/[`ModuleReply`] and service the
/// module's callbacks against `host`.
#[async_trait]
pub trait ModuleTransport: Send + Sync {
    /// Invoke the module's endpoint for `request` under `capability`, resolving the
    /// module's sub-resource callbacks through `host` (the host kernel, as an
    /// [`Issuer`]). The in-process transport hands `host` straight to the module's
    /// [`Invocation`]; a wire transport would call `host.issue(..)` for each
    /// [`ModuleReply::HostCall`] and send back a [`ModuleCall::HostResult`].
    async fn invoke(
        &self,
        request: Request,
        capability: &Capability,
        host: &dyn Issuer,
    ) -> Result<Representation>;

    /// The module's bound entries (for the host's `entries()` / the catalog), if it can
    /// enumerate. Default `None`.
    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        None
    }

    /// Ask the module for its [`ModuleManifest`] — bindings **and** how it rewrites names.
    ///
    /// Asked **once, at mount time** ([`ModuleSpace::connect`]), never per resolution:
    /// `Space::resolve` is synchronous and a real transport is not, which is precisely why
    /// the module declares its canonicalization instead of being asked to resolve.
    ///
    /// The default answers [`ModuleManifest::unknown`] — the honest answer for a transport
    /// that cannot carry the question, and for a peer older than
    /// [`ModuleCall::Manifest`]. It is a *defaulted* method so a third-party transport keeps
    /// compiling; the cost is that such a transport reports `Unknown`, which is exactly
    /// what it is.
    async fn manifest(&self) -> Result<ModuleManifest> {
        Ok(ModuleManifest::unknown(self.entries()))
    }

    /// Ask the module for its bound entries' cards ([`ModuleCard`]) — every endpoint's own
    /// `describe()`, so the host can hand the kernel the module's self-description through
    /// the mount. Asked **once, at mount time** ([`ModuleSpace::connect`]), beside
    /// [`manifest`](Self::manifest).
    ///
    /// The default answers none — the honest answer for a transport that cannot carry the
    /// question, and for a peer older than [`ModuleCall::Cards`].
    async fn cards(&self) -> Result<Vec<ModuleCard>> {
        Ok(Vec::new())
    }
}

/// **Phase 1.** The module runs in the same process; "transport" is a direct call. The
/// module's endpoint runs with the **host** as its issuer, so its `inv.source`/
/// `inv.issue` resolve back through the host kernel (its cache, its other spaces) —
/// proving the callback machinery with zero wire risk. A Phase-2 transport swaps in
/// without touching the module's code or [`ModuleSpace`].
pub struct InProcessTransport {
    space: Arc<dyn Space>,
    rewrite: ModuleRewrite,
}

impl InProcessTransport {
    /// Wrap a module's `space()` as an in-process transport.
    pub fn new(space: impl Space + 'static) -> Self {
        Self {
            space: Arc::new(space),
            rewrite: ModuleRewrite::Unknown,
        }
    }

    /// Wrap an already-`Arc`'d space.
    pub fn from_arc(space: Arc<dyn Space>) -> Self {
        Self {
            space,
            rewrite: ModuleRewrite::Unknown,
        }
    }

    /// Declare how the module's space rewrites names (builder). See [`ModuleRewrite`].
    ///
    /// Build the declaration from the *same* [`AliasTable`] the module's
    /// [`Alias`](ikigai_core::Alias) rewrites through, so the two cannot drift:
    ///
    /// ```
    /// use std::sync::Arc;
    /// use ikigai_core::{Alias, AliasTable, EndpointSpace, Space};
    /// use ikigai_module::{InProcessTransport, ModuleRewrite};
    ///
    /// let table = Arc::new(AliasTable::new().exact("urn:demo:old", "urn:demo:new"));
    /// let inner: Arc<dyn Space> = Arc::new(EndpointSpace::new());
    /// let aliased = Arc::new(Alias::new(Arc::clone(&table), inner));
    /// let transport = InProcessTransport::from_arc(aliased)
    ///     .declaring(ModuleRewrite::from_table(&table));
    /// # let _ = transport;
    /// ```
    pub fn declaring(mut self, rewrite: ModuleRewrite) -> Self {
        self.rewrite = rewrite;
        self
    }
}

#[async_trait]
impl ModuleTransport for InProcessTransport {
    async fn invoke(
        &self,
        request: Request,
        capability: &Capability,
        host: &dyn Issuer,
    ) -> Result<Representation> {
        // The same dispatch the wire transports run, shortcut: no codec between the module's
        // reply and the host's reading of it. The module's endpoint runs with the HOST as its
        // issuer, so its `inv.source(..)` calls cross straight back to the host kernel.
        outcome_from(dispatch(&*self.space, &self.rewrite, &request, capability, host).await)
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        self.space.entries()
    }

    async fn manifest(&self) -> Result<ModuleManifest> {
        // In-process: no wire, so the declaration is handed over directly.
        Ok(ModuleManifest::new(
            self.space.entries(),
            self.rewrite.clone(),
        ))
    }

    async fn cards(&self) -> Result<Vec<ModuleCard>> {
        Ok(cards_of(&*self.space))
    }
}

// ---------------------------------------------------------------------------
// The serialized session transport.
//
// `InProcessTransport` proves the *callback machinery* but shortcuts the wire — it calls
// the module's endpoint directly, so `ModuleCall`/`ModuleReply` are never serialized.
// `LoopbackTransport` runs the **full session through the codec**: every `Invoke`,
// `HostCall`, `HostResult`, and `Resolved` is `postcard`-encoded and sent over an
// in-memory byte channel, exactly as a socket or wasm transport will frame it. Both ends
// live in this process (no socket, no second runtime), so it isolates the protocol — the
// session state machine and `Request`/`Capability`/`Representation` marshalling — from the
// transport plumbing a real home adds. It's the foundation those homes build on.
// ---------------------------------------------------------------------------

/// Encode a module-protocol message to `postcard` bytes — the same codec (and on-wire
/// bytes) `ikigai-wire` frames for the kernel `Call`/`Reply` protocol.
fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>> {
    postcard::to_allocvec(message)
        .map_err(|e| Error::Endpoint(format!("module-protocol encode failed: {e}")))
}

/// Decode a module-protocol message from a complete `postcard` byte slice.
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    postcard::from_bytes(bytes)
        .map_err(|e| Error::Endpoint(format!("module-protocol decode failed: {e}")))
}

/// A [`ModuleTransport`] that runs the `ModuleCall`/`ModuleReply` session over a pair of
/// in-memory byte channels, serializing every message with the private `encode`/`decode`. Same
/// protocol and bytes as a real (socket/wasm) transport, both ends in-process — so it
/// proves the session without any I/O risk.
///
/// Host callbacks are assumed **sequential** (the module awaits each `inv.source` before
/// the next), which matches the pilot (`ikigai-xslt`); concurrent callbacks from one
/// module invocation are an open question (see the design doc).
pub struct LoopbackTransport {
    space: Arc<dyn Space>,
    rewrite: ModuleRewrite,
}

impl LoopbackTransport {
    /// Wrap a module's `space()` as a serialized loopback transport.
    pub fn new(space: impl Space + 'static) -> Self {
        Self {
            space: Arc::new(space),
            rewrite: ModuleRewrite::Unknown,
        }
    }

    /// Wrap an already-`Arc`'d space.
    pub fn from_arc(space: Arc<dyn Space>) -> Self {
        Self {
            space,
            rewrite: ModuleRewrite::Unknown,
        }
    }

    /// Declare how the module's space rewrites names (builder) — see
    /// [`InProcessTransport::declaring`]. Unlike the in-process transport, this
    /// declaration is answered **through the codec**: [`manifest`](Self::manifest) runs a
    /// real `Manifest`/`Manifest` exchange over the byte channel, which is what proves a
    /// socket or wasm transport can carry it.
    pub fn declaring(mut self, rewrite: ModuleRewrite) -> Self {
        self.rewrite = rewrite;
        self
    }
}

#[async_trait]
impl ModuleTransport for LoopbackTransport {
    async fn invoke(
        &self,
        request: Request,
        capability: &Capability,
        host: &dyn Issuer,
    ) -> Result<Representation> {
        // Two one-way byte channels — the in-memory stand-in for a socket's read/write
        // halves. `host_to_module` carries `ModuleCall`s, `module_to_host` carries
        // `ModuleReply`s.
        let (host_to_module_tx, host_to_module_rx) = mpsc::unbounded::<Vec<u8>>();
        let (module_to_host_tx, mut module_to_host_rx) = mpsc::unbounded::<Vec<u8>>();

        // The module side: decode the `Invoke`, run the endpoint under a remote issuer
        // that round-trips each `inv.source` as a `HostCall`/`HostResult`.
        let module_side = run_module_session(
            Arc::clone(&self.space),
            self.rewrite.clone(),
            host_to_module_rx,
            module_to_host_tx,
        );

        // The host side: send the `Invoke`, then service each `HostCall` against the host
        // kernel (re-clamping the carried capability to the session — a module may only
        // ever narrow) until the module replies `Resolved`/`Error`.
        let host_side = async {
            let invoke = ModuleCall::Invoke {
                request,
                capability: capability.clone(),
            };
            send(&host_to_module_tx, &invoke)?;
            loop {
                let bytes = module_to_host_rx.next().await.ok_or_else(|| {
                    Error::Endpoint("module closed the session early".to_string())
                })?;
                match decode::<ModuleReply>(&bytes)? {
                    ModuleReply::HostCall {
                        request,
                        capability: carried,
                    } => {
                        let clamped = capability.clamp(&carried);
                        let answer = host_answer(host.issue(request, &clamped).await);
                        send(&host_to_module_tx, &answer)?;
                    }
                    reply => return outcome_from(reply),
                }
            }
        };

        // Drive both halves concurrently on whatever executor runs `invoke` (no spawner
        // needed — pure future composition, single-thread/wasm-friendly). The module side
        // returns once it has sent its final reply; the host side yields the answer.
        let (_module_done, result) = futures::join!(module_side, host_side);
        result
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        // `entries()` is synchronous; the loopback's space is local, so answer it directly.
        // (The `ModuleCall::Describe` path exists for transports that can't — a real
        // wasm/socket module answers introspection over the wire; see the tests.)
        self.space.entries()
    }

    async fn manifest(&self) -> Result<ModuleManifest> {
        // ★ Through the codec, deliberately. The declaration is only worth anything if it
        // survives serialization — a Phase-2 transport carries it as bytes — so this runs
        // the real `ModuleCall::Manifest` / `ModuleReply::Manifest` exchange over the byte
        // channel rather than reading `self.rewrite` directly, the way `entries()` may.
        let (host_to_module_tx, host_to_module_rx) = mpsc::unbounded::<Vec<u8>>();
        let (module_to_host_tx, mut module_to_host_rx) = mpsc::unbounded::<Vec<u8>>();
        let module_side = run_module_session(
            Arc::clone(&self.space),
            self.rewrite.clone(),
            host_to_module_rx,
            module_to_host_tx,
        );
        let host_side = async {
            send(&host_to_module_tx, &ModuleCall::Manifest)?;
            let bytes = module_to_host_rx
                .next()
                .await
                .ok_or_else(|| Error::Endpoint("module closed the session early".to_string()))?;
            match decode::<ModuleReply>(&bytes)? {
                ModuleReply::Manifest(manifest) => Ok(manifest),
                // A peer that predates `Manifest` fails to decode the call and answers
                // `Error`; its bindings are still askable the 0.1.9 way, but its naming is
                // `Unknown` — never "does not rewrite".
                ModuleReply::Error(_) => Ok(ModuleManifest::unknown(self.space.entries())),
                _ => Err(Error::Endpoint(
                    "module answered Manifest with something else".to_string(),
                )),
            }
        };
        let (_module_done, result) = futures::join!(module_side, host_side);
        result
    }

    async fn cards(&self) -> Result<Vec<ModuleCard>> {
        // Through the codec, like `manifest`: a card is only worth anything if it survives
        // serialization.
        let (host_to_module_tx, host_to_module_rx) = mpsc::unbounded::<Vec<u8>>();
        let (module_to_host_tx, mut module_to_host_rx) = mpsc::unbounded::<Vec<u8>>();
        let module_side = run_module_session(
            Arc::clone(&self.space),
            self.rewrite.clone(),
            host_to_module_rx,
            module_to_host_tx,
        );
        let host_side = async {
            send(&host_to_module_tx, &ModuleCall::Cards)?;
            let bytes = module_to_host_rx
                .next()
                .await
                .ok_or_else(|| Error::Endpoint("module closed the session early".to_string()))?;
            match decode::<ModuleReply>(&bytes)? {
                ModuleReply::Cards(cards) => Ok(cards),
                // A peer that predates `Cards` fails to decode the call and answers `Error`:
                // no cards, not a failure.
                ModuleReply::Error(_) => Ok(Vec::new()),
                _ => Err(Error::Endpoint(
                    "module answered Cards with something else".to_string(),
                )),
            }
        };
        let (_module_done, result) = futures::join!(module_side, host_side);
        result
    }
}

/// Send a `postcard`-encoded message down a byte channel.
fn send<T: Serialize>(tx: &mpsc::UnboundedSender<Vec<u8>>, message: &T) -> Result<()> {
    tx.unbounded_send(encode(message)?)
        .map_err(|_| Error::Endpoint("module session channel closed".to_string()))
}

/// The module side of the session: read one `ModuleCall`, act on it, and send back the
/// matching `ModuleReply`. For `Invoke`, the endpoint runs under a [`SessionHostIssuer`]
/// whose `issue` emits a `HostCall` and awaits the next `HostResult` — so the module's
/// `inv.source`/`inv.issue` cross the (serialized) channel back to the host kernel.
async fn run_module_session(
    space: Arc<dyn Space>,
    rewrite: ModuleRewrite,
    mut from_host: mpsc::UnboundedReceiver<Vec<u8>>,
    to_host: mpsc::UnboundedSender<Vec<u8>>,
) {
    let Some(first) = from_host.next().await else {
        return; // host hung up before sending anything
    };
    let reply = match decode::<ModuleCall>(&first) {
        Ok(ModuleCall::Invoke {
            request,
            capability,
        }) => {
            // The issuer now owns the receiver: after `Invoke`, every inbound message is the
            // host's answer to one of its `HostCall`s.
            let issuer = SessionHostIssuer {
                to_host: to_host.clone(),
                from_host: AsyncMutex::new(from_host),
            };
            dispatch(&*space, &rewrite, &request, &capability, &issuer).await
        }
        Ok(ModuleCall::Describe) => ModuleReply::Bindings(space.entries()),
        Ok(ModuleCall::Manifest) => {
            ModuleReply::Manifest(ModuleManifest::new(space.entries(), rewrite))
        }
        Ok(ModuleCall::Cards) => ModuleReply::Cards(cards_of(&*space)),
        Ok(ModuleCall::HostResult(_) | ModuleCall::HostError(_)) => {
            ModuleReply::Error("module received HostResult before Invoke".to_string())
        }
        Err(e) => ModuleReply::Error(e.to_string()),
    };
    // Best-effort: if the host has already gone, there's no one to tell.
    if let Ok(bytes) = encode(&reply) {
        let _ = to_host.unbounded_send(bytes);
    }
}

/// The module end of the callback channel: an [`Issuer`] that turns each sub-request into
/// a `HostCall` on the wire and blocks on the matching `HostResult`. The mirror of the
/// host-side [`HostBridge`] — together they make `inv.source` inside a module resolve on
/// the host kernel across the (serialized) transport.
struct SessionHostIssuer {
    to_host: mpsc::UnboundedSender<Vec<u8>>,
    from_host: AsyncMutex<mpsc::UnboundedReceiver<Vec<u8>>>,
}

#[async_trait]
impl Issuer for SessionHostIssuer {
    async fn issue(&self, request: Request, capability: &Capability) -> Result<Representation> {
        let call = ModuleReply::HostCall {
            request,
            capability: capability.clone(),
        };
        send(&self.to_host, &call)?;
        // Await the host's answer. Callbacks are sequential, so this lock is uncontended;
        // holding it across the await is sound (a `futures` async mutex).
        let bytes = {
            let mut from_host = self.from_host.lock().await;
            from_host
                .next()
                .await
                .ok_or_else(|| Error::Endpoint("host closed the session".to_string()))?
        };
        answer_from(decode::<ModuleCall>(&bytes)?)
    }
}

// ---------------------------------------------------------------------------
// The transport-agnostic module side of the session.
//
// `LoopbackTransport` and the UDS server each carry the session over a specific pipe
// (channels, a socket) and own both ends. `run_session` is the *module side* on its own:
// given the host's encoded `Invoke` and a `host_call` that pumps one `HostCall`→`HostResult`
// exchange, it runs the endpoint and returns the encoded final `ModuleReply`. The caller
// supplies the pump, so the same module logic runs over any transport — in particular a
// browser, where the pump is a JS byte-channel and `host_call` bridges the `!Send` JS call
// (spawn_local + oneshot) to the `Send` future the issuer needs.
//
// (The loopback/UDS transports predate this and keep their own inline session loops;
// folding them onto `run_session` is a possible later tidy-up.)
// ---------------------------------------------------------------------------

/// Run one module session from the host's encoded [`ModuleCall::Invoke`] (`invoke`),
/// pumping each of the module's sub-resource callbacks through `host_call`, and return the
/// encoded final [`ModuleReply`] (`Resolved` / `Error`, or `Bindings` for a `Describe`).
///
/// `host_call` receives the encoded [`ModuleReply::HostCall`] and returns the host's
/// encoded [`ModuleCall::HostResult`] — i.e. one turn of the byte pump, exactly what a
/// channel/socket/JS transport carries. It yields a `Send` future (the wasm caller bridges
/// any `!Send` JS work behind a `spawn_local` + `oneshot` at that boundary).
///
/// Callbacks are assumed sequential (the module awaits each `inv.source` before the next),
/// matching the `ikigai-xslt` pilot.
pub async fn run_session<F, Fut>(space: &Arc<dyn Space>, invoke: &[u8], host_call: F) -> Vec<u8>
where
    F: Fn(Vec<u8>) -> Fut + Send + Sync,
    Fut: core::future::Future<Output = std::result::Result<Vec<u8>, String>> + Send,
{
    run_session_declaring(space, &ModuleRewrite::Unknown, invoke, host_call).await
}

/// [`run_session`], for a module that **rewrites names** and can say how.
///
/// A wasm module reached through [`wasm_module!`] declares nothing, so `run_session`
/// answers [`ModuleRewrite::Unknown`] — the truthful answer, and the one that keeps the
/// identity guard armed. A module that composes an [`Alias`](ikigai_core::Alias) passes its
/// declaration here instead, and a host that has the matching declaration (statically, via
/// [`WasmModuleSpace::declaring`], or over the wire via [`ModuleCall::Manifest`]) shares one
/// identity with it across the boundary.
pub async fn run_session_declaring<F, Fut>(
    space: &Arc<dyn Space>,
    rewrite: &ModuleRewrite,
    invoke: &[u8],
    host_call: F,
) -> Vec<u8>
where
    F: Fn(Vec<u8>) -> Fut + Send + Sync,
    Fut: core::future::Future<Output = std::result::Result<Vec<u8>, String>> + Send,
{
    let reply = match decode::<ModuleCall>(invoke) {
        Ok(ModuleCall::Invoke {
            request,
            capability,
        }) => {
            let issuer = ClosureHostIssuer {
                host_call: &host_call,
            };
            dispatch(&**space, rewrite, &request, &capability, &issuer).await
        }
        Ok(ModuleCall::Describe) => ModuleReply::Bindings(space.entries()),
        Ok(ModuleCall::Manifest) => {
            ModuleReply::Manifest(ModuleManifest::new(space.entries(), rewrite.clone()))
        }
        Ok(ModuleCall::Cards) => ModuleReply::Cards(cards_of(&**space)),
        Ok(ModuleCall::HostResult(_) | ModuleCall::HostError(_)) => {
            ModuleReply::Error("module received HostResult before Invoke".to_string())
        }
        Err(e) => ModuleReply::Error(e.to_string()),
    };
    // Encoding a Representation/SpaceEntry shouldn't fail; if it somehow does, still hand
    // back a decodable `ModuleReply::Error` rather than empty bytes.
    encode(&reply).unwrap_or_else(|_| {
        encode(&ModuleReply::Error(
            "module reply encode failed".to_string(),
        ))
        .unwrap_or_default()
    })
}

/// The module's [`Issuer`] for [`run_session`]: turn each sub-request into an encoded
/// `HostCall`, pump it through the host's closure, and decode the `HostResult`.
struct ClosureHostIssuer<'a, F> {
    host_call: &'a F,
}

#[async_trait]
impl<F, Fut> Issuer for ClosureHostIssuer<'_, F>
where
    F: Fn(Vec<u8>) -> Fut + Send + Sync,
    Fut: core::future::Future<Output = std::result::Result<Vec<u8>, String>> + Send,
{
    async fn issue(&self, request: Request, capability: &Capability) -> Result<Representation> {
        let host_call = ModuleReply::HostCall {
            request,
            capability: capability.clone(),
        };
        let answer = (self.host_call)(encode(&host_call)?)
            .await
            .map_err(Error::Endpoint)?;
        answer_from(decode::<ModuleCall>(&answer)?)
    }
}

// ---------------------------------------------------------------------------
// Browser host support: a generic WasmModuleSpace + out-of-band HostCall servicing.
//
// The native transports (loopback, UDS) drive the HostCall loop *in-band*: the host owns
// the channel, services each HostCall as it arrives, and records its provenance on the
// outer invocation. A browser can't — a wasm module's JS imports are *global*, so the
// module's HostCalls go to a global `hostCall` the host exports, NOT back through the call
// the host made. So the browser pattern splits in two, joined by a per-transform sink:
//   * `WasmModuleSpace` drives `invoke_session` (over a host-supplied [`ModuleSessionTransport`])
//     and folds the sink into the result;
//   * `serve_host_call` (called by the host's global `hostCall`) resolves each HostCall and
//     records it into the active sink.
// Both are plain Rust — the host wraps the actual (wasm-bindgen) JS calls. The
// `wasm_module!` macro generates the matching module-side glue. So a new lazy module costs:
// one `wasm_module!(space)` (its artifact) + one `WasmModuleSpace::new(..)` (the host
// binding) — no hand-written crate or endpoint.
// ---------------------------------------------------------------------------

/// How a [`WasmModuleSpace`] reaches its module: run one session, given the encoded
/// `Invoke`, returning the encoded `ModuleReply`. The host wraps the actual call (e.g. a
/// lazy-loaded wasm instance's `invoke_session` over a JS shim); the module pumps its
/// `HostCall`s to the global the host serves with [`serve_host_call`] while this awaits.
#[async_trait]
pub trait ModuleSessionTransport: Send + Sync {
    /// Run the module session for `invoke` (an encoded [`ModuleCall::Invoke`]) and return
    /// the encoded final [`ModuleReply`].
    async fn invoke_session(&self, invoke: Vec<u8>) -> std::result::Result<Vec<u8>, String>;
}

/// The cache provenance accumulated from one transform's out-of-band `HostCall`s, so the
/// host can fold it into the transform's result (the module's `Resolved` drops its threads
/// on the wire — `Representation::threads` is `serde(skip)` — so they're captured here).
#[derive(Default)]
struct DepSink {
    threads: BTreeSet<Thread>,
    expiry: Option<Expiry>,
}

impl DepSink {
    fn record(&mut self, representation: &Representation) {
        self.expiry = Some(match self.expiry {
            Some(e) => e.most_restrictive(representation.expiry),
            None => representation.expiry,
        });
        self.threads
            .extend(representation.threads().iter().cloned());
    }
}

thread_local! {
    // Sinks of all in-flight WasmModuleSpace invocations on this (single-threaded) host,
    // keyed by id so an invocation holds only the `u64` across its await (not a `!Send`
    // handle). `serve_host_call` records into every active sink; nesting just
    // over-approximates dependencies, which is safe.
    static DEP_SINKS: RefCell<Vec<(u64, RefCell<DepSink>)>> = const { RefCell::new(Vec::new()) };
    static NEXT_SINK_ID: Cell<u64> = const { Cell::new(0) };
}

fn install_sink() -> u64 {
    let id = NEXT_SINK_ID.with(|c| {
        let id = c.get();
        c.set(id.wrapping_add(1));
        id
    });
    DEP_SINKS.with(|s| s.borrow_mut().push((id, RefCell::new(DepSink::default()))));
    id
}

fn take_sink(id: u64) -> DepSink {
    DEP_SINKS.with(|s| {
        let mut sinks = s.borrow_mut();
        match sinks.iter().position(|(sid, _)| *sid == id) {
            Some(pos) => sinks.remove(pos).1.into_inner(),
            None => DepSink::default(),
        }
    })
}

/// Service one out-of-band `HostCall` for a module session: decode the host call, resolve
/// the sub-request via `resolve` (the host kernel), record its provenance against every
/// in-flight [`WasmModuleSpace`] invocation, and return the encoded answer — a `HostResult`
/// for a success, a `HostError` for a failure with its [`Error`] type intact (either is a
/// decodable answer). The host's global `hostCall` export calls this.
pub async fn serve_host_call<F, Fut>(reply: &[u8], resolve: F) -> Vec<u8>
where
    F: FnOnce(Request, Capability) -> Fut,
    Fut: core::future::Future<Output = Result<Representation>>,
{
    let answer = match decode::<ModuleReply>(reply) {
        Ok(ModuleReply::HostCall {
            request,
            capability,
        }) => {
            let result = resolve(request, capability).await;
            if let Ok(representation) = &result {
                DEP_SINKS.with(|sinks| {
                    for (_, sink) in sinks.borrow().iter() {
                        sink.borrow_mut().record(representation);
                    }
                });
            }
            // Typed, so a module resolving a host resource that is denied or absent sees
            // `Denied` / `NotFound`, not an endpoint string (see `ModuleError`).
            host_answer(result)
        }
        Ok(_) => ModuleCall::HostResult(Err("serve_host_call: expected a HostCall".to_string())),
        Err(e) => {
            ModuleCall::HostResult(Err(format!("serve_host_call: undecodable HostCall: {e}")))
        }
    };
    encode(&answer).unwrap_or_default()
}

/// A host-side [`Space`] that routes IRIs (by prefix) to a module reached over a
/// [`ModuleSessionTransport`] — the browser counterpart of [`ModuleSpace`], for a module
/// whose `HostCall`s come back out-of-band (serviced by [`serve_host_call`]). It encodes the
/// invocation's request as a `ModuleCall::Invoke`, runs the session, and folds the
/// dependency provenance the host collected into the result. Construct it with the module's
/// [`Description`] so its endpoint still shows a rich card in the catalog.
pub struct WasmModuleSpace {
    prefixes: Vec<String>,
    transport: Arc<dyn ModuleSessionTransport>,
    describe: Description,
    /// Concrete endpoint IRIs this module advertises, each with its own card. Populated
    /// via [`with_endpoint`](Self::with_endpoint). When non-empty these drive `entries()`
    /// (so the ops list in the catalog) and a per-IRI `Meta` card; when empty the space
    /// behaves exactly as before (prefix routing only, no enumeration).
    endpoints: Vec<(String, Description)>,
    /// The module's declared canonicalization, held host-side. A lazy module cannot be
    /// asked before it is loaded — and loading it to ask would defeat the laziness — so
    /// this arrives as static host data, like the endpoint cards beside it.
    aliases: ModuleAliases,
    /// The host's authority declaration for this mount — see [`ModuleFloor`]. Folded into
    /// every card `card_for` hands out and enforced before anything crosses the boundary.
    floor: ModuleFloor,
}

impl WasmModuleSpace {
    /// Route every IRI starting with one of `prefixes` to `transport`; `describe` is the
    /// module endpoint's self-description (for `Meta` / the catalog). With no enumerated
    /// endpoints (see [`with_endpoint`](Self::with_endpoint)) the space does not list in
    /// the catalog — it only resolves by prefix.
    ///
    /// `floor` is the host's authority declaration for the whole mount ([`ModuleFloor`]) —
    /// by value, so mounting a module is always an explicit decision and the ungated mount
    /// cannot be reached by omission. A per-endpoint card refines it; it never lowers it.
    pub fn new(
        prefixes: impl IntoIterator<Item = impl Into<String>>,
        transport: Arc<dyn ModuleSessionTransport>,
        describe: Description,
        floor: ModuleFloor,
    ) -> Self {
        Self {
            prefixes: prefixes.into_iter().map(Into::into).collect(),
            transport,
            describe,
            endpoints: Vec::new(),
            aliases: ModuleAliases::unknown(),
            floor,
        }
    }

    /// Install the module's declared canonicalization (builder) — see [`ModuleRewrite`].
    ///
    /// Errors if the declared table is unparseable, or if any rule names something outside
    /// the prefixes this space is mounted at: a module may only canonicalize names the host
    /// routed to it. Call it after the prefixes are set, i.e. straight after
    /// [`new`](Self::new).
    pub fn declaring(mut self, rewrite: ModuleRewrite) -> Result<Self> {
        self.aliases = ModuleAliases::install(&self.prefixes, rewrite)?;
        Ok(self)
    }

    /// What to do about a module that declared [`ModuleRewrite::Undeclarable`] (builder).
    /// Default [`OnUndeclarable::Refuse`].
    pub fn on_undeclarable(mut self, policy: OnUndeclarable) -> Self {
        self.aliases.policy = policy;
        self
    }

    /// Declare a bound pattern — an exact IRI or a URI template — and its self-description
    /// so it **enumerates into the catalog** and answers `Meta` with its own card, without
    /// loading the module. (A lazy module cannot be asked for its cards the way
    /// [`ModuleSpace::connect`] asks: asking means loading. So here they are host data.) The
    /// host supplies these as static data (a tiny manifest); the catalog reads only
    /// `entries()` + `describe()` (pure metadata), so the wasm artifact is still fetched
    /// and instantiated lazily, on the first real `Source`/`Sink` against the IRI. Builder
    /// style; call once per endpoint.
    pub fn with_endpoint(mut self, iri: impl Into<String>, describe: Description) -> Self {
        self.endpoints.push((iri.into(), describe));
        self
    }

    /// The card to hand the resolved endpoint for `target`: the enumerated endpoint's own
    /// description if `target` is one, else the generic prefix card — **always with the
    /// mount's floor folded in**. The fallback is what used to make an undeclared IRI under
    /// the prefix *less* gated than a declared one; it cannot any more, because the floor
    /// applies to both arms.
    fn card_for(&self, target: &Iri) -> Description {
        let card = self
            .host_card(target)
            .cloned()
            .unwrap_or_else(|| self.describe.clone());
        self.floor.applied_to(card)
    }

    /// The host-declared card matching `target`, if any — an exact IRI or a template.
    fn host_card(&self, target: &Iri) -> Option<&Description> {
        match_card(
            self.endpoints
                .iter()
                .map(|(pattern, card)| (pattern.as_str(), card.id.as_str(), card)),
            target,
        )
        .map(|(_, card)| card)
    }
}

impl Space for WasmModuleSpace {
    fn resolve(&self, request: &Request, _scope: &Scope) -> Resolution {
        let target = request.target.as_str();
        let matches = self.host_card(&request.target).is_some()
            || self.prefixes.iter().any(|p| target.starts_with(p.as_str()));
        if !matches {
            return Resolution::Miss;
        }
        // The canonical this space reports is the module's DECLARED rewrite, applied
        // host-side. `None` when nothing was declared — a claim, not a default, which is
        // why this stays a struct literal rather than `Resolved::new`: the next field
        // `Resolved` grows breaks this site on purpose, so the claim gets re-read.
        let canonical = match self.aliases.route(&request.target) {
            Routing::Direct => None,
            Routing::Canonical(iri) => Some(iri),
            Routing::Refuse(message) => {
                return Resolution::Hit(Resolved::new(refusing_endpoint(message), Bindings::new()))
            }
        };
        Resolution::Hit(Resolved {
            endpoint: Arc::new(WasmModuleEndpoint {
                transport: Arc::clone(&self.transport),
                describe: self.card_for(&request.target),
                floor: self.floor.clone(),
            }),
            bindings: Bindings::new(),
            canonical,
        })
    }

    /// Who enumerates: the same rule as [`ModuleSpace::entries`] — every pattern the space
    /// holds a card for — which here means the host's, since a lazy module is never asked.
    /// A bare prefix can't list its (open) IRI set. Empty => `None`, preserving the prior
    /// "not in the catalog" behaviour for modules that declare nothing.
    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        if self.endpoints.is_empty() {
            return None;
        }
        // `SpaceEntry::new` leaves `origin: None`, which is the correct semantics here and
        // not a placeholder: a lazy module's bindings ARE this kernel's own bindings.
        // `origin` is `Some(label)` only for a binding surfaced from a *mounted remote*
        // in a federated catalog — a module loaded in-process is not a remote.
        Some(
            self.endpoints
                .iter()
                .map(|(iri, describe)| SpaceEntry::new(iri.clone(), describe.id.clone()))
                .collect(),
        )
    }
}

/// The endpoint a [`WasmModuleSpace`] resolves to: drive the session over the transport and
/// fold the out-of-band callbacks' provenance into the result.
struct WasmModuleEndpoint {
    transport: Arc<dyn ModuleSessionTransport>,
    describe: Description,
    floor: ModuleFloor,
}

#[async_trait]
impl Endpoint for WasmModuleEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if let Some(scope) = self.floor.unsatisfied(inv.capability) {
            return Err(self.floor.denial(scope, inv.request.target.as_str()));
        }
        let invoke = encode(&ModuleCall::Invoke {
            request: inv.request.clone(),
            capability: inv.capability.clone(),
        })?;
        // Install a sink so each `serve_host_call` records what it resolved; take it before
        // `?` so it's cleaned up even on failure. Only the `u64` id crosses the await.
        let sink_id = install_sink();
        let result = self.transport.invoke_session(invoke).await;
        let collected = take_sink(sink_id);
        let reply_bytes = result.map_err(Error::Endpoint)?;

        // The module's own declared threads and a typed failure come back through
        // `outcome_from`; the callbacks' provenance the host collected out-of-band is folded
        // in here, no more cacheable than the inputs.
        let representation = outcome_from(decode::<ModuleReply>(&reply_bytes)?)?;
        let expiry = match collected.expiry {
            Some(dep) => representation.expiry.most_restrictive(dep),
            None => representation.expiry,
        };
        let mut representation = representation.with_expiry(expiry);
        for thread in collected.threads {
            representation = representation.depends_on(thread);
        }
        Ok(representation)
    }

    fn name(&self) -> &str {
        "wasm-module"
    }

    fn describe(&self) -> Description {
        self.describe.clone()
    }
}

/// Generate the wasm-bindgen glue that makes a module's `space()` a standalone, lazily
/// loadable artifact — so a new module is one macro line, not a hand-written crate. Emits a
/// public `invoke_session(Vec<u8>) -> Vec<u8>` (async) that runs [`run_session`] over the
/// given space, plus the `hostCall` import and the `!Send`→`Send` bridge it needs.
///
/// Use it in a `cdylib` crate that depends on `ikigai-module`, `ikigai-core`, `wasm-bindgen`,
/// `wasm-bindgen-futures`, `js-sys`, and `futures`, with `use wasm_bindgen::prelude::*;` in
/// scope:
///
/// ```ignore
/// ikigai_module::wasm_module!(ikigai_xslt::space);
/// ```
#[macro_export]
macro_rules! wasm_module {
    ($space:path) => {
        /// Run one module session: the host hands the encoded `Invoke` and gets back the
        /// encoded `ModuleReply`. The module pumps its sub-resource callbacks to the host's
        /// `hostCall` global while this awaits.
        #[::wasm_bindgen::prelude::wasm_bindgen]
        pub async fn invoke_session(invoke: ::std::vec::Vec<u8>) -> ::std::vec::Vec<u8> {
            let space: ::std::sync::Arc<dyn ::ikigai_core::Space> = ::std::sync::Arc::new($space());
            $crate::run_session(&space, &invoke, __ikigai_module_host_call).await
        }

        // The host's session pump, a global import: hand it an encoded `ModuleReply`
        // (a `HostCall`) and it returns the encoded `ModuleCall` (the `HostResult`).
        #[::wasm_bindgen::prelude::wasm_bindgen]
        extern "C" {
            #[::wasm_bindgen::prelude::wasm_bindgen(catch, js_name = "hostCall")]
            async fn __ikigai_module_host_call_js(
                reply: &[u8],
            ) -> ::core::result::Result<::wasm_bindgen::JsValue, ::wasm_bindgen::JsValue>;
        }

        // Bridge the `!Send` JS call to the `Send` future `run_session` needs: confine the
        // `JsFuture` to a `spawn_local` task and ferry the bytes back through a oneshot.
        fn __ikigai_module_host_call(
            reply: ::std::vec::Vec<u8>,
        ) -> impl ::core::future::Future<
            Output = ::core::result::Result<::std::vec::Vec<u8>, ::std::string::String>,
        > + ::core::marker::Send {
            let (tx, rx) = ::futures::channel::oneshot::channel();
            ::wasm_bindgen_futures::spawn_local(async move {
                let result = match __ikigai_module_host_call_js(&reply).await {
                    ::core::result::Result::Ok(value) => {
                        ::core::result::Result::Ok(::js_sys::Uint8Array::new(&value).to_vec())
                    }
                    ::core::result::Result::Err(e) => ::core::result::Result::Err(
                        ::wasm_bindgen::JsValue::as_string(&e)
                            .unwrap_or_else(|| ::std::string::String::from("hostCall failed")),
                    ),
                };
                let _ = tx.send(result);
            });
            async move {
                rx.await
                    .map_err(|_| ::std::string::String::from("hostCall task was dropped"))?
            }
        }
    };
}

// ---------------------------------------------------------------------------
// A real home: the session over a Unix-domain socket.
//
// `LoopbackTransport` runs the session over in-memory channels; this swaps those for a
// socket. The module is an out-of-process peer: `serve` runs its `space()` behind a UDS,
// and the host-side `UdsTransport` connects and drives the same session — send `Invoke`,
// service each `HostCall` against the host kernel, receive `Resolved`. The host loop and
// the module-side issuer are the loopback's, byte-for-byte; only the pipe changed (framed
// blocking socket I/O instead of `mpsc`). Unix only.
//
// Security is the operating system's: the socket is `0600`, meant for a per-user `0700`
// directory (the caller's path), and `serve` refuses any peer whose kernel-verified UID
// isn't the server's own user (`SO_PEERCRED` / `getpeereid`) — the same defense-in-depth
// model as `ikigai-ipc`.
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub use uds::{serve, serve_declaring, UdsTransport};

#[cfg(unix)]
mod uds {
    use super::*;
    use std::io::{self, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};

    /// Largest framed message accepted — guards the length header against a bogus
    /// allocation. 64 MiB is far above any representation a module round-trips.
    const MAX_FRAME: usize = 64 * 1024 * 1024;

    /// Write a `postcard`-encoded message length-prefixed (`u32` big-endian, then the
    /// payload) — the same framing `ikigai-wire` uses, inlined to keep the dep off.
    fn write_frame<W: Write, T: Serialize>(writer: &mut W, message: &T) -> io::Result<()> {
        let bytes = postcard::to_allocvec(message)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let len = u32::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
        writer.write_all(&len.to_be_bytes())?;
        writer.write_all(&bytes)?;
        writer.flush()
    }

    /// Read one length-prefixed `postcard` message (the counterpart to [`write_frame`]).
    fn read_frame<R: Read, T: DeserializeOwned>(reader: &mut R) -> io::Result<T> {
        let mut len = [0u8; 4];
        reader.read_exact(&mut len)?;
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "framed message exceeds the size limit",
            ));
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        postcard::from_bytes(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    fn io_err(e: io::Error) -> Error {
        Error::Endpoint(format!("module socket transport: {e}"))
    }

    /// A [`ModuleTransport`] that reaches a module served on a Unix socket. Each `invoke`
    /// opens a connection, runs one session, and closes it (so concurrent invocations
    /// never share a stream). The host-side loop is the loopback's, over framed socket I/O.
    pub struct UdsTransport {
        path: PathBuf,
    }

    impl UdsTransport {
        /// A transport reaching the module server listening on `path`.
        pub fn connect(path: impl Into<PathBuf>) -> Self {
            Self { path: path.into() }
        }
    }

    #[async_trait]
    impl ModuleTransport for UdsTransport {
        async fn invoke(
            &self,
            request: Request,
            capability: &Capability,
            host: &dyn Issuer,
        ) -> Result<Representation> {
            let mut stream = UnixStream::connect(&self.path).map_err(io_err)?;
            let invoke = ModuleCall::Invoke {
                request,
                capability: capability.clone(),
            };
            write_frame(&mut stream, &invoke).map_err(io_err)?;
            loop {
                match read_frame::<_, ModuleReply>(&mut stream).map_err(io_err)? {
                    ModuleReply::HostCall {
                        request,
                        capability: carried,
                    } => {
                        let clamped = capability.clamp(&carried);
                        let answer = host_answer(host.issue(request, &clamped).await);
                        write_frame(&mut stream, &answer).map_err(io_err)?;
                    }
                    reply => return outcome_from(reply),
                }
            }
        }

        fn entries(&self) -> Option<Vec<SpaceEntry>> {
            // Ask the server over the wire (`Describe`); best-effort, so introspection of
            // an unreachable module degrades to "no entries" rather than erroring.
            let mut stream = UnixStream::connect(&self.path).ok()?;
            write_frame(&mut stream, &ModuleCall::Describe).ok()?;
            match read_frame::<_, ModuleReply>(&mut stream).ok()? {
                ModuleReply::Bindings(entries) => entries,
                _ => None,
            }
        }

        async fn manifest(&self) -> Result<ModuleManifest> {
            let mut stream = UnixStream::connect(&self.path).map_err(io_err)?;
            write_frame(&mut stream, &ModuleCall::Manifest).map_err(io_err)?;
            // Connect/write failures are real errors (the module is unreachable); anything
            // that comes back other than a `Manifest` is not. A server older than
            // `ModuleCall::Manifest` cannot decode the frame and drops the connection, so
            // the read EOFs — which says its NAMING is unknown, not that it does not
            // rewrite. The module-side guard is what covers that gap.
            Ok(match read_frame::<_, ModuleReply>(&mut stream) {
                Ok(ModuleReply::Manifest(manifest)) => manifest,
                _ => ModuleManifest::unknown(self.entries()),
            })
        }

        async fn cards(&self) -> Result<Vec<ModuleCard>> {
            let mut stream = UnixStream::connect(&self.path).map_err(io_err)?;
            write_frame(&mut stream, &ModuleCall::Cards).map_err(io_err)?;
            // A server older than `ModuleCall::Cards` cannot decode the frame and drops the
            // connection: no cards, which is exactly what such a server can say.
            Ok(match read_frame::<_, ModuleReply>(&mut stream) {
                Ok(ModuleReply::Cards(cards)) => cards,
                _ => Vec::new(),
            })
        }
    }

    /// Run `space` as a module server on `path` until an unrecoverable accept error: bind
    /// the socket (replacing a stale one), restrict it to `0600`, and serve each
    /// connection on its own thread. The caller should place `path` in a per-user `0700`
    /// directory (see `ikigai-ipc::default_socket_path` for the convention).
    ///
    /// Each connection's kernel-verified peer UID is checked, and any peer that isn't the
    /// server's own user is refused — defense in depth over the `0600`/`0700` filesystem
    /// permissions (the same model `ikigai-ipc` uses). Capability-based authorization
    /// (finer than per-user) layers on later.
    pub fn serve(space: Arc<dyn Space>, path: &Path) -> io::Result<()> {
        serve_declaring(space, ModuleRewrite::Unknown, path)
    }

    /// [`serve`], for a module whose space **rewrites names**: it answers
    /// [`ModuleCall::Manifest`] with `rewrite`, so a host can install the module's
    /// canonicalization and share one identity with it. `serve` declares
    /// [`ModuleRewrite::Unknown`] — truthfully, since it was told nothing.
    pub fn serve_declaring(
        space: Arc<dyn Space>,
        rewrite: ModuleRewrite,
        path: &Path,
    ) -> io::Result<()> {
        let _ = std::fs::remove_file(path); // a leftover socket would fail the bind
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let me = own_uid();
        for stream in listener.incoming() {
            let stream = stream?;
            if peer_uid(&stream) != Some(me) {
                continue; // not our user — drop it
            }
            let space = Arc::clone(&space);
            let rewrite = rewrite.clone();
            std::thread::spawn(move || serve_connection(space, rewrite, stream));
        }
        Ok(())
    }

    /// This process's real user id.
    #[allow(unsafe_code)]
    pub(crate) fn own_uid() -> u32 {
        // SAFETY: `getuid` reads a process attribute and cannot fail.
        unsafe { libc::getuid() }
    }

    /// The connected peer's user id, kernel-verified — `None` if it can't be read.
    /// (Linux reads `SO_PEERCRED`; macOS/BSD use `getpeereid`.)
    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)]
    pub(crate) fn peer_uid(stream: &UnixStream) -> Option<u32> {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: a valid fd and correctly-sized out-params for SO_PEERCRED.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        (rc == 0).then_some(cred.uid)
    }

    /// The connected peer's user id (macOS/BSD use `getpeereid`).
    #[cfg(not(target_os = "linux"))]
    #[allow(unsafe_code)]
    pub(crate) fn peer_uid(stream: &UnixStream) -> Option<u32> {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: a valid fd and two valid out-params.
        let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
        (rc == 0).then_some(uid)
    }

    /// Serve one connection: run a module session per `Invoke` until the peer hangs up.
    /// `pub(crate)` so a test can drive a single accepted connection directly.
    pub(crate) fn serve_connection(
        space: Arc<dyn Space>,
        rewrite: ModuleRewrite,
        stream: UnixStream,
    ) {
        loop {
            let call: ModuleCall = match read_frame(&mut &stream) {
                Ok(call) => call,
                Err(_) => return, // EOF or a malformed frame ends the session
            };
            let reply = match call {
                ModuleCall::Invoke {
                    request,
                    capability,
                } => futures::executor::block_on(run_session(
                    &space, &rewrite, &stream, request, capability,
                )),
                ModuleCall::Describe => ModuleReply::Bindings(space.entries()),
                ModuleCall::Manifest => {
                    ModuleReply::Manifest(ModuleManifest::new(space.entries(), rewrite.clone()))
                }
                ModuleCall::Cards => ModuleReply::Cards(cards_of(&*space)),
                ModuleCall::HostResult(_) | ModuleCall::HostError(_) => {
                    ModuleReply::Error("server received HostResult before Invoke".to_string())
                }
            };
            if write_frame(&mut &stream, &reply).is_err() {
                return;
            }
        }
    }

    /// Resolve `request` in the module's space and run the endpoint under a
    /// [`SocketHostIssuer`], so its `inv.source`/`inv.issue` round-trip as
    /// `HostCall`/`HostResult` on `stream`.
    async fn run_session(
        space: &Arc<dyn Space>,
        rewrite: &ModuleRewrite,
        stream: &UnixStream,
        request: Request,
        capability: Capability,
    ) -> ModuleReply {
        let issuer = SocketHostIssuer { stream };
        dispatch(&**space, rewrite, &request, &capability, &issuer).await
    }

    /// The module end of the callback channel over a socket: emit a `HostCall` frame and
    /// block on the next `HostResult` frame. The socket counterpart of the loopback's
    /// `SessionHostIssuer`; callbacks are assumed sequential (the server reads the next
    /// frame as the answer to the last `HostCall`).
    struct SocketHostIssuer<'a> {
        stream: &'a UnixStream,
    }

    #[async_trait]
    impl Issuer for SocketHostIssuer<'_> {
        async fn issue(&self, request: Request, capability: &Capability) -> Result<Representation> {
            let call = ModuleReply::HostCall {
                request,
                capability: capability.clone(),
            };
            let mut stream = self.stream;
            write_frame(&mut stream, &call).map_err(io_err)?;
            answer_from(read_frame::<_, ModuleCall>(&mut stream).map_err(io_err)?)
        }
    }
}

// ---------------------------------------------------------------------------
// The host side.
// ---------------------------------------------------------------------------

/// A host-side [`Space`] that routes IRIs (by prefix) to a module over a
/// [`ModuleTransport`]. Slots into the kernel's root `Fallback` where a
/// statically-linked `space()` would go:
///
/// ```ignore
/// Fallback::new(vec![
///     Arc::new(local_space),
///     Arc::new(ModuleSpace::new(
///         ["urn:xslt:"],
///         Arc::new(InProcessTransport::new(ikigai_xslt::space())),
///         ModuleFloor::requiring("urn:cap:xslt"),   // ← what this mount may do
///     )),
///     // …
/// ])
/// ```
pub struct ModuleSpace {
    prefixes: Vec<String>,
    transport: Arc<dyn ModuleTransport>,
    aliases: ModuleAliases,
    /// The host's authority declaration for this mount — see [`ModuleFloor`].
    floor: ModuleFloor,
    /// Patterns the host declares a card for — the host's word about an endpoint, and the
    /// place a *refinement* of the floor lives. Host data, exactly as in
    /// [`WasmModuleSpace`]; a host card wins over the module's own card for the same
    /// pattern, and the floor is folded into both, so neither can lower the mount.
    endpoints: Vec<(String, Description)>,
    /// The module's own cards, asked for once at [`connect`](Self::connect) and held here so
    /// the synchronous `resolve` can hand the kernel the module's self-description for an
    /// IRI the host declared nothing for. Empty for a mount made with [`new`](Self::new),
    /// which never asks. Only patterns under the mount's prefixes are kept: the host lists
    /// what it routes.
    cards: Vec<ModuleCard>,
    /// The card for an IRI under the prefixes that no host card and no module card matches
    /// ([`describing`](Self::describing)); a bare `"module"` unless the host says better.
    describe: Description,
}

impl ModuleSpace {
    /// Route every IRI starting with one of `prefixes` to `transport`, **without asking
    /// the module anything** — neither how it names things nor what its endpoints are (so
    /// an IRI the host declares no card for describes itself with the generic card; see
    /// [`describing`](Self::describing) and [`connect`](Self::connect)).
    ///
    /// Correct for the overwhelmingly common module, which resolves every target under the
    /// name it was given. For a module that composes a rewriting space, prefer
    /// [`connect`](Self::connect): this constructor records
    /// [`ModuleRewrite::Unknown`], so the host shares no identity with the module and the
    /// module side refuses any invocation whose resolution reports a rewrite (see
    /// [`ModuleRewrite`]).
    /// `floor` is the host's authority declaration for the whole mount ([`ModuleFloor`]),
    /// taken by value so the ungated mount cannot be reached by omission — it must be
    /// written, `ModuleFloor::public()`.
    pub fn new(
        prefixes: impl IntoIterator<Item = impl Into<String>>,
        transport: Arc<dyn ModuleTransport>,
        floor: ModuleFloor,
    ) -> Self {
        Self {
            prefixes: prefixes.into_iter().map(Into::into).collect(),
            transport,
            aliases: ModuleAliases::unknown(),
            floor,
            endpoints: Vec::new(),
            cards: Vec::new(),
            describe: Description::new("module"),
        }
    }

    /// Ask the module for its [`ModuleManifest`] and install the canonicalization it
    /// declares — the mount-time round trip that lets a module compose a rewriting space —
    /// and for its [`ModuleCard`]s, installed beside the host's own so the module's
    /// endpoints describe themselves through the mount exactly as they would linked.
    ///
    /// This is the one place the module is asked, and it is asked **once**: from here on
    /// the rewrite is applied by the host, synchronously, inside `Space::resolve`, and
    /// reported on [`Resolved::canonical`], so the kernel's cache key, golden-thread cut
    /// and capability floor all name the backing resource. Asking per-resolution is what
    /// the synchronous `Space::resolve` signature forbids.
    ///
    /// Errors if the module's declared table is unparseable or names anything outside
    /// `prefixes` — at mount time, where an operator is watching.
    /// The module is asked how it NAMES things; it is never asked what it may DO — `floor`
    /// is the host's ([`ModuleFloor`]).
    pub async fn connect(
        prefixes: impl IntoIterator<Item = impl Into<String>>,
        transport: Arc<dyn ModuleTransport>,
        floor: ModuleFloor,
    ) -> Result<Self> {
        let prefixes: Vec<String> = prefixes.into_iter().map(Into::into).collect();
        let manifest = transport.manifest().await?;
        let aliases = ModuleAliases::install(&prefixes, manifest.rewrite)?;
        // The module's cards, kept only for the patterns this mount routes: a card for a
        // name the host never routed here would list an IRI the mount cannot serve.
        let cards = transport
            .cards()
            .await?
            .into_iter()
            .filter(|card| {
                prefixes
                    .iter()
                    .any(|p| card.entry.pattern.starts_with(p.as_str()))
            })
            .collect();
        Ok(Self {
            prefixes,
            transport,
            aliases,
            floor,
            endpoints: Vec::new(),
            cards,
            describe: Description::new("module"),
        })
    }

    /// The card for an IRI under the prefixes that nothing else describes (builder): what
    /// `Meta` answers for a name the host never enumerated and the module never listed.
    /// Default `Description::new("module")`. Display only — the floor is folded in either
    /// way, so this can never be an authority fallback.
    pub fn describing(mut self, describe: Description) -> Self {
        self.describe = describe;
        self
    }

    /// Install a declaration the host already holds, without asking (builder). Same
    /// validation as [`connect`](Self::connect).
    pub fn declaring(mut self, rewrite: ModuleRewrite) -> Result<Self> {
        self.aliases = ModuleAliases::install(&self.prefixes, rewrite)?;
        Ok(self)
    }

    /// What to do about a module that declared [`ModuleRewrite::Undeclarable`] (builder).
    /// Default [`OnUndeclarable::Refuse`].
    pub fn on_undeclarable(mut self, policy: OnUndeclarable) -> Self {
        self.aliases.policy = policy;
        self
    }

    /// Declare a concrete endpoint IRI and the card the host stands behind for it: what it
    /// answers `Meta` with, and — the point — the place a *refinement* of the mount's
    /// [`ModuleFloor`] is written (`Description::new(..).verb(..).requires(..)`). Builder
    /// style; call once per endpoint.
    ///
    /// A card can only ADD to the floor: `ModuleFloor::applied_to` (private) folds the mount's
    /// scopes into every card, so an IRI with no card is gated exactly as strictly as one
    /// with, and forgetting a card can never buy less gating.
    pub fn with_endpoint(mut self, iri: impl Into<String>, describe: Description) -> Self {
        self.endpoints.push((iri.into(), describe));
        self
    }

    /// Whether `pattern` is under one of the mount's prefixes — what this mount routes.
    fn routes(&self, pattern: &str) -> bool {
        self.prefixes
            .iter()
            .any(|p| pattern.starts_with(p.as_str()))
    }

    /// The host-declared card matching `target`, if any — an exact IRI or a template.
    fn host_card(&self, target: &Iri) -> Option<&Description> {
        match_card(
            self.endpoints
                .iter()
                .map(|(pattern, card)| (pattern.as_str(), card.id.as_str(), card)),
            target,
        )
        .map(|(_, card)| card)
    }

    /// The name and card to hand the resolved endpoint for `target`, the mount's floor
    /// folded into the card: the host's card if it declared one, else the module's own
    /// (asked at `connect`), else the generic card — a *display* fallback only, never an
    /// authority one, since the floor applies to all three.
    fn card_for(&self, target: &Iri) -> (String, Description) {
        let host = self
            .endpoints
            .iter()
            .map(|(pattern, card)| (pattern.as_str(), card.id.as_str(), card));
        let module = self.cards.iter().map(|card| {
            (
                card.entry.pattern.as_str(),
                card.entry.endpoint.as_str(),
                &card.description,
            )
        });
        let (name, card) =
            match_card(host.chain(module), target).unwrap_or(("module", &self.describe));
        (name.to_string(), self.floor.applied_to(card.clone()))
    }

    /// What the module said about how it names things.
    pub fn rewrite(&self) -> &ModuleRewrite {
        &self.aliases.rewrite
    }

    /// The authority floor this mount imposes.
    pub fn floor(&self) -> &ModuleFloor {
        &self.floor
    }
}

impl Space for ModuleSpace {
    fn resolve(&self, request: &Request, _scope: &Scope) -> Resolution {
        if !self.routes(request.target.as_str()) && self.host_card(&request.target).is_none() {
            return Resolution::Miss;
        }
        // ★ The module's declared rewrite, applied HERE — host-side, synchronously, by the
        // kernel's own `AliasTable`. The canonical rides back on the `Resolved` and the
        // kernel adopts it before it computes the request id, so the logical and backing
        // names are ONE cache entry and ONE golden thread across the module boundary.
        // `None` when nothing was declared: a claim, not a default, which is why this stays
        // a struct literal — the compile break IS the review trigger.
        let canonical = match self.aliases.route(&request.target) {
            Routing::Direct => None,
            Routing::Canonical(iri) => Some(iri),
            Routing::Refuse(message) => {
                return Resolution::Hit(Resolved::new(refusing_endpoint(message), Bindings::new()))
            }
        };
        // (A real host also *triggers lazy instantiation* of the module here.)
        let (name, describe) = self.card_for(&request.target);
        Resolution::Hit(Resolved {
            endpoint: Arc::new(ModuleEndpoint {
                transport: Arc::clone(&self.transport),
                name,
                describe,
                floor: self.floor.clone(),
            }),
            bindings: Bindings::new(),
            canonical,
        })
    }

    /// ★ Who enumerates: **the host lists every pattern it holds a card for, then whatever
    /// the module says it binds under the routed prefixes.** Host cards first (they win
    /// resolution too), then the module's cards from `connect`, then the transport's live
    /// answer for a mount that never asked — each pattern once. [`WasmModuleSpace`] follows
    /// the same rule and simply holds no module cards, because asking a lazy module means
    /// loading it: the two spaces differ in what they can KNOW, not in the rule.
    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        let mut entries: Vec<SpaceEntry> = self
            .endpoints
            .iter()
            .map(|(pattern, card)| SpaceEntry::new(pattern.clone(), card.id.clone()))
            .collect();
        let listed =
            |entries: &[SpaceEntry], pattern: &str| entries.iter().any(|e| e.pattern == pattern);
        for card in &self.cards {
            if !listed(&entries, &card.entry.pattern) {
                entries.push(card.entry.clone());
            }
        }
        for entry in self.transport.entries().unwrap_or_default() {
            if self.routes(&entry.pattern) && !listed(&entries, &entry.pattern) {
                entries.push(entry);
            }
        }
        (!entries.is_empty()).then_some(entries)
    }
}

/// The host-side endpoint a [`ModuleSpace`] resolves to: it forwards the invocation to
/// the module over the transport, bridging the module's callbacks back to the host
/// through *this* invocation — so the host kernel records the dependency threads and
/// serves the callbacks from its cache (cacheability composes across the boundary).
struct ModuleEndpoint {
    transport: Arc<dyn ModuleTransport>,
    /// The bound endpoint's name as the card's source knows it — the module's for a module
    /// card, the description id for a host card, `"module"` for the generic one — so a
    /// template entry's probe (core's `describe_entry` guard) recognizes what it reached.
    name: String,
    describe: Description,
    floor: ModuleFloor,
}

#[async_trait]
impl Endpoint for ModuleEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        // ★ The mount's capability floor, host-side, before anything crosses the boundary.
        // The kernel's own pre-dispatch check (`declared = enforced`) already holds it for
        // every verb this endpoint's card DECLARES; this holds it for the rest — a prefix
        // mount whose IRI has no card declares no verbs, synthesizes no action specs, and
        // was therefore checked against nothing at all. That gap is how a declared
        // requirement used to reach an ungated invocation. `Meta` never arrives here: the
        // kernel renders `describe()` without invoking, which is the same exemption core
        // makes by leaving `Meta` out of `action_specs()`.
        if let Some(scope) = self.floor.unsatisfied(inv.capability) {
            return Err(self.floor.denial(scope, inv.request.target.as_str()));
        }
        let bridge = HostBridge { inv };
        self.transport
            .invoke(inv.request.clone(), inv.capability, &bridge)
            .await
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn describe(&self) -> Description {
        self.describe.clone()
    }
}

/// The host end of the callback channel: an [`Issuer`] that forwards a module's
/// sub-request to the host kernel through the originating [`Invocation`]. In-process
/// this is a direct re-entrant call; over a wire transport the equivalent loop services
/// [`ModuleReply::HostCall`] messages with `host.issue(..)`.
struct HostBridge<'a, 'b> {
    inv: &'b Invocation<'a>,
}

#[async_trait]
impl Issuer for HostBridge<'_, '_> {
    async fn issue(&self, request: Request, _capability: &Capability) -> Result<Representation> {
        // Resolve against the host kernel via the host invocation, so its golden
        // thread is recorded as a dependency (the result is cacheable + invalidated
        // exactly as the statically-linked module would be).
        self.inv.issue(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{
        ActionSpec, Alias, ArgRef, ArgSpec, Description, EndpointSpace, Exact, Fallback, Kernel,
        MetaRenderer, ReprType, Rewrite, Verb,
    };
    use std::sync::Mutex;

    // A tiny meta renderer so the test kernel can describe endpoints if asked.
    struct PlainRenderer;
    impl MetaRenderer for PlainRenderer {
        fn render(&self, d: &Description, _t: &ReprType) -> Result<Representation> {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                d.id.as_bytes().to_vec(),
            ))
        }
    }

    // A stand-in module endpoint — the smallest thing that exercises the module-format
    // contract: it resolves TWO sub-resources (`a=` and `b=`) *back through the host
    // kernel* (via `inv.source`, carried over the ModuleTransport) and joins them. That
    // host callback is the whole point of the format, so the test owns a trivial endpoint
    // rather than pulling in a concrete module crate just to stand one up.
    struct ConcatEndpoint;

    #[async_trait]
    impl Endpoint for ConcatEndpoint {
        async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
            let mut out = Vec::new();
            for arg in ["a", "b"] {
                let uri = inv.inline_str(arg).map_err(|_| {
                    Error::Endpoint(format!("urn:stub:concat needs a `{arg}=<uri>` reference"))
                })?;
                let iri = Iri::parse(uri)
                    .map_err(|e| Error::Endpoint(format!("bad resource IRI `{uri}`: {e}")))?;
                // ← the host callback: resolved against the host kernel, over the transport.
                out.extend_from_slice(&inv.source(&iri).await?.bytes);
            }
            // Cacheable, so the result inherits both sub-resources' golden threads —
            // exactly the host-side caching a real module relies on. It also declares a
            // thread named after the resource it *is*, which is what a module writing
            // through its own name would cut: that thread is the module's answer to "what
            // did I resolve?", so the rewriting tests can cut the backing name and watch
            // an entry created through the logical name go.
            Ok(Representation::new(ReprType::new("text/plain"), out)
                .cacheable()
                .depends_on(inv.request.target.as_str()))
        }

        fn name(&self) -> &str {
            "stub-concat"
        }

        fn describe(&self) -> Description {
            Description::new("stub-concat")
                .title("Concat (test stub)")
                .verb(Verb::Source)
                .input(ArgSpec::new("a").summary("first resolvable resource IRI"))
                .input(ArgSpec::new("b").summary("second resolvable resource IRI"))
                .output("text/plain")
        }
    }

    // The stub module's `space()` — bound only inside a ModuleSpace below, never linked
    // into a local host space, so the ONLY way its endpoint resolves `a`/`b` is by
    // calling back to the host.
    fn stub_module() -> EndpointSpace {
        EndpointSpace::new()
            .bind(Exact::new("urn:stub:concat"), ConcatEndpoint)
            // Reports the name it was invoked under. The one-line answer to "did the host
            // canonicalize before it resolved?", and it works over every transport because
            // the target rides in the `Request`, which does serialize.
            .bind(
                Exact::new("urn:stub:whoami"),
                FnEndpoint::new("stub-whoami", |inv: &Invocation<'_>| {
                    Ok(Representation::new(
                        ReprType::new("text/plain"),
                        inv.request.target.as_str().as_bytes().to_vec(),
                    ))
                }),
            )
    }

    // A fixed host resource, declaring a golden thread named after itself — the ordinary
    // convention, and what lets a test cut one of the module's dependencies.
    fn fixed(name: &'static str, media: &'static str, body: &'static str) -> FnEndpoint {
        FnEndpoint::new(name, move |inv: &Invocation<'_>| {
            Ok(
                Representation::new(ReprType::new(media), body.as_bytes().to_vec())
                    .cacheable()
                    .depends_on(inv.request.target.as_str()),
            )
        })
    }

    #[test]
    fn module_endpoint_resolves_its_refs_back_through_the_host() {
        // Host space: the two resources the module will reach back for. The module is NOT
        // linked into a local space — it's reached only through the ModuleSpace, over the
        // InProcessTransport.
        let host_space = EndpointSpace::new()
            .bind(
                Exact::new("urn:test:greeting"),
                fixed("greeting", "text/plain", "hello, "),
            )
            .bind(
                Exact::new("urn:test:subject"),
                fixed("subject", "text/plain", "module"),
            );

        let module = ModuleSpace::new(
            ["urn:stub:"],
            Arc::new(InProcessTransport::new(stub_module())),
            ModuleFloor::public(),
        );

        let root: Arc<dyn Space> = Arc::new(Fallback::new(vec![
            Arc::new(host_space) as Arc<dyn Space>,
            Arc::new(module) as Arc<dyn Space>,
        ]));
        let kernel = Kernel::with_meta_renderer(root, Arc::new(PlainRenderer));

        let request = Request::new(Verb::Source, Iri::parse("urn:stub:concat").unwrap())
            .with_arg("a", ArgRef::Inline(b"urn:test:greeting".to_vec()))
            .with_arg("b", ArgRef::Inline(b"urn:test:subject".to_vec()));

        let rep = block_on(kernel.issue(request, &Capability::root())).expect("module invoke");

        // The module joined two resources it pulled back from the host.
        assert_eq!(String::from_utf8(rep.bytes).unwrap(), "hello, module");
    }

    #[test]
    fn the_module_result_is_cached_by_the_host_kernel() {
        // The module is a stateless leaf; the HOST kernel caches its result. Same query
        // twice ⇒ the second is served from cache (cache_len stays 1 for the top result).
        let host_space = EndpointSpace::new()
            .bind(
                Exact::new("urn:test:greeting"),
                fixed("greeting", "text/plain", "hello, "),
            )
            .bind(
                Exact::new("urn:test:subject"),
                fixed("subject", "text/plain", "module"),
            );
        let module = ModuleSpace::new(
            ["urn:stub:"],
            Arc::new(InProcessTransport::new(stub_module())),
            ModuleFloor::public(),
        );
        let root: Arc<dyn Space> = Arc::new(Fallback::new(vec![
            Arc::new(host_space) as Arc<dyn Space>,
            Arc::new(module) as Arc<dyn Space>,
        ]));
        let kernel = Kernel::with_meta_renderer(root, Arc::new(PlainRenderer));
        let req = || {
            Request::new(Verb::Source, Iri::parse("urn:stub:concat").unwrap())
                .with_arg("a", ArgRef::Inline(b"urn:test:greeting".to_vec()))
                .with_arg("b", ArgRef::Inline(b"urn:test:subject".to_vec()))
        };
        let a = block_on(kernel.issue(req(), &Capability::root())).unwrap();
        assert!(
            kernel.is_cached(&req(), &Capability::root()),
            "module result is cacheable host-side"
        );
        let b = block_on(kernel.issue(req(), &Capability::root())).unwrap();
        assert_eq!(a.bytes, b.bytes);
    }

    // --- LoopbackTransport: the same stub, but the session runs through the codec --------

    fn concat_request() -> Request {
        Request::new(Verb::Source, Iri::parse("urn:stub:concat").unwrap())
            .with_arg("a", ArgRef::Inline(b"urn:test:greeting".to_vec()))
            .with_arg("b", ArgRef::Inline(b"urn:test:subject".to_vec()))
    }

    // Host space + a module routed over `transport`, as one root space.
    fn root_over(transport: impl ModuleTransport + 'static) -> Arc<dyn Space> {
        let host_space = EndpointSpace::new()
            .bind(
                Exact::new("urn:test:greeting"),
                fixed("greeting", "text/plain", "hello, "),
            )
            .bind(
                Exact::new("urn:test:subject"),
                fixed("subject", "text/plain", "module"),
            );
        let module = ModuleSpace::new(
            ["urn:stub:"],
            Arc::new(transport) as Arc<dyn ModuleTransport>,
            ModuleFloor::public(),
        );
        Arc::new(Fallback::new(vec![
            Arc::new(host_space) as Arc<dyn Space>,
            Arc::new(module) as Arc<dyn Space>,
        ]))
    }

    #[test]
    fn loopback_runs_the_full_serialized_session() {
        // Same stub, but every Invoke / HostCall / HostResult / Resolved is postcard-encoded
        // over a byte channel. A correct "hello, module" proves the session state machine ran
        // and that Request, Capability, and Representation all round-tripped through the codec.
        let kernel = Kernel::with_meta_renderer(
            root_over(LoopbackTransport::new(stub_module())),
            Arc::new(PlainRenderer),
        );
        let rep =
            block_on(kernel.issue(concat_request(), &Capability::root())).expect("loopback invoke");
        assert_eq!(String::from_utf8(rep.bytes).unwrap(), "hello, module");
    }

    #[test]
    fn loopback_result_is_cached_via_callback_provenance() {
        // The two HostCalls resolve through the host kernel (recorded on the *outer*
        // invocation), so the serialized transform inherits their cacheability and is cached
        // host-side — exactly as the in-process transport. Provenance rides the callbacks,
        // not the serialized `Resolved` (whose threads are `serde(skip)`).
        let kernel = Kernel::with_meta_renderer(
            root_over(LoopbackTransport::new(stub_module())),
            Arc::new(PlainRenderer),
        );
        let a = block_on(kernel.issue(concat_request(), &Capability::root())).unwrap();
        assert!(
            kernel.is_cached(&concat_request(), &Capability::root()),
            "loopback result is cacheable host-side"
        );
        let b = block_on(kernel.issue(concat_request(), &Capability::root())).unwrap();
        assert_eq!(a.bytes, b.bytes);
    }

    #[test]
    fn loopback_describe_round_trips_the_module_bindings() {
        // The Describe arm: send a `Describe`, get back `Bindings` carrying the module's bound
        // IRIs — so `urn:kernel:catalog` stays whole when a module answers introspection over
        // a real (wasm/socket) transport that can't call `entries()` synchronously.
        let (host_to_module_tx, host_to_module_rx) = mpsc::unbounded::<Vec<u8>>();
        let (module_to_host_tx, mut module_to_host_rx) = mpsc::unbounded::<Vec<u8>>();
        host_to_module_tx
            .unbounded_send(encode(&ModuleCall::Describe).unwrap())
            .unwrap();
        block_on(run_module_session(
            Arc::new(stub_module()),
            ModuleRewrite::None,
            host_to_module_rx,
            module_to_host_tx,
        ));
        let reply: ModuleReply = decode(&block_on(module_to_host_rx.next()).unwrap()).unwrap();
        match reply {
            ModuleReply::Bindings(entries) => {
                let patterns: Vec<String> = entries
                    .unwrap_or_default()
                    .into_iter()
                    .map(|e| e.pattern)
                    .collect();
                assert!(
                    patterns.iter().any(|p| p == "urn:stub:concat"),
                    "expected urn:stub:concat in bindings, got {patterns:?}"
                );
            }
            other => panic!("expected Bindings, got {other:?}"),
        }
    }

    // --- run_session: the generic module side, driven by a closure pump ----------------

    #[test]
    fn run_session_pumps_host_calls_through_a_closure() {
        // The closure is the byte pump a real transport provides — it decodes each HostCall,
        // resolves it on a host kernel, and encodes the HostResult. This is the exact shape
        // the browser uses, with a JS byte-channel as the pump.
        let host_space = EndpointSpace::new()
            .bind(
                Exact::new("urn:test:greeting"),
                fixed("greeting", "text/plain", "hello, "),
            )
            .bind(
                Exact::new("urn:test:subject"),
                fixed("subject", "text/plain", "module"),
            );
        let host_kernel = Arc::new(Kernel::with_meta_renderer(
            Arc::new(host_space) as Arc<dyn Space>,
            Arc::new(PlainRenderer),
        ));
        let module: Arc<dyn Space> = Arc::new(stub_module());

        let invoke = encode(&ModuleCall::Invoke {
            request: concat_request(),
            capability: Capability::root(),
        })
        .unwrap();

        let host_call = move |reply_bytes: Vec<u8>| {
            let host_kernel = Arc::clone(&host_kernel);
            async move {
                match decode::<ModuleReply>(&reply_bytes).map_err(|e| e.to_string())? {
                    ModuleReply::HostCall {
                        request,
                        capability,
                    } => {
                        let result = host_kernel
                            .issue(request, &capability)
                            .await
                            .map_err(|e| e.to_string());
                        encode(&ModuleCall::HostResult(result)).map_err(|e| e.to_string())
                    }
                    _ => Err("expected HostCall".to_string()),
                }
            }
        };

        let reply_bytes = block_on(run_session(&module, &invoke, host_call));
        let rep = outcome_from(decode::<ModuleReply>(&reply_bytes).unwrap())
            .expect("the session resolved");
        assert_eq!(
            String::from_utf8(rep.bytes.clone()).unwrap(),
            "hello, module"
        );
        // The stub declares a thread under its own name; the closure pump carries it
        // (`ResolvedThreaded`) and the host re-attaches it.
        assert_eq!(
            rep.threads().iter().cloned().collect::<Vec<_>>(),
            [Thread::new("urn:stub:concat")]
        );
    }

    // --- WasmModuleSpace + serve_host_call: the browser's split, exercised on native ----

    // A fake `ModuleSessionTransport` that runs the module side in-process via `run_session`,
    // servicing each HostCall out-of-band through `serve_host_call` against a separate
    // host-resources kernel — the same split the browser uses (host drives `invoke_session`;
    // the module's HostCalls hit a global the host serves), minus the wasm boundary.
    struct FakeTransport {
        module: Arc<dyn Space>,
        host: Arc<Kernel>,
    }

    #[async_trait]
    impl ModuleSessionTransport for FakeTransport {
        async fn invoke_session(&self, invoke: Vec<u8>) -> std::result::Result<Vec<u8>, String> {
            let host = Arc::clone(&self.host);
            let host_call = move |reply: Vec<u8>| {
                let host = Arc::clone(&host);
                async move {
                    Ok(serve_host_call(&reply, |request, capability| {
                        let host = Arc::clone(&host);
                        async move { host.issue(request, &capability).await }
                    })
                    .await)
                }
            };
            Ok(run_session(&self.module, &invoke, host_call).await)
        }
    }

    #[test]
    fn wasm_module_space_drives_a_session_with_out_of_band_callbacks() {
        // WasmModuleSpace encodes the Invoke and drives the transport; the module's two
        // HostCalls are serviced out-of-band by serve_host_call (recording into the sink the
        // space installed); the result folds that provenance. A correct "hello, module"
        // proves the whole browser-shaped split composes.
        let host_resources = Arc::new(Kernel::with_meta_renderer(
            Arc::new(
                EndpointSpace::new()
                    .bind(
                        Exact::new("urn:test:greeting"),
                        fixed("greeting", "text/plain", "hello, "),
                    )
                    .bind(
                        Exact::new("urn:test:subject"),
                        fixed("subject", "text/plain", "module"),
                    ),
            ) as Arc<dyn Space>,
            Arc::new(PlainRenderer),
        ));
        let transport = Arc::new(FakeTransport {
            module: Arc::new(stub_module()),
            host: host_resources,
        });
        let describe = Description::new("stub-concat").title("Concat (test stub)");
        let kernel = Kernel::with_meta_renderer(
            Arc::new(WasmModuleSpace::new(
                ["urn:stub:"],
                transport,
                describe,
                ModuleFloor::public(),
            )) as Arc<dyn Space>,
            Arc::new(PlainRenderer),
        );

        let rep =
            block_on(kernel.issue(concat_request(), &Capability::root())).expect("wasm invoke");
        assert_eq!(String::from_utf8(rep.bytes).unwrap(), "hello, module");
        // The refs are permanently cacheable (no thread), so the folded result caches too.
        assert!(kernel.is_cached(&concat_request(), &Capability::root()));
    }

    #[test]
    fn declared_endpoints_enumerate_and_meta_without_loading_the_module() {
        // Enumeration and `Meta` are pure host-side metadata: a `WasmModuleSpace` answers
        // both from the cards declared via `with_endpoint`, never touching the transport —
        // so the wasm artifact stays lazy (it loads only on a real `Source`/`Sink`).
        struct NeverTransport;
        #[async_trait]
        impl ModuleSessionTransport for NeverTransport {
            async fn invoke_session(
                &self,
                _invoke: Vec<u8>,
            ) -> std::result::Result<Vec<u8>, String> {
                panic!("transport invoked for a metadata-only operation — module loaded eagerly");
            }
        }

        let space = WasmModuleSpace::new(
            ["urn:jsonld:"],
            Arc::new(NeverTransport),
            Description::new("jsonld"),
            ModuleFloor::public(),
        )
        .with_endpoint(
            "urn:jsonld:expand",
            Description::new("urn:jsonld:expand").title("Expand"),
        )
        .with_endpoint(
            "urn:jsonld:compact",
            Description::new("urn:jsonld:compact").title("Compact"),
        );

        // entries() lists exactly the declared IRIs, so the catalog renders their cards.
        let entries = space.entries().expect("declared endpoints enumerate");
        let patterns: Vec<&str> = entries.iter().map(|e| e.pattern.as_str()).collect();
        assert_eq!(patterns, ["urn:jsonld:expand", "urn:jsonld:compact"]);

        // Meta on a declared IRI resolves to that endpoint's own card.
        let scope = Scope::empty();
        let expand = Iri::parse("urn:jsonld:expand").unwrap();
        let Resolution::Hit(resolved) = space.resolve(&Request::new(Verb::Meta, expand), &scope)
        else {
            panic!("a declared IRI should resolve");
        };
        assert_eq!(resolved.endpoint.describe().title, "Expand");

        // An undeclared IRI under the prefix still resolves, with the generic card.
        let flatten = Iri::parse("urn:jsonld:flatten").unwrap();
        let Resolution::Hit(generic) = space.resolve(&Request::new(Verb::Meta, flatten), &scope)
        else {
            panic!("a prefix-matched IRI should resolve");
        };
        assert_eq!(generic.endpoint.describe().id, "jsonld");
    }

    #[test]
    fn a_module_space_with_no_declared_endpoints_does_not_enumerate() {
        // Backward-compatible: a bare prefix space contributes nothing to the catalog.
        struct NeverTransport;
        #[async_trait]
        impl ModuleSessionTransport for NeverTransport {
            async fn invoke_session(
                &self,
                _invoke: Vec<u8>,
            ) -> std::result::Result<Vec<u8>, String> {
                unreachable!()
            }
        }
        let space = WasmModuleSpace::new(
            ["urn:stub:"],
            Arc::new(NeverTransport),
            Description::new("stub"),
            ModuleFloor::public(),
        );
        assert!(space.entries().is_none());
    }

    // --- UdsTransport: the same session, but over a real Unix socket -------------------

    #[cfg(unix)]
    #[test]
    fn a_uds_module_declares_its_rewrite_over_the_socket() {
        // The closest thing in this crate to a Phase-2 transport: the declaration crosses a
        // real socket as a framed `Manifest`, the host installs it, and the same one-identity
        // property holds. Each `invoke` opens its own connection, so the server runs its
        // normal accept loop rather than the single-connection harness below.
        use std::thread;
        use std::time::Duration;

        let path = std::env::temp_dir().join(format!(
            "ikigai-module-uds-alias-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let table = join_table();
        let space = aliasing_module(&table);
        let rewrite = ModuleRewrite::from_table(&table);
        let served = path.clone();
        thread::spawn(move || {
            let _ = crate::uds::serve_declaring(space, rewrite, &served);
        });
        // The listener is bound on another thread; wait for the socket to appear rather
        // than racing it.
        for _ in 0..400 {
            if path.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }

        let transport = Arc::new(crate::uds::UdsTransport::connect(&path));
        let module = block_on(ModuleSpace::connect(
            ["urn:stub:"],
            transport,
            ModuleFloor::public(),
        ))
        .expect("mount the socket-served module");
        assert_eq!(module.rewrite(), &ModuleRewrite::from_table(&table));
        assert_one_identity_across_the_boundary(&kernel_with(module));
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn module_session_round_trips_over_a_unix_socket() {
        use std::os::unix::net::UnixListener;
        use std::thread;

        let path =
            std::env::temp_dir().join(format!("ikigai-module-uds-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);

        // Module server: the stub space, served on one accepted connection on its own thread.
        let listener = UnixListener::bind(&path).unwrap();
        let space: Arc<dyn Space> = Arc::new(stub_module());
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            crate::uds::serve_connection(space, ModuleRewrite::None, stream);
        });

        // Host kernel: urn:stub:* routed to the module over the socket; the two refs it
        // pulls back live only on the host.
        let host_space = EndpointSpace::new()
            .bind(
                Exact::new("urn:test:greeting"),
                fixed("greeting", "text/plain", "hello, "),
            )
            .bind(
                Exact::new("urn:test:subject"),
                fixed("subject", "text/plain", "module"),
            );
        let module = ModuleSpace::new(
            ["urn:stub:"],
            Arc::new(crate::uds::UdsTransport::connect(&path)),
            ModuleFloor::public(),
        );
        let root: Arc<dyn Space> = Arc::new(Fallback::new(vec![
            Arc::new(host_space) as Arc<dyn Space>,
            Arc::new(module) as Arc<dyn Space>,
        ]));
        let kernel = Kernel::with_meta_renderer(root, Arc::new(PlainRenderer));

        // A correct result means Invoke + two HostCalls + two HostResults + Resolved all
        // crossed the socket as framed postcard messages, and the module's `inv.source`
        // calls resolved back on the host kernel.
        let rep =
            block_on(kernel.issue(concat_request(), &Capability::root())).expect("uds invoke");
        assert_eq!(String::from_utf8(rep.bytes).unwrap(), "hello, module");
        // Cached host-side via the callbacks' provenance, exactly as the other transports.
        assert!(kernel.is_cached(&concat_request(), &Capability::root()));

        // The transport closed its connection after the session, so the server's read hits
        // EOF and the handler returns.
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn a_self_connection_reports_our_own_uid() {
        // The peercred guard `serve` applies: a peer connecting from this same process
        // reads back as our own UID, so it's admitted (and a different user would not be).
        use std::os::unix::net::{UnixListener, UnixStream};
        let path =
            std::env::temp_dir().join(format!("ikigai-module-uid-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let client = UnixStream::connect(&path).unwrap();
        let (server_side, _) = listener.accept().unwrap();
        assert_eq!(
            crate::uds::peer_uid(&server_side),
            Some(crate::uds::own_uid())
        );
        drop(client);
        let _ = std::fs::remove_file(&path);
    }

    // --- ★ A module composing a REWRITING space -----------------------------------------
    //
    // The acceptance property: an `Alias` installed inside the module's own space gives
    // the logical and the backing name ONE cache entry and ONE golden thread on the host,
    // the same property core proved for an alias nested under a local overlay. Proved over
    // the in-process transport AND the loopback, because only the second shows the
    // declaration surviving the codec.

    // The module's table: `urn:stub:join` is the logical name, `urn:stub:concat` the
    // backing one. Built once and shared between the module's `Alias` and the declaration
    // handed to the transport — the pairing that keeps the two from drifting.
    fn join_table() -> Arc<AliasTable> {
        Arc::new(
            AliasTable::new()
                .exact("urn:stub:join", "urn:stub:concat")
                .exact("urn:stub:me", "urn:stub:whoami"),
        )
    }

    /// The stub module's space with that alias composed into it.
    fn aliasing_module(table: &Arc<AliasTable>) -> Arc<dyn Space> {
        Arc::new(Alias::new(Arc::clone(table), Arc::new(stub_module())))
    }

    /// The same request as `concat_request`, under the module's LOGICAL name.
    fn join_request() -> Request {
        Request::new(Verb::Source, Iri::parse("urn:stub:join").unwrap())
            .with_arg("a", ArgRef::Inline(b"urn:test:greeting".to_vec()))
            .with_arg("b", ArgRef::Inline(b"urn:test:subject".to_vec()))
    }

    /// `urn:stub:whoami` under its logical name.
    fn me_request() -> Request {
        Request::new(Verb::Source, Iri::parse("urn:stub:me").unwrap())
    }

    /// A host kernel with the two callback resources plus `module` in its root.
    fn kernel_with(module: ModuleSpace) -> Kernel {
        let host_space = EndpointSpace::new()
            .bind(
                Exact::new("urn:test:greeting"),
                fixed("greeting", "text/plain", "hello, "),
            )
            .bind(
                Exact::new("urn:test:subject"),
                fixed("subject", "text/plain", "module"),
            );
        let root: Arc<dyn Space> = Arc::new(Fallback::new(vec![
            Arc::new(host_space) as Arc<dyn Space>,
            Arc::new(module) as Arc<dyn Space>,
        ]));
        Kernel::with_meta_renderer(root, Arc::new(PlainRenderer))
    }

    /// Mount a module that aliases, declaring the table it aliases through.
    fn declared_module(transport: Arc<dyn ModuleTransport>) -> ModuleSpace {
        block_on(ModuleSpace::connect(
            ["urn:stub:"],
            transport,
            ModuleFloor::public(),
        ))
        .expect("connect to the module")
    }

    /// The acceptance assertions, run against whichever transport carried the declaration.
    fn assert_one_identity_across_the_boundary(kernel: &Kernel) {
        let cap = Capability::root();

        // The module's endpoint runs under the BACKING name. The host canonicalized from
        // the module's own declaration before it resolved, so the `Request` that crossed
        // the boundary names the resource actually reached — which is what makes the
        // module's own `Alias` a no-op on the way in, and what the kernel's `Meta`,
        // capability floor and trace all agree on.
        let who = block_on(kernel.issue(me_request(), &cap)).expect("aliased whoami");
        assert_eq!(String::from_utf8(who.bytes).unwrap(), "urn:stub:whoami");

        // Issue under the LOGICAL name: it works, and it is filed under the BACKING one,
        // because `ModuleSpace` reported the canonical and the kernel adopted it before it
        // computed the request id.
        let rep = block_on(kernel.issue(join_request(), &cap)).expect("aliased module invoke");
        assert_eq!(String::from_utf8(rep.bytes).unwrap(), "hello, module");
        assert!(
            kernel.is_cached(&concat_request(), &cap),
            "the logical name's result is cached under the BACKING name"
        );
        let entries = kernel.cache_len();

        // ONE cache entry: issuing under the backing name serves that same entry instead
        // of making a second. (Before the declaration crossed the boundary this was two
        // entries over one resource, and nothing anywhere said so.)
        let again = block_on(kernel.issue(concat_request(), &cap)).expect("backing-name invoke");
        assert_eq!(String::from_utf8(again.bytes).unwrap(), "hello, module");
        assert_eq!(
            kernel.cache_len(),
            entries,
            "the backing name must not create a second entry"
        );

        // ONE golden thread: because there is one entry, there is one thread set — the
        // provenance of the resolution that filled it. Cutting a dependency reaches what
        // was cached through either name.
        kernel.cut("urn:test:greeting");
        assert!(
            !kernel.is_cached(&concat_request(), &cap),
            "a cut reaches the single entry both names index"
        );
    }

    #[test]
    fn an_alias_inside_a_module_shares_one_identity_in_process() {
        let table = join_table();
        let transport = Arc::new(
            InProcessTransport::from_arc(aliasing_module(&table))
                .declaring(ModuleRewrite::from_table(&table)),
        );
        assert_one_identity_across_the_boundary(&kernel_with(declared_module(transport)));
    }

    #[test]
    fn an_alias_inside_a_module_shares_one_identity_over_the_codec() {
        // Same property, but the declaration reached the host as postcard bytes over the
        // loopback's `Manifest` exchange — which is what a socket or wasm transport does.
        let table = join_table();
        let transport = Arc::new(
            LoopbackTransport::from_arc(aliasing_module(&table))
                .declaring(ModuleRewrite::from_table(&table)),
        );
        assert_one_identity_across_the_boundary(&kernel_with(declared_module(transport)));
    }

    #[test]
    fn a_thread_the_module_declares_names_the_backing_resource() {
        // The stronger form of "one golden thread", and the one an operator actually
        // relies on: the thread the module's endpoint DECLARED is the backing name, so a
        // cut naming the backing resource invalidates what the logical name cached.
        //
        // In-process AND through the codec. `Representation::threads` is `serde(skip)`, so
        // through 0.2 a wire transport dropped the module's own declared threads and this
        // held in-process only; `ModuleReply::ResolvedThreaded` carries them now.
        let table = join_table();
        let transports: [Arc<dyn ModuleTransport>; 2] = [
            Arc::new(
                InProcessTransport::from_arc(aliasing_module(&table))
                    .declaring(ModuleRewrite::from_table(&table)),
            ),
            Arc::new(
                LoopbackTransport::from_arc(aliasing_module(&table))
                    .declaring(ModuleRewrite::from_table(&table)),
            ),
        ];
        for transport in transports {
            let kernel = kernel_with(declared_module(transport));
            let cap = Capability::root();
            block_on(kernel.issue(join_request(), &cap)).expect("aliased module invoke");
            assert!(kernel.is_cached(&concat_request(), &cap));

            // The logical name is NOT the thread — nothing was ever filed under it.
            kernel.cut("urn:stub:join");
            assert!(
                kernel.is_cached(&concat_request(), &cap),
                "cutting the logical name touches nothing: the resource is the backing one"
            );
            kernel.cut("urn:stub:concat");
            assert!(
                !kernel.is_cached(&concat_request(), &cap),
                "the module declared its thread under the backing name"
            );
        }
    }

    #[test]
    fn the_declaration_survives_the_codec() {
        // The narrow claim the test above depends on: `ModuleRewrite` round-trips through
        // postcard as part of a real `Manifest`/`Manifest` exchange, and parses back into
        // the table it was built from.
        let table = join_table();
        let transport = LoopbackTransport::from_arc(aliasing_module(&table))
            .declaring(ModuleRewrite::from_table(&table));
        let manifest = block_on(transport.manifest()).expect("manifest over the codec");
        assert_eq!(manifest.rewrite, ModuleRewrite::from_table(&table));
        let parsed = manifest
            .rewrite
            .table()
            .expect("the declared table parses")
            .expect("a table was declared");
        assert_eq!(parsed.rules().len(), 2);
        assert_eq!(
            parsed
                .canonicalize(&Iri::parse("urn:stub:join").unwrap())
                .canonical()
                .map(Iri::as_str),
            Some("urn:stub:concat"),
        );
        // And the bindings still ride along, so a host mounting a module asks once.
        assert_eq!(
            manifest.entries.as_deref(),
            Some(
                &[
                    SpaceEntry::new("urn:stub:concat", "stub-concat"),
                    SpaceEntry::new("urn:stub:whoami", "stub-whoami"),
                ][..]
            ),
        );
    }

    // --- ★ The signal: an undeclared or undeclarable rewrite is never silent -------------

    /// Mount an aliasing module WITHOUT telling the host, and try the logical name.
    fn undeclared_error(transport: Arc<dyn ModuleTransport>) -> String {
        let kernel = kernel_with(ModuleSpace::new(
            ["urn:stub:"],
            transport,
            ModuleFloor::public(),
        ));
        let err = block_on(kernel.issue(join_request(), &Capability::root()))
            .expect_err("an undeclared rewrite must not be served");
        assert!(
            !kernel.is_cached(&concat_request(), &Capability::root()),
            "a refused invocation caches nothing under either name"
        );
        err.to_string()
    }

    #[test]
    fn an_undeclared_rewrite_is_refused_rather_than_split_in_two() {
        // `ModuleSpace::new` never asked, so the host holds `Unknown` and resolves under
        // the name it was given. The module then resolves under a DIFFERENT name and says
        // so on `Resolved::canonical` — which the host can no longer act on, its cache key
        // and thread already fixed. The module side refuses, naming both names, instead of
        // returning a right-looking answer filed under the wrong one.
        let table = join_table();
        for message in [
            undeclared_error(Arc::new(InProcessTransport::from_arc(aliasing_module(
                &table,
            )))),
            undeclared_error(Arc::new(LoopbackTransport::from_arc(aliasing_module(
                &table,
            )))),
        ] {
            assert!(message.contains("urn:stub:join"), "{message}");
            assert!(message.contains("urn:stub:concat"), "{message}");
            assert!(message.contains("never declared"), "{message}");
        }
    }

    #[test]
    fn declaring_none_is_a_claim_and_a_module_that_breaks_it_is_refused() {
        // `None` is not "say nothing" — it is "I resolve every target under the name you
        // gave me". A module that then rewrites has broken its own declaration, and the
        // guard says so exactly as it does for `Unknown`.
        let table = join_table();
        let transport = Arc::new(
            InProcessTransport::from_arc(aliasing_module(&table)).declaring(ModuleRewrite::None),
        );
        let module = declared_module(transport);
        assert_eq!(module.rewrite(), &ModuleRewrite::None);
        let kernel = kernel_with(module);
        let err = block_on(kernel.issue(join_request(), &Capability::root()))
            .expect_err("a broken `None` declaration must be refused");
        assert!(err.to_string().contains("never declared"), "{err}");
    }

    /// A module that rewrites through an arbitrary closure — the shape that provably
    /// cannot be written down as a table, and so must be declared `Undeclarable`.
    fn undeclarable_module() -> Arc<dyn Space> {
        Arc::new(Rewrite::new(Arc::new(stub_module()), |iri| {
            (iri.as_str() == "urn:stub:join").then(|| Iri::parse("urn:stub:concat").unwrap())
        }))
    }

    #[test]
    fn an_undeclarable_rewrite_is_refused_by_default() {
        let transport = Arc::new(
            InProcessTransport::from_arc(undeclarable_module()).declaring(
                ModuleRewrite::Undeclarable("rewrites through a host-supplied closure".to_string()),
            ),
        );
        let kernel = kernel_with(declared_module(transport));
        let err = block_on(kernel.issue(join_request(), &Capability::root()))
            .expect_err("an undeclarable rewrite is refused by default");
        let message = err.to_string();
        assert!(message.contains("cannot declare"), "{message}");
        assert!(message.contains("host-supplied closure"), "{message}");
    }

    #[test]
    fn an_undeclarable_rewrite_can_be_accepted_out_loud() {
        // The other legitimate answer: accept the split, but say so. The host supplies a
        // sink and gets one line per affected resolution — the difference between an
        // operator who knows identity is split here and 0.1.9, where nobody did.
        let warnings: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&warnings);
        let transport = Arc::new(
            InProcessTransport::from_arc(undeclarable_module()).declaring(
                ModuleRewrite::Undeclarable("rewrites through a host-supplied closure".to_string()),
            ),
        );
        let module = declared_module(transport).on_undeclarable(OnUndeclarable::Warn(Arc::new(
            move |message: &str| sink.lock().unwrap().push(message.to_string()),
        )));
        let kernel = kernel_with(module);
        let rep = block_on(kernel.issue(join_request(), &Capability::root()))
            .expect("accepted, so it resolves");
        assert_eq!(String::from_utf8(rep.bytes).unwrap(), "hello, module");
        let warnings = warnings.lock().unwrap();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("cannot declare"), "{warnings:?}");
        // And the split it warned about is real: the answer is filed under the LOGICAL
        // name, because that is the only name the host ever knew.
        assert!(kernel.is_cached(&join_request(), &Capability::root()));
        assert!(!kernel.is_cached(&concat_request(), &Capability::root()));
    }

    // --- Mount-time validation: a declaration is checked where an operator is watching ---

    #[test]
    fn a_rewrite_pointing_outside_the_modules_prefixes_is_refused_at_mount_time() {
        // The rewrite the host installs decides the kernel's IDENTITY for the request, so
        // a rule pointing outside the namespace the host routed to this module is a claim
        // on a name the module was never given.
        let transport = Arc::new(InProcessTransport::new(stub_module()));
        let err = ModuleSpace::new(["urn:stub:"], transport, ModuleFloor::public())
            .declaring(ModuleRewrite::Table(
                "exact urn:stub:join urn:test:greeting\n".to_string(),
            ))
            .map(|_| ())
            .expect_err("a rule leaving the module's namespace must not mount");
        assert!(err.to_string().contains("outside the prefixes"), "{err}");
    }

    #[test]
    fn a_rewrite_naming_the_kernel_namespace_is_refused_at_mount_time() {
        let transport = Arc::new(InProcessTransport::new(stub_module()));
        let err = ModuleSpace::new(
            ["urn:stub:", "urn:kernel:"],
            transport,
            ModuleFloor::public(),
        )
        .declaring(ModuleRewrite::Table(
            "exact urn:stub:join urn:kernel:cut\n".to_string(),
        ))
        .map(|_| ())
        .expect_err("the reserved namespace is not aliasable");
        assert!(
            err.to_string().contains("reserved kernel namespace"),
            "{err}"
        );
    }

    #[test]
    fn an_unparseable_declared_table_is_refused_at_mount_time() {
        let transport = Arc::new(InProcessTransport::new(stub_module()));
        let err = ModuleSpace::new(["urn:stub:"], transport, ModuleFloor::public())
            .declaring(ModuleRewrite::Table("wobble urn:stub:join\n".to_string()))
            .map(|_| ())
            .expect_err("a malformed table fails when it is read");
        assert!(err.to_string().contains("unparseable"), "{err}");
    }

    // --- Wire compatibility with 0.1.9 --------------------------------------------------

    #[test]
    fn the_0_1_9_message_bytes_are_unchanged() {
        // postcard keys an enum on its variant INDEX, so the whole compatibility claim is
        // "the new variants were appended". Pinned here because nothing else would notice
        // a variant inserted in the middle — it would just start decoding as another
        // message.
        assert_eq!(encode(&ModuleCall::Describe).unwrap(), vec![2]);
        assert_eq!(encode(&ModuleCall::Manifest).unwrap(), vec![3]);
        // 0.3 appended, in this order: `HostError` = 4 and `Cards` = 5 on the call side;
        // `ErrorTyped` = 5, `ResolvedThreaded` = 6 and `Cards` = 7 on the reply side. And
        // `ModuleError`'s variants sit where `WireError`'s do (`Denied` = 4).
        assert_eq!(
            encode(&ModuleCall::HostError(ModuleError::Denied("x".into()))).unwrap()[..2],
            [4, 4]
        );
        assert_eq!(encode(&ModuleCall::Cards).unwrap(), vec![5]);
        assert_eq!(
            encode(&ModuleReply::ErrorTyped(ModuleError::Denied("x".into()))).unwrap()[..2],
            [5, 4]
        );
        let empty = Representation::new(ReprType::new("text/plain"), Vec::new());
        assert_eq!(
            encode(&ModuleReply::ResolvedThreaded {
                representation: empty,
                threads: Vec::new(),
            })
            .unwrap()[0],
            6
        );
        assert_eq!(encode(&ModuleReply::Cards(Vec::new())).unwrap(), vec![7, 0]);
        assert_eq!(encode(&ModuleReply::Bindings(None)).unwrap(), vec![3, 0]);
        assert_eq!(
            encode(&ModuleReply::Manifest(ModuleManifest::unknown(None)))
                .unwrap()
                .first(),
            Some(&4),
        );
        // And from the other direction: bytes a 0.1.9 peer would have written still decode
        // to the message they meant.
        assert!(matches!(
            decode::<ModuleCall>(&[2]).unwrap(),
            ModuleCall::Describe
        ));
        assert!(matches!(
            decode::<ModuleReply>(&[3, 0]).unwrap(),
            ModuleReply::Bindings(None)
        ));
    }

    #[test]
    fn card_survives_the_codec() {
        // `Description` derives serde for JSON — `skip_serializing_if` on its optional
        // fields — and postcard is not self-describing, so a card cannot ride the frame as
        // a struct: a skipped field reads as "end of buffer" on the way back. It crosses as
        // JSON text inside the frame instead, and comes back whole: typed inputs, a default,
        // per-verb actions, `requires`, a template entry.
        let card = ModuleCard {
            entry: SpaceEntry::new("urn:demo:thing:{id}", "thing"),
            description: Description::new("thing")
                .title("A thing")
                .input(ArgSpec::new("id").binding().class(XSD_STRING))
                .action(
                    ActionSpec::new(Verb::Source)
                        .input(
                            ArgSpec::new("as")
                                .one_of(["text/plain", "text/turtle"])
                                .default_value("text/plain"),
                        )
                        .output("text/plain")
                        .output("text/turtle"),
                )
                .action(
                    ActionSpec::new(Verb::Sink)
                        .input(ArgSpec::new("content").class(XSD_STRING))
                        .requires("urn:cap:demo:write"),
                ),
        };
        let bytes = encode(&ModuleReply::Cards(vec![card.clone()])).unwrap();
        match decode::<ModuleReply>(&bytes).unwrap() {
            ModuleReply::Cards(cards) => assert_eq!(cards, [card]),
            other => panic!("expected Cards, got {other:?}"),
        }
    }

    #[test]
    fn connect_installs_the_modules_cards_through_the_codec() {
        // The module's own `describe()` reaches the kernel through a `connect`ed mount —
        // over the loopback, so the cards crossed as bytes — for an exact and for a template
        // binding, and the catalog lists what the module binds. `new` asks nothing and
        // answers the generic card.
        let module: Arc<dyn Space> = Arc::new(
            gated_module().bind(
                UriTemplate::parse("urn:stub:echo:{word}").unwrap(),
                FnEndpoint::new("stub-echo", |inv: &Invocation<'_>| {
                    Ok(Representation::new(
                        ReprType::new("text/plain"),
                        inv.bindings.get("word").unwrap_or("").as_bytes().to_vec(),
                    ))
                })
                .with_description(
                    Description::new("stub-echo")
                        .verb(Verb::Source)
                        .input(ArgSpec::new("word").binding().class(XSD_STRING)),
                ),
            ),
        );
        let asked = block_on(ModuleSpace::connect(
            ["urn:stub:"],
            Arc::new(LoopbackTransport::from_arc(Arc::clone(&module))),
            ModuleFloor::public(),
        ))
        .unwrap();
        let kernel = kernel_over(asked);
        assert_eq!(
            kernel.describe_pattern("urn:stub:greet").unwrap(),
            GreetEndpoint.describe(),
            "an exact binding's card is the module's"
        );
        let echo = kernel.describe_pattern("urn:stub:echo:{word}").unwrap();
        assert_eq!(
            echo.id, "stub-echo",
            "a template binding's card is found by matching"
        );
        assert_eq!(
            kernel
                .entries()
                .unwrap()
                .iter()
                .filter(|e| e.pattern.starts_with("urn:stub:"))
                .map(|e| e.pattern.as_str())
                .collect::<Vec<_>>(),
            ["urn:stub:greet", "urn:stub:echo:{word}"]
        );
        // And the kernel enforces what the card declares, host-side, before the wire.
        let denial =
            block_on(kernel.issue(greet_request(), &Capability::scoped([READ]))).unwrap_err();
        assert!(matches!(denial, Error::Denied(_)), "{denial:?}");

        let unasked = kernel_over(ModuleSpace::new(
            ["urn:stub:"],
            Arc::new(LoopbackTransport::from_arc(module)),
            ModuleFloor::public(),
        ));
        assert_eq!(
            unasked.describe_pattern("urn:stub:greet").unwrap().id,
            "module"
        );
    }

    #[test]
    fn a_transport_that_cannot_answer_reports_unknown_not_none() {
        // The default `manifest()` — what a third-party transport and every 0.1.9 peer
        // gives. `Unknown` is the absence of a claim; reading it as `None` ("does not
        // rewrite") is precisely the silent split this arc removes.
        struct BareTransport;

        #[async_trait]
        impl ModuleTransport for BareTransport {
            async fn invoke(
                &self,
                _request: Request,
                _capability: &Capability,
                _host: &dyn Issuer,
            ) -> Result<Representation> {
                unreachable!()
            }
        }

        let manifest = block_on(BareTransport.manifest()).unwrap();
        assert_eq!(manifest.rewrite, ModuleRewrite::Unknown);
        assert!(!manifest.rewrite.is_declared());
        let module = block_on(ModuleSpace::connect(
            ["urn:stub:"],
            Arc::new(BareTransport),
            ModuleFloor::public(),
        ))
        .expect("mounting an unasked module still works");
        assert_eq!(module.rewrite(), &ModuleRewrite::Unknown);
    }

    // -----------------------------------------------------------------------------------
    // Capability enforcement across the module boundary.
    //
    // The defect these pin: an endpoint declaring `.requires("urn:cap:demo:greet")`, reached
    // through a `ModuleSpace`, used to RESOLVE under a capability granting only
    // `urn:cap:demo:read` — while the identical declaration on a *linked* endpoint was
    // correctly denied. Two halves to the fix, and both are tested here:
    //
    //   * the mount's `ModuleFloor` — the HOST's authority declaration, which is the
    //     authoritative gate precisely because the module cannot lower it; and
    //   * the module honoring its OWN card, which can only ever deny more.
    //
    // The pair matters: without the positive case a test suite passes by denying
    // everything, and without the floor a module declaring nothing would be ungated.
    // -----------------------------------------------------------------------------------

    const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

    /// The scope the gated stub declares, and one that is not it.
    const GREET: &str = "urn:cap:demo:greet";
    const READ: &str = "urn:cap:demo:read";

    /// A module endpoint that DECLARES an authority requirement and takes no arguments —
    /// the smallest thing that can be resolved identically linked and loaded.
    struct GreetEndpoint;

    #[async_trait]
    impl Endpoint for GreetEndpoint {
        async fn invoke(&self, _inv: &Invocation<'_>) -> Result<Representation> {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                b"greetings".to_vec(),
            ))
        }

        fn name(&self) -> &str {
            "stub-greet"
        }

        fn describe(&self) -> Description {
            Description::new("stub-greet")
                .title("Greet (gated test stub)")
                .verb(Verb::Source)
                .requires(GREET)
                .output("text/plain")
        }
    }

    fn gated_module() -> EndpointSpace {
        EndpointSpace::new().bind(Exact::new("urn:stub:greet"), GreetEndpoint)
    }

    fn greet_request() -> Request {
        Request::new(Verb::Source, Iri::parse("urn:stub:greet").unwrap())
    }

    fn kernel_over(space: impl Space + 'static) -> Kernel {
        Kernel::with_meta_renderer(Arc::new(space) as Arc<dyn Space>, Arc::new(PlainRenderer))
    }

    #[test]
    fn a_module_endpoints_declared_requirement_is_enforced_like_a_linked_ones() {
        // THE REPRODUCTION. Same endpoint, same declaration, same capability — once bound
        // straight into the host's space, once reached only through a module mount. The two
        // paths must agree, in both directions.
        let linked = kernel_over(gated_module());
        let loaded = kernel_over(ModuleSpace::new(
            ["urn:stub:"],
            Arc::new(InProcessTransport::new(gated_module())),
            // Deliberately `public()`: this isolates the module's own declaration. The
            // mount adds nothing, so anything that denies here is the module honoring its
            // card — which is what used to be ignored entirely.
            ModuleFloor::public(),
        ));

        let wrong = Capability::scoped([READ]);
        let linked_denial = block_on(linked.issue(greet_request(), &wrong))
            .expect_err("a linked endpoint's declaration is enforced by the kernel");
        let loaded_denial = block_on(loaded.issue(greet_request(), &wrong))
            .expect_err("a module endpoint's declaration must be enforced too");
        assert!(
            matches!(linked_denial, Error::Denied(_)),
            "{linked_denial:?}"
        );
        assert!(
            matches!(loaded_denial, Error::Denied(_)),
            "{loaded_denial:?}"
        );
        assert!(loaded_denial.to_string().contains(GREET), "{loaded_denial}");

        // The other direction, or the suite would pass by denying everything.
        let right = Capability::scoped([GREET]);
        assert_eq!(
            block_on(linked.issue(greet_request(), &right))
                .expect("granted, linked")
                .bytes,
            b"greetings".to_vec()
        );
        assert_eq!(
            block_on(loaded.issue(greet_request(), &right))
                .expect("granted, loaded")
                .bytes,
            b"greetings".to_vec()
        );
    }

    #[test]
    fn the_serialized_session_enforces_the_declaration_too() {
        // Through the codec, so the guard is not an artifact of the direct-call transport —
        // and through `ModuleSpace::new`, so no card reaches the kernel and the refusal is
        // the MODULE side's, crossing the wire. Through 0.2 it arrived as `Error::Endpoint`
        // (`ModuleReply::Error` carried a string); `ModuleReply::ErrorTyped` keeps it a
        // permanent `Denied`.
        let kernel = kernel_over(ModuleSpace::new(
            ["urn:stub:"],
            Arc::new(LoopbackTransport::new(gated_module())),
            ModuleFloor::public(),
        ));
        let denial = block_on(kernel.issue(greet_request(), &Capability::scoped([READ])))
            .expect_err("the module's declaration is enforced over the session too");
        assert!(matches!(denial, Error::Denied(_)), "{denial:?}");
        assert!(
            !denial.is_transient(),
            "a refusal that crossed the wire is still permanent: {denial:?}"
        );
        assert!(denial.to_string().contains(GREET), "{denial}");
        assert_eq!(
            block_on(kernel.issue(greet_request(), &Capability::scoped([GREET])))
                .expect("granted, over the session")
                .bytes,
            b"greetings".to_vec()
        );
    }

    #[test]
    fn a_module_that_declares_nothing_does_not_thereby_become_ungated() {
        // ★ The trust direction. `stub_module`'s `urn:stub:whoami` declares no requirement
        // at all — under the old code that meant "ungated", which made UNDER-DECLARING the
        // escape hatch. The mount's floor is the host's word, and the module has no way to
        // lower it.
        const MOUNT: &str = "urn:cap:module:stub";
        let kernel = kernel_over(ModuleSpace::new(
            ["urn:stub:"],
            Arc::new(InProcessTransport::new(stub_module())),
            ModuleFloor::requiring(MOUNT),
        ));
        let whoami = || Request::new(Verb::Source, Iri::parse("urn:stub:whoami").unwrap());

        let denial = block_on(kernel.issue(whoami(), &Capability::scoped([READ])))
            .expect_err("the mount's floor gates an endpoint that declares nothing");
        assert!(matches!(denial, Error::Denied(_)), "{denial:?}");
        assert!(denial.to_string().contains(MOUNT), "{denial}");
        // The denial has to say what to add — it is not guessable from a refusal.
        assert!(
            denial.to_string().contains("ModuleFloor::requiring"),
            "{denial}"
        );

        assert!(block_on(kernel.issue(whoami(), &Capability::scoped([MOUNT]))).is_ok());
    }

    #[test]
    fn an_iri_with_no_host_card_is_gated_exactly_as_one_with() {
        // `card_for`'s fallback was the hole: an IRI the host never enumerated took the
        // generic prefix card, which carried no `requires`, so *forgetting* a card bought
        // LESS gating than declaring one. The floor applies to both arms now.
        const MOUNT: &str = "urn:cap:module:stub";
        let kernel = kernel_over(
            ModuleSpace::new(
                ["urn:stub:"],
                Arc::new(InProcessTransport::new(stub_module())),
                ModuleFloor::requiring(MOUNT),
            )
            // Declared: this one has a card. `urn:stub:whoami` deliberately does not.
            .with_endpoint(
                "urn:stub:concat",
                Description::new("stub-concat").verb(Verb::Source),
            ),
        );
        let unrelated = Capability::scoped([READ]);
        for target in ["urn:stub:concat", "urn:stub:whoami"] {
            let request = Request::new(Verb::Source, Iri::parse(target).unwrap());
            let denial = block_on(kernel.issue(request, &unrelated))
                .expect_err("every IRI under the mount is gated by the floor")
                .to_string();
            assert!(denial.contains(MOUNT), "{target}: {denial}");
        }
    }

    #[test]
    fn the_floor_rides_in_the_card_the_kernel_enforces() {
        // The manifold's half of `declared = enforced`: what a catalog offers under this
        // mount is what the mount admits. Folded into the flat `requires` AND into an
        // explicitly declared action, since an explicit action wins for its verb and would
        // otherwise advertise a smaller requirement than the mount enforces.
        const MOUNT: &str = "urn:cap:module:stub";
        let space = ModuleSpace::new(
            ["urn:stub:"],
            Arc::new(InProcessTransport::new(stub_module())),
            ModuleFloor::requiring(MOUNT),
        )
        .with_endpoint(
            "urn:stub:concat",
            Description::new("stub-concat")
                .verb(Verb::Source)
                // A card may only ADD to the floor.
                .requires(READ)
                .action(ActionSpec::new(Verb::Sink).requires(GREET)),
        );

        let card = card_of(&space, "urn:stub:concat");
        assert!(card.requires.contains(&MOUNT.to_string()), "{card:?}");
        assert!(card.requires.contains(&READ.to_string()), "{card:?}");
        let sink = card
            .action_specs()
            .into_iter()
            .find(|a| a.verb == Verb::Sink)
            .expect("the declared Sink action");
        assert!(sink.requires.contains(&MOUNT.to_string()), "{sink:?}");
        assert!(sink.requires.contains(&GREET.to_string()), "{sink:?}");

        // …and the undeclared IRI's fallback card carries the floor too.
        let fallback = card_of(&space, "urn:stub:whoami");
        assert_eq!(fallback.requires, vec![MOUNT.to_string()]);
    }

    /// The card a space hands the kernel for `target` (what `unsatisfied_scope` reads).
    fn card_of(space: &dyn Space, target: &str) -> Description {
        let request = Request::new(Verb::Source, Iri::parse(target).unwrap());
        let Resolution::Hit(resolved) = space.resolve(&request, &Scope::empty()) else {
            panic!("{target} should resolve under the mount");
        };
        resolved.endpoint.describe()
    }

    #[test]
    fn meta_stays_readable_under_a_floor_the_caller_cannot_clear() {
        // Core exempts `Meta` by construction (`action_specs()` carries no Meta spec) and the
        // kernel renders `describe()` without invoking, so the floor's invoke-time check
        // never sees a Meta request either. Self-description stays readable wherever the
        // catalog offers it — pinned, because a floor that hid the manifold would make the
        // system unnavigable exactly when an agent needs to learn what it may ask for.
        let kernel = kernel_over(ModuleSpace::new(
            ["urn:stub:"],
            Arc::new(InProcessTransport::new(stub_module())),
            ModuleFloor::requiring("urn:cap:module:stub"),
        ));
        let meta = Request::new(Verb::Meta, Iri::parse("urn:stub:whoami").unwrap());
        assert!(block_on(kernel.issue(meta, &Capability::scoped([READ]))).is_ok());
    }

    #[test]
    fn a_wasm_mounts_generic_card_is_gated_as_well() {
        // The same fallback, on the browser space. Its generic card is host-supplied, so it
        // LOOKS authored — but a prefix mount serves an open IRI set and only the floor
        // reaches the ones nobody enumerated.
        struct NeverTransport;
        #[async_trait]
        impl ModuleSessionTransport for NeverTransport {
            async fn invoke_session(
                &self,
                _invoke: Vec<u8>,
            ) -> std::result::Result<Vec<u8>, String> {
                panic!("the floor must refuse before anything crosses the boundary");
            }
        }
        const MOUNT: &str = "urn:cap:xslt";
        let kernel = kernel_over(WasmModuleSpace::new(
            ["urn:xslt:"],
            Arc::new(NeverTransport),
            Description::new("xslt").verb(Verb::Source),
            ModuleFloor::requiring(MOUNT),
        ));
        let request = Request::new(Verb::Source, Iri::parse("urn:xslt:anything").unwrap());
        let denial = block_on(kernel.issue(request, &Capability::scoped([READ])))
            .expect_err("the floor gates an un-enumerated IRI under the prefix");
        assert!(matches!(denial, Error::Denied(_)), "{denial:?}");
        assert!(denial.to_string().contains(MOUNT), "{denial}");
    }

    #[test]
    fn capability_scopes_match_the_kernels_predicate() {
        // `cap_satisfies` is a restatement of core's `pub(crate)` predicate; if the two ever
        // disagree, the manifold offers what the mount refuses (or worse, the reverse).
        // Root, exact, wildcard-held, wildcard-not-held — the four cases core's has.
        assert!(cap_satisfies(&Capability::root(), "urn:cap:anything"));
        assert!(cap_satisfies(&Capability::root(), "urn:cap:net:*"));
        let held = Capability::scoped(["urn:cap:net:example.com"]);
        assert!(cap_satisfies(&held, "urn:cap:net:*"));
        assert!(cap_satisfies(&held, "urn:cap:net:example.com"));
        assert!(!cap_satisfies(&held, "urn:cap:net:other.com"));
        assert!(!cap_satisfies(&held, "urn:cap:fs:*"));
    }

    #[test]
    fn a_public_floor_is_a_sentence_the_host_writes_not_one_it_omits() {
        // The ungated mount still exists — some modules genuinely need no authority — but it
        // is now `ModuleFloor::public()`, by value, at every mount constructor. There is no
        // `Default`, so it cannot be reached by forgetting.
        assert!(ModuleFloor::public().scopes().is_empty());
        assert!(ModuleFloor::public()
            .unsatisfied(&Capability::scoped([READ]))
            .is_none());
        let floor = ModuleFloor::requiring("urn:cap:a").and("urn:cap:b");
        assert_eq!(
            floor.unsatisfied(&Capability::scoped(["urn:cap:a"])),
            Some("urn:cap:b")
        );
        assert_eq!(floor.unsatisfied(&Capability::root()), None);
    }
}
