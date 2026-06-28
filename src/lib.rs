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
//! See `ikigai-cli/docs/module-format-design.md`.

// `deny`, not `forbid`, so the UDS server's peercred check (and only it) can opt into the
// `libc` FFI it needs via a scoped `#[allow(unsafe_code)]`; everything else stays unsafe-free.
#![deny(unsafe_code)]

use async_trait::async_trait;
use futures::channel::mpsc;
use futures::lock::Mutex as AsyncMutex;
use futures::StreamExt;
use ikigai_core::{
    Bindings, Capability, Description, Endpoint, Error, Expiry, Invocation, Issuer, Representation,
    Request, Resolution, Resolved, Result, Scope, Space, SpaceEntry, Thread,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
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
    /// The host's answer to a [`ModuleReply::HostCall`] the module made.
    HostResult(std::result::Result<Representation, String>),
    /// Ask for the module's bound entries (for `entries()` / the catalog).
    Describe,
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
    /// The invocation finished with a representation.
    Resolved(Representation),
    /// The invocation failed.
    Error(String),
    /// The answer to a [`ModuleCall::Describe`].
    Bindings(Option<Vec<SpaceEntry>>),
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
}

/// **Phase 1.** The module runs in the same process; "transport" is a direct call. The
/// module's endpoint runs with the **host** as its issuer, so its `inv.source`/
/// `inv.issue` resolve back through the host kernel (its cache, its other spaces) —
/// proving the callback machinery with zero wire risk. A Phase-2 transport swaps in
/// without touching the module's code or [`ModuleSpace`].
pub struct InProcessTransport {
    space: Arc<dyn Space>,
}

impl InProcessTransport {
    /// Wrap a module's `space()` as an in-process transport.
    pub fn new(space: impl Space + 'static) -> Self {
        Self {
            space: Arc::new(space),
        }
    }

    /// Wrap an already-`Arc`'d space.
    pub fn from_arc(space: Arc<dyn Space>) -> Self {
        Self { space }
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
        match self.space.resolve(&request, &Scope::empty()) {
            Resolution::Hit(resolved) => {
                // Run the module's endpoint with the HOST as its issuer: its
                // `inv.source(..)` calls cross back to the host kernel.
                let inv = Invocation::with_issuer(&request, &resolved.bindings, capability, host);
                resolved.endpoint.invoke(&inv).await
            }
            Resolution::Miss => Err(Error::Unresolved(request.target.clone())),
        }
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        self.space.entries()
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
/// in-memory byte channels, serializing every message with [`encode`]/[`decode`]. Same
/// protocol and bytes as a real (socket/wasm) transport, both ends in-process — so it
/// proves the session without any I/O risk.
///
/// Host callbacks are assumed **sequential** (the module awaits each `inv.source` before
/// the next), which matches the pilot (`ikigai-xslt`); concurrent callbacks from one
/// module invocation are an open question (see the design doc).
pub struct LoopbackTransport {
    space: Arc<dyn Space>,
}

impl LoopbackTransport {
    /// Wrap a module's `space()` as a serialized loopback transport.
    pub fn new(space: impl Space + 'static) -> Self {
        Self {
            space: Arc::new(space),
        }
    }

    /// Wrap an already-`Arc`'d space.
    pub fn from_arc(space: Arc<dyn Space>) -> Self {
        Self { space }
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
                        let result = host
                            .issue(request, &clamped)
                            .await
                            .map_err(|e| e.to_string());
                        send(&host_to_module_tx, &ModuleCall::HostResult(result))?;
                    }
                    ModuleReply::Resolved(representation) => return Ok(representation),
                    ModuleReply::Error(message) => return Err(Error::Endpoint(message)),
                    ModuleReply::Bindings(_) => {
                        return Err(Error::Endpoint(
                            "module sent Bindings in reply to Invoke".to_string(),
                        ))
                    }
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
        }) => match space.resolve(&request, &Scope::empty()) {
            Resolution::Hit(resolved) => {
                // The issuer now owns the receiver: after `Invoke`, every inbound message
                // is a `HostResult` answering one of its `HostCall`s.
                let issuer = SessionHostIssuer {
                    to_host: to_host.clone(),
                    from_host: AsyncMutex::new(from_host),
                };
                let inv =
                    Invocation::with_issuer(&request, &resolved.bindings, &capability, &issuer);
                match resolved.endpoint.invoke(&inv).await {
                    Ok(representation) => ModuleReply::Resolved(representation),
                    Err(e) => ModuleReply::Error(e.to_string()),
                }
            }
            Resolution::Miss => ModuleReply::Error(format!(
                "module did not resolve {}",
                request.target.as_str()
            )),
        },
        Ok(ModuleCall::Describe) => ModuleReply::Bindings(space.entries()),
        Ok(ModuleCall::HostResult(_)) => {
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
        match decode::<ModuleCall>(&bytes)? {
            ModuleCall::HostResult(Ok(representation)) => Ok(representation),
            ModuleCall::HostResult(Err(message)) => Err(Error::Endpoint(message)),
            _ => Err(Error::Endpoint(
                "expected HostResult answering a HostCall".to_string(),
            )),
        }
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
    let reply = match decode::<ModuleCall>(invoke) {
        Ok(ModuleCall::Invoke {
            request,
            capability,
        }) => match space.resolve(&request, &Scope::empty()) {
            Resolution::Hit(resolved) => {
                let issuer = ClosureHostIssuer {
                    host_call: &host_call,
                };
                let inv =
                    Invocation::with_issuer(&request, &resolved.bindings, &capability, &issuer);
                match resolved.endpoint.invoke(&inv).await {
                    Ok(representation) => ModuleReply::Resolved(representation),
                    Err(e) => ModuleReply::Error(e.to_string()),
                }
            }
            Resolution::Miss => ModuleReply::Error(format!(
                "module did not resolve {}",
                request.target.as_str()
            )),
        },
        Ok(ModuleCall::Describe) => ModuleReply::Bindings(space.entries()),
        Ok(ModuleCall::HostResult(_)) => {
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
        match decode::<ModuleCall>(&answer)? {
            ModuleCall::HostResult(Ok(representation)) => Ok(representation),
            ModuleCall::HostResult(Err(message)) => Err(Error::Endpoint(message)),
            _ => Err(Error::Endpoint(
                "expected HostResult answering a HostCall".to_string(),
            )),
        }
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
/// in-flight [`WasmModuleSpace`] invocation, and return the encoded `HostResult` (`Ok` or
/// `Err` — either is a decodable answer). The host's global `hostCall` export calls this.
pub async fn serve_host_call<F, Fut>(reply: &[u8], resolve: F) -> Vec<u8>
where
    F: FnOnce(Request, Capability) -> Fut,
    Fut: core::future::Future<Output = std::result::Result<Representation, String>>,
{
    let result = match decode::<ModuleReply>(reply) {
        Ok(ModuleReply::HostCall {
            request,
            capability,
        }) => match resolve(request, capability).await {
            Ok(representation) => {
                DEP_SINKS.with(|sinks| {
                    for (_, sink) in sinks.borrow().iter() {
                        sink.borrow_mut().record(&representation);
                    }
                });
                Ok(representation)
            }
            Err(message) => Err(message),
        },
        Ok(_) => Err("serve_host_call: expected a HostCall".to_string()),
        Err(e) => Err(format!("serve_host_call: undecodable HostCall: {e}")),
    };
    encode(&ModuleCall::HostResult(result)).unwrap_or_default()
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
}

impl WasmModuleSpace {
    /// Route every IRI starting with one of `prefixes` to `transport`; `describe` is the
    /// module endpoint's self-description (for `Meta` / the catalog). With no enumerated
    /// endpoints (see [`with_endpoint`](Self::with_endpoint)) the space does not list in
    /// the catalog — it only resolves by prefix.
    pub fn new(
        prefixes: impl IntoIterator<Item = impl Into<String>>,
        transport: Arc<dyn ModuleSessionTransport>,
        describe: Description,
    ) -> Self {
        Self {
            prefixes: prefixes.into_iter().map(Into::into).collect(),
            transport,
            describe,
            endpoints: Vec::new(),
        }
    }

    /// Declare a concrete endpoint IRI and its self-description so it **enumerates into the
    /// catalog** and answers `Meta` with its own card — without loading the module. The
    /// host supplies these as static data (a tiny manifest); the catalog reads only
    /// `entries()` + `describe()` (pure metadata), so the wasm artifact is still fetched
    /// and instantiated lazily, on the first real `Source`/`Sink` against the IRI. Builder
    /// style; call once per endpoint.
    pub fn with_endpoint(mut self, iri: impl Into<String>, describe: Description) -> Self {
        self.endpoints.push((iri.into(), describe));
        self
    }

    /// The card to hand the resolved endpoint for `target`: the enumerated endpoint's own
    /// description if `target` is one, else the generic prefix card.
    fn card_for(&self, target: &str) -> Description {
        self.endpoints
            .iter()
            .find(|(iri, _)| iri == target)
            .map(|(_, d)| d.clone())
            .unwrap_or_else(|| self.describe.clone())
    }
}

impl Space for WasmModuleSpace {
    fn resolve(&self, request: &Request, _scope: &Scope) -> Resolution {
        let target = request.target.as_str();
        let matches = self.endpoints.iter().any(|(iri, _)| iri == target)
            || self.prefixes.iter().any(|p| target.starts_with(p.as_str()));
        if matches {
            Resolution::Hit(Resolved {
                endpoint: Arc::new(WasmModuleEndpoint {
                    transport: Arc::clone(&self.transport),
                    describe: self.card_for(target),
                }),
                bindings: Bindings::new(),
            })
        } else {
            Resolution::Miss
        }
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        // Only the explicitly-declared endpoints enumerate; a bare prefix can't list its
        // (open) IRI set. Empty => `None`, preserving the prior "not in the catalog"
        // behaviour for modules that declare nothing.
        if self.endpoints.is_empty() {
            return None;
        }
        Some(
            self.endpoints
                .iter()
                .map(|(iri, describe)| SpaceEntry {
                    pattern: iri.clone(),
                    endpoint: describe.id.clone(),
                })
                .collect(),
        )
    }
}

/// The endpoint a [`WasmModuleSpace`] resolves to: drive the session over the transport and
/// fold the out-of-band callbacks' provenance into the result.
struct WasmModuleEndpoint {
    transport: Arc<dyn ModuleSessionTransport>,
    describe: Description,
}

#[async_trait]
impl Endpoint for WasmModuleEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
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

        match decode::<ModuleReply>(&reply_bytes)? {
            ModuleReply::Resolved(representation) => {
                // Re-attach the provenance the wire dropped, no more cacheable than inputs.
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
            ModuleReply::Error(message) => Err(Error::Endpoint(message)),
            _ => Err(Error::Endpoint(
                "module returned an unexpected reply to Invoke".to_string(),
            )),
        }
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
pub use uds::{serve, UdsTransport};

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
                        let result = host
                            .issue(request, &clamped)
                            .await
                            .map_err(|e| e.to_string());
                        write_frame(&mut stream, &ModuleCall::HostResult(result))
                            .map_err(io_err)?;
                    }
                    ModuleReply::Resolved(representation) => return Ok(representation),
                    ModuleReply::Error(message) => return Err(Error::Endpoint(message)),
                    ModuleReply::Bindings(_) => {
                        return Err(Error::Endpoint(
                            "module sent Bindings in reply to Invoke".to_string(),
                        ))
                    }
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
            std::thread::spawn(move || serve_connection(space, stream));
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
    pub(crate) fn serve_connection(space: Arc<dyn Space>, stream: UnixStream) {
        loop {
            let call: ModuleCall = match read_frame(&mut &stream) {
                Ok(call) => call,
                Err(_) => return, // EOF or a malformed frame ends the session
            };
            let reply = match call {
                ModuleCall::Invoke {
                    request,
                    capability,
                } => futures::executor::block_on(run_session(&space, &stream, request, capability)),
                ModuleCall::Describe => ModuleReply::Bindings(space.entries()),
                ModuleCall::HostResult(_) => {
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
        stream: &UnixStream,
        request: Request,
        capability: Capability,
    ) -> ModuleReply {
        match space.resolve(&request, &Scope::empty()) {
            Resolution::Hit(resolved) => {
                let issuer = SocketHostIssuer { stream };
                let inv =
                    Invocation::with_issuer(&request, &resolved.bindings, &capability, &issuer);
                match resolved.endpoint.invoke(&inv).await {
                    Ok(representation) => ModuleReply::Resolved(representation),
                    Err(e) => ModuleReply::Error(e.to_string()),
                }
            }
            Resolution::Miss => ModuleReply::Error(format!(
                "module did not resolve {}",
                request.target.as_str()
            )),
        }
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
            match read_frame::<_, ModuleCall>(&mut stream).map_err(io_err)? {
                ModuleCall::HostResult(Ok(representation)) => Ok(representation),
                ModuleCall::HostResult(Err(message)) => Err(Error::Endpoint(message)),
                _ => Err(Error::Endpoint(
                    "expected HostResult answering a HostCall".to_string(),
                )),
            }
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
///     Arc::new(ModuleSpace::new(["urn:xslt:"], Arc::new(InProcessTransport::new(ikigai_xslt::space())))),
///     // …
/// ])
/// ```
pub struct ModuleSpace {
    prefixes: Vec<String>,
    transport: Arc<dyn ModuleTransport>,
}

impl ModuleSpace {
    /// Route every IRI starting with one of `prefixes` to `transport`.
    pub fn new(
        prefixes: impl IntoIterator<Item = impl Into<String>>,
        transport: Arc<dyn ModuleTransport>,
    ) -> Self {
        Self {
            prefixes: prefixes.into_iter().map(Into::into).collect(),
            transport,
        }
    }
}

impl Space for ModuleSpace {
    fn resolve(&self, request: &Request, _scope: &Scope) -> Resolution {
        let target = request.target.as_str();
        if self.prefixes.iter().any(|p| target.starts_with(p.as_str())) {
            // (A real host also *triggers lazy instantiation* of the module here.)
            Resolution::Hit(Resolved {
                endpoint: Arc::new(ModuleEndpoint {
                    transport: Arc::clone(&self.transport),
                }),
                bindings: Bindings::new(),
            })
        } else {
            Resolution::Miss
        }
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        self.transport.entries()
    }
}

/// The host-side endpoint a [`ModuleSpace`] resolves to: it forwards the invocation to
/// the module over the transport, bridging the module's callbacks back to the host
/// through *this* invocation — so the host kernel records the dependency threads and
/// serves the callbacks from its cache (cacheability composes across the boundary).
struct ModuleEndpoint {
    transport: Arc<dyn ModuleTransport>,
}

#[async_trait]
impl Endpoint for ModuleEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let bridge = HostBridge { inv };
        self.transport
            .invoke(inv.request.clone(), inv.capability, &bridge)
            .await
    }

    fn name(&self) -> &str {
        "module"
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
        ArgRef, ArgSpec, Description, EndpointSpace, Exact, Fallback, FnEndpoint, Iri, Kernel,
        MetaRenderer, ReprType, Verb,
    };

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
            // exactly the host-side caching a real module relies on.
            Ok(Representation::new(ReprType::new("text/plain"), out).cacheable())
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
        EndpointSpace::new().bind(Exact::new("urn:stub:concat"), ConcatEndpoint)
    }

    fn fixed(name: &'static str, media: &'static str, body: &'static str) -> FnEndpoint {
        FnEndpoint::new(name, move |_inv: &Invocation<'_>| {
            Ok(Representation::new(ReprType::new(media), body.as_bytes().to_vec()).cacheable())
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
        match decode::<ModuleReply>(&reply_bytes).unwrap() {
            ModuleReply::Resolved(rep) => {
                assert_eq!(String::from_utf8(rep.bytes).unwrap(), "hello, module")
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
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
                        async move {
                            host.issue(request, &capability)
                                .await
                                .map_err(|e| e.to_string())
                        }
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
            Arc::new(WasmModuleSpace::new(["urn:stub:"], transport, describe)) as Arc<dyn Space>,
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
        );
        assert!(space.entries().is_none());
    }

    // --- UdsTransport: the same session, but over a real Unix socket -------------------

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
            crate::uds::serve_connection(space, stream);
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
}
