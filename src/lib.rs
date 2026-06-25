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
//!   `Representation` marshalling) without any socket or wasm plumbing. A socket/wasm
//!   transport swaps the channel for framed I/O without touching the module or
//!   [`ModuleSpace`].
//!
//! See `ikigai-cli/docs/module-format-design.md`.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use futures::channel::mpsc;
use futures::lock::Mutex as AsyncMutex;
use futures::StreamExt;
use ikigai_core::{
    Bindings, Capability, Endpoint, Error, Invocation, Issuer, Representation, Request, Resolution,
    Resolved, Result, Scope, Space, SpaceEntry,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
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
        let module_side =
            run_module_session(Arc::clone(&self.space), host_to_module_rx, module_to_host_tx);

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
                let bytes = module_to_host_rx
                    .next()
                    .await
                    .ok_or_else(|| Error::Endpoint("module closed the session early".to_string()))?;
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
    use ikigai_core::{
        ArgRef, ArgSpec, Description, EndpointSpace, Exact, Fallback, FnEndpoint, Iri, Kernel,
        MetaRenderer, ReprType, Verb,
    };
    use futures::executor::block_on;

    // A tiny meta renderer so the test kernel can describe endpoints if asked.
    struct PlainRenderer;
    impl MetaRenderer for PlainRenderer {
        fn render(&self, d: &Description, _t: &ReprType) -> Result<Representation> {
            Ok(Representation::new(ReprType::new("text/plain"), d.id.as_bytes().to_vec()))
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
            .bind(Exact::new("urn:test:greeting"), fixed("greeting", "text/plain", "hello, "))
            .bind(Exact::new("urn:test:subject"), fixed("subject", "text/plain", "module"));

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
            .bind(Exact::new("urn:test:greeting"), fixed("greeting", "text/plain", "hello, "))
            .bind(Exact::new("urn:test:subject"), fixed("subject", "text/plain", "module"));
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
        assert!(kernel.is_cached(&req(), &Capability::root()), "module result is cacheable host-side");
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
            .bind(Exact::new("urn:test:greeting"), fixed("greeting", "text/plain", "hello, "))
            .bind(Exact::new("urn:test:subject"), fixed("subject", "text/plain", "module"));
        let module = ModuleSpace::new(["urn:stub:"], Arc::new(transport) as Arc<dyn ModuleTransport>);
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
        let kernel =
            Kernel::with_meta_renderer(root_over(LoopbackTransport::new(stub_module())), Arc::new(PlainRenderer));
        let rep = block_on(kernel.issue(concat_request(), &Capability::root())).expect("loopback invoke");
        assert_eq!(String::from_utf8(rep.bytes).unwrap(), "hello, module");
    }

    #[test]
    fn loopback_result_is_cached_via_callback_provenance() {
        // The two HostCalls resolve through the host kernel (recorded on the *outer*
        // invocation), so the serialized transform inherits their cacheability and is cached
        // host-side — exactly as the in-process transport. Provenance rides the callbacks,
        // not the serialized `Resolved` (whose threads are `serde(skip)`).
        let kernel =
            Kernel::with_meta_renderer(root_over(LoopbackTransport::new(stub_module())), Arc::new(PlainRenderer));
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
                let patterns: Vec<String> =
                    entries.unwrap_or_default().into_iter().map(|e| e.pattern).collect();
                assert!(
                    patterns.iter().any(|p| p == "urn:stub:concat"),
                    "expected urn:stub:concat in bindings, got {patterns:?}"
                );
            }
            other => panic!("expected Bindings, got {other:?}"),
        }
    }
}
