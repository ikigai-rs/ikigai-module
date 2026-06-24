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
//! - [`ModuleCall`] / [`ModuleReply`] define the *wire session* a Phase-2 transport
//!   (a second wasm instance, or an embedded wasmtime, or a socket) marshals — kept
//!   here so the protocol is pinned even though the in-process transport calls directly.
//!
//! See `ikigai-cli/docs/module-format-design.md`.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use ikigai_core::{
    Bindings, Capability, Endpoint, Error, Invocation, Issuer, Representation, Request, Resolution,
    Resolved, Result, Scope, Space, SpaceEntry,
};
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
        ArgRef, Description, EndpointSpace, Exact, Fallback, FnEndpoint, Iri, Kernel, MetaRenderer,
        ReprType, Verb,
    };
    use futures::executor::block_on;

    // A tiny meta renderer so the test kernel can describe endpoints if asked.
    struct PlainRenderer;
    impl MetaRenderer for PlainRenderer {
        fn render(&self, d: &Description, _t: &ReprType) -> Result<Representation> {
            Ok(Representation::new(ReprType::new("text/plain"), d.id.as_bytes().to_vec()))
        }
    }

    // The module's `src` and `stylesheet`, served BY THE HOST as cacheable resources —
    // exactly the refs the module will reach back for.
    const SRC_RDFXML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <Endpoint xmlns="https://ikigai-rs.dev/ns#" rdf:about="urn:ikigai:endpoint:toUpper">
    <id>toUpper</id><title>Upper-case</title><summary>Upper-cases text.</summary>
  </Endpoint>
  <Endpoint xmlns="https://ikigai-rs.dev/ns#" rdf:about="urn:ikigai:endpoint:reverseList">
    <id>reverseList</id><title>Reverse list</title><summary>Reverses items.</summary>
  </Endpoint>
</rdf:RDF>"#;

    const CARDS_XSL: &str = r#"<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:ik="https://ikigai-rs.dev/ns#">
  <xsl:template match="/"><div class="cards"><xsl:apply-templates select="//ik:Endpoint"/></div></xsl:template>
  <xsl:template match="ik:Endpoint"><article class="card"><h3><xsl:value-of select="ik:title"/></h3></article></xsl:template>
</xsl:stylesheet>"#;

    fn fixed(name: &'static str, media: &'static str, body: &'static str) -> FnEndpoint {
        FnEndpoint::new(name, move |_inv: &Invocation<'_>| {
            Ok(Representation::new(ReprType::new(media), body.as_bytes().to_vec()).cacheable())
        })
    }

    #[test]
    fn module_endpoint_resolves_its_src_and_stylesheet_back_through_the_host() {
        // Host space: the src + stylesheet resources the module will reach back for.
        // The module (ikigai-xslt) is NOT linked into a local space — it's reached only
        // through the ModuleSpace, over the InProcessTransport.
        let host_space = EndpointSpace::new()
            .bind(Exact::new("urn:test:src.rdf"), fixed("src", "application/rdf+xml", SRC_RDFXML))
            .bind(Exact::new("urn:test:cards.xsl"), fixed("xsl", "text/xml", CARDS_XSL));

        let module = ModuleSpace::new(
            ["urn:xslt:"],
            Arc::new(InProcessTransport::new(ikigai_xslt::space())),
        );

        let root: Arc<dyn Space> = Arc::new(Fallback::new(vec![
            Arc::new(host_space) as Arc<dyn Space>,
            Arc::new(module) as Arc<dyn Space>,
        ]));
        let kernel = Kernel::with_meta_renderer(root, Arc::new(PlainRenderer));

        let request = Request::new(Verb::Source, Iri::parse("urn:xslt:transform").unwrap())
            .with_arg("src", ArgRef::Inline(b"urn:test:src.rdf".to_vec()))
            .with_arg("stylesheet", ArgRef::Inline(b"urn:test:cards.xsl".to_vec()));

        let rep = block_on(kernel.issue(request, &Capability::root())).expect("module invoke");
        let html = String::from_utf8(rep.bytes).unwrap();

        // The XSLT ran in the "module", over data it pulled back from the host: two cards.
        assert_eq!(html.matches("class='card'").count() + html.matches("class=\"card\"").count(), 2, "{html}");
        assert!(html.contains("Upper-case") && html.contains("Reverse list"), "{html}");
    }

    #[test]
    fn the_module_result_is_cached_by_the_host_kernel() {
        // The module is a stateless leaf; the HOST kernel caches its result. Same query
        // twice ⇒ the second is served from cache (cache_len stays 1 for the top result).
        let host_space = EndpointSpace::new()
            .bind(Exact::new("urn:test:src.rdf"), fixed("src", "application/rdf+xml", SRC_RDFXML))
            .bind(Exact::new("urn:test:cards.xsl"), fixed("xsl", "text/xml", CARDS_XSL));
        let module = ModuleSpace::new(
            ["urn:xslt:"],
            Arc::new(InProcessTransport::new(ikigai_xslt::space())),
        );
        let root: Arc<dyn Space> = Arc::new(Fallback::new(vec![
            Arc::new(host_space) as Arc<dyn Space>,
            Arc::new(module) as Arc<dyn Space>,
        ]));
        let kernel = Kernel::with_meta_renderer(root, Arc::new(PlainRenderer));
        let req = || {
            Request::new(Verb::Source, Iri::parse("urn:xslt:transform").unwrap())
                .with_arg("src", ArgRef::Inline(b"urn:test:src.rdf".to_vec()))
                .with_arg("stylesheet", ArgRef::Inline(b"urn:test:cards.xsl".to_vec()))
        };
        let a = block_on(kernel.issue(req(), &Capability::root())).unwrap();
        assert!(kernel.is_cached(&req(), &Capability::root()), "module result is cacheable host-side");
        let b = block_on(kernel.issue(req(), &Capability::root())).unwrap();
        assert_eq!(a.bytes, b.bytes);
    }
}
