# ikigai-module

The dynamically-loadable **module format** for the
[ikigai-core](https://crates.io/crates/ikigai-core) resolution kernel: package an
independently-compiled `space()` + endpoints (e.g. an XSLT processor) and mount it
behind a few IRI prefixes, while its endpoints still resolve their `src`/`stylesheet`
references against the **host's** kernel — its catalog, its cache, its other spaces.

In Resource-Oriented Computing terms, a module is a [`Space`] reached over a
**transport** — but unlike a plain remote kernel (IPC/QUIC, which resolves every
sub-request server-side), a module carries a **reverse callback channel**. When the
module's endpoint needs a sub-resource it calls *back* to the host mid-invocation via
`inv.source` / `inv.issue`. That callback lands on a seam ikigai already has: an
`Invocation` reaches the kernel through the [`Issuer`] trait. The module itself stays a
**stateless leaf** — the dependency threads and cache live entirely host-side, so the
module's result is cached and invalidated exactly as a statically-linked space would be.

## The pieces

| Type | Side | Role |
| --- | --- | --- |
| `ModuleSpace` | host | A `Space` that routes IRIs by prefix to a module over a `ModuleTransport`; slots into the kernel's root `Fallback` where a linked `space()` would go. |
| `ModuleTransport` | host | The seam to a module. `invoke(request, capability, host)` runs the endpoint, servicing its callbacks against `host` (the host kernel as an `Issuer`). |
| `InProcessTransport` | host | Phase-1 transport: runs the module in-process and hands the host straight to the module's `Invocation`, exercising the full callback path with zero wire risk. |
| `HostBridge` | host | The host end of the callback channel — an `Issuer` that forwards a module's sub-request back through the originating `Invocation`, recording its golden thread. |
| `ModuleCall` / `ModuleReply` | wire | The Phase-2 session protocol (`Invoke` / `HostCall` / `HostResult` / `Resolved` / …). Pinned now even though the in-process transport calls directly. |

## Why a session, not a round-trip

A kernel-wire `Call`/`Reply` is one round-trip. A module invocation is a *session*: the
module may interleave one or more host callbacks (`ModuleReply::HostCall` →
`ModuleCall::HostResult`) before it produces its final `Resolved`. `ModuleCall` /
`ModuleReply` capture that contract so a serialized transport speaks the same protocol
the in-process one shortcuts.

## Usage

Mount a module's `space()` behind its prefixes in the kernel's root `Fallback`:

```rust
use std::sync::Arc;
use ikigai_core::{Fallback, Space};
use ikigai_module::{ModuleSpace, InProcessTransport};

let root: Arc<dyn Space> = Arc::new(Fallback::new(vec![
    Arc::new(local_space) as Arc<dyn Space>,
    Arc::new(ModuleSpace::new(
        ["urn:xslt:"],
        Arc::new(InProcessTransport::new(ikigai_xslt::space())),
    )) as Arc<dyn Space>,
    // …
]));
```

The module's endpoints can now resolve `urn:xslt:` IRIs, and any `inv.source(..)` they
make crosses back through the host kernel — so a module endpoint that joins two
host-resolved resources inherits both of their golden threads, and the host caches the
combined result. (See the crate's tests for that end-to-end.)

## Phasing

- **Phase 1 (today)** — `InProcessTransport`: the module runs in the same process and
  the "transport" is a direct call, proving the callback machinery without any wire risk.
- **Phase 2** — a serialized `ModuleTransport` (a second wasm instance, an embedded
  wasmtime, or a socket) that marshals `ModuleCall` / `ModuleReply` as postcard bytes
  and services the module's callbacks with `host.issue(..)`. Swapping it in touches
  neither the module's code nor `ModuleSpace`.

The first real artifact built on this format is
[`ikigai-xslt-module`](https://github.com/ikigai-rs/ikigai-xslt-module).

See `ikigai-cli/docs/module-format-design.md` for the full design.

## License

Licensed under either of MIT or Apache-2.0 at your option (`MIT OR Apache-2.0`).
