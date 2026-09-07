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
| `LoopbackTransport` | host | The same session run **through the codec** — every message postcard-encoded over an in-memory byte channel, both ends in-process. Proves the protocol without a socket. |
| `UdsTransport` / `serve` | both | The first real home: the module runs out-of-process behind a peercred-guarded Unix socket, driven over framed socket I/O. |
| `WasmModuleSpace` / `wasm_module!` | both | The lazy browser module: one macro line emits the artifact's glue, one `WasmModuleSpace` binds it host-side. |
| `ModuleRewrite` / `ModuleManifest` | wire | How the module **names** things — what lets it compose a rewriting space (see below). |
| `ModuleFloor` | host | What the mount **may do** — the capability floor every non-`Meta` verb under it requires. The host's word, not the module's (see below). |

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
use ikigai_module::{InProcessTransport, ModuleFloor, ModuleSpace};

let root: Arc<dyn Space> = Arc::new(Fallback::new(vec![
    Arc::new(local_space) as Arc<dyn Space>,
    Arc::new(ModuleSpace::new(
        ["urn:xslt:"],
        Arc::new(InProcessTransport::new(ikigai_xslt::space())),
        ModuleFloor::requiring("urn:cap:xslt"),   // ← what this mount may do
    )) as Arc<dyn Space>,
    // …
]));
```

The module's endpoints can now resolve `urn:xslt:` IRIs, and any `inv.source(..)` they
make crosses back through the host kernel — so a module endpoint that joins two
host-resolved resources inherits both of their golden threads, and the host caches the
combined result. (See the crate's tests for that end-to-end.)

## The module says what it does; the host says what it may do

`Endpoint::describe()` is what the kernel enforces — *declared capabilities = enforced
capabilities* — and across a module boundary that card has to be authored by the **host**.
The module is the untrusted party here: if its own `requires` were the source of the
enforced requirement, a module declaring none would thereby become ungated and
under-declaring would be the escape hatch. Authority is never self-asserted by the thing
being gated.

So every mount carries a `ModuleFloor`: the scopes every non-`Meta` verb under it requires,
whatever the module says about itself.

```rust
use ikigai_core::{Description, Verb};
use ikigai_module::{ModuleFloor, ModuleSpace};

let mount = ModuleSpace::new(["urn:xslt:"], transport, ModuleFloor::requiring("urn:cap:xslt"))
    // A per-endpoint card REFINES the floor — it can add scopes, never remove them.
    .with_endpoint(
        "urn:xslt:transform",
        Description::new("xslt-transform").verb(Verb::Source).requires("urn:cap:net:*"),
    );
```

Three properties, all of them the point:

- **An IRI with no card is gated exactly as strictly as one with.** The floor is folded into
  every card the mount hands the kernel, including the generic prefix fallback — so
  *forgetting* to enumerate an endpoint can never buy less gating. That fallback was the
  defect: it carried no `requires` at all, so an endpoint declaring
  `.requires("urn:cap:demo:greet")` resolved under a capability granting only
  `urn:cap:demo:read`, while the identical declaration on a *linked* endpoint was denied.
- **A module that declares nothing does not thereby become ungated.** The floor is the
  host's word and the module has no way to lower it.
- **The ungated mount is a sentence you write, never one you omit.** `ModuleFloor` has no
  `Default` and every mount constructor takes one by value, so `ModuleFloor::public()` is a
  deliberate, greppable assertion.

Beside the floor, the module also **honors its own card**: a module-side endpoint declaring
`requires` is checked against the caller's capability at every dispatch site, over every
transport. That can only ever deny *more* than the floor already denies, so it is safe to
trust — and it means one `.requires(..)` declaration means the same thing whether an
endpoint is linked or loaded.

`Meta` is exempt, exactly as it is in the kernel: self-description stays readable wherever
the catalog offers it, so an agent can still learn what it would need in order to ask.

## Composing a rewriting space in a module

Any space should be composable in any module, including one that resolves one name under
another — an `Alias` (a table), a `Rewrite` (a closure), anything reporting
`Resolved::canonical`. That report is what makes a logical name and its backing name **one
resource**: one cache entry, one golden thread, one capability floor.

It cannot ride the resolution across the boundary. The host never asks the module to
resolve — `ModuleSpace::resolve` is a prefix match and `ModuleCall::Invoke` is the first
message, by which time the cache key already exists — and a resolve round trip cannot
simply be added, because `Space::resolve` is *synchronous* while a real transport is not.

So the module **declares** how it names things, and the host applies it locally:

```rust
use std::sync::Arc;
use ikigai_core::{Alias, AliasTable, Space};
use ikigai_module::{InProcessTransport, ModuleFloor, ModuleRewrite, ModuleSpace};

// One table, used twice: the module rewrites through it, and declares it.
let table = Arc::new(AliasTable::new().prefix("urn:xslt:v1:", "urn:xslt:"));
let space: Arc<dyn Space> = Arc::new(Alias::new(Arc::clone(&table), Arc::new(ikigai_xslt::space())));
let transport = Arc::new(
    InProcessTransport::from_arc(space).declaring(ModuleRewrite::from_table(&table)),
);

// `connect` asks once, at mount time, and installs the declaration in the host's own table.
let module = ModuleSpace::connect(["urn:xslt:"], transport, ModuleFloor::requiring("urn:cap:xslt")).await?;
```

From there the rewrite is applied **host-side, synchronously, inside `Space::resolve`** by
the kernel's own `AliasTable`, and reported on `Resolved::canonical` — so the kernel adopts
the backing name before it computes the request id. `urn:xslt:v1:transform` and
`urn:xslt:transform` are then one cache entry and one golden thread. This is `Meta`
("describe yourself") reaching one layer further, not a new mechanism.

### What cannot be declared is said out loud

A table can be written down; an arbitrary hand-written rewriting space cannot. That is a
property of crossing a process boundary — the far side can share identity only as far as it
can describe itself. Three things keep the residual visible instead of silent:

- **`ModuleRewrite::Unknown` is never read as "does not rewrite."** It is the absence of a
  claim (a module that was not asked, or a peer older than `ModuleCall::Manifest`).
- **`ModuleRewrite::Undeclarable(reason)`** is a module saying it rewrites in a way it
  cannot express. The host then **refuses** (the default) or accepts it with a warning —
  `ModuleSpace::on_undeclarable(OnUndeclarable::Warn(sink))`. Never neither.
- **The module side refuses an invocation whose resolution reports a canonical the host did
  not already apply.** A rewrite nobody declared fails loudly, naming both names, at the one
  moment it is knowable — instead of returning a right-looking answer filed under the wrong
  name.

A declared table is also validated at mount time: it must parse, and every rule must stay
inside the prefixes the host routed to the module. A module may only canonicalize names it
was given.

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
