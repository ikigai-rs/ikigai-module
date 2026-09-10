//! The module recipe as one test, held ACROSS the module boundary: `ikigai-conformance`
//! walks one fixture module bare, then through every way this crate mounts a module, and
//! every report is held to the bare one. This crate binds no endpoint of its own — a mount
//! carries whatever the module says — so what the suite can hold a mount to is exactly:
//! **the report through the mount is the report without it.**
//!
//! ## The fixture: a small conforming module, and the host resources it reaches back for
//!
//! [`Leaf`] binds six endpoints under `urn:mod:` that pass the suite on their own (the
//! suite walks fixture endpoints as module endpoints — conformance PENDING #17 — so they
//! must), one per shape a mount has to carry through unchanged:
//!
//! - `cell` — a threaded read: `Source` is `.cacheable()` under the golden thread named
//!   after the resource, `Sink` replaces the value and cuts it. Declared `cacheable`. The
//!   thread is the MODULE's own declaration, which through 0.2 never crossed a wire.
//! - `live` — a live read: uncacheable, a different byte string every time.
//! - `upper` — a pure function of its one input: cacheable with an empty thread set.
//!   Declared `pure` and `cacheable`.
//! - `gated` — declares `urn:cap:demo:read`, the module's own `requires`. ENFORCED under
//!   no grants wants a typed `Denied`; through 0.2 a module-side refusal arrived as
//!   `Error::Endpoint`, which is neither permanent nor transient.
//! - `echo` — bound at a URI template (`urn:mod:echo:{word}`): the card a mount has to
//!   find for an IRI that matches no exact pattern. Pure of its binding; `pure`, `cacheable`.
//! - `join` — the module format's defining shape: it resolves two host resources back
//!   through the boundary (`inv.source`) and joins them, `.cacheable()` with NO thread of
//!   its own — its cacheability is entirely the host resources', carried by the callback
//!   provenance. Declared `cacheable`; a `Fixture` names two resources that exist.
//!
//! Beside the module, the host binds `urn:test:greeting` and `urn:test:subject` — the two
//! resources `join` reaches for — threaded by their own names and declared `cacheable`.
//!
//! ## The mounts
//!
//! [`mounts`] lists the bare space and every mount: `ModuleSpace::connect` over the
//! in-process transport, over the loopback codec, and over a Unix socket; and a
//! `WasmModuleSpace` over the browser's out-of-band split, its cards written by the host
//! (a lazy module cannot be asked). [`conforms`] runs the same suite over each and requires
//! every report clean with the bare report's shape — and, stronger than the suite can say,
//! the same catalog entries and the same description per entry, verbatim.
//!
//! ## What the walk cannot see, pinned by hand
//!
//! - **A mount that never asked sees nothing of the module**
//!   ([`a_mount_that_never_asked_describes_one_endpoint_named_module`]): through
//!   `ModuleSpace::new` the manifold is one endpoint, `module`, with no actions — the
//!   0.2 state, kept as the documented cost of not asking.
//! - **The floor is visible AND enforced** ([`the_floor_is_visible_and_enforced`]): under
//!   `ModuleFloor::requiring(..)` every module action's card carries the scope, the walk is
//!   clean (ENFORCED sees the floor's typed `Denied`), and the module's own `requires`
//!   still adds to it.
//! - **Cacheability is inherited by thread name**
//!   ([`cacheability_is_inherited_by_thread_name`]): a module-declared thread crosses every
//!   transport and a `Sink` through the mount cuts it; a callback-inherited thread is the
//!   host resource's name and cutting THAT invalidates the module's result; a live read
//!   stays live; a pure read caches with no thread. The suite sees "non-empty threads", not
//!   WHICH — the 0.2 loopback cached `cell` forever with an empty set, and only `cacheable`
//!   + this test would have said so.
//! - **Every error type survives, in both directions**
//!   ([`typed_errors_survive_in_both_directions`]): a module endpoint's failure reaches the
//!   host as the same `Error` variant with the same message; a host resource's failure
//!   reaches the module's endpoint the same way. Nothing is stored either way.
//! - **A module-side refusal is a typed `Denied` even when no card reached the kernel**
//!   ([`a_module_side_refusal_is_a_typed_denied_over_every_transport`]).
//! - **The canonical survives** ([`the_canonical_survives_every_mount`]): a module that
//!   composes an `Alias` and declares its table gives the logical and backing names ONE cache
//!   entry through every mount — the declaration crosses (or is written host-side for the
//!   lazy space), the kernel adopts the backing name before it keys anything.

use async_trait::async_trait;
use futures::executor::block_on;
use ikigai_conformance::{Check, Fixture, Report, Suite};
use ikigai_core::{
    ActionSpec, Alias, AliasTable, ArgRef, ArgSpec, Capability, Description, Endpoint,
    EndpointSpace, Error, Exact, Expiry, Fallback, FnEndpoint, Invocation, Iri, Kernel, ReprType,
    Representation, Request, Space, SpaceEntry, Thread, UriTemplate, Verb,
};
use ikigai_module::{
    run_session, serve_host_call, InProcessTransport, LoopbackTransport, ModuleFloor,
    ModuleRewrite, ModuleSessionTransport, ModuleSpace, WasmModuleSpace,
};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const XSD_ANY_URI: &str = "http://www.w3.org/2001/XMLSchema#anyURI";
const READ_CAP: &str = "urn:cap:demo:read";
const MOUNT_CAP: &str = "urn:cap:module:demo";
const TEXT: &str = "text/plain";
const PREFIX: &str = "urn:mod:";

/// The fixture's bindings: id, pattern, verbs — the module's six, then the host's two.
const MODULE_LEAVES: [(&str, &str, &[Verb]); 6] = [
    ("cell", "urn:mod:cell", &[Verb::Source, Verb::Sink]),
    ("live", "urn:mod:live", &[Verb::Source]),
    ("upper", "urn:mod:upper", &[Verb::Source]),
    ("gated", "urn:mod:gated", &[Verb::Source]),
    ("echo", "urn:mod:echo:{word}", &[Verb::Source]),
    ("join", "urn:mod:join", &[Verb::Source]),
];
const HOST_LEAVES: [(&str, &str); 2] = [
    ("greeting", "urn:test:greeting"),
    ("subject", "urn:test:subject"),
];

fn ok(bytes: impl Into<Vec<u8>>) -> Representation {
    Representation::new(ReprType::new(TEXT), bytes)
}

/// `join`: resolve `a` and `b` back through the host and concatenate them. Cacheable with
/// no thread of its own — exactly as cacheable as what it reached for.
struct Join {
    reads: Arc<AtomicU32>,
}

#[async_trait]
impl Endpoint for Join {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation, Error> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let mut out = Vec::new();
        for arg in ["a", "b"] {
            let iri = Iri::parse(inv.inline_str(arg)?).map_err(|e| Error::InvalidArgument {
                name: arg.to_string(),
                detail: e.to_string(),
            })?;
            out.extend_from_slice(&inv.source(&iri).await?.bytes);
        }
        Ok(ok(out).cacheable())
    }

    fn name(&self) -> &str {
        "join"
    }

    fn describe(&self) -> Description {
        Description::new("join")
            .title("Join two host resources")
            .verb(Verb::Source)
            .input(ArgSpec::new("a").class(XSD_ANY_URI))
            .input(ArgSpec::new("b").class(XSD_ANY_URI))
            .output(TEXT)
    }
}

/// The fixture module's endpoints and the counters that say what reached them. Shared
/// `Arc`s, so a mount and a bare walk over one `Leaf` see one state.
struct Leaf {
    space: Arc<dyn Space>,
    cell_reads: Arc<AtomicU32>,
    live_reads: Arc<AtomicU32>,
    join_reads: Arc<AtomicU32>,
}

impl Leaf {
    fn new() -> Self {
        let value = Arc::new(Mutex::new("one".to_string()));
        let cell_reads = Arc::new(AtomicU32::new(0));
        let live_reads = Arc::new(AtomicU32::new(0));
        let join_reads = Arc::new(AtomicU32::new(0));

        let cell = {
            let (value, reads) = (value.clone(), cell_reads.clone());
            FnEndpoint::new("cell", move |inv| match inv.request.verb {
                Verb::Sink => {
                    *value.lock().unwrap() = inv.inline_str("content")?.to_string();
                    Ok(ok("ok"))
                }
                _ => {
                    reads.fetch_add(1, Ordering::SeqCst);
                    let current = value.lock().unwrap().clone();
                    // The thread is named after the resource: the kernel cuts it on a
                    // successful Sink to the same target. This is the MODULE's declaration.
                    Ok(ok(current)
                        .cacheable()
                        .depends_on(inv.request.target.as_str()))
                }
            })
            .with_description(
                Description::new("cell")
                    .title("A mutable cell")
                    .action(ActionSpec::new(Verb::Source).output(TEXT))
                    .action(
                        ActionSpec::new(Verb::Sink)
                            .input(ArgSpec::new("content").class(XSD_STRING))
                            .output(TEXT),
                    ),
            )
        };
        let live = {
            let reads = live_reads.clone();
            FnEndpoint::new("live", move |_inv| {
                let n = reads.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(ok(format!("tick {n}")))
            })
            .with_description(
                Description::new("live")
                    .title("A live counter")
                    .verb(Verb::Source)
                    .output(TEXT),
            )
        };
        let upper = FnEndpoint::new("upper", |inv| {
            Ok(ok(inv.inline_str("in")?.to_uppercase()).cacheable())
        })
        .with_description(
            Description::new("upper")
                .title("Uppercase")
                .verb(Verb::Source)
                .input(ArgSpec::new("in").class(XSD_STRING))
                .output(TEXT),
        );
        let gated = FnEndpoint::new("gated", |_inv| Ok(ok("secret"))).with_description(
            Description::new("gated")
                .title("A gated read")
                .verb(Verb::Source)
                .requires(READ_CAP)
                .output(TEXT),
        );
        let echo = FnEndpoint::new("echo", |inv| {
            let word = inv
                .bindings
                .get("word")
                .ok_or_else(|| Error::MissingArgument("word".to_string()))?;
            Ok(ok(word.to_string()).cacheable())
        })
        .with_description(
            Description::new("echo")
                .title("Echo a template binding")
                .verb(Verb::Source)
                .input(ArgSpec::new("word").binding().class(XSD_STRING))
                .output(TEXT),
        );
        let join = Join {
            reads: join_reads.clone(),
        };

        let space: Arc<dyn Space> = Arc::new(
            EndpointSpace::new()
                .bind(Exact::new("urn:mod:cell"), cell)
                .bind(Exact::new("urn:mod:live"), live)
                .bind(Exact::new("urn:mod:upper"), upper)
                .bind(Exact::new("urn:mod:gated"), gated)
                .bind(UriTemplate::parse("urn:mod:echo:{word}").unwrap(), echo)
                .bind(Exact::new("urn:mod:join"), join),
        );
        Leaf {
            space,
            cell_reads,
            live_reads,
            join_reads,
        }
    }

    fn space(&self) -> Arc<dyn Space> {
        Arc::clone(&self.space)
    }

    fn cell_reads(&self) -> u32 {
        self.cell_reads.load(Ordering::SeqCst)
    }

    fn live_reads(&self) -> u32 {
        self.live_reads.load(Ordering::SeqCst)
    }

    fn join_reads(&self) -> u32 {
        self.join_reads.load(Ordering::SeqCst)
    }
}

/// A fixed host resource, declaring a golden thread named after itself.
fn fixed(id: &'static str, body: &'static str) -> FnEndpoint {
    FnEndpoint::new(id, move |inv| {
        Ok(ok(body).cacheable().depends_on(inv.request.target.as_str()))
    })
    .with_description(
        Description::new(id)
            .title("A host resource")
            .verb(Verb::Source)
            .output(TEXT),
    )
}

/// The host's own space: the two resources `join` reaches back for.
fn host_space() -> Arc<dyn Space> {
    Arc::new(
        EndpointSpace::new()
            .bind(
                Exact::new("urn:test:greeting"),
                fixed("greeting", "hello, "),
            )
            .bind(Exact::new("urn:test:subject"), fixed("subject", "module")),
    )
}

/// The host's root: its own resources, then the module (bare or mounted).
fn root(host: Arc<dyn Space>, module: Arc<dyn Space>) -> Arc<dyn Space> {
    Arc::new(Fallback::new(vec![host, module]))
}

/// The browser's split, on native: the host drives `invoke_session`; the module's
/// `HostCall`s are serviced out-of-band by `serve_host_call` against a host kernel over the
/// same resources, recording provenance into the sink the `WasmModuleSpace` installed.
struct FakeTransport {
    module: Arc<dyn Space>,
    host: Arc<Kernel>,
}

#[async_trait]
impl ModuleSessionTransport for FakeTransport {
    async fn invoke_session(&self, invoke: Vec<u8>) -> Result<Vec<u8>, String> {
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

/// The module's cards as a browser host would write them: one `with_endpoint` per binding,
/// read off the module itself here so the fixture cannot drift from what the host declares.
fn cards_of(module: &Arc<dyn Space>) -> Vec<(String, Description)> {
    let kernel = Kernel::new(Arc::clone(module));
    module
        .entries()
        .unwrap_or_default()
        .into_iter()
        .map(|entry| {
            let description = kernel
                .describe_pattern(&entry.pattern)
                .unwrap_or_else(|| panic!("{} describes itself", entry.pattern));
            (entry.pattern, description)
        })
        .collect()
}

/// One way to mount the module: the host's own space, the module's space (possibly
/// aliased), what it declares about its naming, and the host's floor → the host's root.
type Mount = fn(Arc<dyn Space>, Arc<dyn Space>, ModuleRewrite, ModuleFloor) -> Arc<dyn Space>;

fn bare(
    host: Arc<dyn Space>,
    module: Arc<dyn Space>,
    _rewrite: ModuleRewrite,
    _floor: ModuleFloor,
) -> Arc<dyn Space> {
    root(host, module)
}

fn in_process(
    host: Arc<dyn Space>,
    module: Arc<dyn Space>,
    rewrite: ModuleRewrite,
    floor: ModuleFloor,
) -> Arc<dyn Space> {
    let transport = Arc::new(InProcessTransport::from_arc(module).declaring(rewrite));
    root(
        host,
        Arc::new(block_on(ModuleSpace::connect([PREFIX], transport, floor)).expect("connect")),
    )
}

fn loopback(
    host: Arc<dyn Space>,
    module: Arc<dyn Space>,
    rewrite: ModuleRewrite,
    floor: ModuleFloor,
) -> Arc<dyn Space> {
    let transport = Arc::new(LoopbackTransport::from_arc(module).declaring(rewrite));
    root(
        host,
        Arc::new(block_on(ModuleSpace::connect([PREFIX], transport, floor)).expect("connect")),
    )
}

#[cfg(unix)]
fn uds(
    host: Arc<dyn Space>,
    module: Arc<dyn Space>,
    rewrite: ModuleRewrite,
    floor: ModuleFloor,
) -> Arc<dyn Space> {
    use ikigai_module::{serve_declaring, UdsTransport};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let path = std::env::temp_dir().join(format!(
        "ikigai-module-conformance-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_file(&path);
    let served = path.clone();
    std::thread::spawn(move || {
        let _ = serve_declaring(module, rewrite, &served);
    });
    for _ in 0..400 {
        if path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let transport = Arc::new(UdsTransport::connect(&path));
    root(
        host,
        Arc::new(block_on(ModuleSpace::connect([PREFIX], transport, floor)).expect("connect")),
    )
}

/// The browser split: the module's callbacks are served by a kernel over the HOST's space —
/// whatever the host serves at its `hostCall` global — while the root the caller sees is the
/// same host space plus the mount.
fn wasm(
    host: Arc<dyn Space>,
    module: Arc<dyn Space>,
    rewrite: ModuleRewrite,
    floor: ModuleFloor,
) -> Arc<dyn Space> {
    let transport = Arc::new(FakeTransport {
        module: Arc::clone(&module),
        host: Arc::new(Kernel::new(Arc::clone(&host))),
    });
    let mut space = WasmModuleSpace::new([PREFIX], transport, Description::new("demo"), floor)
        .declaring(rewrite)
        .expect("a declared table inside the prefix");
    for (pattern, description) in cards_of(&module) {
        space = space.with_endpoint(pattern, description);
    }
    root(host, Arc::new(space))
}

/// The bare space and every mount. The bare entry ignores the declaration and the floor:
/// an `Alias` composed locally reports its own canonical, and a floor is a MOUNT's word.
fn mounts() -> Vec<(&'static str, Mount)> {
    let mut mounts: Vec<(&'static str, Mount)> = vec![
        ("bare", bare),
        ("ModuleSpace::connect / in-process", in_process),
        ("ModuleSpace::connect / loopback", loopback),
        ("WasmModuleSpace / out-of-band", wasm),
    ];
    #[cfg(unix)]
    mounts.push(("ModuleSpace::connect / unix socket", uds));
    mounts
}

fn mounted() -> impl Iterator<Item = (&'static str, Mount)> {
    mounts().into_iter().filter(|(label, _)| *label != "bare")
}

fn suite() -> Suite {
    Suite::new()
        .fixture(
            Fixture::new("join", Verb::Source)
                .arg("a", "urn:test:greeting")
                .arg("b", "urn:test:subject"),
        )
        .cacheable("cell")
        .cacheable("upper")
        .cacheable("echo")
        .cacheable("join")
        .cacheable("greeting")
        .cacheable("subject")
        .pure("upper")
        .pure("echo")
}

fn request(verb: Verb, iri: &str, args: &[(&str, &str)]) -> Request {
    let mut request = Request::new(verb, Iri::parse(iri).unwrap());
    for (name, value) in args {
        request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
    }
    request
}

fn issue(
    kernel: &Kernel,
    verb: Verb,
    iri: &str,
    args: &[(&str, &str)],
    capability: &Capability,
) -> Result<Representation, Error> {
    block_on(kernel.issue(request(verb, iri, args), capability))
}

fn source(kernel: &Kernel, iri: &str, args: &[(&str, &str)]) -> Result<Representation, Error> {
    issue(kernel, Verb::Source, iri, args, &Capability::root())
}

fn none() -> Capability {
    Capability::scoped(Vec::<String>::new())
}

/// The catalog without the kernel's own operations, which every root lists alike.
fn catalog(kernel: &Kernel) -> Vec<SpaceEntry> {
    kernel
        .entries()
        .expect("enumerable")
        .into_iter()
        .filter(|e| !e.pattern.starts_with("urn:kernel:"))
        .collect()
}

/// Eight endpoints, nine actions, nothing skipped, nothing opted out, the declarations
/// recorded.
fn assert_shape(label: &str, report: &Report) {
    assert_eq!(
        report.endpoints,
        MODULE_LEAVES.len() + HOST_LEAVES.len(),
        "{label}: {report}"
    );
    assert_eq!(report.actions, 9, "{label}: {report}");
    assert_eq!(
        report.checks.skipped().count(),
        0,
        "{label}: nothing skipped: {report}"
    );
    assert!(report.declared.opted_out.is_empty(), "{label}: {report}");
    assert_eq!(
        report.declared.cacheable,
        ["cell", "upper", "echo", "join", "greeting", "subject"],
        "{label}"
    );
    assert_eq!(report.declared.pure, ["upper", "echo"], "{label}");
}

/// The walk, bare and through every mount: every report clean, every report the same
/// shape — and the catalog and every description through a mount are the bare space's,
/// verbatim, which the suite's static checks passing would not by themselves prove.
#[test]
fn conforms() {
    let bare = Kernel::new(root(host_space(), Leaf::new().space()));
    let report = suite().run_blocking(&bare);
    // Printed even when clean (`--nocapture`): the report is the record.
    eprintln!("bare: {report}");
    assert!(report.is_clean(), "bare: {report}");
    assert_shape("bare", &report);
    let entries = catalog(&bare);
    assert_eq!(entries.len(), MODULE_LEAVES.len() + HOST_LEAVES.len());
    let described: Vec<Description> = entries
        .iter()
        .map(|e| bare.describe_pattern(&e.pattern).expect("bare describes"))
        .collect();

    for (label, mount) in mounted() {
        let kernel = Kernel::new(mount(
            host_space(),
            Leaf::new().space(),
            ModuleRewrite::None,
            ModuleFloor::public(),
        ));
        let report = suite().run_blocking(&kernel);
        eprintln!("{label}: {report}");
        assert!(report.is_clean(), "{label}: {report}");
        assert_shape(label, &report);
        assert_eq!(
            catalog(&kernel),
            entries,
            "{label}: the catalog is the module's"
        );
        for (entry, expected) in entries.iter().zip(&described) {
            assert_eq!(
                kernel.describe_pattern(&entry.pattern).as_ref(),
                Some(expected),
                "{label}: `{}` describes itself as the module does",
                entry.pattern
            );
        }
    }
}

/// `ModuleSpace::new` never asks the module for its cards, so through it the manifold is
/// ONE endpoint, `module`, with no actions — every catalog row describes itself with the
/// generic card, and the suite's one finding says so. This is the 0.2 state, kept as the
/// documented cost of not asking; `connect` is the mount that asks.
#[test]
fn a_mount_that_never_asked_describes_one_endpoint_named_module() {
    let leaf = Leaf::new();
    let unasked = ModuleSpace::new(
        [PREFIX],
        Arc::new(InProcessTransport::from_arc(leaf.space())),
        ModuleFloor::public(),
    );
    let kernel = Kernel::new(root(host_space(), Arc::new(unasked)));
    let report = suite().run_blocking(&kernel);
    eprintln!("unasked: {report}");
    // The module's rows are still listed (the transport enumerates)…
    assert_eq!(
        catalog(&kernel).len(),
        MODULE_LEAVES.len() + HOST_LEAVES.len()
    );
    // …but every exact one describes itself as `module`, with nothing to select — and the
    // template row describes NOTHING: its probe reaches the generic card, whose name is not
    // `echo`, so the kernel's guard against a swallowed sibling (rightly) rejects it.
    assert_eq!(report.endpoints, HOST_LEAVES.len() + 1, "{report}");
    assert_eq!(report.actions, HOST_LEAVES.len(), "{report}");
    let findings: Vec<_> = report.findings.iter().collect();
    assert_eq!(findings.len(), 2, "{report}");
    assert_eq!(findings[0].endpoint, "module");
    assert_eq!(findings[0].check, Check::ArgSpecs);
    assert!(
        findings[0].detail.contains("declares no action"),
        "{report}"
    );
    assert_eq!(findings[1].endpoint, "echo");
    assert!(findings[1].detail.contains("describes nothing"), "{report}");

    // The generic card is the host's to write.
    let described = ModuleSpace::new(
        [PREFIX],
        Arc::new(InProcessTransport::from_arc(leaf.space())),
        ModuleFloor::public(),
    )
    .describing(Description::new("demo-module").title("The demo module"));
    let kernel = Kernel::new(root(host_space(), Arc::new(described)));
    let card = kernel
        .describe(&Iri::parse("urn:mod:cell").unwrap())
        .expect("the generic card");
    assert_eq!(card.id, "demo-module");
}

/// Under a floor, every module action's card carries the mount's scope — the manifold's
/// half of declared = enforced — and the walk is clean because ENFORCED sees the floor's
/// typed `Denied`. The module's own `requires` still adds to it; the host's resources are
/// untouched.
#[test]
fn the_floor_is_visible_and_enforced() {
    for (label, mount) in mounted() {
        let kernel = Kernel::new(mount(
            host_space(),
            Leaf::new().space(),
            ModuleRewrite::None,
            ModuleFloor::requiring(MOUNT_CAP),
        ));
        let report = suite().run_blocking(&kernel);
        eprintln!("{label} under a floor: {report}");
        assert!(report.is_clean(), "{label}: {report}");
        assert_shape(label, &report);

        for (id, pattern, _) in MODULE_LEAVES {
            let card = kernel.describe_pattern(pattern).expect("described");
            for action in card.action_specs() {
                assert!(
                    action.requires.contains(&MOUNT_CAP.to_string()),
                    "{label}: `{id}` {:?} carries the floor: {action:?}",
                    action.verb
                );
            }
        }
        for (id, pattern) in HOST_LEAVES {
            let card = kernel.describe_pattern(pattern).expect("described");
            assert!(
                card.action_specs().iter().all(|a| a.requires.is_empty()),
                "{label}: the host's `{id}` is not under the floor"
            );
        }

        let denial = source_as(&kernel, "urn:mod:live", &none()).unwrap_err();
        assert!(matches!(denial, Error::Denied(_)), "{label}: {denial:?}");
        assert!(denial.to_string().contains(MOUNT_CAP), "{label}: {denial}");
        let mount_only = Capability::scoped([MOUNT_CAP]);
        assert!(
            source_as(&kernel, "urn:mod:live", &mount_only).is_ok(),
            "{label}"
        );
        let denial = source_as(&kernel, "urn:mod:gated", &mount_only).unwrap_err();
        assert!(matches!(denial, Error::Denied(_)), "{label}: {denial:?}");
        assert!(
            denial.to_string().contains(READ_CAP),
            "{label}: the module's own card adds to the floor: {denial}"
        );
        let both = Capability::scoped([MOUNT_CAP, READ_CAP]);
        assert_eq!(
            source_as(&kernel, "urn:mod:gated", &both).unwrap().bytes,
            b"secret",
            "{label}"
        );
    }
}

fn source_as(kernel: &Kernel, iri: &str, capability: &Capability) -> Result<Representation, Error> {
    issue(kernel, Verb::Source, iri, &[], capability)
}

/// A read through a mount is exactly as cacheable as the module says, thread names
/// included: the module's own declared thread crosses and its `Sink` cuts it; a
/// callback-inherited thread is the host resource's name and cutting that invalidates the
/// module's result; a live read stays live; a pure read caches with no thread.
#[test]
fn cacheability_is_inherited_by_thread_name() {
    let join_args = [("a", "urn:test:greeting"), ("b", "urn:test:subject")];
    for (label, mount) in mounts() {
        let leaf = Leaf::new();
        let kernel = Kernel::new(mount(
            host_space(),
            leaf.space(),
            ModuleRewrite::None,
            ModuleFloor::public(),
        ));
        let root = Capability::root();

        // The module's own thread: declared inside the module, cut by a Sink through the mount.
        let first = source(&kernel, "urn:mod:cell", &[]).unwrap();
        assert_eq!(first.expiry, Expiry::Never, "{label}: cell is cacheable");
        assert_eq!(
            first.threads().iter().cloned().collect::<Vec<_>>(),
            [Thread::new("urn:mod:cell")],
            "{label}: the thread the module declared crossed the boundary"
        );
        assert_eq!(source(&kernel, "urn:mod:cell", &[]).unwrap().bytes, b"one");
        assert_eq!(
            leaf.cell_reads(),
            1,
            "{label}: the second read was a cache hit"
        );
        issue(
            &kernel,
            Verb::Sink,
            "urn:mod:cell",
            &[("content", "two")],
            &root,
        )
        .unwrap();
        assert!(
            !kernel.is_cached(&request(Verb::Source, "urn:mod:cell", &[]), &root),
            "{label}: a Sink through the mount cut the module's thread"
        );
        assert_eq!(
            source(&kernel, "urn:mod:cell", &[]).unwrap().bytes,
            b"two",
            "{label}: recomputed after the cut"
        );
        assert_eq!(leaf.cell_reads(), 2, "{label}");

        // Inherited: `join` declares nothing; its threads are the host resources' names.
        let first = source(&kernel, "urn:mod:join", &join_args).unwrap();
        assert_eq!(first.bytes, b"hello, module", "{label}");
        assert_eq!(first.expiry, Expiry::Never, "{label}: join is cacheable");
        let threads = first.threads();
        assert!(
            threads.contains(&Thread::new("urn:test:greeting"))
                && threads.contains(&Thread::new("urn:test:subject")),
            "{label}: the callbacks' provenance rides on the result: {threads:?}"
        );
        source(&kernel, "urn:mod:join", &join_args).unwrap();
        assert_eq!(
            leaf.join_reads(),
            1,
            "{label}: the second read was a cache hit"
        );
        kernel.cut("urn:test:greeting");
        assert!(
            !kernel.is_cached(&request(Verb::Source, "urn:mod:join", &join_args), &root),
            "{label}: cutting a host resource reaches the module's result"
        );
        source(&kernel, "urn:mod:join", &join_args).unwrap();
        assert_eq!(leaf.join_reads(), 2, "{label}: recomputed after the cut");

        // Live: every read reaches the endpoint, nothing is stored.
        let a = source(&kernel, "urn:mod:live", &[]).unwrap();
        let b = source(&kernel, "urn:mod:live", &[]).unwrap();
        assert_eq!(a.expiry, Expiry::Always, "{label}: live stays live");
        assert_ne!(a.bytes, b.bytes, "{label}: two live reads, two answers");
        assert_eq!(leaf.live_reads(), 2, "{label}");

        // Pure: cached with no thread, byte-identical — by value and by binding.
        for (iri, args) in [
            ("urn:mod:upper", &[("in", "hi")][..]),
            ("urn:mod:echo:hi", &[][..]),
        ] {
            let a = source(&kernel, iri, args).unwrap();
            let b = source(&kernel, iri, args).unwrap();
            assert_eq!(a.bytes, b.bytes, "{label}: {iri}");
            assert_eq!(a.expiry, Expiry::Never, "{label}: {iri}");
            assert!(a.threads().is_empty(), "{label}: {iri} is pure, no thread");
            assert!(
                kernel.is_cached(&request(Verb::Source, iri, args), &root),
                "{label}: {iri}"
            );
        }
    }
}

/// Every `Error` variant an endpoint can raise, permanent and transient.
fn every_error() -> Vec<Error> {
    vec![
        Error::Unresolved(Iri::parse("urn:test:nowhere").unwrap()),
        Error::MissingArgument("in".into()),
        Error::InvalidArgument {
            name: "in".into(),
            detail: "not a thing".into(),
        },
        Error::Endpoint("boom".into()),
        Error::Denied("not yours".into()),
        Error::NotFound("gone".into()),
        Error::Timeout("slow".into()),
        Error::Unavailable("down".into()),
    ]
}

/// An endpoint that fails with whatever error it is handed.
fn failing(id: &'static str, error: Error) -> FnEndpoint {
    FnEndpoint::new(id, move |_inv| Err(error.clone()))
        .with_description(Description::new(id).verb(Verb::Source).output(TEXT))
}

/// `relay`: resolve one host resource and hand its bytes back — or its error, unchanged.
struct Relay;

#[async_trait]
impl Endpoint for Relay {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation, Error> {
        let iri = Iri::parse(inv.inline_str("of")?).map_err(|e| Error::InvalidArgument {
            name: "of".into(),
            detail: e.to_string(),
        })?;
        inv.source(&iri).await
    }

    fn name(&self) -> &str {
        "relay"
    }

    fn describe(&self) -> Description {
        Description::new("relay")
            .verb(Verb::Source)
            .input(ArgSpec::new("of").class(XSD_ANY_URI))
            .output(TEXT)
    }
}

/// Module → host: a module endpoint's failure reaches the host as the same variant with
/// the same message, through every mount. Host → module: a host resource's failure reaches
/// the module's endpoint the same way, and comes back out unchanged. Nothing is stored.
#[test]
fn typed_errors_survive_in_both_directions() {
    for (label, mount) in mounted() {
        for error in every_error() {
            // Module → host.
            let module: Arc<dyn Space> = Arc::new(EndpointSpace::new().bind(
                Exact::new("urn:mod:failing"),
                failing("failing", error.clone()),
            ));
            let kernel = Kernel::new(mount(
                host_space(),
                module,
                ModuleRewrite::None,
                ModuleFloor::public(),
            ));
            let out = source(&kernel, "urn:mod:failing", &[]).unwrap_err();
            assert_eq!(out, error, "{label}: module → host");
            assert_eq!(out.is_transient(), error.is_transient(), "{label}");
            assert_eq!(kernel.cache_len(), 0, "{label}: an error stores nothing");

            // Host → module → host. The host's space is this test's own: the failing
            // resource, which the relaying module reaches back for.
            let module: Arc<dyn Space> =
                Arc::new(EndpointSpace::new().bind(Exact::new("urn:mod:relay"), Relay));
            let failing_host: Arc<dyn Space> = Arc::new(EndpointSpace::new().bind(
                Exact::new("urn:test:failing"),
                failing("failing", error.clone()),
            ));
            let kernel = Kernel::new(mount(
                failing_host,
                module,
                ModuleRewrite::None,
                ModuleFloor::public(),
            ));
            let out = source(&kernel, "urn:mod:relay", &[("of", "urn:test:failing")]).unwrap_err();
            assert_eq!(out, error, "{label}: host → module → host");
            assert_eq!(kernel.cache_len(), 0, "{label}");
        }
    }
}

/// Through a mount that holds no card for the endpoint — `ModuleSpace::new`, or a
/// `WasmModuleSpace` with nothing declared — the kernel has no `requires` to check, so the
/// refusal is the MODULE side's, honoring its own card across the wire. It is a typed,
/// permanent `Denied` over every transport (through 0.2 it was an `Endpoint` string).
#[test]
fn a_module_side_refusal_is_a_typed_denied_over_every_transport() {
    let leaf = Leaf::new();
    let unasked: Vec<(&str, Arc<dyn Space>)> = vec![
        (
            "ModuleSpace::new / in-process",
            Arc::new(ModuleSpace::new(
                [PREFIX],
                Arc::new(InProcessTransport::from_arc(leaf.space())),
                ModuleFloor::public(),
            )),
        ),
        (
            "ModuleSpace::new / loopback",
            Arc::new(ModuleSpace::new(
                [PREFIX],
                Arc::new(LoopbackTransport::from_arc(leaf.space())),
                ModuleFloor::public(),
            )),
        ),
        (
            "WasmModuleSpace, no cards",
            Arc::new(WasmModuleSpace::new(
                [PREFIX],
                Arc::new(FakeTransport {
                    module: leaf.space(),
                    host: Arc::new(Kernel::new(host_space())),
                }),
                Description::new("demo"),
                ModuleFloor::public(),
            )),
        ),
    ];
    for (label, space) in unasked {
        let kernel = Kernel::new(root(host_space(), space));
        assert!(
            kernel
                .describe(&Iri::parse("urn:mod:gated").unwrap())
                .expect("the generic card")
                .requires
                .is_empty(),
            "{label}: no card reached the kernel"
        );
        let denial = source_as(&kernel, "urn:mod:gated", &none()).unwrap_err();
        assert!(matches!(denial, Error::Denied(_)), "{label}: {denial:?}");
        assert!(!denial.is_transient(), "{label}");
        assert!(denial.to_string().contains(READ_CAP), "{label}: {denial}");
        assert!(
            denial.to_string().contains("inside the module"),
            "{label}: the refusal names its side: {denial}"
        );
        assert_eq!(
            source_as(&kernel, "urn:mod:gated", &Capability::scoped([READ_CAP]))
                .unwrap()
                .bytes,
            b"secret",
            "{label}"
        );
    }
}

/// A module composing an `Alias` and declaring its table: through every mount, the logical
/// name and the backing name are ONE cache entry and ONE golden thread — the host adopts the
/// backing name before it keys anything. `ModuleReply` carries bytes, not a `Resolved`, so
/// the canonical never rides the invocation; it survives because the DECLARATION crosses
/// (or, for the lazy space, is written host-side) and is applied in `Space::resolve`.
#[test]
fn the_canonical_survives_every_mount() {
    let table = Arc::new(AliasTable::new().exact("urn:mod:alias-cell", "urn:mod:cell"));
    for (label, mount) in mounts() {
        let leaf = Leaf::new();
        let aliased: Arc<dyn Space> = Arc::new(Alias::new(Arc::clone(&table), leaf.space()));
        let kernel = Kernel::new(mount(
            host_space(),
            aliased,
            ModuleRewrite::from_table(&table),
            ModuleFloor::public(),
        ));
        let root = Capability::root();

        let rep = source(&kernel, "urn:mod:alias-cell", &[]).unwrap();
        assert_eq!(rep.bytes, b"one", "{label}");
        assert!(
            kernel.is_cached(&request(Verb::Source, "urn:mod:cell", &[]), &root),
            "{label}: filed under the BACKING name"
        );
        let entries = kernel.cache_len();
        assert_eq!(source(&kernel, "urn:mod:cell", &[]).unwrap().bytes, b"one");
        assert_eq!(
            kernel.cache_len(),
            entries,
            "{label}: the backing name serves the same entry"
        );
        assert_eq!(
            leaf.cell_reads(),
            1,
            "{label}: one computation for two names"
        );
        kernel.cut("urn:mod:cell");
        assert!(
            !kernel.is_cached(&request(Verb::Source, "urn:mod:cell", &[]), &root),
            "{label}: one thread, cut once, reaches what either name cached"
        );
    }
}
