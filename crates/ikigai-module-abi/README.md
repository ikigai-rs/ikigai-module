# ikigai-module-abi

The [ikigai](https://github.com/ikigai-rs) module session's wire types, as plain
`no_std + alloc` data with no ikigai crate under them.

A module session is a conversation of `AbiModuleCall`s (host to module) and `AbiModuleReply`s
(module to host), each one a postcard frame. [`ikigai-module`](https://crates.io/crates/ikigai-module)
defines that session over ikigai-core's own types; this crate mirrors them variant for
variant and field for field, with `String` where core has an IRI or a content id and a card's
description as JSON text, so both encode **the same bytes**. ikigai-module's
`tests/abi_compat.rs` proves it for every variant, both ways, and its
`tests/vectors/module-abi.txt` holds one encoding per variant for other languages to pin.

It is for:

- **wasm guests**, which want the session and nothing else: the same minimal guest measured
  59,205 bytes on these types against 94,114 on ikigai-module's (a core module, release,
  stripped), with no RFC 3987 parser, no `serde_json` and none of ikigai-core linked;
- **peers in other languages**, for whom these definitions are the readable statement of the
  wire.

A Rust host uses `ikigai-module`, which re-exports this crate as `ikigai_module::abi` and
converts between the two shapes.

```rust
use ikigai_module_abi::{AbiCapability, AbiModuleCall, AbiRequest, AbiVerb};

let invoke = AbiModuleCall::Invoke {
    request: AbiRequest::new(AbiVerb::Source, "urn:a"),
    capability: AbiCapability::root(),
};
let bytes = invoke.encode().unwrap();
assert_eq!(AbiModuleCall::decode(&bytes).unwrap(), invoke);
```

An `AbiCapability` is a **claim**, never authority: a host holds a guest's host call to the
capability of the session the guest was invoked under, never to the one the guest wrote.

## License

Licensed under either of MIT or Apache-2.0 at your option (`MIT OR Apache-2.0`).
