# Accessibility

What `ikigai-module` and `ikigai-module-abi` emit that people read, the rules that output
follows, how it is tested, and how to report a barrier. They are libraries: what they write is
error text and one warning, which a host prints or serves. It is not a conformance claim. Adapted
from the [ACCESSIBILITY.md template](https://github.com/mgifford/ACCESSIBILITY.md) (MIT).

| Field | Value |
|---|---|
| Target | WCAG 2.2 Level AA, for any page that presents this output; this repository writes text only |
| Status | Evaluation in progress. No conformance claim. |
| Owner | the maintainers of this repository |
| Report a barrier | [a GitHub issue](https://github.com/ikigai-rs/ikigai-module/issues/new?labels=accessibility) with the `accessibility` label; anything security-sensitive through [private vulnerability reporting](https://github.com/ikigai-rs/ikigai-module/security/advisories/new) |
| Last reviewed | 2026-10-31 |

## What it emits that people read

- **Refusals from a module mount** (`src/lib.rs`), returned as `ikigai_core::Error` and shown by
  whatever host made the request: the capability floor's denial, an undeclared or undeclarable
  rewrite, a declared rewrite table refused at mount time, and an unwired or failing browser
  channel (`wasm_module_channel!`).
- **Protocol errors** (`src/lib.rs`): a module or host that answers out of turn, or bytes that do
  not encode or decode.
- **One warning**: the text handed to the host's sink when a mount accepts an undeclarable
  rewrite with `OnUndeclarable::Warn`. The host decides where it goes.
- **Conversion errors** between the core and ABI shapes (`AbiConversionError`, `src/convert.rs`),
  and the ABI crate's `GivenTwice` message (`crates/ikigai-module-abi/src/lib.rs`).
- **A module's own errors**, carried across the boundary with their type (`ModuleError`). Their
  wording is the module's, not this repository's.

Nothing here writes HTML, SVG, color or a terminal screen.

## The rules that output follows

Verified by reading the source on 2026-10-31:

- A refusal a person can act on is written as sentences that name what it is about and say what
  to do: the floor's denial names the missing scope and the mount's target and says how to grant
  it or change the floor; a rewrite refusal names both names and says how to declare the
  rewrite; a mount-time refusal names the rule and the prefixes it must stay inside.
- An unwired browser channel is refused at once, naming the global function the page did not
  provide, rather than leaving a request waiting with no message.
- A failure keeps its type across the boundary, so a host can say "denied" or "not found" in
  words rather than showing a generic endpoint error.
- No color, escape sequence or markup is written.

## How it is tested

- Unit tests in `src/lib.rs` pin parts of that wording:
  `an_undeclared_rewrite_is_refused_rather_than_split_in_two` (both names and "never declared"),
  `declaring_none_is_a_claim_and_a_module_that_breaks_it_is_refused`,
  `an_undeclarable_rewrite_is_refused_by_default`, `an_undeclarable_rewrite_can_be_accepted_out_loud`
  (the warning), `a_rewrite_pointing_outside_the_modules_prefixes_is_refused_at_mount_time`,
  `a_rewrite_naming_the_kernel_namespace_is_refused_at_mount_time`,
  `an_unparseable_declared_table_is_refused_at_mount_time`,
  `an_unreachable_module_is_unavailable_not_an_endpoint_string` (the channel's name), and the
  floor tests (`a_module_endpoints_declared_requirement_is_enforced_like_a_linked_ones`,
  `the_serialized_session_enforces_the_declaration_too`,
  `a_module_that_declares_nothing_does_not_thereby_become_ungated`,
  `an_iri_with_no_host_card_is_gated_exactly_as_one_with`), which check the denial names the
  endpoint or the mount.
- **No automated accessibility checker, browser or assistive technology has been used on this
  output.**

## Known limitations

Found by reading the source on 2026-10-31, not by testing:

- The protocol errors (`module answered Invoke with a description`, `expected HostResult
  answering a HostCall`, `module-protocol decode failed: …`) use the wire's own type names, name
  no module or target, and say nothing about what to do.
- Some messages print a value in Rust's debug form (`{:?}`): a browser channel that answered
  something other than bytes, and the conversion errors' rejected text.
- Messages wrap names in backticks (`` `name` ``), Markdown punctuation that a screen reader may
  read aloud in a plain-text face.

## Contributing

Read this file before changing any output listed above: a refusal, a protocol error, the warning.
Keep meaning in words, name the input a message is about, say what to do, and say in the pull
request what was tested and what was not.

## Reporting a barrier

[Open an issue](https://github.com/ikigai-rs/ikigai-module/issues/new?labels=accessibility) with
the `accessibility` label (the link sets it when GitHub lets you add labels; otherwise a
maintainer adds it): what you were doing, what happened, and your terminal or browser and any
assistive technology, if you are comfortable sharing them. Anything security-sensitive goes
through [private vulnerability reporting](https://github.com/ikigai-rs/ikigai-module/security/advisories/new).
**We acknowledge a report within 7 days**, and promise nothing further.

## Change history

| Date | Change |
|---|---|
| 2026-10-31 | First version. |
