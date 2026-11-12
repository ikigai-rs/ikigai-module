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
| Last reviewed | 2026-11-12 |

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

The libraries provide text, not a page or terminal interface. The host controls presentation,
focus, wrapping and announcements. Module-provided wording and values can pass through;
this library does not establish their accessibility. Documentation (`README.md`, the ABI
README, Rust API documentation and this file) is also read on GitHub or in an editor or browser.

## The rules that output follows

Reviewed in source on 2026-11-12; these observations are not an end-to-end accessibility evaluation:

- A refusal a person can act on is written as sentences that name what it is about and say what
  to do: the floor's own denial names the missing scope and the mount's target and says how to
  grant it or change the floor (the kernel can refuse first with its own message); a rewrite
  refusal names both names and says how to declare the
  rewrite; a mount-time refusal names the rule and the prefixes it must stay inside.
- An unwired browser channel is refused at once, naming the global function the page did not
  provide, rather than leaving a request waiting with no message.
- A failure keeps its type across the boundary, so a host can say "denied" or "not found" in
  words rather than showing a generic endpoint error.
- Repository-authored messages use words rather than color to carry meaning. Backticks occur
  in messages; module-provided text and interpolated values are not covered by this observation.

## How it is tested

Every named check has a result: Pass, Fail or Blocked. Pass covers only the stated assertions,
not overall accessibility or WCAG conformance. On 2026-11-12, `cargo test --workspace` ran on
main at `a923ca15f14ee5959df9f82c0bb2576233825075`, using Cargo 1.99.0
(`5f94df478`) and rustc 1.99.0 (`b940084d7`) on Linux. It passed 66 unit/integration tests
and 6 documentation tests; 3 documentation examples were ignored. The repository's
[CI workflow](.github/workflows/ci.yml) repeats the workspace test command. Native fixtures
exercise message content and transport behavior, not a browser or assistive technology.

| Check | Result | Evidence |
|---|---|---|
| Undeclared rewrite refusal names both resources | Pass | `cargo test --workspace`, `src/lib.rs`: `an_undeclared_rewrite_is_refused_rather_than_split_in_two` asserts both names and “never declared”; `declaring_none_is_a_claim_and_a_module_that_breaks_it_is_refused` asserts the refusal. Does not evaluate spoken comprehension. |
| Undeclarable rewrite refusal and warning | Pass | Same command, `src/lib.rs`: `an_undeclarable_rewrite_is_refused_by_default` checks “cannot declare” and the reason; `an_undeclarable_rewrite_can_be_accepted_out_loud` checks the warning sink receives “cannot declare”. Does not check a host displays or announces it. |
| Mount-time rewrite refusal identifies the category | Pass | Same command, `src/lib.rs`: `a_rewrite_pointing_outside_the_modules_prefixes_is_refused_at_mount_time`, `a_rewrite_naming_the_kernel_namespace_is_refused_at_mount_time`, `an_unparseable_declared_table_is_refused_at_mount_time` check diagnostic fragments. Does not prove every refusal gives an understandable recovery step. |
| Capability denial identifies the required scope | Pass | Same command, `src/lib.rs`: `a_module_endpoints_declared_requirement_is_enforced_like_a_linked_ones`, `the_serialized_session_enforces_the_declaration_too`, `a_module_that_declares_nothing_does_not_thereby_become_ungated`, `an_iri_with_no_host_card_is_gated_exactly_as_one_with` check denial and the required scope. Does not assert the mount-specific recovery hint: the kernel can refuse first. Does not test comprehension of capability terminology. |
| Unreachable transport keeps its failure type and channel name | Pass | Same command, `src/lib.rs`: `an_unreachable_module_is_unavailable_not_an_endpoint_string` asserts `Unavailable` and `stubInvokeSession` using a native stand-in. Does not execute the JavaScript global lookup in `wasm_module_channel!`. |
| Error types survive the module boundary | Pass | Same command, `tests/conformance.rs`: `typed_errors_survive_in_both_directions` and `a_module_side_refusal_is_a_typed_denied_over_every_transport`; `tests/abi_compat.rs`: `the_error_mirror_round_trips_every_variant`. Checks type preservation, not host presentation or announcements. |
| Protocol errors identify the affected resource and recovery action | Fail | Source review on 2026-11-12, `src/lib.rs`: `outcome_from`, `answer_from` and `decode` use protocol names and give no target or recovery action; see limitations below. No user comprehension test. |
| Conversion and channel errors avoid debug notation | Fail | Source review on 2026-11-12, `src/convert.rs` (`iri`, `arg_from_abi`) and `src/lib.rs` (`__js_channel_call!`) still use Rust debug formatting for some values. |
| Message punctuation is understandable when spoken | Blocked | Backticks remain in messages, including `GivenTwice::fmt` in `crates/ikigai-module-abi/src/lib.rs`. No screen reader session was available; source inspection cannot establish spoken comprehension. |
| Meaning without color, escape sequences or markup in host output | Blocked | Historical source review on 2026-10-31 reported no color, escape sequences or markup. CI does not repeat that review; no host rendering evaluation was available for this update. Interpolated and module-provided text needs separate evaluation. |
| Browser rendering, zoom, reflow and contrast of documentation and hosted messages | Blocked | No browser evaluation was run for this update. The libraries provide no page; documentation renderers and consuming hosts still need evaluation. |
| Manual keyboard | Blocked | No person performed a keyboard pass on documentation or a consuming host; no interactive evaluation session was available. |
| Automated accessibility checker | Blocked | No axe or other accessibility checker was configured or run on rendered documentation or a consuming host for this update. Rust tests are not an accessibility checker. |
| Screen reader | Blocked | No screen reader session was available or used on this output for this update. |
| Screen magnifier | Blocked | No screen magnifier session was available or used on this output for this update. |
| Speech input | Blocked | No speech-input session was available or used on this output for this update. |
| Switch access | Blocked | No switch-access session was available or used on this output for this update. |
| Braille display | Blocked | No braille display was available or used on this output for this update. |

## Known limitations

Confirmed by source review on 2026-11-12, not by assistive-technology testing:

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
request what was tested and what was not. In the pull request's `## Accessibility` section,
give every check a row in a Check | Result | Evidence table: Pass, Fail or Blocked, with the
test or command and tool version, or why it could not run. Keep unrun checks Blocked,
including each assistive technology nobody used. A historical run CI does not repeat is
Blocked with its date, not Pass.

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
| 2026-11-12 | Record check results, current native test evidence, known failures and blocked browser and assistive-technology evaluations. |
