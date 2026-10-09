This is the **code leg** of openWallet (`openwallet`): the implementation
and its tests.

**The project's rules are not here.** They are in the assembly root
`opensoft/openWallet`, in `AGENTS-shape.md` — read that before touching anything
that spans the legs. This leg is mounted there at `code/`, and the other leg,
`opensoft/openWallet-spec`, beside it at `../spec/`, once the root is cloned with
`--recurse-submodules`.

Working here is ordinary — an ordinary repository on an ordinary branch. What
advancing this leg does NOT do is advance the project: that is ONE commit in
`opensoft/openWallet` moving the gitlink, `contracts/code-pin.yaml` and every
workflow `@<sha>` for this leg together.

Being the code leg confers no authority over the implementation. The split is
navigation.

## Shared OpenSpec/Speckit protocol

Use the shared OpenSpec/Speckit workflow from:

- `$HOME/.agents/AGENTS.md`
- `$HOME/.agents/protocols/openspec-speckit-workflow.md`
- `$HOME/.agents/protocols/project-agent-bootstrap.md`

Repository documents remain authoritative for openWallet product facts, contract
ownership, validation, versioning, and release constraints.

This is a three-leg project, and the protocol runs from the assembly root. The
root holds `.specify/`. `openspec/` and the Speckit feature directories are in
the spec leg. This leg holds the implementation and its tests, and a feature's
work here happens in `worktrees/<NNN-feature-name>/code/` under the root.

## What this leg is

**Status: carved.** This leg's content was carved from opensoft/openXwallet at
`90111df262d6f54f7e82651d860adc12345f83f4` and landed as this repository's #2
(merge `72313daa`). The carve was governed by openXwallet's
`split-openwallet-neutral-core` (tracked in opensoft/openXwallet#25), and its
declared path mapping is openXwallet's `docs/openwallet-carve-manifest.yaml`.
The assembly root pins this leg at `72313daa` (`wallet-v1.6`, at the time of
writing). Post-carve maintenance follows, starting with that change's task 8.2.

After the split this leg owns the neutral wallet standard's bytes, every path at
the repository-relative path it had in openXwallet at the carve commit:

- **both contract families.** These are `contracts/openxwallet/` (less the three
  `grant-review-*` negatives, which stay in openXwallet) and
  `contracts/openxwallet-agent-profile/`. They hold the eight digested artifacts
  at unchanged sha256, and the packaged corpus with both `examples/` prefixes
  intact;
- **the corpus binding**, added under `contracts/openxwallet/examples/` (RULED
  Q6);
- **the conformance validator**, `scripts/validate-openxwallet.py`. Its diff
  from the carve is the declared hunks (a)-(e) plus post-carve maintenance
  commits, each reviewed as a contract-behaviour change. The first is task
  8.2's code-leg part, the format-checker refusal's pointer;
- **the syntax gate**, `scripts/wallet-yaml-syntax-gate.py`;
- **their tests**: `tests/wallet_yaml_syntax_gate/`, `tests/multi_key_wallets/`
  and the prune half of `tests/nested_repo_prune/`;
- **the checks `wallet-validation` and `pytest-suite`**, run from INSIDE this
  leg. `wallet-validation` arrived without its envelope-verify step.

The contracts are here, beside their validator, by a ruling: Brett Heap,
2026-10-08, "Code leg, declared override (Recommended)" (RULED Q7). It overrides
openRepoShape's `spec-governance` default, which would send `contracts/**` to
the spec leg. The carve manifest declares the override on each of the 73 rows it
governs.

Two things are NOT here. The specifications, archives and Speckit features are
in the spec leg, `opensoft/openWallet-spec`. The release identity (the
manifest, CHANGELOG, release records, proof and tag) is in the assembly root.
Each artifact's per-file `contract_schema_version` stays inside its own bytes,
here.

## The rules that are not negotiable here

1. **Consumers pin; nobody forks.** Consumers pin openWallet's ASSEMBLY ROOT by
   commit and digest, and verify this leg through the root's lockstep. They
   never pin this leg directly. Domain descendants pin a version and carry a
   profile, and never fork. A need a profile cannot express is an upstream
   change, made through the spec leg's OpenSpec instance.
2. **Machine keys do not move casually.** Paths, `kind:` values, capability ids,
   the `xfactory_wallet_*` prefix, finding codes and filenames are pinned BY
   NAME by live consumers, which reach them as `openWallet/code/<path>`. Renaming
   one is a breaking change with a migration note, never a tidy-up.
3. **Every gate is offline.** No check reads the network, an upstream tree, a
   sibling leg or the root's `contracts/manifest.yaml`. openxFactory's vendored
   job envelope does not travel here, and nothing here reads it. The approval
   vocabulary is ONE DECLARED BINDING that the caller supplies, and a posture
   with no binding declared is refused (RULED Q6).
4. **The wallet checks run from this leg's root, and never from the assembly
   root.** A validator run from the root prunes both legs (each holds a `.git`
   entry), scans nothing and exits 0. That was MEASURED (openXwallet
   `design.md` D7). It is therefore never wired as a gate. The checks are this
   leg's `wallet-validation` and `pytest-suite`.
5. **Run the gates before pushing**, from this leg's root: the syntax gate,
   the validator (plain and `--strict`) and `python3 -m pytest tests/ -q`. These
   are openXwallet's rule-5 gates less its pin verifier, whose envelope does
   not travel.
6. **No leg is tagged.** A release is five coordinated values, realized across
   one assembly-root commit and the leg commits it pins. The annotated
   `wallet-v*` tag goes on the root, and only after the proof is green.
