# openWallet-code

The **code leg** of the `openwallet` project: the implementation and its
tests. The requirements it implements live in
[`opensoft/openWallet-spec`](https://github.com/opensoft/openWallet-spec).

**Clone the assembly root, not this repository.** This leg is mounted as a
submodule at `code/` inside
[`opensoft/openWallet`](https://github.com/opensoft/openWallet), which
is what pins the commit of this repository that the project currently is:

```sh
git clone --recurse-submodules https://github.com/opensoft/openWallet.git
cd openWallet
make bootstrap
```

Working here directly is fine — it is an ordinary repository with an ordinary
branch. What advancing this leg does NOT do is advance the project: that is a
commit in the assembly root moving the gitlink, `contracts/code-pin.yaml` and
any workflow `@<sha>` reference together.

Being the code leg confers no authority over the implementation. The split is
navigation; authority travels in grants, and a project that keeps spec and
code in one repository is reviewed identically.

Topic: `xf-project-openwallet`.

## Status: carved

Content was carved from
[opensoft/openXwallet](https://github.com/opensoft/openXwallet) at
`90111df262d6f54f7e82651d860adc12345f83f4` and landed as this repository's #2
(merge `72313daa`). openXwallet's `docs/openwallet-carve-manifest.yaml`
declares every path that moved here, byte for byte and at an unchanged
repository-relative path. The declared edits were applied on top of the pure
carve as one auditable diff. The procedure is the assembly root's
`docs/openwallet-cutover-runbook.md`. The assembly root pins this leg at
`72313daa` (`wallet-v1.6`, at the time of writing). Post-carve maintenance
follows, starting with task 8.2 of openXwallet's
`split-openwallet-neutral-core`.

## What this leg owns after the split

- both contract families, `contracts/openxwallet/` and
  `contracts/openxwallet-agent-profile/`, with the eight digested artifacts at
  unchanged sha256 and the packaged corpus;
- the corpus binding, the one declared vocabulary the corpus is validated
  against;
- the conformance validator `scripts/validate-openxwallet.py`;
- the syntax gate `scripts/wallet-yaml-syntax-gate.py`;
- their tests, under `tests/`;
- the checks `wallet-validation` and `pytest-suite`, which run from INSIDE this
  leg. A validator run from the assembly root scans nothing and is never a gate.

The contracts sit here, beside the validator that reads them, by a declared
override of openRepoShape's default (Brett Heap, 2026-10-08, RULED Q7). The
specifications live in
[`opensoft/openWallet-spec`](https://github.com/opensoft/openWallet-spec). The
release identity (manifest, CHANGELOG, release records, proof and tag) lives in
the assembly root.

## Pinning openWallet

Consumers pin the ASSEMBLY ROOT by commit and digest, and verify this leg
through the root's lockstep. Inside a consumer, a path `P` here is
`openWallet/code/P`, and its sha256 is the same at every depth. Domain
descendants pin a version and carry a profile. They never fork.

## Gates

Every gate is offline: no check reads the network, an upstream tree, a sibling
leg or the root's manifest. The vendored openxFactory envelope does not travel
here. The approval vocabulary is one declared binding that the caller supplies.

## Agents

See [`AGENTS.md`](AGENTS.md) and [`CLAUDE.md`](CLAUDE.md). Both point at the
shared OpenSpec/Speckit protocol, which runs from the assembly root.
