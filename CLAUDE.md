# Agent Instructions

## Shared OpenSpec/Speckit Protocol

This repo uses the user-global OpenSpec/Speckit workflow instead of duplicating
process rules in every repository.

- Global agent entrypoint: `$HOME/.agents/AGENTS.md`
- Workflow protocol: `$HOME/.agents/protocols/openspec-speckit-workflow.md`
- Bootstrap contract: `$HOME/.agents/protocols/project-agent-bootstrap.md`

Repo-local documents remain authoritative for project-specific commands, runtime
prerequisites, source-of-truth docs, tests, and release constraints. See
[`AGENTS.md`](AGENTS.md) for the rules of this leg of openWallet and the way back
to its assembly root, and [`README.md`](README.md) for what this repository
owns.
