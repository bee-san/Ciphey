# Security Policy

This document is the canonical security policy for `ciphey`.

## Supported Versions

Security fixes are applied on `master`.

| Version | Supported |
| --- | --- |
| `master` | Yes |
| Latest tagged release | Best effort |
| Older releases | No |

If a fix is shipped in a release, assume older releases remain vulnerable unless explicitly noted otherwise.

## Reporting A Vulnerability

Do not open a public GitHub issue for a suspected vulnerability.

Report it privately to `bee@skerritt.blog` with a subject like `[ciphey security] <short summary>`.

If the GitHub UI shows a `Report a vulnerability` option for this repository, you can use that private reporting flow instead of email.

Include:

- affected version, commit, or branch
- operating system and how you installed `ciphey`
- a short impact statement
- reproduction steps or a proof of concept
- whether the issue requires local access, crafted input, or user interaction

Plain text email is acceptable. If you need a different reporting channel, ask in the initial email.

## What To Expect

Maintainers will aim to:

- acknowledge the report within 72 hours
- confirm whether the issue is in scope
- share status updates while a fix is being prepared
- credit the reporter after disclosure, if requested

Please allow time for a fix before public disclosure.

## Related Security Documents

- Incident response process: [incident_response.md](incident_response.md)
- Project threat model: [threat_model.md](threat_model.md)

## Scope Notes

Issues that are especially relevant for this project include:

- crashes, hangs, or resource-exhaustion bugs triggered by untrusted input
- unsafe handling of local files passed through the CLI
- data exposure involving `~/.ciphey/config.toml` or `~/.ciphey/database.sqlite`
- supply-chain issues in release artifacts or dependencies that materially affect users of `ciphey`

## User Data And Secrets

Current repository behavior that matters for security review:

- `ciphey` stores cache and human-review data in a local SQLite database at `~/.ciphey/database.sqlite`.
- Configuration is stored locally at `~/.ciphey/config.toml`.
- `ciphey` asks for no tokens or credentials and downloads nothing. (The first-run "enhanced detection" prompt, which asked for a Hugging Face token to download a model that was never used, was removed; see [#1031](https://github.com/bee-san/Ciphey/issues/1031).)

If you report an issue, avoid sending real secrets or private datasets unless they are necessary to reproduce the problem.
