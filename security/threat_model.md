# Threat Model

This document outlines all the threats Ciphey may face.

## System Overview

`ciphey` is a local decoding tool with a thin CLI over a library-first core. Users provide ciphertext, files and configuration. The search pipeline runs decoders and checkers against attacker-controlled input and stores some local state under `~/.ciphey`.

## Security Goals

- protect local secrets and sensitive user data (the api keys)
- avoid unsafe handling of attacker-controlled input (so no CLI escapes)
- preserve integrity of release artifacts and repository automation (so users don't download malicious releases)

## Key Assets

- local files passed through `--file`
- `~/.ciphey/config.toml`
- `~/.ciphey/database.sqlite`
- release artifacts, workflow definitions, and dependency metadata

## Trust Boundaries

- CLI arguments, stdin, and file contents are untrusted input. Because Ciphey is local we should trust the user knows what they are doing.
- Decoder and checker execution must treat transformed candidate strings as untrusted.
- Wordlists the user points ciphey at are files from outside, read as untrusted input. Ciphey downloads nothing itself.
- SQLite-backed persistence is trusted only as local state owned by the current user, not as authoritative truth from a trusted server.
- GitHub workflows, release automation, and repository settings form the supply-chain boundary for published artifacts.

## STRIDE Threat Analysis

### Spoofing

Relevant risks:

- release automation or dependency sources are impersonated through compromised credentials, tags, or workflow context

Mitigations:

- prefer authenticated, explicit sources for release and dependency operations
- protect repository settings, default branch controls, and workflow credentials
- Ensure no 1 maintainer can cut a release, and the maintainers that do have PGP keys and MFA setup.

### Tampering

Relevant risks:

- attacker-controlled input or local persistence modifies later decode behavior in unexpected ways
- SQLite-backed cache or human-review data is poisoned and later reused as if it were trustworthy
- workflow definitions, release artifacts, or dependency metadata are modified without appropriate review

Mitigations:

- keep storage behavior explicit and predictable
- check a cached plaintext with the current checkers (and the human checker, if it is on) before returning it, and forget it if it fails
- use test helpers instead of the real user database in tests
- review SQLite changes in the source code for corruption, injection, and persistence-boundary risks

### Repudiation

Relevant risks:

- maintainers cannot reconstruct what was changed, when a vulnerable artifact was published, or which workflow introduced it
- incident evidence is incomplete because logs, reproduction steps, or affected revisions were not recorded

Mitigations:

- capture the affected version, commit, impact, and reproduction details during intake (releases in GitHub does this)
- keep release and workflow changes traceable through reviewed commits and pull requests
- record advisory IDs, affected revisions, and mitigation steps in incident notes

### Information Disclosure

Relevant risks:

- local files passed through `--file` may contain sensitive content that is mishandled or overexposed (via logging)
- configuration or database contents are logged, persisted, or disclosed unintentionally
- plaintext-identification logic classifies secrets or credentials as meaningful plaintext and surfaces them unnecessarily

Mitigations:

- keep file access explicit and local to user-requested paths
- do not log or persist tokens unnecessarily
- validate checker changes with representative encoded and plaintext examples
- treat secret-like output as a security consideration during checker tuning

### Denial Of Service

Ciphey is entirely locally run, the only risk of a DoS attack is from the trusted user themselves.

### Elevation Of Privilege

Relevant risks:

- unsafe Rust, FFI, or C bindings violate memory-safety assumptions and create behavior outside intended trust boundaries
- workflows or automation receive broader token permissions than required and can take actions beyond their intended scope
- local persistence or setup flows gain authority they should not have over later runs or release processes

Mitigations:

- review `unsafe`, FFI, regex, file-handling, and SQLite changes as security-sensitive
- apply least-privilege permissions to GitHub Actions workflows and automation tokens
- keep setup, persistence, and release boundaries narrow and explicit

## Assumptions And Out Of Scope

- A fully compromised user workstation is out of scope.
- Ciphey makes no network requests at runtime, so network threats are limited to dependency/release workflows.
- `ciphey` is a local analysis tool, not a sandbox for safely executing untrusted code.
