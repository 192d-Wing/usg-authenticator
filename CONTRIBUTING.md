# Contributing — usg-authenticator

## Commits: Conventional Commits 1.0.0

Format: `type(scope): subject`

- **Types:** `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`, `security`.
- **Scopes:** `pacp`, `pae`, `radius-client`, `radsec`, `enforce`, `enforce-sonic`, `eapol-io`, `authd`, `cli`, `kat`, `workspace`, `docs`.
- Subject: imperative mood, ≤72 chars, no trailing period.
- Breaking changes: `type(scope)!: ...` and a `BREAKING CHANGE:` footer.

Enable the message template once: `git config commit.template .gitmessage`

## Branching

- One branch per milestone: `feat/<area>-<short>` (e.g. `feat/pacp-eapol-codec`).
- **Every branch gets a code review for logic bugs and vulnerabilities before merge.** Fail closed: trust/crypto/parse errors must never silently degrade.

## Security baseline (non-negotiable)

- `#![forbid(unsafe_code)]` in all pure crates (`pacp`, `pae`, `radius-client`, `enforce`, `kat`). `unsafe` is confined to FFI/syscall crates (`eapol-io`) and must be justified in-comment.
- No panics on attacker-controlled input: parsers return `Result`, never `unwrap`/`expect`/indexing that can panic on malformed bytes.
- No `as` truncation on lengths; use checked conversions.
- Deny lints in CI (see `Cargo.toml` workspace lints).
- Authorization is **fail-closed**: any parse/trust/enforcement failure leaves the port unauthorized.
