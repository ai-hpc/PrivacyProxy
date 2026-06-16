# Contributing to PrivacyProxy

Thanks for your interest! PrivacyProxy is an on-device, OpenAI-compatible **privacy gateway for AI agents** — it anonymizes prompts and tool I/O locally, routes to OpenRouter's free models, and rehydrates the response, so you get strong reasoning without handing your confidential data to endpoints that log and train on their input.

Please read **[ARCHITECTURE.md](ARCHITECTURE.md)** first — it is the source of truth for the design, and most contributions should trace back to a decision documented there.

## Project status

Early. The architecture is defined; the Rust workspace (milestone **M1**) is being scaffolded, so expect things to move. The highest-value contributions right now are listed under [Ways to contribute](#ways-to-contribute).

## The privacy contract (non-negotiable)

PrivacyProxy is a privacy tool, so a few rules override normal convenience. A PR that weakens any of these will not be merged regardless of its other merits:

1. **Fail closed.** If the egress guard cannot prove a payload is safe, it must block — never "best effort." Do not add a path that sends data upstream when detection is uncertain.
2. **The deterministic floor is the guarantee.** Regex / entropy / gazetteer detection is what we promise. Statistical or LLM-based detection only *adds* recall; it never replaces the floor.
3. **Never log plaintext.** No logging of original (pre-anonymization) content, secret values, or the placeholder→original map. Logs may contain placeholders and metadata only.
4. **Never commit secrets or the Vault.** `.env` and `*.db` / `*.sqlite` are git-ignored on purpose — the Vault holds plaintext originals. Don't override that.
5. **Detector/transform changes need a leak test.** Add fixtures (e.g. `.env` dumps, stack traces, PII-laden tool output) and assert that zero original bytes survive in the outbound payload.

## Ways to contribute

- **Detection rules** — new regex/entropy recognizers, private-vocab/gazetteer matching, and false-positive / false-negative fixtures.
- **Protocol compatibility** — making real agents (OpenClaw, Hermes, Genie-Claw, Cursor, Open WebUI, …) work cleanly against the gateway; edge cases in tool-calling and streaming.
- **Provider / router** — OpenRouter failover, capability gating, new model entries, output-format repair for free models.
- **Architecture review** — poke holes in `ARCHITECTURE.md`, especially the privacy/utility tradeoff and the streaming-rehydration state machine.
- **Docs & examples** — setup guides and client-integration recipes.

For anything large or design-altering, **open an issue or discussion first** so we can align before you build.

## Development setup

Requires a recent stable Rust toolchain ([rustup](https://rustup.rs/)).

```bash
git clone https://github.com/ai-hpc/PrivacyProxy.git
cd PrivacyProxy

# once the workspace lands:
cargo build
cargo test                                  # includes the leak-test harness
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

### Validating docs (Mermaid diagrams)

`ARCHITECTURE.md` is diagram-heavy and every Mermaid block must parse against the real engine. Before submitting documentation changes:

```bash
npm i mermaid jsdom                          # in the repo root; node_modules is git-ignored
node scripts/check-mermaid.mjs ARCHITECTURE.md
```

The script exits non-zero and prints the offending block + parser error if any diagram is invalid.

## Pull requests

- Keep PRs small and focused on one change.
- Use [Conventional Commits](https://www.conventionalcommits.org/) for messages (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, …).
- Ensure `cargo fmt`, `cargo clippy`, and `cargo test` are clean — plus the Mermaid check for doc changes.
- Describe *what* changed and *why*, and link the issue/discussion and the relevant `ARCHITECTURE.md` section.

## Coding standards

- Idiomatic Rust; `cargo clippy` clean with no warnings.
- No `unwrap()` / `expect()` / `panic!` on non-test code paths — return `Result` and handle the error.
- `pp-core` stays I/O-free; side effects belong in the outer crates.
- New public behavior ships with tests; privacy-affecting behavior ships with **leak tests**.

## Reporting security & privacy issues

**Do not open a public issue for a vulnerability or a data-leak bug.** Report it privately through the repository's **Security** tab ("Report a vulnerability"). Given the threat model, any path that lets confidential data reach an upstream provider is a security bug — please treat it as one.

## License

This project does not yet ship a `LICENSE`; one will be added before the first release. By contributing, you agree that your contributions will be licensed under the license the project adopts.
