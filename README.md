# PrivacyProxy

**An on-device, OpenAI-compatible privacy gateway for AI agents.** Use the strongest *free* models on OpenRouter — the ones that log and train on everything you send — without ever exposing your confidential data.

> Your data stays local. Your reasoning is rented for free.

Point any OpenAI-compatible client (agent, chat UI, IDE) at `http://localhost:8080/v1`. PrivacyProxy anonymizes prompts, tool definitions, and tool-call arguments **locally**, forwards only sanitized text to OpenRouter, and restores your real data in the response — so the cloud model reasons over `__PERSON_1__` and `__PRIVATE_1__`, never `Alex` or `Falcon`.

## Why

The free endpoints are explicit: *"do not upload any confidential information … your use is logged … to improve [the provider's] products and services."* PrivacyProxy is the layer that lets you use them anyway. The adversary isn't a hacker — it's the provider's **lawful logging pipeline** — and the guarantee is one testable property:

> **No bytes you'd consider confidential ever reach the upstream API.**

## Status

Early but working. The M1 core is functional and **validated live** against OpenRouter free models:

| Capability | |
|---|---|
| OpenAI `/v1/chat/completions` (buffered) | ✅ |
| Streaming (SSE) with split-safe rehydration | ✅ |
| Agent tool-calling (tools schema + tool-call arguments) | ✅ |
| Capability-aware failover across free models | ✅ |
| Fail-closed egress guard | ✅ |
| Optional on-device semantic detection (local LLM) | ✅ (opt-in) |
| Local memory (M2): recall · policy-filtered injection · audit export | ✅ |

Not yet: dedicated ONNX in-process NER, multimodal content, conversational memory extraction. See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the full design. The **M2 local-memory** system (adapted from [genie-claw](https://github.com/GeniePod/genie-claw)) is designed and implemented per **[doc/MEMORY.md](doc/MEMORY.md)**.

## How it works

```mermaid
flowchart LR
    client["your agent / chat UI"] -->|"real data"| pp["PrivacyProxy<br/>:8080"]
    pp -->|"sanitized only"| or["OpenRouter<br/>free models"]
    or -->|"response with placeholders"| pp
    pp -->|"real data restored"| client
    pp -.->|"never leaves the box"| vault[("local vault<br/>+ your vocabulary")]

    style pp fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    style or fill:#ffebee,stroke:#c62828
    style vault fill:#fff3e0,stroke:#e65100
```

## Quick start

Requires a stable [Rust toolchain](https://rustup.rs/).

```bash
git clone https://github.com/ai-hpc/PrivacyProxy.git
cd PrivacyProxy
cargo build --release

export OPENROUTER_API_KEY=sk-or-...                 # a free OpenRouter key
export PRIVACYPROXY_VOCAB="Falcon, Acme Corp"        # your private terms
./target/release/privacyproxy                        # listens on 127.0.0.1:8080
```

Then any OpenAI client works unchanged:

```bash
curl -s http://localhost:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"auto","messages":[{"role":"user",
       "content":"Email alex@example.com about Project Falcon."}]}'
```

The cloud model receives `Email __EMAIL_1__ about Project __PRIVATE_1__.` — your client gets the real values back.

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8080/v1", api_key="unused")
```

## What gets anonymized

The deterministic detection floor — pure Rust, no external services:

- **Private vocabulary** — your terms from `PRIVACYPROXY_VOCAB` (the primary, most reliable detector).
- **Emails** — `local@domain.tld`.
- **Secrets** — high-entropy tokens (API keys and the like), redacted **irreversibly**: the model sees `__SECRET_1__` and it is never restored.

Reversible entities round-trip (placeholder out, real value back); secrets are redact-only. The same vault drives message content, tool-call arguments, and tool descriptions.

**Optional on-device semantic layer.** With `PRIVACYPROXY_LLM_URL` set, the gateway also asks a small local model to flag sensitive names the rules miss — people, organizations, projects. It's best-effort recall: if the model is unavailable, slow, or wrong, the deterministic floor still protects you. The model only ever sees your *local* text (it's part of the trusted layer) and is **never** part of the guarantee.

```bash
# e.g. via llama.cpp, on-device
llama-server -m falcon-h1-0.5b-instruct.gguf --port 8081
export PRIVACYPROXY_LLM_URL=http://127.0.0.1:8081
```

## Memory (M2)

The gateway can remember facts/preferences and recall the relevant ones into a request — **anonymized in-band**, so the cloud only ever sees placeholders.

```bash
# remember something
#   anonymized (default) = may be injected, but masked by the pipeline
#   local_only           = never sent to the cloud
curl -s localhost:8080/v1/memory -H content-type:application/json \
  -d '{"content":"User prefers concise answers","kind":"preference"}'

curl -s localhost:8080/v1/memory/export   # human-auditable Markdown of what's stored
```

`local_only` memories are never injected into a cloud request; instead they **seed the gazetteer**, so their terms are masked everywhere. Recalled memories are tracked and promoted with use. Design + provenance (adapted from genie-claw): **[doc/MEMORY.md](doc/MEMORY.md)**.

## Configuration

| Env var | Purpose | Default |
|---|---|---|
| `OPENROUTER_API_KEY` | free OpenRouter key | _(required for upstream calls)_ |
| `PRIVACYPROXY_VOCAB` | comma-separated private terms | empty |
| `PRIVACYPROXY_LOCAL_KEY` | require `Authorization: Bearer <key>` from clients | unset → auth disabled (dev) |
| `PRIVACYPROXY_BIND` | listen address | `127.0.0.1:8080` |
| `PRIVACYPROXY_DB` | durable vault path (`:memory:` for ephemeral) | `privacyproxy.db` |
| `PRIVACYPROXY_LLM_URL` | local OpenAI-compatible endpoint for semantic detection | unset (off) |
| `PRIVACYPROXY_LLM_MODEL` | model name for the semantic detector | `falcon-h1-0.5b-instruct` |
| `PRIVACYPROXY_DB_KEY` | passphrase to encrypt the durable vault at rest (AES-256-GCM) | unset (plaintext) |
| `PRIVACYPROXY_VOCAB_FILE` | file of vocabulary terms, one per line (`#` comments) | unset |
| `PRIVACYPROXY_MEMORY_DB` | memory store path (`:memory:` for ephemeral) | `privacyproxy-memory.db` |
| `PRIVACYPROXY_MEMORY_SEMANTIC` | `1` enables semantic recall (hash embedder) | off |

## Limitations (honest)

- **Structural tool fields** (function names, parameter keys) aren't anonymized — they can't carry the placeholder sentinel. If one contains PII, the egress guard **blocks** the request (fail-closed) rather than leak it.
- **The guarantee is the deterministic floor** (vocabulary + email + secrets). The optional local LLM adds best-effort recall but isn't part of the guarantee, and its quality depends on the model you run. A dedicated ONNX in-process NER is a future backend behind the same seam.
- **Two-layer vault** — known vocabulary persists durably (SQLite); emails/secrets/discovered entities are ephemeral per request. Stored originals can be **encrypted at rest** (AES-256-GCM) by setting `PRIVACYPROXY_DB_KEY`; otherwise they're plaintext in the local (git-ignored) DB.
- **Output quality** ≈ free-model ceiling × context surviving anonymization. Coding and agent work fit best, since logic and structure survive masking.

## Project layout

```
crates/
  pp-core        domain types + Detector/Vault traits (no I/O)
  pp-detect      detection: gazetteer · email · entropy · optional local-LLM
  pp-anonymize   anonymize · rehydrate · streaming StreamRehydrator · egress guard
  pp-store       vaults: in-memory · SQLite · two-layer (durable + ephemeral)
  pp-upstream    Provider + OpenRouter client with capability-aware failover
  pp-protocol    OpenAI-compatible wire types
  pp-gateway     the `privacyproxy` binary: axum server + pipeline
```

## Contributing

See **[CONTRIBUTING.md](CONTRIBUTING.md)** — note the non-negotiable privacy contract. Licensed under [MIT](LICENSE).
