//! `pp-gateway` — the `privacyproxy` binary: an OpenAI-compatible HTTP gateway
//! that anonymises requests (content, tool-call args, tool descriptions),
//! routes to OpenRouter's free models with failover, and rehydrates responses —
//! buffered and streaming (`ARCHITECTURE.md` §4, §5, §7, §10, §12).
#![forbid(unsafe_code)]

mod pipeline;

use std::convert::Infallible;
use std::env;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, Sse},
        IntoResponse, Response,
    },
    routing::{delete, get, post},
    Json, Router,
};
use eventsource_stream::Eventsource;
use futures::{Stream, StreamExt};
use pp_anonymize::egress_guard;
use pp_core::{Detector, EgressPolicy, Embedder, EntityKind, Memory, Vault};
use pp_detect::{
    EmailRecognizer, Ensemble, EntropyRecognizer, GazetteerRecognizer, LocalLlmRecognizer,
};
use pp_protocol::{ChatRequest, Message};
use pp_store::{HashEmbedder, LayeredVault, MemVault, MemoryStore, SqliteVault};
use pp_upstream::{
    ByteStream, ModelEntry, OpenRouterProvider, Provider, ProviderError, RouterConfig,
};
use serde_json::{json, Value};

/// Shared, immutable application state.
struct AppState {
    /// User private vocabulary (parsed once); the gazetteer is built per request.
    vocab: Vec<(String, EntityKind)>,
    /// Precise re-detection (no entropy) for the egress guard.
    guard: Ensemble,
    provider: Arc<dyn Provider>,
    /// Durable personal vault (SQLite), shared across requests.
    personal: Arc<dyn Vault>,
    /// Durable, recallable memory store (M2).
    memory: Arc<MemoryStore>,
    /// Optional semantic detector (local LLM); `None` unless configured.
    llm: Option<Arc<LocalLlmRecognizer>>,
    /// If set, clients must present `Authorization: Bearer <key>`.
    local_key: Option<String>,
}

type SharedState = Arc<AppState>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let openrouter_key = env::var("OPENROUTER_API_KEY")
        .or_else(|_| env::var("PRIVACYPROXY_OPENROUTER_KEY"))
        .unwrap_or_default();
    if openrouter_key.is_empty() {
        tracing::warn!("no OPENROUTER_API_KEY set — upstream chat calls will fail");
    }

    let local_key = env::var("PRIVACYPROXY_LOCAL_KEY")
        .ok()
        .filter(|k| !k.is_empty());
    if local_key.is_none() {
        tracing::warn!("no PRIVACYPROXY_LOCAL_KEY set — gateway auth is DISABLED (dev only)");
    }

    let bind = env::var("PRIVACYPROXY_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    let provider: Arc<dyn Provider> =
        Arc::new(OpenRouterProvider::new(openrouter_key, default_models()));

    // Durable personal vault. `:memory:` (or unset → a local file) keeps known
    // vocabulary mapped to stable placeholders across restarts.
    let db = env::var("PRIVACYPROXY_DB").unwrap_or_else(|_| "privacyproxy.db".to_string());
    let db_key = env::var("PRIVACYPROXY_DB_KEY")
        .ok()
        .filter(|k| !k.is_empty());
    let personal: Arc<dyn Vault> = Arc::new(if db == ":memory:" {
        SqliteVault::in_memory()?
    } else {
        SqliteVault::open_with_key(&db, db_key.as_deref())?
    });
    tracing::info!(encrypted = db_key.is_some(), "personal vault: {db}");

    let memory_db =
        env::var("PRIVACYPROXY_MEMORY_DB").unwrap_or_else(|_| "privacyproxy-memory.db".to_string());
    let semantic = matches!(
        env::var("PRIVACYPROXY_MEMORY_SEMANTIC").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    );
    let embedder: Option<Arc<dyn Embedder>> =
        semantic.then(|| Arc::new(HashEmbedder::default()) as Arc<dyn Embedder>);
    let memory: Arc<MemoryStore> = Arc::new(if memory_db == ":memory:" {
        MemoryStore::in_memory_with_embedder(embedder)?
    } else {
        MemoryStore::open_with_embedder(&memory_db, embedder)?
    });
    tracing::info!(semantic, "memory store: {memory_db}");

    let vocab = parse_vocab();

    // Optional local semantic detector (e.g. llama.cpp + Falcon-H1-0.5B-Instruct).
    let llm = env::var("PRIVACYPROXY_LLM_URL")
        .ok()
        .filter(|u| !u.is_empty())
        .map(|url| {
            let model = env::var("PRIVACYPROXY_LLM_MODEL")
                .unwrap_or_else(|_| "falcon-h1-0.5b-instruct".to_string());
            tracing::info!("local semantic detection: {url} ({model})");
            Arc::new(LocalLlmRecognizer::new(&url, &model))
        });

    let state = Arc::new(AppState {
        guard: build_guard(&vocab),
        vocab,
        provider,
        personal,
        memory,
        llm,
        local_key,
    });

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("PrivacyProxy listening on http://{bind}  (POST /v1/chat/completions)");
    axum::serve(listener, app(state)).await?;
    Ok(())
}

fn app(state: SharedState) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/memory", post(memory_add).get(memory_list))
        .route("/v1/memory/:id", delete(memory_delete))
        .with_state(state)
}

async fn chat_completions(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(mut req): Json<ChatRequest>,
) -> Response {
    if !authorized(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response();
    }

    // Per-request vault: durable personal layer (shared) + a fresh ephemeral
    // session layer. Placeholders are consistent within the request and never
    // leak to the client; known vocabulary stays stable across runs.
    let vault: Arc<dyn Vault> = Arc::new(LayeredVault::new(
        state.personal.clone(),
        Arc::new(MemVault::new()),
    ));

    // M2: recall memories relevant to the request and inject the cloud-safe
    // ones as system context. They flow through anonymize below, so the cloud
    // only ever sees placeholders; `local_only` memories are never injected.
    let mem_query = gather_text(&req);
    let mut recalled = state.memory.recall(&mem_query, MEMORY_RECALL_K);
    for m in state.memory.semantic_recall(&mem_query, MEMORY_RECALL_K) {
        if !recalled.iter().any(|h| h.id == m.id) {
            recalled.push(m); // fuse semantic hits (no-op unless an embedder is set)
        }
    }
    let injectable = select_injectable(recalled, MEMORY_BUDGET_TOKENS);
    if let Some(block) = memory_block(&injectable) {
        tracing::info!(memories = injectable.len(), "injecting recalled memory");
        req.messages.insert(
            0,
            Message {
                role: "system".to_string(),
                content: Some(block),
                extra: Default::default(),
            },
        );
    }

    // This request's detection floor: user vocabulary + `local_only` memory
    // terms (so memory strengthens detection on-device), then email, entropy,
    // and any terms the optional local LLM flags.
    let mut terms = state.vocab.clone();
    terms.extend(
        state
            .memory
            .local_only_terms()
            .into_iter()
            .map(|t| (t, EntityKind::Custom("private".to_string()))),
    );
    let mut detectors: Vec<Box<dyn Detector>> = Vec::new();
    if !terms.is_empty() {
        detectors.push(Box::new(GazetteerRecognizer::new(terms)));
    }
    detectors.push(Box::new(EmailRecognizer));
    detectors.push(Box::new(EntropyRecognizer::default()));
    if let Some(llm) = &state.llm {
        let found = llm.scan(&gather_text(&req)).await;
        if !found.is_empty() {
            tracing::info!(semantic = found.len(), "local LLM flagged extra entities");
            detectors.push(Box::new(GazetteerRecognizer::with_priority(found, 2)));
        }
    }
    let anonymizer = Ensemble::new(detectors);

    let audit = pipeline::anonymize_request(&mut req, &anonymizer, &*vault);
    let needs_tools = req.has_tools();
    let streaming = req.stream == Some(true);

    let sanitized = match serde_json::to_value(&req) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("serialise error: {e}"),
            )
                .into_response()
        }
    };

    // Fail closed if anything sensitive survived into an un-rewritten field.
    if let Err(leaks) = egress_guard(&sanitized.to_string(), &state.guard) {
        tracing::error!(
            count = leaks.len(),
            "egress guard tripped — blocking request"
        );
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": {
                "message": "request blocked: detected un-anonymised sensitive data in a \
                            field the gateway does not rewrite (e.g. a function name)",
                "type": "privacy_egress_guard"
            }})),
        )
            .into_response();
    }

    tracing::info!(
        redactions = audit.len(),
        needs_tools,
        streaming,
        "forwarding sanitised request"
    );

    if streaming {
        match state.provider.chat_stream(&sanitized, needs_tools).await {
            Ok(upstream) => sse_rehydrated(upstream, vault).into_response(),
            Err(err) => provider_error_response(err),
        }
    } else {
        match state.provider.chat(&sanitized, needs_tools).await {
            Ok(mut resp) => {
                pipeline::rehydrate_response(&mut resp, &*vault);
                Json(resp).into_response()
            }
            Err(err) => provider_error_response(err),
        }
    }
}

/// Transform the upstream SSE byte stream into a rehydrated SSE response: parse
/// each `data:` frame, restore placeholders in `delta.content` and tool-call
/// arguments (reassembling any split across frames), and re-emit.
fn sse_rehydrated(
    upstream: ByteStream,
    vault: Arc<dyn Vault>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = async_stream::stream! {
        let mut state = pipeline::StreamState::default();
        let mut events = upstream.eventsource();
        while let Some(item) = events.next().await {
            let event = match item {
                Ok(event) => event,
                Err(_) => break, // upstream stream error → end the response
            };
            if event.data == "[DONE]" {
                for chunk in state.flush(&*vault) {
                    yield ev(chunk.to_string());
                }
                yield ev("[DONE]".to_string());
                return;
            }
            match serde_json::from_str::<Value>(&event.data) {
                Ok(mut chunk) => {
                    pipeline::rehydrate_deltas(&mut chunk, &mut state, &*vault);
                    yield ev(chunk.to_string());
                }
                Err(_) => yield ev(event.data),
            }
        }
        // Upstream ended without an explicit [DONE]: flush any held tails.
        for chunk in state.flush(&*vault) {
            yield ev(chunk.to_string());
        }
    };
    Sse::new(stream)
}

fn ev(data: String) -> Result<Event, Infallible> {
    Ok(Event::default().data(data))
}

fn authorized(state: &AppState, headers: &HeaderMap) -> bool {
    match &state.local_key {
        None => true, // dev mode: auth disabled
        Some(expected) => headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|token| token == expected)
            .unwrap_or(false),
    }
}

fn provider_error_response(err: ProviderError) -> Response {
    let code = match &err {
        ProviderError::NoCandidates => StatusCode::INTERNAL_SERVER_ERROR,
        ProviderError::Upstream(status, _) => {
            StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY)
        }
        _ => StatusCode::BAD_GATEWAY,
    };
    tracing::error!(error = %err, "upstream call failed");
    (
        code,
        Json(json!({ "error": { "message": err.to_string(), "type": "upstream_error" } })),
    )
        .into_response()
}

/// Default OpenRouter free-model preference list (`ARCHITECTURE.md` §12, §15).
/// `tools` reflects best-known function-calling support; `gemma` is marked
/// `false` to demonstrate capability gating.
fn default_models() -> RouterConfig {
    let m = |id: &str, priority: u8, tools: bool, context: u32| ModelEntry {
        id: id.to_string(),
        priority,
        tools,
        context,
    };
    RouterConfig {
        models: vec![
            m("nvidia/nemotron-3-ultra-550b-a55b:free", 1, true, 131072),
            m("openai/gpt-oss-120b:free", 2, true, 131072),
            m("qwen/qwen3-next-80b-a3b-instruct:free", 3, true, 131072),
            m("meta-llama/llama-3.3-70b-instruct:free", 4, true, 131072),
            m("google/gemma-4-31b-it:free", 5, false, 8192),
        ],
    }
}

/// Parse the user's private vocabulary from `PRIVACYPROXY_VOCAB` (comma-separated)
/// and/or `PRIVACYPROXY_VOCAB_FILE` (one term per line; `#` comments ignored).
fn parse_vocab() -> Vec<(String, EntityKind)> {
    let env_csv = env::var("PRIVACYPROXY_VOCAB").unwrap_or_default();
    let file = env::var("PRIVACYPROXY_VOCAB_FILE").ok().and_then(|p| {
        std::fs::read_to_string(&p)
            .map_err(|e| tracing::warn!("could not read PRIVACYPROXY_VOCAB_FILE {p}: {e}"))
            .ok()
    });
    vocab_terms(&env_csv, file.as_deref())
}

/// Pure vocabulary parser: comma-separated env value plus optional file contents
/// (one term per line). Trims, drops blanks and `#` comment lines.
fn vocab_terms(env_csv: &str, file_contents: Option<&str>) -> Vec<(String, EntityKind)> {
    let env_terms = env_csv.split(',');
    let file_terms = file_contents.into_iter().flat_map(|c| c.lines());
    env_terms
        .chain(file_terms)
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(|s| (s.to_string(), EntityKind::Custom("private".to_string())))
        .collect()
}

/// Egress-guard ensemble: precise deterministic identifiers only (vocabulary +
/// email — no entropy, no LLM terms). The guard enforces the guarantee, and the
/// guarantee is the deterministic floor.
fn build_guard(vocab: &[(String, EntityKind)]) -> Ensemble {
    let mut detectors: Vec<Box<dyn Detector>> = Vec::new();
    if !vocab.is_empty() {
        detectors.push(Box::new(GazetteerRecognizer::new(vocab.to_vec())));
    }
    detectors.push(Box::new(EmailRecognizer));
    Ensemble::new(detectors)
}

/// All message text content joined — the input to recall and the local detector.
fn gather_text(req: &ChatRequest) -> String {
    req.messages
        .iter()
        .filter_map(|m| m.content.as_deref())
        .collect::<Vec<_>>()
        .join("\n")
}

// --- M2 memory ------------------------------------------------------------

const MEMORY_RECALL_K: usize = 8;
const MEMORY_BUDGET_TOKENS: usize = 400;

/// Keep only memories that may cross the cloud boundary, then select greedily
/// within a token budget (never dump all memory). `local_only` is dropped.
fn select_injectable(recalled: Vec<Memory>, budget_tokens: usize) -> Vec<Memory> {
    let mut out = Vec::new();
    let mut used = 0usize;
    for m in recalled {
        if m.egress_policy != EgressPolicy::Anonymized {
            continue;
        }
        let cost = m.content.len() / 4 + 2;
        if used + cost > budget_tokens {
            break;
        }
        used += cost;
        out.push(m);
    }
    out
}

/// Format selected memories as a system-context block, or `None` if empty.
fn memory_block(selected: &[Memory]) -> Option<String> {
    if selected.is_empty() {
        return None;
    }
    let lines = selected
        .iter()
        .map(|m| format!("- {}", m.content))
        .collect::<Vec<_>>()
        .join("\n");
    Some(format!(
        "Relevant context about the user (use only if helpful):\n{lines}"
    ))
}

fn memory_json(m: &Memory) -> Value {
    json!({
        "id": m.id,
        "content": m.content,
        "kind": m.kind,
        "egress_policy": m.egress_policy.as_str(),
        "created_ms": m.created_ms,
    })
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

async fn memory_add(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response();
    }
    let content = body["content"].as_str().unwrap_or("").trim();
    if content.is_empty() {
        return (StatusCode::BAD_REQUEST, "field 'content' is required").into_response();
    }
    let kind = body["kind"].as_str().unwrap_or("fact");
    let policy = EgressPolicy::from_storage(body["egress_policy"].as_str().unwrap_or("anonymized"));
    match state.memory.add(content, kind, policy, now_ms()) {
        Some(m) => (StatusCode::CREATED, Json(memory_json(&m))).into_response(),
        None => (StatusCode::INTERNAL_SERVER_ERROR, "could not store memory").into_response(),
    }
}

async fn memory_list(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response();
    }
    let items: Vec<Value> = state.memory.list().iter().map(memory_json).collect();
    Json(json!({ "memories": items })).into_response()
}

async fn memory_delete(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response();
    }
    if state.memory.delete(&id) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem(content: &str, policy: EgressPolicy) -> Memory {
        Memory {
            id: "x".to_string(),
            content: content.to_string(),
            kind: "fact".to_string(),
            egress_policy: policy,
            created_ms: 0,
        }
    }

    #[test]
    fn injectable_drops_local_only_and_respects_budget() {
        let recalled = vec![
            mem("alpha", EgressPolicy::Anonymized),
            mem("a secret password", EgressPolicy::LocalOnly),
            mem("beta", EgressPolicy::Anonymized),
        ];
        let selected = select_injectable(recalled, 1000);
        assert_eq!(selected.len(), 2, "local_only must be dropped");
        assert!(selected
            .iter()
            .all(|m| m.egress_policy == EgressPolicy::Anonymized));

        let many: Vec<Memory> = (0..50)
            .map(|i| {
                mem(
                    &format!("memory number {i} with some padding text"),
                    EgressPolicy::Anonymized,
                )
            })
            .collect();
        assert!(
            select_injectable(many, 40).len() < 50,
            "budget must truncate"
        );
    }

    #[test]
    fn memory_block_formats_or_none() {
        assert!(memory_block(&[]).is_none());
        let block = memory_block(&[mem("likes jazz", EgressPolicy::Anonymized)]).unwrap();
        assert!(block.contains("- likes jazz"));
    }

    #[test]
    fn vocab_from_env_and_file() {
        let v = vocab_terms(
            "Falcon, Acme Corp",
            Some("# my projects\nMercury\n\n  Apollo  \n"),
        );
        let terms: Vec<&str> = v.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(terms, vec!["Falcon", "Acme Corp", "Mercury", "Apollo"]);
        assert!(v
            .iter()
            .all(|(_, k)| matches!(k, EntityKind::Custom(s) if s == "private")));
    }

    #[test]
    fn vocab_empty_inputs() {
        assert!(vocab_terms("", None).is_empty());
        assert!(vocab_terms("  ,  ", None).is_empty());
    }
}
