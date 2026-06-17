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
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use eventsource_stream::Eventsource;
use futures::{Stream, StreamExt};
use pp_anonymize::egress_guard;
use pp_core::{Detector, EntityKind, Vault};
use pp_detect::{
    EmailRecognizer, Ensemble, EntropyRecognizer, GazetteerRecognizer, LocalLlmRecognizer,
};
use pp_protocol::ChatRequest;
use pp_store::{LayeredVault, MemVault, SqliteVault};
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
    let personal: Arc<dyn Vault> = Arc::new(if db == ":memory:" {
        SqliteVault::in_memory()?
    } else {
        SqliteVault::open(&db)?
    });
    tracing::info!("personal vault: {db}");

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

    // This request's detection floor, optionally augmented by terms the local
    // semantic detector flags (best-effort; never weakens the floor guarantee).
    let mut detectors: Vec<Box<dyn Detector>> = Vec::new();
    if !state.vocab.is_empty() {
        detectors.push(Box::new(GazetteerRecognizer::new(state.vocab.clone())));
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

/// Parse the user's private vocabulary from `PRIVACYPROXY_VOCAB` (comma-separated).
fn parse_vocab() -> Vec<(String, EntityKind)> {
    env::var("PRIVACYPROXY_VOCAB")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
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

/// All message text content joined — the input to the optional semantic detector.
fn gather_text(req: &ChatRequest) -> String {
    req.messages
        .iter()
        .filter_map(|m| m.content.as_deref())
        .collect::<Vec<_>>()
        .join("\n")
}
