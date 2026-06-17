//! `pp-gateway` — the `privacyproxy` binary: an OpenAI-compatible HTTP gateway
//! that anonymises requests, routes to OpenRouter's free models with failover,
//! and rehydrates responses — buffered and streaming (`ARCHITECTURE.md` §5,
//! §10, §12).
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
use pp_anonymize::{egress_guard, StreamRehydrator};
use pp_core::{Detector, EntityKind, Vault};
use pp_detect::{EmailRecognizer, Ensemble, EntropyRecognizer, GazetteerRecognizer};
use pp_protocol::ChatRequest;
use pp_store::MemVault;
use pp_upstream::{
    ByteStream, ModelEntry, OpenRouterProvider, Provider, ProviderError, RouterConfig,
};
use serde_json::{json, Value};

/// Shared, immutable application state.
struct AppState {
    /// Full detection floor (incl. entropy) used to anonymise message content.
    anonymizer: Ensemble,
    /// Precise re-detection (no entropy) for the egress guard.
    guard: Ensemble,
    provider: Arc<dyn Provider>,
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
    let state = Arc::new(AppState {
        anonymizer: build_ensemble(true),
        guard: build_ensemble(false),
        provider,
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

    // Per-request vault (Arc so it can move into the streaming task). Placeholders
    // are consistent within the request and never leak to the client.
    let vault: Arc<dyn Vault> = Arc::new(MemVault::new());
    let audit = pipeline::anonymize_request(&mut req, &state.anonymizer, &*vault);
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
                            field the gateway does not yet rewrite (e.g. tool definitions)",
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
/// each `data:` frame, restore placeholders in `delta.content` (reassembling
/// any split across frames via [`StreamRehydrator`]), and re-emit.
fn sse_rehydrated(
    upstream: ByteStream,
    vault: Arc<dyn Vault>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = async_stream::stream! {
        let mut rehydrators: Vec<StreamRehydrator> = Vec::new();
        let mut events = upstream.eventsource();
        while let Some(item) = events.next().await {
            let event = match item {
                Ok(event) => event,
                Err(_) => break, // upstream stream error → end the response
            };
            if event.data == "[DONE]" {
                for r in rehydrators.iter_mut() {
                    let tail = r.flush(&*vault);
                    if !tail.is_empty() {
                        yield ev(tail_chunk(&tail));
                    }
                }
                yield ev("[DONE]".to_string());
                return;
            }
            match serde_json::from_str::<Value>(&event.data) {
                Ok(mut chunk) => {
                    pipeline::rehydrate_deltas(&mut chunk, &mut rehydrators, &*vault);
                    yield ev(chunk.to_string());
                }
                Err(_) => yield ev(event.data),
            }
        }
        // Upstream ended without an explicit [DONE]: flush any held tails.
        for r in rehydrators.iter_mut() {
            let tail = r.flush(&*vault);
            if !tail.is_empty() {
                yield ev(tail_chunk(&tail));
            }
        }
    };
    Sse::new(stream)
}

fn ev(data: String) -> Result<Event, Infallible> {
    Ok(Event::default().data(data))
}

fn tail_chunk(content: &str) -> String {
    json!({ "choices": [{ "index": 0, "delta": { "content": content } }] }).to_string()
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

/// Build a detection ensemble. `with_entropy` distinguishes the anonymiser
/// (full floor) from the egress guard (precise, no entropy). Optional user
/// vocabulary comes from `PRIVACYPROXY_VOCAB` (comma-separated terms).
fn build_ensemble(with_entropy: bool) -> Ensemble {
    let mut detectors: Vec<Box<dyn Detector>> = Vec::new();

    let terms: Vec<(String, EntityKind)> = env::var("PRIVACYPROXY_VOCAB")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| (s.to_string(), EntityKind::Custom("private".to_string())))
        .collect();
    if !terms.is_empty() {
        detectors.push(Box::new(GazetteerRecognizer::new(terms)));
    }

    detectors.push(Box::new(EmailRecognizer));
    if with_entropy {
        detectors.push(Box::new(EntropyRecognizer::default()));
    }
    Ensemble::new(detectors)
}
