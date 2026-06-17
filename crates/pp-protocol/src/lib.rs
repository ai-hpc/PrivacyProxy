//! `pp-protocol` — OpenAI-compatible wire types (requests, responses, deltas,
//! tool calls).
//!
//! Stub for now: the serde models land with the gateway HTTP layer. The
//! gateway normalises every inbound dialect to one internal representation
//! (`ARCHITECTURE.md` §6, §19).
#![forbid(unsafe_code)]

/// The wire dialects the gateway can speak to clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    /// The default normalisation target; OpenRouter is compatible with it.
    OpenAiChatCompletions,
}
