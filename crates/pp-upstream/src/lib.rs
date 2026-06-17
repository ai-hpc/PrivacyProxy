//! `pp-upstream` — provider abstraction and the capability-aware failover
//! router over OpenRouter's free models (`ARCHITECTURE.md` §12).
//!
//! The async HTTP `Provider` impls (reqwest + SSE) land with the gateway.
//! This crate defines the routing data model and candidate selection, which
//! are pure and unit-testable.
#![forbid(unsafe_code)]

/// One configured upstream model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelEntry {
    /// OpenRouter model id, e.g. `nvidia/nemotron-3-ultra-550b-a55b:free`.
    pub id: String,
    /// Preference rank — **lower is tried first** (1 = primary).
    pub priority: u8,
    /// Whether this model reliably supports tool/function calling.
    pub tools: bool,
    /// Context window in tokens.
    pub context: u32,
}

/// Ordered model preferences for the failover router.
#[derive(Clone, Debug, Default)]
pub struct RouterConfig {
    pub models: Vec<ModelEntry>,
}

impl RouterConfig {
    /// Candidates for a request: filtered by capability (tool-calling requests
    /// only route to `tools == true` models), then ordered by preference.
    pub fn candidates(&self, needs_tools: bool) -> Vec<&ModelEntry> {
        let mut c: Vec<&ModelEntry> = self
            .models
            .iter()
            .filter(|m| !needs_tools || m.tools)
            .collect();
        c.sort_by_key(|m| m.priority);
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(id: &str, priority: u8, tools: bool) -> ModelEntry {
        ModelEntry {
            id: id.into(),
            priority,
            tools,
            context: 0,
        }
    }

    #[test]
    fn tool_requests_skip_non_tool_models() {
        let cfg = RouterConfig {
            models: vec![m("a", 2, false), m("b", 1, true), m("c", 3, true)],
        };
        let ids: Vec<_> = cfg.candidates(true).iter().map(|m| m.id.clone()).collect();
        assert_eq!(ids, vec!["b", "c"]); // "a" filtered out, rest ordered by priority
    }

    #[test]
    fn non_tool_requests_keep_all_ordered() {
        let cfg = RouterConfig {
            models: vec![m("a", 2, false), m("b", 1, true)],
        };
        let ids: Vec<_> = cfg.candidates(false).iter().map(|m| m.id.clone()).collect();
        assert_eq!(ids, vec!["b", "a"]);
    }
}
