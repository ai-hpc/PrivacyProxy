//! `pp-eval` binary — run the built-in scenarios against OpenRouter's free
//! models and print a baseline-vs-anonymised report.
//!
//! ```bash
//! OPENROUTER_API_KEY=sk-or-... cargo run -p pp-eval --release
//! ```
//!
//! Each scenario makes two upstream calls (baseline + anonymised); mind the
//! free-tier rate limits (~20 req/min, 50–1000 req/day per account). Exits
//! non-zero if any scenario leaked a sensitive term upstream.
#![forbid(unsafe_code)]

use pp_eval::{builtin_scenarios, run_scenario, Report};
use pp_upstream::{ModelEntry, OpenRouterProvider, Provider, RouterConfig};

/// A small free-model preference list (lower priority = tried first).
fn models() -> RouterConfig {
    let m = |id: &str, priority: u8| ModelEntry {
        id: id.to_string(),
        priority,
        tools: true,
        context: 131072,
    };
    RouterConfig {
        models: vec![
            m("nvidia/nemotron-3-ultra-550b-a55b:free", 1),
            m("openai/gpt-oss-120b:free", 2),
            m("qwen/qwen3-next-80b-a3b-instruct:free", 3),
            m("meta-llama/llama-3.3-70b-instruct:free", 4),
        ],
    }
}

#[tokio::main]
async fn main() {
    let key = std::env::var("OPENROUTER_API_KEY")
        .or_else(|_| std::env::var("PRIVACYPROXY_OPENROUTER_KEY"))
        .unwrap_or_default();
    if key.is_empty() {
        eprintln!("error: set OPENROUTER_API_KEY (a free OpenRouter key)");
        std::process::exit(2);
    }

    let provider: &dyn Provider = &OpenRouterProvider::new(key, models());
    let scenarios = builtin_scenarios();
    eprintln!(
        "running {} scenarios · {} upstream calls (baseline + anonymised each)\n",
        scenarios.len(),
        scenarios.len() * 2
    );

    let mut outcomes = Vec::with_capacity(scenarios.len());
    for s in &scenarios {
        let o = run_scenario(s, provider).await;
        match &o.error {
            Some(e) => eprintln!("  {:<22} ERROR: {e}", s.name),
            None => eprintln!(
                "  {:<22} baseline={} anon={} leak={}",
                s.name,
                if o.baseline_pass { "ok" } else { "miss" },
                if o.anon_pass { "ok" } else { "miss" },
                if o.leaked { "YES" } else { "no" },
            ),
        }
        outcomes.push(o);
    }

    let report = Report { outcomes };
    println!("\n{}", report.table());

    if report.leaks() > 0 {
        eprintln!(
            "FAIL: {} scenario(s) leaked a sensitive term upstream",
            report.leaks()
        );
        std::process::exit(1);
    }
}
