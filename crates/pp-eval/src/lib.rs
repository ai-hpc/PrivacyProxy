//! `pp-eval` — quantify what anonymisation costs.
//!
//! For each scenario we send the prompt to the same model **twice**: once raw
//! (baseline) and once through the privacy sandwich (anonymise → upstream →
//! rehydrate). We score task success on both and check that the anonymised
//! request never carried a sensitive term upstream. The aggregate answers two
//! questions the README only asserted qualitatively: *how much does masking
//! degrade output?* and *does the floor actually hold?* (leaks must be 0).
//!
//! Scoring is pure and the runner takes any [`pp_upstream::Provider`], so the
//! whole harness is unit-testable offline against a mock — no network, no
//! free-tier quota burned.
#![forbid(unsafe_code)]

use pp_anonymize::{anonymize, rehydrate};
use pp_core::{Detector, EntityKind};
use pp_detect::{
    EmailRecognizer, Ensemble, EntropyRecognizer, GazetteerRecognizer, RegexRecognizer,
};
use pp_store::MemVault;
use pp_upstream::Provider;
use serde_json::{json, Value};

/// A pass/fail criterion applied (case-insensitively) to a model's reply.
#[derive(Clone, Debug)]
pub enum Check {
    /// The reply must contain every one of these substrings.
    Contains(Vec<String>),
    /// The reply must contain none of these substrings.
    NotContains(Vec<String>),
}

impl Check {
    pub fn passes(&self, text: &str) -> bool {
        let hay = text.to_lowercase();
        let has = |n: &String| hay.contains(&n.to_lowercase());
        match self {
            Check::Contains(needles) => needles.iter().all(has),
            Check::NotContains(needles) => !needles.iter().any(has),
        }
    }
}

/// One eval case: a prompt, the private vocabulary to mask for it, a success
/// criterion, and the terms that must never reach the upstream payload.
#[derive(Clone, Debug)]
pub struct Scenario {
    pub name: &'static str,
    pub vocab: Vec<(String, EntityKind)>,
    pub prompt: String,
    pub check: Check,
    /// Originals that must NOT appear in the sanitised (upstream) request.
    pub sensitive: Vec<String>,
}

/// Result of running one scenario through both paths.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub name: &'static str,
    pub baseline_pass: bool,
    pub anon_pass: bool,
    /// A sensitive term survived into the sanitised request — a guarantee breach.
    pub leaked: bool,
    /// Set if an upstream call failed (the scenario is then inconclusive).
    pub error: Option<String>,
}

/// The gateway's deterministic floor, rebuilt for a scenario's vocabulary.
fn floor(vocab: &[(String, EntityKind)]) -> Ensemble {
    let mut d: Vec<Box<dyn Detector>> = Vec::new();
    if !vocab.is_empty() {
        d.push(Box::new(GazetteerRecognizer::new(vocab.to_vec())));
    }
    d.push(Box::new(EmailRecognizer));
    d.push(Box::new(RegexRecognizer::defaults()));
    d.push(Box::new(EntropyRecognizer::default()));
    Ensemble::new(d)
}

fn request(prompt: &str) -> Value {
    json!({ "model": "auto", "messages": [{ "role": "user", "content": prompt }] })
}

fn content_of(resp: &Value) -> String {
    resp["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// Run one scenario through the baseline and the privacy sandwich.
pub async fn run_scenario(s: &Scenario, provider: &dyn Provider) -> Outcome {
    let fail = |baseline_pass, leaked, e: String| Outcome {
        name: s.name,
        baseline_pass,
        anon_pass: false,
        leaked,
        error: Some(e),
    };

    // Baseline: the raw prompt, no anonymisation.
    let baseline = match provider.chat(&request(&s.prompt), false).await {
        Ok(r) => content_of(&r),
        Err(e) => return fail(false, false, e.to_string()),
    };
    let baseline_pass = s.check.passes(&baseline);

    // Anonymised: mask → forward → rehydrate, exactly as the gateway does.
    let vault = MemVault::new();
    let san = anonymize(&s.prompt, &floor(&s.vocab), &vault);
    let leaked = s.sensitive.iter().any(|t| san.text.contains(t.as_str()));
    let anon = match provider.chat(&request(&san.text), false).await {
        Ok(r) => rehydrate(&content_of(&r), &vault),
        Err(e) => return fail(baseline_pass, leaked, e.to_string()),
    };

    Outcome {
        name: s.name,
        baseline_pass,
        anon_pass: s.check.passes(&anon),
        leaked,
        error: None,
    }
}

/// Aggregated results across scenarios.
pub struct Report {
    pub outcomes: Vec<Outcome>,
}

impl Report {
    fn rate(&self, f: impl Fn(&Outcome) -> bool) -> f32 {
        let scored: Vec<&Outcome> = self.outcomes.iter().filter(|o| o.error.is_none()).collect();
        if scored.is_empty() {
            return 0.0;
        }
        scored.iter().filter(|o| f(o)).count() as f32 / scored.len() as f32
    }

    pub fn baseline_rate(&self) -> f32 {
        self.rate(|o| o.baseline_pass)
    }
    pub fn anon_rate(&self) -> f32 {
        self.rate(|o| o.anon_pass)
    }

    /// Anonymised pass rate as a fraction of the baseline — "quality retained".
    /// 1.0 means masking cost nothing the model could otherwise do.
    pub fn retention(&self) -> f32 {
        let base = self.baseline_rate();
        if base == 0.0 {
            1.0
        } else {
            (self.anon_rate() / base).min(1.0)
        }
    }

    pub fn leaks(&self) -> usize {
        self.outcomes.iter().filter(|o| o.leaked).count()
    }

    pub fn table(&self) -> String {
        let mark = |b| if b { "ok " } else { "MISS" };
        let mut out = String::from(
            "scenario               baseline  anon   leak\n\
             ---------------------- --------  -----  ----\n",
        );
        for o in &self.outcomes {
            if let Some(e) = &o.error {
                out.push_str(&format!("{:<22} ERROR: {e}\n", o.name));
                continue;
            }
            out.push_str(&format!(
                "{:<22} {:<8}  {:<5}  {}\n",
                o.name,
                mark(o.baseline_pass),
                mark(o.anon_pass),
                if o.leaked { "LEAK" } else { "-" },
            ));
        }
        out.push_str(&format!(
            "\nbaseline {:.0}%  ·  anonymised {:.0}%  ·  quality retained {:.0}%  ·  leaks {}\n",
            self.baseline_rate() * 100.0,
            self.anon_rate() * 100.0,
            self.retention() * 100.0,
            self.leaks(),
        ));
        out
    }
}

/// The built-in scenarios. Each success criterion targets content the floor does
/// **not** mask (a number, a month, code structure), so a drop from baseline to
/// anonymised isolates damage caused by masking the surrounding PII.
pub fn builtin_scenarios() -> Vec<Scenario> {
    let custom = |s: &str| EntityKind::Custom(s.to_string());
    vec![
        Scenario {
            name: "extract-month",
            vocab: vec![("Project Falcon".into(), custom("project"))],
            prompt: "Project Falcon ships in March 2027. Reply with only the month it ships."
                .into(),
            check: Check::Contains(vec!["march".into()]),
            sensitive: vec!["Falcon".into()],
        },
        Scenario {
            name: "count-contacts",
            vocab: vec![],
            prompt: "Contacts: alex@acme.com and phone 415-555-0142. \
                     Reply with only the number of distinct contact methods."
                .into(),
            check: Check::Contains(vec!["2".into()]),
            sensitive: vec!["alex@acme.com".into(), "415-555-0142".into()],
        },
        Scenario {
            name: "code-structure",
            vocab: vec![],
            prompt: "My token is Zx91Kp7Qw3Er8Tn2Vb6Yh4Mj0Lc5Df8Gs2Na6Rt. \
                     Write a one-line bash command exporting it as the env var MYKEY. \
                     Reply with only the command."
                .into(),
            check: Check::Contains(vec!["export".into(), "MYKEY".into()]),
            sensitive: vec!["Zx91Kp7Qw3Er8Tn2Vb6Yh4Mj0Lc5Df8Gs2Na6Rt".into()],
        },
        Scenario {
            name: "format-json",
            vocab: vec![("Acme Corp".into(), custom("org"))],
            prompt: "Acme Corp asked for a status. Reply with only this JSON: {\"ok\": true}"
                .into(),
            check: Check::Contains(vec!["\"ok\"".into(), "true".into()]),
            sensitive: vec!["Acme Corp".into()],
        },
        Scenario {
            name: "reason-over-masked",
            vocab: vec![("Sarah Jenkins".into(), EntityKind::Person)],
            prompt: "Sarah Jenkins is 34 and her sister is 5 years younger. \
                     Reply with only the sister's age."
                .into(),
            check: Check::Contains(vec!["29".into()]),
            sensitive: vec!["Sarah Jenkins".into()],
        },
        Scenario {
            name: "keep-instruction",
            vocab: vec![("Falcon".into(), custom("project"))],
            prompt: "Translate to French and reply with only the translation: \
                     'The Falcon report is ready.'"
                .into(),
            check: Check::Contains(vec!["rapport".into()]),
            sensitive: vec!["Falcon".into()],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use pp_upstream::{ByteStream, Provider, ProviderError};

    /// Offline provider: echoes the last user message back as the assistant
    /// reply. Lets us exercise the full plumbing deterministically — masking,
    /// rehydration, scoring, leak detection — with no network.
    struct EchoProvider;

    #[async_trait]
    impl Provider for EchoProvider {
        async fn chat(&self, body: &Value, _needs_tools: bool) -> Result<Value, ProviderError> {
            let content = body["messages"]
                .as_array()
                .and_then(|m| m.last())
                .and_then(|m| m["content"].as_str())
                .unwrap_or_default();
            Ok(json!({ "choices": [{ "message": { "role": "assistant", "content": content } }] }))
        }
        async fn chat_stream(
            &self,
            _body: &Value,
            _needs_tools: bool,
        ) -> Result<ByteStream, ProviderError> {
            Err(ProviderError::NoCandidates)
        }
    }

    #[test]
    fn check_is_case_insensitive() {
        assert!(Check::Contains(vec!["March".into()]).passes("ships in march"));
        assert!(!Check::Contains(vec!["April".into()]).passes("ships in march"));
        assert!(Check::NotContains(vec!["Falcon".into()]).passes("the __PROJECT_1__ report"));
        assert!(!Check::NotContains(vec!["Falcon".into()]).passes("the Falcon report"));
    }

    #[tokio::test]
    async fn round_trips_and_does_not_leak() {
        let s = Scenario {
            name: "t",
            vocab: vec![("Falcon".into(), EntityKind::Custom("project".into()))],
            prompt: "Project Falcon ships in March. Mention Falcon and the month.".into(),
            check: Check::Contains(vec!["falcon".into(), "march".into()]),
            sensitive: vec!["Falcon".into()],
        };
        let o = run_scenario(&s, &EchoProvider).await;
        assert!(o.error.is_none());
        assert!(o.baseline_pass, "raw echo contains Falcon + March");
        assert!(o.anon_pass, "anon path restores Falcon and keeps March");
        assert!(!o.leaked, "the sanitised prompt must not contain Falcon");
    }

    #[tokio::test]
    async fn leak_detection_flags_unmasked_term() {
        // 'March' is not a masked entity, so it rides through to the upstream
        // payload — the harness must flag that as a leak.
        let s = Scenario {
            name: "t",
            vocab: vec![],
            prompt: "ship in March".into(),
            check: Check::Contains(vec![]),
            sensitive: vec!["March".into()],
        };
        let o = run_scenario(&s, &EchoProvider).await;
        assert!(o.leaked);
    }

    #[tokio::test]
    async fn report_aggregates_rates_and_retention() {
        let outcomes = vec![
            Outcome {
                name: "a",
                baseline_pass: true,
                anon_pass: true,
                leaked: false,
                error: None,
            },
            Outcome {
                name: "b",
                baseline_pass: true,
                anon_pass: false,
                leaked: false,
                error: None,
            },
            Outcome {
                name: "c",
                baseline_pass: false,
                anon_pass: false,
                leaked: false,
                error: None,
            },
        ];
        let r = Report { outcomes };
        assert!((r.baseline_rate() - 2.0 / 3.0).abs() < 1e-6);
        assert!((r.anon_rate() - 1.0 / 3.0).abs() < 1e-6);
        assert!((r.retention() - 0.5).abs() < 1e-6); // 1 of 2 baseline-passes survived
        assert_eq!(r.leaks(), 0);
        assert!(r.table().contains("quality retained"));
    }
}
