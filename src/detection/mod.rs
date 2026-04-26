mod rules;

use crate::MinerFamily;

const MIN_DETECTION_SCORE: u8 = 40;
const AMBIGUITY_MARGIN: u8 = 10;

#[derive(Debug, Clone, Copy)]
pub(crate) enum DetectionSource<'a> {
    Http { endpoint: &'a str },
    CGMinerApi,
}

#[derive(Debug, Clone)]
pub(crate) struct MinerMatch {
    pub family: MinerFamily,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone)]
struct FamilyScore {
    family: MinerFamily,
    points: u8,
    reasons: Vec<&'static str>,
}

impl FamilyScore {
    fn new(family: MinerFamily) -> Self {
        Self {
            family,
            points: 0,
            reasons: Vec::new(),
        }
    }

    fn add(&mut self, points: u8, reason: &'static str) {
        self.points = self.points.saturating_add(points);
        self.reasons.push(reason);
    }

    fn add_if_contains(&mut self, haystack: &str, needle: &str, points: u8, reason: &'static str) {
        if haystack.contains(needle) {
            self.add(points, reason);
        }
    }
}

pub(crate) fn detect(source: DetectionSource<'_>, text: &str) -> Option<MinerMatch> {
    let lower: String = text.to_ascii_lowercase();

    // Miner-specific heuristics live under `rules/`, so adding a new family
    // should not require touching the protocol probing code.
    let mut scores = [
        rules::bitaxe::score(source, &lower),
        rules::antminer::score(source, &lower),
        rules::whatsminer::score(source, &lower),
        rules::avalon::score(source, &lower),
        rules::cgminer::score(source, &lower),
    ];

    scores.sort_by(|a, b| b.points.cmp(&a.points));

    let best: &FamilyScore = &scores[0];
    let runner_up: &FamilyScore = &scores[1];

    if best.points < MIN_DETECTION_SCORE {
        return None;
    }

    if best.points < runner_up.points.saturating_add(AMBIGUITY_MARGIN) {
        return None;
    }

    Some(MinerMatch {
        family: best.family,
        confidence: adjust_confidence(source, best.points),
        evidence: best
            .reasons
            .iter()
            .map(|reason| format!("match={reason}"))
            .collect(),
    })
}

fn adjust_confidence(source: DetectionSource<'_>, score: u8) -> u8 {
    match source {
        DetectionSource::Http { endpoint: "/" } => score.saturating_sub(8),
        DetectionSource::Http { .. } | DetectionSource::CGMinerApi => score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_bitaxe_from_http_api_payload() {
        let detected = detect(
            DetectionSource::Http {
                endpoint: "/api/system/info",
            },
            r#"{"hostname":"bitaxe","asicModel":"Bitaxe Supra","version":"esp-miner 2.5"}"#,
        )
        .expect("expected bitaxe detection");

        assert_eq!(detected.family, MinerFamily::Bitaxe);
        assert!(detected.confidence >= 90);
    }

    #[test]
    fn detect_whatsminer_over_bmminer_hint() {
        let detected = detect(
            DetectionSource::CGMinerApi,
            r#"STATUS=S,Code=11|VERSION=BMMiner/2.0.0,PROD=WhatsMiner M30S++"#,
        )
        .expect("expected whatsminer detection");

        assert_eq!(detected.family, MinerFamily::Whatsminer);
    }

    #[test]
    fn detect_generic_cgminer_from_4028_shape() {
        let detected = detect(
            DetectionSource::CGMinerApi,
            r#"STATUS=S,When=1711111111,Code=11,Msg=Summary|VERSION=CGMiner 4.12.0"#,
        )
        .expect("expected cgminer detection");

        assert_eq!(detected.family, MinerFamily::CGMinerCompatible);
    }

    #[test]
    fn detect_bitaxe_from_asic_model_only() {
        let detected = detect(
            DetectionSource::Http {
                endpoint: "/api/system/info",
            },
            r#"{"asicModel":"BM1368","hostname":"miner"}"#,
        )
        .expect("expected bitaxe detection");

        assert_eq!(detected.family, MinerFamily::Bitaxe);
    }

    #[test]
    fn bm1397_needs_bitaxe_context() {
        let detected = detect(
            DetectionSource::Http {
                endpoint: "/api/system/info",
            },
            r#"{"asicModel":"BM1397"}"#,
        )
        .expect("expected bitaxe detection");

        assert_eq!(detected.family, MinerFamily::Bitaxe);
    }

    #[test]
    fn reject_ambiguous_payload() {
        let detected = detect(
            DetectionSource::Http { endpoint: "/" },
            "antminer whatsminer",
        );

        assert!(detected.is_none());
    }
}
