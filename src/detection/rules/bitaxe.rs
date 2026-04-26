use super::super::{DetectionSource, FamilyScore};
use crate::MinerFamily;

pub(crate) fn score(source: DetectionSource<'_>, text: &str) -> FamilyScore {
    let mut score: FamilyScore = FamilyScore::new(MinerFamily::Bitaxe);

    score.add_if_contains(text, "bitaxe", 70, "bitaxe");
    score.add_if_contains(text, "axeos", 18, "axeos");
    score.add_if_contains(text, "esp-miner", 28, "esp-miner");
    score.add_if_contains(text, "\"asicmodel\"", 18, "asicmodel");
    score.add_if_contains(text, "\"asic_model\"", 18, "asic_model");
    score.add_if_contains(text, "bm1366", 32, "bm1366");
    score.add_if_contains(text, "bm1368", 32, "bm1368");
    score.add_if_contains(text, "bm1370", 32, "bm1370");
    score.add_if_contains(text, "bm1397", 16, "bm1397");

    if matches!(
        source,
        DetectionSource::Http {
            endpoint: "/api/system/info"
        }
    ) && (text.contains("\"asicmodel\"") || text.contains("\"asic_model\""))
    {
        score.add(12, "bitaxe-api-shape");
    }

    if matches!(
        source,
        DetectionSource::Http {
            endpoint: "/api/system/info"
        }
    ) && (text.contains("bm1366")
        || text.contains("bm1368")
        || text.contains("bm1370")
        || text.contains("bm1397"))
    {
        score.add(10, "bitaxe-asic-model");
    }

    score
}
