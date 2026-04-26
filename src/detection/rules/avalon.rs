use super::super::{DetectionSource, FamilyScore};
use crate::MinerFamily;

pub(crate) fn score(_: DetectionSource<'_>, text: &str) -> FamilyScore {
    let mut score: FamilyScore = FamilyScore::new(MinerFamily::Avalon);

    score.add_if_contains(text, "avalon", 70, "avalon");
    score.add_if_contains(text, "canaan", 34, "canaan");
    score.add_if_contains(text, "avalonminer", 18, "avalonminer");

    score
}
