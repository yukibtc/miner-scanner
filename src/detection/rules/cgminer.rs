use super::super::{DetectionSource, FamilyScore};
use crate::MinerFamily;

pub(crate) fn score(source: DetectionSource<'_>, text: &str) -> FamilyScore {
    let mut score: FamilyScore = FamilyScore::new(MinerFamily::CGMinerCompatible);

    score.add_if_contains(text, "cgminer", 42, "cgminer");

    if matches!(source, DetectionSource::CGMinerApi)
        && text.contains("status=")
        && text.contains("version=")
    {
        score.add(12, "cgm-api-shape");
    }

    score
}
