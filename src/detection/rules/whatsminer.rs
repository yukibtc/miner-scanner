use super::super::{DetectionSource, FamilyScore};
use crate::MinerFamily;

pub(crate) fn score(source: DetectionSource<'_>, text: &str) -> FamilyScore {
    let mut score: FamilyScore = FamilyScore::new(MinerFamily::Whatsminer);

    score.add_if_contains(text, "whatsminer", 70, "whatsminer");
    score.add_if_contains(text, "microbt", 34, "microbt");
    score.add_if_contains(text, "prod=whatsminer", 18, "prod-whatsminer");

    if matches!(source, DetectionSource::CGMinerApi) && text.contains("prod=whatsminer") {
        score.add(8, "whatsminer-cgm-shape");
    }

    score
}
