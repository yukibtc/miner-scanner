use super::super::{DetectionSource, FamilyScore};
use crate::MinerFamily;

pub(crate) fn score(source: DetectionSource<'_>, text: &str) -> FamilyScore {
    let mut score: FamilyScore = FamilyScore::new(MinerFamily::Antminer);

    score.add_if_contains(text, "antminer", 70, "antminer");
    score.add_if_contains(text, "bmminer", 15, "bmminer");
    score.add_if_contains(text, "xilinx bm", 24, "xilinx-bm");
    score.add_if_contains(text, "\"minertype\"", 18, "minertype");

    if matches!(
        source,
        DetectionSource::Http {
            endpoint: "/cgi-bin/get_system_info.cgi"
        }
    ) && text.contains("\"minertype\"")
    {
        score.add(10, "antminer-cgi-shape");
    }

    score
}
