use std::net::SocketAddr;

/// Broad miner family inferred from network responses.
///
/// Classification is heuristic. It is intended to help downstream code pick
/// the right integration path, not to provide a strict hardware guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MinerFamily {
    /// Bitaxe devices and compatible firmware responses.
    Bitaxe,
    /// Bitmain Antminer devices.
    Antminer,
    /// MicroBT Whatsminer devices.
    Whatsminer,
    /// Canaan Avalon devices.
    Avalon,
    /// Generic CGMiner-style devices that do not match a more specific family.
    CGMinerCompatible,
}

impl MinerFamily {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Bitaxe => "Bitaxe",
            Self::Antminer => "Antminer",
            Self::Whatsminer => "Whatsminer",
            Self::Avalon => "Avalon",
            Self::CGMinerCompatible => "CGMiner-compatible",
        }
    }
}

/// A miner candidate discovered during a network scan.
///
/// This type keeps the classification intentionally small: the socket address,
/// the inferred family, a heuristic confidence score, and a short list of
/// evidence strings collected from the probes.
#[derive(Debug, Clone)]
pub struct DiscoveredMiner {
    /// Address that answered the probe.
    ///
    /// The port reflects the probe that produced the strongest match.
    pub addr: SocketAddr,
    /// Inferred miner family.
    pub family: MinerFamily,
    /// Heuristic confidence score in the `0..=100` range.
    ///
    /// This is useful for ranking detections relative to each other. It should
    /// not be interpreted as a statistical probability.
    pub confidence: u8,
    /// Human-readable hints collected during classification.
    ///
    /// These strings are primarily meant for debugging and inspection. Their
    /// exact format is not intended to be a stable parsing surface.
    pub evidence: Vec<String>,
}

impl DiscoveredMiner {
    pub(crate) fn merge_detections(first: Option<Self>, second: Option<Self>) -> Option<Self> {
        match (first, second) {
            (Some(mut a), Some(b)) => {
                // Keep the strongest classification, but preserve supporting
                // evidence from both probe families.
                if b.confidence > a.confidence {
                    a.addr.set_port(b.addr.port());
                    a.family = b.family;
                    a.confidence = b.confidence;
                }

                for item in b.evidence {
                    if !a.evidence.contains(&item) {
                        a.evidence.push(item);
                    }
                }

                if a.addr.port() != b.addr.port() {
                    a.evidence.push(format!("secondary_port={}", b.addr.port()));
                }
                if a.family != b.family {
                    a.evidence
                        .push(format!("secondary_family={}", b.family.as_str()));
                }

                Some(a)
            }
            (Some(item), None) | (None, Some(item)) => Some(item),
            (None, None) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn merge_keeps_best_and_enriches_evidence() {
        let first = DiscoveredMiner {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
            family: MinerFamily::CGMinerCompatible,
            confidence: 80,
            evidence: vec!["source=http/".to_string()],
        };
        let second = DiscoveredMiner {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 4028),
            family: MinerFamily::Antminer,
            confidence: 90,
            evidence: vec!["source=tcp:4028".to_string()],
        };

        let merged = DiscoveredMiner::merge_detections(Some(first), Some(second))
            .expect("expected merged miner");
        assert_eq!(merged.family, MinerFamily::Antminer);
        assert!(merged.evidence.iter().any(|e| e == "source=http/"));
        assert!(merged.evidence.iter().any(|e| e == "source=tcp:4028"));
    }
}
