#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

use futures_util::Stream;
use futures_util::stream::{self, StreamExt};
use ipnet::IpNet;

mod cgm;
mod detection;
mod http;
mod io;
mod miner;
mod util;

pub use self::miner::{DiscoveredMiner, MinerFamily};

/// Controls how the scanner probes each host.
///
/// The defaults are tuned for a typical local network where miners are
/// expected to answer quickly. Slower networks may require larger timeout
/// values or lower concurrency.
#[derive(Debug, Clone, Copy)]
pub struct ScanOptions {
    /// Maximum number of hosts probed at the same time.
    pub concurrency: usize,
    /// Timeout applied while opening a TCP connection.
    pub connect_timeout: Duration,
    /// Timeout applied to each read and write after a connection is open.
    pub io_timeout: Duration,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            concurrency: 256,
            connect_timeout: Duration::from_millis(500),
            io_timeout: Duration::from_millis(500),
        }
    }
}

/// Scans every host in `cidr` and yields miner detections as they arrive.
///
/// The returned stream only includes positive matches. Hosts that do not answer
/// or cannot be classified are silently skipped.
///
/// Detection currently relies on:
/// - HTTP probes on port `80`
/// - CGMiner-compatible API probes on port `4028`
///
/// Results are produced concurrently, so the output order does not match the
/// IP order from the input subnet.
pub fn scan_network(
    cidr: IpNet,
    opts: ScanOptions,
) -> Pin<Box<dyn Stream<Item = DiscoveredMiner> + Send + Sync>> {
    Box::pin(
        stream::iter(cidr.hosts())
            .map(move |ip| async move { scan_host(ip, opts).await })
            .buffer_unordered(opts.concurrency)
            .filter_map(|x| async move { x }),
    )
}

#[inline]
async fn scan_host(ip: IpAddr, opts: ScanOptions) -> Option<DiscoveredMiner> {
    // Run both probe families in parallel and consolidate the strongest match.
    let (http_detection, cgm_detection) =
        futures_util::join!(http::probe(ip, opts), cgm::probe(ip, opts));
    DiscoveredMiner::merge_detections(http_detection, cgm_detection)
}
