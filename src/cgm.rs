use std::net::{IpAddr, SocketAddr};

use tokio::net::TcpStream;

use crate::detection::{self, DetectionSource};
use crate::io::{connect_tcp, tcp_stream_read, tcp_stream_write_all};
use crate::{DiscoveredMiner, MinerFamily, ScanOptions, util};

const PROBE_CGM_COMMAND: &[u8] = br#"{"command":"version"}"#;

pub(crate) async fn probe(ip: IpAddr, opts: ScanOptions) -> Option<DiscoveredMiner> {
    let addr: SocketAddr = SocketAddr::new(ip, 4028);

    let mut stream: TcpStream = connect_tcp(addr, opts.connect_timeout).await?;

    tcp_stream_write_all(&mut stream, PROBE_CGM_COMMAND, opts.io_timeout).await?;

    let mut response: Vec<u8> = Vec::with_capacity(2048);

    // CGMiner-style responses are usually small. A short bounded read keeps the
    // probe cheap while still covering the common firmware responses.
    for _ in 0..2 {
        let mut buf: [u8; 1024] = [0u8; 1024];

        let n: usize = tcp_stream_read(&mut stream, &mut buf, opts.io_timeout).await?;

        if n == 0 {
            break;
        }

        response.extend_from_slice(&buf[..n]);

        if n < buf.len() {
            break;
        }
    }

    if response.is_empty() {
        return None;
    }

    let resp: String = sanitize(&response);
    classify_4028_payload(addr, resp)
}

fn classify_4028_payload(addr: SocketAddr, body: String) -> Option<DiscoveredMiner> {
    let detected = detection::detect(DetectionSource::CGMinerApi, &body)?;

    Some(DiscoveredMiner {
        addr,
        family: detected.family,
        confidence: confidence_for_4028(detected.family, detected.confidence),
        evidence: {
            let mut evidence: Vec<String> = vec![String::from("source=tcp:4028")];
            evidence.extend(detected.evidence);
            evidence.push(util::truncate(body, 220));
            evidence
        },
    })
}

fn confidence_for_4028(category: MinerFamily, detected_confidence: u8) -> u8 {
    let floor: u8 = match category {
        MinerFamily::Antminer | MinerFamily::Whatsminer | MinerFamily::Avalon => 80,
        MinerFamily::Bitaxe => 68,
        MinerFamily::CGMinerCompatible => 54,
    };

    detected_confidence.max(floor)
}

fn sanitize(bytes: &[u8]) -> String {
    // Some firmware returns separators or non-printable bytes. Normalizing the
    // payload keeps the downstream matcher simple and predictable.
    bytes
        .iter()
        .map(|b| {
            let c: char = *b as char;
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                ' '
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn classify_whatsminer_4028_payload() {
        let body = r#"STATUS=S,When=1711111111,Code=11,Msg=Summary|VERSION=BMMiner/2.0.0,PROD=WhatsMiner M30S++"#;
        let detected = classify_4028_payload(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)), 4028),
            body.to_string(),
        )
        .expect("expected 4028 detection");

        assert_eq!(detected.family, MinerFamily::Whatsminer);
    }
}
