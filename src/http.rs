use std::net::{IpAddr, SocketAddr};
use std::str;

use tokio::net::TcpStream;

use crate::detection::{self, DetectionSource};
use crate::io::{connect_tcp, tcp_stream_read, tcp_stream_write_all};
use crate::{DiscoveredMiner, ScanOptions, util};

const PROBE_HTTP_ENDPOINTS: [&str; 4] = [
    "/api/system/info",
    "/cgi-bin/get_system_info.cgi",
    "/api/v1/info",
    "/",
];

struct HttpBody {
    body: String,
    keep_alive: bool,
}

impl HttpBody {
    async fn fetch(
        stream: &mut TcpStream,
        ip: IpAddr,
        endpoint: &str,
        opts: ScanOptions,
    ) -> Option<Self> {
        let request: String =
            format!("GET {endpoint} HTTP/1.1\r\nHost: {ip}\r\nConnection: keep-alive\r\n\r\n");

        tcp_stream_write_all(stream, request.as_bytes(), opts.io_timeout).await?;

        let mut response: Vec<u8> = Vec::with_capacity(2048);

        loop {
            if split_http_message(&response).is_some() {
                break;
            }

            if response.len() >= 16 * 1024 {
                return None;
            }

            let read: usize = read_http_chunk(stream, opts, &mut response).await?;

            if read == 0 {
                return None;
            }
        }

        let (header_bytes, body_bytes) = split_http_message(&response)?;
        let head: HttpResponseHead = HttpResponseHead::parse(header_bytes)?;
        let mut body: Vec<u8> = body_bytes.to_vec();

        if let Some(content_length) = head.content_length {
            if content_length > 64 * 1024 {
                return None;
            }

            while body.len() < content_length {
                let read: usize = read_http_chunk(stream, opts, &mut body).await?;

                if read == 0 {
                    return None;
                }
            }

            body.truncate(content_length);

            return Some(Self {
                body: String::from_utf8_lossy(&body).into_owned(),
                keep_alive: head.keep_alive,
            });
        }

        if head.chunked {
            // Some firmwares speak enough HTTP/1.1 to use chunked transfer
            // encoding, so decode it before classification.
            let decoded: Vec<u8> = read_chunked_http_body(stream, opts, body).await?;

            return Some(Self {
                body: String::from_utf8_lossy(&decoded).into_owned(),
                keep_alive: head.keep_alive,
            });
        }

        // Without an explicit length, read until the peer closes the
        // connection and treat the body as non-reusable.
        loop {
            let read: usize = read_http_chunk(stream, opts, &mut body).await?;

            if read == 0 {
                break;
            }
        }

        Some(Self {
            body: String::from_utf8_lossy(&body).into_owned(),
            keep_alive: false,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct HttpResponseHead {
    content_length: Option<usize>,
    chunked: bool,
    keep_alive: bool,
}

impl HttpResponseHead {
    fn parse(headers: &[u8]) -> Option<Self> {
        let headers: &str = str::from_utf8(headers).ok()?;

        let mut lines = headers.split("\r\n");
        let status_line: &str = lines.next()?;

        let http11: bool = status_line.starts_with("HTTP/1.1");
        let http10: bool = status_line.starts_with("HTTP/1.0");

        if !http11 && !http10 {
            return None;
        }

        let mut connection_close: bool = http10;
        let mut connection_keep_alive: bool = false;
        let mut content_length = None;
        let mut chunked: bool = false;

        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };

            let value: &str = value.trim();

            if name.eq_ignore_ascii_case("Content-Length") {
                content_length = value.parse().ok();
                continue;
            }

            if name.eq_ignore_ascii_case("Transfer-Encoding") {
                chunked = value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("chunked"));
                continue;
            }

            if name.eq_ignore_ascii_case("Connection") {
                connection_close = value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("close"));
                connection_keep_alive = value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("keep-alive"));
            }
        }

        let keep_alive: bool = if http11 {
            !connection_close
        } else {
            connection_keep_alive && !connection_close
        };

        Some(Self {
            content_length,
            chunked,
            keep_alive,
        })
    }
}

enum ChunkedBody {
    Complete(Vec<u8>),
    Incomplete,
}

impl ChunkedBody {
    fn decode(encoded: &[u8]) -> Option<Self> {
        let mut cursor: usize = 0;
        let mut decoded: Vec<u8> = Vec::new();

        loop {
            let Some(line_end) = find_crlf(encoded, cursor) else {
                return Some(Self::Incomplete);
            };

            let size_line: &str = str::from_utf8(&encoded[cursor..line_end]).ok()?;
            let size_token: &str = size_line.split(';').next()?.trim();
            let chunk_size: usize = usize::from_str_radix(size_token, 16).ok()?;
            let chunk_start: usize = line_end + 2;
            let chunk_end: usize = chunk_start.checked_add(chunk_size)?;
            let trailer_end: usize = chunk_end.checked_add(2)?;

            if trailer_end > encoded.len() {
                return Some(Self::Incomplete);
            }

            if &encoded[chunk_end..trailer_end] != b"\r\n" {
                return None;
            }

            if decoded.len().saturating_add(chunk_size) > 64 * 1024 {
                return None;
            }

            decoded.extend_from_slice(&encoded[chunk_start..chunk_end]);
            cursor = trailer_end;

            if chunk_size == 0 {
                if cursor == encoded.len() {
                    return Some(Self::Complete(decoded));
                }

                return match find_trailer_end(encoded, cursor) {
                    Some(_) => Some(Self::Complete(decoded)),
                    None => Some(Self::Incomplete),
                };
            }
        }
    }
}

pub(crate) async fn probe(ip: IpAddr, opts: ScanOptions) -> Option<DiscoveredMiner> {
    let addr: SocketAddr = SocketAddr::new(ip, 80);

    let mut stream: TcpStream = connect_tcp(addr, opts.connect_timeout).await?;

    for endpoint in PROBE_HTTP_ENDPOINTS {
        // Reuse the same connection for as long as the target honors
        // keep-alive. This keeps the multi-endpoint probe inexpensive.
        let Some(response) = HttpBody::fetch(&mut stream, addr.ip(), endpoint, opts).await else {
            continue;
        };

        if let Some(detection) = classify_http_payload(addr, endpoint, response.body) {
            return Some(detection);
        }

        if !response.keep_alive {
            break;
        }
    }

    None
}

fn classify_http_payload(
    addr: SocketAddr,
    endpoint: &str,
    body: String,
) -> Option<DiscoveredMiner> {
    let detected = detection::detect(DetectionSource::Http { endpoint }, &body)?;

    let mut evidence: Vec<String> = vec![format!("source=http{endpoint}")];
    evidence.extend(detected.evidence);
    evidence.push(util::truncate(body, 220));

    Some(DiscoveredMiner {
        addr,
        family: detected.family,
        confidence: detected.confidence,
        evidence,
    })
}

async fn read_http_chunk(
    stream: &mut TcpStream,
    opts: ScanOptions,
    target: &mut Vec<u8>,
) -> Option<usize> {
    let mut buf: [u8; 1024] = [0u8; 1024];

    let n: usize = tcp_stream_read(stream, &mut buf, opts.io_timeout).await?;

    if n > 0 {
        target.extend_from_slice(&buf[..n]);
    }

    Some(n)
}

async fn read_chunked_http_body(
    stream: &mut TcpStream,
    opts: ScanOptions,
    mut encoded: Vec<u8>,
) -> Option<Vec<u8>> {
    loop {
        match ChunkedBody::decode(&encoded)? {
            ChunkedBody::Complete(body) => return Some(body),
            ChunkedBody::Incomplete => {
                if encoded.len() >= 64 * 1024 {
                    return None;
                }

                let read: usize = read_http_chunk(stream, opts, &mut encoded).await?;

                if read == 0 {
                    return None;
                }
            }
        }
    }
}

fn split_http_message(response: &[u8]) -> Option<(&[u8], &[u8])> {
    const HEADER_END: &[u8] = b"\r\n\r\n";

    response
        .windows(HEADER_END.len())
        .position(|window| window == HEADER_END)
        .map(|index| (&response[..index], &response[index + HEADER_END.len()..]))
}

fn find_crlf(bytes: &[u8], start: usize) -> Option<usize> {
    bytes[start..]
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|index| start + index)
}

fn find_trailer_end(bytes: &[u8], start: usize) -> Option<usize> {
    const TRAILER_END: &[u8] = b"\r\n\r\n";

    if start + 2 <= bytes.len() && &bytes[start..start + 2] == b"\r\n" {
        return Some(start + 2);
    }

    bytes[start..]
        .windows(TRAILER_END.len())
        .position(|window| window == TRAILER_END)
        .map(|index| start + index + TRAILER_END.len())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::MinerFamily;

    #[test]
    fn classify_bitaxe_http_payload() {
        let body = r#"{"hostname":"bitaxe","asicModel":"Bitaxe Supra","version":"esp-miner 2.5"}"#;
        let detected = classify_http_payload(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 80),
            "/api/system/info",
            body.to_string(),
        )
        .expect("expected bitaxe detection");

        assert_eq!(detected.family, MinerFamily::Bitaxe);
    }

    #[test]
    fn classify_antminer_http_payload() {
        let body = r#"{"minertype":"Antminer S19j Pro","hostname":"miner-s19"}"#;
        let detected = classify_http_payload(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)), 80),
            "/cgi-bin/get_system_info.cgi",
            body.to_string(),
        )
        .expect("expected antminer detection");

        assert_eq!(detected.family, MinerFamily::Antminer);
    }

    #[test]
    fn split_http_message_extracts_payload() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody";
        let (_, body) = split_http_message(response).expect("expected HTTP body");

        assert_eq!(body, b"body");
    }

    #[test]
    fn parse_http_response_head_detects_keep_alive() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n";
        let head = HttpResponseHead::parse(headers).expect("expected HTTP head");

        assert_eq!(head.content_length, Some(4));
        assert!(!head.chunked);
        assert!(head.keep_alive);
    }

    #[test]
    fn decode_chunked_body_extracts_payload() {
        let encoded = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let body = ChunkedBody::decode(encoded).expect("expected chunked body");

        match body {
            ChunkedBody::Complete(body) => assert_eq!(body, b"Wikipedia"),
            ChunkedBody::Incomplete => panic!("expected complete chunked body"),
        }
    }
}
