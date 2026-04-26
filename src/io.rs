use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

#[inline]
pub(crate) async fn connect_tcp(addr: SocketAddr, timeout: Duration) -> Option<TcpStream> {
    match time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => Some(stream),
        _ => None,
    }
}

pub(crate) async fn tcp_stream_write_all(
    stream: &mut TcpStream,
    data: &[u8],
    timeout: Duration,
) -> Option<()> {
    match time::timeout(timeout, stream.write_all(data)).await {
        Ok(Ok(())) => Some(()),
        _ => None,
    }
}

pub(crate) async fn tcp_stream_read(
    stream: &mut TcpStream,
    buf: &mut [u8],
    timeout: Duration,
) -> Option<usize> {
    match time::timeout(timeout, stream.read(buf)).await {
        Ok(Ok(size)) => Some(size),
        _ => None,
    }
}
