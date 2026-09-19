//! Stream abstraction — plain TCP or TLS on both client and upstream sides.

use bytes::BytesMut;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;

/// Read into `buf`, treating EOF (`read_buf` returning `Ok(0)`) as an error
/// rather than "no data yet".
///
/// `read_buf` yields `Ok(0)` when the peer has closed its half of the socket.
/// A handshake-phase loop reads, tries to parse a complete message, and loops
/// when it has none yet. If such a loop calls `read_buf(...).await?` directly,
/// an EOF returns `Ok(0)`, leaves the buffer unchanged, and the loop spins the
/// task at 100% CPU until an outer timeout fires — the root cause of issue #24
/// and its siblings across the startup, auth, reset, and inject paths. Routing
/// every such loop through this helper turns a closed socket into a prompt,
/// clean `UnexpectedEof`. The steady-state pipe (`pipe_pooled`) and the pool's
/// `drain_outstanding` already handle `Ok(0)` inline; this is the same rule for
/// the handshake side, in one place.
pub async fn read_or_eof<S>(stream: &mut S, buf: &mut BytesMut) -> io::Result<usize>
where
    S: AsyncReadExt + Unpin,
{
    match stream.read_buf(buf).await {
        Ok(0) => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer closed connection during handshake",
        )),
        other => other,
    }
}

// ─── Client-facing stream ───────────────────────────────────────────────────

#[allow(clippy::large_enum_variant)]
pub enum ClientStream {
    Plain(TcpStream),
    Tls(ServerTlsStream<TcpStream>),
}

impl ClientStream {
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Plain(s) => s.peer_addr(),
            Self::Tls(s) => s.get_ref().0.peer_addr(),
        }
    }
}

impl AsyncRead for ClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Unpin for ClientStream {}

// ─── Upstream-facing stream ─────────────────────────────────────────────────

#[allow(clippy::large_enum_variant)]
pub enum UpstreamStream {
    Plain(TcpStream),
    Tls(ClientTlsStream<TcpStream>),
}

impl AsyncRead for UpstreamStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Unpin for UpstreamStream {}
