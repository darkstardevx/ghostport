//! A minimal, hand-rolled HTTP/1.1 responder — serves exactly one real
//! endpoint (`GET /metrics`), so pulling in a real HTTP server crate
//! for this would be real overkill, and works against this project's
//! own "small enough to actually audit" ethos (the same reasoning
//! `ghostport-core`'s `ratelimit.rs` already states for being
//! hand-rolled instead of a crate). Reads only the request line,
//! ignores headers and any body entirely, and only ever writes one of
//! two fixed response shapes.

use crate::render;
use ghostport_core::stats::StatusSnapshot;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Bounds how long a client is given to finish sending a request line.
/// Without this, a slow/malicious client that opens a connection and
/// never finishes one would hold a task open forever — exactly the
/// class of bug the recent stability pass fixed elsewhere in this
/// project; applied here proactively rather than needing a third pass.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounds how long a scrape is willing to wait on the daemon's own
/// status socket. `ipc::query_status`'s read has no timeout of its
/// own (confirmed by reading `ipc.rs` directly) — this crate defends
/// itself at the call site since it doesn't own that code.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// A request line longer than this is rejected rather than read into
/// an ever-growing buffer.
const MAX_REQUEST_LINE: usize = 8192;

/// Runs the exporter's HTTP server on `listener` until the process
/// exits, querying `socket_path` fresh on every `GET /metrics` request
/// (see `render` module docs for why there's no caching/poll interval).
pub async fn serve(listener: TcpListener, socket_path: PathBuf) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let socket_path = socket_path.clone();
        tokio::spawn(async move {
            let _ = handle_connection(stream, &socket_path).await;
        });
    }
}

async fn handle_connection(mut stream: TcpStream, socket_path: &Path) -> std::io::Result<()> {
    let request_line =
        match tokio::time::timeout(REQUEST_READ_TIMEOUT, read_request_line(&mut stream)).await {
            Ok(Ok(line)) => line,
            _ => return Ok(()), // timed out or a real read error -- nothing to respond with
        };

    let response = match parse_request_path(&request_line).as_deref() {
        Some("/metrics") => {
            let snapshot = query_snapshot(socket_path).await;
            let body = render::render(snapshot.as_ref());
            http_response(200, "OK", "text/plain; version=0.0.4", &body)
        }
        _ => http_response(404, "Not Found", "text/plain", "not found\n"),
    };

    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

fn http_response(status: u16, reason: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

async fn query_snapshot(socket_path: &Path) -> Option<StatusSnapshot> {
    match tokio::time::timeout(
        QUERY_TIMEOUT,
        ghostport_core::ipc::query_status(socket_path),
    )
    .await
    {
        Ok(Ok(snapshot)) => Some(snapshot),
        _ => None,
    }
}

/// Reads until a full request line (through the first `\n`) is
/// available, or `MAX_REQUEST_LINE` is exceeded. Anything after the
/// first line — headers, any body — is never read, since nothing here
/// needs them.
async fn read_request_line(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break; // connection closed before a newline arrived
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            buf.truncate(pos);
            break;
        }
        if buf.len() > MAX_REQUEST_LINE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request line too long",
            ));
        }
    }
    Ok(String::from_utf8_lossy(&buf).trim().to_string())
}

/// Parses `GET /path HTTP/1.1` down to just `/path`. Anything that
/// isn't a well-formed `GET` request line yields `None`.
fn parse_request_path(request_line: &str) -> Option<String> {
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    if method != "GET" {
        return None;
    }
    Some(path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_real_get_request_line() {
        assert_eq!(
            parse_request_path("GET /metrics HTTP/1.1"),
            Some("/metrics".to_string())
        );
    }

    #[test]
    fn rejects_non_get_methods() {
        assert_eq!(parse_request_path("POST /metrics HTTP/1.1"), None);
    }

    #[test]
    fn rejects_a_malformed_or_empty_line() {
        assert_eq!(parse_request_path(""), None);
        assert_eq!(parse_request_path("garbage"), None);
    }

    #[test]
    fn response_has_a_correct_content_length() {
        let response = http_response(200, "OK", "text/plain", "hello");
        assert!(response.contains("Content-Length: 5"));
        assert!(response.ends_with("hello"));
    }
}
