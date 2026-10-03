//! Helpers for reaching a gateway at an IPv6 link-local address.
//!
//! A link-local (`FE80::/10`) gateway can only be reached on a specific interface, identified by
//! the address's zone (scope) id. The HTTP clients used elsewhere resolve the URL host themselves
//! and cannot carry that zone id, so for a link-local gateway we connect to the scoped socket
//! address directly and speak a minimal HTTP/1.1 ourselves.

use std::net::{Ipv6Addr, SocketAddr};

/// Whether `addr` is an IPv6 link-local address (`FE80::/10`) carrying a non-zero zone (scope) id.
pub fn is_scoped_link_local(addr: &SocketAddr) -> bool {
    matches!(addr, SocketAddr::V6(a) if is_link_local(a.ip()) && a.scope_id() != 0)
}

/// If `addr` is an IPv6 link-local address without a zone id, inherit it from `from` (the address an
/// SSDP response was received from) so the gateway can later be reached on that interface. Any other
/// address is returned unchanged.
pub fn apply_response_scope(addr: SocketAddr, from: SocketAddr) -> SocketAddr {
    if let (SocketAddr::V6(mut a), SocketAddr::V6(f)) = (addr, from) {
        if is_link_local(a.ip()) && a.scope_id() == 0 && f.scope_id() != 0 {
            a.set_scope_id(f.scope_id());
            return SocketAddr::V6(a);
        }
    }
    addr
}

/// The URL / `Host`-header form of `addr` with any IPv6 zone id omitted (`[fe80::1]:1900`).
pub fn host_without_zone(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(a) => a.to_string(),
        SocketAddr::V6(a) => format!("[{}]:{}", a.ip(), a.port()),
    }
}

fn is_link_local(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

/// Perform an HTTP/1.1 request directly over a TCP connection to `addr` (which may carry an IPv6
/// zone id, for a link-local gateway), returning the response body. Uses `Connection: close` and
/// reads to EOF, decoding `Transfer-Encoding: chunked` if present. The body is capped at `max_body`.
#[cfg(feature = "io_sync")]
pub fn raw_http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&str>,
    timeout: std::time::Duration,
    max_body: usize,
) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind, Read, Write};
    use std::net::TcpStream;

    let host = host_without_zone(&addr);
    let stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (name, value) in extra_headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    if let Some(body) = body {
        request.push_str(body);
    }
    (&stream).write_all(request.as_bytes())?;

    // `Connection: close` => the server closes after the response, so read to EOF (capped).
    let mut raw = Vec::new();
    (&stream).take(max_body as u64 + 1).read_to_end(&mut raw)?;
    if raw.len() > max_body {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "gateway response body exceeded the maximum allowed size",
        ));
    }

    let header_end = find_subsequence(&raw, b"\r\n\r\n")
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "malformed HTTP response"))?;
    let headers = &raw[..header_end];
    let body = &raw[header_end + 4..];

    if headers_are_chunked(headers) {
        dechunk(body)
    } else {
        Ok(body.to_vec())
    }
}

#[cfg(feature = "io_sync")]
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(feature = "io_sync")]
fn headers_are_chunked(headers: &[u8]) -> bool {
    let lower: Vec<u8> = headers.iter().map(|b| b.to_ascii_lowercase()).collect();
    find_subsequence(&lower, b"transfer-encoding:").is_some() && find_subsequence(&lower, b"chunked").is_some()
}

#[cfg(feature = "io_sync")]
fn dechunk(mut body: &[u8]) -> std::io::Result<Vec<u8>> {
    let err = || std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed chunked response");
    let mut out = Vec::new();
    loop {
        let nl = find_subsequence(body, b"\r\n").ok_or_else(err)?;
        let size_line = std::str::from_utf8(&body[..nl]).map_err(|_| err())?;
        // A chunk size may be followed by `;`-separated extensions.
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16).map_err(|_| err())?;
        body = &body[nl + 2..];
        if size == 0 {
            break;
        }
        let chunk_end = size.checked_add(2).ok_or_else(err)?;
        if body.len() < chunk_end || &body[size..chunk_end] != b"\r\n" {
            return Err(err());
        }
        out.extend_from_slice(&body[..size]);
        body = &body[chunk_end..]; // skip the chunk data and its trailing CRLF
    }
    Ok(out)
}

#[cfg(all(test, feature = "io_sync"))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn scoped_link_local_detection() {
        assert!(is_scoped_link_local(&"[fe80::1%3]:80".parse().unwrap()));
        assert!(!is_scoped_link_local(&"[fe80::1]:80".parse().unwrap())); // no zone id
        assert!(!is_scoped_link_local(&"[2001:db8::1%3]:80".parse().unwrap())); // not link-local
        assert!(!is_scoped_link_local(&"192.168.1.1:80".parse().unwrap())); // ipv4
    }

    #[test]
    fn host_without_zone_strips_scope() {
        assert_eq!(
            host_without_zone(&"[fe80::1%3]:1900".parse().unwrap()),
            "[fe80::1]:1900"
        );
        assert_eq!(
            host_without_zone(&"192.168.1.1:1900".parse().unwrap()),
            "192.168.1.1:1900"
        );
    }

    fn serve_once(response: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(response);
            }
        });
        addr
    }

    #[test]
    fn raw_http_get_content_length() {
        let addr = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
        let body = raw_http_request(addr, "GET", "/desc.xml", &[], None, Duration::from_secs(2), 1024 * 1024).unwrap();
        assert_eq!(body, b"hello");
    }

    #[test]
    fn raw_http_post_chunked() {
        let addr = serve_once(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        );
        let body = raw_http_request(
            addr,
            "POST",
            "/ctl",
            &[("Content-Type", "text/xml")],
            Some("<x/>"),
            Duration::from_secs(2),
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(body, b"hello world");
    }
}
