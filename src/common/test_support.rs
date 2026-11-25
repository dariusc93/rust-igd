//! A one-shot HTTP server on a loopback address, for tests of the control path (no real gateway or network).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread::JoinHandle;

/// Loopback bind addresses to exercise; callers skip the one that cannot be bound (e.g. IPv6 disabled).
pub const LOOPBACKS: [&str; 2] = ["127.0.0.1:0", "[::1]:0"];

pub const SERVICE: &str = "urn:schemas-upnp-org:service:WANIPConnection:2";

pub const ENTRY_RESPONSE: &str = r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetSpecificPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2"><NewInternalPort>4000</NewInternalPort><NewInternalClient>192.0.2.10</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>example</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration></u:GetSpecificPortMappingEntryResponse></s:Body></s:Envelope>"#;

pub const NO_SUCH_ENTRY_FAULT: &str = r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>714</errorCode><errorDescription>NoSuchEntryInArray</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"#;

/// Answer one request with `status` and `response_body`; the handle returns what the client sent.
/// `None` if `bind` is unavailable on this machine.
pub fn serve_once(
    bind: &str,
    status: &'static str,
    response_body: &'static str,
) -> Option<(SocketAddr, JoinHandle<String>)> {
    let listener = TcpListener::bind(bind).ok()?;
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "client closed before sending a full request");
            request.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&request);
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let length = head
                    .to_ascii_lowercase()
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
                    .unwrap_or(0usize);
                if body.len() >= length {
                    break;
                }
            }
        }
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
            response_body.len()
        )
        .unwrap();
        String::from_utf8(request).unwrap()
    });
    Some((addr, handle))
}
