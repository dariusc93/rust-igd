//! Tokio abstraction for the aio [`Gateway`].

use bytes::Bytes;
use futures::prelude::*;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::Request;
use hyper_util::client::legacy::Client;
use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::{net::UdpSocket, time::timeout};

use super::{Provider, HEADER_NAME, MAX_RESPONSE_SIZE};
#[cfg(feature = "ipv6")]
use crate::aio::Ipv6FirewallGateway;
use crate::common::options::{DEFAULT_REQUEST_TIMEOUT, DEFAULT_TIMEOUT, MAX_RESPONSE_BYTES, RESPONSE_TIMEOUT};
use crate::common::{messages, parsing, SearchOptions};
use crate::errors::SearchError;
use crate::{aio::Gateway, RequestError};
use log::debug;

enum SearchTarget {
    Wan,
    #[cfg(feature = "ipv6")]
    Firewall,
}

struct DiscoveredDevice {
    addr: SocketAddr,
    root_url: String,
    urls: parsing::DeviceUrls,
    control_schema: Option<HashMap<String, Vec<String>>>,
}

/// Tokio provider for the [`Gateway`].
#[derive(Debug, Clone)]
pub struct Tokio;

impl Provider for Tokio {
    async fn send_async(url: &str, action: &str, body: &str) -> Result<String, RequestError> {
        // A link-local gateway can only be reached on a specific interface (the address's zone id),
        // which the hyper client cannot carry through a URL, so connect to the scoped address
        // directly via hyper's low-level connection API.
        if let Some((addr, path)) = scoped_link_local_target(url) {
            let headers = [(HEADER_NAME, action), ("Content-Type", "text/xml")];
            let send = raw_http_request(addr, "POST", &path, &headers, Some(body.to_string()));
            let bytes = timeout(DEFAULT_REQUEST_TIMEOUT, send).await??;
            return Ok(String::from_utf8(bytes)?);
        }

        let client = Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

        let body = body.to_string();

        let req = Request::builder()
            .uri(url)
            .method("POST")
            .header(HEADER_NAME, action)
            .header(CONTENT_TYPE, "text/xml")
            .header(CONTENT_LENGTH, body.len() as u64)
            .body(body)?;

        let send = async {
            let resp = client.request(req).await?;
            let body = Limited::new(resp.into_body(), MAX_RESPONSE_BYTES)
                .collect()
                .await
                .map_err(|e| RequestError::InvalidResponse(format!("could not read response body: {e}")))?
                .to_bytes();
            let string = String::from_utf8(body.to_vec())?;
            Ok::<_, RequestError>(string)
        };

        timeout(DEFAULT_REQUEST_TIMEOUT, send).await?
    }
}

/// Search for a gateway with the provided options.
pub async fn search_gateway(options: SearchOptions) -> Result<Gateway<Tokio>, SearchError> {
    let discovered = search_device(options, SearchTarget::Wan).await?;
    let wan = discovered.urls.wan.ok_or(SearchError::InvalidResponse)?;
    let control_schema = discovered.control_schema.ok_or(SearchError::InvalidResponse)?;
    Ok(Gateway {
        addr: discovered.addr,
        root_url: discovered.root_url,
        control_url: wan.control_url,
        control_schema_url: wan.control_schema_url,
        control_schema,
        service_type: wan.service_type,
        #[cfg(feature = "ipv6")]
        ipv6_firewall_control_url: discovered.urls.ipv6_firewall_control_url,
        provider: Tokio,
    })
}

/// Search for a gateway that exposes an IPv6 firewall service.
///
/// Use `SearchOptions::ipv6(scope_id)` to search over an IPv6 link.
#[cfg(feature = "ipv6")]
pub async fn search_ipv6_firewall_gateway(options: SearchOptions) -> Result<Ipv6FirewallGateway<Tokio>, SearchError> {
    let discovered = search_device(options, SearchTarget::Firewall).await?;
    let control_url = discovered
        .urls
        .ipv6_firewall_control_url
        .ok_or(SearchError::InvalidResponse)?;
    Ok(Ipv6FirewallGateway::new(
        discovered.addr,
        discovered.root_url,
        control_url,
    ))
}

async fn search_device(options: SearchOptions, target: SearchTarget) -> Result<DiscoveredDevice, SearchError> {
    let search_timeout = options.timeout.unwrap_or(DEFAULT_TIMEOUT);
    match timeout(search_timeout, discover(options, target)).await {
        Ok(Ok(discovered)) => Ok(discovered),
        Ok(Err(err)) => Err(err),
        Err(_err) => {
            // Timeout
            Err(SearchError::NoResponseWithinTimeout)
        }
    }
}

async fn discover(options: SearchOptions, target: SearchTarget) -> Result<DiscoveredDevice, SearchError> {
    // Create socket for future calls
    let mut socket = UdpSocket::bind(&options.bind_addr).await?;

    send_search_request(&mut socket, options.broadcast_address).await?;
    let response_timeout = options.single_search_timeout.unwrap_or(RESPONSE_TIMEOUT);

    loop {
        let search_response = receive_search_response(&mut socket);

        // Receive search response
        let (response_body, from) = match timeout(response_timeout, search_response).await {
            Ok(Ok(v)) => v,
            Ok(Err(err)) => {
                debug!("error while receiving broadcast response: {err}");
                continue;
            }
            Err(_) => {
                debug!("timeout while receiving broadcast response");
                continue;
            }
        };

        let (addr, root_url) = match handle_broadcast_resp(&from, &response_body) {
            Ok(v) => v,
            Err(e) => {
                debug!("error handling broadcast response: {}", e);
                continue;
            }
        };

        if !options.gateway_ip_version.accepts(addr.ip()) {
            debug!("skipping gateway {}: not the requested IP version", addr);
            continue;
        }

        let urls = match get_control_urls(&addr, &root_url).await {
            Ok(v) => v,
            Err(e) => {
                debug!("error getting control URLs: {}", e);
                continue;
            }
        };

        let control_schema = match target {
            SearchTarget::Wan => {
                let Some(wan) = urls.wan.as_ref() else {
                    continue;
                };
                match get_control_schemas(&addr, &wan.control_schema_url).await {
                    Ok(schema) => Some(schema),
                    Err(e) => {
                        debug!("error getting control schemas: {}", e);
                        continue;
                    }
                }
            }
            #[cfg(feature = "ipv6")]
            SearchTarget::Firewall => {
                if urls.ipv6_firewall_control_url.is_none() {
                    continue;
                }
                None
            }
        };

        return Ok(DiscoveredDevice {
            addr,
            root_url,
            urls,
            control_schema,
        });
    }
}

// Create a new search.
async fn send_search_request(socket: &mut UdpSocket, addr: SocketAddr) -> Result<(), SearchError> {
    debug!(
        "sending broadcast request to: {} on interface: {:?}",
        addr,
        socket.local_addr()
    );
    let request = messages::search_request(&addr);
    socket
        .send_to(request.as_bytes(), &addr)
        .map_ok(|_| ())
        .map_err(SearchError::from)
        .await
}

async fn receive_search_response(socket: &mut UdpSocket) -> Result<(Vec<u8>, SocketAddr), SearchError> {
    let mut buff = [0u8; MAX_RESPONSE_SIZE];
    let (n, from) = socket.recv_from(&mut buff).map_err(SearchError::from).await?;
    debug!("received broadcast response from: {}", from);
    Ok((buff[..n].to_vec(), from))
}

// Handle a UDP response message.
fn handle_broadcast_resp(from: &SocketAddr, data: &[u8]) -> Result<(SocketAddr, String), SearchError> {
    debug!("handling broadcast response from: {}", from);

    // Convert response to text.
    let text = std::str::from_utf8(data).map_err(SearchError::from)?;

    // Parse socket address and path.
    let (addr, root_url) = parsing::parse_search_result(text)?;

    let addr = crate::common::linklocal::apply_response_scope(addr, *from);

    Ok((addr, root_url))
}

async fn get_control_urls(addr: &SocketAddr, path: &str) -> Result<parsing::DeviceUrls, SearchError> {
    let resp = if crate::common::linklocal::is_scoped_link_local(addr) {
        raw_http_request(*addr, "GET", path, &[], None)
            .await
            .map_err(|_| SearchError::InvalidResponse)?
    } else {
        let uri = match format!("http://{addr}{path}").parse() {
            Ok(uri) => uri,
            Err(err) => return Err(SearchError::from(err)),
        };

        debug!("requesting control url from: {uri}");
        let client: Client<_, Empty<Bytes>> = Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

        Limited::new(client.get(uri).await?.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|_| SearchError::InvalidResponse)?
            .to_bytes()
            .to_vec()
    };

    debug!("handling control response from: {addr}");
    parsing::parse_device_urls(std::io::Cursor::new(&resp))
}

async fn get_control_schemas(
    addr: &SocketAddr,
    control_schema_url: &str,
) -> Result<HashMap<String, Vec<String>>, SearchError> {
    let resp = if crate::common::linklocal::is_scoped_link_local(addr) {
        raw_http_request(*addr, "GET", control_schema_url, &[], None)
            .await
            .map_err(|_| SearchError::InvalidResponse)?
    } else {
        let uri = match format!("http://{addr}{control_schema_url}").parse() {
            Ok(uri) => uri,
            Err(err) => return Err(SearchError::from(err)),
        };

        debug!("requesting control schema from: {uri}");
        let client: Client<_, Empty<Bytes>> = Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

        Limited::new(client.get(uri).await?.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|_| SearchError::InvalidResponse)?
            .to_bytes()
            .to_vec()
    };

    debug!("handling schema response from: {addr}");
    let c = std::io::Cursor::new(&resp);
    parsing::parse_schemas(c)
}

/// Reach a link-local gateway by connecting directly to its scoped socket address (which a URL
/// cannot carry) and speaking HTTP/1.1 over hyper's low-level connection API.
async fn raw_http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: Option<String>,
) -> Result<Vec<u8>, RequestError> {
    use hyper::header::{CONNECTION, HOST};

    use std::task::Poll;

    let host = crate::common::linklocal::host_without_zone(&addr);
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

    let body = body.unwrap_or_default();
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, host)
        .header(CONNECTION, "close")
        .header(CONTENT_LENGTH, body.len() as u64);
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }
    let req = builder.body(Full::new(Bytes::from(body)))?;

    let request = async move {
        let resp = sender.send_request(req).await?;
        let bytes = Limited::new(resp.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|e| RequestError::InvalidResponse(format!("could not read response body: {e}")))?
            .to_bytes();
        Ok::<Vec<u8>, RequestError>(bytes.to_vec())
    };

    let mut request = std::pin::pin!(request);
    let mut conn = std::pin::pin!(conn);
    let mut conn_done = false;

    futures::future::poll_fn(move |cx| {
        if !conn_done {
            match conn.as_mut().poll(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(RequestError::HyperError(e))),
                Poll::Ready(Ok(())) => conn_done = true,
                Poll::Pending => {}
            }
        }
        request.as_mut().poll(cx)
    })
    .await
}

/// If `url` targets a scoped IPv6 link-local address, return that address (with its zone id) and the
/// request path. A normal URL is served by the regular hyper client, so this returns `None`.
fn scoped_link_local_target(url: &str) -> Option<(SocketAddr, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let addr: SocketAddr = authority.parse().ok()?;
    crate::common::linklocal::is_scoped_link_local(&addr).then_some((addr, path))
}
