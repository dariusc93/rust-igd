//! Tokio abstraction for the aio [`Gateway`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use async_trait::async_trait;
use futures::prelude::*;
use hyper::{
    header::{CONTENT_LENGTH, CONTENT_TYPE},
    Body, Client, Request,
};

use tokio::{net::UdpSocket, time::timeout};

use log::debug;
use tokio::time::error::Elapsed;
use crate::common::{messages, parsing, SearchOptions};
use crate::{aio::Gateway, RequestError};
use crate::common::options::DEFAULT_TIMEOUT;
use super::{Provider, HEADER_NAME, MAX_RESPONSE_SIZE};
use crate::errors::SearchError;

/// Tokio provider for the [`Gateway`].
#[derive(Debug, Clone)]
pub struct Tokio;

#[async_trait]
impl Provider for Tokio {
    async fn send_async(url: &str, action: &str, body: &str) -> Result<String, RequestError> {
        let client = Client::new();

        let req = Request::builder()
            .uri(url)
            .method("POST")
            .header(HEADER_NAME, action)
            .header(CONTENT_TYPE, "text/xml")
            .header(CONTENT_LENGTH, body.len() as u64)
            .body(Body::from(body.to_string()))?;

        let resp = client.request(req).await?;
        let body = hyper::body::to_bytes(resp.into_body()).await?;
        let string = String::from_utf8(body.to_vec())?;
        Ok(string)
    }
}

/// Timeout for each broadcast response.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Search for a gateway with the provided options.
pub async fn search_gateway(options: SearchOptions) -> Result<Gateway<Tokio>, SearchError> {
    // Create socket for future calls
    let mut socket = UdpSocket::bind(&options.bind_addr).await?;

    send_search_request(&mut socket, options.broadcast_address).await?;

    let max_search_time = options.timeout.unwrap_or(DEFAULT_TIMEOUT);
    let start_search_time = std::time::Instant::now();

    loop {
        if start_search_time.elapsed() > max_search_time {
            break Err(SearchError::NoResponseWithinTimeout);
        }

        let search_response = receive_search_response(&mut socket);

        // Receive search response
        let (response_body, from) = match timeout(RESPONSE_TIMEOUT, search_response).await {
            Ok(Ok(v)) => v,
            Ok(Err(err)) => {
                debug!("error while receiving broadcast response: {err}");
                continue;
            },
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

        let (control_schema_url, control_url) = match get_control_urls(&addr, &root_url).await {
            Ok(v) => v,
            Err(e) => {
                debug!("error getting control URLs: {}", e);
                continue;
            }
        };

        let control_schema = match get_control_schemas(&addr, &control_schema_url).await {
            Ok(v) => v,
            Err(e) => {
                debug!("error getting control schemas: {}", e);
                continue;
            }
        };

        break Ok(Gateway {
            addr,
            root_url,
            control_url,
            control_schema_url,
            control_schema,
            provider: Tokio,
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
    socket
        .send_to(messages::SEARCH_REQUEST.as_bytes(), &addr)
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

    Ok((addr, root_url))
}

async fn get_control_urls(addr: &SocketAddr, path: &str) -> Result<(String, String), SearchError> {
    let uri = match format!("http://{addr}{path}").parse() {
        Ok(uri) => uri,
        Err(err) => return Err(SearchError::from(err)),
    };

    debug!("requesting control url from: {uri}");
    let client = Client::new();
    let resp = hyper::body::to_bytes(client.get(uri).await?.into_body())
        .map_err(SearchError::from)
        .await?;

    debug!("handling control response from: {addr}");
    let c = std::io::Cursor::new(&resp);
    parsing::parse_control_urls(c)
}

async fn get_control_schemas(
    addr: &SocketAddr,
    control_schema_url: &str,
) -> Result<HashMap<String, Vec<String>>, SearchError> {
    let uri = match format!("http://{addr}{control_schema_url}").parse() {
        Ok(uri) => uri,
        Err(err) => return Err(SearchError::from(err)),
    };

    debug!("requesting control schema from: {uri}");
    let client = Client::new();
    let resp = hyper::body::to_bytes(client.get(uri).await?.into_body())
        .map_err(SearchError::from)
        .await?;

    debug!("handling schema response from: {addr}");
    let c = std::io::Cursor::new(&resp);
    parsing::parse_schemas(c)
}
