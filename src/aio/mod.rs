//! This module implements the same features as the main crate, but using async io.

mod gateway;

#[cfg(feature = "aio_tokio")]
pub mod tokio;

#[cfg(feature = "aio_async_std")]
pub mod async_std;

use alloc::collections::BTreeMap;

use embedded_nal_async::{Dns, SocketAddr, TcpConnect};
use log::debug;
use nourl::Url;
use reqwless::request::RequestBuilder;
use reqwless::{client::HttpClient, request::Method};
use core::future::Future;

use crate::{RequestError, SearchError};

pub use self::gateway::Gateway;

pub(crate) const MAX_RESPONSE_SIZE: usize = 1500;
pub(crate) const HEADER_NAME: &str = "SOAPAction";

/// Trait to allow abstracting over `tokio` and `async-std`.
pub trait Provider {
    /// Send an async request over the executor.
    fn send_async(&mut self, url: &str, action: &str, body: &str) -> impl Future<Output = Result<String, RequestError>>;
}

/// Reqwless provider for the [`Gateway`].
pub struct Reqwless<'a, T, D>(HttpClient<'a, T, D>)
where
    T: TcpConnect,
    D: Dns;

impl<'a, T, D> Provider for Reqwless<'a, T, D>
where
    T: TcpConnect,
    D: Dns,
{
    async fn send_async(&mut self, url: &str, action: &str, body: &str) -> Result<String, RequestError> {
        let headers = [(HEADER_NAME, action), ("Content-Type", "text/xml")];

        let mut rx_buf = vec![0; 1024];
        let body = loop {
            let mut client = self
                .0
                .request(Method::POST, url)
                .await?
                .body(body.as_bytes())
                .headers(&headers);
            let resp = match client.send(&mut rx_buf).await {
                Err(reqwless::Error::BufferTooSmall) => {
                    rx_buf.resize(rx_buf.len() * 2, 0);
                    continue;
                }
                resp => resp,
            }
            .map_err(RequestError::from)?;
            match resp.body().read_to_end().await {
                Err(reqwless::Error::BufferTooSmall) => {
                    rx_buf.resize(rx_buf.len() * 2, 0);
                    continue;
                }
                resp => break resp?,
            }
        };

        Ok(String::from_utf8(body.to_vec())?)
    }
}

async fn create_gateway<'a, T, D>(
    from: SocketAddr,
    response_body: Vec<u8>,
    mut client: HttpClient<'_, T, D>,
) -> Result<Gateway<Reqwless<'_, T, D>>, SearchError>
where
    T: TcpConnect,
    D: Dns,
{
    let (addr, root_url) = handle_broadcast_resp(&from, &response_body)?;

    let (control_schema_url, control_url) = get_control_urls(&addr, &root_url, &mut client).await?;
    let control_schema = get_control_schemas(&addr, &control_schema_url, &mut client).await?;

    Ok(Gateway {
        addr,
        root_url,
        control_url,
        control_schema_url,
        control_schema,
        provider: Reqwless(client),
    })
}

// Handle a UDP response message.
pub(crate) fn handle_broadcast_resp(from: &SocketAddr, data: &[u8]) -> Result<(SocketAddr, String), SearchError> {
    debug!("handling broadcast response from: {}", from);

    // Convert response to text.
    let text = core::str::from_utf8(data).map_err(SearchError::from)?;

    // Parse socket address and path.
    let (addr, root_url) = crate::common::parsing::parse_search_result(text)?;

    Ok((addr, root_url))
}

pub(crate) async fn get_control_urls<'a, T, D>(
    addr: &SocketAddr,
    path: &str,
    client: &mut HttpClient<'a, T, D>,
) -> Result<(String, String), SearchError>
where
    T: TcpConnect,
    D: Dns,
{
    let uri = format!("http://{addr}{path}");
    let uri = match Url::parse(&uri) {
        Ok(_) => uri.as_str(),
        Err(err) => return Err(SearchError::from(err)),
    };

    debug!("requesting control url from: {uri}");

    let mut rx_buf = vec![0; 1024];
    let body = loop {
        let mut client = client.request(Method::GET, uri).await?;
        let resp = match client.send(&mut rx_buf).await {
            Err(reqwless::Error::BufferTooSmall) => {
                rx_buf.resize(rx_buf.len() * 2, 0);
                continue;
            }
            resp => resp,
        }
        .map_err(SearchError::from)?;
        match resp.body().read_to_end().await {
            Err(reqwless::Error::BufferTooSmall) => {
                rx_buf.resize(rx_buf.len() * 2, 0);
                continue;
            }
            resp => break resp?,
        }
    };

    debug!("handling control response from: {addr}");
    let c = std::io::Cursor::new(body);
    crate::common::parsing::parse_control_urls(c)
}

pub(crate) async fn get_control_schemas<'a, T, D>(
    addr: &SocketAddr,
    control_schema_url: &str,
    client: &mut HttpClient<'a, T, D>,
) -> Result<BTreeMap<String, Vec<String>>, SearchError>
where
    T: TcpConnect,
    D: Dns,
{
    let uri = format!("http://{addr}{control_schema_url}");
    let uri = match Url::parse(&uri) {
        Ok(_) => uri.as_str(),
        Err(err) => return Err(SearchError::from(err)),
    };

    debug!("requesting control schema from: {uri}");

    let mut rx_buf = vec![0; 1024];
    let body = loop {
        let mut client = client.request(Method::GET, uri).await?;
        let resp = match client.send(&mut rx_buf).await {
            Err(reqwless::Error::BufferTooSmall) => {
                rx_buf.resize(rx_buf.len() * 2, 0);
                continue;
            }
            resp => resp,
        }
        .map_err(SearchError::from)?;
        match resp.body().read_to_end().await {
            Err(reqwless::Error::BufferTooSmall) => {
                rx_buf.resize(rx_buf.len() * 2, 0);
                continue;
            }
            resp => break resp?,
        }
    };

    debug!("handling schema response from: {addr}");
    let c = std::io::Cursor::new(body);
    crate::common::parsing::parse_schemas(c)
}
