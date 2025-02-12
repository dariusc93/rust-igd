use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::str;
use std::time::{Duration, Instant};

use attohttpc::{Method, RequestBuilder};
use log::debug;

use crate::common::options::{DEFAULT_TIMEOUT, RESPONSE_TIMEOUT};
use crate::common::{messages, parsing, SearchOptions};
use crate::errors::SearchError;
use crate::gateway::Gateway;

/// Search gateway, using the given `SearchOptions`.
///
/// The default `SearchOptions` should suffice in most cases.
/// It can be created with `Default::default()` or `SearchOptions::default()`.
///
/// # Example
/// ```no_run
/// use igd_next::{search_gateway, SearchOptions, Result};
///
/// fn main() -> Result {
///     let gateway = search_gateway(Default::default())?;
///     let ip = gateway.get_external_ip()?;
///     println!("External IP address: {}", ip);
///     Ok(())
/// }
/// ```
pub fn search_gateway(options: SearchOptions) -> Result<Gateway, SearchError> {
    let start = Instant::now();
    let max_time = options.timeout.unwrap_or(DEFAULT_TIMEOUT);

    let socket = UdpSocket::bind(options.bind_addr)?;

    let read_timeout = options.single_search_timeout.unwrap_or(RESPONSE_TIMEOUT);
    socket.set_read_timeout(Some(read_timeout))?;

    socket.send_to(messages::SEARCH_REQUEST.as_bytes(), options.broadcast_address)?;

    while start.elapsed() < max_time {
        let mut buf = [0u8; 1500];

        // limit read, to the remaining time available
        socket.set_read_timeout(Some(max_time - start.elapsed()))?;
        let (read, _) = socket.recv_from(&mut buf)?;
        let text = str::from_utf8(&buf[..read])?;

        let (addr, root_url) = parsing::parse_search_result(text)?;

        let (control_schema_url, control_url) = match get_control_urls(&addr, &root_url, max_time - start.elapsed()) {
            Ok(o) => o,
            Err(e) => {
                debug!(
                    "Error has occurred while getting control urls. error: {}, addr: {}, root_url: {}",
                    e, addr, root_url
                );
                continue;
            }
        };

        let control_schema = match get_schemas(&addr, &control_schema_url, max_time - start.elapsed()) {
            Ok(o) => o,
            Err(e) => {
                debug!(
                    "Error has occurred while getting schemas. error: {}, addr: {}, control_schema_url: {}",
                    e, addr, control_schema_url
                );
                continue;
            }
        };

        return Ok(Gateway {
            addr,
            root_url,
            control_url,
            control_schema_url,
            control_schema,
        });
    }

    Err(SearchError::NoResponseWithinTimeout)
}

fn get_control_urls(addr: &SocketAddr, root_url: &str, timeout: Duration) -> Result<(String, String), SearchError> {
    let url = format!("http://{}:{}{}", addr.ip(), addr.port(), root_url);
    match RequestBuilder::try_new(Method::GET, url) {
        Ok(request_builder) => {
            let response = request_builder.timeout(timeout).send()?;
            parsing::parse_control_urls(&response.bytes()?[..])
        }
        Err(error) => Err(SearchError::HttpError(error)),
    }
}

fn get_schemas(
    addr: &SocketAddr,
    control_schema_url: &str,
    timeout: Duration,
) -> Result<HashMap<String, Vec<String>>, SearchError> {
    let url = format!("http://{}:{}{}", addr.ip(), addr.port(), control_schema_url);
    match RequestBuilder::try_new(Method::GET, url) {
        Ok(request_builder) => {
            let response = request_builder.timeout(timeout).send()?;
            parsing::parse_schemas(&response.bytes()?[..])
        }
        Err(error) => Err(SearchError::HttpError(error)),
    }
}
