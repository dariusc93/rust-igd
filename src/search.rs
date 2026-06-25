use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::str;
use std::time::{Duration, Instant};

use attohttpc::{Method, RequestBuilder};
use log::debug;

use crate::common::options::{DEFAULT_TIMEOUT, MAX_RESPONSE_BYTES, RESPONSE_TIMEOUT};
use crate::common::{self, messages, parsing, SearchOptions};
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

    let response_timeout = options.single_search_timeout.unwrap_or(RESPONSE_TIMEOUT);

    let request = messages::search_request(&options.broadcast_address);
    socket.send_to(request.as_bytes(), options.broadcast_address)?;

    while start.elapsed() < max_time {
        let remaining = max_time.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            break;
        }

        // limit read, to the remaining time available
        socket.set_read_timeout(Some(response_timeout.min(remaining)))?;

        let mut buf = [0u8; 1500];
        let (read, _) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                debug!("error while receiving broadcast response: {e}");
                continue;
            }
        };

        let text = match str::from_utf8(&buf[..read]) {
            Ok(text) => text,
            Err(e) => {
                debug!("received a non-utf8 broadcast response: {e}");
                continue;
            }
        };

        let (addr, root_url) = match parsing::parse_search_result(text) {
            Ok(v) => v,
            Err(e) => {
                debug!("could not parse broadcast response: {e}");
                continue;
            }
        };

        if !options.gateway_ip_version.accepts(addr.ip()) {
            debug!("skipping gateway {addr}. Not the requested IP version");
            continue;
        }

        let urls = match get_control_urls(&addr, &root_url, max_time.saturating_sub(start.elapsed())) {
            Ok(o) => o,
            Err(e) => {
                debug!(
                    "Error has occurred while getting control urls. error: {}, addr: {}, root_url: {}",
                    e, addr, root_url
                );
                continue;
            }
        };

        let control_schema = match get_schemas(
            &addr,
            &urls.control_schema_url,
            max_time.saturating_sub(start.elapsed()),
        ) {
            Ok(o) => o,
            Err(e) => {
                debug!(
                    "Error has occurred while getting schemas. error: {}, addr: {}, control_schema_url: {}",
                    e, addr, urls.control_schema_url
                );
                continue;
            }
        };

        return Ok(Gateway {
            addr,
            root_url,
            control_url: urls.control_url,
            control_schema_url: urls.control_schema_url,
            control_schema,
            service_type: urls.service_type,
            #[cfg(feature = "ipv6")]
            ipv6_firewall_control_url: urls.ipv6_firewall_control_url,
        });
    }

    Err(SearchError::NoResponseWithinTimeout)
}

fn get_control_urls(addr: &SocketAddr, root_url: &str, timeout: Duration) -> Result<parsing::DeviceUrls, SearchError> {
    let url = format!("http://{addr}{root_url}");
    let response = match RequestBuilder::try_new(Method::GET, url) {
        Ok(request_builder) => request_builder.timeout(timeout).send()?,
        Err(error) => return Err(SearchError::HttpError(error)),
    };
    let body = common::read_response_body(response, MAX_RESPONSE_BYTES)?;
    let (service_type, control_schema_url, control_url) = parsing::parse_control_urls(&body[..])?;
    Ok(parsing::DeviceUrls {
        service_type,
        control_schema_url,
        control_url,
        #[cfg(feature = "ipv6")]
        ipv6_firewall_control_url: parsing::parse_firewall_control_url(&body[..]),
    })
}

fn get_schemas(
    addr: &SocketAddr,
    control_schema_url: &str,
    timeout: Duration,
) -> Result<HashMap<String, Vec<String>>, SearchError> {
    let url = format!("http://{addr}{control_schema_url}");
    match RequestBuilder::try_new(Method::GET, url) {
        Ok(request_builder) => {
            let response = request_builder.timeout(timeout).send()?;
            parsing::parse_schemas(&common::read_response_body(response, MAX_RESPONSE_BYTES)?[..])
        }
        Err(error) => Err(SearchError::HttpError(error)),
    }
}
