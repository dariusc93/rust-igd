use alloc::collections::BTreeMap;
use alloc::str;
use core::net::SocketAddr;
use std::net::UdpSocket;

use log::debug;

use crate::common::{messages, parsing, SearchOptions};
use crate::errors::SearchError;
use crate::gateway::Gateway;

pub(crate) const MAX_RESPONSE_SIZE: usize = 1500;

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
    let socket = UdpSocket::bind(options.bind_addr)?;
    socket.set_read_timeout(options.timeout)?;

    socket.send_to(messages::SEARCH_REQUEST.as_bytes(), options.broadcast_address)?;

    loop {
        let mut buf = [0u8; MAX_RESPONSE_SIZE];
        let (read, _) = socket.recv_from(&mut buf)?;
        let text = str::from_utf8(&buf[..read])?;

        let (addr, root_url) = parsing::parse_search_result(text)?;

        let (control_schema_url, control_url) = match get_control_urls(&addr, &root_url) {
            Ok(o) => o,
            Err(e) => {
                debug!(
                    "Error has occurred while getting control urls. error: {}, addr: {}, root_url: {}",
                    e, addr, root_url
                );
                continue;
            }
        };

        let control_schema = match get_schemas(&addr, &control_schema_url) {
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
}

fn get_control_urls(addr: &SocketAddr, root_url: &str) -> Result<(String, String), SearchError> {
    let url = format!("http://{}:{}{}", addr.ip(), addr.port(), root_url);
    let respond = minreq::get(url).send().map_err(SearchError::HttpError)?;
    parsing::parse_control_urls(respond.as_bytes())
}

fn get_schemas(addr: &SocketAddr, control_schema_url: &str) -> Result<BTreeMap<String, Vec<String>>, SearchError> {
    let url = format!("http://{}:{}{}", addr.ip(), addr.port(), control_schema_url);
    let respond = minreq::get(url).send().map_err(SearchError::HttpError)?;
    parsing::parse_schemas(respond.as_bytes())
}
