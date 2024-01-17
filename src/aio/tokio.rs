//! Tokio abstraction for the aio [`Gateway`].

use super::{Reqwless, MAX_RESPONSE_SIZE};
use crate::aio::Gateway;
use crate::common::{messages, SearchOptions};
use crate::errors::SearchError;
use embedded_io_adapters::tokio_1::FromTokio;
use embedded_io_async::{ErrorType, Read, Write};
use embedded_nal_async::{AddrType, Dns, IpAddr, SocketAddr, TcpConnect};
use futures::prelude::*;
use log::debug;
use reqwless::client::HttpClient;
use reqwless::TryBufRead;
use tokio::net::TcpStream;
use tokio::{net::UdpSocket, time::timeout};

/// Stream shim for Tokio

pub struct TokioStream(pub(crate) FromTokio<TcpStream>);

impl TryBufRead for TokioStream {}

impl ErrorType for TokioStream {
    type Error = <FromTokio<TcpStream> as ErrorType>::Error;
}

impl Read for TokioStream {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.read(buf).await
    }
}

impl Write for TokioStream {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.0.write(buf).await
    }
}

/// TcpSocket shim for Tokio
pub struct TokioTcp;

impl TcpConnect for TokioTcp {
    type Error = std::io::Error;
    type Connection<'a> = TokioStream;

    async fn connect(&self, remote: SocketAddr) -> Result<Self::Connection<'_>, Self::Error> {
        let ip = match remote {
            SocketAddr::V4(a) => a.ip().octets().into(),
            SocketAddr::V6(a) => a.ip().octets().into(),
        };
        let remote = SocketAddr::new(ip, remote.port());
        let stream = TcpStream::connect(remote).await?;
        let stream = FromTokio::new(stream);
        Ok(TokioStream(stream))
    }
}

/// DNS resolver for Tokio
pub struct TokioDns;

impl Dns for TokioDns {
    type Error = std::io::Error;

    async fn get_host_by_name(&self, host: &str, addr_type: AddrType) -> Result<IpAddr, Self::Error> {
        for address in tokio::net::lookup_host((host, 0_u16)).await? {
            match address {
                SocketAddr::V4(a) if addr_type == AddrType::IPv4 || addr_type == AddrType::Either => {
                    return Ok(IpAddr::V4(a.ip().octets().into()))
                }
                SocketAddr::V6(a) if addr_type == AddrType::IPv6 || addr_type == AddrType::Either => {
                    return Ok(IpAddr::V6(a.ip().octets().into()))
                }
                _ => {}
            }
        }
        Err(std::io::ErrorKind::AddrNotAvailable.into())
    }

    async fn get_host_by_address(&self, _: IpAddr, _: &mut [u8]) -> Result<usize, Self::Error> {
        todo!()
    }
}

/// Search for a gateway with the provided options.
pub async fn search_gateway<'a>(
    options: SearchOptions,
) -> Result<Gateway<Reqwless<'a, TokioTcp, TokioDns>>, SearchError> {
    // Create socket for future calls
    let socket = UdpSocket::bind(&options.bind_addr).await?;

    let addr = options.broadcast_address;
    debug!(
        "sending broadcast request to: {} on interface: {:?}",
        addr,
        socket.local_addr()
    );
    socket
        .send_to(messages::SEARCH_REQUEST.as_bytes(), &addr)
        .map_ok(|_| ())
        .map_err(SearchError::from)
        .await?;

    let search_response = async {
        let mut buff = [0u8; MAX_RESPONSE_SIZE];
        let (n, from) = socket.recv_from(&mut buff).map_err(SearchError::from).await?;
        debug!("received broadcast response from: {}", from);
        Ok::<_, SearchError>((buff[..n].to_vec(), from))
    };

    // Receive search response, optionally with a timeout.
    let (response_body, from) = match options.timeout {
        Some(t) => timeout(t, search_response).await?,
        None => search_response.await,
    }?;

    super::create_gateway(from, response_body, HttpClient::new(&TokioTcp, &TokioDns)).await
}
