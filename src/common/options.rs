use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Default timeout for a gateway search.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for each broadcast response during a gateway search.
#[allow(dead_code)]
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Gateway search configuration
///
/// SearchOptions::default() should suffice for most situations.
///
/// # Example
/// To customize only a few options you can use `Default::default()` or `SearchOptions::default()` and the
/// [struct update syntax](https://doc.rust-lang.org/book/ch05-01-defining-structs.html#creating-instances-from-other-instances-with-struct-update-syntax).
/// ```
/// # use std::time::Duration;
/// # use igd_next::SearchOptions;
/// let opts = SearchOptions::default().set_timeout(Duration::from_secs(10));
/// ```
pub struct SearchOptions {
    /// Bind address for UDP socket (defaults to all `0.0.0.0`)
    bind_addr: SocketAddr,
    /// Broadcast address for discovery packets (defaults to `239.255.255.250:1900`)
    broadcast_address: SocketAddr,
    /// Timeout for a search iteration (defaults to 10s)
    timeout: Option<Duration>,
    /// Timeout for a single search response (defaults to 5s)
    single_search_timeout: Option<Duration>,
}

impl SearchOptions {
    /// Set bind address for UDP socket (defaults to all `0.0.0.0`)
    pub fn set_bind_addr(mut self, bind_addr: impl Into<SocketAddr>) -> Self {
        self.bind_addr = bind_addr.into();
        self
    }

    /// Set broadcast address for delivery packets  (defaults to `239.255.255.250:1900`)
    pub fn set_broadcast_address(mut self, broadcast_address: impl Into<SocketAddr>) -> Self {
        self.broadcast_address = broadcast_address.into();
        self
    }

    /// Set timeout for a search iteration (defaults to 10s)
    pub fn set_timeout(mut self, timeout: impl Into<Option<Duration>>) -> Self {
        self.timeout = timeout.into();
        self
    }

    /// Set timeout for a single search response (defaults to 5s)
    pub fn set_single_search_timeout(mut self, single_search_timeout: impl Into<Option<Duration>>) -> Self {
        self.single_search_timeout = single_search_timeout.into();
        self
    }
}

impl SearchOptions {
    /// Bind address for UDP socket (defaults to all `0.0.0.0`)
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Broadcast address for discovery packets (defaults to `239.255.255.250:1900`)
    pub fn broadcast_address(&self) -> SocketAddr {
        self.broadcast_address
    }

    /// Timeout for a search iteration (defaults to 10s)
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Timeout for a single search response (defaults to 5s)
    pub fn single_search_timeout(&self) -> Option<Duration> {
        self.single_search_timeout
    }
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            bind_addr: (IpAddr::from([0, 0, 0, 0]), 0).into(),
            broadcast_address: "239.255.255.250:1900".parse().unwrap(),
            timeout: Some(DEFAULT_TIMEOUT),
            single_search_timeout: Some(RESPONSE_TIMEOUT),
        }
    }
}
