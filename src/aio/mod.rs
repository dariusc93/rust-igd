//! This module implements the same features as the main crate, but using async io.

mod gateway;

#[cfg(feature = "aio_tokio")]
pub mod tokio;

#[cfg(feature = "aio_async_std")]
pub mod async_std;

use std::future::Future;

use crate::RequestError;

pub use self::gateway::Gateway;

pub(crate) const MAX_RESPONSE_SIZE: usize = 1500;
pub(crate) const HEADER_NAME: &str = "SOAPAction";

/// Trait to allow abstracting over `tokio` and `async-std`.
pub trait Provider {
    /// Send an async request over the executor.
    fn send_async(url: &str, action: &str, body: &str) -> impl Future<Output = Result<String, RequestError>>;
}
