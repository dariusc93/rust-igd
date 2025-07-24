//! This module implements the same features as the main crate, but using async io.

mod gateway;

#[cfg(feature = "aio_tokio")]
pub mod tokio;

use async_trait::async_trait;

use crate::RequestError;

pub use self::gateway::Gateway;

pub(crate) const MAX_RESPONSE_SIZE: usize = 1500;
pub(crate) const HEADER_NAME: &str = "SOAPAction";

/// Trait to allow abstracting over `tokio`.
#[async_trait]
pub trait Provider {
    /// Send an async request over the executor.
    async fn send_async(url: &str, action: &str, body: &str) -> Result<String, RequestError>;
}
