#![deny(missing_docs)]
#![warn(clippy::std_instead_of_core)]
#![warn(clippy::std_instead_of_alloc)]
#![warn(clippy::alloc_instead_of_core)]

//! This library allows you to communicate with an IGD enabled device.
//! Use one of the `search_gateway` functions to obtain a `Gateway` object.
//! You can then communicate with the device via this object.

extern crate alloc;

// data structures
pub use self::common::parsing::PortMappingEntry;
pub use self::common::SearchOptions;
pub use self::errors::{
    AddAnyPortError, AddPortError, GetExternalIpError, GetGenericPortMappingEntryError, RemovePortError, RequestError,
    SearchError,
};
pub use self::errors::{Error, Result};

#[cfg(feature = "sync")]
pub use self::gateway::Gateway;

// search of gateway
#[cfg(feature = "sync")]
pub use self::search::search_gateway;

#[cfg(any(feature = "aio_tokio", feature = "aio_async_std"))]
pub mod aio;
mod common;
mod errors;

#[cfg(feature = "sync")]
mod gateway;

#[cfg(feature = "sync")]
mod search;

use alloc::fmt;

/// Represents the protocols available for port mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMappingProtocol {
    /// TCP protocol
    TCP,
    /// UDP protocol
    UDP,
}

impl fmt::Display for PortMappingProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                PortMappingProtocol::TCP => "TCP",
                PortMappingProtocol::UDP => "UDP",
            }
        )
    }
}
