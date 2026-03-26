pub mod httpq;
pub mod kt;
pub mod protocols;
pub mod storage;
pub mod engine;

pub use engine::{
    PortableGroupSnapshot, PortableInboundBootstrapEvent, PortableInboundDirectEvent,
    PortableOutboundDirectEvent, PortableOutboundGroupControlEvent, PortableSessionSnapshot,
};
pub use engine::PortableTrustVerificationResult;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientCoreError {
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("invalid state: {0}")]
    State(String),
}

pub type Result<T> = std::result::Result<T, ClientCoreError>;
