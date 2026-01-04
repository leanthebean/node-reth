//! Privacy RPC module.
//!
//! This module provides the `priv_*` JSON-RPC methods for privacy operations:
//! - `priv_sendRawTransaction` - Submit and execute a private transaction
//! - `priv_getPrivateNonce` - Get the current private nonce for an address
//! - `priv_getShieldedAddress` - Get the shielded address for a protocol and index
//! - `priv_getPrivateStorage` - Get a private storage value (with auth check)

mod rpc;
mod traits;
mod types;

pub use rpc::PrivacyApiImpl;
pub use traits::PrivacyApiServer;
pub use types::PrivateTransactionResult;
