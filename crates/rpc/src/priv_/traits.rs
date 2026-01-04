//! Traits for privacy RPC methods.

use alloy_primitives::{Address, Bytes, U256};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use crate::priv_::types::PrivateTransactionResult;

/// RPC API for privacy operations.
///
/// These methods enable private transaction execution and privacy-related queries.
#[rpc(server, namespace = "priv")]
pub trait PrivacyApi {
    /// Submit and execute a private transaction.
    ///
    /// The transaction is executed immediately in the TEE environment.
    /// If public writes occur, a block transaction is created for on-chain inclusion.
    ///
    /// # Parameters
    ///
    /// * `raw_tx` - RLP-encoded private transaction bytes
    ///
    /// # Returns
    ///
    /// The execution result including output, gas used, and whether public writes occurred.
    #[method(name = "sendRawTransaction")]
    async fn send_raw_transaction(&self, raw_tx: Bytes) -> RpcResult<PrivateTransactionResult>;

    /// Get the current private nonce for an address.
    ///
    /// This returns the nonce that should be used for the next private transaction
    /// from this address.
    ///
    /// # Parameters
    ///
    /// * `address` - The address to query the nonce for
    ///
    /// # Returns
    ///
    /// The current private nonce (next expected nonce for a transaction).
    #[method(name = "getPrivateNonce")]
    async fn get_private_nonce(&self, address: Address) -> RpcResult<U256>;

    /// Get the shielded address for a user, protocol, and index.
    ///
    /// Shielded addresses are deterministically derived from:
    /// - The user's real address
    /// - The protocol contract address
    /// - An index (0 = persistent, >0 = fresh/ephemeral)
    ///
    /// # Parameters
    ///
    /// * `user` - The real user address
    /// * `protocol` - The protocol address for derivation context
    /// * `index` - Shielded index (0 for persistent address)
    ///
    /// # Returns
    ///
    /// The derived shielded address.
    #[method(name = "getShieldedAddress")]
    async fn get_shielded_address(
        &self,
        user: Address,
        protocol: Address,
        index: u64,
    ) -> RpcResult<Address>;

    /// Get a private storage value.
    ///
    /// This checks authorization before returning values. Returns zero
    /// for unauthorized callers or if the slot is not private.
    ///
    /// # Parameters
    ///
    /// * `contract` - Contract address
    /// * `slot` - Storage slot
    /// * `caller` - The caller address for authorization checking
    ///
    /// # Returns
    ///
    /// The storage value if authorized, zero otherwise.
    #[method(name = "getPrivateStorage")]
    async fn get_private_storage(
        &self,
        contract: Address,
        slot: U256,
        caller: Address,
    ) -> RpcResult<U256>;
}
