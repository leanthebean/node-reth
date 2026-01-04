//! Privacy RPC Handler Logic.
//!
//! This module provides the handler logic for privacy-related RPC methods:
//! - `priv_sendRawTransaction` - Submit a private transaction
//! - `priv_getPrivateNonce` - Get the current private nonce for an address
//! - `priv_getShieldedAddress` - Get the shielded address for a protocol and index
//!
//! These handlers are designed to be integrated into the rpc crate's JSON-RPC layer.
//! They provide the core logic without the JSON-RPC framework dependencies.
//!
//! # Example
//!
//! ```ignore
//! use base_reth_privacy::rpc_handler::PrivacyRpcHandler;
//!
//! let handler = PrivacyRpcHandler::new(executor, block_env_fn);
//!
//! // Submit a private transaction
//! let result = handler.send_raw_transaction(hex_tx, db)?;
//!
//! // Get private nonce
//! let nonce = handler.get_private_nonce(address);
//!
//! // Get shielded address
//! let shielded = handler.get_shielded_address(user, protocol, index);
//! ```

use crate::{
    executor::{ExecutorError, PrivateExecutionResult, PrivateTransactionExecutor},
    transaction::PrivateTransaction,
};
use alloy_primitives::{Address, Bytes};
use op_revm::OpSpecId;
use revm::{context::BlockEnv, database_interface::Database, DatabaseCommit};
use std::fmt::Debug;
use std::sync::Arc;

/// Handler for privacy-related RPC methods.
///
/// This handler provides the core logic for executing private transactions
/// and querying privacy-related state.
#[derive(Debug)]
pub struct PrivacyRpcHandler {
    /// The private transaction executor.
    executor: Arc<PrivateTransactionExecutor>,
    /// Default OP spec ID to use for execution.
    spec_id: OpSpecId,
}

impl PrivacyRpcHandler {
    /// Create a new privacy RPC handler.
    pub fn new(executor: Arc<PrivateTransactionExecutor>, spec_id: OpSpecId) -> Self {
        Self { executor, spec_id }
    }

    /// Get a reference to the executor.
    pub fn executor(&self) -> &PrivateTransactionExecutor {
        &self.executor
    }

    /// Submit a private transaction.
    ///
    /// # Arguments
    ///
    /// * `raw_tx` - Hex-encoded private transaction
    /// * `db` - State database
    /// * `block_env` - Current block environment
    ///
    /// # Returns
    ///
    /// The execution result, or an error if validation or execution fails.
    pub fn send_raw_transaction<DB>(
        &self,
        raw_tx: &Bytes,
        db: DB,
        block_env: BlockEnv,
    ) -> Result<PrivateExecutionResult, PrivacyRpcError>
    where
        DB: Database + DatabaseCommit + Debug,
        DB::Error: std::error::Error + Send + Sync + 'static,
    {
        // Decode the transaction
        let tx = PrivateTransaction::from_bytes(raw_tx)
            .map_err(|e| PrivacyRpcError::InvalidTransaction(e.to_string()))?;

        // Execute
        self.executor
            .execute_private_tx(&tx, db, block_env, self.spec_id)
            .map_err(PrivacyRpcError::Executor)
    }

    /// Get the current private nonce for an address.
    ///
    /// This is the nonce that should be used for the next private transaction.
    pub fn get_private_nonce(&self, address: Address) -> u64 {
        self.executor.nonce_manager().get_nonce(address)
    }

    /// Get the shielded address for a user, protocol, and index.
    ///
    /// # Arguments
    ///
    /// * `user` - The real user address
    /// * `protocol` - The protocol address for derivation
    /// * `index` - The shielded index (0 for persistent, >0 for fresh)
    ///
    /// # Returns
    ///
    /// The derived shielded address.
    pub fn get_shielded_address(&self, user: Address, protocol: Address, index: u64) -> Address {
        self.executor
            .shielded_manager()
            .get_shielded_address(user, protocol, index)
    }

    /// Get a private storage value.
    ///
    /// This checks authorization before returning the value.
    ///
    /// # Arguments
    ///
    /// * `contract` - Contract address
    /// * `slot` - Storage slot
    /// * `caller` - The caller requesting the value (for authorization)
    ///
    /// # Returns
    ///
    /// The storage value if authorized, or zero if not.
    pub fn get_private_storage(
        &self,
        contract: Address,
        slot: alloy_primitives::U256,
        caller: Address,
    ) -> alloy_primitives::U256 {
        use crate::classification::{classify_slot, SlotClassification};
        use crate::store::READ;

        let registry = self.executor.registry();
        let store = self.executor.private_store();

        // Classify the slot
        match classify_slot(registry, contract, slot) {
            SlotClassification::Public => {
                // Public slot - return zero (caller should use eth_getStorageAt)
                alloy_primitives::U256::ZERO
            }
            SlotClassification::Private { owner } => {
                // Check authorization
                if caller == owner || caller == contract {
                    store.get(contract, slot)
                } else if store.is_authorized(contract, slot, caller, READ) {
                    store.get(contract, slot)
                } else {
                    // Not authorized
                    alloy_primitives::U256::ZERO
                }
            }
        }
    }

    /// Sign a private transaction.
    ///
    /// Creates a properly signed `PrivateTransaction` that can be submitted.
    /// This is a helper for testing/development.
    ///
    /// Note: In production, the user would sign the transaction themselves.
    pub fn create_signed_transaction(
        &self,
        from: Address,
        to: Address,
        data: Bytes,
        gas_limit: u64,
        mode: crate::PrivacyMode,
        private_key: &[u8; 32],
    ) -> Result<PrivateTransaction, PrivacyRpcError> {
        let nonce = self.get_private_nonce(from);
        let chain_id = self.executor.chain_id();

        let tx = PrivateTransaction::new(from, to, data, gas_limit, nonce, mode, chain_id);
        let signed = tx
            .sign(private_key)
            .map_err(|e| PrivacyRpcError::SigningError(e.to_string()))?;

        Ok(signed)
    }
}

/// Errors that can occur in privacy RPC handlers.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PrivacyRpcError {
    /// Invalid transaction format.
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Executor error.
    #[error("executor error: {0}")]
    Executor(#[from] ExecutorError),

    /// Signing error.
    #[error("signing error: {0}")]
    SigningError(String),

    /// Database error.
    #[error("database error: {0}")]
    Database(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        nonce::PrivateNonceManager, registry::PrivacyRegistry, shielded::ShieldedKeyManager,
        store::PrivateStateStore,
    };

    fn test_user() -> Address {
        Address::new([0x42; 20])
    }

    fn test_protocol() -> Address {
        Address::new([0x11; 20])
    }

    fn create_handler() -> PrivacyRpcHandler {
        let nonce_manager = Arc::new(PrivateNonceManager::new());
        let shielded_manager = Arc::new(ShieldedKeyManager::new(84532));
        let registry = Arc::new(PrivacyRegistry::new());
        let store = Arc::new(PrivateStateStore::new());

        let executor = Arc::new(PrivateTransactionExecutor::new(
            nonce_manager,
            shielded_manager,
            registry,
            store,
            84532,
        ));

        PrivacyRpcHandler::new(executor, OpSpecId::CANYON)
    }

    #[test]
    fn test_get_private_nonce() {
        let handler = create_handler();
        let user = test_user();

        // Initial nonce should be 0
        assert_eq!(handler.get_private_nonce(user), 0);

        // Increment nonce
        handler.executor.nonce_manager().increment_nonce(user);
        assert_eq!(handler.get_private_nonce(user), 1);
    }

    #[test]
    fn test_get_shielded_address() {
        let handler = create_handler();
        let user = test_user();
        let protocol = test_protocol();

        let addr0 = handler.get_shielded_address(user, protocol, 0);
        let addr1 = handler.get_shielded_address(user, protocol, 1);

        // Different indices should give different addresses
        assert_ne!(addr0, addr1);

        // Same inputs should give same output (deterministic)
        assert_eq!(addr0, handler.get_shielded_address(user, protocol, 0));
    }

    #[test]
    fn test_get_shielded_address_different_protocols() {
        let handler = create_handler();
        let user = test_user();
        let protocol1 = Address::new([0x11; 20]);
        let protocol2 = Address::new([0x22; 20]);

        let addr1 = handler.get_shielded_address(user, protocol1, 0);
        let addr2 = handler.get_shielded_address(user, protocol2, 0);

        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_error_display() {
        let err = PrivacyRpcError::InvalidTransaction("bad format".to_string());
        assert!(format!("{}", err).contains("bad format"));
    }
}
