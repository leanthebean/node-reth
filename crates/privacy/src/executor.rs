//! Private Transaction Executor.
//!
//! The executor handles the complete lifecycle of a private transaction:
//!
//! 1. **Validation**: Verify signature, check nonce, validate structure
//! 2. **Mode Resolution**: Determine effective sender (Real or Shielded)
//! 3. **Execution**: Run the EVM with privacy-aware database
//! 4. **Write Detection**: Track if any public storage was written
//! 5. **Block Transaction**: Create on-chain transaction if needed
//!
//! # Execution Flow
//!
//! ```text
//!     priv_sendRawTransaction
//!             │
//!             ▼
//!     ┌───────────────┐
//!     │   Validate    │ ← Signature, nonce, structure
//!     └───────┬───────┘
//!             │
//!             ▼
//!     ┌───────────────┐
//!     │  Resolve Mode │ ← Real: msg.sender = user
//!     │               │   Shielded: msg.sender = derived
//!     └───────┬───────┘
//!             │
//!             ▼
//!     ┌───────────────┐
//!     │    Execute    │ ← EVM with PrivacyDatabase
//!     └───────┬───────┘
//!             │
//!     ┌───────┴───────┐
//!     │               │
//!     ▼               ▼
//! No public      Public writes
//! writes         occurred
//!     │               │
//!     │               ▼
//!     │       ┌───────────────┐
//!     │       │ Create Block  │ ← Sign with shielded key if Shielded
//!     │       │  Transaction  │
//!     │       └───────────────┘
//!     │               │
//!     └───────┬───────┘
//!             ▼
//!        Return Result
//! ```

use crate::{
    mode::PrivacyMode,
    nonce::{NonceError, PrivateNonceManager},
    shielded::ShieldedKeyManager,
    transaction::{PrivateTransaction, PrivateTransactionError},
};
use alloy_primitives::{Address, Bytes, Signature, B256};
use std::sync::Arc;

/// Result of executing a private transaction.
#[derive(Debug, Clone)]
pub struct PrivateExecutionResult {
    /// Whether execution succeeded (didn't revert).
    pub success: bool,

    /// Return data from the execution.
    pub output: Bytes,

    /// Gas used during execution.
    pub gas_used: u64,

    /// Whether any public storage was written.
    ///
    /// If true, a block transaction must be created.
    pub public_write_occurred: bool,

    /// The effective sender used during execution.
    ///
    /// - Real mode: equals `from`
    /// - Shielded mode: derived shielded address
    pub effective_sender: Address,

    /// The real user who signed the transaction.
    pub real_sender: Address,

    /// Block transaction to include (if public writes occurred).
    pub block_transaction: Option<BlockTransaction>,
}

/// A transaction to include in a block (when public writes occur).
#[derive(Debug, Clone)]
pub struct BlockTransaction {
    /// From address (real user or shielded).
    pub from: Address,

    /// To address.
    pub to: Address,

    /// Calldata.
    pub data: Bytes,

    /// Gas limit.
    pub gas_limit: u64,

    /// Signature.
    ///
    /// - Real mode: original user signature (re-signed for on-chain format)
    /// - Shielded mode: signed by derived shielded key
    pub signature: Signature,

    /// Transaction hash for on-chain inclusion.
    pub tx_hash: B256,
}

/// Executor for private transactions.
///
/// Coordinates validation, execution, and block transaction creation.
#[derive(Debug)]
pub struct PrivateTransactionExecutor {
    /// Private nonce manager.
    nonce_manager: Arc<PrivateNonceManager>,

    /// Shielded key manager.
    shielded_manager: Arc<ShieldedKeyManager>,

    /// Chain ID.
    chain_id: u64,
}

impl PrivateTransactionExecutor {
    /// Create a new executor.
    pub fn new(
        nonce_manager: Arc<PrivateNonceManager>,
        shielded_manager: Arc<ShieldedKeyManager>,
        chain_id: u64,
    ) -> Self {
        Self {
            nonce_manager,
            shielded_manager,
            chain_id,
        }
    }

    /// Get the nonce manager.
    pub fn nonce_manager(&self) -> &PrivateNonceManager {
        &self.nonce_manager
    }

    /// Get the shielded key manager.
    pub fn shielded_manager(&self) -> &ShieldedKeyManager {
        &self.shielded_manager
    }

    /// Get the chain ID.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Validate a private transaction without executing it.
    ///
    /// Checks:
    /// - Transaction structure (value = 0, gas > 0, to != 0)
    /// - Signature validity
    /// - Signer matches `from`
    /// - Chain ID matches
    /// - Private nonce is correct
    pub fn validate(&self, tx: &PrivateTransaction) -> Result<(), ExecutorError> {
        // 1. Validate transaction structure
        tx.validate().map_err(ExecutorError::Transaction)?;

        // 2. Verify chain ID
        if tx.chain_id != self.chain_id {
            return Err(ExecutorError::ChainIdMismatch {
                expected: self.chain_id,
                actual: tx.chain_id,
            });
        }

        // 3. Verify signature
        tx.verify_signature().map_err(ExecutorError::Transaction)?;

        // 4. Validate private nonce
        self.nonce_manager
            .validate_nonce(tx.from, tx.private_nonce)
            .map_err(ExecutorError::Nonce)?;

        Ok(())
    }

    /// Resolve the effective sender based on privacy mode.
    pub fn resolve_effective_sender(&self, tx: &PrivateTransaction) -> Address {
        match &tx.mode {
            PrivacyMode::Real => tx.from,
            PrivacyMode::Shielded { protocol, index } => {
                self.shielded_manager
                    .get_shielded_address(tx.from, *protocol, *index)
            }
        }
    }

    /// Execute a private transaction.
    ///
    /// This is a simplified executor that doesn't actually run the EVM.
    /// In a full implementation, this would:
    /// 1. Create a PrivacyDatabase wrapper
    /// 2. Set up the EVM with the privacy inspector
    /// 3. Execute the transaction
    /// 4. Track public vs private writes
    /// 5. Return the result
    ///
    /// For now, this provides the validation and mode resolution logic,
    /// leaving actual EVM execution to the integration layer.
    pub fn prepare_execution(
        &self,
        tx: &PrivateTransaction,
    ) -> Result<PreparedExecution, ExecutorError> {
        // Validate the transaction
        self.validate(tx)?;

        // Resolve effective sender
        let effective_sender = self.resolve_effective_sender(tx);

        // Use the nonce (increment it)
        self.nonce_manager
            .use_nonce(tx.from, tx.private_nonce)
            .map_err(ExecutorError::Nonce)?;

        Ok(PreparedExecution {
            effective_sender,
            real_sender: tx.from,
            to: tx.to,
            data: tx.data.clone(),
            gas_limit: tx.gas_limit,
            mode: tx.mode,
        })
    }

    /// Roll back a nonce after execution failure.
    ///
    /// Call this if `prepare_execution` succeeded but EVM execution failed
    /// and the transaction should be retryable.
    pub fn rollback_nonce(&self, user: Address) {
        self.nonce_manager.decrement_nonce(user);
    }

    /// Create a block transaction after execution completes.
    ///
    /// Only call this if `public_write_occurred` is true.
    pub fn create_block_transaction(
        &self,
        tx: &PrivateTransaction,
        effective_sender: Address,
    ) -> Result<BlockTransaction, ExecutorError> {
        // Build the on-chain transaction hash
        let tx_hash = self.compute_block_tx_hash(effective_sender, tx.to, &tx.data, tx.gas_limit);

        // Sign with appropriate key
        let signature = match &tx.mode {
            PrivacyMode::Real => {
                // In Real mode, we need the user's signature for the on-chain tx
                // For now, return a placeholder - the RPC layer should handle this
                tx.signature
            }
            PrivacyMode::Shielded { protocol, index } => {
                // In Shielded mode, sign with the derived key
                self.shielded_manager.sign_hash(tx.from, *protocol, *index, tx_hash)
            }
        };

        Ok(BlockTransaction {
            from: effective_sender,
            to: tx.to,
            data: tx.data.clone(),
            gas_limit: tx.gas_limit,
            signature,
            tx_hash,
        })
    }

    /// Compute the hash for a block transaction.
    fn compute_block_tx_hash(
        &self,
        from: Address,
        to: Address,
        data: &Bytes,
        gas_limit: u64,
    ) -> B256 {
        use alloy_primitives::keccak256;

        let mut preimage = Vec::with_capacity(256);
        preimage.extend_from_slice(b"BlockTransaction");
        preimage.extend_from_slice(&self.chain_id.to_be_bytes());
        preimage.extend_from_slice(from.as_slice());
        preimage.extend_from_slice(to.as_slice());
        preimage.extend_from_slice(keccak256(data).as_slice());
        preimage.extend_from_slice(&gas_limit.to_be_bytes());

        keccak256(&preimage)
    }
}

/// A prepared execution ready for the EVM.
#[derive(Debug, Clone)]
pub struct PreparedExecution {
    /// The effective sender (msg.sender during execution).
    pub effective_sender: Address,

    /// The real user who signed.
    pub real_sender: Address,

    /// Destination contract.
    pub to: Address,

    /// Calldata.
    pub data: Bytes,

    /// Gas limit.
    pub gas_limit: u64,

    /// Privacy mode.
    pub mode: PrivacyMode,
}

/// Errors that can occur during execution.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ExecutorError {
    /// Transaction validation error.
    #[error("transaction error: {0}")]
    Transaction(#[from] PrivateTransactionError),

    /// Nonce validation error.
    #[error("nonce error: {0}")]
    Nonce(#[from] NonceError),

    /// Chain ID mismatch.
    #[error("chain ID mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch {
        /// Expected chain ID.
        expected: u64,
        /// Actual chain ID in transaction.
        actual: u64,
    },

    /// EVM execution error.
    #[error("execution failed: {0}")]
    Execution(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, Signature, U256};

    fn test_user() -> Address {
        address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
    }

    fn test_contract() -> Address {
        address!("1234567890123456789012345678901234567890")
    }

    fn create_executor() -> PrivateTransactionExecutor {
        let nonce_manager = Arc::new(PrivateNonceManager::new());
        let shielded_manager = Arc::new(ShieldedKeyManager::new(84532));
        PrivateTransactionExecutor::new(nonce_manager, shielded_manager, 84532)
    }

    fn unsigned_tx(mode: PrivacyMode) -> PrivateTransaction {
        PrivateTransaction {
            from: test_user(),
            to: test_contract(),
            data: Bytes::from(vec![0x12, 0x34]),
            value: U256::ZERO,
            gas_limit: 100_000,
            private_nonce: 0,
            mode,
            chain_id: 84532,
            signature: Signature::new(U256::ZERO, U256::ZERO, false),
        }
    }

    #[test]
    fn test_new_executor() {
        let executor = create_executor();
        assert_eq!(executor.chain_id(), 84532);
    }

    #[test]
    fn test_resolve_effective_sender_real() {
        let executor = create_executor();
        let tx = unsigned_tx(PrivacyMode::Real);

        let sender = executor.resolve_effective_sender(&tx);
        assert_eq!(sender, test_user());
    }

    #[test]
    fn test_resolve_effective_sender_shielded() {
        let executor = create_executor();
        let tx = unsigned_tx(PrivacyMode::Shielded {
            protocol: test_contract(),
            index: 0,
        });

        let sender = executor.resolve_effective_sender(&tx);

        // Should be a derived address, not the real user
        assert_ne!(sender, test_user());
        assert!(!sender.is_zero());
    }

    #[test]
    fn test_validate_chain_id_mismatch() {
        let executor = create_executor();
        let mut tx = unsigned_tx(PrivacyMode::Real);
        tx.chain_id = 1; // Wrong chain

        let err = executor.validate(&tx).unwrap_err();
        assert!(matches!(err, ExecutorError::ChainIdMismatch { .. }));
    }

    #[test]
    fn test_validate_invalid_structure() {
        let executor = create_executor();
        let mut tx = unsigned_tx(PrivacyMode::Real);
        tx.value = U256::from(1); // Non-zero value not allowed

        let err = executor.validate(&tx).unwrap_err();
        assert!(matches!(
            err,
            ExecutorError::Transaction(PrivateTransactionError::NonZeroValue)
        ));
    }

    #[test]
    fn test_create_block_transaction_shielded() {
        let executor = create_executor();
        let tx = unsigned_tx(PrivacyMode::Shielded {
            protocol: test_contract(),
            index: 0,
        });

        let effective_sender = executor.resolve_effective_sender(&tx);
        let block_tx = executor
            .create_block_transaction(&tx, effective_sender)
            .unwrap();

        assert_eq!(block_tx.from, effective_sender);
        assert_eq!(block_tx.to, test_contract());
        assert_eq!(block_tx.gas_limit, 100_000);

        // Signature should recover to the shielded address
        let recovered = block_tx
            .signature
            .recover_address_from_prehash(&block_tx.tx_hash)
            .unwrap();
        assert_eq!(recovered, effective_sender);
    }

    #[test]
    fn test_rollback_nonce() {
        let executor = create_executor();

        // Manually increment nonce
        executor.nonce_manager.increment_nonce(test_user());
        assert_eq!(executor.nonce_manager.get_nonce(test_user()), 1);

        // Rollback
        executor.rollback_nonce(test_user());
        assert_eq!(executor.nonce_manager.get_nonce(test_user()), 0);
    }

    #[test]
    fn test_compute_block_tx_hash_deterministic() {
        let executor = create_executor();

        let hash1 = executor.compute_block_tx_hash(
            test_user(),
            test_contract(),
            &Bytes::from(vec![0x12]),
            100_000,
        );

        let hash2 = executor.compute_block_tx_hash(
            test_user(),
            test_contract(),
            &Bytes::from(vec![0x12]),
            100_000,
        );

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_block_tx_hash_different_inputs() {
        let executor = create_executor();

        let hash1 = executor.compute_block_tx_hash(
            test_user(),
            test_contract(),
            &Bytes::from(vec![0x12]),
            100_000,
        );

        let hash2 = executor.compute_block_tx_hash(
            test_user(),
            test_contract(),
            &Bytes::from(vec![0x34]), // Different data
            100_000,
        );

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_error_display() {
        let err = ExecutorError::ChainIdMismatch {
            expected: 84532,
            actual: 1,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("chain ID mismatch"));
        assert!(msg.contains("84532"));
    }
}
