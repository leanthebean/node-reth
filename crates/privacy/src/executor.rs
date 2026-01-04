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
    database::PrivacyDatabase,
    evm::PrivacyEvmFactory,
    inspector::{PrivacyInspector, SlotKeyCache},
    mode::PrivacyMode,
    nonce::{NonceError, NonceReservation, PrivateNonceManager},
    precompiles::setup_precompile_context_guarded,
    registry::PrivacyRegistry,
    shielded::ShieldedKeyManager,
    store::PrivateStateStore,
    transaction::{PrivateTransaction, PrivateTransactionError},
};
use alloy_evm::{Evm, EvmEnv, EvmFactory};
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use op_revm::{OpSpecId, OpTransaction};
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    database_interface::Database,
    primitives::HashMap,
    DatabaseCommit,
};
use std::fmt::Debug;
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

    /// Privacy registry for slot classification.
    registry: Arc<PrivacyRegistry>,

    /// Private state store.
    private_store: Arc<PrivateStateStore>,

    /// Chain ID.
    chain_id: u64,
}

impl PrivateTransactionExecutor {
    /// Create a new executor.
    pub fn new(
        nonce_manager: Arc<PrivateNonceManager>,
        shielded_manager: Arc<ShieldedKeyManager>,
        registry: Arc<PrivacyRegistry>,
        private_store: Arc<PrivateStateStore>,
        chain_id: u64,
    ) -> Self {
        Self {
            nonce_manager,
            shielded_manager,
            registry,
            private_store,
            chain_id,
        }
    }

    /// Get the privacy registry.
    pub fn registry(&self) -> &PrivacyRegistry {
        &self.registry
    }

    /// Get the private store.
    pub fn private_store(&self) -> &PrivateStateStore {
        &self.private_store
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
    ///
    /// # Two-Phase Nonce Pattern
    ///
    /// This method returns a `NonceReservation` along with the prepared execution.
    /// The reservation validates the nonce but does NOT increment it.
    /// After successful execution, call `commit_reservation()` to increment the nonce.
    /// If execution fails, drop the reservation without committing - the nonce
    /// remains unchanged and the transaction can be retried.
    pub fn prepare_execution(
        &self,
        tx: &PrivateTransaction,
    ) -> Result<(PreparedExecution, NonceReservation), ExecutorError> {
        // Validate the transaction
        self.validate(tx)?;

        // Resolve effective sender
        let effective_sender = self.resolve_effective_sender(tx);

        // Reserve the nonce (validates but does NOT increment)
        // The reservation must be committed after successful execution
        let reservation = self
            .nonce_manager
            .reserve_nonce(tx.from, tx.private_nonce)
            .map_err(ExecutorError::Nonce)?;

        Ok((
            PreparedExecution {
                effective_sender,
                real_sender: tx.from,
                to: tx.to,
                data: tx.data.clone(),
                gas_limit: tx.gas_limit,
                mode: tx.mode,
            },
            reservation,
        ))
    }

    /// Execute a private transaction with EVM.
    ///
    /// This is the main entry point for private transaction execution.
    /// It:
    /// 1. Validates the transaction
    /// 2. Sets up the privacy-aware EVM
    /// 3. Executes the transaction
    /// 4. Tracks public vs private writes
    /// 5. Creates a block transaction if needed
    ///
    /// # Type Parameters
    ///
    /// * `DB` - The underlying database type (must implement Database + DatabaseCommit)
    ///
    /// # Arguments
    ///
    /// * `tx` - The private transaction to execute
    /// * `db` - The underlying state database
    /// * `block_env` - Block environment for the EVM
    /// * `spec_id` - The OP spec ID to use
    ///
    /// # Returns
    ///
    /// The execution result including output, gas used, and whether public writes occurred.
    pub fn execute_private_tx<DB>(
        &self,
        tx: &PrivateTransaction,
        db: DB,
        block_env: BlockEnv,
        spec_id: OpSpecId,
    ) -> Result<PrivateExecutionResult, ExecutorError>
    where
        DB: Database + DatabaseCommit + Clone + Debug,
        DB::Error: std::error::Error + Send + Sync + 'static,
    {
        // 1. Validate and prepare (nonce is reserved but NOT incremented)
        let (prepared, nonce_reservation) = self.prepare_execution(tx)?;

        // 2. Set up privacy database
        let slot_key_cache = Arc::new(SlotKeyCache::new());
        let mut privacy_db = PrivacyDatabase::new(
            db,
            Arc::clone(&self.registry),
            Arc::clone(&self.private_store),
        );
        privacy_db.set_slot_key_cache(Arc::clone(&slot_key_cache));
        privacy_db.set_tx_sender(prepared.effective_sender);
        // Convert U256 block number to u64 (safe for practical block numbers)
        let block_number: u64 = block_env.number.try_into().unwrap_or(u64::MAX);
        privacy_db.set_block(block_number);

        // 3. Set up precompile context with RAII guard
        // The guard ensures context is cleared even if we panic or return early
        let _context_guard = setup_precompile_context_guarded(
            Arc::clone(&self.registry),
            Arc::clone(&self.private_store),
            prepared.effective_sender,
            block_number,
        );

        // 4. Create EVM with privacy inspector
        let inspector = PrivacyInspector::new(Arc::clone(&slot_key_cache));
        let evm_factory = PrivacyEvmFactory::new();

        let cfg_env = CfgEnv::new_with_spec(spec_id);
        let evm_env = EvmEnv::new(cfg_env, block_env);

        let mut evm = evm_factory.create_evm_with_inspector(privacy_db, evm_env, inspector);

        // 5. Set up transaction environment
        let tx_env = TxEnv {
            caller: prepared.effective_sender,
            gas_limit: prepared.gas_limit,
            data: prepared.data.clone(),
            kind: TxKind::Call(prepared.to),
            value: U256::ZERO,
            ..Default::default()
        };

        // Wrap in OpTransaction for the OP EVM
        // We set a dummy enveloped_tx to satisfy the OP EVM validation.
        // This is required for L1 cost calculation, but we use a minimal placeholder
        // since private transactions don't need accurate L1 cost estimates.
        let mut op_tx = OpTransaction::new(tx_env);
        op_tx.enveloped_tx = Some(Bytes::from(vec![0x00]));

        // 6. Execute the transaction
        let exec_result = evm
            .transact_raw(op_tx)
            .map_err(|e| ExecutorError::Execution(format!("EVM error: {e}")))?;

        // 7. Get the output and gas used
        let (success, output, gas_used) = match &exec_result.result {
            revm::context::result::ExecutionResult::Success { output, gas_used, .. } => {
                let bytes = match output {
                    revm::context::result::Output::Call(b) => b.clone(),
                    revm::context::result::Output::Create(b, _) => b.clone(),
                };
                (true, Bytes::from(bytes.to_vec()), *gas_used)
            }
            revm::context::result::ExecutionResult::Revert { output, gas_used } => {
                (false, Bytes::from(output.to_vec()), *gas_used)
            }
            revm::context::result::ExecutionResult::Halt { gas_used, .. } => {
                (false, Bytes::new(), *gas_used)
            }
        };

        // 8. Detect public writes by checking which state changes go to public vs private
        let public_write_occurred = self.detect_public_writes(&exec_result.state);

        // 9. Commit state changes through the privacy database
        // This routes private slots to the private store and public slots to the underlying DB
        let mut db = evm.into_db();
        db.commit(exec_result.state);

        // 10. Clear transaction context from database
        // Note: Precompile context is automatically cleared when _context_guard is dropped
        db.clear_tx_context();

        // 11. Commit the nonce reservation now that execution succeeded
        // If we had returned early due to an error, the reservation would be dropped
        // without committing, leaving the nonce unchanged for retry
        self.nonce_manager.commit_reservation(&nonce_reservation);

        // 12. Create block transaction if needed
        let block_transaction = if public_write_occurred {
            Some(self.create_block_transaction(tx, prepared.effective_sender)?)
        } else {
            None
        };

        Ok(PrivateExecutionResult {
            success,
            output,
            gas_used,
            public_write_occurred,
            effective_sender: prepared.effective_sender,
            real_sender: prepared.real_sender,
            block_transaction,
        })
    }

    /// Detect if any public storage writes occurred in the execution result.
    ///
    /// We check each storage change to see if it's classified as public or private.
    fn detect_public_writes(
        &self,
        state: &HashMap<Address, revm::state::Account>,
    ) -> bool {
        use crate::classification::{classify_slot, SlotClassification};

        for (address, account) in state {
            for (slot, value) in &account.storage {
                // Only check slots that actually changed
                if value.present_value == value.original_value {
                    continue;
                }

                // Classify the slot
                match classify_slot(&self.registry, *address, *slot) {
                    SlotClassification::Public => {
                        // Public write detected!
                        return true;
                    }
                    SlotClassification::Private { .. } => {
                        // Private write, doesn't trigger block tx
                    }
                }
            }
        }

        false
    }

    /// Roll back a nonce after execution failure.
    ///
    /// # Deprecated
    ///
    /// With the two-phase nonce pattern, this method is rarely needed.
    /// `prepare_execution` now returns a `NonceReservation` that only
    /// increments the nonce when `commit_reservation()` is called.
    /// If execution fails, simply drop the reservation without committing.
    ///
    /// This method is kept for backwards compatibility with code that
    /// uses `use_nonce()` directly instead of the two-phase pattern.
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
        let registry = Arc::new(PrivacyRegistry::new());
        let private_store = Arc::new(PrivateStateStore::new());
        PrivateTransactionExecutor::new(
            nonce_manager,
            shielded_manager,
            registry,
            private_store,
            84532,
        )
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
