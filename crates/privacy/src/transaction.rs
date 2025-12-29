//! Private Transaction Types for priv_* RPC endpoints.
//!
//! A [`PrivateTransaction`] is submitted via `priv_sendRawTransaction` and
//! executed with privacy-preserving semantics. Key differences from regular
//! transactions:
//!
//! - **Signed by real user**: The signature is always from the real user,
//!   even in Shielded mode where `msg.sender` differs.
//! - **Private nonce**: Uses a separate nonce counter, not the ETH nonce.
//! - **No value transfer**: ETH transfers are not supported (value must be 0).
//! - **Mode selection**: Caller chooses Real or Shielded execution mode.
//!
//! # Example
//!
//! ```ignore
//! use base_reth_privacy::transaction::PrivateTransaction;
//! use base_reth_privacy::mode::PrivacyMode;
//! use alloy_primitives::{Address, Bytes, U256};
//!
//! let tx = PrivateTransaction {
//!     from: user_address,
//!     to: contract_address,
//!     data: calldata,
//!     value: U256::ZERO,
//!     gas_limit: 100_000,
//!     private_nonce: 0,
//!     mode: PrivacyMode::Real,
//!     chain_id: 84532,
//!     signature: user_signature,
//! };
//!
//! tx.validate()?;
//! let signer = tx.recover_signer()?;
//! assert_eq!(signer, user_address);
//! ```

use crate::mode::PrivacyMode;
use alloy_primitives::{keccak256, Address, Bytes, Signature, B256, U256};
use serde::{Deserialize, Serialize};

/// A private transaction submitted via `priv_sendRawTransaction`.
///
/// This transaction type is used for privacy-preserving interactions where
/// the effective `msg.sender` may differ from the signing user (in Shielded mode).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateTransaction {
    /// Real user address.
    ///
    /// This is always the actual user who signs the transaction, regardless
    /// of the privacy mode. Used for:
    /// - Signature verification
    /// - Private nonce lookup
    /// - Seed lookup for shielded key derivation
    pub from: Address,

    /// Destination contract address.
    ///
    /// Contract creation (to = 0x0) is not supported via priv_* transactions.
    pub to: Address,

    /// Transaction calldata.
    ///
    /// The function selector and encoded arguments to call on the destination.
    pub data: Bytes,

    /// ETH value to transfer.
    ///
    /// **Must be zero.** ETH transfers are not supported in private transactions
    /// because:
    /// - In Shielded mode, the shielded address would need ETH
    /// - Value transfers would leak information about the sender
    pub value: U256,

    /// Gas limit for execution.
    ///
    /// Execution will be reverted if gas is exhausted.
    pub gas_limit: u64,

    /// Private nonce.
    ///
    /// This is a separate nonce counter from the ETH nonce, keyed by the
    /// **real user address** (not the shielded address). This ensures:
    /// - Replay protection across private transactions
    /// - Ordering of private transactions from the same user
    pub private_nonce: u64,

    /// Privacy mode for execution.
    ///
    /// - `Real`: msg.sender = from (real user)
    /// - `Shielded`: msg.sender = derived shielded address
    pub mode: PrivacyMode,

    /// Chain ID for replay protection.
    ///
    /// Used in:
    /// - Signing hash computation
    /// - Shielded address derivation
    pub chain_id: u64,

    /// Signature from the real user.
    ///
    /// Signs over all transaction fields using a custom signing scheme.
    /// The signer must match the `from` address.
    pub signature: Signature,
}

impl PrivateTransaction {
    /// Validate the transaction structure.
    ///
    /// Checks:
    /// - Value must be zero
    /// - Gas limit must be non-zero
    /// - Destination must not be zero (no contract creation)
    pub fn validate(&self) -> Result<(), PrivateTransactionError> {
        // Value must be 0 - no ETH transfers in private transactions
        if self.value != U256::ZERO {
            return Err(PrivateTransactionError::NonZeroValue);
        }

        // Gas limit must be reasonable
        if self.gas_limit == 0 {
            return Err(PrivateTransactionError::ZeroGasLimit);
        }

        // No contract creation via priv_* transactions
        if self.to == Address::ZERO {
            return Err(PrivateTransactionError::ContractCreationNotAllowed);
        }

        Ok(())
    }

    /// Recover the signer address from the signature.
    ///
    /// Returns an error if signature recovery fails.
    pub fn recover_signer(&self) -> Result<Address, PrivateTransactionError> {
        let signing_hash = self.signing_hash();

        self.signature
            .recover_address_from_prehash(&signing_hash)
            .map_err(|_| PrivateTransactionError::InvalidSignature)
    }

    /// Verify that the signature matches the declared `from` address.
    pub fn verify_signature(&self) -> Result<(), PrivateTransactionError> {
        let signer = self.recover_signer()?;

        if signer != self.from {
            return Err(PrivateTransactionError::SignerMismatch {
                expected: self.from,
                actual: signer,
            });
        }

        Ok(())
    }

    /// Compute the hash that was signed.
    ///
    /// Uses a custom signing scheme:
    /// ```text
    /// keccak256(
    ///     "PrivateTransaction" ||
    ///     chain_id ||
    ///     from ||
    ///     to ||
    ///     keccak256(data) ||
    ///     gas_limit ||
    ///     private_nonce ||
    ///     mode_hash
    /// )
    /// ```
    pub fn signing_hash(&self) -> B256 {
        let mut preimage = Vec::with_capacity(256);

        // Domain separator
        preimage.extend_from_slice(b"PrivateTransaction");

        // Chain ID (8 bytes)
        preimage.extend_from_slice(&self.chain_id.to_be_bytes());

        // From address (20 bytes)
        preimage.extend_from_slice(self.from.as_slice());

        // To address (20 bytes)
        preimage.extend_from_slice(self.to.as_slice());

        // Data hash (32 bytes)
        preimage.extend_from_slice(keccak256(&self.data).as_slice());

        // Gas limit (8 bytes)
        preimage.extend_from_slice(&self.gas_limit.to_be_bytes());

        // Private nonce (8 bytes)
        preimage.extend_from_slice(&self.private_nonce.to_be_bytes());

        // Mode hash (32 bytes)
        preimage.extend_from_slice(self.mode_hash().as_slice());

        keccak256(&preimage)
    }

    /// Compute a hash of the privacy mode.
    fn mode_hash(&self) -> B256 {
        match &self.mode {
            PrivacyMode::Real => keccak256(b"Real"),
            PrivacyMode::Shielded { protocol, index } => {
                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(b"Shielded");
                data.extend_from_slice(protocol.as_slice());
                data.extend_from_slice(&index.to_be_bytes());
                keccak256(&data)
            }
        }
    }

    /// Create an unsigned transaction (for testing).
    #[cfg(test)]
    pub fn unsigned(
        from: Address,
        to: Address,
        data: Bytes,
        gas_limit: u64,
        private_nonce: u64,
        mode: PrivacyMode,
        chain_id: u64,
    ) -> Self {
        Self {
            from,
            to,
            data,
            value: U256::ZERO,
            gas_limit,
            private_nonce,
            mode,
            chain_id,
            signature: Signature::new(U256::ZERO, U256::ZERO, false),
        }
    }
}

/// Errors that can occur when working with private transactions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrivateTransactionError {
    /// Value must be zero for private transactions.
    #[error("value must be 0 for private transactions")]
    NonZeroValue,

    /// Gas limit cannot be zero.
    #[error("gas limit cannot be 0")]
    ZeroGasLimit,

    /// Contract creation is not allowed via priv_* transactions.
    #[error("contract creation not allowed via priv_*")]
    ContractCreationNotAllowed,

    /// Signature recovery failed.
    #[error("invalid signature")]
    InvalidSignature,

    /// Recovered signer does not match the declared `from` address.
    #[error("signer mismatch: expected {expected}, got {actual}")]
    SignerMismatch {
        /// The declared `from` address.
        expected: Address,
        /// The recovered signer address.
        actual: Address,
    },

    /// Invalid private nonce.
    #[error("invalid nonce: expected {expected}, got {actual}")]
    InvalidNonce {
        /// The expected nonce.
        expected: u64,
        /// The provided nonce.
        actual: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    fn test_from() -> Address {
        address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
    }

    fn test_to() -> Address {
        address!("1234567890123456789012345678901234567890")
    }

    fn valid_tx() -> PrivateTransaction {
        PrivateTransaction::unsigned(
            test_from(),
            test_to(),
            Bytes::from(vec![0x12, 0x34]),
            100_000,
            0,
            PrivacyMode::Real,
            84532,
        )
    }

    #[test]
    fn test_validate_success() {
        let tx = valid_tx();
        assert!(tx.validate().is_ok());
    }

    #[test]
    fn test_validate_non_zero_value() {
        let mut tx = valid_tx();
        tx.value = U256::from(1);

        let err = tx.validate().unwrap_err();
        assert!(matches!(err, PrivateTransactionError::NonZeroValue));
    }

    #[test]
    fn test_validate_zero_gas_limit() {
        let mut tx = valid_tx();
        tx.gas_limit = 0;

        let err = tx.validate().unwrap_err();
        assert!(matches!(err, PrivateTransactionError::ZeroGasLimit));
    }

    #[test]
    fn test_validate_contract_creation() {
        let mut tx = valid_tx();
        tx.to = Address::ZERO;

        let err = tx.validate().unwrap_err();
        assert!(matches!(
            err,
            PrivateTransactionError::ContractCreationNotAllowed
        ));
    }

    #[test]
    fn test_signing_hash_deterministic() {
        let tx = valid_tx();

        let hash1 = tx.signing_hash();
        let hash2 = tx.signing_hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_signing_hash_changes_with_mode() {
        let mut tx_real = valid_tx();
        tx_real.mode = PrivacyMode::Real;

        let mut tx_shielded = valid_tx();
        tx_shielded.mode = PrivacyMode::Shielded {
            protocol: test_to(),
            index: 0,
        };

        assert_ne!(tx_real.signing_hash(), tx_shielded.signing_hash());
    }

    #[test]
    fn test_signing_hash_changes_with_nonce() {
        let mut tx1 = valid_tx();
        tx1.private_nonce = 0;

        let mut tx2 = valid_tx();
        tx2.private_nonce = 1;

        assert_ne!(tx1.signing_hash(), tx2.signing_hash());
    }

    #[test]
    fn test_signing_hash_changes_with_chain_id() {
        let mut tx1 = valid_tx();
        tx1.chain_id = 1;

        let mut tx2 = valid_tx();
        tx2.chain_id = 2;

        assert_ne!(tx1.signing_hash(), tx2.signing_hash());
    }

    #[test]
    fn test_mode_hash_different_for_modes() {
        let mut tx_real = valid_tx();
        tx_real.mode = PrivacyMode::Real;

        let mut tx_shielded = valid_tx();
        tx_shielded.mode = PrivacyMode::Shielded {
            protocol: test_to(),
            index: 0,
        };

        assert_ne!(tx_real.mode_hash(), tx_shielded.mode_hash());
    }

    #[test]
    fn test_serialization() {
        let tx = valid_tx();
        let json = serde_json::to_string(&tx).unwrap();
        let deserialized: PrivateTransaction = serde_json::from_str(&json).unwrap();

        assert_eq!(tx.from, deserialized.from);
        assert_eq!(tx.to, deserialized.to);
        assert_eq!(tx.data, deserialized.data);
        assert_eq!(tx.gas_limit, deserialized.gas_limit);
        assert_eq!(tx.private_nonce, deserialized.private_nonce);
        assert_eq!(tx.mode, deserialized.mode);
        assert_eq!(tx.chain_id, deserialized.chain_id);
    }

    #[test]
    fn test_error_display() {
        let err = PrivateTransactionError::NonZeroValue;
        assert!(format!("{}", err).contains("value must be 0"));

        let err = PrivateTransactionError::SignerMismatch {
            expected: test_from(),
            actual: test_to(),
        };
        assert!(format!("{}", err).contains("signer mismatch"));
    }
}
