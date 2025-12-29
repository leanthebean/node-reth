//! Private Nonce Management for priv_* transactions.
//!
//! Private transactions use a separate nonce counter from regular ETH transactions.
//! This provides replay protection within the privacy layer while keeping the
//! public ETH nonce unchanged for non-privacy transactions.
//!
//! # Key Design Decisions
//!
//! 1. **Keyed by real user address**: Even in Shielded mode, the private nonce
//!    is looked up by the real user's address (not the shielded address).
//!    This is because:
//!    - The real user signs all private transactions
//!    - Multiple shielded addresses can be derived from one user
//!    - Nonce tracking should be per-identity, not per-address
//!
//! 2. **In-memory by default**: For development/testing, nonces are stored
//!    in memory. Production deployments should use persistent storage (MDBX).
//!
//! 3. **Atomic operations**: Nonce validation and increment are designed to
//!    be used atomically to prevent race conditions.
//!
//! # Example
//!
//! ```ignore
//! use base_reth_privacy::nonce::PrivateNonceManager;
//! use alloy_primitives::address;
//!
//! let manager = PrivateNonceManager::new();
//! let user = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
//!
//! // Get current nonce (starts at 0)
//! assert_eq!(manager.get_nonce(user), 0);
//!
//! // Validate and use nonce atomically
//! manager.use_nonce(user, 0).unwrap();
//!
//! // Nonce is now 1
//! assert_eq!(manager.get_nonce(user), 1);
//! ```

use alloy_primitives::Address;
use std::collections::HashMap;
use std::sync::RwLock;

/// Manages private nonces for priv_* transactions.
///
/// Private nonces are:
/// - Keyed by the **real user address** (not shielded address)
/// - Separate from the ETH nonce (does not affect regular transactions)
/// - Monotonically increasing (no gaps allowed)
#[derive(Debug, Default)]
pub struct PrivateNonceManager {
    /// In-memory nonce storage: real_address -> next_expected_nonce
    nonces: RwLock<HashMap<Address, u64>>,
}

impl PrivateNonceManager {
    /// Create a new private nonce manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the current nonce for a user (the next expected nonce).
    ///
    /// Returns 0 for users who have never submitted a private transaction.
    pub fn get_nonce(&self, user: Address) -> u64 {
        self.nonces
            .read()
            .expect("nonce lock poisoned")
            .get(&user)
            .copied()
            .unwrap_or(0)
    }

    /// Validate that a transaction has the correct nonce.
    ///
    /// Returns `Ok(())` if the nonce matches, `Err(NonceError)` otherwise.
    pub fn validate_nonce(&self, user: Address, provided_nonce: u64) -> Result<(), NonceError> {
        let expected = self.get_nonce(user);

        if provided_nonce != expected {
            return Err(NonceError::InvalidNonce {
                expected,
                provided: provided_nonce,
            });
        }

        Ok(())
    }

    /// Increment the nonce after successful execution.
    ///
    /// Should be called after a private transaction is successfully executed.
    pub fn increment_nonce(&self, user: Address) {
        let mut nonces = self.nonces.write().expect("nonce lock poisoned");
        let current = nonces.entry(user).or_insert(0);
        *current += 1;
    }

    /// Validate and increment nonce atomically.
    ///
    /// This is the recommended way to use nonces:
    /// 1. Validate the provided nonce matches expected
    /// 2. Increment the nonce
    ///
    /// If validation fails, the nonce is not incremented.
    ///
    /// # Errors
    ///
    /// Returns `NonceError::InvalidNonce` if the provided nonce doesn't match.
    pub fn use_nonce(&self, user: Address, provided_nonce: u64) -> Result<(), NonceError> {
        let mut nonces = self.nonces.write().expect("nonce lock poisoned");
        let expected = nonces.get(&user).copied().unwrap_or(0);

        if provided_nonce != expected {
            return Err(NonceError::InvalidNonce {
                expected,
                provided: provided_nonce,
            });
        }

        *nonces.entry(user).or_insert(0) += 1;
        Ok(())
    }

    /// Decrement the nonce (for rollback on execution failure).
    ///
    /// Should only be called when:
    /// 1. `increment_nonce` was called
    /// 2. Execution subsequently failed
    /// 3. The transaction should be retryable
    ///
    /// Note: This is a best-effort operation. If the nonce is already 0,
    /// it will not underflow.
    pub fn decrement_nonce(&self, user: Address) {
        let mut nonces = self.nonces.write().expect("nonce lock poisoned");
        if let Some(nonce) = nonces.get_mut(&user) {
            *nonce = nonce.saturating_sub(1);
        }
    }

    /// Set the nonce for a user directly.
    ///
    /// Primarily for testing or state restoration from persistent storage.
    pub fn set_nonce(&self, user: Address, nonce: u64) {
        let mut nonces = self.nonces.write().expect("nonce lock poisoned");
        nonces.insert(user, nonce);
    }

    /// Get all user nonces (for persistence).
    pub fn all_nonces(&self) -> HashMap<Address, u64> {
        self.nonces.read().expect("nonce lock poisoned").clone()
    }

    /// Clear all nonces (for testing).
    #[cfg(test)]
    pub fn clear(&self) {
        self.nonces.write().expect("nonce lock poisoned").clear();
    }
}

impl Clone for PrivateNonceManager {
    fn clone(&self) -> Self {
        Self {
            nonces: RwLock::new(self.nonces.read().expect("nonce lock poisoned").clone()),
        }
    }
}

/// Errors that can occur during nonce operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NonceError {
    /// The provided nonce does not match the expected nonce.
    #[error("invalid nonce: expected {expected}, provided {provided}")]
    InvalidNonce {
        /// The expected (next) nonce.
        expected: u64,
        /// The nonce provided in the transaction.
        provided: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    fn test_user() -> Address {
        address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
    }

    fn test_user2() -> Address {
        address!("70997970C51812dc3A010C7d01b50e0d17dc79C8")
    }

    #[test]
    fn test_new_user_starts_at_zero() {
        let manager = PrivateNonceManager::new();
        assert_eq!(manager.get_nonce(test_user()), 0);
    }

    #[test]
    fn test_increment_nonce() {
        let manager = PrivateNonceManager::new();
        let user = test_user();

        assert_eq!(manager.get_nonce(user), 0);

        manager.increment_nonce(user);
        assert_eq!(manager.get_nonce(user), 1);

        manager.increment_nonce(user);
        assert_eq!(manager.get_nonce(user), 2);
    }

    #[test]
    fn test_validate_nonce_success() {
        let manager = PrivateNonceManager::new();
        let user = test_user();

        // Nonce 0 should be valid for new user
        assert!(manager.validate_nonce(user, 0).is_ok());

        manager.increment_nonce(user);

        // Nonce 1 should be valid after increment
        assert!(manager.validate_nonce(user, 1).is_ok());
    }

    #[test]
    fn test_validate_nonce_failure() {
        let manager = PrivateNonceManager::new();
        let user = test_user();

        // Nonce 1 should fail for new user (expected 0)
        let err = manager.validate_nonce(user, 1).unwrap_err();
        assert!(matches!(
            err,
            NonceError::InvalidNonce {
                expected: 0,
                provided: 1
            }
        ));

        manager.increment_nonce(user);

        // Nonce 0 should fail after increment (expected 1)
        let err = manager.validate_nonce(user, 0).unwrap_err();
        assert!(matches!(
            err,
            NonceError::InvalidNonce {
                expected: 1,
                provided: 0
            }
        ));
    }

    #[test]
    fn test_use_nonce_success() {
        let manager = PrivateNonceManager::new();
        let user = test_user();

        // Use nonce 0
        assert!(manager.use_nonce(user, 0).is_ok());
        assert_eq!(manager.get_nonce(user), 1);

        // Use nonce 1
        assert!(manager.use_nonce(user, 1).is_ok());
        assert_eq!(manager.get_nonce(user), 2);
    }

    #[test]
    fn test_use_nonce_failure_does_not_increment() {
        let manager = PrivateNonceManager::new();
        let user = test_user();

        // Try to use wrong nonce
        assert!(manager.use_nonce(user, 5).is_err());

        // Nonce should still be 0
        assert_eq!(manager.get_nonce(user), 0);
    }

    #[test]
    fn test_decrement_nonce() {
        let manager = PrivateNonceManager::new();
        let user = test_user();

        manager.set_nonce(user, 5);
        assert_eq!(manager.get_nonce(user), 5);

        manager.decrement_nonce(user);
        assert_eq!(manager.get_nonce(user), 4);
    }

    #[test]
    fn test_decrement_nonce_does_not_underflow() {
        let manager = PrivateNonceManager::new();
        let user = test_user();

        // Nonce starts at 0
        manager.decrement_nonce(user);

        // Should not go negative
        assert_eq!(manager.get_nonce(user), 0);
    }

    #[test]
    fn test_decrement_unknown_user() {
        let manager = PrivateNonceManager::new();
        let user = test_user();

        // Decrementing unknown user should be a no-op
        manager.decrement_nonce(user);
        assert_eq!(manager.get_nonce(user), 0);
    }

    #[test]
    fn test_users_are_isolated() {
        let manager = PrivateNonceManager::new();
        let user1 = test_user();
        let user2 = test_user2();

        manager.increment_nonce(user1);
        manager.increment_nonce(user1);
        manager.increment_nonce(user2);

        assert_eq!(manager.get_nonce(user1), 2);
        assert_eq!(manager.get_nonce(user2), 1);
    }

    #[test]
    fn test_set_nonce() {
        let manager = PrivateNonceManager::new();
        let user = test_user();

        manager.set_nonce(user, 100);
        assert_eq!(manager.get_nonce(user), 100);
    }

    #[test]
    fn test_all_nonces() {
        let manager = PrivateNonceManager::new();
        let user1 = test_user();
        let user2 = test_user2();

        manager.set_nonce(user1, 5);
        manager.set_nonce(user2, 10);

        let all = manager.all_nonces();
        assert_eq!(all.get(&user1), Some(&5));
        assert_eq!(all.get(&user2), Some(&10));
    }

    #[test]
    fn test_clone() {
        let manager = PrivateNonceManager::new();
        manager.set_nonce(test_user(), 42);

        let cloned = manager.clone();
        assert_eq!(cloned.get_nonce(test_user()), 42);

        // Changes to clone should not affect original
        cloned.increment_nonce(test_user());
        assert_eq!(manager.get_nonce(test_user()), 42);
        assert_eq!(cloned.get_nonce(test_user()), 43);
    }

    #[test]
    fn test_error_display() {
        let err = NonceError::InvalidNonce {
            expected: 5,
            provided: 10,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("expected 5"));
        assert!(msg.contains("provided 10"));
    }
}
