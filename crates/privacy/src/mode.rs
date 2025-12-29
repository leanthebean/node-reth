//! Privacy Mode for priv_* transactions.
//!
//! Defines the two modes of privacy-enabled transaction execution:
//! - **Real mode**: `msg.sender` equals the real user address
//! - **Shielded mode**: `msg.sender` equals a derived shielded address
//!
//! # Real vs Shielded Mode
//!
//! ## Real Mode
//! - Use when identity reveal is acceptable
//! - Examples: poker showdown, public actions, account linking
//! - `msg.sender = real_user_address`
//!
//! ## Shielded Mode
//! - Use when anonymity is required
//! - `msg.sender = derive_shielded(user_seed, protocol, chain_id, index)`
//! - `index = 0`: Persistent per-protocol address (DeFi positions consolidate)
//! - `index > 0`: Fresh unlinkable address (anonymous votes, swaps)
//!
//! # Example
//!
//! ```ignore
//! use base_reth_privacy::mode::PrivacyMode;
//! use alloy_primitives::address;
//!
//! // Real mode - identity visible
//! let real = PrivacyMode::Real;
//!
//! // Shielded mode - anonymous interaction with poker contract
//! let shielded = PrivacyMode::Shielded {
//!     protocol: address!("1234567890123456789012345678901234567890"),
//!     index: 0, // Persistent address for this game
//! };
//! ```

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

/// Privacy mode for priv_* transactions.
///
/// Determines how the effective `msg.sender` is computed during execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum PrivacyMode {
    /// Real mode: `msg.sender` equals the real user address.
    ///
    /// Use when:
    /// - Identity reveal is acceptable or required
    /// - Interacting with contracts that need to know the real user
    /// - Linking shielded actions back to the real identity
    Real,

    /// Shielded mode: `msg.sender` equals a derived shielded address.
    ///
    /// The shielded address is derived deterministically from:
    /// - User's seed (stored encrypted, unique per user)
    /// - Protocol address (the contract being interacted with)
    /// - Chain ID (replay protection across chains)
    /// - Index (0 = persistent, >0 = fresh unlinkable)
    ///
    /// Use when:
    /// - Anonymity is required
    /// - Actions should not be linkable to the real user
    /// - Privacy-preserving interactions (voting, trading, gaming)
    Shielded {
        /// Protocol address for derivation.
        ///
        /// Typically the main contract address (e.g., poker game contract).
        /// Using the same protocol ensures consistent shielded addresses
        /// for the same user across interactions with that protocol.
        protocol: Address,

        /// Index for deterministic derivation.
        ///
        /// - `index = 0`: Persistent address per protocol. Allows position
        ///   consolidation (e.g., DeFi balance tracking across transactions).
        /// - `index > 0`: Fresh unlinkable address. Each index produces a
        ///   unique address that cannot be linked to other indices or the
        ///   real user without the seed.
        index: u64,
    },
}

impl PrivacyMode {
    /// Create a new Real mode.
    #[inline]
    pub const fn real() -> Self {
        Self::Real
    }

    /// Create a new Shielded mode with persistent address (index = 0).
    #[inline]
    pub const fn shielded_persistent(protocol: Address) -> Self {
        Self::Shielded { protocol, index: 0 }
    }

    /// Create a new Shielded mode with fresh address (index > 0).
    #[inline]
    pub const fn shielded_fresh(protocol: Address, index: u64) -> Self {
        Self::Shielded { protocol, index }
    }

    /// Check if this is Real mode.
    #[inline]
    pub const fn is_real(&self) -> bool {
        matches!(self, Self::Real)
    }

    /// Check if this is Shielded mode.
    #[inline]
    pub const fn is_shielded(&self) -> bool {
        matches!(self, Self::Shielded { .. })
    }

    /// Get the shielded parameters if in Shielded mode.
    ///
    /// Returns `Some((protocol, index))` for Shielded mode, `None` for Real mode.
    #[inline]
    pub const fn shielded_params(&self) -> Option<(Address, u64)> {
        match self {
            Self::Shielded { protocol, index } => Some((*protocol, *index)),
            Self::Real => None,
        }
    }

    /// Get the protocol address if in Shielded mode.
    #[inline]
    pub const fn protocol(&self) -> Option<Address> {
        match self {
            Self::Shielded { protocol, .. } => Some(*protocol),
            Self::Real => None,
        }
    }

    /// Get the index if in Shielded mode.
    #[inline]
    pub const fn index(&self) -> Option<u64> {
        match self {
            Self::Shielded { index, .. } => Some(*index),
            Self::Real => None,
        }
    }

    /// Check if this is a persistent shielded address (index = 0).
    #[inline]
    pub const fn is_persistent(&self) -> bool {
        matches!(self, Self::Shielded { index: 0, .. })
    }

    /// Check if this is a fresh shielded address (index > 0).
    #[inline]
    pub const fn is_fresh(&self) -> bool {
        matches!(self, Self::Shielded { index, .. } if *index > 0)
    }
}

impl Default for PrivacyMode {
    /// Default to Real mode (identity visible).
    fn default() -> Self {
        Self::Real
    }
}

impl std::fmt::Display for PrivacyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Real => write!(f, "Real"),
            Self::Shielded { protocol, index } => {
                write!(f, "Shielded(protocol={}, index={})", protocol, index)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    fn test_protocol() -> Address {
        address!("1234567890123456789012345678901234567890")
    }

    #[test]
    fn test_real_mode() {
        let mode = PrivacyMode::Real;
        assert!(mode.is_real());
        assert!(!mode.is_shielded());
        assert_eq!(mode.shielded_params(), None);
        assert_eq!(mode.protocol(), None);
        assert_eq!(mode.index(), None);
    }

    #[test]
    fn test_shielded_persistent() {
        let protocol = test_protocol();
        let mode = PrivacyMode::shielded_persistent(protocol);

        assert!(!mode.is_real());
        assert!(mode.is_shielded());
        assert!(mode.is_persistent());
        assert!(!mode.is_fresh());
        assert_eq!(mode.shielded_params(), Some((protocol, 0)));
        assert_eq!(mode.protocol(), Some(protocol));
        assert_eq!(mode.index(), Some(0));
    }

    #[test]
    fn test_shielded_fresh() {
        let protocol = test_protocol();
        let mode = PrivacyMode::shielded_fresh(protocol, 42);

        assert!(!mode.is_real());
        assert!(mode.is_shielded());
        assert!(!mode.is_persistent());
        assert!(mode.is_fresh());
        assert_eq!(mode.shielded_params(), Some((protocol, 42)));
        assert_eq!(mode.protocol(), Some(protocol));
        assert_eq!(mode.index(), Some(42));
    }

    #[test]
    fn test_default_is_real() {
        let mode = PrivacyMode::default();
        assert!(mode.is_real());
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", PrivacyMode::Real), "Real");

        let shielded = PrivacyMode::Shielded {
            protocol: test_protocol(),
            index: 5,
        };
        assert!(format!("{}", shielded).contains("Shielded"));
        assert!(format!("{}", shielded).contains("index=5"));
    }

    #[test]
    fn test_serialization() {
        let real = PrivacyMode::Real;
        let json = serde_json::to_string(&real).unwrap();
        let deserialized: PrivacyMode = serde_json::from_str(&json).unwrap();
        assert_eq!(real, deserialized);

        let shielded = PrivacyMode::Shielded {
            protocol: test_protocol(),
            index: 123,
        };
        let json = serde_json::to_string(&shielded).unwrap();
        let deserialized: PrivacyMode = serde_json::from_str(&json).unwrap();
        assert_eq!(shielded, deserialized);
    }

    #[test]
    fn test_equality() {
        let protocol = test_protocol();

        assert_eq!(PrivacyMode::Real, PrivacyMode::Real);
        assert_ne!(PrivacyMode::Real, PrivacyMode::shielded_persistent(protocol));

        let shielded1 = PrivacyMode::Shielded {
            protocol,
            index: 1,
        };
        let shielded2 = PrivacyMode::Shielded {
            protocol,
            index: 1,
        };
        let shielded3 = PrivacyMode::Shielded {
            protocol,
            index: 2,
        };

        assert_eq!(shielded1, shielded2);
        assert_ne!(shielded1, shielded3);
    }

    #[test]
    fn test_const_constructors() {
        // Verify const fn works at compile time
        const REAL: PrivacyMode = PrivacyMode::real();
        assert!(REAL.is_real());

        const PROTOCOL: Address = address!("0000000000000000000000000000000000000001");
        const PERSISTENT: PrivacyMode = PrivacyMode::shielded_persistent(PROTOCOL);
        assert!(PERSISTENT.is_persistent());

        const FRESH: PrivacyMode = PrivacyMode::shielded_fresh(PROTOCOL, 99);
        assert!(FRESH.is_fresh());
    }
}
