//! Slot Classification
//!
//! Determines whether a storage slot is public or private based on
//! the privacy registry configuration.
//!
//! # Defensive Classification
//!
//! For contracts with mapping slots, the first access to a mapping slot
//! may occur before the slot ownership has been recorded (which happens
//! during write commits). To prevent data leakage, use [`classify_slot_defensive`]
//! which treats unrecorded high-entropy slots as private when the contract
//! has mapping slots configured.

use crate::registry::{OwnershipType, PrivacyRegistry, SlotType};
use alloy_primitives::{Address, U256};

/// Classification of a storage slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotClassification {
    /// The slot is public and stored in the standard state trie.
    Public,
    /// The slot is private and stored in the TEE-local store.
    Private {
        /// The owner of this slot (for authorization purposes)
        owner: Address,
    },
}

impl SlotClassification {
    /// Returns `true` if the slot is private.
    pub fn is_private(&self) -> bool {
        matches!(self, Self::Private { .. })
    }

    /// Returns `true` if the slot is public.
    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }

    /// Returns the owner if the slot is private.
    pub fn owner(&self) -> Option<Address> {
        match self {
            Self::Private { owner } => Some(*owner),
            Self::Public => None,
        }
    }
}

/// Classify a storage slot as public or private.
///
/// # Arguments
///
/// * `registry` - The privacy registry to consult
/// * `contract` - The contract address
/// * `slot` - The storage slot being accessed
///
/// # Returns
///
/// - `SlotClassification::Public` if the contract is not registered or the slot is not private
/// - `SlotClassification::Private { owner }` if the slot is private
///
/// # Example
///
/// ```ignore
/// use base_reth_privacy::{PrivacyRegistry, classify_slot, SlotClassification};
///
/// let registry = PrivacyRegistry::new();
/// // ... register contracts ...
///
/// match classify_slot(&registry, contract, slot) {
///     SlotClassification::Public => {
///         // Read from triedb
///     }
///     SlotClassification::Private { owner } => {
///         // Read from private store
///     }
/// }
/// ```
pub fn classify_slot(registry: &PrivacyRegistry, contract: Address, slot: U256) -> SlotClassification {
    // Fast path: unregistered contracts are always public
    let config = match registry.get_config(&contract) {
        Some(c) => c,
        None => return SlotClassification::Public,
    };

    // Check each slot configuration
    for slot_config in &config.slots {
        match slot_config.slot_type {
            SlotType::Simple => {
                // Simple slots: exact match
                if slot == slot_config.base_slot {
                    let owner = resolve_simple_owner(&slot_config.ownership, contract);
                    return SlotClassification::Private { owner };
                }
            }
            SlotType::Mapping | SlotType::NestedMapping | SlotType::MappingToStruct { .. } => {
                // For mappings, we can't reverse the hash to check the base slot.
                // Instead, check if this slot was recorded as a mapping slot.
                if let Some(owner) = registry.get_slot_owner(contract, slot) {
                    return SlotClassification::Private { owner };
                }
            }
        }
    }

    // Default: public
    SlotClassification::Public
}

/// Configuration for defensive slot classification.
///
/// Controls how unrecorded mapping slots are handled to prevent data leakage
/// on first access before ownership is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefensiveClassification {
    /// Unknown mapping slots default to PUBLIC (legacy/insecure behavior).
    ///
    /// **Warning**: This may leak private data on first access to a mapping slot.
    LegacyPublic,

    /// Unknown mapping slots default to PRIVATE with the caller as owner.
    ///
    /// This is the safest option as it prevents data leakage while allowing
    /// the current caller to access their own data.
    PrivateWithCaller(Address),

    /// Unknown mapping slots default to PRIVATE with the contract as owner.
    ///
    /// Use this when the caller is unknown or when all data should be
    /// contract-controlled.
    PrivateWithContract,
}

/// Classify a storage slot with defensive handling of unrecorded mapping slots.
///
/// This is the preferred classification function as it prevents data leakage
/// when a mapping slot is first accessed before ownership has been recorded.
///
/// # Arguments
///
/// * `registry` - The privacy registry to consult
/// * `contract` - The contract address
/// * `slot` - The storage slot being accessed
/// * `defensive` - How to handle unrecorded mapping slots
///
/// # Returns
///
/// - `SlotClassification::Public` if the contract is not registered or the slot is not private
/// - `SlotClassification::Private { owner }` if the slot is private or defensively classified
///
/// # Example
///
/// ```ignore
/// use base_reth_privacy::{classify_slot_defensive, DefensiveClassification, SlotClassification};
///
/// // Use defensive classification with caller as fallback owner
/// let classification = classify_slot_defensive(
///     &registry,
///     contract,
///     slot,
///     DefensiveClassification::PrivateWithCaller(msg_sender),
/// );
/// ```
pub fn classify_slot_defensive(
    registry: &PrivacyRegistry,
    contract: Address,
    slot: U256,
    defensive: DefensiveClassification,
) -> SlotClassification {
    // Fast path: unregistered contracts are always public
    let config = match registry.get_config(&contract) {
        Some(c) => c,
        None => return SlotClassification::Public,
    };

    // Check simple slots first (exact match)
    for slot_config in &config.slots {
        if let SlotType::Simple = slot_config.slot_type {
            if slot == slot_config.base_slot {
                let owner = resolve_simple_owner(&slot_config.ownership, contract);
                return SlotClassification::Private { owner };
            }
        }
    }

    // Check recorded mapping slots
    if let Some(owner) = registry.get_slot_owner(contract, slot) {
        return SlotClassification::Private { owner };
    }

    // Check if contract has any mapping slots configured
    let has_mapping_slots = config.slots.iter().any(|sc| {
        matches!(
            sc.slot_type,
            SlotType::Mapping | SlotType::NestedMapping | SlotType::MappingToStruct { .. }
        )
    });

    // Defensive classification for unrecorded slots in contracts with mappings
    if has_mapping_slots && is_potential_mapping_slot(slot) {
        match defensive {
            DefensiveClassification::LegacyPublic => SlotClassification::Public,
            DefensiveClassification::PrivateWithCaller(caller) => {
                SlotClassification::Private { owner: caller }
            }
            DefensiveClassification::PrivateWithContract => {
                SlotClassification::Private { owner: contract }
            }
        }
    } else {
        SlotClassification::Public
    }
}

/// Heuristic to detect potential mapping slots.
///
/// Mapping slots are computed as `keccak256(key || base_slot)`, which produces
/// high-entropy values. Simple slots are typically small sequential numbers
/// (0, 1, 2, ...) used by the Solidity compiler.
///
/// # Heuristic
///
/// A slot is considered a potential mapping slot if:
/// - Its value is >= 256 (simple slots are typically < 100)
/// - It has non-zero bytes in the upper half (indicates hash output)
///
/// This heuristic may have false positives for large simple slots or false
/// negatives for mapping slots with low base values, but errs on the side
/// of caution for security.
fn is_potential_mapping_slot(slot: U256) -> bool {
    // Simple slots are typically small numbers (< 256)
    if slot < U256::from(256) {
        return false;
    }

    // Check if the slot has characteristics of a keccak256 hash output:
    // Hash outputs have high entropy and typically have non-zero upper bytes
    let bytes = slot.to_be_bytes::<32>();

    // If any of the first 16 bytes are non-zero, it's likely a hash
    bytes[0..16].iter().any(|&b| b != 0)
}

/// Resolve the owner for a simple (non-mapping) slot.
fn resolve_simple_owner(ownership: &OwnershipType, contract: Address) -> Address {
    match ownership {
        OwnershipType::Contract => contract,
        OwnershipType::FixedOwner(addr) => *addr,
        // For simple slots, these don't really apply but we handle them
        OwnershipType::MappingKey
        | OwnershipType::OuterKey
        | OwnershipType::InnerKey => contract,
    }
}

/// Resolve the owner for a mapping slot based on the key used.
///
/// This is called when we intercept a mapping write and need to determine
/// who owns the resulting slot.
///
/// # Arguments
///
/// * `ownership` - How ownership is determined for this mapping
/// * `key` - The mapping key (typically an address)
/// * `outer_key` - For nested mappings, the outer key
/// * `contract` - The contract address (fallback owner)
pub fn resolve_mapping_owner(
    ownership: &OwnershipType,
    key: Address,
    outer_key: Option<Address>,
    contract: Address,
) -> Address {
    match ownership {
        OwnershipType::Contract => contract,
        OwnershipType::MappingKey => key,
        OwnershipType::OuterKey => outer_key.unwrap_or(key),
        OwnershipType::InnerKey => key,
        OwnershipType::FixedOwner(addr) => *addr,
    }
}

/// Compute the storage slot for a mapping access.
///
/// For `mapping(address => T)`, the slot is `keccak256(abi.encode(key, base_slot))`.
///
/// # Arguments
///
/// * `base_slot` - The base slot of the mapping
/// * `key` - The mapping key
///
/// # Returns
///
/// The computed storage slot.
pub fn compute_mapping_slot(base_slot: U256, key: Address) -> U256 {
    use alloy_primitives::keccak256;

    // abi.encode(key, base_slot) = 32 bytes for key (left-padded) + 32 bytes for slot
    let mut data = [0u8; 64];
    // Key is right-aligned in first 32 bytes (address is 20 bytes)
    data[12..32].copy_from_slice(key.as_slice());
    // Slot is big-endian in second 32 bytes
    data[32..64].copy_from_slice(&base_slot.to_be_bytes::<32>());

    let hash = keccak256(&data);
    U256::from_be_bytes(hash.0)
}

/// Compute the storage slot for a nested mapping access.
///
/// For `mapping(address => mapping(address => T))`, the slot is:
/// `keccak256(abi.encode(inner_key, keccak256(abi.encode(outer_key, base_slot))))`
///
/// # Arguments
///
/// * `base_slot` - The base slot of the outer mapping
/// * `outer_key` - The key for the outer mapping
/// * `inner_key` - The key for the inner mapping
///
/// # Returns
///
/// The computed storage slot.
pub fn compute_nested_mapping_slot(base_slot: U256, outer_key: Address, inner_key: Address) -> U256 {
    let outer_slot = compute_mapping_slot(base_slot, outer_key);
    compute_mapping_slot(outer_slot, inner_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{PrivateContractConfig, SlotConfig};

    fn test_address(n: u8) -> Address {
        Address::new([n; 20])
    }

    #[test]
    fn test_unregistered_contract_is_public() {
        let registry = PrivacyRegistry::new();
        let contract = test_address(1);
        let slot = U256::from(0);

        let result = classify_slot(&registry, contract, slot);
        assert!(result.is_public());
        assert_eq!(result.owner(), None);
    }

    #[test]
    fn test_simple_private_slot() {
        let registry = PrivacyRegistry::new();
        let contract = test_address(1);
        let admin = test_address(2);

        let config = PrivateContractConfig {
            address: contract,
            admin,
            slots: vec![SlotConfig {
                base_slot: U256::from(5),
                slot_type: SlotType::Simple,
                ownership: OwnershipType::Contract,
            }],
            registered_at: 1,
            hide_events: false,
        };

        registry.register(config).unwrap();

        let result = classify_slot(&registry, contract, U256::from(5));
        assert!(result.is_private());
        assert_eq!(result.owner(), Some(contract));
    }

    #[test]
    fn test_simple_slot_with_fixed_owner() {
        let registry = PrivacyRegistry::new();
        let contract = test_address(1);
        let admin = test_address(2);
        let fixed_owner = test_address(99);

        let config = PrivateContractConfig {
            address: contract,
            admin,
            slots: vec![SlotConfig {
                base_slot: U256::from(5),
                slot_type: SlotType::Simple,
                ownership: OwnershipType::FixedOwner(fixed_owner),
            }],
            registered_at: 1,
            hide_events: false,
        };

        registry.register(config).unwrap();

        let result = classify_slot(&registry, contract, U256::from(5));
        assert!(result.is_private());
        assert_eq!(result.owner(), Some(fixed_owner));
    }

    #[test]
    fn test_non_registered_slot_is_public() {
        let registry = PrivacyRegistry::new();
        let contract = test_address(1);
        let admin = test_address(2);

        let config = PrivateContractConfig {
            address: contract,
            admin,
            slots: vec![SlotConfig {
                base_slot: U256::from(5),
                slot_type: SlotType::Simple,
                ownership: OwnershipType::Contract,
            }],
            registered_at: 1,
            hide_events: false,
        };

        registry.register(config).unwrap();

        // Slot 10 is not registered as private
        let result = classify_slot(&registry, contract, U256::from(10));
        assert!(result.is_public());
    }

    #[test]
    fn test_mapping_slot_with_recorded_owner() {
        let registry = PrivacyRegistry::new();
        let contract = test_address(1);
        let admin = test_address(2);
        let alice = test_address(10);

        let config = PrivateContractConfig {
            address: contract,
            admin,
            slots: vec![SlotConfig {
                base_slot: U256::ZERO,
                slot_type: SlotType::Mapping,
                ownership: OwnershipType::MappingKey,
            }],
            registered_at: 1,
            hide_events: false,
        };

        registry.register(config).unwrap();

        // Compute the slot for balances[alice]
        let computed_slot = compute_mapping_slot(U256::ZERO, alice);

        // Record the owner (this would happen during SSTORE interception)
        registry.record_slot_owner(contract, computed_slot, alice);

        // Now classify the slot
        let result = classify_slot(&registry, contract, computed_slot);
        assert!(result.is_private());
        assert_eq!(result.owner(), Some(alice));
    }

    #[test]
    fn test_unrecorded_mapping_slot_is_public() {
        let registry = PrivacyRegistry::new();
        let contract = test_address(1);
        let admin = test_address(2);
        let alice = test_address(10);

        let config = PrivateContractConfig {
            address: contract,
            admin,
            slots: vec![SlotConfig {
                base_slot: U256::ZERO,
                slot_type: SlotType::Mapping,
                ownership: OwnershipType::MappingKey,
            }],
            registered_at: 1,
            hide_events: false,
        };

        registry.register(config).unwrap();

        // Compute the slot for balances[alice] but DON'T record the owner
        let computed_slot = compute_mapping_slot(U256::ZERO, alice);

        // Without recording, we can't know it's private
        let result = classify_slot(&registry, contract, computed_slot);
        assert!(result.is_public());
    }

    #[test]
    fn test_compute_mapping_slot() {
        let base_slot = U256::ZERO;
        let key = Address::new([0xAB; 20]);

        let slot1 = compute_mapping_slot(base_slot, key);
        let slot2 = compute_mapping_slot(base_slot, key);

        // Same inputs produce same output
        assert_eq!(slot1, slot2);

        // Different key produces different slot
        let other_key = Address::new([0xCD; 20]);
        let slot3 = compute_mapping_slot(base_slot, other_key);
        assert_ne!(slot1, slot3);

        // Different base slot produces different slot
        let slot4 = compute_mapping_slot(U256::from(1), key);
        assert_ne!(slot1, slot4);
    }

    #[test]
    fn test_compute_nested_mapping_slot() {
        let base_slot = U256::from(1); // allowances
        let owner = Address::new([0xAA; 20]);
        let spender = Address::new([0xBB; 20]);

        let slot = compute_nested_mapping_slot(base_slot, owner, spender);

        // Verify it's different from a simple mapping
        let simple_slot = compute_mapping_slot(base_slot, owner);
        assert_ne!(slot, simple_slot);

        // Verify order matters
        let reversed = compute_nested_mapping_slot(base_slot, spender, owner);
        assert_ne!(slot, reversed);
    }

    #[test]
    fn test_resolve_mapping_owner() {
        let key = test_address(10);
        let outer_key = test_address(20);
        let contract = test_address(1);
        let fixed = test_address(99);

        assert_eq!(
            resolve_mapping_owner(&OwnershipType::Contract, key, None, contract),
            contract
        );
        assert_eq!(
            resolve_mapping_owner(&OwnershipType::MappingKey, key, None, contract),
            key
        );
        assert_eq!(
            resolve_mapping_owner(&OwnershipType::OuterKey, key, Some(outer_key), contract),
            outer_key
        );
        assert_eq!(
            resolve_mapping_owner(&OwnershipType::InnerKey, key, Some(outer_key), contract),
            key
        );
        assert_eq!(
            resolve_mapping_owner(&OwnershipType::FixedOwner(fixed), key, None, contract),
            fixed
        );
    }

    #[test]
    fn test_slot_classification_methods() {
        let public = SlotClassification::Public;
        assert!(public.is_public());
        assert!(!public.is_private());
        assert_eq!(public.owner(), None);

        let owner = test_address(10);
        let private = SlotClassification::Private { owner };
        assert!(private.is_private());
        assert!(!private.is_public());
        assert_eq!(private.owner(), Some(owner));
    }

    #[test]
    fn test_multiple_slot_configs() {
        let registry = PrivacyRegistry::new();
        let contract = test_address(1);
        let admin = test_address(2);
        let alice = test_address(10);

        let config = PrivateContractConfig {
            address: contract,
            admin,
            slots: vec![
                SlotConfig {
                    base_slot: U256::from(0),
                    slot_type: SlotType::Mapping,
                    ownership: OwnershipType::MappingKey,
                },
                SlotConfig {
                    base_slot: U256::from(1),
                    slot_type: SlotType::NestedMapping,
                    ownership: OwnershipType::OuterKey,
                },
                SlotConfig {
                    base_slot: U256::from(5),
                    slot_type: SlotType::Simple,
                    ownership: OwnershipType::Contract,
                },
            ],
            registered_at: 1,
            hide_events: false,
        };

        registry.register(config).unwrap();

        // Simple slot should be private
        assert!(classify_slot(&registry, contract, U256::from(5)).is_private());

        // Simple slot 6 should be public (not in config)
        assert!(classify_slot(&registry, contract, U256::from(6)).is_public());

        // Record a mapping slot owner
        let balance_slot = compute_mapping_slot(U256::ZERO, alice);
        registry.record_slot_owner(contract, balance_slot, alice);
        assert!(classify_slot(&registry, contract, balance_slot).is_private());
    }

    // ==================== Defensive Classification Tests ====================

    #[test]
    fn test_defensive_unrecorded_mapping_with_caller() {
        let registry = PrivacyRegistry::new();
        let contract = test_address(1);
        let admin = test_address(2);
        let caller = test_address(50);
        let alice = test_address(10);

        let config = PrivateContractConfig {
            address: contract,
            admin,
            slots: vec![SlotConfig {
                base_slot: U256::ZERO,
                slot_type: SlotType::Mapping,
                ownership: OwnershipType::MappingKey,
            }],
            registered_at: 1,
            hide_events: false,
        };

        registry.register(config).unwrap();

        // Compute a mapping slot but DON'T record the owner
        let unrecorded_slot = compute_mapping_slot(U256::ZERO, alice);

        // With defensive classification, unrecorded high-entropy slots are private
        let result = classify_slot_defensive(
            &registry,
            contract,
            unrecorded_slot,
            DefensiveClassification::PrivateWithCaller(caller),
        );

        assert!(result.is_private());
        assert_eq!(result.owner(), Some(caller));
    }

    #[test]
    fn test_defensive_unrecorded_mapping_with_contract() {
        let registry = PrivacyRegistry::new();
        let contract = test_address(1);
        let admin = test_address(2);
        let alice = test_address(10);

        let config = PrivateContractConfig {
            address: contract,
            admin,
            slots: vec![SlotConfig {
                base_slot: U256::ZERO,
                slot_type: SlotType::Mapping,
                ownership: OwnershipType::MappingKey,
            }],
            registered_at: 1,
            hide_events: false,
        };

        registry.register(config).unwrap();

        let unrecorded_slot = compute_mapping_slot(U256::ZERO, alice);

        let result = classify_slot_defensive(
            &registry,
            contract,
            unrecorded_slot,
            DefensiveClassification::PrivateWithContract,
        );

        assert!(result.is_private());
        assert_eq!(result.owner(), Some(contract));
    }

    #[test]
    fn test_defensive_legacy_public() {
        let registry = PrivacyRegistry::new();
        let contract = test_address(1);
        let admin = test_address(2);
        let alice = test_address(10);

        let config = PrivateContractConfig {
            address: contract,
            admin,
            slots: vec![SlotConfig {
                base_slot: U256::ZERO,
                slot_type: SlotType::Mapping,
                ownership: OwnershipType::MappingKey,
            }],
            registered_at: 1,
            hide_events: false,
        };

        registry.register(config).unwrap();

        let unrecorded_slot = compute_mapping_slot(U256::ZERO, alice);

        // Legacy mode returns public (insecure)
        let result = classify_slot_defensive(
            &registry,
            contract,
            unrecorded_slot,
            DefensiveClassification::LegacyPublic,
        );

        assert!(result.is_public());
    }

    #[test]
    fn test_defensive_simple_slot_still_works() {
        let registry = PrivacyRegistry::new();
        let contract = test_address(1);
        let admin = test_address(2);
        let caller = test_address(50);

        let config = PrivateContractConfig {
            address: contract,
            admin,
            slots: vec![SlotConfig {
                base_slot: U256::from(5),
                slot_type: SlotType::Simple,
                ownership: OwnershipType::Contract,
            }],
            registered_at: 1,
            hide_events: false,
        };

        registry.register(config).unwrap();

        // Simple slots should still be classified correctly
        let result = classify_slot_defensive(
            &registry,
            contract,
            U256::from(5),
            DefensiveClassification::PrivateWithCaller(caller),
        );

        assert!(result.is_private());
        assert_eq!(result.owner(), Some(contract)); // Not caller!
    }

    #[test]
    fn test_defensive_low_entropy_slot_is_public() {
        let registry = PrivacyRegistry::new();
        let contract = test_address(1);
        let admin = test_address(2);
        let caller = test_address(50);

        let config = PrivateContractConfig {
            address: contract,
            admin,
            slots: vec![SlotConfig {
                base_slot: U256::ZERO,
                slot_type: SlotType::Mapping,
                ownership: OwnershipType::MappingKey,
            }],
            registered_at: 1,
            hide_events: false,
        };

        registry.register(config).unwrap();

        // Low-entropy slots (< 256) are NOT treated as mapping slots
        let result = classify_slot_defensive(
            &registry,
            contract,
            U256::from(100), // Low value, not a mapping slot
            DefensiveClassification::PrivateWithCaller(caller),
        );

        assert!(result.is_public());
    }

    #[test]
    fn test_defensive_contract_without_mappings() {
        let registry = PrivacyRegistry::new();
        let contract = test_address(1);
        let admin = test_address(2);
        let caller = test_address(50);

        // Contract with only simple slots (no mappings)
        let config = PrivateContractConfig {
            address: contract,
            admin,
            slots: vec![SlotConfig {
                base_slot: U256::from(5),
                slot_type: SlotType::Simple,
                ownership: OwnershipType::Contract,
            }],
            registered_at: 1,
            hide_events: false,
        };

        registry.register(config).unwrap();

        // High-entropy slot but contract has no mappings - should be public
        let high_entropy_slot = U256::from_be_bytes([0xFF; 32]);
        let result = classify_slot_defensive(
            &registry,
            contract,
            high_entropy_slot,
            DefensiveClassification::PrivateWithCaller(caller),
        );

        assert!(result.is_public());
    }

    #[test]
    fn test_is_potential_mapping_slot() {
        // Low values are not mapping slots
        assert!(!is_potential_mapping_slot(U256::ZERO));
        assert!(!is_potential_mapping_slot(U256::from(100)));
        assert!(!is_potential_mapping_slot(U256::from(255)));

        // Values >= 256 with high-entropy bytes are mapping slots
        let high_entropy = U256::from_be_bytes([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        ]);
        assert!(is_potential_mapping_slot(high_entropy));

        // A real keccak256 output
        let alice = test_address(10);
        let mapping_slot = compute_mapping_slot(U256::ZERO, alice);
        assert!(is_potential_mapping_slot(mapping_slot));
    }
}
