//! Shielded Address Management and Key Derivation.
//!
//! This module provides shielded address derivation and key management for
//! privacy-preserving transactions. Shielded addresses allow users to interact
//! with protocols without revealing their real identity.
//!
//! # Derivation Scheme
//!
//! Shielded addresses are derived deterministically:
//! ```text
//! private_key = keccak256(seed || protocol || chain_id || index || "shielded")
//! public_key = private_key * G  (secp256k1 generator point)
//! address = keccak256(public_key)[12..32]
//! ```
//!
//! # Security Model
//!
//! - **Seed confidentiality**: Each user has a unique 32-byte seed, stored
//!   encrypted (TEE sealing in production). The seed is generated once and
//!   persisted across sessions.
//!
//! - **Deterministic derivation**: Given the same (seed, protocol, chain_id, index),
//!   the same shielded address is always derived. This enables:
//!   - `index = 0`: Persistent per-protocol identity (positions consolidate)
//!   - `index > 0`: Fresh unlinkable addresses (anonymous actions)
//!
//! - **Unlinkability**: Without the seed, shielded addresses cannot be linked
//!   to each other or to the real user.
//!
//! # Example
//!
//! ```ignore
//! use base_reth_privacy::shielded::ShieldedKeyManager;
//! use alloy_primitives::address;
//!
//! let manager = ShieldedKeyManager::new(84532); // Base Sepolia chain ID
//! let user = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
//! let protocol = address!("1234567890123456789012345678901234567890");
//!
//! // Get persistent shielded address (index = 0)
//! let shielded = manager.get_shielded_address(user, protocol, 0);
//!
//! // Get fresh shielded address (index = 1)
//! let fresh = manager.get_shielded_address(user, protocol, 1);
//!
//! assert_ne!(shielded, fresh);
//! ```

use alloy_primitives::{keccak256, Address, B256};
use std::collections::HashMap;
use std::sync::RwLock;

/// A derived shielded key pair.
#[derive(Debug, Clone)]
pub struct DerivedKey {
    /// The shielded address.
    pub address: Address,
    /// The private key bytes (32 bytes).
    pub private_key: [u8; 32],
}

/// Manages shielded addresses and their derived private keys.
///
/// Responsibilities:
/// - Generate and store user seeds (one per real address)
/// - Derive shielded addresses from seeds
/// - Sign messages with derived keys
/// - Cache derived keys for performance
#[derive(Debug)]
pub struct ShieldedKeyManager {
    /// User seeds: real_address -> seed
    ///
    /// In production, these should be encrypted at rest (TEE sealing).
    seeds: RwLock<HashMap<Address, [u8; 32]>>,

    /// Cached derived keys: (real_address, protocol, index) -> DerivedKey
    ///
    /// Cleared on restart for security.
    key_cache: RwLock<HashMap<(Address, Address, u64), DerivedKey>>,

    /// Chain ID for derivation (prevents cross-chain address reuse).
    chain_id: u64,
}

impl ShieldedKeyManager {
    /// Create a new shielded key manager for the given chain.
    pub fn new(chain_id: u64) -> Self {
        Self {
            seeds: RwLock::new(HashMap::new()),
            key_cache: RwLock::new(HashMap::new()),
            chain_id,
        }
    }

    /// Get the chain ID this manager is configured for.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Get or create a seed for a user.
    ///
    /// If the user doesn't have a seed, a new one is generated deterministically
    /// (in production, this should use secure random generation).
    pub fn get_or_create_seed(&self, user: Address) -> [u8; 32] {
        // Check if seed exists
        {
            let seeds = self.seeds.read().expect("seed lock poisoned");
            if let Some(seed) = seeds.get(&user) {
                return *seed;
            }
        }

        // Generate new seed
        let seed = self.generate_seed(user);

        // Store it
        {
            let mut seeds = self.seeds.write().expect("seed lock poisoned");
            seeds.insert(user, seed);
        }

        seed
    }

    /// Generate a cryptographically random seed for a user.
    ///
    /// This uses the operating system's secure random number generator
    /// to produce a 32-byte seed that cannot be predicted or derived
    /// from public information.
    ///
    /// For testing with reproducible results, use [`set_seed`] to inject
    /// a known seed value instead.
    fn generate_seed(&self, _user: Address) -> [u8; 32] {
        rand::random()
    }

    /// Set a user's seed directly.
    ///
    /// Used for:
    /// - Restoring seeds from persistent storage
    /// - Testing with known seeds
    pub fn set_seed(&self, user: Address, seed: [u8; 32]) {
        let mut seeds = self.seeds.write().expect("seed lock poisoned");
        seeds.insert(user, seed);

        // Clear cache entries for this user (seed changed)
        let mut cache = self.key_cache.write().expect("cache lock poisoned");
        cache.retain(|(u, _, _), _| *u != user);
    }

    /// Derive a shielded address and key for the given parameters.
    ///
    /// This caches the result for subsequent lookups.
    pub fn derive_shielded(
        &self,
        user: Address,
        protocol: Address,
        index: u64,
    ) -> DerivedKey {
        let cache_key = (user, protocol, index);

        // Check cache first
        {
            let cache = self.key_cache.read().expect("cache lock poisoned");
            if let Some(key) = cache.get(&cache_key) {
                return key.clone();
            }
        }

        // Derive the key
        let seed = self.get_or_create_seed(user);
        let derived = self.derive_from_seed(seed, protocol, index);

        // Cache it
        {
            let mut cache = self.key_cache.write().expect("cache lock poisoned");
            cache.insert(cache_key, derived.clone());
        }

        derived
    }

    /// Get the shielded address without caching the key.
    ///
    /// Use this for display purposes when you don't need to sign.
    pub fn get_shielded_address(
        &self,
        user: Address,
        protocol: Address,
        index: u64,
    ) -> Address {
        self.derive_shielded(user, protocol, index).address
    }

    /// Derive a shielded key from a seed.
    ///
    /// Derivation: `keccak256(seed || protocol || chain_id || index || "shielded")`
    fn derive_from_seed(
        &self,
        seed: [u8; 32],
        protocol: Address,
        index: u64,
    ) -> DerivedKey {
        // Build derivation input
        let mut data = Vec::with_capacity(128);
        data.extend_from_slice(&seed);
        data.extend_from_slice(protocol.as_slice());
        data.extend_from_slice(&self.chain_id.to_be_bytes());
        data.extend_from_slice(&index.to_be_bytes());
        data.extend_from_slice(b"shielded");

        let derived_hash = keccak256(&data);
        let private_key = derived_hash.0;

        // Derive address from private key
        let address = self.private_key_to_address(&private_key);

        DerivedKey {
            address,
            private_key,
        }
    }

    /// Convert a private key to an Ethereum address.
    ///
    /// Uses secp256k1 curve to derive the public key, then hashes it.
    fn private_key_to_address(&self, private_key: &[u8; 32]) -> Address {
        use k256::ecdsa::SigningKey;
        use k256::PublicKey;
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        // Create signing key from private key bytes
        let signing_key = SigningKey::from_bytes(private_key.into())
            .expect("valid private key (keccak output is always valid)");

        // Get the public key in uncompressed form (65 bytes: 0x04 || x || y)
        let public_key: PublicKey = signing_key.verifying_key().into();
        let encoded_point = public_key.to_encoded_point(false); // false = uncompressed

        // Skip the 0x04 prefix - we want just the 64 bytes (x || y)
        let public_key_bytes = &encoded_point.as_bytes()[1..];

        // Keccak256 hash of public key, take last 20 bytes
        let hash = keccak256(public_key_bytes);
        Address::from_slice(&hash[12..])
    }

    /// Sign a message hash with a derived shielded key.
    ///
    /// Returns an Ethereum-compatible signature (v, r, s).
    pub fn sign_hash(
        &self,
        user: Address,
        protocol: Address,
        index: u64,
        hash: B256,
    ) -> alloy_primitives::Signature {
        use k256::ecdsa::{RecoveryId, Signature as K256Sig, SigningKey};

        let derived = self.derive_shielded(user, protocol, index);
        let signing_key = SigningKey::from_bytes((&derived.private_key).into())
            .expect("valid private key");

        // Sign the prehash
        let (signature, recovery_id): (K256Sig, RecoveryId) = signing_key
            .sign_prehash_recoverable(hash.as_slice())
            .expect("signing should succeed");

        // Convert to alloy Signature
        let r = alloy_primitives::U256::from_be_slice(&signature.r().to_bytes());
        let s = alloy_primitives::U256::from_be_slice(&signature.s().to_bytes());
        let v = recovery_id.is_y_odd();

        alloy_primitives::Signature::new(r, s, v)
    }

    /// Clear the key cache.
    ///
    /// Should be called periodically for security, or on restart.
    pub fn clear_cache(&self) {
        self.key_cache.write().expect("cache lock poisoned").clear();
    }

    /// Clear all data (seeds and cache).
    ///
    /// Primarily for testing.
    #[cfg(test)]
    pub fn clear_all(&self) {
        self.seeds.write().expect("seed lock poisoned").clear();
        self.key_cache.write().expect("cache lock poisoned").clear();
    }

    /// Check if a user has a seed.
    pub fn has_seed(&self, user: Address) -> bool {
        self.seeds.read().expect("seed lock poisoned").contains_key(&user)
    }

    /// Get all users with seeds (for persistence).
    pub fn all_users(&self) -> Vec<Address> {
        self.seeds
            .read()
            .expect("seed lock poisoned")
            .keys()
            .copied()
            .collect()
    }
}

impl Clone for ShieldedKeyManager {
    fn clone(&self) -> Self {
        Self {
            seeds: RwLock::new(self.seeds.read().expect("seed lock poisoned").clone()),
            key_cache: RwLock::new(HashMap::new()), // Don't clone cache
            chain_id: self.chain_id,
        }
    }
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

    fn test_protocol() -> Address {
        address!("1234567890123456789012345678901234567890")
    }

    fn test_protocol2() -> Address {
        address!("abcdef0123456789abcdef0123456789abcdef01")
    }

    #[test]
    fn test_new_manager() {
        let manager = ShieldedKeyManager::new(84532);
        assert_eq!(manager.chain_id(), 84532);
    }

    #[test]
    fn test_seed_generation() {
        let manager = ShieldedKeyManager::new(84532);
        let user = test_user();

        // First call generates seed
        let seed1 = manager.get_or_create_seed(user);

        // Second call returns same seed
        let seed2 = manager.get_or_create_seed(user);

        assert_eq!(seed1, seed2);
    }

    #[test]
    fn test_different_users_different_seeds() {
        let manager = ShieldedKeyManager::new(84532);

        // With RNG, different users will get different random seeds
        let seed1 = manager.get_or_create_seed(test_user());
        let seed2 = manager.get_or_create_seed(test_user2());

        // Seeds should be different (extremely unlikely to collide with 32 random bytes)
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn test_rng_seed_generation_produces_unique_seeds() {
        let manager = ShieldedKeyManager::new(84532);

        // Generate multiple seeds and verify they're all unique
        let users: Vec<Address> = (0..10)
            .map(|i| Address::new([i as u8; 20]))
            .collect();

        let seeds: Vec<[u8; 32]> = users
            .iter()
            .map(|u| manager.get_or_create_seed(*u))
            .collect();

        // All seeds should be unique
        for i in 0..seeds.len() {
            for j in (i + 1)..seeds.len() {
                assert_ne!(seeds[i], seeds[j], "Seeds at {} and {} should differ", i, j);
            }
        }
    }

    #[test]
    fn test_derive_shielded_deterministic() {
        let manager = ShieldedKeyManager::new(84532);
        let user = test_user();
        let protocol = test_protocol();

        let key1 = manager.derive_shielded(user, protocol, 0);
        let key2 = manager.derive_shielded(user, protocol, 0);

        assert_eq!(key1.address, key2.address);
        assert_eq!(key1.private_key, key2.private_key);
    }

    #[test]
    fn test_different_indices_different_addresses() {
        let manager = ShieldedKeyManager::new(84532);
        let user = test_user();
        let protocol = test_protocol();

        let addr0 = manager.get_shielded_address(user, protocol, 0);
        let addr1 = manager.get_shielded_address(user, protocol, 1);
        let addr2 = manager.get_shielded_address(user, protocol, 2);

        assert_ne!(addr0, addr1);
        assert_ne!(addr1, addr2);
        assert_ne!(addr0, addr2);
    }

    #[test]
    fn test_different_protocols_different_addresses() {
        let manager = ShieldedKeyManager::new(84532);
        let user = test_user();

        let addr1 = manager.get_shielded_address(user, test_protocol(), 0);
        let addr2 = manager.get_shielded_address(user, test_protocol2(), 0);

        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_different_users_different_addresses() {
        let manager = ShieldedKeyManager::new(84532);
        let protocol = test_protocol();

        let addr1 = manager.get_shielded_address(test_user(), protocol, 0);
        let addr2 = manager.get_shielded_address(test_user2(), protocol, 0);

        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_different_chains_different_addresses() {
        let manager1 = ShieldedKeyManager::new(1); // Mainnet
        let manager2 = ShieldedKeyManager::new(84532); // Base Sepolia

        let user = test_user();
        let protocol = test_protocol();

        // Set same seed for both
        let seed = [0x42u8; 32];
        manager1.set_seed(user, seed);
        manager2.set_seed(user, seed);

        let addr1 = manager1.get_shielded_address(user, protocol, 0);
        let addr2 = manager2.get_shielded_address(user, protocol, 0);

        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_set_seed() {
        let manager = ShieldedKeyManager::new(84532);
        let user = test_user();
        let custom_seed = [0xAAu8; 32];

        manager.set_seed(user, custom_seed);

        let retrieved = manager.get_or_create_seed(user);
        assert_eq!(retrieved, custom_seed);
    }

    #[test]
    fn test_sign_hash() {
        let manager = ShieldedKeyManager::new(84532);
        let user = test_user();
        let protocol = test_protocol();

        let hash = keccak256(b"test message");
        let signature = manager.sign_hash(user, protocol, 0, hash);

        // Verify signature recovers to the shielded address
        let derived = manager.derive_shielded(user, protocol, 0);
        let recovered = signature
            .recover_address_from_prehash(&hash)
            .expect("recovery should succeed");

        assert_eq!(recovered, derived.address);
    }

    #[test]
    fn test_different_messages_different_signatures() {
        let manager = ShieldedKeyManager::new(84532);
        let user = test_user();
        let protocol = test_protocol();

        let hash1 = keccak256(b"message 1");
        let hash2 = keccak256(b"message 2");

        let sig1 = manager.sign_hash(user, protocol, 0, hash1);
        let sig2 = manager.sign_hash(user, protocol, 0, hash2);

        // Same signer, different messages = different signatures
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_clear_cache() {
        let manager = ShieldedKeyManager::new(84532);
        let user = test_user();
        let protocol = test_protocol();

        // Populate cache
        let _ = manager.derive_shielded(user, protocol, 0);

        // Clear cache
        manager.clear_cache();

        // Should still work (re-derives)
        let key = manager.derive_shielded(user, protocol, 0);
        assert!(!key.address.is_zero());
    }

    #[test]
    fn test_has_seed() {
        let manager = ShieldedKeyManager::new(84532);
        let user = test_user();

        assert!(!manager.has_seed(user));

        manager.get_or_create_seed(user);

        assert!(manager.has_seed(user));
    }

    #[test]
    fn test_all_users() {
        let manager = ShieldedKeyManager::new(84532);

        manager.get_or_create_seed(test_user());
        manager.get_or_create_seed(test_user2());

        let users = manager.all_users();
        assert_eq!(users.len(), 2);
        assert!(users.contains(&test_user()));
        assert!(users.contains(&test_user2()));
    }

    #[test]
    fn test_clone() {
        let manager = ShieldedKeyManager::new(84532);
        manager.set_seed(test_user(), [0x42u8; 32]);

        let cloned = manager.clone();

        // Seeds should be cloned
        assert_eq!(
            cloned.get_or_create_seed(test_user()),
            manager.get_or_create_seed(test_user())
        );

        // Same derivation
        assert_eq!(
            cloned.get_shielded_address(test_user(), test_protocol(), 0),
            manager.get_shielded_address(test_user(), test_protocol(), 0)
        );
    }

    #[test]
    fn test_shielded_address_is_valid() {
        let manager = ShieldedKeyManager::new(84532);
        let addr = manager.get_shielded_address(test_user(), test_protocol(), 0);

        // Should be a valid non-zero address
        assert!(!addr.is_zero());

        // Should be 20 bytes (inherent in Address type)
        assert_eq!(addr.as_slice().len(), 20);
    }
}
