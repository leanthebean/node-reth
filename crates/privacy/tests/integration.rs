//! Integration tests for the privacy layer.
//!
//! These tests verify the complete privacy flow:
//! 1. Contract registration via Registry
//! 2. Slot authorization via PrivateStateStore
//! 3. Private state storage and retrieval
//! 4. RPC filtering for unauthorized callers
//! 5. Full EVM execution with privacy-aware database
//!
//! Note: These tests run the privacy layer components in isolation (without a full node).
//! For full E2E tests with flashblocks, see `crates/rpc/tests/`.

use std::sync::Arc;

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use base_reth_privacy::{
    PrivacyDatabase, PrivacyRegistry, PrivateStateStore,
    executor::{PrivateTransactionExecutor, ExecutorError},
    inspector::SlotKeyCache,
    nonce::PrivateNonceManager,
    registry::{PrivateContractConfig, OwnershipType, SlotConfig, SlotType},
    rpc::PrivacyRpcFilter,
    shielded::ShieldedKeyManager,
    store::{AuthEntry, READ},
    transaction::PrivateTransaction,
    mode::PrivacyMode,
};
use revm::database_interface::{Database, DatabaseRef};
use revm::DatabaseCommit;

// Helper to create a test address
fn test_address(n: u8) -> Address {
    Address::new([n; 20])
}

// Helper to compute a mapping slot like Solidity does
// keccak256(abi.encode(key, base_slot))
fn compute_mapping_slot(key: Address, base_slot: U256) -> U256 {
    let mut data = [0u8; 64];
    data[12..32].copy_from_slice(key.as_slice());
    data[32..64].copy_from_slice(&base_slot.to_be_bytes::<32>());
    let hash = keccak256(&data);
    U256::from_be_bytes(hash.0)
}

// Helper to extract the key from a computed slot using the cache
fn key_from_data(data: &[u8; 64]) -> B256 {
    B256::from_slice(&data[0..32])
}

/// Mock database for testing - stores account/storage in memory
#[derive(Default, Clone)]
struct MockDatabase {
    storage: std::collections::HashMap<(Address, U256), U256>,
}

impl Database for MockDatabase {
    type Error = std::convert::Infallible;

    fn basic(
        &mut self,
        _address: Address,
    ) -> Result<Option<revm::state::AccountInfo>, Self::Error> {
        Ok(Some(revm::state::AccountInfo::default()))
    }

    fn code_by_hash(
        &mut self,
        _code_hash: B256,
    ) -> Result<revm::bytecode::Bytecode, Self::Error> {
        Ok(revm::bytecode::Bytecode::default())
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(self.storage.get(&(address, index)).copied().unwrap_or(U256::ZERO))
    }

    fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}

impl DatabaseRef for MockDatabase {
    type Error = std::convert::Infallible;

    fn basic_ref(
        &self,
        _address: Address,
    ) -> Result<Option<revm::state::AccountInfo>, Self::Error> {
        Ok(Some(revm::state::AccountInfo::default()))
    }

    fn code_by_hash_ref(
        &self,
        _code_hash: B256,
    ) -> Result<revm::bytecode::Bytecode, Self::Error> {
        Ok(revm::bytecode::Bytecode::default())
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(self.storage.get(&(address, index)).copied().unwrap_or(U256::ZERO))
    }

    fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}

// Helper to create a private contract config
fn create_config(contract: Address, admin: Address, slots: Vec<SlotConfig>, hide_events: bool) -> PrivateContractConfig {
    PrivateContractConfig {
        address: contract,
        admin,
        slots,
        registered_at: 0,
        hide_events,
    }
}

// ============================================================================
// Registry Tests
// ============================================================================

#[test]
fn test_register_contract_with_mapping_slot() {
    let registry = PrivacyRegistry::new();
    let contract = test_address(1);
    let admin = test_address(2);

    // Configure a mapping slot at base slot 1 with MappingKey ownership
    let config = create_config(
        contract,
        admin,
        vec![SlotConfig {
            base_slot: U256::from(1),
            slot_type: SlotType::Mapping,
            ownership: OwnershipType::MappingKey,
        }],
        false,
    );

    registry.register(config).unwrap();

    assert!(registry.is_registered(&contract));
    assert!(!registry.is_registered(&test_address(99))); // Not registered
}

#[test]
fn test_slot_owner_tracking() {
    let registry = PrivacyRegistry::new();
    let contract = test_address(1);
    let admin = test_address(2);
    let user = test_address(10);

    // Register contract with mapping slot
    let config = create_config(
        contract,
        admin,
        vec![SlotConfig {
            base_slot: U256::from(1),
            slot_type: SlotType::Mapping,
            ownership: OwnershipType::MappingKey,
        }],
        false,
    );
    registry.register(config).unwrap();

    // Compute the slot for user's balance
    let computed_slot = compute_mapping_slot(user, U256::from(1));

    // Record the owner
    registry.record_slot_owner(contract, computed_slot, user);

    // Verify we can look up the owner
    let owner = registry.get_slot_owner(contract, computed_slot);
    assert_eq!(owner, Some(user));
}

// ============================================================================
// Private Store Tests
// ============================================================================

#[test]
fn test_private_store_set_and_get() {
    let store = PrivateStateStore::new();
    let contract = test_address(1);
    let slot = U256::from(42);
    let value = U256::from(12345);
    let owner = test_address(10);

    store.set(contract, slot, value, owner);

    // Get returns the value
    let retrieved = store.get(contract, slot);
    assert_eq!(retrieved, value);
}

#[test]
fn test_private_store_authorization() {
    let store = PrivateStateStore::new();
    let contract = test_address(1);
    let slot = U256::from(42);
    let owner = test_address(10);
    let delegate = test_address(20);
    let value = U256::from(12345);

    // First set a value with owner
    store.set(contract, slot, value, owner);

    // Owner is always authorized (has owner entry)
    assert!(store.is_authorized(contract, slot, owner, READ));

    // Delegate is not authorized initially
    assert!(!store.is_authorized(contract, slot, delegate, READ));

    // Grant read access to delegate
    store.authorize(contract, slot, delegate, AuthEntry::new(READ, 0, 0));

    // Now delegate is authorized
    assert!(store.is_authorized(contract, slot, delegate, READ));
}

// ============================================================================
// Privacy Database Integration Tests
// ============================================================================

#[test]
fn test_privacy_database_public_slot_passthrough() {
    let mock_db = MockDatabase::default();
    let registry = Arc::new(PrivacyRegistry::new());
    let store = Arc::new(PrivateStateStore::new());

    let mut privacy_db = PrivacyDatabase::new(mock_db.clone(), registry, store);

    let contract = test_address(1);
    let slot = U256::from(0);

    // Contract is not registered, so all slots are public (passthrough)
    let value = privacy_db.storage(contract, slot).unwrap();
    assert_eq!(value, U256::ZERO); // Mock returns ZERO for unset slots
}

#[test]
fn test_privacy_database_with_slot_key_cache() {
    let mut mock_db = MockDatabase::default();
    let registry = Arc::new(PrivacyRegistry::new());
    let store = Arc::new(PrivateStateStore::new());

    // Set up a value in the mock database
    let contract = test_address(1);
    let user = test_address(10);
    let base_slot = U256::from(1);
    let computed_slot = compute_mapping_slot(user, base_slot);
    let value = U256::from(1000);

    mock_db.storage.insert((contract, computed_slot), value);

    // Register the contract with a mapping slot
    let admin = test_address(2);
    let config = create_config(
        contract,
        admin,
        vec![SlotConfig {
            base_slot,
            slot_type: SlotType::Mapping,
            ownership: OwnershipType::MappingKey,
        }],
        false,
    );
    registry.register(config).unwrap();

    // Create the slot key cache and populate it (simulating inspector behavior)
    let cache = Arc::new(SlotKeyCache::new());
    let mut data = [0u8; 64];
    data[12..32].copy_from_slice(user.as_slice());
    data[32..64].copy_from_slice(&base_slot.to_be_bytes::<32>());
    let key = key_from_data(&data);
    cache.insert(contract, computed_slot, base_slot, key);

    // Create privacy database with the cache
    let mut privacy_db = PrivacyDatabase::new(mock_db, Arc::clone(&registry), Arc::clone(&store));
    privacy_db.set_slot_key_cache(cache);
    privacy_db.set_tx_sender(user); // User is the transaction sender

    // The slot should be classified as private (mapping slot with registered contract)
    // When we read, it should work because we haven't committed yet (reads go to inner db)
    let read_value = privacy_db.storage(contract, computed_slot).unwrap();
    assert_eq!(read_value, value);
}

// ============================================================================
// RPC Privacy Filter Tests
// ============================================================================

#[test]
fn test_rpc_filter_allows_public_slots() {
    let registry = Arc::new(PrivacyRegistry::new());
    let store = Arc::new(PrivateStateStore::new());
    let filter = PrivacyRpcFilter::new(Some(registry), Some(store));

    let contract = test_address(1);
    let slot = U256::from(0);
    let caller = Some(test_address(10));
    let value = B256::from(U256::from(12345));

    // Contract not registered - all slots are public
    let filtered = filter.filter_storage(contract, slot, value, caller);
    assert_eq!(filtered, value);
}

#[test]
fn test_rpc_filter_hides_unauthorized_private_slots() {
    let registry = Arc::new(PrivacyRegistry::new());
    let store = Arc::new(PrivateStateStore::new());

    // Register a contract with a simple private slot
    let contract = test_address(1);
    let admin = test_address(2);
    let owner = test_address(10);
    let unauthorized = test_address(99);

    let slot = U256::from(5);
    let value = B256::from(U256::from(12345));

    let config = create_config(
        contract,
        admin,
        vec![SlotConfig {
            base_slot: slot,
            slot_type: SlotType::Simple,
            ownership: OwnershipType::FixedOwner(owner),
        }],
        false,
    );
    registry.register(config).unwrap();

    // Store the private value
    store.set(contract, slot, U256::from(12345), owner);

    let filter = PrivacyRpcFilter::new(Some(Arc::clone(&registry)), Some(Arc::clone(&store)));

    // Owner can see the value
    let filtered_for_owner = filter.filter_storage(contract, slot, value, Some(owner));
    assert_eq!(filtered_for_owner, value);

    // Admin can see the value (admin check depends on how classify_slot works)
    // Note: The admin check is in is_caller_authorized but may not be implemented
    // For now, test that owner works

    // Unauthorized user sees zero
    let filtered_for_unauthorized = filter.filter_storage(contract, slot, value, Some(unauthorized));
    assert_eq!(filtered_for_unauthorized, B256::ZERO);
}

#[test]
fn test_rpc_filter_with_delegated_access() {
    let registry = Arc::new(PrivacyRegistry::new());
    let store = Arc::new(PrivateStateStore::new());

    // Register a contract with a private slot
    let contract = test_address(1);
    let admin = test_address(2);
    let owner = test_address(10);
    let delegate = test_address(20);

    let slot = U256::from(5);
    let value = B256::from(U256::from(12345));

    let config = create_config(
        contract,
        admin,
        vec![SlotConfig {
            base_slot: slot,
            slot_type: SlotType::Simple,
            ownership: OwnershipType::FixedOwner(owner),
        }],
        false,
    );
    registry.register(config).unwrap();

    // Store the private value
    store.set(contract, slot, U256::from(12345), owner);

    let filter = PrivacyRpcFilter::new(Some(Arc::clone(&registry)), Some(Arc::clone(&store)));

    // Delegate cannot see the value initially
    let filtered = filter.filter_storage(contract, slot, value, Some(delegate));
    assert_eq!(filtered, B256::ZERO);

    // Grant read access to delegate
    store.authorize(contract, slot, delegate, AuthEntry::new(READ, 0, 0));

    // Now delegate can see the value
    let filtered = filter.filter_storage(contract, slot, value, Some(delegate));
    assert_eq!(filtered, value);
}

// ============================================================================
// Inspector Slot Key Cache Tests
// ============================================================================

#[test]
fn test_slot_key_cache_mapping_lookup() {
    let cache = SlotKeyCache::new();

    let contract = test_address(1);
    let user = test_address(10);
    let base_slot = U256::from(1);

    // Compute the slot as the inspector would
    let computed_slot = compute_mapping_slot(user, base_slot);

    // Build the key (first 32 bytes of input to keccak)
    let mut data = [0u8; 64];
    data[12..32].copy_from_slice(user.as_slice());
    data[32..64].copy_from_slice(&base_slot.to_be_bytes::<32>());
    let key = B256::from_slice(&data[0..32]);

    // Insert into cache
    cache.insert(contract, computed_slot, base_slot, key);

    // Look it up
    let result = cache.get(contract, computed_slot);
    assert!(result.is_some());

    let (retrieved_base, retrieved_key) = result.unwrap();
    assert_eq!(retrieved_base, base_slot);
    assert_eq!(retrieved_key, key);

    // Extract the address from the key
    let extracted_address = Address::from_slice(&retrieved_key[12..32]);
    assert_eq!(extracted_address, user);
}

#[test]
fn test_slot_key_cache_nested_mapping() {
    let cache = SlotKeyCache::new();

    let contract = test_address(1);
    let owner = test_address(10);
    let spender = test_address(20);
    let base_slot = U256::from(2); // allowances mapping at slot 2

    // First level: keccak256(abi.encode(owner, base_slot))
    let slot1 = compute_mapping_slot(owner, base_slot);

    // Second level: keccak256(abi.encode(spender, slot1))
    let slot2 = compute_mapping_slot(spender, slot1);

    // Build keys
    let mut data1 = [0u8; 64];
    data1[12..32].copy_from_slice(owner.as_slice());
    data1[32..64].copy_from_slice(&base_slot.to_be_bytes::<32>());
    let key1 = B256::from_slice(&data1[0..32]);

    let mut data2 = [0u8; 64];
    data2[12..32].copy_from_slice(spender.as_slice());
    data2[32..64].copy_from_slice(&slot1.to_be_bytes::<32>());
    let key2 = B256::from_slice(&data2[0..32]);

    // Insert both levels
    cache.insert(contract, slot1, base_slot, key1);
    cache.insert(contract, slot2, slot1, key2);

    // Look up second level
    let result = cache.get(contract, slot2);
    assert!(result.is_some());

    let (retrieved_base, retrieved_key) = result.unwrap();
    // The base is the first level slot
    assert_eq!(retrieved_base, slot1);
    // The key contains the spender
    let extracted_spender = Address::from_slice(&retrieved_key[12..32]);
    assert_eq!(extracted_spender, spender);

    // Can trace back to get the owner from slot1
    let result1 = cache.get(contract, slot1);
    assert!(result1.is_some());
    let (_, key1_retrieved) = result1.unwrap();
    let extracted_owner = Address::from_slice(&key1_retrieved[12..32]);
    assert_eq!(extracted_owner, owner);
}

// ============================================================================
// Event Filtering Tests
// ============================================================================

// Helper to create a test log compatible with RPC types
fn create_test_log(address: Address, data: U256) -> alloy_rpc_types_eth::Log {
    alloy_rpc_types_eth::Log {
        inner: alloy_primitives::Log {
            address,
            data: alloy_primitives::LogData::new_unchecked(
                vec![],
                Bytes::from(data.to_be_bytes::<32>().to_vec()),
            ),
        },
        block_hash: Some(B256::ZERO),
        block_number: Some(1),
        block_timestamp: None,
        transaction_hash: Some(B256::ZERO),
        transaction_index: Some(0),
        log_index: Some(0),
        removed: false,
    }
}

#[test]
fn test_event_filtering_hide_events() {
    let registry = Arc::new(PrivacyRegistry::new());
    let store = Arc::new(PrivateStateStore::new());

    // Register a contract with hide_events = true
    let contract = test_address(1);
    let admin = test_address(2);

    let config = create_config(contract, admin, vec![], true);
    registry.register(config).unwrap();

    let filter = PrivacyRpcFilter::new(Some(Arc::clone(&registry)), Some(store));

    // Create a test log from the private contract
    let log = create_test_log(contract, U256::from(100));

    // Admin can see the log
    let filtered = filter.filter_logs(vec![log.clone()], Some(admin));
    assert_eq!(filtered.len(), 1);

    // Random user cannot see the log
    let unauthorized = test_address(99);
    let filtered = filter.filter_logs(vec![log.clone()], Some(unauthorized));
    assert_eq!(filtered.len(), 0);
}

#[test]
fn test_event_filtering_public_contract() {
    let registry = Arc::new(PrivacyRegistry::new());
    let store = Arc::new(PrivateStateStore::new());

    // Register a contract with hide_events = false
    let contract = test_address(1);
    let admin = test_address(2);

    let config = create_config(contract, admin, vec![], false);
    registry.register(config).unwrap();

    let filter = PrivacyRpcFilter::new(Some(Arc::clone(&registry)), Some(store));

    // Create a test log
    let log = create_test_log(contract, U256::from(100));

    // Anyone can see the log when hide_events is false
    let unauthorized = test_address(99);
    let filtered = filter.filter_logs(vec![log], Some(unauthorized));
    assert_eq!(filtered.len(), 1);
}

// ============================================================================
// Executor Integration Tests
// ============================================================================

/// Mock database that supports commit operations for executor tests.
#[derive(Default, Clone, Debug)]
struct MockCommitDatabase {
    storage: std::collections::HashMap<(Address, U256), U256>,
    code: std::collections::HashMap<Address, revm::bytecode::Bytecode>,
}

impl MockCommitDatabase {
    fn with_contract(mut self, address: Address, bytecode: revm::bytecode::Bytecode) -> Self {
        self.code.insert(address, bytecode);
        self
    }
}

impl Database for MockCommitDatabase {
    type Error = std::convert::Infallible;

    fn basic(
        &mut self,
        address: Address,
    ) -> Result<Option<revm::state::AccountInfo>, Self::Error> {
        // Return account info with code if we have it
        if let Some(code) = self.code.get(&address) {
            Ok(Some(revm::state::AccountInfo {
                balance: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
                nonce: 0,
                code_hash: code.hash_slow(),
                code: Some(code.clone()),
            }))
        } else {
            Ok(Some(revm::state::AccountInfo::default()))
        }
    }

    fn code_by_hash(
        &mut self,
        code_hash: B256,
    ) -> Result<revm::bytecode::Bytecode, Self::Error> {
        // Find code by hash
        for code in self.code.values() {
            if code.hash_slow() == code_hash {
                return Ok(code.clone());
            }
        }
        Ok(revm::bytecode::Bytecode::default())
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(self.storage.get(&(address, index)).copied().unwrap_or(U256::ZERO))
    }

    fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}

impl DatabaseRef for MockCommitDatabase {
    type Error = std::convert::Infallible;

    fn basic_ref(
        &self,
        address: Address,
    ) -> Result<Option<revm::state::AccountInfo>, Self::Error> {
        if let Some(code) = self.code.get(&address) {
            Ok(Some(revm::state::AccountInfo {
                balance: U256::from(1_000_000_000_000_000_000u128),
                nonce: 0,
                code_hash: code.hash_slow(),
                code: Some(code.clone()),
            }))
        } else {
            Ok(Some(revm::state::AccountInfo::default()))
        }
    }

    fn code_by_hash_ref(
        &self,
        code_hash: B256,
    ) -> Result<revm::bytecode::Bytecode, Self::Error> {
        for code in self.code.values() {
            if code.hash_slow() == code_hash {
                return Ok(code.clone());
            }
        }
        Ok(revm::bytecode::Bytecode::default())
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(self.storage.get(&(address, index)).copied().unwrap_or(U256::ZERO))
    }

    fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}

impl DatabaseCommit for MockCommitDatabase {
    fn commit(&mut self, changes: revm::primitives::HashMap<Address, revm::state::Account>) {
        for (address, account) in changes {
            for (slot, value) in account.storage {
                if value.present_value != value.original_value {
                    self.storage.insert((address, slot), value.present_value);
                }
            }
        }
    }
}

// Test private key - Foundry's default test account #0
// Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
// Key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
const TEST_PRIVATE_KEY: [u8; 32] = [
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3,
    0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc,
    0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
];

fn test_user_address() -> Address {
    alloy_primitives::address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
}

fn create_signed_tx(
    from: Address,
    to: Address,
    data: Bytes,
    mode: PrivacyMode,
    nonce: u64,
) -> PrivateTransaction {
    let tx = PrivateTransaction::new(from, to, data, 1_000_000, nonce, mode, 84532);
    tx.sign(&TEST_PRIVATE_KEY).expect("signing should succeed")
}

fn create_test_executor() -> (
    PrivateTransactionExecutor,
    Arc<PrivacyRegistry>,
    Arc<PrivateStateStore>,
    Arc<PrivateNonceManager>,
) {
    let nonce_manager = Arc::new(PrivateNonceManager::new());
    let shielded_manager = Arc::new(ShieldedKeyManager::new(84532));
    let registry = Arc::new(PrivacyRegistry::new());
    let store = Arc::new(PrivateStateStore::new());

    let executor = PrivateTransactionExecutor::new(
        Arc::clone(&nonce_manager),
        shielded_manager,
        Arc::clone(&registry),
        Arc::clone(&store),
        84532,
    );

    (executor, registry, store, nonce_manager)
}

fn test_block_env() -> revm::context::BlockEnv {
    revm::context::BlockEnv {
        number: U256::from(1),
        timestamp: U256::from(1704067200), // 2024-01-01
        gas_limit: 30_000_000,
        beneficiary: Address::ZERO,
        ..Default::default()
    }
}

/// Create bytecode that stores a value at a given slot.
/// Bytecode: PUSH32 value, PUSH32 slot, SSTORE, STOP
fn sstore_bytecode(slot: U256, value: U256) -> revm::bytecode::Bytecode {
    let mut code = Vec::new();

    // PUSH32 value
    code.push(0x7f);
    code.extend_from_slice(&value.to_be_bytes::<32>());

    // PUSH32 slot
    code.push(0x7f);
    code.extend_from_slice(&slot.to_be_bytes::<32>());

    // SSTORE
    code.push(0x55);

    // STOP
    code.push(0x00);

    revm::bytecode::Bytecode::new_raw(Bytes::from(code))
}

#[test]
fn test_executor_validate_signed_transaction() {
    let (executor, _, _, _) = create_test_executor();

    let tx = create_signed_tx(
        test_user_address(),
        test_address(1),
        Bytes::new(),
        PrivacyMode::Real,
        0,
    );

    // Validation should succeed
    let result = executor.validate(&tx);
    assert!(result.is_ok(), "validation failed: {:?}", result.err());
}

#[test]
fn test_executor_validate_wrong_nonce() {
    let (executor, _, _, _) = create_test_executor();

    // Create tx with nonce 5 when expected is 0
    let tx = create_signed_tx(
        test_user_address(),
        test_address(1),
        Bytes::new(),
        PrivacyMode::Real,
        5, // Wrong nonce
    );

    let result = executor.validate(&tx);
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert!(
        matches!(err, ExecutorError::Nonce(_)),
        "expected Nonce error, got: {:?}",
        err
    );
}

#[test]
fn test_executor_validate_wrong_chain_id() {
    let (executor, _, _, _) = create_test_executor();

    // Create tx with wrong chain ID
    let tx = PrivateTransaction::new(
        test_user_address(),
        test_address(1),
        Bytes::new(),
        1_000_000,
        0,
        PrivacyMode::Real,
        1, // Wrong chain ID (expected 84532)
    );
    let signed = tx.sign(&TEST_PRIVATE_KEY).unwrap();

    let result = executor.validate(&signed);
    assert!(result.is_err());

    let err = result.unwrap_err();
    // The error should be a ChainIdMismatch - check the error type directly
    assert!(
        matches!(err, ExecutorError::ChainIdMismatch { .. }),
        "expected ChainIdMismatch error, got: {:?}",
        err
    );
}

#[test]
fn test_executor_effective_sender_real_mode() {
    let (executor, _, _, _) = create_test_executor();

    let tx = create_signed_tx(
        test_user_address(),
        test_address(1),
        Bytes::new(),
        PrivacyMode::Real,
        0,
    );

    let sender = executor.resolve_effective_sender(&tx);
    assert_eq!(sender, test_user_address());
}

#[test]
fn test_executor_effective_sender_shielded_mode() {
    let (executor, _, _, _) = create_test_executor();

    let tx = create_signed_tx(
        test_user_address(),
        test_address(1),
        Bytes::new(),
        PrivacyMode::Shielded {
            protocol: test_address(1),
            index: 0,
        },
        0,
    );

    let sender = executor.resolve_effective_sender(&tx);

    // Shielded mode should give a different address
    assert_ne!(sender, test_user_address());
    assert!(!sender.is_zero());
}

#[test]
fn test_executor_nonce_increment_on_prepare() {
    let (executor, _, _, nonce_manager) = create_test_executor();

    // Initial nonce should be 0
    assert_eq!(nonce_manager.get_nonce(test_user_address()), 0);

    let tx = create_signed_tx(
        test_user_address(),
        test_address(1),
        Bytes::new(),
        PrivacyMode::Real,
        0,
    );

    // Prepare execution (which uses the nonce)
    let result = executor.prepare_execution(&tx);
    assert!(result.is_ok());

    // Nonce should be incremented
    assert_eq!(nonce_manager.get_nonce(test_user_address()), 1);
}

#[test]
fn test_execute_private_tx_simple_call() {
    let (executor, _, store, _) = create_test_executor();

    let contract = test_address(100);
    let slot = U256::from(42);
    let value = U256::from(12345);

    // Create bytecode that stores value at slot
    let bytecode = sstore_bytecode(slot, value);
    let db = MockCommitDatabase::default().with_contract(contract, bytecode);

    let tx = create_signed_tx(
        test_user_address(),
        contract,
        Bytes::new(), // No calldata needed, contract just runs
        PrivacyMode::Real,
        0,
    );

    let result = executor.execute_private_tx(&tx, db, test_block_env(), op_revm::OpSpecId::CANYON);

    assert!(result.is_ok(), "execution failed: {:?}", result.err());

    let exec_result = result.unwrap();
    assert!(exec_result.success);
    assert_eq!(exec_result.effective_sender, test_user_address());
    assert_eq!(exec_result.real_sender, test_user_address());

    // Contract is not registered, so this is a public write
    assert!(exec_result.public_write_occurred);
    assert!(exec_result.block_transaction.is_some());

    // Value should NOT be in private store (public write)
    assert_eq!(store.get(contract, slot), U256::ZERO);
}

#[test]
fn test_execute_private_tx_private_slot_write() {
    let (executor, registry, store, _) = create_test_executor();

    let contract = test_address(100);
    let slot = U256::from(5);
    let value = U256::from(99999);

    // Register contract with private slot
    let config = create_config(
        contract,
        test_user_address(),
        vec![SlotConfig {
            base_slot: slot,
            slot_type: SlotType::Simple,
            ownership: OwnershipType::Contract,
        }],
        false,
    );
    registry.register(config).unwrap();

    // Create bytecode that stores value at the private slot
    let bytecode = sstore_bytecode(slot, value);
    let db = MockCommitDatabase::default().with_contract(contract, bytecode);

    let tx = create_signed_tx(
        test_user_address(),
        contract,
        Bytes::new(),
        PrivacyMode::Real,
        0,
    );

    let result = executor.execute_private_tx(&tx, db, test_block_env(), op_revm::OpSpecId::CANYON);

    assert!(result.is_ok(), "execution failed: {:?}", result.err());

    let exec_result = result.unwrap();
    assert!(exec_result.success);

    // Private slot write should NOT trigger block transaction
    assert!(!exec_result.public_write_occurred);
    assert!(exec_result.block_transaction.is_none());

    // Value SHOULD be in private store
    assert_eq!(store.get(contract, slot), value);
}

#[test]
fn test_execute_private_tx_shielded_mode() {
    let (executor, _, _, _) = create_test_executor();

    let contract = test_address(100);
    let slot = U256::from(42);
    let value = U256::from(12345);

    let bytecode = sstore_bytecode(slot, value);
    let db = MockCommitDatabase::default().with_contract(contract, bytecode);

    let tx = create_signed_tx(
        test_user_address(),
        contract,
        Bytes::new(),
        PrivacyMode::Shielded {
            protocol: contract,
            index: 0,
        },
        0,
    );

    let result = executor.execute_private_tx(&tx, db, test_block_env(), op_revm::OpSpecId::CANYON);

    assert!(result.is_ok(), "execution failed: {:?}", result.err());

    let exec_result = result.unwrap();
    assert!(exec_result.success);

    // Effective sender should be shielded address
    assert_ne!(exec_result.effective_sender, test_user_address());
    assert_eq!(exec_result.real_sender, test_user_address());

    // Public write occurred (unregistered contract)
    assert!(exec_result.public_write_occurred);

    // Block transaction should be from shielded address
    let block_tx = exec_result.block_transaction.unwrap();
    assert_eq!(block_tx.from, exec_result.effective_sender);

    // Signature should be valid for shielded address
    let recovered = block_tx
        .signature
        .recover_address_from_prehash(&block_tx.tx_hash)
        .unwrap();
    assert_eq!(recovered, exec_result.effective_sender);
}
