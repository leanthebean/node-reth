//! Integration tests covering the Privacy RPC surface area.

use std::{any::Any, net::SocketAddr, sync::Arc};

use alloy_primitives::{Address, U256};
use alloy_rpc_client::RpcClient;
use base_reth_privacy::{
    PrivacyRegistry, PrivateNonceManager, PrivateStateStore, ShieldedKeyManager,
};
use base_reth_rpc::{PrivacyApiImpl, PrivacyApiServer};
use base_reth_test_utils::{init_silenced_tracing, load_genesis};
use reth::{
    args::{DiscoveryArgs, NetworkArgs, RpcServerArgs},
    builder::{Node, NodeBuilder, NodeConfig, NodeHandle},
    chainspec::Chain,
    core::exit::NodeExitFuture,
    tasks::TaskManager,
};
use reth_optimism_chainspec::OpChainSpecBuilder;
use reth_optimism_node::{OpNode, args::RollupArgs};
use reth_provider::providers::BlockchainProvider;

const BASE_SEPOLIA_CHAIN_ID: u64 = 84532;

struct NodeContext {
    http_api_addr: SocketAddr,
    _node_exit_future: NodeExitFuture,
    _node: Box<dyn Any + Sync + Send>,
}

impl NodeContext {
    async fn rpc_client(&self) -> eyre::Result<RpcClient> {
        let url = format!("http://{}", self.http_api_addr);
        let client = RpcClient::new_http(url.parse()?);
        Ok(client)
    }
}

async fn setup_node() -> eyre::Result<NodeContext> {
    init_silenced_tracing();
    let tasks = TaskManager::current();
    let exec = tasks.executor();

    let genesis = load_genesis();
    let chain_spec = Arc::new(
        OpChainSpecBuilder::base_mainnet()
            .genesis(genesis)
            .ecotone_activated()
            .chain(Chain::from(BASE_SEPOLIA_CHAIN_ID))
            .build(),
    );

    let network_config = NetworkArgs {
        discovery: DiscoveryArgs { disable_discovery: true, ..DiscoveryArgs::default() },
        ..NetworkArgs::default()
    };

    let node_config = NodeConfig::new(chain_spec.clone())
        .with_network(network_config.clone())
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http())
        .with_unused_ports();

    let node = OpNode::new(RollupArgs::default());

    // Create privacy components
    let nonce_manager = Arc::new(PrivateNonceManager::new());
    let shielded_manager = Arc::new(ShieldedKeyManager::new(BASE_SEPOLIA_CHAIN_ID));
    let registry = Arc::new(PrivacyRegistry::new());
    let store = Arc::new(PrivateStateStore::new());

    // Clone for the closure
    let nm = nonce_manager.clone();
    let sm = shielded_manager.clone();
    let reg = registry.clone();
    let st = store.clone();

    let NodeHandle { node, node_exit_future } = NodeBuilder::new(node_config.clone())
        .testing_node(exec.clone())
        .with_types_and_provider::<OpNode, BlockchainProvider<_>>()
        .with_components(node.components_builder())
        .with_add_ons(node.add_ons())
        .extend_rpc_modules(move |ctx| {
            let privacy_api = PrivacyApiImpl::new(
                ctx.provider().clone(),
                nm.clone(),
                sm.clone(),
                reg.clone(),
                st.clone(),
                BASE_SEPOLIA_CHAIN_ID,
            );
            ctx.modules.merge_configured(privacy_api.into_rpc())?;
            Ok(())
        })
        .launch()
        .await?;

    let http_api_addr = node
        .rpc_server_handle()
        .http_local_addr()
        .ok_or_else(|| eyre::eyre!("Failed to get http api address"))?;

    Ok(NodeContext { http_api_addr, _node_exit_future: node_exit_future, _node: Box::new(node) })
}

// =============================================================================
// priv_getPrivateNonce Tests
// =============================================================================

#[tokio::test]
async fn test_get_private_nonce_new_address() -> eyre::Result<()> {
    let node = setup_node().await?;
    let client = node.rpc_client().await?;

    // A random address should have nonce 0
    let addr = Address::random();
    let nonce: U256 = client.request("priv_getPrivateNonce", (addr,)).await?;

    assert_eq!(nonce, U256::ZERO);
    Ok(())
}

#[tokio::test]
async fn test_get_private_nonce_consistent() -> eyre::Result<()> {
    let node = setup_node().await?;
    let client = node.rpc_client().await?;

    // Same address should return consistent results
    let addr = Address::repeat_byte(0x42);

    let nonce1: U256 = client.request("priv_getPrivateNonce", (addr,)).await?;
    let nonce2: U256 = client.request("priv_getPrivateNonce", (addr,)).await?;

    assert_eq!(nonce1, nonce2);
    Ok(())
}

// =============================================================================
// priv_getShieldedAddress Tests
// =============================================================================

#[tokio::test]
async fn test_get_shielded_address_deterministic() -> eyre::Result<()> {
    let node = setup_node().await?;
    let client = node.rpc_client().await?;

    let user = Address::repeat_byte(0x11);
    let protocol = Address::repeat_byte(0x22);

    // Same inputs should produce same output
    let addr1: Address = client
        .request("priv_getShieldedAddress", (user, protocol, 0u64))
        .await?;
    let addr2: Address = client
        .request("priv_getShieldedAddress", (user, protocol, 0u64))
        .await?;

    assert_eq!(addr1, addr2);
    Ok(())
}

#[tokio::test]
async fn test_get_shielded_address_different_index() -> eyre::Result<()> {
    let node = setup_node().await?;
    let client = node.rpc_client().await?;

    let user = Address::repeat_byte(0x11);
    let protocol = Address::repeat_byte(0x22);

    // Different index should produce different address
    let addr0: Address = client
        .request("priv_getShieldedAddress", (user, protocol, 0u64))
        .await?;
    let addr1: Address = client
        .request("priv_getShieldedAddress", (user, protocol, 1u64))
        .await?;
    let addr2: Address = client
        .request("priv_getShieldedAddress", (user, protocol, 2u64))
        .await?;

    assert_ne!(addr0, addr1);
    assert_ne!(addr1, addr2);
    assert_ne!(addr0, addr2);
    Ok(())
}

#[tokio::test]
async fn test_get_shielded_address_different_protocol() -> eyre::Result<()> {
    let node = setup_node().await?;
    let client = node.rpc_client().await?;

    let user = Address::repeat_byte(0x11);
    let protocol1 = Address::repeat_byte(0x22);
    let protocol2 = Address::repeat_byte(0x33);

    // Different protocol should produce different address
    let addr1: Address = client
        .request("priv_getShieldedAddress", (user, protocol1, 0u64))
        .await?;
    let addr2: Address = client
        .request("priv_getShieldedAddress", (user, protocol2, 0u64))
        .await?;

    assert_ne!(addr1, addr2);
    Ok(())
}

#[tokio::test]
async fn test_get_shielded_address_different_user() -> eyre::Result<()> {
    let node = setup_node().await?;
    let client = node.rpc_client().await?;

    let user1 = Address::repeat_byte(0x11);
    let user2 = Address::repeat_byte(0x12);
    let protocol = Address::repeat_byte(0x22);

    // Different user should produce different address
    let addr1: Address = client
        .request("priv_getShieldedAddress", (user1, protocol, 0u64))
        .await?;
    let addr2: Address = client
        .request("priv_getShieldedAddress", (user2, protocol, 0u64))
        .await?;

    assert_ne!(addr1, addr2);
    Ok(())
}

// =============================================================================
// priv_getPrivateStorage Tests
// =============================================================================

#[tokio::test]
async fn test_get_private_storage_unauthorized() -> eyre::Result<()> {
    let node = setup_node().await?;
    let client = node.rpc_client().await?;

    // Without any registration or authorization, should return zero
    let contract = Address::random();
    let slot = U256::from(1);
    let caller = Address::random();

    let value: U256 = client
        .request("priv_getPrivateStorage", (contract, slot, caller))
        .await?;

    assert_eq!(value, U256::ZERO);
    Ok(())
}

#[tokio::test]
async fn test_get_private_storage_nonexistent_slot() -> eyre::Result<()> {
    let node = setup_node().await?;
    let client = node.rpc_client().await?;

    // A slot that was never written to should return zero
    let contract = Address::repeat_byte(0xaa);
    let slot = U256::from(999);
    let caller = Address::repeat_byte(0xbb);

    let value: U256 = client
        .request("priv_getPrivateStorage", (contract, slot, caller))
        .await?;

    assert_eq!(value, U256::ZERO);
    Ok(())
}

// =============================================================================
// Error Handling Tests
// =============================================================================

#[tokio::test]
async fn test_rpc_methods_exist() -> eyre::Result<()> {
    let node = setup_node().await?;
    let client = node.rpc_client().await?;

    // Verify all RPC methods are registered and callable
    let addr = Address::ZERO;
    let slot = U256::ZERO;

    // These should all succeed (not return "method not found")
    let _: U256 = client.request("priv_getPrivateNonce", (addr,)).await?;
    let _: Address = client
        .request("priv_getShieldedAddress", (addr, addr, 0u64))
        .await?;
    let _: U256 = client
        .request("priv_getPrivateStorage", (addr, slot, addr))
        .await?;

    Ok(())
}
