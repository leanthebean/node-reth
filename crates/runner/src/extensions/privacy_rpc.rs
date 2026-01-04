//! Contains the [PrivacyRpcExtension] which wires up the privacy RPC modules on the node builder.

use std::sync::Arc;

use base_reth_privacy::{
    PrivacyRegistry, PrivateNonceManager, PrivateStateStore, ShieldedKeyManager,
};
use base_reth_rpc::{PrivacyApiImpl, PrivacyApiServer};
use once_cell::sync::OnceCell;
use tracing::info;

use crate::{
    BaseNodeConfig,
    extensions::{BaseNodeExtension, ConfigurableBaseNodeExtension, OpBuilder},
};

/// Cell for sharing the privacy registry across extensions.
pub type PrivacyRegistryCell = Arc<OnceCell<Arc<PrivacyRegistry>>>;
/// Cell for sharing the private state store across extensions.
pub type PrivateStoreCell = Arc<OnceCell<Arc<PrivateStateStore>>>;
/// Cell for sharing the private nonce manager across extensions.
pub type PrivateNonceCell = Arc<OnceCell<Arc<PrivateNonceManager>>>;
/// Cell for sharing the shielded key manager across extensions.
pub type ShieldedKeyCell = Arc<OnceCell<Arc<ShieldedKeyManager>>>;

/// Configuration for the privacy RPC extension.
#[derive(Debug, Clone)]
pub struct PrivacyRpcConfig {
    /// Whether privacy RPC is enabled.
    pub enabled: bool,
    /// Chain ID for the privacy layer.
    pub chain_id: u64,
}

/// Extension that wires the privacy RPC modules into the node builder.
#[derive(Debug, Clone)]
pub struct PrivacyRpcExtension {
    /// Configuration.
    config: PrivacyRpcConfig,
    /// Shared registry cell.
    registry_cell: PrivacyRegistryCell,
    /// Shared private store cell.
    store_cell: PrivateStoreCell,
    /// Shared nonce manager cell.
    nonce_cell: PrivateNonceCell,
    /// Shared shielded key manager cell.
    shielded_cell: ShieldedKeyCell,
}

impl PrivacyRpcExtension {
    /// Creates a new privacy RPC extension.
    pub fn new(config: PrivacyRpcConfig) -> Self {
        Self {
            config,
            registry_cell: Arc::new(OnceCell::new()),
            store_cell: Arc::new(OnceCell::new()),
            nonce_cell: Arc::new(OnceCell::new()),
            shielded_cell: Arc::new(OnceCell::new()),
        }
    }

    /// Creates a new extension with shared cells.
    ///
    /// Use this when the privacy components need to be shared with other parts
    /// of the system (e.g., the execution layer).
    pub fn with_cells(
        config: PrivacyRpcConfig,
        registry_cell: PrivacyRegistryCell,
        store_cell: PrivateStoreCell,
        nonce_cell: PrivateNonceCell,
        shielded_cell: ShieldedKeyCell,
    ) -> Self {
        Self {
            config,
            registry_cell,
            store_cell,
            nonce_cell,
            shielded_cell,
        }
    }

    /// Get or initialize the privacy registry.
    pub fn registry(&self) -> Arc<PrivacyRegistry> {
        self.registry_cell
            .get_or_init(|| Arc::new(PrivacyRegistry::new()))
            .clone()
    }

    /// Get or initialize the private store.
    pub fn store(&self) -> Arc<PrivateStateStore> {
        self.store_cell
            .get_or_init(|| Arc::new(PrivateStateStore::new()))
            .clone()
    }

    /// Get or initialize the nonce manager.
    pub fn nonce_manager(&self) -> Arc<PrivateNonceManager> {
        self.nonce_cell
            .get_or_init(|| Arc::new(PrivateNonceManager::new()))
            .clone()
    }

    /// Get or initialize the shielded key manager.
    pub fn shielded_manager(&self) -> Arc<ShieldedKeyManager> {
        let chain_id = self.config.chain_id;
        self.shielded_cell
            .get_or_init(|| Arc::new(ShieldedKeyManager::new(chain_id)))
            .clone()
    }
}

impl BaseNodeExtension for PrivacyRpcExtension {
    fn apply(&self, builder: OpBuilder) -> OpBuilder {
        if !self.config.enabled {
            info!(message = "Privacy RPC is disabled");
            return builder;
        }

        let registry = self.registry();
        let store = self.store();
        let nonce_manager = self.nonce_manager();
        let shielded_manager = self.shielded_manager();
        let chain_id = self.config.chain_id;

        builder.extend_rpc_modules(move |ctx| {
            info!(message = "Starting Privacy RPC");

            let privacy_api = PrivacyApiImpl::new(
                ctx.provider().clone(),
                nonce_manager.clone(),
                shielded_manager.clone(),
                registry.clone(),
                store.clone(),
                chain_id,
            );

            ctx.modules.merge_configured(privacy_api.into_rpc())?;

            info!(
                chain_id = chain_id,
                "Privacy RPC modules registered: priv_sendRawTransaction, priv_getPrivateNonce, priv_getShieldedAddress, priv_getPrivateStorage"
            );

            Ok(())
        })
    }
}

impl ConfigurableBaseNodeExtension for PrivacyRpcExtension {
    fn build(config: &BaseNodeConfig) -> eyre::Result<Self> {
        let privacy_config = match &config.privacy {
            Some(cfg) => PrivacyRpcConfig {
                enabled: true,
                chain_id: cfg.chain_id,
            },
            None => PrivacyRpcConfig {
                enabled: false,
                chain_id: 0, // Not used when disabled
            },
        };

        Ok(Self::new(privacy_config))
    }
}
