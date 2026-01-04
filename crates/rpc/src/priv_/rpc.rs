//! Privacy RPC implementation.

use alloy_consensus::Header;
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{Address, Bytes, U256};
use base_reth_privacy::{
    PrivacyRpcError, PrivacyRpcHandler, PrivateNonceManager, PrivateStateStore, PrivateTransactionExecutor,
    PrivacyRegistry, ShieldedKeyManager,
};
use jsonrpsee::core::{RpcResult, async_trait};
use op_revm::OpSpecId;
use reth::providers::BlockReaderIdExt;
use reth::revm::{State, database::StateProviderDatabase};
use reth_optimism_chainspec::OpChainSpec;
use reth_provider::{ChainSpecProvider, StateProvider, StateProviderFactory};
use revm::context::BlockEnv;
use std::sync::Arc;
use tracing::{debug, error, info};

use crate::priv_::{PrivacyApiServer, PrivateTransactionResult};

/// Implementation of the privacy RPC API.
#[derive(Debug)]
pub struct PrivacyApiImpl<Provider> {
    handler: Arc<PrivacyRpcHandler>,
    provider: Provider,
}

impl<Provider> PrivacyApiImpl<Provider>
where
    Provider: StateProviderFactory
        + ChainSpecProvider<ChainSpec = OpChainSpec>
        + BlockReaderIdExt<Header = Header>
        + Clone,
{
    /// Creates a new instance of PrivacyApiImpl.
    pub fn new(
        provider: Provider,
        nonce_manager: Arc<PrivateNonceManager>,
        shielded_manager: Arc<ShieldedKeyManager>,
        registry: Arc<PrivacyRegistry>,
        store: Arc<PrivateStateStore>,
        chain_id: u64,
    ) -> Self {
        let executor = Arc::new(PrivateTransactionExecutor::new(
            nonce_manager,
            shielded_manager,
            registry,
            store,
            chain_id,
        ));
        let handler = Arc::new(PrivacyRpcHandler::new(executor, OpSpecId::CANYON));
        Self { handler, provider }
    }

    /// Creates a new instance with an existing handler.
    pub fn with_handler(provider: Provider, handler: Arc<PrivacyRpcHandler>) -> Self {
        Self { handler, provider }
    }
}

/// Create block environment from header.
fn block_env_from_header(header: &Header) -> BlockEnv {
    BlockEnv {
        number: U256::from(header.number),
        beneficiary: header.beneficiary,
        timestamp: U256::from(header.timestamp),
        gas_limit: header.gas_limit,
        basefee: header.base_fee_per_gas.unwrap_or_default(),
        difficulty: header.difficulty,
        prevrandao: Some(header.mix_hash),
        ..Default::default()
    }
}

/// Wrap a state provider into a State<DB> suitable for execution.
fn wrap_state_provider<SP: StateProvider>(
    state_provider: SP,
) -> State<StateProviderDatabase<SP>> {
    let state_db = StateProviderDatabase::new(state_provider);
    State::builder().with_database(state_db).with_bundle_update().build()
}

#[async_trait]
impl<Provider> PrivacyApiServer for PrivacyApiImpl<Provider>
where
    Provider: StateProviderFactory
        + ChainSpecProvider<ChainSpec = OpChainSpec>
        + BlockReaderIdExt<Header = Header>
        + Clone
        + Send
        + Sync
        + 'static,
{
    async fn send_raw_transaction(&self, raw_tx: Bytes) -> RpcResult<PrivateTransactionResult> {
        info!(tx_len = raw_tx.len(), "Processing priv_sendRawTransaction");

        // Get the latest header
        let header = self
            .provider
            .sealed_header_by_number_or_tag(BlockNumberOrTag::Latest)
            .map_err(|e| {
                error!(error = %e, "Failed to get latest header");
                rpc_internal_error(format!("Failed to get latest header: {}", e))
            })?
            .ok_or_else(|| rpc_internal_error("Latest block not found".to_string()))?;

        debug!(
            block_number = header.number,
            block_hash = %header.hash(),
            "Got latest header for private transaction"
        );

        // Get state provider for the block
        let state_provider = self.provider.state_by_block_hash(header.hash()).map_err(|e| {
            error!(error = %e, "Failed to get state provider");
            rpc_internal_error(format!("Failed to get state provider: {}", e))
        })?;

        // Build block environment from header
        let block_env = block_env_from_header(&header);

        // Wrap state provider into a database suitable for execution
        let db = wrap_state_provider(state_provider);

        // Execute the private transaction
        let result = self
            .handler
            .send_raw_transaction(&raw_tx, db, block_env)
            .map_err(|e| {
                error!(error = %e, "Private transaction execution failed");
                convert_privacy_error(e)
            })?;

        info!(
            success = result.success,
            gas_used = result.gas_used,
            public_write = result.public_write_occurred,
            "Private transaction executed"
        );

        Ok(result.into())
    }

    async fn get_private_nonce(&self, address: Address) -> RpcResult<U256> {
        debug!(%address, "Processing priv_getPrivateNonce");
        let nonce = self.handler.get_private_nonce(address);
        Ok(U256::from(nonce))
    }

    async fn get_shielded_address(
        &self,
        user: Address,
        protocol: Address,
        index: u64,
    ) -> RpcResult<Address> {
        debug!(%user, %protocol, index, "Processing priv_getShieldedAddress");
        let shielded = self.handler.get_shielded_address(user, protocol, index);
        Ok(shielded)
    }

    async fn get_private_storage(
        &self,
        contract: Address,
        slot: U256,
        caller: Address,
    ) -> RpcResult<U256> {
        debug!(%contract, %slot, %caller, "Processing priv_getPrivateStorage");
        let value = self.handler.get_private_storage(contract, slot, caller);
        Ok(value)
    }
}

/// Convert a PrivacyRpcError to a JSON-RPC error.
fn convert_privacy_error(err: PrivacyRpcError) -> jsonrpsee::types::ErrorObjectOwned {
    use jsonrpsee::types::ErrorCode;

    match err {
        PrivacyRpcError::InvalidTransaction(msg) => jsonrpsee::types::ErrorObjectOwned::owned(
            ErrorCode::InvalidParams.code(),
            format!("Invalid transaction: {}", msg),
            None::<()>,
        ),
        PrivacyRpcError::Executor(e) => jsonrpsee::types::ErrorObjectOwned::owned(
            ErrorCode::InternalError.code(),
            format!("Executor error: {}", e),
            None::<()>,
        ),
        PrivacyRpcError::SigningError(msg) => jsonrpsee::types::ErrorObjectOwned::owned(
            ErrorCode::InvalidParams.code(),
            format!("Signing error: {}", msg),
            None::<()>,
        ),
        PrivacyRpcError::Database(msg) => jsonrpsee::types::ErrorObjectOwned::owned(
            ErrorCode::InternalError.code(),
            format!("Database error: {}", msg),
            None::<()>,
        ),
    }
}

/// Create an internal error response.
fn rpc_internal_error(msg: String) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObjectOwned::owned(
        jsonrpsee::types::ErrorCode::InternalError.code(),
        msg,
        None::<()>,
    )
}
