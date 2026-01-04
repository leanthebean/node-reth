//! Types for privacy RPC responses.

use alloy_primitives::{Address, Bytes, B256, U256};
use serde::{Deserialize, Serialize};

/// Result of executing a private transaction via `priv_sendRawTransaction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateTransactionResult {
    /// Whether execution succeeded (didn't revert).
    pub success: bool,
    /// Return data from the execution.
    pub output: Bytes,
    /// Gas used during execution.
    pub gas_used: U256,
    /// Whether any public storage was written.
    pub public_write_occurred: bool,
    /// The effective sender used during execution.
    pub effective_sender: Address,
    /// The real user who signed the transaction.
    pub real_sender: Address,
    /// Block transaction hash (if public writes occurred).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_tx_hash: Option<B256>,
}

#[cfg(feature = "privacy")]
impl From<base_reth_privacy::PrivateExecutionResult> for PrivateTransactionResult {
    fn from(result: base_reth_privacy::PrivateExecutionResult) -> Self {
        Self {
            success: result.success,
            output: result.output,
            gas_used: U256::from(result.gas_used),
            public_write_occurred: result.public_write_occurred,
            effective_sender: result.effective_sender,
            real_sender: result.real_sender,
            block_tx_hash: result.block_transaction.map(|tx| tx.tx_hash),
        }
    }
}
