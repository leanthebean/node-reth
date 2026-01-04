//! Precompile Context Management
//!
//! Provides thread-local storage for the privacy registry and store during
//! EVM execution. This is necessary because revm's PrecompileFn signature
//! is stateless.

use crate::{PrivacyRegistry, PrivateStateStore};
use alloy_primitives::Address;
use std::cell::RefCell;
use std::sync::Arc;

/// Context available to privacy precompiles during execution.
#[derive(Clone)]
pub struct PrecompileContext {
    /// The privacy registry for slot classification
    pub registry: Arc<PrivacyRegistry>,
    /// The private state store for TEE-local storage
    pub store: Arc<PrivateStateStore>,
    /// The caller address (msg.sender in EVM context)
    pub caller: Address,
    /// The current block number
    pub block: u64,
}

impl PrecompileContext {
    /// Create a new precompile context.
    pub fn new(
        registry: Arc<PrivacyRegistry>,
        store: Arc<PrivateStateStore>,
        caller: Address,
        block: u64,
    ) -> Self {
        Self {
            registry,
            store,
            caller,
            block,
        }
    }
}

impl std::fmt::Debug for PrecompileContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrecompileContext")
            .field("caller", &self.caller)
            .field("block", &self.block)
            .finish()
    }
}

thread_local! {
    /// Thread-local storage for the precompile context.
    static CONTEXT: RefCell<Option<PrecompileContext>> = const { RefCell::new(None) };
}

/// Set the precompile context for the current thread.
///
/// This must be called before executing any transaction that might call
/// the privacy precompiles.
///
/// # Panics
///
/// This function does not panic, but calling precompile functions without
/// setting the context will result in errors.
pub fn set_context(ctx: PrecompileContext) {
    CONTEXT.with(|c| {
        *c.borrow_mut() = Some(ctx);
    });
}

/// Clear the precompile context for the current thread.
///
/// This should be called after transaction execution to clean up.
/// Prefer using [`ContextGuard`] for automatic cleanup.
pub fn clear_context() {
    CONTEXT.with(|c| {
        *c.borrow_mut() = None;
    });
}

/// RAII guard that clears the precompile context when dropped.
///
/// This ensures context is always cleaned up, even on panic or early return.
/// Use [`set_context_guarded`] to create a guard.
///
/// # Example
///
/// ```ignore
/// let _guard = set_context_guarded(ctx);
/// // Context is active here
/// // ... execution (may panic or return early) ...
/// // Context is automatically cleared when _guard is dropped
/// ```
#[derive(Debug)]
#[must_use = "ContextGuard must be held for the duration of execution; dropping it clears context"]
pub struct ContextGuard {
    // Private field prevents direct construction
    _private: (),
}

impl Drop for ContextGuard {
    fn drop(&mut self) {
        clear_context();
    }
}

/// Set the precompile context and return a guard that clears it on drop.
///
/// This is the preferred way to set context as it guarantees cleanup
/// even if the code panics or returns early.
///
/// # Example
///
/// ```ignore
/// let _guard = set_context_guarded(ctx);
/// // Context is active
/// evm.execute()?; // May panic or return Err
/// // Guard ensures cleanup happens regardless
/// ```
pub fn set_context_guarded(ctx: PrecompileContext) -> ContextGuard {
    set_context(ctx);
    ContextGuard { _private: () }
}

/// Execute a function with access to the current precompile context.
///
/// Returns `None` if no context is set.
pub(super) fn with_context<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&PrecompileContext) -> R,
{
    CONTEXT.with(|c| c.borrow().as_ref().map(f))
}

/// Execute a function with mutable access to the precompile context.
///
/// Returns `None` if no context is set.
#[cfg(test)]
pub(super) fn with_context_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut PrecompileContext) -> R,
{
    CONTEXT.with(|c| c.borrow_mut().as_mut().map(f))
}

/// Check if a context is currently set.
#[cfg(test)]
pub(super) fn has_context() -> bool {
    CONTEXT.with(|c| c.borrow().is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address(n: u8) -> Address {
        Address::new([n; 20])
    }

    fn setup_test_context() -> PrecompileContext {
        let registry = Arc::new(PrivacyRegistry::new());
        let store = Arc::new(PrivateStateStore::new());
        PrecompileContext::new(registry, store, test_address(1), 100)
    }

    #[test]
    fn test_set_and_get_context() {
        // Clear any existing context first
        clear_context();

        let ctx = setup_test_context();
        set_context(ctx);

        let caller = with_context(|c| c.caller);
        assert_eq!(caller, Some(test_address(1)));

        let block = with_context(|c| c.block);
        assert_eq!(block, Some(100));

        clear_context();

        let caller = with_context(|c| c.caller);
        assert_eq!(caller, None);
    }

    #[test]
    fn test_has_context() {
        clear_context();
        assert!(!has_context());

        set_context(setup_test_context());
        assert!(has_context());

        clear_context();
        assert!(!has_context());
    }

    #[test]
    fn test_with_context_mut() {
        clear_context();

        let ctx = setup_test_context();
        set_context(ctx);

        // Modify the caller
        with_context_mut(|c| {
            c.caller = test_address(99);
        });

        let caller = with_context(|c| c.caller);
        assert_eq!(caller, Some(test_address(99)));

        clear_context();
    }

    #[test]
    fn test_context_isolation() {
        // This test verifies that context changes don't leak
        clear_context();

        assert!(!has_context());

        {
            set_context(setup_test_context());
            assert!(has_context());
        }

        // Context should still be set (it's not scoped)
        assert!(has_context());

        clear_context();
        assert!(!has_context());
    }

    #[test]
    fn test_context_guard_clears_on_drop() {
        clear_context();
        assert!(!has_context());

        {
            let _guard = set_context_guarded(setup_test_context());
            assert!(has_context());

            let caller = with_context(|c| c.caller);
            assert_eq!(caller, Some(test_address(1)));
        }

        // Context should be cleared when guard is dropped
        assert!(!has_context());
    }

    #[test]
    fn test_context_guard_clears_on_early_return() {
        clear_context();

        // Simulate early return scenario
        let result: Option<Address> = {
            let _guard = set_context_guarded(setup_test_context());
            assert!(has_context());

            // Get caller and "return early"
            with_context(|c| c.caller)
        };

        assert_eq!(result, Some(test_address(1)));

        // Context should be cleared after scope exits
        assert!(!has_context());
    }

    #[test]
    fn test_context_guard_clears_on_panic() {
        clear_context();

        let result = std::panic::catch_unwind(|| {
            let _guard = set_context_guarded(setup_test_context());
            assert!(has_context());
            panic!("intentional panic for testing");
        });

        assert!(result.is_err());
        // Context should be cleared even after panic
        assert!(!has_context());
    }
}
