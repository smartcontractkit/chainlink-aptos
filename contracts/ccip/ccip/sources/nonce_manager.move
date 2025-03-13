module ccip::nonce_manager {
    use std::error;
    use std::signer;
    use std::smart_table::{Self, SmartTable};
    use std::string::{Self, String};

    use ccip::auth;
    use ccip::state_object;

    friend ccip::onramp;

    struct NonceManagerState has key, store {
        // dest chain selector -> sender -> nonce
        outbound_nonces: SmartTable<u64, SmartTable<address, u64>>
    }

    const E_ALREADY_INITIALIZED: u64 = 1;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"NonceManager 1.6.0")
    }

    fun init_module(publisher: &signer) {
        auth::assert_only_owner(signer::address_of(publisher));

        assert!(
            !exists<NonceManagerState>(state_object::object_address()),
            error::invalid_argument(E_ALREADY_INITIALIZED)
        );

        let state_object_signer = state_object::object_signer();

        let state = NonceManagerState { outbound_nonces: smart_table::new() };

        move_to(&state_object_signer, state);
    }

    public fun get_outbound_nonce(
        dest_chain_selector: u64, sender: address
    ): u64 acquires NonceManagerState {
        let state = borrow_state();

        if (!smart_table::contains(&state.outbound_nonces, dest_chain_selector)) {
            return 0;
        };

        let dest_chain_nonces =
            smart_table::borrow(&state.outbound_nonces, dest_chain_selector);
        *smart_table::borrow_with_default(dest_chain_nonces, sender, &0)
    }

    public(friend) fun get_incremented_outbound_nonce(
        dest_chain_selector: u64, sender: address
    ): u64 acquires NonceManagerState {
        let state = borrow_state_mut();

        if (!smart_table::contains(&state.outbound_nonces, dest_chain_selector)) {
            smart_table::add(
                &mut state.outbound_nonces, dest_chain_selector, smart_table::new()
            );
        };

        let dest_chain_nonces =
            smart_table::borrow_mut(&mut state.outbound_nonces, dest_chain_selector);
        let nonce_ref = smart_table::borrow_mut_with_default(
            dest_chain_nonces, sender, 0
        );
        let incremented_nonce = *nonce_ref + 1;
        *nonce_ref = incremented_nonce;
        incremented_nonce
    }

    inline fun borrow_state(): &NonceManagerState {
        borrow_global<NonceManagerState>(state_object::object_address())
    }

    inline fun borrow_state_mut(): &mut NonceManagerState {
        borrow_global_mut<NonceManagerState>(state_object::object_address())
    }
}
