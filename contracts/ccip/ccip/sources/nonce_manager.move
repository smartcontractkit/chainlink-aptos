module ccip::nonce_manager {
    use std::signer;
    use std::big_ordered_map::{Self, BigOrderedMap};
    use std::string::{Self, String};

    use ccip::auth;
    use ccip::state_object;

    struct NonceManagerState has key, store {
        // dest chain selector -> sender -> nonce
        outbound_nonces: BigOrderedMap<u64, BigOrderedMap<address, u64>>
    }

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"NonceManager 1.6.0")
    }

    fun init_module(_publisher: &signer) {
        let state_object_signer = state_object::object_signer();

        move_to(
            &state_object_signer,
            NonceManagerState {
                outbound_nonces: big_ordered_map::new_with_config(0, 0, false)
            }
        );
    }

    #[view]
    public fun get_outbound_nonce(
        dest_chain_selector: u64, sender: address
    ): u64 acquires NonceManagerState {
        let state = borrow_state();

        if (!state.outbound_nonces.contains(&dest_chain_selector)) {
            return 0;
        };

        let dest_chain_nonces = state.outbound_nonces.borrow(&dest_chain_selector);
        if (!dest_chain_nonces.contains(&sender)) {
            return 0;
        };
        *dest_chain_nonces.borrow(&sender)
    }

    public fun get_incremented_outbound_nonce(
        caller: &signer, dest_chain_selector: u64, sender: address
    ): u64 acquires NonceManagerState {
        auth::assert_is_allowed_onramp(signer::address_of(caller));

        let state = borrow_state_mut();

        if (!state.outbound_nonces.contains(&dest_chain_selector)) {
            state.outbound_nonces.add(
                dest_chain_selector, big_ordered_map::new_with_config(0, 0, false)
            );
        };

        let dest_chain_nonces = state.outbound_nonces.borrow_mut(&dest_chain_selector);
        if (!dest_chain_nonces.contains(&sender)) {
            dest_chain_nonces.add(sender, 0);
        };
        let nonce_ref = dest_chain_nonces.borrow_mut(&sender);
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

    // ========================== TEST ONLY ==========================

    #[test_only]
    public fun test_init_module(publisher: &signer) {
        init_module(publisher);
    }
}
