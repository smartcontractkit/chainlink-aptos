module managed_token::faucet {
    use std::object;
    use aptos_framework::fungible_asset;
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::object::{address_to_object, ExtendRef};

    use managed_token::managed_token;

    const FAUCET_OBJECT_SEED: vector<u8> = b"ManagedTokenFaucet";

    const E_NOT_PUBLISHER: u64 = 1;

    struct FaucetState has key, store {
        extend_ref: ExtendRef
    }

    fun init_module(publisher: &signer) {
        assert!(object::is_object(@managed_token), E_NOT_PUBLISHER);
        let constructor_ref = object::create_named_object(publisher, FAUCET_OBJECT_SEED);
        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let faucet_signer = object::generate_signer(&constructor_ref);

        move_to(&faucet_signer, FaucetState { extend_ref });
    }

    #[view]
    public fun state_address(): address {
        object::create_object_address(&@managed_token, FAUCET_OBJECT_SEED)
    }

    /// @notice Allows to drip exactly one unit of the token to an arbitrary address.
    /// @param to the address to drip the token to
    public entry fun drip(to: address) acquires FaucetState {
        let state = borrow_global<FaucetState>(state_address());
        let faucet_signer = object::generate_signer_for_extending(&state.extend_ref);
        let token_metadata = address_to_object<Metadata>(managed_token::token_metadata());
        let decimals = fungible_asset::decimals(token_metadata);
        let amount: u64 = 1;
        for (i in 0..decimals) {
            amount *= 10;
        };
        managed_token::mint(&faucet_signer, to, amount);
    }
}
