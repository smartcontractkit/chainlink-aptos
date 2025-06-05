module managed_token::faucet {
    use std::account::{Self, SignerCapability};
    use std::object;
    use aptos_framework::fungible_asset;
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::object::address_to_object;

    use managed_token::managed_token;

    const STORE_OBJECT_SEED: vector<u8> = b"ManagedTokenFaucet";

    const E_NOT_PUBLISHER: u64 = 1;

    struct FaucetState has key, store {
        store_signer_cap: SignerCapability
    }

    fun init_module(publisher: &signer) {
        assert!(object::is_object(@managed_token), E_NOT_PUBLISHER);
        let (store_signer, store_signer_cap) =
            account::create_resource_account(publisher, STORE_OBJECT_SEED);
        move_to(&store_signer, FaucetState { store_signer_cap });
    }

    #[view]
    fun store_address(): address {
        account::create_resource_address(&@managed_token, STORE_OBJECT_SEED)
    }

    /// @notice Allows to drip exactly one unit of the token to an arbitrary address.
    /// @param to the address to drip the token to
    public entry fun drip(to: address) acquires FaucetState {
        let state = borrow_global<FaucetState>(store_address());
        let signer = &account::create_signer_with_capability(&state.store_signer_cap);
        let token_metadata = address_to_object<Metadata>(managed_token::token_metadata());
        let decimals = fungible_asset::decimals(token_metadata);
        let amount: u64 = 1;
        for (i in 0..decimals) {
            amount *= 10;
        };
        managed_token::mint(signer, to, amount);
    }
}

