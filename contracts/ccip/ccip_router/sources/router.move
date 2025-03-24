module ccip_router::router {
    use std::account::{Self, SignerCapability};
    use std::signer;
    use std::string::{Self, String};

    use ccip::auth;
    use ccip::onramp;

    struct RouterState has key {
        signer_capability: SignerCapability
    }

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"Router 1.6.0")
    }

    fun init_module(publisher: &signer) {
        let signer_capability = auth::retrieve_router_signer_cap(publisher);
        move_to(publisher, RouterState { signer_capability });
    }

    #[view]
    public fun get_state_address(): address acquires RouterState {
        signer::address_of(&get_signer())
    }

    #[view]
    public fun is_chain_supported(dest_chain_selector: u64): bool {
        onramp::is_chain_supported(dest_chain_selector)
    }

    #[view]
    public fun get_fee(
        dest_chain_selector: u64,
        receiver: vector<u8>,
        data: vector<u8>,
        token_addresses: vector<address>,
        token_amounts: vector<u64>,
        token_store_addresses: vector<address>,
        fee_token: address,
        fee_token_store: address,
        extra_args: vector<u8>
    ): u64 {
        onramp::get_fee(
            dest_chain_selector,
            receiver,
            data,
            token_addresses,
            token_amounts,
            token_store_addresses,
            fee_token,
            fee_token_store,
            extra_args
        )
    }

    public entry fun ccip_send(
        caller: &signer,
        dest_chain_selector: u64,
        receiver: vector<u8>,
        data: vector<u8>,
        token_addresses: vector<address>,
        token_amounts: vector<u64>,
        token_store_addresses: vector<address>,
        fee_token: address,
        fee_token_store: address,
        extra_args: vector<u8>
    ) acquires RouterState {
        onramp::ccip_send(
            &get_signer(),
            caller,
            dest_chain_selector,
            receiver,
            data,
            token_addresses,
            token_amounts,
            token_store_addresses,
            fee_token,
            fee_token_store,
            extra_args
        );
    }

    public fun ccip_send_with_message_id(
        caller: &signer,
        dest_chain_selector: u64,
        receiver: vector<u8>,
        data: vector<u8>,
        token_addresses: vector<address>,
        token_amounts: vector<u64>,
        token_store_addresses: vector<address>,
        fee_token: address,
        fee_token_store: address,
        extra_args: vector<u8>
    ): vector<u8> acquires RouterState {
        onramp::ccip_send(
            &get_signer(),
            caller,
            dest_chain_selector,
            receiver,
            data,
            token_addresses,
            token_amounts,
            token_store_addresses,
            fee_token,
            fee_token_store,
            extra_args
        )
    }

    inline fun get_signer(): signer {
        account::create_signer_with_capability(&borrow_state().signer_capability)
    }

    inline fun borrow_state(): &RouterState {
        borrow_global<RouterState>(@ccip_router)
    }
}
