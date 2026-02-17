module ccip::token_admin_dispatcher {
    use std::dispatchable_fungible_asset;
    use std::fungible_asset::FungibleAsset;
    use std::signer;

    use ccip::auth;
    use ccip::token_admin_registry;

    public fun dispatch_lock_or_burn(
        caller: &signer,
        token_pool_address: address,
        fa: FungibleAsset,
        sender: address,
        remote_chain_selector: u64,
        receiver: vector<u8>
    ): (vector<u8>, vector<u8>) {
        auth::assert_is_allowed_onramp(signer::address_of(caller));

        if (token_admin_registry::has_token_pool_registration_v2(token_pool_address)) {
            token_admin_registry::lock_or_burn_v2(
                token_pool_address,
                fa,
                sender,
                remote_chain_selector,
                receiver
            )
        } else {
            let dispatch_fungible_store =
                token_admin_registry::start_lock_or_burn(
                    token_pool_address,
                    sender,
                    remote_chain_selector,
                    receiver
                );

            dispatchable_fungible_asset::deposit(dispatch_fungible_store, fa);

            token_admin_registry::finish_lock_or_burn(token_pool_address)
        }
    }

    public fun dispatch_release_or_mint(
        caller: &signer,
        token_pool_address: address,
        sender: vector<u8>,
        receiver: address,
        source_amount: u256,
        local_token: address,
        remote_chain_selector: u64,
        source_pool_address: vector<u8>,
        source_pool_data: vector<u8>,
        offchain_token_data: vector<u8>
    ): (FungibleAsset, u64) {
        auth::assert_is_allowed_offramp(signer::address_of(caller));

        if (token_admin_registry::has_token_pool_registration_v2(token_pool_address)) {
            token_admin_registry::release_or_mint_v2(
                token_pool_address,
                sender,
                receiver,
                source_amount,
                local_token,
                remote_chain_selector,
                source_pool_address,
                source_pool_data,
                offchain_token_data
            )
        } else {
            let (dispatch_owner, dispatch_fungible_store) =
                token_admin_registry::start_release_or_mint(
                    token_pool_address,
                    sender,
                    receiver,
                    source_amount,
                    local_token,
                    remote_chain_selector,
                    source_pool_address,
                    source_pool_data,
                    offchain_token_data
                );

            let fa =
                dispatchable_fungible_asset::withdraw(
                    &dispatch_owner, dispatch_fungible_store, 0
                );

            let destination_amount =
                token_admin_registry::finish_release_or_mint(token_pool_address);

            (fa, destination_amount)
        }
    }
}
