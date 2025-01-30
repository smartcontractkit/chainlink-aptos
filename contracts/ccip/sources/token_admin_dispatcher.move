module ccip::token_admin_dispatcher {
    use std::dispatchable_fungible_asset;
    use std::error;
    use std::fungible_asset::{Self, FungibleAsset};

    use ccip::token_admin_registry;

    friend ccip::onramp;
    friend ccip::offramp;

    const E_WITHDRAW_AMOUNT_MISMATCH: u64 = 1;

    public(friend) fun dispatch_lock_or_burn(
        token_pool_address: address,
        fungible_asset: FungibleAsset,
        sender: address,
        remote_chain_selector: u64,
        receiver: vector<u8>
    ): (vector<u8>, vector<u8>) {
        let dispatch_fungible_store =
            token_admin_registry::start_lock_or_burn(
                token_pool_address,
                sender,
                remote_chain_selector,
                receiver
            );

        dispatchable_fungible_asset::deposit(dispatch_fungible_store, fungible_asset);

        token_admin_registry::finish_lock_or_burn(token_pool_address)
    }

    public(friend) fun dispatch_release_or_mint(
        token_pool_address: address,
        amount: u64,
        sender: vector<u8>,
        remote_chain_selector: u64,
        receiver: address,
        source_pool_address: vector<u8>,
        source_pool_data: vector<u8>,
        offchain_token_data: vector<u8>
    ): (FungibleAsset, u64) {
        let (dispatch_owner, dispatch_fungible_store) =
            token_admin_registry::start_release_or_mint(
                token_pool_address,
                sender,
                remote_chain_selector,
                receiver,
                source_pool_address,
                source_pool_data,
                offchain_token_data
            );

        let fa =
            dispatchable_fungible_asset::withdraw(
                &dispatch_owner, dispatch_fungible_store, amount
            );

        let destination_amount =
            token_admin_registry::finish_release_or_mint(token_pool_address);

        let fa_amount = fungible_asset::amount(&fa);

        assert!(
            destination_amount == fa_amount,
            error::invalid_state(E_WITHDRAW_AMOUNT_MISMATCH)
        );

        (fa, destination_amount)
    }
}
