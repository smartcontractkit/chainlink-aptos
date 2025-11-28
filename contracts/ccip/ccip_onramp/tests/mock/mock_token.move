#[test_only]
module ccip_onramp::mock_token {
    use std::fungible_asset::{Self, FungibleAsset, TransferRef};
    use std::object::{Object, ConstructorRef};
    use std::string::{Self};
    use std::option::{Self};

    public fun add_dynamic_dispatch_function(
        ccip_onramp_signer: &signer, constructor_ref: &ConstructorRef
    ) {
        let deposit =
            std::function_info::new_function_info(
                ccip_onramp_signer,
                string::utf8(b"mock_token"),
                string::utf8(b"lock_or_burn")
            );
        let withdraw =
            std::function_info::new_function_info(
                ccip_onramp_signer,
                string::utf8(b"mock_token"),
                string::utf8(b"release_or_mint")
            );
        std::dispatchable_fungible_asset::register_dispatch_functions(
            constructor_ref,
            option::some(withdraw),
            option::some(deposit),
            option::none()
        );
    }

    public fun lock_or_burn<T: key>(
        store: Object<T>, fa: FungibleAsset, transfer_ref: &TransferRef
    ) {
        fungible_asset::deposit_with_ref(transfer_ref, store, fa);
    }

    public fun release_or_mint<T: key>(
        store: Object<T>, amount: u64, transfer_ref: &TransferRef
    ): FungibleAsset {
        fungible_asset::withdraw_with_ref(transfer_ref, store, amount)
    }
}
