#[test_only]
module ccip_offramp::mock_token {
    use std::fungible_asset::{Self, FungibleAsset, TransferRef};
    use std::object::{Object, ConstructorRef};
    use std::string::{Self};
    use std::option::{Self};
    use std::function_info;
    use std::dispatchable_fungible_asset;

    public fun add_dynamic_dispatch_function(
        ccip_onramp_signer: &signer, constructor_ref: &ConstructorRef
    ) {
        let deposit =
            function_info::new_function_info(
                ccip_onramp_signer,
                string::utf8(b"mock_token"),
                string::utf8(b"deposit")
            );
        let withdraw =
            function_info::new_function_info(
                ccip_onramp_signer,
                string::utf8(b"mock_token"),
                string::utf8(b"withdraw")
            );
        dispatchable_fungible_asset::register_dispatch_functions(
            constructor_ref,
            option::some(withdraw),
            option::some(deposit),
            option::none()
        );
    }

    public fun deposit<T: key>(
        store: Object<T>, fa: FungibleAsset, transfer_ref: &TransferRef
    ) {
        std::debug::print(&std::string::utf8(b"custom lock_or_burn called"));
        fungible_asset::deposit_with_ref(transfer_ref, store, fa);
        std::debug::print(&std::string::utf8(b"custom lock_or_burn done"));
    }

    public fun withdraw<T: key>(
        store: Object<T>, amount: u64, transfer_ref: &TransferRef
    ): FungibleAsset {
        std::debug::print(&std::string::utf8(b"custom release_or_mint called"));
        let fa = fungible_asset::withdraw_with_ref(transfer_ref, store, amount);
        std::debug::print(&std::string::utf8(b"custom release_or_mint done"));
        fa
    }
}
