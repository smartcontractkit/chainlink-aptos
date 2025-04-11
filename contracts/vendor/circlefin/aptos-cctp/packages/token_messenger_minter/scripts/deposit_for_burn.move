script {
    use aptos_framework::fungible_asset::{Metadata};
    use aptos_framework::object::{Self, Object};
    use aptos_framework::primary_fungible_store;
    use token_messenger_minter::token_messenger;

    fun deposit_for_burn(caller: &signer,
                         amount: u64,
                         destination_domain: u32,
                         mint_recipient: address,
                         burn_token: address) {
        let token_obj: Object<Metadata> = object::address_to_object(burn_token);
        let asset = primary_fungible_store::withdraw(caller, token_obj, amount);
        token_messenger::deposit_for_burn(
            caller,
            asset,
            destination_domain,
            mint_recipient,
        );
    }
}
