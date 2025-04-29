script {
    use std::option;
    use token_messenger_minter::token_messenger;

    fun replace_deposit_for_burn(caller: &signer,
                                 original_message: vector<u8>,
                                 original_attestation: vector<u8>,
                                 new_destination_caller: option::Option<address>,
                                 new_mint_recipient: option::Option<address>) {
        token_messenger::replace_deposit_for_burn(
            caller,
            &original_message,
            &original_attestation,
            &new_destination_caller,
            &new_mint_recipient
        );
    }
}
