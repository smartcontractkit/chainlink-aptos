module ccip::internal {
    use std::error;
    use std::vector;

    friend ccip::fee_quoter;
    friend ccip::onramp;

    const E_TOKEN_ARGUMENTS_MISMATCH: u64 = 1;

    struct Aptos2AnyMessage has drop {
        receiver: vector<u8>,
        data: vector<u8>,
        token_amounts: vector<Aptos2AnyTokenAmount>,
        fee_token: address,
        fee_token_store: address,
        extra_args: vector<u8>
    }

    struct Aptos2AnyTokenAmount has drop {
        token: address,
        amount: u64,
        token_store: address
    }

    public(friend) fun new_aptos2any_message(
        receiver: vector<u8>,
        data: vector<u8>,
        token_addresses: vector<address>,
        token_amounts: vector<u64>,
        token_store_addresses: vector<address>,
        fee_token: address,
        fee_token_store: address,
        extra_args: vector<u8>
    ): Aptos2AnyMessage {
        let tokens_len = vector::length(&token_addresses);
        assert!(
            tokens_len == vector::length(&token_amounts),
            error::invalid_argument(E_TOKEN_ARGUMENTS_MISMATCH)
        );
        assert!(
            tokens_len == vector::length(&token_store_addresses),
            error::invalid_argument(E_TOKEN_ARGUMENTS_MISMATCH)
        );
        let converted_token_amounts = vector[];
        for (i in 0..tokens_len) {
            let token = *vector::borrow(&token_addresses, i);
            let amount = *vector::borrow(&token_amounts, i);
            let token_store = *vector::borrow(&token_store_addresses, i);
            vector::push_back(
                &mut converted_token_amounts,
                Aptos2AnyTokenAmount { token, amount, token_store }
            );
        };
        Aptos2AnyMessage {
            receiver,
            data,
            token_amounts: converted_token_amounts,
            fee_token,
            fee_token_store,
            extra_args
        }
    }

    /// Returns all fields except for FungibleAsset
    public(friend) fun get_aptos2any_fields(
        message: &Aptos2AnyMessage
    ): (vector<u8>, vector<u8>, address, address, vector<u8>) {
        (
            message.receiver,
            message.data,
            message.fee_token,
            message.fee_token_store,
            message.extra_args
        )
    }

    public(friend) fun get_aptos2any_token_transfers(
        message: &Aptos2AnyMessage
    ): (vector<address>, vector<u64>) {
        let token_addresses = vector[];
        let token_amounts = vector[];
        vector::for_each_ref(
            &message.token_amounts,
            |token_amount| {
                let token_amount: &Aptos2AnyTokenAmount = token_amount;
                vector::push_back(&mut token_addresses, token_amount.token);
                vector::push_back(&mut token_amounts, token_amount.amount);
            }
        );
        (token_addresses, token_amounts)
    }
}
