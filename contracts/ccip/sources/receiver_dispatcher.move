module ccip::receiver_dispatcher {
    use std::dispatchable_fungible_asset;
    use std::option::Option;

    use ccip::receiver_registry;

    friend ccip::offramp;

    public(friend) fun dispatch_receive(
        receiver_address: address,
        message_id: vector<u8>,
        source_chain_selector: u64,
        sender: vector<u8>,
        data: vector<u8>,
        token_addresses: vector<address>,
        token_amounts: vector<u64>
    ): Option<u128> {
        let dispatch_metadata =
            receiver_registry::start_receive(
                receiver_address,
                message_id,
                source_chain_selector,
                sender,
                data,
                token_addresses,
                token_amounts
            );

        let result = dispatchable_fungible_asset::derived_supply(dispatch_metadata);

        receiver_registry::finish_receive(receiver_address);

        result
    }
}
