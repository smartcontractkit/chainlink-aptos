module ccip::receiver_dispatcher {
    use std::dispatchable_fungible_asset;
    use std::option::Option;

    use ccip::client;
    use ccip::receiver_registry;

    friend ccip::offramp;

    public(friend) fun dispatch_receive(
        receiver_address: address, message: client::Any2AptosMessage
    ): Option<u128> {
        let dispatch_metadata =
            receiver_registry::start_receive(receiver_address, message);

        let result = dispatchable_fungible_asset::derived_supply(dispatch_metadata);

        receiver_registry::finish_receive(receiver_address);

        result
    }
}
