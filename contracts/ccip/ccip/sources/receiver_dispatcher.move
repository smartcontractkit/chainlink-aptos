module ccip::receiver_dispatcher {
    use std::dispatchable_fungible_asset;
    use std::signer;

    use ccip::auth;
    use ccip::client;
    use ccip::receiver_registry;

    public fun dispatch_receive(
        caller: &signer, receiver_address: address, message: client::Any2AptosMessage
    ) {
        auth::assert_is_allowed_offramp(signer::address_of(caller));

        let dispatch_metadata =
            receiver_registry::start_receive(receiver_address, message);
        dispatchable_fungible_asset::derived_supply(dispatch_metadata);
        receiver_registry::finish_receive(receiver_address);
    }
}
