#[test_only]
module ccip_dummy_receiver::dummy_receiver_tests {
    use std::object::{Self};
    use std::signer;
    use aptos_framework::timestamp;
    use ccip_dummy_receiver::dummy_receiver::{Self};
    use ccip::client;
    use ccip::receiver_registry;
    use ccip::state_object;
    use ccip::auth;
    use ccip::receiver_dispatcher;

    const TEST_DATA: vector<u8> = b"test message";
    const TEST_MESSAGE_ID: vector<u8> = b"test_message_id";
    const TEST_SOURCE_CHAIN_SELECTOR: u64 = 1;
    const TEST_SENDER: vector<u8> = b"test_sender";

    fun init_timestamp(aptos_framework: &signer, timestamp_seconds: u64) {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        timestamp::update_global_time_for_test_secs(timestamp_seconds);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_dummy_receiver = @ccip_dummy_receiver,
            owner = @0x100
        )
    ]
    fun test_ccip_receive_emits_event(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_dummy_receiver: &signer,
        owner: &signer
    ) {
        let owner_addr = signer::address_of(owner);
        init_timestamp(aptos_framework, 100000);

        // Create object for @ccip
        let _constructor_ref = object::create_named_object(owner, b"ccip");

        // Create object for @ccip_dummy_receiver
        let _constructor_ref = object::create_named_object(
            owner, b"ccip_dummy_receiver"
        );

        state_object::init_module_for_testing(ccip);
        auth::test_init_module(ccip);

        receiver_registry::init_module_for_testing(owner);

        // Add owner to allowed offramps
        auth::apply_allowed_offramp_updates(
            owner,
            vector[], // offramps to remove
            vector[owner_addr] // offramps to add
        );

        // Initialize the dummy receiver (this also registers it)
        dummy_receiver::test_init_module(ccip_dummy_receiver);

        // Create a test message
        let message =
            client::new_any2aptos_message(
                TEST_MESSAGE_ID,
                TEST_SOURCE_CHAIN_SELECTOR,
                TEST_SENDER,
                TEST_DATA,
                vector[] // empty token amounts
            );

        // Dispatch the message
        receiver_dispatcher::dispatch_receive(owner, @ccip_dummy_receiver, message);

        // Verify the event was emitted
        let events = dummy_receiver::get_received_message_events();
        assert!(events.length() == 1);
        let expected_event = dummy_receiver::new_received_message_event(TEST_DATA);
        assert!(events.borrow(0) == &expected_event);
    }
}
