module ccip_dummy_receiver::dummy_receiver {
    use std::account;
    use std::event;
    use std::object::Object;
    use std::option::{Self, Option};
    use std::signer;
    use std::string::{Self, String};

    use ccip::client;
    use ccip::receiver_registry;

    const E_TEST_ABORT: u64 = 1;

    #[event]
    struct ReceivedMessage has store, drop {
        data: vector<u8>
    }

    struct CCIPReceiverState has key {
        received_message_events: event::EventHandle<ReceivedMessage>
    }

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"DummyReceiver 1.6.0")
    }

    fun init_module(publisher: &signer) {
        assert!(signer::address_of(publisher) == @ccip_dummy_receiver, 1);

        // Create an account on the object for event handles, required before AIP-115 activation
        account::create_account_if_does_not_exist(@ccip_dummy_receiver);

        let handle = account::new_event_handle(publisher);

        move_to(publisher, CCIPReceiverState { received_message_events: handle });

        receiver_registry::register_receiver(
            publisher, b"dummy_receiver", DummyReceiverProof {}
        );
    }

    struct DummyReceiverProof has drop {}

    public fun ccip_receive<T: key>(_metadata: Object<T>): Option<u128> acquires CCIPReceiverState {
        let message =
            receiver_registry::get_receiver_input(
                @ccip_dummy_receiver, DummyReceiverProof {}
            );
        let data = client::get_data(&message);
        if (data == b"abort") {
            abort E_TEST_ABORT
        };

        let state = borrow_state_mut();

        event::emit_event(&mut state.received_message_events, ReceivedMessage { data });

        option::none()
    }

    inline fun borrow_state_mut(): &mut CCIPReceiverState {
        borrow_global_mut<CCIPReceiverState>(@ccip_dummy_receiver)
    }

    #[test_only]
    public fun new_received_message_event(data: vector<u8>): ReceivedMessage {
        ReceivedMessage { data }
    }

    #[test_only]
    public fun test_init_module(publisher: &signer) {
        init_module(publisher);
    }

    #[test_only]
    public fun new_dummy_receiver_proof(): DummyReceiverProof {
        DummyReceiverProof {}
    }

    #[test_only]
    public fun get_received_message_events(): vector<ReceivedMessage> acquires CCIPReceiverState {
        let state = borrow_global<CCIPReceiverState>(@ccip_dummy_receiver);
        event::emitted_events_by_handle<ReceivedMessage>(&state.received_message_events)
    }
}
