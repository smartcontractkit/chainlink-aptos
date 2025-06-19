module ccip_dummy_receiver::dummy_receiver {
    use std::account;
    use std::event;
    use std::object::Object;
    use std::option::{Self, Option};
    use std::signer;
    use std::string::{Self, String};

    use ccip::client;
    use ccip::receiver_registry;

    #[event]
    struct ReceivedMessage has store, drop {
        data: vector<u8>
    }

    #[event]
    struct AlwaysAbortToggled has store, drop {
        always_abort: bool
    }

    struct CCIPReceiverState has key {
        received_message_events: event::EventHandle<ReceivedMessage>,
        always_abort_events: event::EventHandle<AlwaysAbortToggled>,
        always_abort: bool
    }

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"DummyReceiver 1.6.0")
    }

    #[view]
    public fun get_always_abort(): bool acquires CCIPReceiverState {
        let state = borrow_state();
        state.always_abort
    }

    fun init_module(publisher: &signer) {
        assert!(signer::address_of(publisher) == @ccip_dummy_receiver, 1);

        // Create an account on the object for event handles, required before AIP-115 activation
        account::create_account_if_does_not_exist(@ccip_dummy_receiver);

        let received_message_handle = account::new_event_handle(publisher);
        let always_abort_handle = account::new_event_handle(publisher);

        move_to(publisher, CCIPReceiverState { 
            received_message_events: received_message_handle,
            always_abort_events: always_abort_handle,
            always_abort: false
        });

        receiver_registry::register_receiver(
            publisher, b"dummy_receiver", DummyReceiverProof {}
        );
    }

    struct DummyReceiverProof has drop {}

    public fun ccip_receive<T: key>(_metadata: Object<T>): Option<u128> acquires CCIPReceiverState {
        let state = borrow_state();
        
        // Check if always_abort is enabled
        if (state.always_abort) {
            abort 1
        };

        let message =
            receiver_registry::get_receiver_input(
                @ccip_dummy_receiver, DummyReceiverProof {}
            );
        let data = client::get_data(&message);
        if (data == b"abort") {
            abort 1
        };

        let state_mut = borrow_state_mut();

        event::emit(ReceivedMessage { data });
        event::emit_event(&mut state_mut.received_message_events, ReceivedMessage { data });

        option::none()
    }

    /// Set the always_abort flag. Anyone can call this function
    public entry fun set_always_abort(always_abort: bool) acquires CCIPReceiverState {
        let state = borrow_state_mut();
        state.always_abort = always_abort;

        event::emit(AlwaysAbortToggled { always_abort });
        event::emit_event(&mut state.always_abort_events, AlwaysAbortToggled { always_abort });
    }

    /// Enable always_abort flag. Anyone can call this function to toggle the always_abort flag.
    public entry fun enable_always_abort() acquires CCIPReceiverState {
        set_always_abort(true);
    }

    /// Disable always_abort flag. Anyone can call this function to toggle the always_abort flag.  
    public entry fun disable_always_abort() acquires CCIPReceiverState {
        set_always_abort(false);
    }

    inline fun borrow_state(): &CCIPReceiverState {
        borrow_global<CCIPReceiverState>(@ccip_dummy_receiver)
    }

    inline fun borrow_state_mut(): &mut CCIPReceiverState {
        borrow_global_mut<CCIPReceiverState>(@ccip_dummy_receiver)
    }

    #[test_only]
    public fun new_received_message_event(data: vector<u8>): ReceivedMessage {
        ReceivedMessage { data }
    }

    #[test_only]
    public fun new_always_abort_toggled_event(always_abort: bool): AlwaysAbortToggled {
        AlwaysAbortToggled { always_abort }
    }

    #[test_only]
    public fun test_init_module() {
        init_module(publisher);
    }

    #[test_only]
    public fun new_dummy_receiver_proof(): DummyReceiverProof {
        DummyReceiverProof {}
    }
}
