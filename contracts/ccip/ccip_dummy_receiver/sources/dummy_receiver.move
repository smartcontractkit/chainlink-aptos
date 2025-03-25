module ccip_dummy_receiver::dummy_receiver {
    use std::event;
    use std::object::Object;
    use std::option::{Self, Option};
    use std::string::{Self, String};

    use ccip::client;
    use ccip::receiver_registry;

    #[event]
    struct ReceivedMessage has store, drop {
        data: vector<u8>
    }

    struct DummyReceiverProof has drop {}

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"DummyReceiver 1.6.0")
    }

    fun init_module(publisher: &signer) {
        receiver_registry::register_receiver(
            publisher, b"dummy_receiver", DummyReceiverProof {}
        );
    }

    public fun ccip_receive<T: key>(_metadata: Object<T>): Option<u128> {
        let message =
            receiver_registry::get_receiver_input(
                @ccip_dummy_receiver, DummyReceiverProof {}
            );
        let data = client::get_data(&message);

        event::emit(ReceivedMessage { data });

        option::none()
    }
}
