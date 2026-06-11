module cre_canary_receiver_secondary::canary_receiver {
    use std::event;
    use std::option;
    use std::signer;
    use std::string::{Self, String};

    use aptos_framework::object;

    struct State has key {
        counter: u64
    }

    struct OnReport has drop {}

    #[event]
    struct MessageReceived has drop, store {
        message: String,
        counter: u64
    }

    fun init_module(publisher: &signer) {
        assert!(signer::address_of(publisher) == @cre_canary_receiver_secondary, 1);

        let cb = aptos_framework::function_info::new_function_info(
            publisher,
            string::utf8(b"canary_receiver"),
            string::utf8(b"on_report")
        );
        platform_secondary::storage::register(publisher, cb, OnReport {});

        move_to(publisher, State { counter: 0 });
    }

    public fun on_report<T: key>(
        _meta: object::Object<T>
    ): option::Option<u128> acquires State {
        let (_metadata, data) = platform_secondary::storage::retrieve(OnReport {});
        handle_report(data)
    }

    fun handle_report(data: vector<u8>): option::Option<u128> acquires State {
        let message = string::utf8(data);
        let state = borrow_global_mut<State>(@cre_canary_receiver_secondary);

        state.counter = state.counter + 1;
        event::emit(MessageReceived { message, counter: state.counter });

        option::none()
    }

    #[view]
    public fun get_counter(): u64 acquires State {
        borrow_global<State>(@cre_canary_receiver_secondary).counter
    }
}
