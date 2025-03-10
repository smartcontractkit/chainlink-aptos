module test::echo {
    use std::string::String;
    use std::vector;
    use aptos_framework::account;
    use aptos_framework::event;

    struct SingleValueEvent has store, drop {
        value: u64
    }

    struct DoubleValueEvent has store, drop {
        number: u64,
        text: String
    }

    struct TripleValueEvent has store, drop {
        values: vector<vector<u8>>
    }

    struct EventStore has key {
        single_value_events: event::EventHandle<SingleValueEvent>,
        double_value_events: event::EventHandle<DoubleValueEvent>,
        triple_value_events: event::EventHandle<TripleValueEvent>
    }

    fun init_module(account: &signer) {
        move_to(account, EventStore {
            single_value_events: account::new_event_handle<SingleValueEvent>(account),
            double_value_events: account::new_event_handle<DoubleValueEvent>(account),
            triple_value_events: account::new_event_handle<TripleValueEvent>(account)
        });
    }

    public entry fun echo_with_events(
        _account: &signer,
        number: u64,
        text: String,
        bytes: vector<u8>
    ) acquires EventStore {
        let store = borrow_global_mut<EventStore>(@test);
        
        event::emit_event(&mut store.single_value_events, SingleValueEvent { value: number });
        event::emit_event(&mut store.double_value_events, DoubleValueEvent { number, text });
        
        let values = vector::empty<vector<u8>>();
        vector::push_back(&mut values, bytes);
        event::emit_event(&mut store.triple_value_events, TripleValueEvent { values });
    }

    #[view]
    public fun echo_u64(val: u64): u64 {
        val
    }

    #[view]
    public fun echo_u256(val: u256): u256 {
        val
    }

    #[view]
    public fun echo_u32_u64_tuple(val1: u32, val2: u64): (u32, u64) {
        (val1, val2)
    }

    #[view]
    public fun echo_string(val: String): String {
        val
    }

    #[view]
    public fun echo_byte_vector(val: vector<u8>): vector<u8> {
        val
    }

    #[view]
    public fun echo_byte_vector_vector(val: vector<vector<u8>>): vector<vector<u8>> {
        val
    }
}
