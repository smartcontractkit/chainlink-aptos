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

    struct VectorVectorEvent has store, drop {
        values: vector<vector<u8>>
    }

    struct Nested has store, drop {
        id: u64,
        description: String
    }

    struct ComplexStruct has store, drop {
        flag: bool,
        nested: Nested,
        values: vector<u64>
    }

    struct EventStore has key {
        single_value_events: event::EventHandle<SingleValueEvent>,
        double_value_events: event::EventHandle<DoubleValueEvent>,
        vector_vector_events: event::EventHandle<VectorVectorEvent>,
        complex_struct_events: event::EventHandle<ComplexStruct>
    }

    fun init_module(account: &signer) {
        move_to(
            account,
            EventStore {
                single_value_events: account::new_event_handle<SingleValueEvent>(account),
                double_value_events: account::new_event_handle<DoubleValueEvent>(account),
                vector_vector_events: account::new_event_handle<VectorVectorEvent>(
                    account
                ),
                complex_struct_events: account::new_event_handle<ComplexStruct>(account)
            }
        );
    }

    public entry fun echo_with_events(
        _account: &signer, number: u64, text: String, bytes: vector<u8>
    ) acquires EventStore {
        let store = borrow_global_mut<EventStore>(@test);

        event::emit_event(
            &mut store.single_value_events, SingleValueEvent { value: number }
        );
        event::emit_event(&mut store.double_value_events, DoubleValueEvent { number, text });

        let values = vector::empty<vector<u8>>();
        vector::push_back(&mut values, bytes);
        event::emit_event(&mut store.vector_vector_events, VectorVectorEvent { values });

        let nested = Nested { id: number, description: text };
        let cs = ComplexStruct {
            flag: true,
            nested,
            values: vector[number, number + 1]
        };
        event::emit_event(&mut store.complex_struct_events, cs);
    }

    // used to test event account address handling in ChainReader
    #[view]
    public fun get_event_address(): address {
        @test
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
    public fun echo_u32_vector(val: vector<u32>): vector<u32> {
        val
    }

    #[view]
    public fun echo_byte_vector_vector(val: vector<vector<u8>>): vector<vector<u8>> {
        val
    }

    #[view]
    public fun get_complex_struct(val: u64, text: String): ComplexStruct {
        let nested = Nested { id: val, description: text };
        ComplexStruct { flag: true, nested, values: vector[val, val + 1] }
    }

    #[view]
    public fun get_complex_struct_array(val: u64, text: String): vector<ComplexStruct> {
        let cs1 = get_complex_struct(val, text);
        let cs2 = get_complex_struct(val, text);
        vector[cs1, cs2]
    }
}
