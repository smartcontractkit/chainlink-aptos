module mcms_test::mcms_user {
    use std::error;
    use std::option;
    use std::string::{Self, String};
    use std::signer;
    use std::object::Object;

    use mcms::bcs_stream;
    use mcms::mcms_registry;

    const EUNKNOWN_FUNCTION: u64 = 1;

    struct UserData has key, drop, store {
        invocations: u8,
        a: String,
        b: vector<u8>,
        c: address,
        d: u128
    }

    public fun function_one(arg1: String, arg2: vector<u8>) acquires UserData {
        let user_data = borrow_global_mut<UserData>(@mcms_test);
        user_data.invocations += 1;
        user_data.a = arg1;
        user_data.b = arg2;
    }

    public fun function_two(arg1: address, arg2: u128) acquires UserData {
        let user_data = borrow_global_mut<UserData>(@mcms_test);
        user_data.invocations += 1;
        user_data.c = arg1;
        user_data.d = arg2;
    }

    fun init_module(publisher: &signer) {
        assert!(signer::address_of(publisher) == @mcms_test, 1);

        move_to(
            publisher,
            UserData {
                invocations: 0,
                a: string::utf8(b""),
                b: vector[],
                c: @0x0,
                d: 0
            }
        );

        mcms_registry::register_entrypoint(
            publisher, string::utf8(b"mcms_user"), SampleMcmsCallback {}
        );
    }

    struct SampleMcmsCallback has drop {}

    public fun mcms_entrypoint<T: key>(_metadata: Object<T>): option::Option<u128> acquires UserData {
        // for any caller of mcms_entrypoint except mcms, get_callback_params would
        // fail and the transaction would abort.
        let (_signer, function, data) =
            mcms_registry::get_callback_params(@mcms_test, SampleMcmsCallback {});

        let function_bytes = *function.bytes();
        let stream = bcs_stream::new(data);

        if (function_bytes == b"function_one") {
            let arg1 = bcs_stream::deserialize_string(&mut stream);
            let arg2 = bcs_stream::deserialize_vector_u8(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            function_one(arg1, arg2);
        } else if (function_bytes == b"function_two") {
            let arg1 = bcs_stream::deserialize_address(&mut stream);
            let arg2 = bcs_stream::deserialize_u128(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            function_two(arg1, arg2);
        } else {
            abort error::invalid_argument(EUNKNOWN_FUNCTION)
        };

        option::none()
    }
}
