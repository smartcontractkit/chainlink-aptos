#[test_only]
/// Test-only receiver. Separate module to avoid dispatch reentrancy into
/// `mock_forwarder` / `mock_storage`.
module platform_mock::mock_test_receiver {
    use std::option;
    use std::string;
    use aptos_framework::function_info;
    use aptos_framework::object::Object;

    use platform_mock::mock_storage;

    struct TestProof has drop {}

    public fun test_callback<T: key>(_metadata: Object<T>): option::Option<u128> {
        let (_m, _d) = mock_storage::retrieve<TestProof>(TestProof {});
        option::none()
    }

    public fun register(publisher: &signer) {
        let cb = function_info::new_function_info(
            publisher,
            string::utf8(b"mock_test_receiver"),
            string::utf8(b"test_callback"),
        );
        mock_storage::register<TestProof>(publisher, cb, TestProof {});
    }
}
