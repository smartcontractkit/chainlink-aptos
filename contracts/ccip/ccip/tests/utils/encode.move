#[test_only]
module ccip::encode {

    use ccip::eth_abi;

    const SVM_EXTRA_ARGS_V1_TAG: vector<u8> = x"1f3b3aba";
    const GENERIC_EXTRA_ARGS_V2_TAG: vector<u8> = x"181dcf10";

    public fun encode_svm_extra_args_v1(
        compute_units: u32,
        account_is_writable_bitmap: u64,
        allow_out_of_order_execution: bool,
        token_receiver: vector<u8>,
        accounts: vector<vector<u8>>
    ): vector<u8> {
        let extra_args = vector[];
        eth_abi::encode_selector(&mut extra_args, SVM_EXTRA_ARGS_V1_TAG);
        eth_abi::encode_u32(&mut extra_args, compute_units);
        eth_abi::encode_u64(&mut extra_args, account_is_writable_bitmap);
        eth_abi::encode_bool(&mut extra_args, allow_out_of_order_execution);
        eth_abi::encode_bytes32(&mut extra_args, token_receiver);

        // Encode accounts vector length
        eth_abi::encode_u256(&mut extra_args, (accounts.length() as u256));

        // Encode each account manually
        let i = 0;
        let accounts_len = accounts.length();
        while (i < accounts_len) {
            eth_abi::encode_bytes32(&mut extra_args, *accounts.borrow(i));
            i = i + 1;
        };

        extra_args
    }
}
