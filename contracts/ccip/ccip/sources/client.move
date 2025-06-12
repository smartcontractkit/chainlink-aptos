/// This module defines messages for end users to interact with Aptos CCIP.
module ccip::client {
    use std::bcs;
    use std::error;

    const GENERIC_EXTRA_ARGS_V2_TAG: vector<u8> = x"181dcf10";
    const SVM_EXTRA_ARGS_V1_TAG: vector<u8> = x"1f3b3aba";

    const E_INVALID_SVM_TOKEN_RECEIVER_LENGTH: u64 = 1;
    const E_INVALID_SVM_ACCOUNT_LENGTH: u64 = 2;

    #[view]
    public fun generic_extra_args_v2_tag(): vector<u8> {
        GENERIC_EXTRA_ARGS_V2_TAG
    }

    #[view]
    public fun svm_extra_args_v1_tag(): vector<u8> {
        SVM_EXTRA_ARGS_V1_TAG
    }

    #[view]
    public fun encode_generic_extra_args_v2(
        gas_limit: u256, allow_out_of_order_execution: bool
    ): vector<u8> {
        let extra_args = vector[];
        extra_args.append(GENERIC_EXTRA_ARGS_V2_TAG);
        extra_args.append(bcs::to_bytes(&gas_limit));
        extra_args.append(bcs::to_bytes(&allow_out_of_order_execution));
        extra_args
    }

    #[view]
    public fun encode_svm_extra_args_v1(
        compute_units: u32,
        account_is_writable_bitmap: u64,
        allow_out_of_order_execution: bool,
        token_receiver: vector<u8>,
        accounts: vector<vector<u8>>
    ): vector<u8> {
        let extra_args = vector[];
        extra_args.append(SVM_EXTRA_ARGS_V1_TAG);
        extra_args.append(bcs::to_bytes(&compute_units));
        extra_args.append(bcs::to_bytes(&account_is_writable_bitmap));
        extra_args.append(bcs::to_bytes(&allow_out_of_order_execution));
        pad_svm_address(&mut token_receiver);
        assert!(
            token_receiver.length() == 32,
            error::invalid_argument(E_INVALID_SVM_TOKEN_RECEIVER_LENGTH)
        );
        extra_args.append(bcs::to_bytes(&token_receiver));
        let accounts_len = accounts.length();
        for (i in 0..accounts_len) {
            let account = accounts.borrow_mut(i);
            pad_svm_address(account);
            assert!(
                account.length() == 32,
                error::invalid_argument(E_INVALID_SVM_ACCOUNT_LENGTH)
            );
        };
        extra_args.append(bcs::to_bytes(&accounts));
        extra_args
    }

    inline fun pad_svm_address(svm_address: &mut vector<u8>) {
        if (svm_address.length() < 32) {
            svm_address.reverse();
            while (svm_address.length() < 32) {
                svm_address.push_back(0);
            };
            svm_address.reverse();
        }
    }

    struct Any2AptosMessage has store, drop, copy {
        message_id: vector<u8>,
        source_chain_selector: u64,
        sender: vector<u8>,
        data: vector<u8>,
        dest_token_amounts: vector<Any2AptosTokenAmount>
    }

    struct Any2AptosTokenAmount has store, drop, copy {
        token: address,
        amount: u64
    }

    public fun new_any2aptos_message(
        message_id: vector<u8>,
        source_chain_selector: u64,
        sender: vector<u8>,
        data: vector<u8>,
        dest_token_amounts: vector<Any2AptosTokenAmount>
    ): Any2AptosMessage {
        Any2AptosMessage {
            message_id,
            source_chain_selector,
            sender,
            data,
            dest_token_amounts
        }
    }

    public fun new_dest_token_amounts(
        token_addresses: vector<address>, token_amounts: vector<u64>
    ): vector<Any2AptosTokenAmount> {
        token_addresses.zip_map_ref(
            &token_amounts,
            |token_address, token_amount| {
                Any2AptosTokenAmount { token: *token_address, amount: *token_amount }
            }
        )
    }

    // Any2AptosMessage accessors

    public fun get_message_id(input: &Any2AptosMessage): vector<u8> {
        input.message_id
    }

    public fun get_source_chain_selector(input: &Any2AptosMessage): u64 {
        input.source_chain_selector
    }

    public fun get_sender(input: &Any2AptosMessage): vector<u8> {
        input.sender
    }

    public fun get_data(input: &Any2AptosMessage): vector<u8> {
        input.data
    }

    public fun get_dest_token_amounts(input: &Any2AptosMessage): vector<Any2AptosTokenAmount> {
        input.dest_token_amounts
    }

    // Any2AptosTokenAmount accessors

    public fun get_token(input: &Any2AptosTokenAmount): address {
        input.token
    }

    public fun get_amount(input: &Any2AptosTokenAmount): u64 {
        input.amount
    }

    #[test]
    fun test_pad_svm_address_empty() {
        let addr = vector[];
        pad_svm_address(&mut addr);
        assert!(addr.length() == 32, 0);
        // Verify all bytes are zeros
        for (i in 0..32) {
            assert!(*addr.borrow(i) == 0, 1);
        };
    }

    #[test]
    fun test_pad_svm_address_single_byte() {
        let addr = vector[0x42];
        pad_svm_address(&mut addr);
        assert!(addr.length() == 32, 0);
        // First 31 bytes should be zero, last byte should be 0x42
        for (i in 0..31) {
            assert!(*addr.borrow(i) == 0, 1);
        };
        assert!(*addr.borrow(31) == 0x42, 2);
    }

    #[test]
    fun test_pad_svm_address_partial() {
        let addr = vector[0x01, 0x02, 0x03, 0x04];
        pad_svm_address(&mut addr);
        assert!(addr.length() == 32, 0);
        // First 28 bytes should be zero, last 4 bytes should be the original data
        for (i in 0..28) {
            assert!(*addr.borrow(i) == 0, 1);
        };
        assert!(*addr.borrow(28) == 0x01, 2);
        assert!(*addr.borrow(29) == 0x02, 3);
        assert!(*addr.borrow(30) == 0x03, 4);
        assert!(*addr.borrow(31) == 0x04, 5);
    }

    #[test]
    fun test_pad_svm_address_exact_32_bytes() {
        let addr = vector[];
        for (i in 0..32) {
            addr.push_back((i as u8));
        };
        let original_addr = addr;
        pad_svm_address(&mut addr);
        assert!(addr.length() == 32, 0);
        // Should remain unchanged since it's already 32 bytes
        assert!(addr == original_addr, 1);
    }

    #[test]
    fun test_pad_svm_address_31_bytes() {
        let addr = vector[];
        for (i in 0..31) {
            addr.push_back((i as u8));
        };
        pad_svm_address(&mut addr);
        assert!(addr.length() == 32, 0);
        // First byte should be 0 (padding), rest should be the original data
        assert!(*addr.borrow(0) == 0, 1);
        for (i in 1..32) {
            assert!(*addr.borrow(i) == ((i - 1) as u8), 2);
        };
    }

    #[test]
    fun test_encode_svm_extra_args_v1_basic() {
        let token_receiver = vector[0x01, 0x02, 0x03];
        let accounts = vector[vector[0x04, 0x05], vector[0x06, 0x07, 0x08]];

        let result = encode_svm_extra_args_v1(
            1000u32, 0u64, true, token_receiver, accounts
        );

        // Verify the result starts with the correct tag
        let tag_len = SVM_EXTRA_ARGS_V1_TAG.length();
        for (i in 0..tag_len) {
            assert!(*result.borrow(i) == *SVM_EXTRA_ARGS_V1_TAG.borrow(i), 0);
        };

        // Result should be non-empty and contain the tag
        assert!(result.length() > tag_len, 1);
    }

    #[test]
    fun test_encode_svm_extra_args_v1_empty_accounts() {
        let token_receiver = vector[0xFF];
        let accounts = vector[];

        let result = encode_svm_extra_args_v1(
            500u32, 0u64, false, token_receiver, accounts
        );

        // Should not fail and should contain the tag
        let tag_len = SVM_EXTRA_ARGS_V1_TAG.length();
        assert!(result.length() > tag_len, 0);
    }

    #[test]
    fun test_encode_svm_extra_args_v1_32_byte_addresses() {
        let token_receiver = vector[];
        let account1 = vector[];
        let account2 = vector[];

        // Create exactly 32-byte addresses
        for (i in 0..32) {
            token_receiver.push_back((i as u8));
            account1.push_back(((i + 100) as u8));
            account2.push_back(((i + 200) as u8));
        };

        let accounts = vector[account1, account2];

        let result =
            encode_svm_extra_args_v1(
                2000u32,
                0xFFFFFFFFFFFFFFFFu64,
                true,
                token_receiver,
                accounts
            );

        // Should succeed without padding since addresses are already 32 bytes
        let tag_len = SVM_EXTRA_ARGS_V1_TAG.length();
        assert!(result.length() > tag_len, 0);
    }

    #[test]
    fun test_encode_svm_extra_args_v1_mixed_address_lengths() {
        let token_receiver = vector[0x11]; // 1 byte
        let accounts = vector[
            vector[0x22, 0x33], // 2 bytes
            vector[], // 0 bytes (empty)
            vector[0x44, 0x55, 0x66, 0x77, 0x88] // 5 bytes
        ];

        let result = encode_svm_extra_args_v1(
            750u32, 0u64, false, token_receiver, accounts
        );

        // All addresses should be padded to 32 bytes internally
        let tag_len = SVM_EXTRA_ARGS_V1_TAG.length();
        assert!(result.length() > tag_len, 0);
    }

    #[test]
    #[expected_failure(abort_code = 65537)]
    // E_INVALID_SVM_TOKEN_RECEIVER_LENGTH
    fun test_encode_svm_extra_args_v1_invalid_token_receiver_length() {
        // This test should fail because we're creating a token_receiver that's longer than 32 bytes
        let token_receiver = vector[];
        for (i in 0..33) { // 33 bytes - too long
            token_receiver.push_back((i as u8));
        };
        let accounts = vector[];
        encode_svm_extra_args_v1(1000u32, 0u64, true, token_receiver, accounts);
    }

    #[test]
    #[expected_failure(abort_code = 65538)]
    // E_INVALID_SVM_ACCOUNT_LENGTH
    fun test_encode_svm_extra_args_v1_invalid_account_length() {
        // This test should fail because we're creating an account that's longer than 32 bytes
        let token_receiver = vector[0x01];
        let long_account = vector[];
        for (i in 0..33) { // 33 bytes - too long
            long_account.push_back((i as u8));
        };
        let accounts = vector[long_account];

        encode_svm_extra_args_v1(1000u32, 0u64, true, token_receiver, accounts);
    }
}
