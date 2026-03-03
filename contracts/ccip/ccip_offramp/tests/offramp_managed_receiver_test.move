#[test_only]
module ccip_offramp::offramp_managed_receiver_test {
    use std::account;
    use std::fungible_asset;
    use std::object;
    use std::primary_fungible_store;
    use std::signer;
    use std::bcs;
    use std::string;
    use std::timestamp;

    use ccip_offramp::offramp_test;
    use ccip_offramp::offramp;
    use ccip_offramp::mock_ccip_receiver;
    use ccip::receiver_registry;
    use managed_token::managed_token;
    use managed_token_pool::managed_token_pool;

    const MANAGED_TOKEN_POOL: u8 = 2;
    const MANAGED_TOKEN_SEED: vector<u8> = b"ManagedToken";

    const EVM_SOURCE_CHAIN_SELECTOR: u64 = 909606746561742123;
    const MOCK_EVM_ADDRESS_VECTOR: vector<u8> = x"4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97";
    const EVM_SENDER: vector<u8> = x"d87929a32cf0cbdc9e2d07ffc7c33344079de727";
    const GAS_LIMIT: u64 = 1000000;

    fun setup_mock_ccip_receiver(owner: &signer, ccip_offramp: &signer) {
        account::create_account_if_does_not_exist(signer::address_of(ccip_offramp));
        receiver_registry::init_module_for_testing(owner);
        mock_ccip_receiver::test_init_module(ccip_offramp);
    }

    struct TestMessage has drop {
        message: offramp::Any2AptosRampMessage,
        merkle_root: vector<u8>,
        proofs: vector<vector<u8>>
    }

    fun create_and_commit_message(
        message_id: vector<u8>,
        sequence_number: u64,
        receiver: address,
        data: vector<u8>,
        token_amounts: vector<offramp::Any2AptosTokenTransfer>
    ): TestMessage {
        let static_config = offramp::get_static_config();
        let dest_chain_selector = offramp::chain_selector(&static_config);

        let header =
            offramp::test_create_ramp_message_header(
                message_id,
                EVM_SOURCE_CHAIN_SELECTOR,
                dest_chain_selector,
                sequence_number,
                0
            );

        let message =
            offramp::test_create_any2aptos_ramp_message(
                header,
                EVM_SENDER,
                data,
                receiver,
                (GAS_LIMIT as u256),
                token_amounts
            );

        let source_chain_config =
            offramp::get_source_chain_config(EVM_SOURCE_CHAIN_SELECTOR);
        let on_ramp = offramp::source_chain_config_on_ramp(&source_chain_config);

        let metadata_hash =
            offramp::test_calculate_metadata_hash(
                EVM_SOURCE_CHAIN_SELECTOR, dest_chain_selector, on_ramp
            );

        let message_hash = offramp::test_calculate_message_hash(&message, metadata_hash);
        let merkle_root = message_hash;
        let proofs = vector[];

        offramp::test_add_root(merkle_root, timestamp::now_seconds() - 3700);

        TestMessage { message, merkle_root, proofs }
    }

    fun execute_message_and_verify_success(
        sequence_number: u64,
        test_message: TestMessage,
        offchain_token_data: vector<vector<u8>>
    ) {
        let TestMessage { message, merkle_root: _, proofs } = test_message;

        let report =
            offramp::test_create_execution_report(
                EVM_SOURCE_CHAIN_SELECTOR,
                message,
                offchain_token_data,
                proofs
            );

        offramp::test_execute_single_report(report);

        let execution_state =
            offramp::get_execution_state(EVM_SOURCE_CHAIN_SELECTOR, sequence_number);
        assert!(execution_state == 2);
    }

    // ======================== NON DISPATCHABLE TESTS ========================
    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_offramp = @ccip_offramp,
            owner = @admin,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            managed_token_pool = @managed_token_pool,
            managed_token = @managed_token,
            regulated_token_pool = @regulated_token_pool,
            regulated_token = @regulated_token
        )
    ]
    fun test_execute_non_dispatchable_token_transfer_only(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer
    ) {
        let (_owner_addr, token_obj) =
            offramp_test::setup(
                aptos_framework,
                ccip,
                ccip_offramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                managed_token_pool,
                managed_token,
                regulated_token_pool,
                regulated_token,
                MANAGED_TOKEN_POOL,
                MANAGED_TOKEN_SEED,
                false, // is_dispatchable
                false // use_v1_init
            );
        let token_addr = object::object_address(&token_obj);

        setup_mock_ccip_receiver(owner, ccip_offramp);

        // Add to allowlist for release_or_mint
        let pool_address = managed_token_pool::get_store_address();
        managed_token::apply_allowed_minter_updates(
            owner, vector[], vector[pool_address]
        );

        // Add to allowlist for lock_or_burn
        let pool_address = managed_token_pool::get_store_address();
        managed_token::apply_allowed_burner_updates(
            owner, vector[], vector[pool_address]
        );

        // // Grant receiver state signer minter and burner role for transfer during forwarding
        // let state_address = managed_dispatchable_receiver::get_state_address();
        // managed_token::apply_allowed_minter_updates(owner, vector[], vector[state_address]);
        // managed_token::apply_allowed_burner_updates(owner, vector[], vector[state_address]);

        let token_amounts =
            offramp::test_create_any2aptos_token_transfer(
                MOCK_EVM_ADDRESS_VECTOR,
                token_addr,
                1000000,
                vector[],
                100000
            );

        let test_message =
            create_and_commit_message(
                x"0000000000000000000000000000000000000000000000000000000000000004",
                4, // sequence number
                @ccip_offramp, // receiver
                vector[],
                vector[token_amounts]
            );

        execute_message_and_verify_success(4, test_message, vector[vector[]]);

        let token_obj = object::address_to_object<fungible_asset::Metadata>(token_addr);
        let receiver_store =
            primary_fungible_store::primary_store(@ccip_offramp, token_obj);
        let receiver_balance = fungible_asset::balance(receiver_store);
        assert!(receiver_balance == 100000);

        let tokens_only_events = mock_ccip_receiver::get_received_tokens_only_events();
        assert!(tokens_only_events.length() == 1);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_offramp = @ccip_offramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            managed_token_pool = @managed_token_pool,
            managed_token = @managed_token,
            regulated_token_pool = @regulated_token_pool,
            regulated_token = @regulated_token
        )
    ]
    fun test_execute_non_dispatchable_message_only(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer
    ) {
        let (_owner_addr, _token_obj) =
            offramp_test::setup(
                aptos_framework,
                ccip,
                ccip_offramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                managed_token_pool,
                managed_token,
                regulated_token_pool,
                regulated_token,
                MANAGED_TOKEN_POOL,
                MANAGED_TOKEN_SEED,
                false, // is_dispatchable
                false // use_v1_init
            );

        setup_mock_ccip_receiver(owner, ccip_offramp);

        // Add to allowlist for lock_or_burn/release_or_mint
        let pool_address = managed_token_pool::get_store_address();
        managed_token::apply_allowed_burner_updates(
            owner, vector[], vector[pool_address]
        );
        managed_token::apply_allowed_minter_updates(
            owner, vector[], vector[pool_address]
        );

        let test_data = b"Hello from EVM chain!";
        let test_message =
            create_and_commit_message(
                x"0000000000000000000000000000000000000000000000000000000000000002",
                2,
                @ccip_offramp, // receiver
                test_data,
                vector[]
            );

        execute_message_and_verify_success(2, test_message, vector[]);

        let received_events = mock_ccip_receiver::get_received_message_events();
        assert!(received_events.length() == 1);

        let event = received_events.borrow(0);
        let event_message = mock_ccip_receiver::received_message_get_message(event);
        assert!(event_message == string::utf8(test_data));
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_offramp = @ccip_offramp,
            owner = @0x100,
            recipient = @0x999,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            managed_token_pool = @managed_token_pool,
            managed_token = @managed_token,
            regulated_token_pool = @regulated_token_pool,
            regulated_token = @regulated_token
        )
    ]
    fun test_receiver_non_dispatchable_tokens_with_forwarding(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        recipient: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer
    ) {
        let (_owner_addr, token_obj) =
            offramp_test::setup(
                aptos_framework,
                ccip,
                ccip_offramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                managed_token_pool,
                managed_token,
                regulated_token_pool,
                regulated_token,
                MANAGED_TOKEN_POOL,
                MANAGED_TOKEN_SEED,
                false, // is_dispatchable
                false // use_v1_init
            );
        let token_addr = object::object_address(&token_obj);

        setup_mock_ccip_receiver(owner, ccip_offramp);

        // Add to allowlist for lock_or_burn/release_or_mint
        let pool_address = managed_token_pool::get_store_address();
        managed_token::apply_allowed_burner_updates(
            owner, vector[], vector[pool_address]
        );
        managed_token::apply_allowed_minter_updates(
            owner, vector[], vector[pool_address]
        );

        let recipient_addr = signer::address_of(recipient);
        account::create_account_for_test(recipient_addr);

        // Sending 200,000 tokens to receiver contract first
        let token_amounts =
            offramp::test_create_any2aptos_token_transfer(
                MOCK_EVM_ADDRESS_VECTOR,
                token_addr,
                1000000,
                vector[],
                200000
            );

        let test_data = bcs::to_bytes(&recipient_addr);
        let test_message =
            create_and_commit_message(
                x"0000000000000000000000000000000000000000000000000000000000000003",
                3, // sequence number
                @ccip_offramp, // receiver
                test_data,
                vector[token_amounts]
            );

        execute_message_and_verify_success(3, test_message, vector[vector[]]);

        let token_obj = object::address_to_object<fungible_asset::Metadata>(token_addr);

        let receiver_store =
            primary_fungible_store::primary_store(@ccip_offramp, token_obj);
        let receiver_balance = fungible_asset::balance(receiver_store);
        assert!(receiver_balance == 0);

        let recipient_store =
            primary_fungible_store::primary_store(recipient_addr, token_obj);
        let recipient_balance = fungible_asset::balance(recipient_store);
        assert!(recipient_balance == 200000);

        let forwarded_events = mock_ccip_receiver::get_forwarded_tokens_events();
        assert!(forwarded_events.length() == 1);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_offramp = @ccip_offramp,
            owner = @admin,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            managed_token_pool = @managed_token_pool,
            managed_token = @managed_token,
            regulated_token_pool = @regulated_token_pool,
            regulated_token = @regulated_token
        )
    ]
    fun test_execute_dispatchable_token_transfer_only(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer
    ) {
        let (_owner_addr, token_obj) =
            offramp_test::setup(
                aptos_framework,
                ccip,
                ccip_offramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                managed_token_pool,
                managed_token,
                regulated_token_pool,
                regulated_token,
                MANAGED_TOKEN_POOL,
                MANAGED_TOKEN_SEED,
                true, // is_dispatchable
                false // use_v1_init
            );
        let token_addr = object::object_address(&token_obj);

        setup_mock_ccip_receiver(owner, ccip_offramp);

        // Add to allowlist for lock_or_burn/release_or_mint
        let pool_address = managed_token_pool::get_store_address();
        managed_token::apply_allowed_minter_updates(
            owner, vector[], vector[pool_address]
        );
        managed_token::apply_allowed_burner_updates(
            owner, vector[], vector[pool_address]
        );

        // Grant receiver state signer minter and burner role for transfer during forwarding
        let state_address = mock_ccip_receiver::get_state_address();
        managed_token::apply_allowed_minter_updates(
            owner, vector[], vector[state_address]
        );
        managed_token::apply_allowed_burner_updates(
            owner, vector[], vector[state_address]
        );

        let token_amounts =
            offramp::test_create_any2aptos_token_transfer(
                MOCK_EVM_ADDRESS_VECTOR,
                token_addr,
                1000000,
                vector[],
                100000
            );

        let test_message =
            create_and_commit_message(
                x"0000000000000000000000000000000000000000000000000000000000000004",
                4, // sequence number
                @ccip_offramp, // receiver
                vector[],
                vector[token_amounts]
            );

        execute_message_and_verify_success(4, test_message, vector[vector[]]);

        let token_obj = object::address_to_object<fungible_asset::Metadata>(token_addr);
        let receiver_store =
            primary_fungible_store::primary_store(@ccip_offramp, token_obj);
        let receiver_balance = fungible_asset::balance(receiver_store);
        assert!(receiver_balance == 100000);

        let tokens_only_events = mock_ccip_receiver::get_received_tokens_only_events();
        assert!(tokens_only_events.length() == 1);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_offramp = @ccip_offramp,
            owner = @admin,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            managed_token_pool = @managed_token_pool,
            managed_token = @managed_token,
            regulated_token_pool = @regulated_token_pool,
            regulated_token = @regulated_token
        )
    ]
    fun test_execute_dispatchable_message_only(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer
    ) {
        let (_owner_addr, _token_obj) =
            offramp_test::setup(
                aptos_framework,
                ccip,
                ccip_offramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                managed_token_pool,
                managed_token,
                regulated_token_pool,
                regulated_token,
                MANAGED_TOKEN_POOL,
                MANAGED_TOKEN_SEED,
                true, // is_dispatchable
                false // use_v1_init
            );

        setup_mock_ccip_receiver(owner, ccip_offramp);

        let test_data = b"Hello from EVM chain!";
        let test_message =
            create_and_commit_message(
                x"0000000000000000000000000000000000000000000000000000000000000005",
                5, // sequence number
                @ccip_offramp, // receiver
                test_data,
                vector[]
            );

        execute_message_and_verify_success(5, test_message, vector[]);

        let received_events = mock_ccip_receiver::get_received_message_events();
        assert!(received_events.length() == 1);

        let event = received_events.borrow(0);
        let event_message = mock_ccip_receiver::received_message_get_message(event);
        assert!(event_message == string::utf8(test_data));
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_offramp = @ccip_offramp,
            owner = @admin,
            recipient = @0x999,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            managed_token_pool = @managed_token_pool,
            managed_token = @managed_token,
            regulated_token_pool = @regulated_token_pool,
            regulated_token = @regulated_token
        )
    ]
    fun test_receiver_dispatchable_tokens_with_forwarding(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        recipient: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer
    ) {
        let (_owner_addr, token_obj) =
            offramp_test::setup(
                aptos_framework,
                ccip,
                ccip_offramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                managed_token_pool,
                managed_token,
                regulated_token_pool,
                regulated_token,
                MANAGED_TOKEN_POOL,
                MANAGED_TOKEN_SEED,
                true, // is_dispatchable
                false // use_v1_init
            );
        let token_addr = object::object_address(&token_obj);

        setup_mock_ccip_receiver(owner, ccip_offramp);

        // Add to allowlist for lock_or_burn/release_or_mint
        let pool_address = managed_token_pool::get_store_address();
        managed_token::apply_allowed_minter_updates(
            owner, vector[], vector[pool_address]
        );
        managed_token::apply_allowed_burner_updates(
            owner, vector[], vector[pool_address]
        );

        // Grant receiver state signer BRIDGE_MINTER_OR_BURNER_ROLE (role 6) for transfer during forwarding
        let state_address = mock_ccip_receiver::get_state_address();
        managed_token::apply_allowed_minter_updates(
            owner, vector[], vector[state_address]
        );
        managed_token::apply_allowed_burner_updates(
            owner, vector[], vector[state_address]
        );

        let recipient_addr = signer::address_of(recipient);
        account::create_account_for_test(recipient_addr);

        let token_amounts =
            offramp::test_create_any2aptos_token_transfer(
                MOCK_EVM_ADDRESS_VECTOR,
                token_addr,
                1000000,
                vector[],
                200000
            );

        let test_data = bcs::to_bytes(&recipient_addr);
        let test_message =
            create_and_commit_message(
                x"0000000000000000000000000000000000000000000000000000000000000006",
                6, // sequence number
                @ccip_offramp, // receiver
                test_data,
                vector[token_amounts]
            );

        execute_message_and_verify_success(6, test_message, vector[vector[]]);

        let token_obj = object::address_to_object<fungible_asset::Metadata>(token_addr);

        let receiver_store =
            primary_fungible_store::primary_store(@ccip_offramp, token_obj);
        let receiver_balance = fungible_asset::balance(receiver_store);
        assert!(receiver_balance == 0);

        let recipient_store =
            primary_fungible_store::primary_store(recipient_addr, token_obj);
        let recipient_balance = fungible_asset::balance(recipient_store);
        assert!(recipient_balance == 200000);

        let forwarded_events = mock_ccip_receiver::get_forwarded_tokens_events();
        assert!(forwarded_events.length() == 1);
    }
}
