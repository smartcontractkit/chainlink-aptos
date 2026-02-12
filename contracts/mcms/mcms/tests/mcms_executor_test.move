#[test_only]
module mcms::mcms_executor_test {
    use std::signer;
    use std::string;
    use aptos_framework::account;
    use aptos_framework::chain_id;
    use aptos_framework::timestamp;

    use mcms::mcms;
    use mcms::mcms_account;
    use mcms::mcms_executor;

    const TIMESTAMP: u64 = 1724800000;
    const CHAIN_ID: u8 = 4;

    const TEST_ROLE: u8 = 1;
    const TEST_CHAIN_ID: u256 = 4;
    const TEST_NONCE: u64 = 0;

    const PROPOSER_ADDR1: vector<u8> = x"5916431f0ea809587757df994233861e1271be55";
    const PROPOSER_ADDR2: vector<u8> = x"8803c3ed076e57d51e28301933418094bd961cc5";
    const PROPOSER_ADDR3: vector<u8> = x"8950e6c6832c9b0591801418684d27b2853b2c74";

    const ROOT: vector<u8> = x"f7a8b0f28b2ae826313604377ecd0dd07dd4107e0777db5d251560aa2dbf760d";

    const TEST_PROOF: vector<vector<u8>> = vector[
        x"a619565e90c1c564293b59b344ed0e12ed06eafb3c45b70baf6fdf299a046297",
        x"951f1094081a858642cc6635f0885317828a7fddddd00668391c50f1e9e1bb66",
        x"597116801e22b18150f2abc4ca2ecd63e147bb67e24e4b5f900d49b909e1919f"
    ];

    const TEST_DATA_PART1: vector<u8> = x"0123456789abcdef0123456789abcdef";
    const TEST_DATA_PART2: vector<u8> = x"fedcba9876543210fedcba9876543210";

    const SIGNER_GROUPS: vector<u8> = vector[0, 0, 0];
    const GROUP_QUORUMS: vector<u8> = vector[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    const GROUP_PARENTS: vector<u8> = vector[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    #[test_only]
    fun setup(deployer: &signer, framework: &signer): address {
        // Create test accounts
        let deployer_addr = signer::address_of(deployer);
        account::create_account_for_test(deployer_addr);

        // Setup chain and timestamp
        timestamp::set_time_has_started_for_testing(framework);
        timestamp::update_global_time_for_test_secs(TIMESTAMP);
        chain_id::initialize_for_test(framework, CHAIN_ID);

        // Initialize modules
        mcms_account::init_module_for_testing(deployer);
        mcms::init_module_for_testing(deployer);

        deployer_addr
    }

    #[test(deployer = @mcms, framework = @aptos_framework, caller = @0x123)]
    public fun test_stage_data(
        deployer: &signer, framework: &signer, caller: &signer
    ) {
        // Setup the test environment
        setup(deployer, framework);

        // Create the caller account
        let caller_addr = signer::address_of(caller);
        account::create_account_for_test(caller_addr);

        // Stage the first data chunk
        mcms_executor::stage_data(caller, TEST_DATA_PART1, vector[]);

        // Stage the second data chunk and proofs
        mcms_executor::stage_data(caller, TEST_DATA_PART2, TEST_PROOF);

        // Clean up staged data to avoid test interference
        mcms_executor::clear_staged_data(caller);
    }

    #[test(deployer = @mcms, framework = @aptos_framework, caller = @0x123)]
    public fun test_clear_staged_data(
        deployer: &signer, framework: &signer, caller: &signer
    ) {
        // Setup the test environment
        setup(deployer, framework);

        // Create the caller account
        let caller_addr = signer::address_of(caller);
        account::create_account_for_test(caller_addr);

        // Stage some data
        mcms_executor::stage_data(caller, TEST_DATA_PART1, vector[]);

        // Clear the staged data
        mcms_executor::clear_staged_data(caller);

        // Stage new data to verify we can still use the module after clearing
        mcms_executor::stage_data(caller, TEST_DATA_PART2, vector[]);

        // Clean up again
        mcms_executor::clear_staged_data(caller);
    }

    #[test(
        deployer = @mcms,
        owner = @mcms_owner,
        framework = @aptos_framework,
        caller = @0x123
    )]
    #[expected_failure(abort_code = mcms::mcms::E_POST_OP_COUNT_REACHED, location = mcms::mcms)]
    public fun test_stage_data_and_execute_with_invalid_op_count(
        deployer: &signer, owner: &signer, framework: &signer, caller: &signer
    ) {
        setup(deployer, framework);

        let caller_addr = signer::address_of(caller);
        account::create_account_for_test(caller_addr);

        let role = mcms::proposer_role();
        mcms::set_config(
            owner,
            role,
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );

        mcms_executor::stage_data(caller, TEST_DATA_PART1, vector[]);

        mcms_executor::stage_data_and_execute(
            caller,
            role,
            TEST_CHAIN_ID,
            @mcms,
            TEST_NONCE,
            @mcms,
            string::utf8(b"mcms"),
            string::utf8(b"timelock_update_min_delay"),
            TEST_DATA_PART2,
            TEST_PROOF
        );
    }
}
