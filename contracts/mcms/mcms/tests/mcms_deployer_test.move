#[test_only]
module mcms::mcms_deployer_test {
    use std::signer;
    use aptos_framework::account;
    use aptos_framework::chain_id;
    use aptos_framework::timestamp;

    use mcms::object_code_util;

    use mcms::mcms_account;
    use mcms::mcms_deployer;
    use mcms::mcms_registry;

    const TIMESTAMP: u64 = 1724800000;
    const CHAIN_ID: u8 = 4;

    // Simulated metadata and code chunks (for test purposes only)
    const TEST_METADATA_CHUNK1: vector<u8> = x"0a0b0c0d0e0f"; // Simple mock metadata
    const TEST_METADATA_CHUNK2: vector<u8> = x"1a1b1c1d1e1f"; // Additional metadata

    const TEST_CODE_CHUNK1: vector<u8> = x"0123456789"; // Mock bytecode chunk 1
    const TEST_CODE_CHUNK2: vector<u8> = x"abcdef0123"; // Mock bytecode chunk 2
    const TEST_CODE_CHUNK3: vector<u8> = x"456789abcd"; // Mock bytecode chunk 3

    const TEST_OBJECT_SEED: vector<u8> = x"deadbeef";

    #[test_only]
    fun setup(deployer: &signer, owner: &signer, framework: &signer): address {
        let deployer_addr = signer::address_of(deployer);
        let owner_addr = signer::address_of(owner);
        account::create_account_for_test(deployer_addr);
        account::create_account_for_test(owner_addr);

        timestamp::set_time_has_started_for_testing(framework);
        timestamp::update_global_time_for_test_secs(TIMESTAMP);
        chain_id::initialize_for_test(framework, CHAIN_ID);

        mcms_account::init_module_for_testing(deployer);
        mcms_registry::init_module_for_testing(deployer);

        deployer_addr
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_stage_code_chunk(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        // Stage a code chunk for the first module (index 0)
        let code_indices1 = vector[0u16, 1u16];
        let code_chunks1 = vector[TEST_CODE_CHUNK1, TEST_CODE_CHUNK2];
        mcms_deployer::stage_code_chunk(
            owner,
            TEST_METADATA_CHUNK1,
            code_indices1,
            code_chunks1
        );

        // Stage additional code chunks
        let code_indices2 = vector[0u16, 2u16];
        let code_chunks2 = vector[TEST_CODE_CHUNK2, TEST_CODE_CHUNK3];
        mcms_deployer::stage_code_chunk(
            owner,
            TEST_METADATA_CHUNK2,
            code_indices2,
            code_chunks2
        );

        // Clean up after testing
        mcms_deployer::cleanup_staging_area(owner);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_cleanup_staging_area(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        // Setup the test environment
        setup(deployer, owner, framework);

        // Stage some code chunks
        let code_indices = vector[0u16];
        let code_chunks = vector[TEST_CODE_CHUNK1];
        mcms_deployer::stage_code_chunk(
            owner,
            TEST_METADATA_CHUNK1,
            code_indices,
            code_chunks
        );

        // Clean up the staging area
        mcms_deployer::cleanup_staging_area(owner);

        // Stage again to verify we can use the module after cleaning
        mcms_deployer::stage_code_chunk(
            owner,
            TEST_METADATA_CHUNK2,
            code_indices,
            code_chunks
        );

        // Final cleanup
        mcms_deployer::cleanup_staging_area(owner);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_stage_code_chunk_and_publish_to_object(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        // Prepare code chunks for publishing
        let (metadata, code) = object_code_util::test_metadata_and_code();

        // This will try to publish the mock code to a new object
        mcms_deployer::stage_code_chunk_and_publish_to_object(
            owner,
            metadata,
            vector[0, 1],
            code,
            TEST_OBJECT_SEED
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure]
    // Will fail due to missing code object/invalid bytecode
    public fun test_stage_code_chunk_and_upgrade_object_code(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        // Setup the test environment
        setup(deployer, owner, framework);

        // Get a hypothetical object address to upgrade
        let object_address = mcms_registry::get_new_code_object_address(TEST_OBJECT_SEED);

        // Prepare code chunks for upgrading
        let code_indices = vector[0u16, 1u16];
        let code_chunks = vector[TEST_CODE_CHUNK1, TEST_CODE_CHUNK2];

        // This will fail because the object doesn't exist and bytecode isn't valid,
        // but it will exercise the code paths in mcms_deployer
        mcms_deployer::stage_code_chunk_and_upgrade_object_code(
            owner,
            TEST_METADATA_CHUNK1,
            code_indices,
            code_chunks,
            object_address
        );
    }
}
