#[test_only]
module mcms::mcms_registry_test {
    use std::signer;
    use std::string::{Self};
    use std::vector;
    use std::object::{Self};
    use std::code::{PackageRegistry};
    use std::option::{Self};
    use aptos_framework::account;
    use aptos_framework::chain_id;
    use aptos_framework::timestamp;
    use mcms::object_code_util;
    use mcms::mcms_registry;
    use mcms::mcms_account;

    const TIMESTAMP: u64 = 1724800000;
    const CHAIN_ID: u8 = 4;

    struct ModuleProof has drop {}

    struct TestCallback has drop {
        data: vector<u8>
    }

    public fun setup(
        framework: &signer, test_account: &signer, owner: &signer
    ): address {
        let test_addr = signer::address_of(test_account);
        let owner_addr = signer::address_of(owner);
        account::create_account_for_test(test_addr);
        account::create_account_for_test(owner_addr);

        timestamp::set_time_has_started_for_testing(framework);
        timestamp::update_global_time_for_test_secs(TIMESTAMP);
        chain_id::initialize_for_test(framework, CHAIN_ID);

        test_addr
    }

    #[test(test_account = @0xabc, owner = @mcms_owner, framework = @0x1)]
    public fun test_get_new_code_object_owner_address(
        test_account: &signer, owner: &signer, framework: &signer
    ) {
        let _test_addr = setup(framework, test_account, owner);

        let seed = b"test_seed";
        let address = mcms_registry::get_new_code_object_owner_address(seed);

        assert!(address != @0x0, 0);
    }

    #[test(test_account = @0xabc, owner = @mcms_owner, framework = @0x1)]
    public fun test_get_new_code_object_address(
        test_account: &signer, owner: &signer, framework: &signer
    ) {
        let _test_addr = setup(framework, test_account, owner);

        let seed = b"test_seed";
        let address = mcms_registry::get_new_code_object_address(seed);

        assert!(address != @0x0, 0);
    }

    #[test(
        mcms = @mcms, test_account = @0xabc, owner = @mcms_owner, framework = @0x1
    )]
    public fun test_dispatch_functionality(
        mcms: &signer, owner: &signer, framework: &signer
    ) {
        setup(framework, mcms, owner);
        mcms_account::init_module_for_testing(mcms);
        mcms_registry::init_module_for_testing(mcms);

        let module_name = string::utf8(b"mcms_registry_test");
        let _owner_addr =
            mcms_registry::register_entrypoint(mcms, module_name, ModuleProof {});

        let account_addr = signer::address_of(mcms);
        let function_name = string::utf8(b"test_function");
        let dispatch_data = b"test_data";

        let _metadata =
            mcms_registry::test_start_dispatch(
                account_addr,
                module_name,
                function_name,
                dispatch_data
            );

        let (_callback_signer, callback_function, callback_data) =
            mcms_registry::get_callback_params<ModuleProof>(account_addr, ModuleProof {});

        assert!(callback_function == function_name, 1);
        assert!(callback_data == dispatch_data, 2);

        mcms_registry::test_finish_dispatch(account_addr);
    }

    #[test(
        mcms = @mcms, test_account = @0xabc, owner = @mcms_owner, framework = @0x1
    )]
    #[expected_failure(abort_code = 65541, location = mcms_registry)]
    public fun test_duplicate_dispatch_fails(
        mcms: &signer, test_account: &signer, owner: &signer, framework: &signer
    ) {
        setup(framework, test_account, owner);
        mcms_registry::init_module_for_testing(mcms);
        mcms_account::init_module_for_testing(mcms);

        let module_name = string::utf8(b"mcms_registry_test");
        mcms_registry::register_entrypoint<ModuleProof>(
            test_account, module_name, ModuleProof {}
        );

        // Try to register the same module again - should fail with E_MODULE_ALREADY_REGISTERED
        mcms_registry::register_entrypoint<ModuleProof>(
            test_account, module_name, ModuleProof {}
        );
    }

    #[test(
        mcms = @mcms, test_account = @0xabc, owner = @mcms_owner, framework = @0x1
    )]
    #[expected_failure(abort_code = 65541, location = mcms_registry)]
    public fun test_wrong_proof_type_fails(
        mcms: &signer, test_account: &signer, owner: &signer, framework: &signer
    ) {
        // Setup
        setup(framework, test_account, owner);
        mcms_registry::init_module_for_testing(mcms);
        mcms_account::init_module_for_testing(mcms);

        // Register with one proof type (use a unique name for this test)
        let module_name = string::utf8(b"test_module_wrong_proof_type");
        let _owner_addr =
            mcms_registry::register_entrypoint<ModuleProof>(
                test_account, module_name, ModuleProof {}
            );

        // Start dispatch to set up callback params
        let account_addr = signer::address_of(test_account);
        let function_name = string::utf8(b"test_function");
        let dispatch_data = b"test_data";
        mcms_registry::test_start_dispatch(
            account_addr,
            module_name,
            function_name,
            dispatch_data
        );

        // Try to get callback params with different proof type
        mcms_registry::get_callback_params<TestCallback>(
            account_addr, TestCallback { data: vector::empty() }
        );
    }

    #[test(
        mcms = @mcms, test_account = @0xabc, owner = @mcms_owner, framework = @0x1
    )]
    #[expected_failure(abort_code = 65541, location = mcms_registry)]
    public fun test_missing_callback_params_fails(
        mcms: &signer, test_account: &signer, owner: &signer, framework: &signer
    ) {
        // Setup
        setup(framework, test_account, owner);
        mcms_registry::init_module_for_testing(mcms);
        mcms_account::init_module_for_testing(mcms);

        // Register module (use a unique name for this test)
        let module_name = string::utf8(b"test_module_missing_params");
        mcms_registry::register_entrypoint<ModuleProof>(
            test_account, module_name, ModuleProof {}
        );

        // Try to get callback params without starting dispatch
        let account_addr = signer::address_of(test_account);
        mcms_registry::get_callback_params<ModuleProof>(account_addr, ModuleProof {});
    }

    #[test(
        mcms = @mcms, test_account = @0xabc, owner = @mcms_owner, framework = @0x1
    )]
    #[expected_failure(abort_code = 65541, location = mcms_registry)]
    public fun test_finish_dispatch_without_consuming_params_fails(
        mcms: &signer, test_account: &signer, owner: &signer, framework: &signer
    ) {
        setup(framework, test_account, owner);
        mcms_registry::init_module_for_testing(mcms);
        mcms_account::init_module_for_testing(mcms);

        // Register module (use a unique name for this test)
        let module_name = string::utf8(b"test_module_finish_without_consuming");
        mcms_registry::register_entrypoint<ModuleProof>(
            test_account, module_name, ModuleProof {}
        );

        // Start dispatch
        let account_addr = signer::address_of(test_account);
        let function_name = string::utf8(b"test_function");
        let dispatch_data = b"test_data";
        mcms_registry::test_start_dispatch(
            account_addr,
            module_name,
            function_name,
            dispatch_data
        );

        // Try to finish dispatch without consuming params - should fail with E_CALLBACK_PARAMS_NOT_CONSUMED
        mcms_registry::test_finish_dispatch(account_addr);
    }

    #[test(
        mcms = @mcms, test_account = @0xabc, owner = @mcms_owner, framework = @0x1
    )]
    #[expected_failure(abort_code = 65544, location = mcms_registry)]
    public fun test_register_with_empty_module_name_fails(
        mcms: &signer, test_account: &signer, owner: &signer, framework: &signer
    ) {
        setup(framework, test_account, owner);
        mcms_registry::init_module_for_testing(mcms);
        mcms_account::init_module_for_testing(mcms);

        // Try to register with empty module name
        mcms_registry::register_entrypoint<ModuleProof>(
            test_account, string::utf8(b""), ModuleProof {}
        );
    }

    #[test(
        mcms = @mcms, test_account = @0xabc, owner = @mcms_owner, framework = @0x1
    )]
    #[expected_failure(abort_code = 65545, location = mcms_registry)]
    public fun test_register_with_too_long_module_name_fails(
        mcms: &signer, test_account: &signer, owner: &signer, framework: &signer
    ) {
        // Setup
        setup(framework, test_account, owner);
        mcms_registry::init_module_for_testing(mcms);
        mcms_account::init_module_for_testing(mcms);

        // Create a module name longer than 64 bytes
        let long_name = vector::empty<u8>();
        let i = 0;
        while (i < 65) {
            vector::push_back(&mut long_name, 97); // 'a'
            i = i + 1;
        };

        // Try to register with too long module name
        mcms_registry::register_entrypoint<ModuleProof>(
            test_account, string::utf8(long_name), ModuleProof {}
        );
    }

    #[test(
        mcms = @mcms, test_account = @0xabc, owner = @mcms_owner, framework = @0x1
    )]
    #[expected_failure(abort_code = 65541, location = mcms::mcms_registry)]
    public fun test_register_duplicate_module_fails_same_account(
        mcms: &signer, test_account: &signer, owner: &signer, framework: &signer
    ) {
        // Setup
        setup(framework, test_account, owner);
        mcms_registry::init_module_for_testing(mcms);
        mcms_account::init_module_for_testing(mcms);

        // Register module first time
        let module_name = string::utf8(b"test_module");
        mcms_registry::register_entrypoint<ModuleProof>(
            test_account, module_name, ModuleProof {}
        );

        // Try to register the same module name again - should fail with E_MODULE_ALREADY_REGISTERED
        mcms_registry::register_entrypoint<ModuleProof>(
            test_account, module_name, ModuleProof {}
        );
    }

    #[test(
        mcms = @mcms, test_account = @0xabc, owner = @mcms_owner, framework = @0x1
    )]
    #[expected_failure(abort_code = 65547, location = mcms::mcms_registry)]
    public fun test_invalid_code_object_fails(
        mcms: &signer, test_account: &signer, owner: &signer, framework: &signer
    ) {
        setup(framework, test_account, owner);
        mcms_registry::init_module_for_testing(mcms);
        mcms_account::init_module_for_testing(mcms);

        // Fails with E_INVALID_CODE_OBJECT
        mcms_registry::accept_code_object(test_account, @0x12345);
    }

    #[test(
        mcms = @mcms, test_account = @0xabc, owner = @mcms_owner, framework = @0x1
    )]
    #[expected_failure(abort_code = 65546, location = mcms::mcms_registry)]
    public fun test_get_registered_owner_address_not_registered(
        mcms: &signer, test_account: &signer, owner: &signer, framework: &signer
    ) {
        setup(framework, test_account, owner);
        mcms_registry::init_module_for_testing(mcms);
        mcms_account::init_module_for_testing(mcms);

        // Try to get owner for unregistered address - should fail with E_ADDRESS_NOT_REGISTERED
        mcms_registry::get_registered_owner_address(@0x12345);
    }

    #[test(
        mcms = @mcms, test_account = @0xabc, owner = @mcms_owner, framework = @0x1
    )]
    #[expected_failure(abort_code = 65547, location = mcms::mcms_registry)]
    public fun test_is_owned_code_object_invalid_object(
        mcms: &signer, test_account: &signer, owner: &signer, framework: &signer
    ) {
        setup(framework, test_account, owner);
        mcms_registry::init_module_for_testing(mcms);
        mcms_account::init_module_for_testing(mcms);

        // Should fail with E_INVALID_CODE_OBJECT since address doesn't exist as an object
        mcms_registry::is_owned_code_object(@0x12345);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @0x1)]
    #[expected_failure(abort_code = 196623, location = mcms::mcms_registry)]
    public fun test_transfer_code_object_no_pending_transfer(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(framework, deployer, owner);
        mcms_registry::init_module_for_testing(deployer);
        mcms_account::init_module_for_testing(deployer);

        let (metadata, code) = object_code_util::test_metadata_and_code();
        let object_address = object_code_util::publish_code_object(owner, metadata, code);
        mcms_registry::create_owner_for_preexisting_code_object(owner, object_address);
        let owner_address =
            mcms_registry::get_preexisting_code_object_owner_address(object_address);
        object::transfer(
            owner,
            object::address_to_object<PackageRegistry>(object_address),
            owner_address
        );
        mcms_registry::transfer_code_object(owner, object_address, owner_address);

        mcms_registry::move_from_owner_transfers(owner_address);
        // Fails with E_NO_PENDING_TRANSFER
        mcms_registry::accept_code_object(deployer, object_address);
    }

    // Test Module MCMS Entrypoint
    public fun mcms_entrypoint<T: key>(_metadata: object::Object<T>): option::Option<u128> {
        option::none()
    }
}
