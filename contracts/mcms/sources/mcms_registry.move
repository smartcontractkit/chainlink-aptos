module mcms::mcms_registry {
    use std::account::{Self, SignerCapability};
    use std::bcs;
    use std::code::PackageRegistry;
    use std::dispatchable_fungible_asset;
    use std::error;
    use std::function_info::{Self, FunctionInfo};
    use std::fungible_asset::{Self, Metadata};
    use std::object::{Self, ExtendRef, Object};
    use std::option;
    use std::signer;
    use std::smart_table::{Self, SmartTable};
    use std::string::{Self, String};
    use std::type_info::{Self, TypeInfo};
    use std::vector;

    use mcms::mcms_account;

    friend mcms::mcms;
    friend mcms::mcms_deployer;

    const EXISTING_OBJECT_REGISTRATION_SEED: vector<u8> = b"CHAINLINK_MCMS_EXISTING_OBJECT_REGISTRATION";
    const NEW_OBJECT_REGISTRATION_SEED: vector<u8> = b"CHAINLINK_MCMS_NEW_OBJECT_REGISTRATION";
    const DISPATCH_OBJECT_SEED: vector<u8> = b"CHAINLINK_MCMS_DISPATCH_OBJECT";

    // https://github.com/aptos-labs/aptos-core/blob/7fc73792e9db11462c9a42038c4a9eb41cc00192/aptos-move/framework/aptos-framework/sources/object_code_deployment.move#L53
    const OBJECT_CODE_DEPLOYMENT_DOMAIN_SEPARATOR: vector<u8> = b"aptos_framework::object_code_deployment";

    struct RegistryState has key {
        // preregistered code object and/or registered callback address -> owner/signer address
        registered_addresses: SmartTable<address, address>
    }

    struct OwnerRegistration has key {
        owner_seed: vector<u8>,
        owner_cap: SignerCapability,
        is_preregistered: bool,

        // module name -> registered module
        callback_modules: SmartTable<vector<u8>, RegisteredModule>
    }

    struct RegisteredModule has store, drop {
        callback_function_info: FunctionInfo,
        proof_type_info: TypeInfo,
        dispatch_metadata: Object<Metadata>,
        dispatch_extend_ref: ExtendRef
    }

    struct ExecutingCallbackParams has key {
        expected_type_info: TypeInfo,
        function: String,
        data: vector<u8>
    }

    const E_CALLBACK_PARAMS_ALREADY_EXISTS: u64 = 1;
    const E_MISSING_CALLBACK_PARAMS: u64 = 2;
    const E_WRONG_PROOF_TYPE: u64 = 3;
    const E_CALLBACK_PARAMS_NOT_CONSUMED: u64 = 4;
    const E_PROOF_NOT_AT_ACCOUNT_ADDRESS: u64 = 5;
    const E_PROOF_NOT_IN_MODULE: u64 = 6;
    const E_MODULE_ALREADY_REGISTERED: u64 = 7;
    const E_EMPTY_MODULE_NAME: u64 = 8;
    const E_MODULE_NAME_TOO_LONG: u64 = 9;
    const E_NOT_REGISTERED: u64 = 10;
    const E_INVALID_CODE_OBJECT: u64 = 11;
    const E_OWNER_ALREADY_REGISTERED: u64 = 12;
    const E_NOT_CODE_OBJECT_OWNER: u64 = 13;

    fun init_module(publisher: &signer) {
        move_to(publisher, RegistryState { registered_addresses: smart_table::new() });
    }

    #[view]
    public fun get_new_code_object_owner_address(
        new_owner_seed: vector<u8>
    ): address {
        let owner_seed = NEW_OBJECT_REGISTRATION_SEED;
        vector::append(&mut owner_seed, new_owner_seed);
        account::create_resource_address(&@mcms, owner_seed)
    }

    #[view]
    public fun get_new_code_object_address(new_owner_seed: vector<u8>): address {
        let object_owner_address = get_new_code_object_owner_address(new_owner_seed);
        let object_code_deployment_seed =
            bcs::to_bytes(&OBJECT_CODE_DEPLOYMENT_DOMAIN_SEPARATOR);
        vector::append(&mut object_code_deployment_seed, bcs::to_bytes(&1u64));
        object::create_object_address(
            &object_owner_address, object_code_deployment_seed
        )
    }

    #[view]
    public fun get_existing_code_object_owner_address(
        object_address: address
    ): address {
        let owner_seed = EXISTING_OBJECT_REGISTRATION_SEED;
        vector::append(&mut owner_seed, bcs::to_bytes(&object_address));
        account::create_resource_address(&@mcms, owner_seed)
    }

    /// Imports a code object (ie. managed by 0x1::code_object_deployment) that was not deployed
    /// using mcms_deployer, and has not registered for a callback, to be owned by MCMS.
    /// If either of these conditions has already occurred, then an object owner was already
    /// created and there is no need to call this function - however, the below flow can still
    /// be followed to transfer ownership to MCMS, omitting the final step.
    ///
    /// Ownership transfer flow:
    /// - if it was deployed using mcms_deployer, call get_new_code_object_owner_address() with
    ///   the same new_owner_seed used when publishing to get the MCMS object owner address.
    /// - otherwise, call get_existing_code_object_owner_address() to get the MCMS object owner
    ///   address.
    /// - call 0x1::object::transfer, transfering ownership to the MCMS object owner address.
    /// - call register_object_owner_for_existing_code_object() with the object address.
    ///
    /// After these steps, MCMS will be the code object owner, and will be able to deploy and upgrade
    /// the code object using proposals with mcms_deployer ops.
    public entry fun register_object_owner_for_existing_code_object(
        caller: &signer, object_address: address
    ) acquires RegistryState {
        mcms_account::assert_is_owner(caller);
        assert!(
            object::object_exists<PackageRegistry>(object_address),
            error::invalid_argument(E_INVALID_CODE_OBJECT)
        );

        let state = borrow_state_mut();
        register_object_owner_for_existing_code_object_internal(state, object_address);
    }

    /// Transfers ownership of a code object to a new owner. Note that this does not unregister
    /// the entrypoint or remove the previous owner from the registry.
    public entry fun transfer_code_object(
        caller: &signer, object_address: address, new_owner_address: address
    ) acquires RegistryState, OwnerRegistration {
        mcms_account::assert_is_owner(caller);

        assert!(
            object::object_exists<PackageRegistry>(object_address),
            error::invalid_argument(E_INVALID_CODE_OBJECT)
        );

        let code_object = object::address_to_object<PackageRegistry>(object_address);

        let state = borrow_state();
        assert!(
            smart_table::contains(&state.registered_addresses, object_address),
            error::invalid_argument(E_NOT_REGISTERED)
        );

        let owner_address =
            *smart_table::borrow(&state.registered_addresses, object_address);
        assert!(
            object::owner(code_object) == owner_address,
            error::invalid_state(E_NOT_CODE_OBJECT_OWNER)
        );

        let owner_registration = borrow_owner_registration(owner_address);
        let owner_signer =
            &account::create_signer_with_capability(&owner_registration.owner_cap);

        object::transfer(owner_signer, code_object, new_owner_address);
    }

    public(friend) fun register_object_owner_for_new_code_object(
        new_owner_seed: vector<u8>
    ): signer acquires RegistryState {
        let owner_seed = NEW_OBJECT_REGISTRATION_SEED;
        vector::append(&mut owner_seed, new_owner_seed);
        let new_code_object_address = get_new_code_object_address(new_owner_seed);
        register_object_owner_internal(
            borrow_state_mut(),
            owner_seed,
            new_code_object_address,
            true
        )
    }

    public(friend) fun get_signer_for_code_object_upgrade(
        object_address: address
    ): signer acquires RegistryState, OwnerRegistration {
        assert!(
            object::object_exists<PackageRegistry>(object_address),
            error::invalid_argument(E_INVALID_CODE_OBJECT)
        );

        let state = borrow_state();
        assert!(
            smart_table::contains(&state.registered_addresses, object_address),
            error::invalid_argument(E_NOT_REGISTERED)
        );
        let owner_address =
            *smart_table::borrow(&state.registered_addresses, object_address);

        let owner_registration = borrow_owner_registration(owner_address);
        account::create_signer_with_capability(&owner_registration.owner_cap)
    }

    inline fun register_object_owner_for_existing_code_object_internal(
        state: &mut RegistryState, object_address: address
    ): signer {
        let owner_seed = EXISTING_OBJECT_REGISTRATION_SEED;
        vector::append(&mut owner_seed, bcs::to_bytes(&object_address));
        register_object_owner_internal(state, owner_seed, object_address, false)
    }

    inline fun register_object_owner_internal(
        state: &mut RegistryState,
        owner_seed: vector<u8>,
        code_object_address: address,
        is_preregistered: bool
    ): signer {
        let mcms_signer = &mcms_account::get_signer();

        let owner_address = account::create_resource_address(&@mcms, owner_seed);
        assert!(
            !exists<OwnerRegistration>(owner_address),
            error::invalid_state(E_OWNER_ALREADY_REGISTERED)
        );

        let (owner_signer, owner_cap) =
            account::create_resource_account(mcms_signer, owner_seed);
        move_to(
            &owner_signer,
            OwnerRegistration {
                owner_seed,
                owner_cap,
                is_preregistered,
                callback_modules: smart_table::new()
            }
        );

        smart_table::add(
            &mut state.registered_addresses,
            code_object_address,
            signer::address_of(&owner_signer)
        );
        owner_signer
    }

    /// Registers a callback to mcms_entrypoint to enable dynamic dispatch.
    public fun register_entrypoint<T: drop>(
        account: &signer, module_name: String, _proof: T
    ): address acquires RegistryState, OwnerRegistration {
        let account_address = signer::address_of(account);
        let account_address_bytes = bcs::to_bytes(&account_address);

        let module_name_bytes = *string::bytes(&module_name);
        let module_name_len = vector::length(&module_name_bytes);
        assert!(
            module_name_len > 0,
            error::invalid_argument(E_EMPTY_MODULE_NAME)
        );
        assert!(
            module_name_len <= 64,
            error::invalid_argument(E_MODULE_NAME_TOO_LONG)
        );

        let state = borrow_state_mut();

        let owner_address =
            if (!smart_table::contains(&state.registered_addresses, account_address)) {
                let owner_signer =
                    register_object_owner_for_existing_code_object_internal(
                        state, account_address
                    );
                signer::address_of(&owner_signer)
            } else {
                *smart_table::borrow(&state.registered_addresses, account_address)
            };

        let registration = borrow_owner_registration_mut(owner_address);

        assert!(
            !smart_table::contains(&registration.callback_modules, module_name_bytes),
            error::invalid_argument(E_MODULE_ALREADY_REGISTERED)
        );

        let proof_type_info = type_info::type_of<T>();

        assert!(
            type_info::account_address(&proof_type_info) == account_address,
            error::invalid_argument(E_PROOF_NOT_AT_ACCOUNT_ADDRESS)
        );
        assert!(
            type_info::module_name(&proof_type_info) == module_name_bytes,
            error::invalid_argument(E_PROOF_NOT_IN_MODULE)
        );

        let owner_signer =
            account::create_signer_with_capability(&registration.owner_cap);

        let object_seed = DISPATCH_OBJECT_SEED;
        vector::append(&mut object_seed, account_address_bytes);
        vector::append(&mut object_seed, module_name_bytes);

        let dispatch_constructor_ref =
            object::create_named_object(&owner_signer, object_seed);
        let dispatch_extend_ref = object::generate_extend_ref(&dispatch_constructor_ref);
        let dispatch_metadata =
            fungible_asset::add_fungibility(
                &dispatch_constructor_ref,
                option::none(),
                string::utf8(b"mcms"),
                string::utf8(b"mcms"),
                0,
                string::utf8(b""),
                string::utf8(b"")
            );

        let callback_function_info =
            function_info::new_function_info(
                account, module_name, string::utf8(b"mcms_entrypoint")
            );

        dispatchable_fungible_asset::register_derive_supply_dispatch_function(
            &dispatch_constructor_ref, option::some(callback_function_info)
        );

        let registered_module = RegisteredModule {
            callback_function_info,
            proof_type_info,
            dispatch_metadata,
            dispatch_extend_ref
        };

        smart_table::add(
            &mut registration.callback_modules, module_name_bytes, registered_module
        );

        owner_address
    }

    public(friend) fun start_dispatch(
        callback_address: address,
        callback_module_name: String,
        callback_function: String,
        data: vector<u8>
    ): Object<Metadata> acquires RegistryState, OwnerRegistration {
        let state = borrow_state();

        assert!(
            smart_table::contains(&state.registered_addresses, callback_address),
            error::invalid_argument(E_NOT_REGISTERED)
        );

        let owner_address =
            *smart_table::borrow(&state.registered_addresses, callback_address);
        assert!(
            !exists<ExecutingCallbackParams>(owner_address),
            error::invalid_state(E_CALLBACK_PARAMS_ALREADY_EXISTS)
        );

        let registration = borrow_owner_registration(owner_address);

        let callback_module_name_bytes = *string::bytes(&callback_module_name);
        let registered_module =
            smart_table::borrow(
                &registration.callback_modules, callback_module_name_bytes
            );

        let owner_signer =
            account::create_signer_with_capability(&registration.owner_cap);

        move_to(
            &owner_signer,
            ExecutingCallbackParams {
                expected_type_info: registered_module.proof_type_info,
                function: callback_function,
                data
            }
        );

        registered_module.dispatch_metadata
    }

    public(friend) fun finish_dispatch(callback_address: address) acquires RegistryState {
        let state = borrow_state();

        assert!(
            smart_table::contains(&state.registered_addresses, callback_address),
            error::invalid_state(E_NOT_REGISTERED)
        );

        let owner_address =
            *smart_table::borrow(&state.registered_addresses, callback_address);
        assert!(
            !exists<ExecutingCallbackParams>(owner_address),
            error::invalid_argument(E_CALLBACK_PARAMS_NOT_CONSUMED)
        );
    }

    public fun get_callback_params<T: drop>(
        callback_address: address, _proof: T
    ): (signer, String, vector<u8>) acquires RegistryState, OwnerRegistration, ExecutingCallbackParams {
        let state = borrow_state();

        assert!(
            smart_table::contains(&state.registered_addresses, callback_address),
            error::invalid_argument(E_NOT_REGISTERED)
        );

        let owner_address =
            *smart_table::borrow(&state.registered_addresses, callback_address);
        assert!(
            exists<ExecutingCallbackParams>(owner_address),
            error::invalid_state(E_MISSING_CALLBACK_PARAMS)
        );

        let ExecutingCallbackParams { expected_type_info, function, data } =
            move_from<ExecutingCallbackParams>(owner_address);

        let proof_type_info = type_info::type_of<T>();
        assert!(
            expected_type_info == proof_type_info,
            error::invalid_argument(E_WRONG_PROOF_TYPE)
        );

        let registration = borrow_owner_registration(owner_address);
        let owner_signer =
            account::create_signer_with_capability(&registration.owner_cap);

        (owner_signer, function, data)
    }

    inline fun borrow_state(): &RegistryState {
        borrow_global<RegistryState>(@mcms)
    }

    inline fun borrow_state_mut(): &mut RegistryState {
        borrow_global_mut<RegistryState>(@mcms)
    }

    inline fun borrow_owner_registration(account_address: address): &OwnerRegistration {
        assert!(
            exists<OwnerRegistration>(account_address),
            error::invalid_argument(E_NOT_REGISTERED)
        );
        borrow_global<OwnerRegistration>(account_address)
    }

    inline fun borrow_owner_registration_mut(account_address: address): &mut OwnerRegistration {
        assert!(
            exists<OwnerRegistration>(account_address),
            error::invalid_argument(E_NOT_REGISTERED)
        );
        borrow_global_mut<OwnerRegistration>(account_address)
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }
}
