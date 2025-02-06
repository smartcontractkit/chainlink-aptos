module mcms::mcms_registry {
    use std::dispatchable_fungible_asset;
    use std::error;
    use std::function_info::{Self, FunctionInfo};
    use std::fungible_asset::{Self, Metadata};
    use std::object::{Self, ExtendRef, Object, TransferRef};
    use std::option::{Self, Option};
    use std::signer;
    use std::smart_table::{Self, SmartTable};
    use std::string::{Self, String};
    use std::type_info::{Self, TypeInfo};

    friend mcms::mcms;

    const REGISTRY_OBJECT_SEED: vector<u8> = b"CHAINLINK_MCMS_REGISTRY";
    const DISPATCHER_OBJECT_SEED: vector<u8> = b"CHAINLINK_MCMS_DISPATCHER";

    struct RegisteredModule has key, store, drop {
        callback_function_info: FunctionInfo,
        proof_type_info: TypeInfo,
        dispatch_metadata: Object<Metadata>,
        dispatch_extend_ref: ExtendRef
    }

    struct MCMSRegistration has key, store {
        is_self_owner: bool,
        owner_extend_ref: ExtendRef,
        owner_transfer_ref: TransferRef,

        // module name -> registered module
        registered_modules: SmartTable<vector<u8>, RegisteredModule>,
        executing_callback_params: Option<CallbackParams>
    }

    struct MCMSRegistryState has key {
        extend_ref: ExtendRef,
        transfer_ref: TransferRef
    }

    struct CallbackParams has store, drop {
        expected_type_info: TypeInfo,
        function: String,
        data: vector<u8>
    }

    const E_CALLBACK_PARAMS_ALREADY_EXISTS: u64 = 1;
    const E_MISSING_CALLBACK_PARAMS: u64 = 2;
    const E_WRONG_PROOF_TYPE: u64 = 3;
    const E_CALLBACK_PARAMS_NOT_CONSUMED: u64 = 4;
    const E_OBJECT_ALREADY_EXISTS: u64 = 5;
    const E_EXPECTED_ADDRESS_MISMATCH: u64 = 6;
    const E_PROOF_NOT_AT_ACCOUNT_ADDRESS: u64 = 7;
    const E_PROOF_NOT_IN_MODULE: u64 = 8;
    const E_MODULE_ALREADY_REGISTERED: u64 = 9;
    const E_MODULE_NAME_TOO_LONG: u64 = 10;
    const E_NOT_REGISTERED: u64 = 11;

    fun init_module(publisher: &signer) {
        let constructor_ref = object::create_named_object(
            publisher, REGISTRY_OBJECT_SEED
        );
        let signer = object::generate_signer(&constructor_ref);
        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let transfer_ref = object::generate_transfer_ref(&constructor_ref);
        move_to(&signer, MCMSRegistryState { extend_ref, transfer_ref });
    }

    #[view]
    public fun get_state_address(): address {
        state_address()
    }

    #[view]
    public fun get_derived_address(object_seed: vector<u8>): address {
        get_derived_address_internal(object_seed)
    }

    inline fun get_derived_address_internal(object_seed: vector<u8>): address {
        object::create_object_address(&state_address(), object_seed)
    }

    public entry fun preregister(
        object_seed: vector<u8>, expected_address: address
    ) acquires MCMSRegistryState {
        // TODO: validate that calling publish_package_txn works from the user module, when
        // publishing into the same account. add large_packages and publish/upgrade hooks
        // to execute() if it does not.
        let state = borrow_state();

        assert!(
            !object::is_object(expected_address),
            error::invalid_state(E_OBJECT_ALREADY_EXISTS)
        );

        let registry_signer = object::generate_signer_for_extending(&state.extend_ref);
        let owner_constructor_ref =
            object::create_named_object(&registry_signer, object_seed);

        assert!(
            object::address_from_constructor_ref(&owner_constructor_ref)
                == expected_address,
            error::invalid_state(E_EXPECTED_ADDRESS_MISMATCH)
        );

        let owner_extend_ref = object::generate_extend_ref(&owner_constructor_ref);
        let owner_transfer_ref = object::generate_transfer_ref(&owner_constructor_ref);

        let owner_signer = object::generate_signer(&owner_constructor_ref);
        move_to(
            &owner_signer,
            MCMSRegistration {
                is_self_owner: true,
                owner_extend_ref,
                owner_transfer_ref,
                registered_modules: smart_table::new(),
                executing_callback_params: option::none()
            }
        );
    }

    #[view]
    public fun get_owner_address(object_address: address): address acquires MCMSRegistration {
        let registration = borrow_registration(object_address);
        object::address_from_extend_ref(&registration.owner_extend_ref)
    }

    inline fun borrow_registration(account_address: address): &MCMSRegistration {
        assert!(
            exists<MCMSRegistration>(account_address),
            error::invalid_argument(E_NOT_REGISTERED)
        );
        borrow_global<MCMSRegistration>(account_address)
    }

    inline fun borrow_registration_mut(account_address: address): &mut MCMSRegistration {
        assert!(
            exists<MCMSRegistration>(account_address),
            error::invalid_argument(E_NOT_REGISTERED)
        );
        borrow_global_mut<MCMSRegistration>(account_address)
    }

    public fun register<T: drop>(
        account: &signer, module_name: String, _proof: T
    ) acquires MCMSRegistryState, MCMSRegistration {
        assert!(
            string::length(&module_name) <= 64,
            error::invalid_argument(E_MODULE_NAME_TOO_LONG)
        );

        let account_address = signer::address_of(account);
        let registry_signer =
            object::generate_signer_for_extending(&borrow_state().extend_ref);

        if (!exists<MCMSRegistration>(account_address)) {
            let owner_constructor_ref =
                object::create_sticky_object(signer::address_of(&registry_signer));
            let owner_extend_ref = object::generate_extend_ref(&owner_constructor_ref);
            let owner_transfer_ref =
                object::generate_transfer_ref(&owner_constructor_ref);

            move_to(
                account,
                MCMSRegistration {
                    is_self_owner: false,
                    owner_extend_ref,
                    owner_transfer_ref,
                    registered_modules: smart_table::new(),
                    executing_callback_params: option::none()
                }
            );
        };

        let registration = borrow_registration_mut(account_address);

        let module_name_bytes = *string::bytes(&module_name);
        assert!(
            !smart_table::contains(&registration.registered_modules, module_name_bytes),
            error::invalid_argument(E_MODULE_ALREADY_REGISTERED)
        );

        let proof_type_name = type_info::type_name<T>();
        let proof_type_info = type_info::type_of<T>();

        assert!(
            type_info::account_address(&proof_type_info) == account_address,
            error::invalid_argument(E_PROOF_NOT_AT_ACCOUNT_ADDRESS)
        );
        assert!(
            type_info::module_name(&proof_type_info) == module_name_bytes,
            error::invalid_argument(E_PROOF_NOT_IN_MODULE)
        );

        let dispatch_constructor_ref =
            object::create_named_object(
                &registry_signer, *string::bytes(&proof_type_name)
            );
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
            &mut registration.registered_modules, module_name_bytes, registered_module
        );
    }

    public(friend) fun start_dispatch(
        callback_address: address,
        callback_module_name: String,
        callback_function: String,
        data: vector<u8>
    ): Object<Metadata> acquires MCMSRegistration {
        let registration = borrow_registration_mut(callback_address);

        let callback_module_name_bytes = *string::bytes(&callback_module_name);
        let registered_module =
            smart_table::borrow_mut(
                &mut registration.registered_modules, callback_module_name_bytes
            );

        assert!(
            option::is_none(&registration.executing_callback_params),
            error::invalid_state(E_CALLBACK_PARAMS_ALREADY_EXISTS)
        );

        registration.executing_callback_params = option::some(
            CallbackParams {
                expected_type_info: registered_module.proof_type_info,
                function: callback_function,
                data
            }
        );

        registered_module.dispatch_metadata
    }

    public(friend) fun finish_dispatch(callback_address: address) acquires MCMSRegistration {
        let registration = borrow_registration(callback_address);
        assert!(
            option::is_none(&registration.executing_callback_params),
            error::invalid_argument(E_CALLBACK_PARAMS_NOT_CONSUMED)
        );
    }

    public fun get_callback_params<T: drop>(
        callback_address: address, _proof: T
    ): (signer, String, vector<u8>) acquires MCMSRegistration {
        let registration = borrow_registration_mut(callback_address);

        assert!(
            option::is_some(&registration.executing_callback_params),
            error::invalid_argument(E_MISSING_CALLBACK_PARAMS)
        );

        let callback_params = option::extract(
            &mut registration.executing_callback_params
        );
        let proof_type_info = type_info::type_of<T>();
        assert!(
            callback_params.expected_type_info == proof_type_info,
            error::invalid_argument(E_WRONG_PROOF_TYPE)
        );

        let owner_signer =
            object::generate_signer_for_extending(&registration.owner_extend_ref);

        (owner_signer, callback_params.function, callback_params.data)
    }

    inline fun state_address(): address {
        object::create_object_address(&@mcms, REGISTRY_OBJECT_SEED)
    }

    inline fun borrow_state(): &MCMSRegistryState {
        borrow_global<MCMSRegistryState>(state_address())
    }

    inline fun borrow_state_mut(): &mut MCMSRegistryState {
        borrow_global_mut<MCMSRegistryState>(state_address())
    }
}
