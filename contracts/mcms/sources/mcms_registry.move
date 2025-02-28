/// This module handles registration and management of code object owners and callbacks.
module mcms::mcms_registry {
    use std::account::{Self, SignerCapability};
    use std::bcs;
    use std::code::PackageRegistry;
    use std::dispatchable_fungible_asset;
    use std::error;
    use std::event;
    use std::fungible_asset::{Self, Metadata};
    use std::function_info::{Self, FunctionInfo};
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

    struct OwnerTransfers has key {
        // object address -> pending transfer
        pending_transfers: SmartTable<address, PendingCodeObjectTransfer>
    }

    struct RegisteredModule has store, drop {
        callback_function_info: FunctionInfo,
        proof_type_info: TypeInfo,
        dispatch_metadata: Object<Metadata>,
        dispatch_extend_ref: ExtendRef
    }

    struct PendingCodeObjectTransfer has store, drop {
        to: address,
        accepted: bool
    }

    struct ExecutingCallbackParams has key {
        expected_type_info: TypeInfo,
        function: String,
        data: vector<u8>
    }

    #[event]
    struct EntrypointRegistered has store, drop {
        owner_address: address,
        account_address: address,
        module_name: String
    }

    #[event]
    struct CodeObjectTransferRequested has store, drop {
        object_address: address,
        mcms_owner_address: address,
        new_owner_address: address
    }

    #[event]
    struct CodeObjectTransferAccepted has store, drop {
        object_address: address,
        mcms_owner_address: address,
        new_owner_address: address
    }

    #[event]
    struct CodeObjectTransferred has store, drop {
        object_address: address,
        mcms_owner_address: address,
        new_owner_address: address
    }

    #[event]
    struct OwnerCreatedForPreexistingObject has store, drop {
        owner_address: address,
        object_address: address
    }

    #[event]
    struct OwnerCreatedForNewObject has store, drop {
        owner_address: address,
        expected_object_address: address
    }

    #[event]
    struct OwnerCreatedForEntrypoint has store, drop {
        owner_address: address,
        account_or_object_address: address
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
    const E_ADDRESS_NOT_REGISTERED: u64 = 10;
    const E_INVALID_CODE_OBJECT: u64 = 11;
    const E_OWNER_ALREADY_REGISTERED: u64 = 12;
    const E_NOT_CODE_OBJECT_OWNER: u64 = 13;
    const E_UNGATED_TRANSFER_DISABLED: u64 = 14;
    const E_NO_PENDING_TRANSFER: u64 = 15;
    const E_TRANSFER_ALREADY_ACCEPTED: u64 = 16;
    const E_NEW_OWNER_MISMATCH: u64 = 17;
    const E_TRANSFER_NOT_ACCEPTED: u64 = 18;
    const E_NOT_PROPOSED_OWNER: u64 = 19;

    fun init_module(publisher: &signer) {
        move_to(publisher, RegistryState { registered_addresses: smart_table::new() });
    }

    #[view]
    /// Returns the resource address for a new code object owner using the provided seed.
    public fun get_new_code_object_owner_address(
        new_owner_seed: vector<u8>
    ): address {
        let owner_seed = NEW_OBJECT_REGISTRATION_SEED;
        vector::append(&mut owner_seed, new_owner_seed);
        account::create_resource_address(&@mcms, owner_seed)
    }

    #[view]
    /// Computes and returns the new code object's address using the new_owner_seed.
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
    /// Derives the resource address for an preexisting code object's owner using the given object_address.
    public fun get_preexisting_code_object_owner_address(
        object_address: address
    ): address {
        let owner_seed = EXISTING_OBJECT_REGISTRATION_SEED;
        vector::append(&mut owner_seed, bcs::to_bytes(&object_address));
        account::create_resource_address(&@mcms, owner_seed)
    }

    #[view]
    /// Returns the registered owner address for a given account address. The account address
    /// can be either a code object address or a callback address.
    /// Aborts if the address is not registered.
    public fun get_registered_owner_address(
        account_address: address
    ): address acquires RegistryState {
        let state = borrow_state();
        assert!(
            smart_table::contains(&state.registered_addresses, account_address),
            error::invalid_argument(E_ADDRESS_NOT_REGISTERED)
        );
        *smart_table::borrow(&state.registered_addresses, account_address)
    }

    #[view]
    /// Returns true if the given address is a code object and is owned by MCMS.
    /// Aborts if the address is not a valid code object.
    public fun is_owned_code_object(object_address: address): bool acquires RegistryState {
        assert!(
            object::object_exists<PackageRegistry>(object_address),
            error::invalid_argument(E_INVALID_CODE_OBJECT)
        );
        let code_object = object::address_to_object<PackageRegistry>(object_address);

        let owner_address = get_registered_owner_address(object_address);
        object::owner(code_object) == owner_address
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
    /// - otherwise, call get_preexisting_code_object_owner_address() to get the MCMS object owner
    ///   address.
    /// - call 0x1::object::transfer, transfering ownership to the MCMS object owner address.
    /// - call create_owner_for_preexisting_code_object() with the object address.
    ///
    /// After these steps, MCMS will be the code object owner, and will be able to deploy and upgrade
    /// the code object using proposals with mcms_deployer ops.
    public entry fun create_owner_for_preexisting_code_object(
        caller: &signer, object_address: address
    ) acquires RegistryState {
        mcms_account::assert_is_owner(caller);
        assert!(
            object::object_exists<PackageRegistry>(object_address),
            error::invalid_argument(E_INVALID_CODE_OBJECT)
        );

        let state = borrow_state_mut();
        let owner_signer =
            &create_owner_for_preexisting_code_object_internal(state, object_address);

        event::emit(
            OwnerCreatedForPreexistingObject {
                owner_address: signer::address_of(owner_signer),
                object_address
            }
        );
    }

    /// Transfers ownership of a code object to a new owner. Note that this does not unregister
    /// the entrypoint or remove the previous owner from the registry.
    ///
    /// Due to Aptos's security model requiring the original owner's signer for 0x1::object::transfer,
    /// we use the same 3-step ownership transfer flow as our ownable.move implementation:
    ///
    /// 1. MCMS owner calls transfer_code_object with the new owner's address
    /// 2. Pending owner calls accept_code_object to confirm the transfer
    /// 3. MCMS owner calls execute_code_object_transfer to complete the transfer
    public entry fun transfer_code_object(
        caller: &signer, object_address: address, new_owner_address: address
    ) acquires RegistryState, OwnerRegistration, OwnerTransfers {
        mcms_account::assert_is_owner(caller);

        assert!(
            object::object_exists<PackageRegistry>(object_address),
            error::invalid_argument(E_INVALID_CODE_OBJECT)
        );

        let code_object = object::address_to_object<PackageRegistry>(object_address);

        // this could occur if the code object was pre-existing and the original creator kept the TransferRef,
        // transferred the object to MCMS by generating a LinearTransferRef.
        assert!(
            object::ungated_transfer_allowed(code_object),
            error::permission_denied(E_UNGATED_TRANSFER_DISABLED)
        );

        let state = borrow_state();
        assert!(
            smart_table::contains(&state.registered_addresses, object_address),
            error::invalid_argument(E_ADDRESS_NOT_REGISTERED)
        );

        let owner_address =
            *smart_table::borrow(&state.registered_addresses, object_address);
        // this could occur if the code object has already been transferred away either through this process
        // or through a TransferRef if the object was pre-existing.
        assert!(
            object::owner(code_object) == owner_address,
            error::invalid_state(E_NOT_CODE_OBJECT_OWNER)
        );

        if (!exists<OwnerTransfers>(owner_address)) {
            let owner_registration = borrow_owner_registration(owner_address);
            let owner_signer =
                &account::create_signer_with_capability(&owner_registration.owner_cap);
            move_to(owner_signer, OwnerTransfers { pending_transfers: smart_table::new() });
        };

        let pending_transfers = borrow_global_mut<OwnerTransfers>(owner_address);

        // override any pending transfers if a new transfer has been requested.
        smart_table::upsert(
            &mut pending_transfers.pending_transfers,
            object_address,
            PendingCodeObjectTransfer { to: new_owner_address, accepted: false }
        );

        event::emit(
            CodeObjectTransferRequested {
                object_address: object_address,
                mcms_owner_address: owner_address,
                new_owner_address: new_owner_address
            }
        );
    }

    public entry fun accept_code_object(
        caller: &signer, object_address: address
    ) acquires RegistryState, OwnerTransfers {
        assert!(
            object::object_exists<PackageRegistry>(object_address),
            error::invalid_argument(E_INVALID_CODE_OBJECT)
        );

        let code_object = object::address_to_object<PackageRegistry>(object_address);

        let state = borrow_state();
        assert!(
            smart_table::contains(&state.registered_addresses, object_address),
            error::invalid_argument(E_ADDRESS_NOT_REGISTERED)
        );

        let owner_address =
            *smart_table::borrow(&state.registered_addresses, object_address);
        // these conditions could occur if the code object was pre-existing and the owner transferred object ownership or disabled
        // ungated transfers using the TransferRef after this transfer process was initiated.
        assert!(
            object::owner(code_object) == owner_address,
            error::invalid_state(E_NOT_CODE_OBJECT_OWNER)
        );
        assert!(
            object::ungated_transfer_allowed(code_object),
            error::permission_denied(E_UNGATED_TRANSFER_DISABLED)
        );

        assert!(
            exists<OwnerTransfers>(owner_address),
            error::invalid_state(E_NO_PENDING_TRANSFER)
        );
        let pending_transfers = borrow_global_mut<OwnerTransfers>(owner_address);

        assert!(
            smart_table::contains(&pending_transfers.pending_transfers, object_address),
            error::invalid_state(E_NO_PENDING_TRANSFER)
        );

        let pending_transfer =
            smart_table::borrow_mut(
                &mut pending_transfers.pending_transfers, object_address
            );
        assert!(
            pending_transfer.to == signer::address_of(caller),
            error::permission_denied(E_NOT_PROPOSED_OWNER)
        );
        assert!(
            !pending_transfer.accepted,
            error::invalid_state(E_TRANSFER_ALREADY_ACCEPTED)
        );

        pending_transfer.accepted = true;

        event::emit(
            CodeObjectTransferAccepted {
                object_address: object_address,
                mcms_owner_address: owner_address,
                new_owner_address: pending_transfer.to
            }
        );
    }

    public entry fun execute_code_object_transfer(
        caller: &signer, object_address: address, new_owner_address: address
    ) acquires RegistryState, OwnerRegistration, OwnerTransfers {
        mcms_account::assert_is_owner(caller);

        assert!(
            object::object_exists<PackageRegistry>(object_address),
            error::invalid_argument(E_INVALID_CODE_OBJECT)
        );

        let code_object = object::address_to_object<PackageRegistry>(object_address);

        let state = borrow_state();
        assert!(
            smart_table::contains(&state.registered_addresses, object_address),
            error::invalid_argument(E_ADDRESS_NOT_REGISTERED)
        );

        let owner_address =
            *smart_table::borrow(&state.registered_addresses, object_address);
        // these conditions could occur if the code object was pre-existing and the owner transferred object ownership or disabled
        // ungated transfers using the TransferRef after this transfer process was initiated.
        assert!(
            object::owner(code_object) == owner_address,
            error::invalid_state(E_NOT_CODE_OBJECT_OWNER)
        );
        assert!(
            object::ungated_transfer_allowed(code_object),
            error::permission_denied(E_UNGATED_TRANSFER_DISABLED)
        );

        assert!(
            exists<OwnerTransfers>(owner_address),
            error::invalid_state(E_NO_PENDING_TRANSFER)
        );
        let pending_transfers = borrow_global_mut<OwnerTransfers>(owner_address);

        assert!(
            smart_table::contains(&pending_transfers.pending_transfers, object_address),
            error::invalid_state(E_NO_PENDING_TRANSFER)
        );
        let pending_transfer =
            smart_table::borrow_mut(
                &mut pending_transfers.pending_transfers, object_address
            );
        assert!(
            pending_transfer.to == new_owner_address,
            error::invalid_state(E_NEW_OWNER_MISMATCH)
        );
        assert!(
            pending_transfer.accepted, error::invalid_state(E_TRANSFER_NOT_ACCEPTED)
        );

        let owner_registration = borrow_owner_registration(owner_address);
        let owner_signer =
            &account::create_signer_with_capability(&owner_registration.owner_cap);

        object::transfer(owner_signer, code_object, new_owner_address);

        event::emit(
            CodeObjectTransferred {
                object_address: object_address,
                mcms_owner_address: owner_address,
                new_owner_address: new_owner_address
            }
        );

        smart_table::remove(&mut pending_transfers.pending_transfers, object_address);
        if (smart_table::length(&pending_transfers.pending_transfers) == 0) {
            let OwnerTransfers { pending_transfers } =
                move_from<OwnerTransfers>(owner_address);
            smart_table::destroy_empty(pending_transfers);
        }
    }

    public(friend) fun create_owner_for_new_code_object(
        new_owner_seed: vector<u8>
    ): signer acquires RegistryState {
        let owner_seed = NEW_OBJECT_REGISTRATION_SEED;
        vector::append(&mut owner_seed, new_owner_seed);
        let new_code_object_address = get_new_code_object_address(new_owner_seed);
        let owner_signer =
            create_owner_internal(
                borrow_state_mut(),
                owner_seed,
                new_code_object_address,
                true
            );

        event::emit(
            OwnerCreatedForNewObject {
                owner_address: signer::address_of(&owner_signer),
                expected_object_address: new_code_object_address
            }
        );

        owner_signer
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
            error::invalid_argument(E_ADDRESS_NOT_REGISTERED)
        );
        let owner_address =
            *smart_table::borrow(&state.registered_addresses, object_address);

        let owner_registration = borrow_owner_registration(owner_address);
        account::create_signer_with_capability(&owner_registration.owner_cap)
    }

    inline fun create_owner_for_preexisting_code_object_internal(
        state: &mut RegistryState, object_address: address
    ): signer {
        let owner_seed = EXISTING_OBJECT_REGISTRATION_SEED;
        vector::append(&mut owner_seed, bcs::to_bytes(&object_address));
        create_owner_internal(state, owner_seed, object_address, false)
    }

    inline fun create_owner_internal(
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
                    create_owner_for_preexisting_code_object_internal(
                        state, account_address
                    );

                let owner_address = signer::address_of(&owner_signer);

                event::emit(
                    OwnerCreatedForEntrypoint {
                        owner_address,
                        account_or_object_address: account_address
                    }
                );

                owner_address
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

        event::emit(EntrypointRegistered { owner_address, account_address, module_name });

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
            error::invalid_argument(E_ADDRESS_NOT_REGISTERED)
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
            error::invalid_state(E_ADDRESS_NOT_REGISTERED)
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
            error::invalid_argument(E_ADDRESS_NOT_REGISTERED)
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
            error::invalid_argument(E_ADDRESS_NOT_REGISTERED)
        );
        borrow_global<OwnerRegistration>(account_address)
    }

    inline fun borrow_owner_registration_mut(account_address: address): &mut OwnerRegistration {
        assert!(
            exists<OwnerRegistration>(account_address),
            error::invalid_argument(E_ADDRESS_NOT_REGISTERED)
        );
        borrow_global_mut<OwnerRegistration>(account_address)
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }
}
