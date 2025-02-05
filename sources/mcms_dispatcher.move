module mcms::mcms_dispatcher {
    use std::bcs;
    use std::option;
    use std::string::{Self, String};
    use std::signer;
    use std::smart_table::{Self, SmartTable};
    use std::vector;

    use aptos_std::type_info::{Self, TypeInfo};

    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::function_info::{Self, FunctionInfo};
    use aptos_framework::fungible_asset::{Self, Metadata};
    use aptos_framework::object::{Self, ExtendRef, TransferRef, Object};

    friend mcms::mcms;

    const DISPATCHER_OBJECT_SEED: vector<u8> = b"CHAINLINK_MCMS_DISPATCHER";

    const EPROOF_ALREADY_EXISTS: u64 = 1;
    const EPROOF_NOT_REGISTERED: u64 = 2;
    const EMODULE_NAME_TOO_LONG: u64 = 3;
    const EMISSING_CALLBACK_PARAMS: u64 = 4;

    struct RegisteredType has key, store, drop {
        type_info: TypeInfo,
        function_info: FunctionInfo
    }

    struct RegisteredObject has key, store, drop {
        metadata: Object<Metadata>,
        extend_ref: ExtendRef
    }

    struct Dispatcher has key {
        registered_types: SmartTable<vector<u8>, RegisteredType>,
        registered_objects: SmartTable<TypeInfo, RegisteredObject>,
        extend_ref: ExtendRef,
        transfer_ref: TransferRef
    }

    struct CallbackParams has drop, key {
        function: String,
        data: vector<u8>
    }

    public fun register<T: drop>(
        account: &signer, module_name: String, _proof: T
    ) acquires Dispatcher {
        assert!(string::length(&module_name) <= 64, EMODULE_NAME_TOO_LONG);

        let callback_key = create_callback_key(signer::address_of(account), module_name);

        let type_name = type_info::type_name<T>();
        let constructor_ref =
            object::create_named_object(&storage_signer(), *string::bytes(&type_name));
        let extend_ref = object::generate_extend_ref(&constructor_ref);

        let function_info =
            function_info::new_function_info(
                account, module_name, string::utf8(b"mcms_entrypoint")
            );

        let metadata =
            fungible_asset::add_fungibility(
                &constructor_ref,
                option::none(),
                string::utf8(b"mcms"),
                string::utf8(b"mcms"),
                0,
                string::utf8(b""),
                string::utf8(b"")
            );

        dispatchable_fungible_asset::register_derive_supply_dispatch_function(
            &constructor_ref, option::some(function_info)
        );

        let dispatcher = borrow_global_mut<Dispatcher>(storage_address());
        let type_info = type_info::type_of<T>();

        assert!(
            !smart_table::contains(&dispatcher.registered_objects, type_info),
            EPROOF_ALREADY_EXISTS
        );

        smart_table::add(
            &mut dispatcher.registered_types,
            callback_key,
            RegisteredType { type_info, function_info }
        );
        smart_table::add(
            &mut dispatcher.registered_objects,
            type_info,
            RegisteredObject { metadata, extend_ref }
        );
    }

    public(friend) fun insert(
        callback_address: address,
        callback_module_name: String,
        callback_function: String,
        data: vector<u8>
    ): Object<Metadata> acquires Dispatcher {
        let callback_key = create_callback_key(callback_address, callback_module_name);

        let dispatcher = borrow_global<Dispatcher>(storage_address());
        let RegisteredType { type_info, function_info: _ } =
            smart_table::borrow(&dispatcher.registered_types, callback_key);

        assert!(
            smart_table::contains(&dispatcher.registered_objects, *type_info),
            EPROOF_NOT_REGISTERED
        );

        let RegisteredObject { metadata, extend_ref } =
            smart_table::borrow(&dispatcher.registered_objects, *type_info);

        let obj_signer = object::generate_signer_for_extending(extend_ref);

        move_to(&obj_signer, CallbackParams { function: callback_function, data });
        *metadata
    }

    public(friend) fun callback_params_exist(obj_address: address): bool {
        object::object_exists<CallbackParams>(obj_address)
    }

    public fun get_callback_params<T: drop>(
        _proof: T
    ): (String, vector<u8>) acquires Dispatcher, CallbackParams {
        let dispatcher = borrow_global<Dispatcher>(storage_address());
        let type_info = type_info::type_of<T>();

        assert!(
            smart_table::contains(&dispatcher.registered_objects, type_info),
            EPROOF_NOT_REGISTERED
        );

        let RegisteredObject { metadata: _, extend_ref } =
            smart_table::borrow(&dispatcher.registered_objects, type_info);

        let obj_address = object::address_from_extend_ref(extend_ref);

        assert!(callback_params_exist(obj_address), EMISSING_CALLBACK_PARAMS);

        let callback_params = move_from<CallbackParams>(obj_address);

        (callback_params.function, callback_params.data)
    }

    fun init_module(publisher: &signer) {
        assert!(signer::address_of(publisher) == @mcms, 1);

        let constructor_ref =
            object::create_named_object(publisher, DISPATCHER_OBJECT_SEED);

        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let transfer_ref = object::generate_transfer_ref(&constructor_ref);
        let object_signer = object::generate_signer(&constructor_ref);

        move_to(
            &object_signer,
            Dispatcher {
                registered_types: smart_table::new(),
                registered_objects: smart_table::new(),
                extend_ref,
                transfer_ref
            }
        );
    }

    inline fun storage_address(): address acquires Dispatcher {
        object::create_object_address(&@mcms, DISPATCHER_OBJECT_SEED)
    }

    inline fun storage_signer(): signer acquires Dispatcher {
        object::generate_signer_for_extending(
            &borrow_global<Dispatcher>(storage_address()).extend_ref
        )
    }

    inline fun create_callback_key(
        callback_address: address, callback_module_name: String
    ): vector<u8> {
        let account_bytes = bcs::to_bytes<address>(&callback_address);
        let module_name_bytes = string::bytes(&callback_module_name);
        vector::append(&mut account_bytes, *module_name_bytes);
        account_bytes
    }
}
