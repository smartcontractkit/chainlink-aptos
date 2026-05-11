/// DEV / TEST ONLY. Mirror of `platform::storage` scoped to `@platform_mock`.
/// V2-only; public API matches prod for receiver source-compatibility.
module platform_mock::mock_storage {
    use std::option;
    use std::string;
    use std::signer;
    use std::vector;

    use aptos_std::smart_table::{SmartTable, Self};
    use aptos_std::type_info::{Self, TypeInfo};

    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::function_info::FunctionInfo;
    use aptos_framework::fungible_asset::{Self, Metadata};
    use aptos_framework::object::{Self, ExtendRef, TransferRef, Object};

    const APP_OBJECT_SEED: vector<u8> = b"MOCK_STORAGE";

    friend platform_mock::mock_forwarder;

    const E_UNKNOWN_RECEIVER: u64 = 1;
    const E_INVALID_METADATA_LENGTH: u64 = 2;

    struct Entry has key, store, drop {
        metadata: Object<Metadata>,
        extend_ref: ExtendRef
    }

    struct Dispatcher has key {
        dispatcher: SmartTable<TypeInfo, Entry>,
        address_to_typeinfo: SmartTable<address, TypeInfo>,
        extend_ref: ExtendRef,
        transfer_ref: TransferRef
    }

    struct Storage has drop, key {
        metadata: vector<u8>,
        data: vector<u8>
    }

    struct ReportMetadata has key, store, drop {
        workflow_cid: vector<u8>,
        workflow_name: vector<u8>,
        workflow_owner: vector<u8>,
        report_id: vector<u8>
    }

    public fun register<T: drop>(
        account: &signer, callback: FunctionInfo, _proof: T
    ) acquires Dispatcher {
        let typename = type_info::type_name<T>();
        let constructor_ref =
            object::create_named_object(&storage_signer(), *string::bytes(&typename));
        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let metadata =
            fungible_asset::add_fungibility(
                &constructor_ref,
                option::none(),
                string::utf8(b"storage"),
                string::utf8(b"dis"),
                0,
                string::utf8(b""),
                string::utf8(b"")
            );
        dispatchable_fungible_asset::register_derive_supply_dispatch_function(
            &constructor_ref, option::some(callback)
        );

        let dispatcher = borrow_global_mut<Dispatcher>(storage_address());
        smart_table::add(
            &mut dispatcher.dispatcher,
            type_info::type_of<T>(),
            Entry { metadata, extend_ref }
        );
        smart_table::add(
            &mut dispatcher.address_to_typeinfo,
            signer::address_of(account),
            type_info::type_of<T>()
        );
    }

    public(friend) fun insert(
        receiver: address, callback_metadata: vector<u8>, callback_data: vector<u8>
    ): Object<Metadata> acquires Dispatcher {
        let dispatcher = borrow_global<Dispatcher>(storage_address());
        assert!(
            smart_table::contains(&dispatcher.address_to_typeinfo, receiver),
            E_UNKNOWN_RECEIVER
        );
        let typeinfo = *smart_table::borrow(&dispatcher.address_to_typeinfo, receiver);
        let Entry { metadata: asset_metadata, extend_ref } =
            smart_table::borrow(&dispatcher.dispatcher, typeinfo);
        let obj_signer = object::generate_signer_for_extending(extend_ref);
        move_to(&obj_signer, Storage { data: callback_data, metadata: callback_metadata });
        *asset_metadata
    }

    public(friend) fun storage_exists(obj_address: address): bool {
        object::object_exists<Storage>(obj_address)
    }

    public fun retrieve<T: drop>(
        _proof: T
    ): (vector<u8>, vector<u8>) acquires Dispatcher, Storage {
        let dispatcher = borrow_global<Dispatcher>(storage_address());
        let typeinfo = type_info::type_of<T>();
        let Entry { metadata: _, extend_ref } =
            smart_table::borrow(&dispatcher.dispatcher, typeinfo);
        let obj_address = object::address_from_extend_ref(extend_ref);
        let data = move_from<Storage>(obj_address);
        (data.metadata, data.data)
    }

    #[view]
    public fun is_registered(receiver: address): bool acquires Dispatcher {
        let dispatcher = borrow_global<Dispatcher>(storage_address());
        smart_table::contains(&dispatcher.address_to_typeinfo, receiver)
    }

    #[view]
    public fun parse_report_metadata(metadata: vector<u8>): ReportMetadata {
        assert!(vector::length(&metadata) == 64, E_INVALID_METADATA_LENGTH);

        ReportMetadata {
            workflow_cid: vector::slice(&metadata, 0, 32),
            workflow_name: vector::slice(&metadata, 32, 42),
            workflow_owner: vector::slice(&metadata, 42, 62),
            report_id: vector::slice(&metadata, 62, 64),
        }
    }

    public fun get_report_metadata_workflow_cid(r: &ReportMetadata): vector<u8> {
        r.workflow_cid
    }
    public fun get_report_metadata_workflow_name(r: &ReportMetadata): vector<u8> {
        r.workflow_name
    }
    public fun get_report_metadata_workflow_owner(r: &ReportMetadata): vector<u8> {
        r.workflow_owner
    }
    public fun get_report_metadata_report_id(r: &ReportMetadata): vector<u8> {
        r.report_id
    }

    fun init_module(publisher: &signer) {
        assert!(signer::address_of(publisher) == @platform_mock, 1);

        let constructor_ref = object::create_named_object(publisher, APP_OBJECT_SEED);
        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let transfer_ref = object::generate_transfer_ref(&constructor_ref);
        let object_signer = object::generate_signer(&constructor_ref);

        move_to(
            &object_signer,
            Dispatcher {
                dispatcher: smart_table::new(),
                address_to_typeinfo: smart_table::new(),
                extend_ref,
                transfer_ref,
            }
        );
    }

    inline fun storage_address(): address {
        object::create_object_address(&@platform_mock, APP_OBJECT_SEED)
    }

    inline fun storage_signer(): signer {
        object::generate_signer_for_extending(
            &borrow_global<Dispatcher>(storage_address()).extend_ref
        )
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }
}
