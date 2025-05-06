/// The storage module stores all the state associated with the dispatch service.
module chainlink_platform::storage {
    use std::option::{Self, Option};
    use std::vector;

    use sui::object::{Self, UID};
    use sui::table::{Self, Table};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::event;

    use chainlink_platform::vector_utils;

    // Constants
    const APP_OBJECT_SEED: vector<u8> = b"STORAGE";

    // Error codes
    const E_UNKNOWN_RECEIVER: u64 = 1;
    const E_INVALID_METADATA_LENGTH: u64 = 2;
    const E_NOT_AUTHORIZED: u64 = 3;
    
    // Capability for authorizing sensitive operations
    struct AdminCap has key, store {
        id: UID
    }

    struct Entry has key, store {
        id: UID,
        metadata: vector<u8>,
        extend_ref: Option<vector<u8>> // Placeholder for capability references
    }

    struct Dispatcher has key {
        id: UID,
        dispatcher: Table<vector<u8>, address>,
        address_to_typeinfo: Table<address, vector<u8>>
    }

    /// Store the data to dispatch here.
    struct Storage has key, store {
        id: UID,
        metadata: vector<u8>,
        data: vector<u8>
    }

    struct ReportMetadata has store, drop {
        workflow_cid: vector<u8>,
        workflow_name: vector<u8>,
        workflow_owner: vector<u8>,
        report_id: vector<u8>
    }

    // One-time initialization function
    fun init(ctx: &mut TxContext) {
        // Create the main Dispatcher object
        let dispatcher = Dispatcher {
            id: object::new(ctx),
            dispatcher: table::new(ctx),
            address_to_typeinfo: table::new(ctx)
        };
        
        // Create admin capability
        let admin_cap = AdminCap {
            id: object::new(ctx)
        };
        
        // Transfer the dispatcher object to a shared object
        transfer::share_object(dispatcher);
        
        // Transfer the admin capability to the sender
        transfer::transfer(admin_cap, tx_context::sender(ctx));
    }

    /// Registers an account and callback for future dispatching, and a proof type `T`
    /// for the callback function to retrieve arguments.
    public fun register<T: drop>(
        _admin_cap: &AdminCap,
        _account_address: address,
        ctx: &mut TxContext
    ) {
        // In Sui, we'd use a different approach to get type info
        // This is a simplified implementation
        let type_name = vector::empty<u8>();
        
        // Create new entry object
        let entry = Entry {
            id: object::new(ctx),
            metadata: type_name,
            extend_ref: option::none()
        };
        
        // Share the entry object
        let _entry_address = object::id_address(&entry);
        transfer::share_object(entry);
        
        // Get shared dispatcher object through dynamic field or directly
        // Note: In actual implementation, we'd need a way to look up the shared Dispatcher
        // This is conceptual and would need to be implemented with Sui's object model
    }

    /// Insert data for dispatching
    public fun insert(
        _receiver: address, 
        callback_metadata: vector<u8>, 
        callback_data: vector<u8>,
        ctx: &mut TxContext
    ): address {
        // Create a new Storage object
        let storage = Storage {
            id: object::new(ctx),
            metadata: callback_metadata,
            data: callback_data
        };
        
        // Share the storage object
        let storage_id = object::id_address(&storage);
        transfer::share_object(storage);
        
        // Emit event
        event::emit(
            StorageCreated {
                storage_id,
                metadata: callback_metadata,
                data_size: vector::length(&callback_data)
            }
        );
        
        // Return the address of the created storage
        storage_id
    }

    /// Check if storage exists at a given address
    public fun storage_exists(_obj_address: address): bool {
        // In Sui, we'd need to check if an object exists at this address
        // For now, return a placeholder implementation
        false // This would be replaced with actual implementation
    }

    /// Parse report metadata
    public fun parse_report_metadata(metadata: vector<u8>): ReportMetadata {
        assert!(vector::length(&metadata) == 64, E_INVALID_METADATA_LENGTH);

        let workflow_cid = vector_utils::slice(&metadata, 0, 32);
        let workflow_name = vector_utils::slice(&metadata, 32, 42);
        let workflow_owner = vector_utils::slice(&metadata, 42, 62);
        let report_id = vector_utils::slice(&metadata, 62, 64);

        ReportMetadata { 
            workflow_cid, 
            workflow_name, 
            workflow_owner, 
            report_id 
        }
    }

    // Struct accessors
    public fun get_report_metadata_workflow_cid(
        report_metadata: &ReportMetadata
    ): vector<u8> {
        report_metadata.workflow_cid
    }

    public fun get_report_metadata_workflow_name(
        report_metadata: &ReportMetadata
    ): vector<u8> {
        report_metadata.workflow_name
    }

    public fun get_report_metadata_workflow_owner(
        report_metadata: &ReportMetadata
    ): vector<u8> {
        report_metadata.workflow_owner
    }

    public fun get_report_metadata_report_id(
        report_metadata: &ReportMetadata
    ): vector<u8> {
        report_metadata.report_id
    }

    // Events
    struct StorageCreated has copy, drop {
        storage_id: address,
        metadata: vector<u8>,
        data_size: u64
    }
}
