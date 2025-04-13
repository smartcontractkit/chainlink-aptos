module link::link_token {
    use std::code::PackageRegistry;
    use std::event;
    use std::fungible_asset::{Self, BurnRef, Metadata, MintRef, TransferRef};
    use std::object::{Self, ExtendRef, Object, TransferRef as ObjectTransferRef};
    use std::option::{Self, Option};
    use std::primary_fungible_store;
    use std::signer;
    use std::string::{Self, String};

    use ccip::allowlist::{Self, AllowlistState};
    use ccip::ownable::{Self, OwnableState};
    use mcms::bcs_stream;
    use mcms::mcms_registry;

    const TOKEN_STATE_SEED: vector<u8> = b"link::link_token::token_state";

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct TokenState has key {
        ownable_state: OwnableState,
        allowed_minters: AllowlistState,
        allowed_burners: AllowlistState,
        token: Option<Object<Metadata>>
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct TokenStateRefs has key {
        extend_ref: ExtendRef,
        transfer_ref: ObjectTransferRef
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct MetadataRefs has key {
        extend_ref: ExtendRef,
        mint_ref: MintRef,
        burn_ref: BurnRef,
        transfer_ref: TransferRef
    }

    #[event]
    struct Initialize has drop, store {
        publisher: address,
        token: Object<Metadata>,
        max_supply: Option<u128>,
        decimals: u8,
        icon: String,
        project: String
    }

    #[event]
    struct Mint has drop, store {
        minter: address,
        to: address,
        amount: u64
    }

    #[event]
    struct Burn has drop, store {
        burner: address,
        from: address,
        amount: u64
    }

    const E_UNKNOWN_FUNCTION: u64 = 0;
    const E_NOT_OWNER: u64 = 1;
    const E_NOT_PUBLISHER: u64 = 2;
    const E_NOT_ALLOWED_MINTER: u64 = 3;
    const E_NOT_ALLOWED_BURNER: u64 = 4;
    const E_TOKEN_NOT_INITIALIZED: u64 = 5;
    const E_TOKEN_ALREADY_INITIALIZED: u64 = 6;

    /// `publisher` is the code object, deployed through object_code_deployment
    fun init_module(publisher: &signer) {
        assert!(object::object_exists<PackageRegistry>(@link), E_NOT_PUBLISHER);

        // Create object owned by code object
        let constructor_ref = &object::create_named_object(publisher, TOKEN_STATE_SEED);
        let extend_ref = object::generate_extend_ref(constructor_ref);
        let object_transfer_ref = object::generate_transfer_ref(constructor_ref);
        let token_state_signer = &object::generate_signer(constructor_ref);

        move_to(
            token_state_signer,
            TokenStateRefs { extend_ref, transfer_ref: object_transfer_ref }
        );

        let allowed_minters =
            allowlist::new_with_name(publisher, vector[], string::utf8(b"minters"));
        allowlist::set_allowlist_enabled(&mut allowed_minters, true);

        let allowed_burners =
            allowlist::new_with_name(publisher, vector[], string::utf8(b"burners"));
        allowlist::set_allowlist_enabled(&mut allowed_burners, true);

        move_to(
            token_state_signer,
            TokenState {
                ownable_state: ownable::new(publisher, @link),
                allowed_minters,
                allowed_burners,
                token: option::none()
            }
        );

        if (@mcms_register_entrypoints != @0x0) {
            mcms_registry::register_entrypoint(
                publisher, string::utf8(b"link_token"), McmsCallback {}
            );
        };
    }

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"LinkToken 1.0.0")
    }

    #[view]
    public fun token_state_address(): address {
        object::create_object_address(&@link, TOKEN_STATE_SEED)
    }

    #[view]
    public fun get_allowed_minters(): vector<address> acquires TokenState {
        allowlist::get_allowlist(&TokenState[token_state_address()].allowed_minters)
    }

    #[view]
    public fun get_allowed_burners(): vector<address> acquires TokenState {
        allowlist::get_allowlist(&TokenState[token_state_address()].allowed_burners)
    }

    #[view]
    public fun is_minter_allowed(minter_address: address): bool acquires TokenState {
        allowlist::is_allowed(
            &TokenState[token_state_address()].allowed_minters,
            minter_address
        )
    }

    #[view]
    public fun is_burner_allowed(burner_address: address): bool acquires TokenState {
        allowlist::is_allowed(
            &TokenState[token_state_address()].allowed_burners,
            burner_address
        )
    }

    #[view]
    public fun token_address(symbol: String): address {
        object::create_object_address(&token_state_address(), *symbol.bytes())
    }

    #[view]
    public fun metadata(): Option<Object<Metadata>> acquires TokenState {
        TokenState[token_state_address()].token
    }

    // ================================================================
    // |                      Only Owner Functions                     |
    // ================================================================

    /// Only owner of this code object can initialize tokens
    public entry fun initialize(
        publisher: &signer,
        max_supply: Option<u128>,
        name: String,
        symbol: String,
        decimals: u8,
        icon: String,
        project: String
    ) acquires TokenState, TokenStateRefs {
        let publisher_addr = signer::address_of(publisher);
        // `authorized_token_state_signer` asserts `publisher` is the owner of the code object
        let token_state_signer = authorized_token_state_signer(publisher);

        // Code object owns token state, which owns the fungible asset
        // Code object => token state => fungible asset
        let constructor_ref =
            &object::create_named_object(&token_state_signer, *symbol.bytes());
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            constructor_ref,
            max_supply,
            name,
            symbol,
            decimals,
            icon,
            project
        );

        let metadata_object_signer = &object::generate_signer(constructor_ref);
        move_to(
            metadata_object_signer,
            MetadataRefs {
                extend_ref: object::generate_extend_ref(constructor_ref),
                mint_ref: fungible_asset::generate_mint_ref(constructor_ref),
                burn_ref: fungible_asset::generate_burn_ref(constructor_ref),
                transfer_ref: fungible_asset::generate_transfer_ref(constructor_ref)
            }
        );

        let token = object::object_from_constructor_ref(constructor_ref);
        TokenState[token_state_address()].token = option::some(token);

        event::emit(
            Initialize {
                publisher: publisher_addr,
                token,
                max_supply,
                decimals,
                icon,
                project
            }
        );
    }

    inline fun authorized_token_state_signer(owner: &signer): signer {
        assert_only_owner(signer::address_of(owner));

        object::generate_signer_for_extending(
            &TokenStateRefs[token_state_address()].extend_ref
        )
    }

    public entry fun apply_allowed_minter_updates(
        caller: &signer,
        minters_to_remove: vector<address>,
        minters_to_add: vector<address>
    ) acquires TokenState {
        assert_only_owner(signer::address_of(caller));

        allowlist::apply_allowlist_updates(
            &mut TokenState[token_state_address()].allowed_minters,
            minters_to_remove,
            minters_to_add
        );
    }

    public entry fun apply_allowed_burner_updates(
        caller: &signer,
        burners_to_remove: vector<address>,
        burners_to_add: vector<address>
    ) acquires TokenState {
        assert_only_owner(signer::address_of(caller));

        allowlist::apply_allowlist_updates(
            &mut TokenState[token_state_address()].allowed_burners,
            burners_to_remove,
            burners_to_add
        );
    }

    // ================================================================
    // |                      Mint/Burn Functions                      |
    // ================================================================

    public entry fun mint(minter: &signer, to: address, amount: u64) acquires MetadataRefs, TokenState {
        let minter_addr = signer::address_of(minter);
        assert_is_allowed_minter(minter_addr);

        if (amount == 0) { return };

        primary_fungible_store::mint(&borrow_metadata_refs().mint_ref, to, amount);

        event::emit(Mint { minter: minter_addr, to, amount });
    }

    public entry fun burn(burner: &signer, from: address, amount: u64) acquires MetadataRefs, TokenState {
        let burner_addr = signer::address_of(burner);
        assert_is_allowed_burner(burner_addr);

        if (amount == 0) { return };

        primary_fungible_store::burn(&borrow_metadata_refs().burn_ref, from, amount);

        event::emit(Burn { burner: burner_addr, from, amount });
    }

    inline fun assert_is_allowed_minter(caller: address) acquires TokenState {
        assert!(
            caller == owner()
                || allowlist::is_allowed(
                    &TokenState[token_state_address()].allowed_minters, caller
                ),
            E_NOT_ALLOWED_MINTER
        );
    }

    inline fun assert_is_allowed_burner(caller: address) acquires TokenState {
        assert!(
            caller == owner()
                || allowlist::is_allowed(
                    &TokenState[token_state_address()].allowed_burners, caller
                ),
            E_NOT_ALLOWED_BURNER
        );
    }

    inline fun borrow_metadata_refs(): &MetadataRefs {
        assert!(
            option::is_some(&TokenState[token_state_address()].token),
            E_TOKEN_NOT_INITIALIZED
        );
        let metadata = option::borrow(&TokenState[token_state_address()].token);
        &MetadataRefs[object::object_address(metadata)]
    }

    // ================================================================
    // |                      Ownable State                           |
    // ================================================================

    #[view]
    public fun owner(): address acquires TokenState {
        ownable::owner(&TokenState[token_state_address()].ownable_state)
    }

    fun assert_only_owner(caller: address) acquires TokenState {
        ownable::assert_only_owner(
            caller, &TokenState[token_state_address()].ownable_state
        )
    }

    /// ownable::transfer_ownership checks if the caller is the owner
    /// So we only extract the ownable state from the token state
    public entry fun transfer_ownership(caller: &signer, to: address) acquires TokenState {
        ownable::transfer_ownership(
            signer::address_of(caller),
            &mut TokenState[token_state_address()].ownable_state,
            to
        )
    }

    /// Anyone can call this as `ownable::accept_ownership` verifies
    /// that the caller is the pending owner
    public entry fun accept_ownership(caller: &signer) acquires TokenState {
        ownable::accept_ownership(
            signer::address_of(caller),
            &mut TokenState[token_state_address()].ownable_state
        )
    }

    /// ownable::execute_ownership_transfer checks if the caller is the owner
    /// So we only extract the ownable state from the token state
    public entry fun execute_ownership_transfer(
        caller: &signer, to: address
    ) acquires TokenState {
        ownable::execute_ownership_transfer(
            caller,
            &mut TokenState[token_state_address()].ownable_state,
            to
        )
    }

    // ================================================================
    // |                      MCMS Entrypoint                         |
    // ================================================================

    struct McmsCallback has drop {}

    public fun mcms_entrypoint<T: key>(
        _metadata: object::Object<T>
    ): Option<u128> acquires MetadataRefs, TokenState, TokenStateRefs {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@link, McmsCallback {});

        let function_bytes = *string::bytes(&function);
        let stream = bcs_stream::new(data);

        if (function_bytes == b"initialize") {
            let max_supply =
                bcs_stream::deserialize_option(
                    &mut stream, |stream| bcs_stream::deserialize_u128(stream)
                );
            let name = bcs_stream::deserialize_string(&mut stream);
            let symbol = bcs_stream::deserialize_string(&mut stream);
            let decimals = bcs_stream::deserialize_u8(&mut stream);
            let icon = bcs_stream::deserialize_string(&mut stream);
            let project = bcs_stream::deserialize_string(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            initialize(
                &caller,
                max_supply,
                name,
                symbol,
                decimals,
                icon,
                project
            )
        } else if (function_bytes == b"mint") {
            let to = bcs_stream::deserialize_address(&mut stream);
            let amount = bcs_stream::deserialize_u64(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            mint(&caller, to, amount)
        } else if (function_bytes == b"burn") {
            let from = bcs_stream::deserialize_address(&mut stream);
            let amount = bcs_stream::deserialize_u64(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            burn(&caller, from, amount)
        } else if (function_bytes == b"apply_allowed_minter_updates") {
            let minters_to_remove =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let minters_to_add =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);

            apply_allowed_minter_updates(&caller, minters_to_remove, minters_to_add)
        } else if (function_bytes == b"apply_allowed_burner_updates") {
            let burners_to_remove =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let burners_to_add =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);

            apply_allowed_burner_updates(&caller, burners_to_remove, burners_to_add)
        } else if (function_bytes == b"transfer_ownership") {
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            transfer_ownership(&caller, to)
        } else if (function_bytes == b"accept_ownership") {
            bcs_stream::assert_is_consumed(&stream);

            accept_ownership(&caller)
        } else if (function_bytes == b"execute_ownership_transfer") {
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            execute_ownership_transfer(&caller, to)
        } else {
            abort E_UNKNOWN_FUNCTION
        };

        option::none()
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }
}
