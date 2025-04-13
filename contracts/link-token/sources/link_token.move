module link::link_token {
    use std::code::PackageRegistry;
    use std::event;
    use std::fungible_asset::{Self, BurnRef, Metadata, MintRef, TransferRef};
    use std::object::{Self, ExtendRef, Object};
    use std::option::{Self, Option};
    use std::primary_fungible_store;
    use std::signer;
    use std::string::{Self, String};

    use ccip::allowlist::{Self, AllowlistState};
    use ccip::ownable::{Self, OwnableState};
    use mcms::bcs_stream;
    use mcms::mcms_registry;

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct ManagementRefs has key {
        extend_ref: ExtendRef,
        mint_ref: MintRef,
        burn_ref: BurnRef,
        transfer_ref: TransferRef
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct TokenState has key {
        ownable_state: OwnableState,
        allowed_minters: AllowlistState,
        allowed_burners: AllowlistState
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

    fun init_module(publisher: &signer) {
        assert!(object::object_exists<PackageRegistry>(@link), E_NOT_PUBLISHER);

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
    public fun get_allowed_minters(
        token_state: Object<TokenState>
    ): vector<address> acquires TokenState {
        allowlist::get_allowlist(
            &TokenState[object::object_address(&token_state)].allowed_minters
        )
    }

    #[view]
    public fun get_allowed_burners(
        token_state: Object<TokenState>
    ): vector<address> acquires TokenState {
        allowlist::get_allowlist(
            &TokenState[object::object_address(&token_state)].allowed_burners
        )
    }

    #[view]
    public fun is_minter_allowed(
        token_state: Object<TokenState>, minter_address: address
    ): bool acquires TokenState {
        allowlist::is_allowed(
            &TokenState[object::object_address(&token_state)].allowed_minters,
            minter_address
        )
    }

    #[view]
    public fun is_burner_allowed(
        token_state: Object<TokenState>, burner_address: address
    ): bool acquires TokenState {
        allowlist::is_allowed(
            &TokenState[object::object_address(&token_state)].allowed_burners,
            burner_address
        )
    }

    #[view]
    public fun token_address(
        token_state: Object<TokenState>, symbol: String
    ): address {
        let owner = object::owner(token_state);
        object::create_object_address(&owner, *symbol.bytes())
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
    ) {
        let code_object = object::address_to_object<PackageRegistry>(@link);
        let publisher_addr = signer::address_of(publisher);
        assert!(object::owns(code_object, publisher_addr), E_NOT_OWNER);

        let constructor_ref = &object::create_named_object(publisher, *symbol.bytes());
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
            ManagementRefs {
                extend_ref: object::generate_extend_ref(constructor_ref),
                mint_ref: fungible_asset::generate_mint_ref(constructor_ref),
                burn_ref: fungible_asset::generate_burn_ref(constructor_ref),
                transfer_ref: fungible_asset::generate_transfer_ref(constructor_ref)
            }
        );

        let allowed_minters =
            allowlist::new_with_name(publisher, vector[], string::utf8(b"minters"));
        allowlist::set_allowlist_enabled(&mut allowed_minters, true);

        let allowed_burners =
            allowlist::new_with_name(publisher, vector[], string::utf8(b"burners"));
        allowlist::set_allowlist_enabled(&mut allowed_burners, true);

        // Move the token state to the metadata object
        move_to(
            metadata_object_signer,
            TokenState {
                ownable_state: ownable::new(publisher, @link),
                allowed_minters,
                allowed_burners
            }
        );

        event::emit(
            Initialize {
                publisher: publisher_addr,
                token: object::object_from_constructor_ref(constructor_ref),
                max_supply,
                decimals,
                icon,
                project
            }
        );
    }

    public entry fun apply_allowed_minter_updates(
        caller: &signer,
        token_state: Object<TokenState>,
        minters_to_remove: vector<address>,
        minters_to_add: vector<address>
    ) acquires TokenState {
        assert_only_owner(signer::address_of(caller), token_state);

        allowlist::apply_allowlist_updates(
            &mut TokenState[object::object_address(&token_state)].allowed_minters,
            minters_to_remove,
            minters_to_add
        );
    }

    public entry fun apply_allowed_burner_updates(
        caller: &signer,
        token_state: Object<TokenState>,
        burners_to_remove: vector<address>,
        burners_to_add: vector<address>
    ) acquires TokenState {
        assert_only_owner(signer::address_of(caller), token_state);

        allowlist::apply_allowlist_updates(
            &mut TokenState[object::object_address(&token_state)].allowed_burners,
            burners_to_remove,
            burners_to_add
        );
    }

    // ================================================================
    // |                      Mint/Burn Functions                      |
    // ================================================================

    public entry fun mint(
        minter: &signer,
        token_state: Object<TokenState>,
        to: address,
        amount: u64
    ) acquires ManagementRefs, TokenState {
        let token_state_addr = object::object_address(&token_state);
        let minter_addr = signer::address_of(minter);
        assert_is_allowed_minter(minter_addr, token_state_addr);

        if (amount == 0) { return };

        let refs = borrow_refs(token_state_addr);
        primary_fungible_store::mint(&refs.mint_ref, to, amount);

        event::emit(Mint { minter: minter_addr, to, amount });
    }

    public entry fun burn(
        burner: &signer,
        token_state: Object<TokenState>,
        from: address,
        amount: u64
    ) acquires ManagementRefs, TokenState {
        let token_state_addr = object::object_address(&token_state);
        let burner_addr = signer::address_of(burner);
        assert_is_allowed_burner(burner_addr, token_state_addr);

        if (amount == 0) { return };

        let refs = borrow_refs(token_state_addr);
        primary_fungible_store::burn(&refs.burn_ref, from, amount);

        event::emit(Burn { burner: burner_addr, from, amount });
    }

    inline fun assert_is_allowed_minter(
        caller: address, token_state_addr: address
    ) {
        let token_state = &TokenState[token_state_addr];
        assert!(
            allowlist::is_allowed(&token_state.allowed_minters, caller),
            E_NOT_ALLOWED_MINTER
        );
    }

    inline fun assert_is_allowed_burner(
        caller: address, token_state_addr: address
    ) {
        let token_state = &TokenState[token_state_addr];
        assert!(
            allowlist::is_allowed(&token_state.allowed_burners, caller),
            E_NOT_ALLOWED_BURNER
        );
    }

    inline fun borrow_refs(token_state_addr: address): &ManagementRefs {
        assert!(
            exists<ManagementRefs>(token_state_addr),
            E_TOKEN_NOT_INITIALIZED
        );
        &ManagementRefs[token_state_addr]
    }

    // ================================================================
    // |                      Ownable State                           |
    // ================================================================

    #[view]
    public fun owner(token_state: Object<TokenState>): address acquires TokenState {
        ownable::owner(&TokenState[object::object_address(&token_state)].ownable_state)
    }

    fun assert_only_owner(
        caller: address, token_state: Object<TokenState>
    ) acquires TokenState {
        ownable::assert_only_owner(
            caller, &TokenState[object::object_address(&token_state)].ownable_state
        )
    }

    /// ownable::transfer_ownership checks if the caller is the owner
    /// So we only extract the ownable state from the token state
    public entry fun transfer_ownership(
        caller: &signer, token_state: Object<TokenState>, to: address
    ) acquires TokenState {
        ownable::transfer_ownership(
            signer::address_of(caller),
            &mut TokenState[object::object_address(&token_state)].ownable_state,
            to
        )
    }

    /// Anyone can call this as `ownable::accept_ownership` verifies
    /// that the caller is the pending owner
    public entry fun accept_ownership(
        caller: &signer, token_state: Object<TokenState>
    ) acquires TokenState {
        ownable::accept_ownership(
            signer::address_of(caller),
            &mut TokenState[object::object_address(&token_state)].ownable_state
        )
    }

    /// ownable::execute_ownership_transfer checks if the caller is the owner
    /// So we only extract the ownable state from the token state
    public entry fun execute_ownership_transfer(
        caller: &signer, token_state: Object<TokenState>, to: address
    ) acquires TokenState {
        ownable::execute_ownership_transfer(
            caller,
            &mut TokenState[object::object_address(&token_state)].ownable_state,
            to
        )
    }

    // ================================================================
    // |                      MCMS Entrypoint                         |
    // ================================================================

    struct McmsCallback has drop {}

    public fun mcms_entrypoint<T: key>(
        _metadata: object::Object<T>
    ): Option<u128> acquires ManagementRefs, TokenState {
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
            let token_state_addr = bcs_stream::deserialize_address(&mut stream);
            let to = bcs_stream::deserialize_address(&mut stream);
            let amount = bcs_stream::deserialize_u64(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            mint(
                &caller,
                token_state_obj(token_state_addr),
                to,
                amount
            )
        } else if (function_bytes == b"burn") {
            let token_state_addr = bcs_stream::deserialize_address(&mut stream);
            let from = bcs_stream::deserialize_address(&mut stream);
            let amount = bcs_stream::deserialize_u64(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            burn(
                &caller,
                token_state_obj(token_state_addr),
                from,
                amount
            )
        } else if (function_bytes == b"apply_allowed_minter_updates") {
            let token_state_addr = bcs_stream::deserialize_address(&mut stream);
            let minters_to_remove =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let minters_to_add =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);

            apply_allowed_minter_updates(
                &caller,
                token_state_obj(token_state_addr),
                minters_to_remove,
                minters_to_add
            )
        } else if (function_bytes == b"apply_allowed_burner_updates") {
            let token_state_addr = bcs_stream::deserialize_address(&mut stream);
            let burners_to_remove =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let burners_to_add =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);

            apply_allowed_burner_updates(
                &caller,
                token_state_obj(token_state_addr),
                burners_to_remove,
                burners_to_add
            )
        } else if (function_bytes == b"transfer_ownership") {
            let token_state_addr = bcs_stream::deserialize_address(&mut stream);
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            transfer_ownership(&caller, token_state_obj(token_state_addr), to)
        } else if (function_bytes == b"accept_ownership") {
            let token_state_addr = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            accept_ownership(&caller, token_state_obj(token_state_addr))
        } else if (function_bytes == b"execute_ownership_transfer") {
            let token_state_addr = bcs_stream::deserialize_address(&mut stream);
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            execute_ownership_transfer(&caller, token_state_obj(token_state_addr), to)
        } else {
            abort E_UNKNOWN_FUNCTION
        };

        option::none()
    }

    fun token_state_obj(token_state_addr: address): Object<TokenState> {
        object::address_to_object<TokenState>(token_state_addr)
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }
}
