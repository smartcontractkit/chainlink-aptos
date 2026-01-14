module managed_token::managed_token {
    use std::account;
    use std::event::{Self, EventHandle};
    use std::fungible_asset::{Self, BurnRef, Metadata, MintRef, TransferRef};
    use std::object::{
        Self,
        ExtendRef,
        Object,
        TransferRef as ObjectTransferRef
    };
    use std::option::{Option};
    use std::primary_fungible_store;
    use std::signer;
    use std::string::{Self, String};

    use managed_token::allowlist::{Self, AllowlistState};
    use managed_token::ownable::{Self, OwnableState};

    const TOKEN_STATE_SEED: vector<u8> = b"managed_token::managed_token::token_state";

    struct TokenStateDeployment has key {
        extend_ref: ExtendRef,
        transfer_ref: ObjectTransferRef,
        ownable_state: OwnableState,
        allowed_minters: AllowlistState,
        allowed_burners: AllowlistState,
        initialize_events: EventHandle<Initialize>,
        mint_events: EventHandle<Mint>,
        burn_events: EventHandle<Burn>
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct TokenState has key {
        extend_ref: ExtendRef,
        transfer_ref: ObjectTransferRef,
        ownable_state: OwnableState,
        allowed_minters: AllowlistState,
        allowed_burners: AllowlistState,
        token: Object<Metadata>,
        initialize_events: EventHandle<Initialize>,
        mint_events: EventHandle<Mint>,
        burn_events: EventHandle<Burn>
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct TokenMetadataRefs has key {
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

    const E_NOT_PUBLISHER: u64 = 1;
    const E_NOT_ALLOWED_MINTER: u64 = 2;
    const E_NOT_ALLOWED_BURNER: u64 = 3;
    const E_TOKEN_NOT_INITIALIZED: u64 = 4;
    const E_TOKEN_ALREADY_INITIALIZED: u64 = 5;
    const E_TOKEN_STATE_DEPLOYMENT_ALREADY_INITIALIZED: u64 = 6;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"ManagedToken 1.0.0")
    }

    #[view]
    public fun token_state_address(): address {
        token_state_address_internal()
    }

    inline fun token_state_address_internal(): address {
        object::create_object_address(&@managed_token, TOKEN_STATE_SEED)
    }

    #[view]
    public fun token_metadata(): address acquires TokenState {
        assert!(
            exists<TokenState>(token_state_address_internal()),
            E_TOKEN_NOT_INITIALIZED
        );
        token_metadata_internal(&TokenState[token_state_address_internal()])
    }

    inline fun token_metadata_internal(state: &TokenState): address {
        object::object_address(&state.token)
    }

    #[view]
    public fun get_allowed_minters(): vector<address> acquires TokenState {
        allowlist::get_allowlist(
            &TokenState[token_state_address_internal()].allowed_minters
        )
    }

    #[view]
    public fun get_allowed_burners(): vector<address> acquires TokenState {
        allowlist::get_allowlist(
            &TokenState[token_state_address_internal()].allowed_burners
        )
    }

    #[view]
    public fun is_minter_allowed(minter: address): bool acquires TokenState {
        allowlist::is_allowed(
            &TokenState[token_state_address_internal()].allowed_minters,
            minter
        )
    }

    #[view]
    public fun is_burner_allowed(burner: address): bool acquires TokenState {
        allowlist::is_allowed(
            &TokenState[token_state_address_internal()].allowed_burners,
            burner
        )
    }

    /// `publisher` is the code object, deployed through object_code_deployment
    fun init_module(publisher: &signer) {
        assert!(object::is_object(@managed_token), E_NOT_PUBLISHER);

        // Create object owned by code object
        let constructor_ref = &object::create_named_object(publisher, TOKEN_STATE_SEED);
        let extend_ref = object::generate_extend_ref(constructor_ref);
        let token_state_signer = &object::generate_signer(constructor_ref);

        // create an Account on the object for event handles.
        account::create_account_if_does_not_exist(signer::address_of(token_state_signer));

        let allowed_minters =
            allowlist::new_with_name(
                token_state_signer, vector[], string::utf8(b"minters")
            );
        allowlist::set_allowlist_enabled(&mut allowed_minters, true);

        let allowed_burners =
            allowlist::new_with_name(
                token_state_signer, vector[], string::utf8(b"burners")
            );
        allowlist::set_allowlist_enabled(&mut allowed_burners, true);

        move_to(
            token_state_signer,
            TokenStateDeployment {
                extend_ref,
                transfer_ref: object::generate_transfer_ref(constructor_ref),
                ownable_state: ownable::new(token_state_signer, @managed_token),
                allowed_minters,
                allowed_burners,
                initialize_events: account::new_event_handle(token_state_signer),
                mint_events: account::new_event_handle(token_state_signer),
                burn_events: account::new_event_handle(token_state_signer)
            }
        );
    }

    // ================================================================
    // |                      Only Owner Functions                     |
    // ================================================================

    /// Only owner of this code object can initialize a token once
    public entry fun initialize(
        publisher: &signer,
        max_supply: Option<u128>,
        name: String,
        symbol: String,
        decimals: u8,
        icon: String,
        project: String
    ) acquires TokenStateDeployment {
        let publisher_addr = signer::address_of(publisher);
        let token_state_address = token_state_address_internal();

        assert!(
            exists<TokenStateDeployment>(token_state_address),
            E_TOKEN_STATE_DEPLOYMENT_ALREADY_INITIALIZED
        );

        let TokenStateDeployment {
            extend_ref,
            transfer_ref,
            ownable_state,
            allowed_minters,
            allowed_burners,
            initialize_events,
            mint_events,
            burn_events
        } = move_from<TokenStateDeployment>(token_state_address);

        assert_only_owner(signer::address_of(publisher), &ownable_state);

        let token_state_signer = &object::generate_signer_for_extending(&extend_ref);

        // Code object owns token state, which owns the fungible asset
        // Code object => token state => fungible asset
        let constructor_ref =
            &object::create_named_object(token_state_signer, *symbol.bytes());
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
            TokenMetadataRefs {
                extend_ref: object::generate_extend_ref(constructor_ref),
                mint_ref: fungible_asset::generate_mint_ref(constructor_ref),
                burn_ref: fungible_asset::generate_burn_ref(constructor_ref),
                transfer_ref: fungible_asset::generate_transfer_ref(constructor_ref)
            }
        );

        let token = object::object_from_constructor_ref(constructor_ref);

        event::emit_event(
            &mut initialize_events,
            Initialize {
                publisher: publisher_addr,
                token,
                max_supply,
                decimals,
                icon,
                project
            }
        );

        move_to(
            token_state_signer,
            TokenState {
                extend_ref,
                transfer_ref,
                ownable_state,
                allowed_minters,
                allowed_burners,
                token,
                initialize_events,
                mint_events,
                burn_events
            }
        );
    }

    public entry fun apply_allowed_minter_updates(
        caller: &signer, minters_to_remove: vector<address>, minters_to_add: vector<address>
    ) acquires TokenState {
        let token_state = &mut TokenState[token_state_address_internal()];
        assert_only_owner(signer::address_of(caller), &token_state.ownable_state);

        allowlist::apply_allowlist_updates(
            &mut token_state.allowed_minters,
            minters_to_remove,
            minters_to_add
        );
    }

    public entry fun apply_allowed_burner_updates(
        caller: &signer, burners_to_remove: vector<address>, burners_to_add: vector<address>
    ) acquires TokenState {
        let token_state = &mut TokenState[token_state_address_internal()];
        assert_only_owner(signer::address_of(caller), &token_state.ownable_state);

        allowlist::apply_allowlist_updates(
            &mut token_state.allowed_burners,
            burners_to_remove,
            burners_to_add
        );
    }

    // ================================================================
    // |                      Mint/Burn Functions                      |
    // ================================================================
    public entry fun mint(
        minter: &signer, to: address, amount: u64
    ) acquires TokenMetadataRefs, TokenState {
        let minter_addr = signer::address_of(minter);
        let state = &mut TokenState[token_state_address_internal()];
        assert_is_allowed_minter(minter_addr, state);

        if (amount == 0) { return };

        primary_fungible_store::mint(
            &borrow_token_metadata_refs(state).mint_ref, to, amount
        );

        event::emit_event(
            &mut state.mint_events,
            Mint { minter: minter_addr, to, amount }
        );
    }

    public entry fun burn(
        burner: &signer, from: address, amount: u64
    ) acquires TokenMetadataRefs, TokenState {
        let burner_addr = signer::address_of(burner);
        let state = &mut TokenState[token_state_address_internal()];
        assert_is_allowed_burner(burner_addr, state);

        if (amount == 0) { return };

        primary_fungible_store::burn(
            &borrow_token_metadata_refs(state).burn_ref, from, amount
        );

        event::emit_event(
            &mut state.burn_events,
            Burn { burner: burner_addr, from, amount }
        );
    }

    inline fun assert_is_allowed_minter(
        caller: address, state: &TokenState
    ) {
        assert!(
            caller == owner_internal(state)
                || allowlist::is_allowed(&state.allowed_minters, caller),
            E_NOT_ALLOWED_MINTER
        );
    }

    inline fun assert_is_allowed_burner(
        caller: address, state: &TokenState
    ) {
        assert!(
            caller == owner_internal(state)
                || allowlist::is_allowed(&state.allowed_burners, caller),
            E_NOT_ALLOWED_BURNER
        );
    }

    inline fun borrow_token_metadata_refs(state: &TokenState): &TokenMetadataRefs {
        &TokenMetadataRefs[token_metadata_internal(state)]
    }

    // ================================================================
    // |                      Ownable State                           |
    // ================================================================
    #[view]
    public fun owner(): address acquires TokenState {
        owner_internal(&TokenState[token_state_address_internal()])
    }

    #[view]
    public fun has_pending_transfer(): bool acquires TokenState {
        ownable::has_pending_transfer(
            &TokenState[token_state_address_internal()].ownable_state
        )
    }

    #[view]
    public fun pending_transfer_from(): Option<address> acquires TokenState {
        ownable::pending_transfer_from(
            &TokenState[token_state_address_internal()].ownable_state
        )
    }

    #[view]
    public fun pending_transfer_to(): Option<address> acquires TokenState {
        ownable::pending_transfer_to(
            &TokenState[token_state_address_internal()].ownable_state
        )
    }

    #[view]
    public fun pending_transfer_accepted(): Option<bool> acquires TokenState {
        ownable::pending_transfer_accepted(
            &TokenState[token_state_address_internal()].ownable_state
        )
    }

    inline fun owner_internal(state: &TokenState): address {
        ownable::owner(&state.ownable_state)
    }

    fun assert_only_owner(caller: address, ownable_state: &OwnableState) {
        ownable::assert_only_owner(caller, ownable_state)
    }

    /// ownable::transfer_ownership checks if the caller is the owner
    /// So we only extract the ownable state from the token state
    public entry fun transfer_ownership(caller: &signer, to: address) acquires TokenState {
        ownable::transfer_ownership(
            caller,
            &mut TokenState[token_state_address_internal()].ownable_state,
            to
        )
    }

    /// Anyone can call this as `ownable::accept_ownership` verifies
    /// that the caller is the pending owner
    public entry fun accept_ownership(caller: &signer) acquires TokenState {
        ownable::accept_ownership(
            caller,
            &mut TokenState[token_state_address_internal()].ownable_state
        )
    }

    /// ownable::execute_ownership_transfer checks if the caller is the owner
    /// So we only extract the ownable state from the token state
    public entry fun execute_ownership_transfer(
        caller: &signer, to: address
    ) acquires TokenState {
        ownable::execute_ownership_transfer(
            caller,
            &mut TokenState[token_state_address_internal()].ownable_state,
            to
        )
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }
}
