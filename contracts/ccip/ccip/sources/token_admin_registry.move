module ccip::token_admin_registry {
    use std::account;
    use std::dispatchable_fungible_asset;
    use std::error;
    use std::event::{Self, EventHandle};
    use std::function_info::{Self, FunctionInfo};
    use std::fungible_asset::{Self, Metadata, FungibleStore, FungibleAsset};
    use std::object::{Self, Object, ExtendRef, TransferRef};
    use std::option::{Self, Option};
    use std::signer;
    use std::big_ordered_map::{Self, BigOrderedMap};
    use std::string::{Self, String};
    use std::type_info::{Self, TypeInfo};

    use ccip::auth;
    use ccip::state_object;

    use mcms::bcs_stream;
    use mcms::mcms_registry;

    friend ccip::token_admin_dispatcher;

    enum ExecutionState has store, drop, copy {
        IDLE,
        LOCK_OR_BURN,
        RELEASE_OR_MINT
    }

    struct TokenAdminRegistryState has key, store {
        extend_ref: ExtendRef,
        transfer_ref: TransferRef,

        // fungible asset metadata address -> TokenConfig
        token_configs: BigOrderedMap<address, TokenConfig>,
        pool_set_events: EventHandle<PoolSet>,
        administrator_transfer_requested_events: EventHandle<AdministratorTransferRequested>,
        administrator_transferred_events: EventHandle<AdministratorTransferred>,
        token_unregistered_events: EventHandle<TokenUnregistered>
    }

    struct TokenConfig has store, drop, copy {
        token_pool_address: address,
        administrator: address,
        pending_administrator: address
    }

    struct TokenPoolRegistration has key, store {
        lock_or_burn_function: FunctionInfo,
        release_or_mint_function: FunctionInfo,
        proof_typeinfo: TypeInfo,
        dispatch_metadata: Object<Metadata>,
        dispatch_deposit_fungible_store: Object<FungibleStore>,
        dispatch_extend_ref: ExtendRef,
        dispatch_transfer_ref: TransferRef,
        dispatch_fa_transfer_ref: fungible_asset::TransferRef,
        execution_state: ExecutionState,
        executing_lock_or_burn_input_v1: Option<LockOrBurnInputV1>,
        executing_release_or_mint_input_v1: Option<ReleaseOrMintInputV1>,
        executing_lock_or_burn_output_v1: Option<LockOrBurnOutputV1>,
        executing_release_or_mint_output_v1: Option<ReleaseOrMintOutputV1>,
        local_token: address
    }

    struct LockOrBurnInputV1 has store, drop {
        sender: address,
        remote_chain_selector: u64,
        receiver: vector<u8>
    }

    struct LockOrBurnOutputV1 has store, drop {
        dest_token_address: vector<u8>,
        dest_pool_data: vector<u8>
    }

    struct ReleaseOrMintInputV1 has store, drop {
        sender: vector<u8>,
        receiver: address,
        source_amount: u256,
        local_token: address,
        remote_chain_selector: u64,
        source_pool_address: vector<u8>,
        source_pool_data: vector<u8>,
        offchain_token_data: vector<u8>
    }

    struct ReleaseOrMintOutputV1 has store, drop {
        destination_amount: u64
    }

    struct TokenPoolCallbacks has copy, drop, store {
        lock_or_burn: |FungibleAsset, LockOrBurnInputV1| (vector<u8>, vector<u8>),
        release_or_mint: |ReleaseOrMintInputV1| (FungibleAsset, u64)
    }

    struct TokenPoolRegistrationV2 has key {
        callbacks: TokenPoolCallbacks,
        local_token: address
    }

    #[event]
    struct PoolSet has store, drop {
        local_token: address,
        previous_pool_address: address,
        new_pool_address: address
    }

    #[event]
    struct AdministratorTransferRequested has store, drop {
        local_token: address,
        current_admin: address,
        new_admin: address
    }

    #[event]
    struct AdministratorTransferred has store, drop {
        local_token: address,
        new_admin: address
    }

    #[event]
    struct TokenUnregistered has store, drop {
        local_token: address,
        previous_pool_address: address
    }

    const E_INVALID_FUNGIBLE_ASSET: u64 = 1;
    const E_NOT_FUNGIBLE_ASSET_OWNER: u64 = 2;
    const E_INVALID_TOKEN_POOL: u64 = 3;
    const E_ALREADY_REGISTERED: u64 = 4;
    const E_UNKNOWN_FUNCTION: u64 = 5;
    const E_PROOF_NOT_IN_TOKEN_POOL_MODULE: u64 = 6;
    const E_PROOF_NOT_AT_TOKEN_POOL_ADDRESS: u64 = 7;
    const E_UNKNOWN_PROOF_TYPE: u64 = 8;
    const E_NOT_IN_IDLE_STATE: u64 = 9;
    const E_NOT_IN_LOCK_OR_BURN_STATE: u64 = 10;
    const E_NOT_IN_RELEASE_OR_MINT_STATE: u64 = 11;
    const E_NON_EMPTY_LOCK_OR_BURN_INPUT: u64 = 12;
    const E_NON_EMPTY_LOCK_OR_BURN_OUTPUT: u64 = 13;
    const E_NON_EMPTY_RELEASE_OR_MINT_INPUT: u64 = 14;
    const E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT: u64 = 15;
    const E_MISSING_LOCK_OR_BURN_INPUT: u64 = 16;
    const E_MISSING_LOCK_OR_BURN_OUTPUT: u64 = 17;
    const E_MISSING_RELEASE_OR_MINT_INPUT: u64 = 18;
    const E_MISSING_RELEASE_OR_MINT_OUTPUT: u64 = 19;
    const E_TOKEN_POOL_NOT_OBJECT: u64 = 20;
    const E_ADMIN_FOR_TOKEN_ALREADY_SET: u64 = 21;
    const E_FUNGIBLE_ASSET_NOT_REGISTERED: u64 = 22;
    const E_NOT_ADMINISTRATOR: u64 = 23;
    const E_NOT_PENDING_ADMINISTRATOR: u64 = 24;
    const E_NOT_AUTHORIZED: u64 = 25;
    const E_INVALID_TOKEN_FOR_POOL: u64 = 26;
    const E_ADMIN_NOT_SET_FOR_TOKEN: u64 = 27;
    const E_ADMIN_ALREADY_SET_FOR_TOKEN: u64 = 28;
    const E_ZERO_ADDRESS: u64 = 29;
    const E_POOL_NOT_REGISTERED: u64 = 30;
    const E_TOKEN_MISMATCH: u64 = 31;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"TokenAdminRegistry 1.6.0")
    }

    fun init_module(publisher: &signer) {
        // Register the entrypoint with mcms
        if (@mcms_register_entrypoints == @0x1) {
            register_mcms_entrypoint(publisher);
        };

        let state_object_signer = state_object::object_signer();

        let constructor_ref =
            object::create_named_object(
                &state_object_signer, b"CCIPTokenAdminRegistry"
            );
        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let transfer_ref = object::generate_transfer_ref(&constructor_ref);

        let state = TokenAdminRegistryState {
            extend_ref,
            transfer_ref,
            token_configs: big_ordered_map::new(),
            pool_set_events: account::new_event_handle(&state_object_signer),
            administrator_transfer_requested_events: account::new_event_handle(
                &state_object_signer
            ),
            administrator_transferred_events: account::new_event_handle(
                &state_object_signer
            ),
            token_unregistered_events: account::new_event_handle(&state_object_signer)
        };

        move_to(&state_object_signer, state);
    }

    #[view]
    public fun get_pools(
        local_tokens: vector<address>
    ): vector<address> acquires TokenAdminRegistryState {
        let state = borrow_state();

        local_tokens.map_ref(
            |local_token| {
                let local_token: address = *local_token;
                if (state.token_configs.contains(&local_token)) {
                    let token_config = state.token_configs.borrow(&local_token);
                    token_config.token_pool_address
                } else {
                    // returns @0x0 for assets without token pools.
                    @0x0
                }
            }
        )
    }

    #[view]
    /// returns the token pool address for the given local token, or @0x0 if the token is not registered.
    public fun get_pool(local_token: address): address acquires TokenAdminRegistryState {
        let state = borrow_state();
        if (state.token_configs.contains(&local_token)) {
            let token_config = state.token_configs.borrow(&local_token);
            token_config.token_pool_address
        } else {
            // returns @0x0 for assets without token pools.
            @0x0
        }
    }

    #[view]
    /// Returns the local token address for the token pool (supports both V1 and V2).
    public fun get_pool_local_token(
        token_pool_address: address
    ): address acquires TokenPoolRegistration, TokenPoolRegistrationV2 {
        if (exists<TokenPoolRegistrationV2>(token_pool_address)) {
            TokenPoolRegistrationV2[token_pool_address].local_token
        } else if (exists<TokenPoolRegistration>(token_pool_address)) {
            get_registration(token_pool_address).local_token
        } else {
            abort error::invalid_argument(E_POOL_NOT_REGISTERED)
        }
    }

    #[view]
    /// Returns the local token address for the token pool.
    public fun get_pool_local_token_v2(
        token_pool_address: address
    ): address acquires TokenPoolRegistrationV2 {
        TokenPoolRegistrationV2[token_pool_address].local_token
    }

    #[view]
    /// Returns true if token pool has TokenPoolRegistrationV2 resource
    public fun has_token_pool_registration_v2(
        token_pool_address: address
    ): bool {
        exists<TokenPoolRegistrationV2>(token_pool_address)
    }

    #[view]
    /// returns (token_pool_address, administrator, pending_administrator)
    public fun get_token_config(
        local_token: address
    ): (address, address, address) acquires TokenAdminRegistryState {
        let state = borrow_state();
        if (state.token_configs.contains(&local_token)) {
            let token_config = state.token_configs.borrow(&local_token);
            (
                token_config.token_pool_address,
                token_config.administrator,
                token_config.pending_administrator
            )
        } else {
            (@0x0, @0x0, @0x0)
        }
    }

    #[view]
    /// Get configured tokens paginated using a start key and limit.
    /// Caller should call this on a certain block to ensure you the same state for every call.
    ///
    /// This function retrieves a batch of token addresses from the registry, starting from
    /// the token address that comes after the provided start_key.
    ///
    /// @param start_key - Address to start pagination from (returns tokens AFTER this address)
    /// @param max_count - Maximum number of tokens to return
    ///
    /// @return:
    ///   - vector<address>: List of token addresses (up to max_count)
    ///   - address: Next key to use for pagination (pass this as start_key in next call)
    ///   - bool: Whether there are more tokens after this batch
    public fun get_all_configured_tokens(
        start_key: address, max_count: u64
    ): (vector<address>, address, bool) acquires TokenAdminRegistryState {
        let token_configs = &borrow_state().token_configs;
        let result = vector[];

        let current_key_opt = token_configs.next_key(&start_key);
        if (max_count == 0 || current_key_opt.is_none()) {
            return (result, start_key, current_key_opt.is_some())
        };

        let current_key = *current_key_opt.borrow();

        result.push_back(current_key);

        if (max_count == 1) {
            let has_more = token_configs.next_key(&current_key).is_some();
            return (result, current_key, has_more);
        };

        for (i in 1..max_count) {
            let next_key_opt = token_configs.next_key(&current_key);
            if (next_key_opt.is_none()) {
                return (result, current_key, false)
            };

            current_key = *next_key_opt.borrow();
            result.push_back(current_key);
        };

        // Check if there are more tokens after the last key
        let has_more = token_configs.next_key(&current_key).is_some();
        (result, current_key, has_more)
    }

    // ================================================================
    // |                       Register Pool                          |
    // ================================================================
    #[deprecated]
    /// @deprecated: Use `register_pool_v2()` instead.
    ///
    /// Registers pool with `TokenPoolRegistration` and sets up dynamic dispatch for a token pool
    /// Registry token config mapping must be done separately via `set_pool()`
    /// by token owner or ccip owner.
    public fun register_pool<ProofType: drop>(
        token_pool_account: &signer,
        token_pool_module_name: vector<u8>,
        local_token: address,
        _proof: ProofType
    ) acquires TokenAdminRegistryState {
        let token_pool_address = signer::address_of(token_pool_account);
        assert!(
            !exists<TokenPoolRegistration>(token_pool_address)
                && !exists<TokenPoolRegistrationV2>(token_pool_address),
            error::invalid_argument(E_ALREADY_REGISTERED)
        );
        assert!(
            object::object_exists<Metadata>(local_token),
            error::invalid_argument(E_INVALID_FUNGIBLE_ASSET)
        );

        let state = borrow_state_mut();

        let lock_or_burn_function =
            function_info::new_function_info(
                token_pool_account,
                string::utf8(token_pool_module_name),
                string::utf8(b"lock_or_burn")
            );
        let proof_typeinfo = type_info::type_of<ProofType>();
        assert!(
            proof_typeinfo.account_address() == token_pool_address,
            error::invalid_argument(E_PROOF_NOT_AT_TOKEN_POOL_ADDRESS)
        );
        assert!(
            proof_typeinfo.module_name() == token_pool_module_name,
            error::invalid_argument(E_PROOF_NOT_IN_TOKEN_POOL_MODULE)
        );

        let release_or_mint_function =
            function_info::new_function_info(
                token_pool_account,
                string::utf8(token_pool_module_name),
                string::utf8(b"release_or_mint")
            );

        let dispatch_constructor_ref =
            object::create_sticky_object(
                object::address_from_extend_ref(&state.extend_ref)
            );
        let dispatch_extend_ref = object::generate_extend_ref(&dispatch_constructor_ref);
        let dispatch_transfer_ref =
            object::generate_transfer_ref(&dispatch_constructor_ref);

        let dispatch_metadata =
            fungible_asset::add_fungibility(
                &dispatch_constructor_ref,
                option::none(),
                // max name length is 32 chars
                string::utf8(b"CCIPTokenAdminRegistry"),
                // max symbol length is 10 chars
                string::utf8(b"CCIPTAR"),
                0,
                string::utf8(b""),
                string::utf8(b"")
            );

        let dispatch_fa_transfer_ref =
            fungible_asset::generate_transfer_ref(&dispatch_constructor_ref);

        // create a FungibleStore for dispatchable_deposit(). it's valid for the FungibleStore to be on the same object
        // as the fungible asset Metadata itself.
        let dispatch_deposit_fungible_store =
            fungible_asset::create_store(&dispatch_constructor_ref, dispatch_metadata);

        dispatchable_fungible_asset::register_dispatch_functions(
            &dispatch_constructor_ref,
            /* withdraw_function= */ option::some(release_or_mint_function),
            /* deposit_function= */ option::some(lock_or_burn_function),
            /* derived_balance_function= */ option::none()
        );

        move_to(
            token_pool_account,
            TokenPoolRegistration {
                lock_or_burn_function,
                release_or_mint_function,
                proof_typeinfo,
                dispatch_metadata,
                dispatch_deposit_fungible_store,
                dispatch_extend_ref,
                dispatch_transfer_ref,
                dispatch_fa_transfer_ref,
                execution_state: ExecutionState::IDLE,
                executing_lock_or_burn_input_v1: option::none(),
                executing_release_or_mint_input_v1: option::none(),
                executing_lock_or_burn_output_v1: option::none(),
                executing_release_or_mint_output_v1: option::none(),
                local_token
            }
        );
    }

    /// Registers a V2 token pool using function-value callbacks (closures).
    ///
    /// Upgrade path: existing legacy pools can upgrade to V2 by calling this function,
    /// which supersedes the legacy registration without requiring `unregister_pool()`.
    /// New pools should use V2 directly. Once V2 is registered, legacy registration
    /// via `register_pool()` is rejected.
    public fun register_pool_v2(
        token_pool_account: &signer,
        local_token: address,
        lock_or_burn: |FungibleAsset, LockOrBurnInputV1| (vector<u8>, vector<u8>) has copy
        + drop + store,
        release_or_mint: |ReleaseOrMintInputV1| (FungibleAsset, u64) has copy + drop + store
    ) {
        let token_pool_address = signer::address_of(token_pool_account);
        assert!(
            !exists<TokenPoolRegistrationV2>(token_pool_address),
            error::invalid_argument(E_ALREADY_REGISTERED)
        );
        assert!(
            object::object_exists<Metadata>(local_token),
            error::invalid_argument(E_INVALID_FUNGIBLE_ASSET)
        );
        if (exists<TokenPoolRegistration>(token_pool_address)) {
            assert!(
                get_registration(token_pool_address).local_token == local_token,
                error::invalid_argument(E_TOKEN_MISMATCH)
            );
        };

        move_to(
            token_pool_account,
            TokenPoolRegistrationV2 {
                callbacks: TokenPoolCallbacks { lock_or_burn, release_or_mint },
                local_token
            }
        );
    }

    public entry fun unregister_pool(
        caller: &signer, local_token: address
    ) acquires TokenAdminRegistryState, TokenPoolRegistration, TokenPoolRegistrationV2 {
        let state = borrow_state_mut();
        assert!(
            state.token_configs.contains(&local_token),
            error::invalid_argument(E_FUNGIBLE_ASSET_NOT_REGISTERED)
        );

        let token_config = state.token_configs.remove(&local_token);
        assert!(
            token_config.administrator == signer::address_of(caller),
            error::permission_denied(E_NOT_ADMINISTRATOR)
        );

        let previous_pool_address = token_config.token_pool_address;
        if (exists<TokenPoolRegistration>(previous_pool_address)) {
            let TokenPoolRegistration {
                lock_or_burn_function: _,
                release_or_mint_function: _,
                proof_typeinfo: _,
                dispatch_metadata: _,
                dispatch_deposit_fungible_store: _,
                dispatch_extend_ref: _,
                dispatch_transfer_ref: _,
                dispatch_fa_transfer_ref: _,
                execution_state: _,
                executing_lock_or_burn_input_v1: _,
                executing_release_or_mint_input_v1: _,
                executing_lock_or_burn_output_v1: _,
                executing_release_or_mint_output_v1: _,
                local_token: _
            } = move_from<TokenPoolRegistration>(previous_pool_address);
        };

        if (exists<TokenPoolRegistrationV2>(previous_pool_address)) {
            let TokenPoolRegistrationV2 { callbacks: _, local_token: _ } =
                move_from<TokenPoolRegistrationV2>(previous_pool_address);
        };

        event::emit_event(
            &mut state.token_unregistered_events,
            TokenUnregistered {
                local_token,
                previous_pool_address: token_config.token_pool_address
            }
        );
    }

    public entry fun set_pool(
        caller: &signer, local_token: address, token_pool_address: address
    ) acquires TokenAdminRegistryState, TokenPoolRegistration, TokenPoolRegistrationV2 {
        assert!(
            object::object_exists<Metadata>(local_token),
            error::invalid_argument(E_INVALID_FUNGIBLE_ASSET)
        );

        let caller_addr = signer::address_of(caller);

        let pool_local_token =
            if (exists<TokenPoolRegistrationV2>(token_pool_address)) {
                get_pool_local_token_v2(token_pool_address)
            } else if (exists<TokenPoolRegistration>(token_pool_address)) {
                get_registration(token_pool_address).local_token
            } else {
                abort error::invalid_argument(E_POOL_NOT_REGISTERED)
            };

        assert!(
            pool_local_token == local_token,
            error::invalid_argument(E_INVALID_TOKEN_FOR_POOL)
        );

        let state = borrow_state_mut();
        assert!(
            state.token_configs.contains(&local_token),
            error::invalid_argument(E_ADMIN_NOT_SET_FOR_TOKEN)
        );

        let config = state.token_configs.borrow_mut(&local_token);
        assert!(
            config.administrator == caller_addr,
            error::permission_denied(E_NOT_ADMINISTRATOR)
        );

        let previous_pool_address = config.token_pool_address;
        config.token_pool_address = token_pool_address;

        if (previous_pool_address != token_pool_address) {
            event::emit_event(
                &mut state.pool_set_events,
                PoolSet {
                    local_token,
                    previous_pool_address,
                    new_pool_address: token_pool_address
                }
            );
        }
    }

    public entry fun propose_administrator(
        caller: &signer, local_token: address, administrator: address
    ) acquires TokenAdminRegistryState {
        assert!(
            object::object_exists<Metadata>(local_token),
            error::invalid_argument(E_INVALID_FUNGIBLE_ASSET)
        );

        let metadata = object::address_to_object<Metadata>(local_token);
        let caller_addr = signer::address_of(caller);

        // Allow CCIP owner or token owner to propose administrator
        assert!(
            object::owns(metadata, caller_addr) || caller_addr == auth::owner(),
            error::permission_denied(E_NOT_AUTHORIZED)
        );

        assert!(administrator != @0x0, error::invalid_argument(E_ZERO_ADDRESS));

        let state = borrow_state_mut();
        if (state.token_configs.contains(&local_token)) {
            let config = state.token_configs.borrow_mut(&local_token);
            assert!(
                config.administrator == @0x0,
                error::invalid_argument(E_ADMIN_FOR_TOKEN_ALREADY_SET)
            );
            config.pending_administrator = administrator;
        } else {
            state.token_configs.add(
                local_token,
                TokenConfig {
                    token_pool_address: @0x0,
                    administrator: @0x0,
                    pending_administrator: administrator
                }
            );
        };

        event::emit_event(
            &mut state.administrator_transfer_requested_events,
            AdministratorTransferRequested {
                local_token,
                current_admin: @0x0,
                new_admin: administrator
            }
        );
    }

    public entry fun transfer_admin_role(
        caller: &signer, local_token: address, new_admin: address
    ) acquires TokenAdminRegistryState {
        let state = borrow_state_mut();

        assert!(
            state.token_configs.contains(&local_token),
            error::invalid_argument(E_FUNGIBLE_ASSET_NOT_REGISTERED)
        );

        let token_config = state.token_configs.borrow_mut(&local_token);

        assert!(
            token_config.administrator == signer::address_of(caller),
            error::permission_denied(E_NOT_ADMINISTRATOR)
        );

        // can be @0x0 to cancel a pending transfer.
        token_config.pending_administrator = new_admin;

        event::emit_event(
            &mut state.administrator_transfer_requested_events,
            AdministratorTransferRequested {
                local_token,
                current_admin: token_config.administrator,
                new_admin
            }
        );
    }

    public entry fun accept_admin_role(
        caller: &signer, local_token: address
    ) acquires TokenAdminRegistryState {
        let state = borrow_state_mut();

        assert!(
            state.token_configs.contains(&local_token),
            error::invalid_argument(E_FUNGIBLE_ASSET_NOT_REGISTERED)
        );

        let token_config = state.token_configs.borrow_mut(&local_token);

        assert!(
            token_config.pending_administrator == signer::address_of(caller),
            error::permission_denied(E_NOT_PENDING_ADMINISTRATOR)
        );

        token_config.administrator = token_config.pending_administrator;
        token_config.pending_administrator = @0x0;

        event::emit_event(
            &mut state.administrator_transferred_events,
            AdministratorTransferred {
                local_token,
                new_admin: token_config.administrator
            }
        );
    }

    #[view]
    public fun is_administrator(
        local_token: address, administrator: address
    ): bool acquires TokenAdminRegistryState {
        let state = borrow_state();
        assert!(
            state.token_configs.contains(&local_token),
            error::invalid_argument(E_FUNGIBLE_ASSET_NOT_REGISTERED)
        );

        let token_config = state.token_configs.borrow(&local_token);
        token_config.administrator == administrator
    }

    // ================================================================
    // |                         Pool I/O V1                          |
    // ================================================================
    public fun get_lock_or_burn_input_v1<ProofType: drop>(
        token_pool_address: address, _proof: ProofType
    ): LockOrBurnInputV1 acquires TokenPoolRegistration {
        let registration = get_registration_mut(token_pool_address);

        assert!(
            type_info::type_of<ProofType>() == registration.proof_typeinfo,
            error::permission_denied(E_UNKNOWN_PROOF_TYPE)
        );

        assert!(
            registration.execution_state is ExecutionState::LOCK_OR_BURN,
            error::invalid_state(E_NOT_IN_LOCK_OR_BURN_STATE)
        );
        assert!(
            registration.executing_lock_or_burn_input_v1.is_some(),
            error::invalid_state(E_MISSING_LOCK_OR_BURN_INPUT)
        );
        assert!(
            registration.executing_lock_or_burn_output_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_OUTPUT)
        );
        assert!(
            registration.executing_release_or_mint_input_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_INPUT)
        );
        assert!(
            registration.executing_release_or_mint_output_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT)
        );

        registration.executing_lock_or_burn_input_v1.extract()
    }

    public fun set_lock_or_burn_output_v1<ProofType: drop>(
        token_pool_address: address,
        _proof: ProofType,
        dest_token_address: vector<u8>,
        dest_pool_data: vector<u8>
    ) acquires TokenPoolRegistration {
        let registration = get_registration_mut(token_pool_address);

        assert!(
            type_info::type_of<ProofType>() == registration.proof_typeinfo,
            error::permission_denied(E_UNKNOWN_PROOF_TYPE)
        );

        assert!(
            registration.execution_state is ExecutionState::LOCK_OR_BURN,
            error::invalid_state(E_NOT_IN_LOCK_OR_BURN_STATE)
        );
        assert!(
            registration.executing_lock_or_burn_input_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_INPUT)
        );
        assert!(
            registration.executing_lock_or_burn_output_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_OUTPUT)
        );
        assert!(
            registration.executing_release_or_mint_input_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_INPUT)
        );
        assert!(
            registration.executing_release_or_mint_output_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT)
        );

        registration.executing_lock_or_burn_output_v1.fill(
            LockOrBurnOutputV1 { dest_token_address, dest_pool_data }
        )
    }

    public fun get_release_or_mint_input_v1<ProofType: drop>(
        token_pool_address: address, _proof: ProofType
    ): ReleaseOrMintInputV1 acquires TokenPoolRegistration {
        let registration = get_registration_mut(token_pool_address);

        assert!(
            type_info::type_of<ProofType>() == registration.proof_typeinfo,
            error::permission_denied(E_UNKNOWN_PROOF_TYPE)
        );

        assert!(
            registration.execution_state is ExecutionState::RELEASE_OR_MINT,
            error::invalid_state(E_NOT_IN_RELEASE_OR_MINT_STATE)
        );
        assert!(
            registration.executing_release_or_mint_input_v1.is_some(),
            error::invalid_state(E_MISSING_RELEASE_OR_MINT_INPUT)
        );
        assert!(
            registration.executing_release_or_mint_output_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT)
        );
        assert!(
            registration.executing_lock_or_burn_input_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_INPUT)
        );
        assert!(
            registration.executing_lock_or_burn_output_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_OUTPUT)
        );

        registration.executing_release_or_mint_input_v1.extract()
    }

    public fun set_release_or_mint_output_v1<ProofType: drop>(
        token_pool_address: address, _proof: ProofType, destination_amount: u64
    ) acquires TokenPoolRegistration {
        let registration = get_registration_mut(token_pool_address);

        assert!(
            type_info::type_of<ProofType>() == registration.proof_typeinfo,
            error::permission_denied(E_UNKNOWN_PROOF_TYPE)
        );

        assert!(
            registration.execution_state is ExecutionState::RELEASE_OR_MINT,
            error::invalid_state(E_NOT_IN_RELEASE_OR_MINT_STATE)
        );
        assert!(
            registration.executing_release_or_mint_input_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_INPUT)
        );
        assert!(
            registration.executing_release_or_mint_output_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT)
        );
        assert!(
            registration.executing_lock_or_burn_input_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_INPUT)
        );
        assert!(
            registration.executing_lock_or_burn_output_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_OUTPUT)
        );

        registration.executing_release_or_mint_output_v1.fill(
            ReleaseOrMintOutputV1 { destination_amount }
        )
    }

    // LockOrBurnInput accessors
    public fun get_lock_or_burn_sender(input: &LockOrBurnInputV1): address {
        input.sender
    }

    public fun get_lock_or_burn_remote_chain_selector(
        input: &LockOrBurnInputV1
    ): u64 {
        input.remote_chain_selector
    }

    public fun get_lock_or_burn_receiver(input: &LockOrBurnInputV1): vector<u8> {
        input.receiver
    }

    // ReleaseOrMintInput accessors
    public fun get_release_or_mint_sender(input: &ReleaseOrMintInputV1): vector<u8> {
        input.sender
    }

    public fun get_release_or_mint_receiver(
        input: &ReleaseOrMintInputV1
    ): address {
        input.receiver
    }

    public fun get_release_or_mint_source_amount(
        input: &ReleaseOrMintInputV1
    ): u256 {
        input.source_amount
    }

    public fun get_release_or_mint_local_token(
        input: &ReleaseOrMintInputV1
    ): address {
        input.local_token
    }

    public fun get_release_or_mint_remote_chain_selector(
        input: &ReleaseOrMintInputV1
    ): u64 {
        input.remote_chain_selector
    }

    public fun get_release_or_mint_source_pool_address(
        input: &ReleaseOrMintInputV1
    ): vector<u8> {
        input.source_pool_address
    }

    public fun get_release_or_mint_source_pool_data(
        input: &ReleaseOrMintInputV1
    ): vector<u8> {
        input.source_pool_data
    }

    public fun get_release_or_mint_offchain_token_data(
        input: &ReleaseOrMintInputV1
    ): vector<u8> {
        input.offchain_token_data
    }

    // ================================================================
    // |                        Lock or Burn                          |
    // ================================================================
    public(friend) fun start_lock_or_burn(
        token_pool_address: address,
        sender: address,
        remote_chain_selector: u64,
        receiver: vector<u8>
    ): Object<FungibleStore> acquires TokenPoolRegistration {
        let registration = get_registration_mut(token_pool_address);

        assert!(
            registration.execution_state is ExecutionState::IDLE,
            error::invalid_state(E_NOT_IN_IDLE_STATE)
        );
        assert!(
            registration.executing_lock_or_burn_input_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_INPUT)
        );
        assert!(
            registration.executing_lock_or_burn_output_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_OUTPUT)
        );
        assert!(
            registration.executing_release_or_mint_input_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_INPUT)
        );
        assert!(
            registration.executing_release_or_mint_output_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT)
        );

        registration.execution_state = ExecutionState::LOCK_OR_BURN;
        registration.executing_lock_or_burn_input_v1.fill(
            LockOrBurnInputV1 { sender, remote_chain_selector, receiver }
        );

        registration.dispatch_deposit_fungible_store
    }

    public(friend) fun finish_lock_or_burn(
        token_pool_address: address
    ): (vector<u8>, vector<u8>) acquires TokenPoolRegistration {
        let registration = get_registration_mut(token_pool_address);

        assert!(
            registration.execution_state is ExecutionState::LOCK_OR_BURN,
            error::invalid_state(E_NOT_IN_LOCK_OR_BURN_STATE)
        );
        assert!(
            registration.executing_lock_or_burn_input_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_INPUT)
        );
        assert!(
            registration.executing_lock_or_burn_output_v1.is_some(),
            error::invalid_state(E_MISSING_LOCK_OR_BURN_OUTPUT)
        );
        assert!(
            registration.executing_release_or_mint_input_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_INPUT)
        );
        assert!(
            registration.executing_release_or_mint_output_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT)
        );

        registration.execution_state = ExecutionState::IDLE;

        // the dispatch callback is passed a fungible_asset::TransferRef reference which could allow the store to be frozen,
        // causing future deposit/withdraw callbacks to fail. note that this fungible store is only used as part of the dispatch
        // mechanism.
        // ref: https://github.com/aptos-labs/aptos-core/blob/7fc73792e9db11462c9a42038c4a9eb41cc00192/aptos-move/framework/aptos-framework/sources/fungible_asset.move#L923
        if (fungible_asset::is_frozen(registration.dispatch_deposit_fungible_store)) {
            fungible_asset::set_frozen_flag(
                &registration.dispatch_fa_transfer_ref,
                registration.dispatch_deposit_fungible_store,
                false
            );
        };

        let output = registration.executing_lock_or_burn_output_v1.extract();
        (output.dest_token_address, output.dest_pool_data)
    }

    // ================================================================
    // |                       Release or Mint                        |
    // ================================================================
    public(friend) fun start_release_or_mint(
        token_pool_address: address,
        sender: vector<u8>,
        receiver: address,
        source_amount: u256,
        local_token: address,
        remote_chain_selector: u64,
        source_pool_address: vector<u8>,
        source_pool_data: vector<u8>,
        offchain_token_data: vector<u8>
    ): (signer, Object<FungibleStore>) acquires TokenPoolRegistration {
        let registration = get_registration_mut(token_pool_address);

        assert!(
            registration.execution_state is ExecutionState::IDLE,
            error::invalid_state(E_NOT_IN_IDLE_STATE)
        );
        assert!(
            registration.executing_release_or_mint_input_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_INPUT)
        );
        assert!(
            registration.executing_release_or_mint_output_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT)
        );
        assert!(
            registration.executing_lock_or_burn_input_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_INPUT)
        );
        assert!(
            registration.executing_lock_or_burn_output_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_OUTPUT)
        );

        registration.execution_state = ExecutionState::RELEASE_OR_MINT;
        registration.executing_release_or_mint_input_v1.fill(
            ReleaseOrMintInputV1 {
                sender,
                receiver,
                source_amount,
                local_token,
                remote_chain_selector,
                source_pool_address,
                source_pool_data,
                offchain_token_data
            }
        );

        (
            object::generate_signer_for_extending(&registration.dispatch_extend_ref),
            registration.dispatch_deposit_fungible_store
        )
    }

    public(friend) fun finish_release_or_mint(
        token_pool_address: address
    ): u64 acquires TokenPoolRegistration {
        let registration = get_registration_mut(token_pool_address);

        assert!(
            registration.execution_state is ExecutionState::RELEASE_OR_MINT,
            error::invalid_state(E_NOT_IN_RELEASE_OR_MINT_STATE)
        );
        assert!(
            registration.executing_release_or_mint_input_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_INPUT)
        );
        assert!(
            registration.executing_release_or_mint_output_v1.is_some(),
            error::invalid_state(E_MISSING_RELEASE_OR_MINT_OUTPUT)
        );
        assert!(
            registration.executing_lock_or_burn_input_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_INPUT)
        );
        assert!(
            registration.executing_lock_or_burn_output_v1.is_none(),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_OUTPUT)
        );

        registration.execution_state = ExecutionState::IDLE;

        // the dispatch callback is passed a fungible_asset::TransferRef reference which could allow the store to be frozen,
        // causing future deposit/withdraw callbacks to fail. note that this fungible store is only used as part of the dispatch
        // mechanism.
        // ref: https://github.com/aptos-labs/aptos-core/blob/7fc73792e9db11462c9a42038c4a9eb41cc00192/aptos-move/framework/aptos-framework/sources/fungible_asset.move#L936
        if (fungible_asset::is_frozen(registration.dispatch_deposit_fungible_store)) {
            fungible_asset::set_frozen_flag(
                &registration.dispatch_fa_transfer_ref,
                registration.dispatch_deposit_fungible_store,
                false
            );
        };

        let output = registration.executing_release_or_mint_output_v1.extract();

        output.destination_amount
    }

    public(friend) fun lock_or_burn_v2(
        token_pool_address: address,
        fa: fungible_asset::FungibleAsset,
        sender: address,
        remote_chain_selector: u64,
        receiver: vector<u8>
    ): (vector<u8>, vector<u8>) acquires TokenPoolRegistrationV2 {
        let pool_config = &TokenPoolRegistrationV2[token_pool_address];
        let input = LockOrBurnInputV1 { sender, remote_chain_selector, receiver };

        (pool_config.callbacks.lock_or_burn)
        (fa, input)
    }

    public(friend) fun release_or_mint_v2(
        token_pool_address: address,
        sender: vector<u8>,
        receiver: address,
        source_amount: u256,
        local_token: address,
        remote_chain_selector: u64,
        source_pool_address: vector<u8>,
        source_pool_data: vector<u8>,
        offchain_token_data: vector<u8>
    ): (FungibleAsset, u64) acquires TokenPoolRegistrationV2 {
        let pool_config = &TokenPoolRegistrationV2[token_pool_address];
        let input =
            ReleaseOrMintInputV1 {
                sender,
                receiver,
                source_amount,
                local_token,
                remote_chain_selector,
                source_pool_address,
                source_pool_data,
                offchain_token_data
            };

        (pool_config.callbacks.release_or_mint)
        (input)
    }

    inline fun borrow_state(): &TokenAdminRegistryState {
        borrow_global<TokenAdminRegistryState>(state_object::object_address())
    }

    inline fun borrow_state_mut(): &mut TokenAdminRegistryState {
        borrow_global_mut<TokenAdminRegistryState>(state_object::object_address())
    }

    inline fun get_registration(token_pool_address: address): &TokenPoolRegistration {
        freeze(get_registration_mut(token_pool_address))
    }

    inline fun get_registration_mut(token_pool_address: address)
        : &mut TokenPoolRegistration {
        assert!(
            exists<TokenPoolRegistration>(token_pool_address),
            error::invalid_argument(E_INVALID_TOKEN_POOL)
        );
        borrow_global_mut<TokenPoolRegistration>(token_pool_address)
    }

    // ================================================================
    // |                      MCMS Entrypoint                         |
    // ================================================================
    struct McmsCallback has drop {}

    public fun mcms_entrypoint<T: key>(
        _metadata: Object<T>
    ): option::Option<u128> acquires TokenAdminRegistryState, TokenPoolRegistration, TokenPoolRegistrationV2 {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@ccip, McmsCallback {});

        let function_bytes = *function.bytes();
        let stream = bcs_stream::new(data);

        if (function_bytes == b"set_pool") {
            let local_token = bcs_stream::deserialize_address(&mut stream);
            let token_pool_address = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            set_pool(&caller, local_token, token_pool_address)
        } else if (function_bytes == b"propose_administrator") {
            let local_token = bcs_stream::deserialize_address(&mut stream);
            let administrator = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            propose_administrator(&caller, local_token, administrator)
        } else if (function_bytes == b"transfer_admin_role") {
            let local_token = bcs_stream::deserialize_address(&mut stream);
            let new_admin = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            transfer_admin_role(&caller, local_token, new_admin)
        } else if (function_bytes == b"accept_admin_role") {
            let local_token = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            accept_admin_role(&caller, local_token)
        } else {
            abort error::invalid_argument(E_UNKNOWN_FUNCTION)
        };

        option::none()
    }

    /// Callable during upgrades
    public(friend) fun register_mcms_entrypoint(publisher: &signer) {
        mcms_registry::register_entrypoint(
            publisher, string::utf8(b"token_admin_registry"), McmsCallback {}
        );
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }

    #[test_only]
    public fun get_token_unregistered_events(): vector<TokenUnregistered> acquires TokenAdminRegistryState {
        event::emitted_events_by_handle<TokenUnregistered>(
            &borrow_state().token_unregistered_events
        )
    }

    #[test_only]
    fun insert_token_addresses_for_test(
        token_addresses: vector<address>
    ) acquires TokenAdminRegistryState {
        let state = borrow_state_mut();

        token_addresses.for_each(
            |token_address| {
                state.token_configs.add(
                    token_address,
                    TokenConfig {
                        token_pool_address: @0x0,
                        administrator: @0x0,
                        pending_administrator: @0x0
                    }
                );
            }
        );
    }

    #[test(publisher = @ccip)]
    fun test_get_all_configured_tokens(publisher: &signer) acquires TokenAdminRegistryState {
        state_object::init_module_for_testing(publisher);
        init_module_for_testing(publisher);

        insert_token_addresses_for_test(vector[@0x1, @0x2, @0x3]);

        let (res, next_key, has_more) = get_all_configured_tokens(@0x0, 0);
        assert!(res.length() == 0);
        assert!(next_key == @0x0);
        assert!(has_more);

        let (res, next_key, has_more) = get_all_configured_tokens(@0x0, 3);
        assert!(res.length() == 3);
        assert!(vector[@0x1, @0x2, @0x3] == res);
        assert!(next_key == @0x3);
        assert!(!has_more);
    }

    #[test(publisher = @ccip)]
    fun test_get_all_configured_tokens_edge_cases(
        publisher: &signer
    ) acquires TokenAdminRegistryState {
        state_object::init_module_for_testing(publisher);
        init_module_for_testing(publisher);

        // Test case 1: Empty state
        let (res, next_key, has_more) = get_all_configured_tokens(@0x0, 1);
        assert!(res.length() == 0);
        assert!(next_key == @0x0);
        assert!(!has_more);

        // Test case 2: Single token
        insert_token_addresses_for_test(vector[@0x1]);
        let (res, _next_key, has_more) = get_all_configured_tokens(@0x0, 1);
        assert!(res.length() == 1);
        assert!(res[0] == @0x1);
        assert!(!has_more);

        // Test case 3: Start from middle
        insert_token_addresses_for_test(vector[@0x2, @0x3]);
        let (res, _next_key, has_more) = get_all_configured_tokens(@0x1, 2);
        assert!(res.length() == 2);
        assert!(res[0] == @0x2);
        assert!(res[1] == @0x3);
        assert!(!has_more);

        // Test case 4: Request more than available
        let (res, _next_key, has_more) = get_all_configured_tokens(@0x0, 5);
        assert!(res.length() == 3);
        assert!(res[0] == @0x1);
        assert!(res[1] == @0x2);
        assert!(res[2] == @0x3);
        assert!(!has_more);
    }

    #[test(publisher = @ccip)]
    fun test_get_all_configured_tokens_pagination(
        publisher: &signer
    ) acquires TokenAdminRegistryState {
        state_object::init_module_for_testing(publisher);
        init_module_for_testing(publisher);

        insert_token_addresses_for_test(vector[@0x1, @0x2, @0x3, @0x4, @0x5]);

        // Test pagination with different chunk sizes
        let current_key = @0x0;
        let total_tokens = vector[];

        // First page: get 2 tokens
        let (res, next_key, more) = get_all_configured_tokens(current_key, 2);
        assert!(res.length() == 2);
        assert!(res[0] == @0x1);
        assert!(res[1] == @0x2);
        assert!(more);
        current_key = next_key;
        total_tokens.append(res);

        // Second page: get 2 more tokens
        let (res, next_key, more) = get_all_configured_tokens(current_key, 2);
        assert!(res.length() == 2);
        assert!(res[0] == @0x3);
        assert!(res[1] == @0x4);
        assert!(more);
        current_key = next_key;
        total_tokens.append(res);

        // Last page: get remaining token
        let (res, _next_key, more) = get_all_configured_tokens(current_key, 2);
        assert!(res.length() == 1);
        assert!(res[0] == @0x5);
        assert!(!more);
        total_tokens.append(res);

        // Verify we got all tokens in order
        assert!(total_tokens.length() == 5);
        assert!(total_tokens[0] == @0x1);
        assert!(total_tokens[1] == @0x2);
        assert!(total_tokens[2] == @0x3);
        assert!(total_tokens[3] == @0x4);
        assert!(total_tokens[4] == @0x5);
    }

    #[test(publisher = @ccip)]
    fun test_get_all_configured_tokens_non_existent(
        publisher: &signer
    ) acquires TokenAdminRegistryState {
        state_object::init_module_for_testing(publisher);
        init_module_for_testing(publisher);

        insert_token_addresses_for_test(vector[@0x1, @0x2, @0x3]);

        // Test starting from non-existent key
        let (res, next_key, has_more) = get_all_configured_tokens(@0x4, 1);
        assert!(res.length() == 0);
        assert!(next_key == @0x4);
        assert!(!has_more);

        // Test starting from key between existing tokens
        let (res, _next_key, has_more) = get_all_configured_tokens(@0x1, 1);
        assert!(res.length() == 1);
        assert!(res[0] == @0x2);
        assert!(has_more);
    }
}
