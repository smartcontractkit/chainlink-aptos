module ccip::token_admin_registry {
    use std::bcs;
    use std::dispatchable_fungible_asset;
    use std::error;
    use std::function_info::{Self, FunctionInfo};
    use std::fungible_asset::{Self, Metadata, FungibleStore};
    use std::object::{Self, Object, ObjectCore, ExtendRef, TransferRef};
    use std::option::{Self, Option};
    use std::signer;
    use std::smart_table::{Self, SmartTable};
    use std::string;
    use std::type_info::{Self, TypeInfo};
    use std::vector;

    use ccip::ownable;

    friend ccip::token_admin_dispatcher;

    const EXECUTION_STATE_IDLE: u8 = 1;
    const EXECUTION_STATE_LOCK_OR_BURN: u8 = 2;
    const EXECUTION_STATE_RELEASE_OR_MINT: u8 = 3;

    struct TokenAdminRegistryState has key, store {
        ownable_state: ownable::OwnableState,
        extend_ref: ExtendRef,
        transfer_ref: TransferRef,

        // fungible asset metadata address -> TokenConfig
        // TODO: there were previously raised concerns during an audit that a user could maliciously calculate the bucket for a key and
        // cause repeated splitting, but we need to retrieve all the keys, which isn't available in Table.
        // consider other solutions.
        token_configs: SmartTable<address, TokenConfig>
    }

    struct TokenConfig has store, drop, copy {
        token_pool_address: address,
        administrator: address,
        pending_administrator: address
    }

    struct TokenPoolRegistration has key, store, drop {
        lock_or_burn_function: FunctionInfo,
        release_or_mint_function: FunctionInfo,
        proof_typeinfo: TypeInfo,
        dispatch_metadata: Object<Metadata>,
        dispatch_deposit_fungible_store: Object<FungibleStore>,
        dispatch_extend_ref: ExtendRef,
        dispatch_transfer_ref: TransferRef,
        dispatch_fa_transfer_ref: fungible_asset::TransferRef,
        execution_state: u8,
        executing_lock_or_burn_input: Option<LockOrBurnInput>,
        executing_release_or_mint_input: Option<ReleaseOrMintInput>,
        executing_lock_or_burn_output: Option<LockOrBurnOutput>,
        executing_release_or_mint_output: Option<ReleaseOrMintOutput>
    }

    struct LockOrBurnInput has store, drop {
        sender: address,
        remote_chain_selector: u64,
        receiver: vector<u8>
    }

    struct LockOrBurnOutput has store, drop {
        dest_token_address: vector<u8>,
        dest_pool_data: vector<u8>
    }

    struct ReleaseOrMintInput has store, drop {
        sender: vector<u8>,
        remote_chain_selector: u64,
        receiver: address,
        source_pool_address: vector<u8>,
        source_pool_data: vector<u8>,
        offchain_token_data: vector<u8>
    }

    // TODO: consider removing ReleaseOrMintOutput, it exists only for a consistent UX across lock and release,
    // since the withdraw() call's FungibleAsset would have the same amount.
    struct ReleaseOrMintOutput has store, drop {
        destination_amount: u64
    }

    const E_NOT_PUBLISHER: u64 = 1;
    const E_ALREADY_INITIALIZED: u64 = 2;
    const E_INVALID_FUNGIBLE_ASSET: u64 = 3;
    const E_NOT_FUNGIBLE_ASSET_OWNER: u64 = 4;
    const E_INVALID_TOKEN_POOL: u64 = 5;
    const E_ALREADY_REGISTERED: u64 = 6;
    const E_DUPLICATE_PROOF_TYPES: u64 = 7;
    const E_PROOF_NOT_IN_TOKEN_POOL_MODULE: u64 = 8;
    const E_PROOF_NOT_AT_TOKEN_POOL_ADDRESS: u64 = 9;
    const E_UNKNOWN_PROOF_TYPE: u64 = 10;
    const E_NOT_IN_IDLE_STATE: u64 = 11;
    const E_NOT_IN_LOCK_OR_BURN_STATE: u64 = 12;
    const E_NOT_IN_RELEASE_OR_MINT_STATE: u64 = 13;
    const E_NON_EMPTY_LOCK_OR_BURN_INPUT: u64 = 14;
    const E_NON_EMPTY_LOCK_OR_BURN_OUTPUT: u64 = 15;
    const E_NON_EMPTY_RELEASE_OR_MINT_INPUT: u64 = 16;
    const E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT: u64 = 17;
    const E_MISSING_LOCK_OR_BURN_INPUT: u64 = 18;
    const E_MISSING_LOCK_OR_BURN_OUTPUT: u64 = 19;
    const E_MISSING_RELEASE_OR_MINT_INPUT: u64 = 20;
    const E_MISSING_RELEASE_OR_MINT_OUTPUT: u64 = 21;
    const E_TOKEN_POOL_NOT_OBJECT: u64 = 22;
    const E_FUNGIBLE_ASSET_ALREADY_REGISTERED: u64 = 23;

    fun init_module(publisher: &signer) {
        initialize(publisher)
    }

    public fun initialize(caller: &signer) {
        assert!(
            signer::address_of(caller) == @ccip,
            error::invalid_argument(E_NOT_PUBLISHER)
        );
        assert!(
            !exists<TokenAdminRegistryState>(@ccip),
            error::invalid_argument(E_ALREADY_INITIALIZED)
        );

        let constructor_ref =
            object::create_named_object(caller, b"CCIPTokenAdminRegistry");
        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let transfer_ref = object::generate_transfer_ref(&constructor_ref);

        let state = TokenAdminRegistryState {
            ownable_state: ownable::new(caller, @0x0),
            extend_ref,
            transfer_ref,
            token_configs: smart_table::new()
        };

        move_to(caller, state);
    }

    #[view]
    public fun get_pools(
        fungible_assets: vector<address>
    ): vector<address> acquires TokenAdminRegistryState {
        let state = borrow_state();

        vector::map_ref(
            &fungible_assets,
            |fungible_asset_address| {
                let fungible_asset_address: address = *fungible_asset_address;
                if (smart_table::contains(&state.token_configs, fungible_asset_address)) {
                    let token_config =
                        smart_table::borrow(
                            &state.token_configs, fungible_asset_address
                        );
                    token_config.token_pool_address
                } else {
                    // returns @0x0 for assets without token pools.
                    @0x0
                }
            }
        )
    }

    #[view]
    public fun get_pool(fungible_asset: address): address acquires TokenAdminRegistryState {
        let state = borrow_state();
        if (smart_table::contains(&state.token_configs, fungible_asset)) {
            let token_config = smart_table::borrow(&state.token_configs, fungible_asset);
            token_config.token_pool_address
        } else {
            // returns @0x0 for assets without token pools.
            @0x0
        }
    }

    #[view]
    public fun get_token_config(
        fungible_asset: address
    ): (address, address, address) acquires TokenAdminRegistryState {
        let state = borrow_state();
        if (smart_table::contains(&state.token_configs, fungible_asset)) {
            let token_config = smart_table::borrow(&state.token_configs, fungible_asset);
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
    public fun get_all_configured_tokens(
        starting_bucket_index: u64,
        starting_vector_index: u64,
        max_count: u64
    ): (vector<address>, Option<u64>, Option<u64>) acquires TokenAdminRegistryState {
        // see the SmartTable documentation for descriptions of the function paramters and return values.
        // ref: https://github.com/aptos-labs/aptos-core/blob/6593fb81261f25490ffddc2252a861c994234c2a/aptos-move/framework/aptos-stdlib/sources/data_structures/smart_table.move#L212

        let state = borrow_state();
        smart_table::keys_paginated(
            &state.token_configs,
            starting_bucket_index,
            starting_vector_index,
            max_count
        )
    }

    public fun register_pool<ProofType: drop>(
        token_pool_account: &signer,
        token_pool_module_name: vector<u8>,
        fungible_asset_metadata: Object<Metadata>,
        _proof: ProofType
    ) acquires TokenAdminRegistryState {
        assert!(
            object::object_exists<Metadata>(
                object::object_address(&fungible_asset_metadata)
            ),
            error::invalid_argument(E_INVALID_FUNGIBLE_ASSET)
        );

        let token_pool_address = signer::address_of(token_pool_account);
        assert!(
            !exists<TokenPoolRegistration>(token_pool_address),
            error::invalid_argument(E_ALREADY_REGISTERED)
        );

        let state = borrow_state_mut();

        assert_can_register(
            ownable::owner(&state.ownable_state),
            signer::address_of(token_pool_account),
            fungible_asset_metadata
        );

        let fungible_asset_address = object::object_address(&fungible_asset_metadata);
        assert!(
            !smart_table::contains(&state.token_configs, fungible_asset_address),
            error::invalid_argument(E_FUNGIBLE_ASSET_ALREADY_REGISTERED)
        );

        // the initial administrator will always be the token pool account.
        // callers can immediately propose a new administrator afterwards if
        // needed.
        let token_config = TokenConfig {
            token_pool_address,
            administrator: token_pool_address,
            pending_administrator: @0x0
        };

        smart_table::add(&mut state.token_configs, fungible_asset_address, token_config);

        let lock_or_burn_function =
            function_info::new_function_info(
                token_pool_account,
                string::utf8(token_pool_module_name),
                string::utf8(b"lock_or_burn")
            );
        let proof_typeinfo = type_info::type_of<ProofType>();
        assert!(
            type_info::account_address(&proof_typeinfo) == token_pool_address,
            error::invalid_argument(E_PROOF_NOT_AT_TOKEN_POOL_ADDRESS)
        );
        assert!(
            type_info::module_name(&proof_typeinfo) == token_pool_module_name,
            error::invalid_argument(E_PROOF_NOT_IN_TOKEN_POOL_MODULE)
        );

        let release_or_mint_function =
            function_info::new_function_info(
                token_pool_account,
                string::utf8(token_pool_module_name),
                string::utf8(b"release_or_mint")
            );

        let dispatch_signer = object::generate_signer_for_extending(&state.extend_ref);

        let dispatch_constructor_ref =
            object::create_named_object(
                &dispatch_signer, bcs::to_bytes(&token_pool_address)
            );
        let dispatch_extend_ref = object::generate_extend_ref(&dispatch_constructor_ref);
        let dispatch_transfer_ref =
            object::generate_transfer_ref(&dispatch_constructor_ref);
        let dispatch_fa_transfer_ref =
            fungible_asset::generate_transfer_ref(&dispatch_constructor_ref);

        let dispatch_metadata =
            fungible_asset::add_fungibility(
                &dispatch_constructor_ref,
                option::none(),
                // this was `typename` but it fails due to ENAME_TOO_LONG
                string::utf8(b"TokenAdminRegistry"),
                string::utf8(b"TAR"),
                0,
                string::utf8(b""),
                string::utf8(b"")
            );

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
                execution_state: EXECUTION_STATE_IDLE,
                executing_lock_or_burn_input: option::none(),
                executing_release_or_mint_input: option::none(),
                executing_lock_or_burn_output: option::none(),
                executing_release_or_mint_output: option::none()
            }
        );
    }

    public fun get_lock_or_burn_input<ProofType: drop>(
        token_pool_address: address, _proof: ProofType
    ): LockOrBurnInput acquires TokenPoolRegistration {
        let registration = get_registration_mut(token_pool_address);

        assert!(
            type_info::type_of<ProofType>() == registration.proof_typeinfo,
            error::permission_denied(E_UNKNOWN_PROOF_TYPE)
        );

        assert!(
            registration.execution_state == EXECUTION_STATE_LOCK_OR_BURN,
            error::invalid_state(E_NOT_IN_LOCK_OR_BURN_STATE)
        );
        assert!(
            option::is_some(&registration.executing_lock_or_burn_input),
            error::invalid_state(E_MISSING_LOCK_OR_BURN_INPUT)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_output),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_OUTPUT)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_input),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_INPUT)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_output),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT)
        );

        option::extract(&mut registration.executing_lock_or_burn_input)
    }

    public fun set_lock_or_burn_output<ProofType: drop>(
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
            registration.execution_state == EXECUTION_STATE_LOCK_OR_BURN,
            error::invalid_state(E_NOT_IN_LOCK_OR_BURN_STATE)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_input),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_INPUT)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_output),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_OUTPUT)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_input),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_INPUT)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_output),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT)
        );

        option::fill(
            &mut registration.executing_lock_or_burn_output,
            LockOrBurnOutput { dest_token_address, dest_pool_data }
        )
    }

    public fun get_release_or_mint_input<ProofType: drop>(
        token_pool_address: address, _proof: ProofType
    ): ReleaseOrMintInput acquires TokenPoolRegistration {
        let registration = get_registration_mut(token_pool_address);

        assert!(
            type_info::type_of<ProofType>() == registration.proof_typeinfo,
            error::permission_denied(E_UNKNOWN_PROOF_TYPE)
        );

        assert!(
            registration.execution_state == EXECUTION_STATE_RELEASE_OR_MINT,
            error::invalid_state(E_NOT_IN_RELEASE_OR_MINT_STATE)
        );
        assert!(
            option::is_some(&registration.executing_release_or_mint_input),
            error::invalid_state(E_MISSING_RELEASE_OR_MINT_INPUT)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_output),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_input),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_INPUT)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_output),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_OUTPUT)
        );

        option::extract(&mut registration.executing_release_or_mint_input)
    }

    public fun set_release_or_mint_output<ProofType: drop>(
        token_pool_address: address, _proof: ProofType, destination_amount: u64
    ) acquires TokenPoolRegistration {
        let registration = get_registration_mut(token_pool_address);

        assert!(
            type_info::type_of<ProofType>() == registration.proof_typeinfo,
            error::permission_denied(E_UNKNOWN_PROOF_TYPE)
        );

        assert!(
            registration.execution_state == EXECUTION_STATE_RELEASE_OR_MINT,
            error::invalid_state(E_NOT_IN_RELEASE_OR_MINT_STATE)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_input),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_INPUT)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_output),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_input),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_INPUT)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_output),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_OUTPUT)
        );

        option::fill(
            &mut registration.executing_release_or_mint_output,
            ReleaseOrMintOutput { destination_amount }
        )
    }

    // LockOrBurnInput accessors
    public fun get_lock_or_burn_sender(input: &LockOrBurnInput): address {
        input.sender
    }

    public fun get_lock_or_burn_remote_chain_selector(
        input: &LockOrBurnInput
    ): u64 {
        input.remote_chain_selector
    }

    public fun get_lock_or_burn_receiver(input: &LockOrBurnInput): vector<u8> {
        input.receiver
    }

    // ReleaseOrMintInput accessors
    public fun get_release_or_mint_sender(input: &ReleaseOrMintInput): vector<u8> {
        input.sender
    }

    public fun get_release_or_mint_remote_chain_selector(
        input: &ReleaseOrMintInput
    ): u64 {
        input.remote_chain_selector
    }

    public fun get_release_or_mint_receiver(input: &ReleaseOrMintInput): address {
        input.receiver
    }

    public fun get_release_or_mint_source_pool_address(
        input: &ReleaseOrMintInput
    ): vector<u8> {
        input.source_pool_address
    }

    public fun get_release_or_mint_source_pool_data(
        input: &ReleaseOrMintInput
    ): vector<u8> {
        input.source_pool_data
    }

    public fun get_release_or_mint_offchain_token_data(
        input: &ReleaseOrMintInput
    ): vector<u8> {
        input.offchain_token_data
    }

    public(friend) fun start_lock_or_burn(
        token_pool_address: address,
        sender: address,
        remote_chain_selector: u64,
        receiver: vector<u8>
    ): Object<FungibleStore> acquires TokenPoolRegistration {
        let registration = get_registration_mut(token_pool_address);

        assert!(
            registration.execution_state == EXECUTION_STATE_IDLE,
            error::invalid_state(E_NOT_IN_IDLE_STATE)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_input),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_INPUT)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_output),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_OUTPUT)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_input),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_INPUT)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_output),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT)
        );

        registration.execution_state = EXECUTION_STATE_LOCK_OR_BURN;
        option::fill(
            &mut registration.executing_lock_or_burn_input,
            LockOrBurnInput { sender, remote_chain_selector, receiver }
        );

        registration.dispatch_deposit_fungible_store
    }

    public(friend) fun finish_lock_or_burn(
        token_pool_address: address
    ): (vector<u8>, vector<u8>) acquires TokenPoolRegistration {
        let registration = get_registration_mut(token_pool_address);

        assert!(
            registration.execution_state == EXECUTION_STATE_LOCK_OR_BURN,
            error::invalid_state(E_NOT_IN_LOCK_OR_BURN_STATE)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_input),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_INPUT)
        );
        assert!(
            option::is_some(&registration.executing_lock_or_burn_output),
            error::invalid_state(E_MISSING_LOCK_OR_BURN_OUTPUT)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_input),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_INPUT)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_output),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT)
        );

        registration.execution_state = EXECUTION_STATE_IDLE;

        // the dispatch callback is passed a fungible_asset::TransferRef reference which could allow the store to be frozen,
        // causing future deposit/withdraw callbacks to fail.
        if (fungible_asset::is_frozen(registration.dispatch_deposit_fungible_store)) {
            fungible_asset::set_frozen_flag(
                &registration.dispatch_fa_transfer_ref,
                registration.dispatch_deposit_fungible_store,
                false
            );
        };

        let output = option::extract(&mut registration.executing_lock_or_burn_output);
        (output.dest_token_address, output.dest_pool_data)
    }

    public(friend) fun start_release_or_mint(
        token_pool_address: address,
        sender: vector<u8>,
        remote_chain_selector: u64,
        receiver: address,
        source_pool_address: vector<u8>,
        source_pool_data: vector<u8>,
        offchain_token_data: vector<u8>
    ): (signer, Object<FungibleStore>) acquires TokenPoolRegistration {
        let registration = get_registration_mut(token_pool_address);

        assert!(
            registration.execution_state == EXECUTION_STATE_IDLE,
            error::invalid_state(E_NOT_IN_IDLE_STATE)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_input),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_INPUT)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_output),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_input),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_INPUT)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_output),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_OUTPUT)
        );

        registration.execution_state = EXECUTION_STATE_RELEASE_OR_MINT;
        option::fill(
            &mut registration.executing_release_or_mint_input,
            ReleaseOrMintInput {
                sender,
                remote_chain_selector,
                receiver,
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
            registration.execution_state == EXECUTION_STATE_RELEASE_OR_MINT,
            error::invalid_state(E_NOT_IN_RELEASE_OR_MINT_STATE)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_input),
            error::invalid_state(E_NON_EMPTY_RELEASE_OR_MINT_INPUT)
        );
        assert!(
            option::is_some(&registration.executing_release_or_mint_output),
            error::invalid_state(E_MISSING_RELEASE_OR_MINT_OUTPUT)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_input),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_INPUT)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_output),
            error::invalid_state(E_NON_EMPTY_LOCK_OR_BURN_OUTPUT)
        );

        registration.execution_state = EXECUTION_STATE_IDLE;

        // the dispatch callback is passed a fungible_asset::TransferRef reference which could allow the store to be frozen,
        // causing future deposit/withdraw callbacks to fail.
        if (fungible_asset::is_frozen(registration.dispatch_deposit_fungible_store)) {
            fungible_asset::set_frozen_flag(
                &registration.dispatch_fa_transfer_ref,
                registration.dispatch_deposit_fungible_store,
                false
            );
        };

        let output = option::extract(
            &mut registration.executing_release_or_mint_output
        );

        output.destination_amount
    }

    fun assert_can_register(
        registry_owner_address: address,
        token_pool_address: address,
        fungible_asset_metadata: Object<Metadata>
    ) {
        assert!(
            object::is_object(token_pool_address),
            error::invalid_argument(E_TOKEN_POOL_NOT_OBJECT)
        );
        let token_pool_object = object::address_to_object<ObjectCore>(token_pool_address);

        let fungible_asset_object_owner_address = object::owner(fungible_asset_metadata);
        let fungible_asset_object_root_owner_address =
            object::root_owner(fungible_asset_metadata);

        let token_pool_object_owner_address = object::owner(token_pool_object);
        if (token_pool_object_owner_address == registry_owner_address) { return };
        if (token_pool_object_owner_address == fungible_asset_object_owner_address
            || token_pool_object_owner_address
                == fungible_asset_object_root_owner_address) { return };

        let token_pool_object_root_owner_address = object::root_owner(token_pool_object);
        if (token_pool_object_root_owner_address == registry_owner_address) { return };
        if (token_pool_object_root_owner_address == fungible_asset_object_owner_address
            || token_pool_object_root_owner_address
                == fungible_asset_object_root_owner_address) { return };

        abort error::permission_denied(E_NOT_FUNGIBLE_ASSET_OWNER)
    }

    inline fun borrow_state(): &TokenAdminRegistryState {
        borrow_global<TokenAdminRegistryState>(@ccip)
    }

    inline fun borrow_state_mut(): &mut TokenAdminRegistryState {
        borrow_global_mut<TokenAdminRegistryState>(@ccip)
    }

    inline fun get_registration_mut(token_pool_address: address): &mut TokenPoolRegistration {
        assert!(
            exists<TokenPoolRegistration>(token_pool_address),
            error::invalid_argument(E_INVALID_TOKEN_POOL)
        );
        borrow_global_mut<TokenPoolRegistration>(token_pool_address)
    }
}
