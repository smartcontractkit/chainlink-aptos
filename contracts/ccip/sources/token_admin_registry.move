module ccip::token_admin_registry {
    use std::bcs;
    use std::dispatchable_fungible_asset;
    use std::error;
    use std::function_info::{Self, FunctionInfo};
    use std::fungible_asset::{Self, Metadata, FungibleStore};
    use std::object::{Self, Object, ObjectCore, ExtendRef, TransferRef};
    use std::option::{Self, Option};
    use std::signer;
    use std::string;
    use std::type_info::{Self, TypeInfo};

    use ccip::ownable;

    friend ccip::token_admin_dispatcher;

    const EXECUTION_STATE_IDLE: u8 = 1;
    const EXECUTION_STATE_LOCK_OR_BURN: u8 = 2;
    const EXECUTION_STATE_RELEASE_OR_MINT: u8 = 3;

    struct TokenAdminRegistryState has key, store {
        ownable_state: ownable::OwnableState,
        extend_ref: ExtendRef,
        transfer_ref: TransferRef
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
    const E_EXECUTING_ASSERTION_FAILED: u64 = 10;
    const E_UNKNOWN_PROOF_TYPE: u64 = 11;

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
            transfer_ref
        };

        move_to(caller, state);
    }

    public fun register_admin<ProofType: drop>(
        token_pool_signer: &signer,
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

        let token_pool_address = signer::address_of(token_pool_signer);
        assert!(
            !exists<TokenPoolRegistration>(token_pool_address),
            error::invalid_argument(E_ALREADY_REGISTERED)
        );

        assert_is_fungible_asset_owner(fungible_asset_metadata, token_pool_address);

        let lock_or_burn_function =
            function_info::new_function_info(
                token_pool_signer,
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
                token_pool_signer,
                string::utf8(token_pool_module_name),
                string::utf8(b"release_or_mint")
            );

        let state = borrow_state_mut();
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
            token_pool_signer,
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

    fun assert_is_fungible_asset_owner(
        fungible_asset_metadata: Object<Metadata>, token_pool_address: address
    ) {
        if (object::is_owner(fungible_asset_metadata, token_pool_address)) { return };

        /*
          We only allow a single token pool at an address. Users can use the CLI `deploy-object` action to put the token pool module
          at a new object address, or programatically a separate module might want to manage multiple token pools, eg:

          let token_pool_constructor_ref = object::create_named_object(fungible_asset_owner, b"TokenPool1");
          let token_pool_signer = object::generate_signer(token_pool_constructor_ref);
          register_admin(token_pool_signer, ..);

          So check if the token pool address is already an object, and if so, allow for a common owner (or common root owner).

          TODO: double-check and validate this logic.
        */
        if (object::is_object(token_pool_address)) {
            let token_pool_object =
                object::address_to_object<ObjectCore>(token_pool_address);
            let token_pool_owner = object::owner(token_pool_object);
            let token_pool_root_owner = object::root_owner(token_pool_object);

            if (token_pool_owner == object::owner(fungible_asset_metadata)
                || token_pool_owner == object::root_owner(fungible_asset_metadata)) {
                return
            };

            if (token_pool_root_owner == object::owner(fungible_asset_metadata)
                || token_pool_root_owner == object::root_owner(fungible_asset_metadata)) {
                return
            };
        };

        abort error::permission_denied(E_NOT_FUNGIBLE_ASSET_OWNER)
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
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_some(&registration.executing_lock_or_burn_input),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_output),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_input),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_output),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
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
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_input),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_output),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_input),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_output),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
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
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_some(&registration.executing_release_or_mint_input),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_output),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_input),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_output),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
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
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_input),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_output),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_input),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_output),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
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
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_input),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_output),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_input),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_output),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
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
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_input),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_some(&registration.executing_lock_or_burn_output),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_input),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_output),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
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
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_input),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_output),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_input),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_output),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
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
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_release_or_mint_input),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_some(&registration.executing_release_or_mint_output),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_input),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
        );
        assert!(
            option::is_none(&registration.executing_lock_or_burn_output),
            error::invalid_state(E_EXECUTING_ASSERTION_FAILED)
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
