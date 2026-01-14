module regulated_token::regulated_token {
    use std::event;
    use std::fungible_asset::{
        Self,
        BurnRef,
        FungibleAsset,
        Metadata,
        MintRef,
        TransferRef,
        RawBalanceRef,
        RawSupplyRef,
        MutateMetadataRef
    };
    use std::object::{
        Self,
        ExtendRef,
        Object,
        TransferRef as ObjectTransferRef
    };
    use std::option::{Self, Option};
    use std::primary_fungible_store;
    use std::account;
    use std::signer;
    use std::string::{Self, String};
    use std::dispatchable_fungible_asset;
    use std::function_info;
    use std::big_ordered_map::{Self, BigOrderedMap};

    use regulated_token::access_control::{Self};
    use regulated_token::ownable::{Self, OwnableState};

    const TOKEN_STATE_SEED: vector<u8> = b"regulated_token::regulated_token::token_state";

    const PAUSER_ROLE: u8 = 0;
    const UNPAUSER_ROLE: u8 = 1;
    const FREEZER_ROLE: u8 = 2;
    const UNFREEZER_ROLE: u8 = 3;
    const MINTER_ROLE: u8 = 4;
    const BURNER_ROLE: u8 = 5;
    const BRIDGE_MINTER_OR_BURNER_ROLE: u8 = 6;
    const RECOVERY_ROLE: u8 = 7;

    enum Role has copy, drop, store {
        PAUSER_ROLE,
        UNPAUSER_ROLE,
        FREEZER_ROLE,
        UNFREEZER_ROLE,
        MINTER_ROLE,
        BURNER_ROLE,
        BRIDGE_MINTER_OR_BURNER_ROLE,
        RECOVERY_ROLE
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct TokenStateDeployment has key {
        extend_ref: ExtendRef,
        transfer_ref: ObjectTransferRef,
        paused: bool,
        frozen_accounts: BigOrderedMap<address, bool>,
        ownable_state: OwnableState
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct TokenState has key {
        extend_ref: ExtendRef,
        transfer_ref: ObjectTransferRef,
        paused: bool,
        frozen_accounts: BigOrderedMap<address, bool>,
        ownable_state: OwnableState,
        token: Object<Metadata>
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct TokenMetadataRefs has key {
        extend_ref: ExtendRef,
        mint_ref: MintRef,
        burn_ref: BurnRef,
        transfer_ref: TransferRef,
        raw_balance_ref: RawBalanceRef,
        raw_supply_ref: RawSupplyRef,
        mutate_metadata_ref: MutateMetadataRef
    }

    #[event]
    struct InitializeToken has drop, store {
        publisher: address,
        token: Object<Metadata>,
        max_supply: Option<u128>,
        decimals: u8,
        icon: String,
        project: String
    }

    #[event]
    struct NativeMint has drop, store {
        minter: address,
        to: address,
        amount: u64
    }

    #[event]
    struct BridgeMint has drop, store {
        minter: address,
        to: address,
        amount: u64
    }

    #[event]
    struct NativeBurn has drop, store {
        burner: address,
        from: address,
        amount: u64
    }

    #[event]
    struct BridgeBurn has drop, store {
        burner: address,
        from: address,
        amount: u64
    }

    #[event]
    struct MinterAdded<R> has drop, store {
        admin: address,
        minter: address,
        role: R,
        operation_type: u8
    }

    #[event]
    struct Paused has drop, store {
        pauser: address
    }

    #[event]
    struct Unpaused has drop, store {
        unpauser: address
    }

    #[event]
    struct AccountFrozen has drop, store {
        freezer: address,
        account: address
    }

    #[event]
    struct AccountUnfrozen has drop, store {
        unfreezer: address,
        account: address
    }

    #[event]
    struct TokensRecovered has drop, store {
        caller: address,
        token_metadata: Object<Metadata>,
        from: address,
        to: address,
        amount: u64
    }

    /// The caller is not the signer of this contract
    const E_NOT_PUBLISHER: u64 = 1;
    /// TokenState has not been initialized yet
    const E_TOKEN_NOT_INITIALIZED: u64 = 2;
    /// Caller must have either BURNER_ROLE or BRIDGE_MINTER_OR_BURNER_ROLE
    const E_ONLY_BURNER_OR_BRIDGE: u64 = 3;
    /// Caller must have either MINTER_ROLE or BRIDGE_MINTER_OR_BURNER_ROLE
    const E_ONLY_MINTER_OR_BRIDGE: u64 = 4;
    /// Invalid fungible asset for transfer ref
    const E_INVALID_ASSET: u64 = 5;
    /// Zero address (0x0) is not allowed
    const E_ZERO_ADDRESS_NOT_ALLOWED: u64 = 6;
    /// Cannot transfer tokens to the regulated token contract address
    const E_CANNOT_TRANSFER_TO_REGULATED_TOKEN: u64 = 7;
    /// Contract is paused
    const E_PAUSED: u64 = 8;
    /// Account is frozen and cannot perform token operations
    const E_ACCOUNT_FROZEN: u64 = 9;
    /// Contract is already paused
    const E_ALREADY_PAUSED: u64 = 14;
    /// Contract is not paused
    const E_NOT_PAUSED: u64 = 15;
    /// Invalid role number provided
    const E_INVALID_ROLE_NUMBER: u64 = 10;
    /// Invalid fungible store provided for token metadata
    const E_INVALID_STORE: u64 = 11;
    /// Fungible store does not exist for this account
    const E_STORE_DOES_NOT_EXIST: u64 = 12;
    /// TokenState deployment has already been initialized
    const E_TOKEN_STATE_DEPLOYMENT_ALREADY_INITIALIZED: u64 = 13;
    /// Account msut be frozen for recovery
    const E_ACCOUNT_MUST_BE_FROZEN_FOR_RECOVERY: u64 = 14;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"RegulatedToken 1.0.0")
    }

    #[view]
    public fun token_state_address(): address {
        token_state_address_internal()
    }

    #[view]
    public fun token_state_object(): Object<TokenState> {
        token_state_object_internal()
    }

    #[view]
    public fun admin(): address {
        access_control::admin<TokenState, Role>(token_state_object_internal())
    }

    #[view]
    public fun pending_admin(): address {
        access_control::pending_admin<TokenState, Role>(token_state_object_internal())
    }

    inline fun token_state_object_internal(): Object<TokenState> {
        let token_state_address = token_state_address_internal();
        assert!(exists<TokenState>(token_state_address), E_TOKEN_NOT_INITIALIZED);
        object::address_to_object(token_state_address)
    }

    inline fun token_state_address_internal(): address {
        object::create_object_address(&@regulated_token, TOKEN_STATE_SEED)
    }

    #[view]
    public fun token_address(): address acquires TokenState {
        object::object_address(&token_metadata_internal())
    }

    #[view]
    public fun token_metadata(): Object<Metadata> acquires TokenState {
        token_metadata_internal()
    }

    inline fun token_metadata_from_state_obj(
        state_obj: Object<TokenState>
    ): Object<Metadata> {
        TokenState[object::object_address(&state_obj)].token
    }

    inline fun token_metadata_internal(): Object<Metadata> {
        let state_address = token_state_address_internal();
        assert!(exists<TokenState>(state_address), E_TOKEN_NOT_INITIALIZED);
        TokenState[state_address].token
    }

    #[view]
    public fun is_paused(): bool acquires TokenState {
        TokenState[token_state_address_internal()].paused
    }

    #[view]
    public fun get_role_members(role_number: u8): vector<address> {
        let role = get_role(role_number);
        access_control::get_role_members(token_state_object_internal(), role)
    }

    #[view]
    public fun get_role_member_count(role_number: u8): u64 {
        let role = get_role(role_number);
        access_control::get_role_member_count(token_state_object_internal(), role)
    }

    #[view]
    public fun get_role_member(role_number: u8, index: u64): address {
        let role = get_role(role_number);
        access_control::get_role_member(token_state_object_internal(), role, index)
    }

    #[view]
    public fun get_admin(): address {
        access_control::admin<TokenState, Role>(token_state_object_internal())
    }

    #[view]
    public fun get_minters(): vector<address> {
        access_control::get_role_members(token_state_object_internal(), minter_role())
    }

    #[view]
    public fun get_bridge_minters_or_burners(): vector<address> {
        access_control::get_role_members(
            token_state_object_internal(), bridge_minter_or_burner_role()
        )
    }

    #[view]
    public fun get_burners(): vector<address> {
        access_control::get_role_members(token_state_object_internal(), burner_role())
    }

    #[view]
    public fun get_freezers(): vector<address> {
        access_control::get_role_members(token_state_object_internal(), freezer_role())
    }

    #[view]
    public fun get_unfreezers(): vector<address> {
        access_control::get_role_members(
            token_state_object_internal(), unfreezer_role()
        )
    }

    #[view]
    public fun get_pausers(): vector<address> {
        access_control::get_role_members(token_state_object_internal(), pauser_role())
    }

    #[view]
    public fun get_unpausers(): vector<address> {
        access_control::get_role_members(
            token_state_object_internal(), unpauser_role()
        )
    }

    #[view]
    public fun get_recovery_managers(): vector<address> {
        access_control::get_role_members(
            token_state_object_internal(), recovery_role()
        )
    }

    #[view]
    public fun get_pending_admin(): address {
        access_control::pending_admin<TokenState, Role>(token_state_object_internal())
    }

    #[view]
    public fun is_frozen(account: address): bool acquires TokenState {
        TokenState[token_state_address_internal()].frozen_accounts.contains(&account)
    }

    #[view]
    /// Get frozen accounts paginated using a start key and limit.
    /// Caller should call this on a certain block to ensure you the same state for every call.
    ///
    /// This function retrieves a batch of frozen account addresses from the registry, starting from
    /// the account address that comes after the provided start_key.
    ///
    /// @param start_key - Address to start pagination from (returns accounts AFTER this address)
    /// @param max_count - Maximum number of accounts to return
    ///
    /// @return:
    ///   - vector<address>: List of frozen account addresses (up to max_count)
    ///   - address: Next key to use for pagination (pass this as start_key in next call)
    ///   - bool: Whether there are more accounts after this batch
    public fun get_all_frozen_accounts(
        start_key: address, max_count: u64
    ): (vector<address>, address, bool) acquires TokenState {
        let frozen_accounts = &TokenState[token_state_address_internal()].frozen_accounts;
        let result = vector[];

        let current_key_opt = frozen_accounts.next_key(&start_key);
        if (max_count == 0 || current_key_opt.is_none()) {
            return (result, start_key, current_key_opt.is_some())
        };

        let current_key = *current_key_opt.borrow();

        result.push_back(current_key);

        for (_i in 1..max_count) {
            let next_key_opt = frozen_accounts.next_key(&current_key);
            if (next_key_opt.is_none()) {
                return (result, current_key, false)
            };

            current_key = *next_key_opt.borrow();
            result.push_back(current_key);
        };

        // Check if there are more accounts after the last key
        let has_more = frozen_accounts.next_key(&current_key).is_some();
        (result, current_key, has_more)
    }

    #[view]
    public fun has_role(account: address, role: u8): bool {
        access_control::has_role(token_state_object_internal(), account, get_role(role))
    }

    public fun deposit<T: key>(
        store: Object<T>, fa: FungibleAsset, transfer_ref: &TransferRef
    ) acquires TokenState {
        let state_obj = token_state_object_internal();
        let token_metadata = token_metadata_from_state_obj(state_obj);
        let token_state = &TokenState[object::object_address(&state_obj)];

        assert_not_paused(token_state);
        assert_not_frozen(object::owner(store), token_state);
        assert_correct_asset(transfer_ref, token_metadata, store);

        fungible_asset::deposit_with_ref(transfer_ref, store, fa);
    }

    public fun withdraw<T: key>(
        store: Object<T>, amount: u64, transfer_ref: &TransferRef
    ): FungibleAsset acquires TokenState {
        let state_obj = token_state_object_internal();
        let token_metadata = token_metadata_from_state_obj(state_obj);
        let token_state = &TokenState[object::object_address(&state_obj)];

        assert_not_paused(token_state);
        assert_not_frozen(object::owner(store), token_state);
        assert_correct_asset(transfer_ref, token_metadata, store);

        fungible_asset::withdraw_with_ref(transfer_ref, store, amount)
    }

    /// `publisher` is the code object, deployed through object_code_deployment
    fun init_module(publisher: &signer) {
        assert!(object::is_object(@regulated_token), E_NOT_PUBLISHER);

        // Create object owned by code object
        let constructor_ref = &object::create_named_object(publisher, TOKEN_STATE_SEED);
        let token_state_signer = &object::generate_signer(constructor_ref);

        // Create an Account on the object for event handles.
        account::create_account_if_does_not_exist(signer::address_of(token_state_signer));

        move_to(
            token_state_signer,
            TokenStateDeployment {
                extend_ref: object::generate_extend_ref(constructor_ref),
                transfer_ref: object::generate_transfer_ref(constructor_ref),
                paused: false,
                frozen_accounts: big_ordered_map::new_with_config(0, 0, false),
                ownable_state: ownable::new(token_state_signer, @regulated_token)
            }
        );

        // Initialize the access control module with `@admin` as the admin
        access_control::init<Role>(constructor_ref, @admin);
    }

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
            paused,
            frozen_accounts,
            ownable_state
        } = move_from<TokenStateDeployment>(token_state_address);

        ownable::assert_only_owner(publisher_addr, &ownable_state);

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

        fungible_asset::set_untransferable(constructor_ref);

        move_to(
            &object::generate_signer(constructor_ref),
            TokenMetadataRefs {
                extend_ref: object::generate_extend_ref(constructor_ref),
                mint_ref: fungible_asset::generate_mint_ref(constructor_ref),
                burn_ref: fungible_asset::generate_burn_ref(constructor_ref),
                transfer_ref: fungible_asset::generate_transfer_ref(constructor_ref),
                raw_balance_ref: fungible_asset::generate_raw_balance_ref(constructor_ref),
                raw_supply_ref: fungible_asset::generate_raw_supply_ref(constructor_ref),
                mutate_metadata_ref: fungible_asset::generate_mutate_metadata_ref(
                    constructor_ref
                )
            }
        );

        // Set up dynamic dispatch functions
        let deposit =
            function_info::new_function_info_from_address(
                @regulated_token,
                string::utf8(b"regulated_token"),
                string::utf8(b"deposit")
            );
        let withdraw =
            function_info::new_function_info_from_address(
                @regulated_token,
                string::utf8(b"regulated_token"),
                string::utf8(b"withdraw")
            );
        dispatchable_fungible_asset::register_dispatch_functions(
            constructor_ref,
            option::some(withdraw),
            option::some(deposit),
            option::none()
        );

        let token = object::object_from_constructor_ref(constructor_ref);
        event::emit(
            InitializeToken {
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
                paused,
                frozen_accounts,
                ownable_state,
                token
            }
        );
    }

    public entry fun mint(
        caller: &signer, to: address, amount: u64
    ) acquires TokenMetadataRefs, TokenState {
        let state_obj = token_state_object_internal();
        let token_state = &TokenState[object::object_address(&state_obj)];

        assert_not_paused(token_state);
        assert_not_frozen(to, token_state);

        let minter = signer::address_of(caller);
        let is_bridge_minter =
            access_control::has_role(state_obj, minter, bridge_minter_or_burner_role());
        let is_native_minter = access_control::has_role(state_obj, minter, minter_role());

        assert!(is_bridge_minter || is_native_minter, E_ONLY_MINTER_OR_BRIDGE);

        primary_fungible_store::mint(&borrow_token_metadata_refs().mint_ref, to, amount);

        if (is_bridge_minter) {
            event::emit(BridgeMint { minter, to, amount });
        } else {
            event::emit(NativeMint { minter, to, amount });
        };
    }

    public entry fun burn(
        caller: &signer, from: address, amount: u64
    ) acquires TokenMetadataRefs, TokenState {
        let state_obj = token_state_object_internal();
        let token_state = &TokenState[object::object_address(&state_obj)];

        assert_not_paused(token_state);
        assert_not_frozen(from, token_state);

        let burner = signer::address_of(caller);
        let (is_bridge_burner, _) = assert_burner_and_get_type(burner, state_obj);

        primary_fungible_store::burn(
            &borrow_token_metadata_refs().burn_ref, from, amount
        );

        if (is_bridge_burner) {
            event::emit(BridgeBurn { burner, from, amount });
        } else {
            event::emit(NativeBurn { burner, from, amount });
        }
    }

    /// Bridge-specific function to mint tokens directly as `FungibleAsset`.
    /// Required because this token has dynamic dispatch enabled
    /// as minting to pool and calling `fungible_asset::withdraw()` reverts.
    /// Only callable by accounts with BRIDGE_MINTER_OR_BURNER_ROLE.
    public fun bridge_mint(
        caller: &signer, to: address, amount: u64
    ): FungibleAsset acquires TokenMetadataRefs, TokenState {
        let state_obj = token_state_object_internal();
        let token_state = &TokenState[object::object_address(&state_obj)];

        assert_not_paused(token_state);
        assert_bridge_minter_or_burner(caller, state_obj);
        assert_not_frozen(to, token_state);

        let fa = fungible_asset::mint(&borrow_token_metadata_refs().mint_ref, amount);

        event::emit(BridgeMint { minter: signer::address_of(caller), to, amount });

        fa
    }

    /// Bridge-specific function to burn `FungibleAsset` directly.
    /// Required because this token has dynamic dispatch enabled
    /// as depositing to pool and calling `fungible_asset::deposit()` reverts.
    /// Only callable by accounts with BRIDGE_MINTER_OR_BURNER_ROLE.
    public fun bridge_burn(
        caller: &signer, from: address, fa: FungibleAsset
    ) acquires TokenMetadataRefs, TokenState {
        let state_obj = token_state_object_internal();
        let token_state = &TokenState[object::object_address(&state_obj)];

        assert_not_paused(token_state);
        assert_bridge_minter_or_burner(caller, state_obj);
        assert_not_frozen(from, token_state);

        let amount = fungible_asset::amount(&fa);
        fungible_asset::burn(&borrow_token_metadata_refs().burn_ref, fa);

        event::emit(BridgeBurn { burner: signer::address_of(caller), from, amount });
    }

    fun freeze_account_internal(
        caller_addr: address,
        account: address,
        transfer_ref: &TransferRef,
        token_state: &mut TokenState
    ) {
        // Ensure the account is frozen at the primary store level
        primary_fungible_store::set_frozen_flag(transfer_ref, account, true);

        if (!token_state.frozen_accounts.contains(&account)) {
            token_state.frozen_accounts.add(account, true);
        };

        event::emit(AccountFrozen { freezer: caller_addr, account });
    }

    fun unfreeze_account_internal(
        caller_addr: address,
        account: address,
        transfer_ref: &TransferRef,
        token_state: &mut TokenState
    ) {
        // Ensure the account is unfrozen at the primary store level
        primary_fungible_store::set_frozen_flag(transfer_ref, account, false);

        if (token_state.frozen_accounts.contains(&account)) {
            token_state.frozen_accounts.remove(&account);
        };

        event::emit(AccountUnfrozen { unfreezer: caller_addr, account });
    }

    fun burn_frozen_funds_internal(
        burner: address,
        account: address,
        burn_ref: &BurnRef,
        token_metadata: Object<Metadata>,
        is_frozen: bool,
        is_bridge_burner: bool
    ) {
        if (is_frozen) {
            let balance = primary_fungible_store::balance(account, token_metadata);
            if (balance > 0) {
                primary_fungible_store::burn(burn_ref, account, balance);
                if (is_bridge_burner) {
                    event::emit(BridgeBurn { burner, from: account, amount: balance });
                } else {
                    event::emit(NativeBurn { burner, from: account, amount: balance });
                };
            };
        };
    }

    fun recover_frozen_funds_internal(
        caller: address,
        from: address,
        to: address,
        transfer_ref: &TransferRef,
        token_state: &TokenState
    ) {
        assert!(
            token_state.frozen_accounts.contains(&from),
            E_ACCOUNT_MUST_BE_FROZEN_FOR_RECOVERY
        );

        let balance = primary_fungible_store::balance(from, token_state.token);
        if (balance > 0) {
            primary_fungible_store::transfer_with_ref(transfer_ref, from, to, balance);
            event::emit(
                TokensRecovered {
                    caller,
                    token_metadata: token_state.token,
                    from,
                    to,
                    amount: balance
                }
            );
        };
    }

    /// Periphery function to apply roles to accounts
    public entry fun grant_role(
        caller: &signer, role_number: u8, account: address
    ) {
        let role = get_role(role_number);

        access_control::grant_role(
            caller,
            token_state_object_internal(),
            role,
            account
        );

        if (role == minter_role() || role == bridge_minter_or_burner_role()) {
            event::emit(
                MinterAdded {
                    admin: signer::address_of(caller),
                    minter: account,
                    role,
                    operation_type: role_number
                }
            );
        }
    }

    public entry fun revoke_role(
        caller: &signer, role_number: u8, account: address
    ) {
        let role = get_role(role_number);
        access_control::revoke_role(
            caller,
            token_state_object_internal(),
            role,
            account
        );
    }

    public entry fun freeze_accounts(
        caller: &signer, accounts: vector<address>
    ) acquires TokenMetadataRefs, TokenState {
        let state_obj = token_state_object_internal();
        assert_freezer(caller, state_obj);

        let caller_addr = signer::address_of(caller);
        let transfer_ref = &borrow_token_metadata_refs().transfer_ref;
        for (i in 0..accounts.length()) {
            freeze_account_internal(
                caller_addr,
                accounts[i],
                transfer_ref,
                &mut TokenState[object::object_address(&state_obj)]
            );
        };
    }

    public entry fun freeze_account(
        caller: &signer, account: address
    ) acquires TokenMetadataRefs, TokenState {
        let state_obj = token_state_object_internal();
        assert_freezer(caller, state_obj);

        let transfer_ref = &borrow_token_metadata_refs().transfer_ref;
        freeze_account_internal(
            signer::address_of(caller),
            account,
            transfer_ref,
            &mut TokenState[object::object_address(&state_obj)]
        );
    }

    public entry fun unfreeze_accounts(
        caller: &signer, accounts: vector<address>
    ) acquires TokenMetadataRefs, TokenState {
        let state_obj = token_state_object_internal();
        assert_unfreezer(caller, state_obj);

        let caller_addr = signer::address_of(caller);
        let transfer_ref = &borrow_token_metadata_refs().transfer_ref;
        for (i in 0..accounts.length()) {
            unfreeze_account_internal(
                caller_addr,
                accounts[i],
                transfer_ref,
                &mut TokenState[object::object_address(&state_obj)]
            );
        };
    }

    public entry fun unfreeze_account(
        caller: &signer, account: address
    ) acquires TokenMetadataRefs, TokenState {
        let state_obj = token_state_object_internal();
        assert_unfreezer(caller, state_obj);

        let transfer_ref = &borrow_token_metadata_refs().transfer_ref;
        unfreeze_account_internal(
            signer::address_of(caller),
            account,
            transfer_ref,
            &mut TokenState[object::object_address(&state_obj)]
        );
    }

    /// Batch revoke and grant roles by role number
    /// `batch_revoke_role` and `batch_grant_role` assert that the caller is the admin
    public entry fun apply_role_updates(
        caller: &signer,
        role_number: u8,
        addresses_to_remove: vector<address>,
        addresses_to_add: vector<address>
    ) {
        let role = get_role(role_number);
        let state_obj = token_state_object_internal();

        if (addresses_to_remove.length() > 0) {
            access_control::batch_revoke_role(
                caller,
                state_obj,
                role,
                addresses_to_remove
            );
        };

        if (addresses_to_add.length() > 0) {
            access_control::batch_grant_role(caller, state_obj, role, addresses_to_add);
        };
    }

    public entry fun pause(caller: &signer) acquires TokenState {
        let state_obj = token_state_object_internal();
        assert_pauser(caller, state_obj);

        let state = &mut TokenState[object::object_address(&state_obj)];
        assert!(!state.paused, E_ALREADY_PAUSED);

        state.paused = true;
        event::emit(Paused { pauser: signer::address_of(caller) });
    }

    public entry fun unpause(caller: &signer) acquires TokenState {
        let state_obj = token_state_object_internal();
        assert_unpauser(caller, state_obj);

        let state = &mut TokenState[object::object_address(&state_obj)];
        assert!(state.paused, E_NOT_PAUSED);

        state.paused = false;
        event::emit(Unpaused { unpauser: signer::address_of(caller) });
    }

    /// Validates and sets up burn frozen funds operation.
    inline fun validate_burn_frozen_funds(
        caller: &signer
    ): (
        address, &BurnRef, Object<Metadata>, &TokenState, bool
    ) {
        let state_obj = token_state_object_internal();
        let token_state = &TokenState[object::object_address(&state_obj)];
        assert_not_paused(token_state);

        let burner = signer::address_of(caller);
        let (is_bridge_burner, _) = assert_burner_and_get_type(burner, state_obj);
        let token_metadata = token_metadata_from_state_obj(state_obj);
        let burn_ref = &borrow_token_metadata_refs().burn_ref;

        (
            burner, burn_ref, token_metadata, token_state, is_bridge_burner
        )
    }

    public entry fun batch_burn_frozen_funds(
        caller: &signer, accounts: vector<address>
    ) acquires TokenMetadataRefs, TokenState {
        let (
            burner, burn_ref, token_metadata, token_state, is_bridge_burner
        ) = validate_burn_frozen_funds(caller);

        for (i in 0..accounts.length()) {
            burn_frozen_funds_internal(
                burner,
                accounts[i],
                burn_ref,
                token_metadata,
                token_state.frozen_accounts.contains(&accounts[i]),
                is_bridge_burner
            );
        };
    }

    public entry fun burn_frozen_funds(
        caller: &signer, from: address
    ) acquires TokenMetadataRefs, TokenState {
        let (
            burner, burn_ref, token_metadata, token_state, is_bridge_burner
        ) = validate_burn_frozen_funds(caller);

        burn_frozen_funds_internal(
            burner,
            from,
            burn_ref,
            token_metadata,
            token_state.frozen_accounts.contains(&from),
            is_bridge_burner
        );
    }

    /// Recovers funds from frozen accounts by transferring them to a specified account.
    /// Only callable by accounts with RECOVERY_ROLE.
    public entry fun recover_frozen_funds(
        caller: &signer, from: address, to: address
    ) acquires TokenMetadataRefs, TokenState {
        let (transfer_ref, token_state) = validate_recovery_procedure(caller, to);
        recover_frozen_funds_internal(
            signer::address_of(caller),
            from,
            to,
            transfer_ref,
            token_state
        );
    }

    /// Batch version of recover_frozen_funds for processing multiple frozen accounts.
    /// Only callable by accounts with RECOVERY_ROLE.
    public entry fun batch_recover_frozen_funds(
        caller: &signer, accounts: vector<address>, to: address
    ) acquires TokenMetadataRefs, TokenState {
        let caller_addr = signer::address_of(caller);
        let (transfer_ref, token_state) = validate_recovery_procedure(caller, to);

        for (i in 0..accounts.length()) {
            recover_frozen_funds_internal(
                caller_addr,
                accounts[i],
                to,
                transfer_ref,
                token_state
            );
        };
    }

    inline fun assert_valid_recovery_recipient(
        to: address, token_state: &TokenState
    ) {
        assert!(to != @0x0, E_ZERO_ADDRESS_NOT_ALLOWED);
        assert!(
            to != @regulated_token && to != token_state_address_internal(),
            E_CANNOT_TRANSFER_TO_REGULATED_TOKEN
        );
        assert_not_frozen(to, token_state);
    }

    inline fun validate_recovery_procedure(caller: &signer, to: address)
        : (&TransferRef, &TokenState) {
        let state_obj = token_state_object_internal();
        let token_state = &TokenState[object::object_address(&state_obj)];

        assert_not_paused(token_state);
        assert_recovery_role(caller, state_obj);
        assert_valid_recovery_recipient(to, token_state);

        (&borrow_token_metadata_refs().transfer_ref, token_state)
    }

    public entry fun transfer_admin(caller: &signer, new_admin: address) {
        access_control::transfer_admin<TokenState, Role>(
            caller, token_state_object_internal(), new_admin
        );
    }

    public entry fun accept_admin(caller: &signer) {
        access_control::accept_admin<TokenState, Role>(
            caller, token_state_object_internal()
        );
    }

    /// Helper function to recover tokens from a specific address
    fun recover_tokens_from_address(
        caller_addr: address,
        from: address,
        to: address,
        transfer_ref: &TransferRef
    ) {
        let token_metadata = fungible_asset::transfer_ref_metadata(transfer_ref);
        let balance = primary_fungible_store::balance(from, token_metadata);
        if (balance > 0) {
            primary_fungible_store::transfer_with_ref(transfer_ref, from, to, balance);
            event::emit(
                TokensRecovered {
                    caller: caller_addr,
                    token_metadata,
                    from,
                    to,
                    amount: balance
                }
            );
        }
    }

    /// In case regulated tokens get stuck in the contract or token state, this function can be used to recover them
    /// This function can only be called by the recovery role
    public entry fun recover_tokens(
        caller: &signer, to: address
    ) acquires TokenMetadataRefs, TokenState {
        let (transfer_ref, _token_state) = validate_recovery_procedure(caller, to);
        let caller_addr = signer::address_of(caller);

        // Recover regulated tokens sent to contract
        recover_tokens_from_address(
            caller_addr,
            @regulated_token,
            to,
            transfer_ref
        );

        // Recover regulated tokens sent to token state address
        recover_tokens_from_address(
            caller_addr,
            token_state_address_internal(),
            to,
            transfer_ref
        );
    }

    fun assert_not_paused(token_state: &TokenState) {
        assert!(!token_state.paused, E_PAUSED);
    }

    inline fun assert_pauser(
        caller: &signer, state_obj: Object<TokenState>
    ) {
        access_control::assert_role(
            state_obj, signer::address_of(caller), pauser_role()
        );
    }

    inline fun assert_unpauser(
        caller: &signer, state_obj: Object<TokenState>
    ) {
        access_control::assert_role(
            state_obj, signer::address_of(caller), unpauser_role()
        );
    }

    inline fun assert_freezer(
        caller: &signer, state_obj: Object<TokenState>
    ) {
        access_control::assert_role(
            state_obj, signer::address_of(caller), freezer_role()
        );
    }

    inline fun assert_unfreezer(
        caller: &signer, state_obj: Object<TokenState>
    ) {
        access_control::assert_role(
            state_obj, signer::address_of(caller), unfreezer_role()
        );
    }

    inline fun assert_recovery_role(
        caller: &signer, state_obj: Object<TokenState>
    ) {
        access_control::assert_role(
            state_obj, signer::address_of(caller), recovery_role()
        );
    }

    fun assert_bridge_minter_or_burner(
        caller: &signer, state_obj: Object<TokenState>
    ) {
        access_control::assert_role(
            state_obj,
            signer::address_of(caller),
            bridge_minter_or_burner_role()
        );
    }

    inline fun assert_burner_and_get_type(
        burner: address, state_obj: Object<TokenState>
    ): (bool, bool) {
        let is_bridge_burner =
            access_control::has_role(state_obj, burner, bridge_minter_or_burner_role());
        let is_native_burner = access_control::has_role(state_obj, burner, burner_role());

        assert!(is_bridge_burner || is_native_burner, E_ONLY_BURNER_OR_BRIDGE);

        (is_bridge_burner, is_native_burner)
    }

    fun assert_not_frozen(account: address, token_state: &TokenState) {
        assert!(!token_state.frozen_accounts.contains(&account), E_ACCOUNT_FROZEN);
    }

    fun assert_correct_asset<T: key>(
        transfer_ref: &TransferRef, token_metadata: Object<Metadata>, store: Object<T>
    ) {
        assert!(
            fungible_asset::transfer_ref_metadata(transfer_ref) == token_metadata,
            E_INVALID_ASSET
        );
        assert!(fungible_asset::store_metadata(store) == token_metadata, E_INVALID_STORE);
    }

    fun get_role(role_number: u8): Role {
        if (role_number == PAUSER_ROLE) {
            pauser_role()
        } else if (role_number == UNPAUSER_ROLE) {
            unpauser_role()
        } else if (role_number == FREEZER_ROLE) {
            freezer_role()
        } else if (role_number == UNFREEZER_ROLE) {
            unfreezer_role()
        } else if (role_number == MINTER_ROLE) {
            minter_role()
        } else if (role_number == BURNER_ROLE) {
            burner_role()
        } else if (role_number == BRIDGE_MINTER_OR_BURNER_ROLE) {
            bridge_minter_or_burner_role()
        } else if (role_number == RECOVERY_ROLE) {
            recovery_role()
        } else {
            abort E_INVALID_ROLE_NUMBER
        }
    }

    inline fun borrow_token_metadata_refs(): &TokenMetadataRefs {
        let token_metadata = token_metadata_internal();
        &TokenMetadataRefs[object::object_address(&token_metadata)]
    }

    public fun pauser_role(): Role {
        Role::PAUSER_ROLE
    }

    public fun unpauser_role(): Role {
        Role::UNPAUSER_ROLE
    }

    public fun freezer_role(): Role {
        Role::FREEZER_ROLE
    }

    public fun unfreezer_role(): Role {
        Role::UNFREEZER_ROLE
    }

    public fun minter_role(): Role {
        Role::MINTER_ROLE
    }

    public fun burner_role(): Role {
        Role::BURNER_ROLE
    }

    public fun bridge_minter_or_burner_role(): Role {
        Role::BRIDGE_MINTER_OR_BURNER_ROLE
    }

    public fun recovery_role(): Role {
        Role::RECOVERY_ROLE
    }

    // ====================== Ownable Functions ======================
    #[view]
    public fun owner(): address acquires TokenState {
        ownable::owner(&TokenState[token_state_address_internal()].ownable_state)
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

    public entry fun transfer_ownership(caller: &signer, to: address) acquires TokenState {
        let state = &mut TokenState[token_state_address_internal()];
        ownable::transfer_ownership(caller, &mut state.ownable_state, to)
    }

    public entry fun accept_ownership(caller: &signer) acquires TokenState {
        let state = &mut TokenState[token_state_address_internal()];
        ownable::accept_ownership(caller, &mut state.ownable_state)
    }

    public entry fun execute_ownership_transfer(
        caller: &signer, to: address
    ) acquires TokenState {
        let state = &mut TokenState[token_state_address_internal()];
        ownable::execute_ownership_transfer(caller, &mut state.ownable_state, to)
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }
}
