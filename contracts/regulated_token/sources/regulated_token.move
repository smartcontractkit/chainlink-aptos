module regulated_token::regulated_token {
    use std::event;
    use std::fungible_asset::{
        Self,
        BurnRef,
        FungibleAsset,
        Metadata,
        MintRef,
        TransferRef
    };
    use std::object::{Self, ExtendRef, Object, TransferRef as ObjectTransferRef};
    use std::option::{Self, Option};
    use std::primary_fungible_store;
    use std::signer;
    use std::string::{Self, String};
    use std::dispatchable_fungible_asset;
    use std::function_info;
    use std::big_ordered_map::{Self, BigOrderedMap};

    use regulated_token::access_control::{Self};
    use regulated_token::ownable::{Self, OwnableState};

    const PAUSER_ROLE: u8 = 0;
    const UNPAUSER_ROLE: u8 = 1;
    const FREEZER_ROLE: u8 = 2;
    const UNFREEZER_ROLE: u8 = 3;
    const MINTER_ROLE: u8 = 4;
    const BURNER_ROLE: u8 = 5;
    const BRIDGE_MINTER_OR_BURNER_ROLE: u8 = 6;
    const RECOVERY_ROLE: u8 = 7;

    enum Role has copy, drop, store {
        PAUSER_ROLE(u8),
        UNPAUSER_ROLE(u8),
        FREEZER_ROLE(u8),
        UNFREEZER_ROLE(u8),
        MINTER_ROLE(u8),
        BURNER_ROLE(u8),
        BRIDGE_MINTER_OR_BURNER_ROLE(u8),
        RECOVERY_ROLE(u8)
    }

    const REGULATED_TOKEN_NAME: vector<u8> = b"Regulated Token";
    const REGULATED_TOKEN_SYMBOL: vector<u8> = b"RT";
    const REGULATED_TOKEN_DECIMALS: u8 = 6;
    const REGULATED_TOKEN_PROJECT_URI: vector<u8> = b"https://regulatedtoken.com";
    const REGULATED_TOKEN_ICON_URI: vector<u8> = b"https://regulatedtoken.com/images/pic.png";

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct TokenState has key {
        extend_ref: ExtendRef,
        transfer_ref: ObjectTransferRef,
        paused: bool,
        frozen_accounts: BigOrderedMap<address, bool>,
        ownable_state: OwnableState
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct TokenMetadataRefs has key {
        extend_ref: ExtendRef,
        mint_ref: MintRef,
        burn_ref: BurnRef,
        transfer_ref: TransferRef
    }

    #[event]
    struct InitializeToken has drop, store {
        publisher: address,
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
    struct TokenPoolMint has drop, store {
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
    struct TokenPoolBurn has drop, store {
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
        freezer: address,
        account: address
    }

    #[event]
    struct TokensRecovered has drop, store {
        caller: address,
        token_metadata: Object<Metadata>,
        to: address,
        balance: u64
    }

    #[event]
    struct TransferAdmin has drop, store {
        admin: address,
        pending_admin: address
    }

    #[event]
    struct AcceptAdmin has drop, store {
        old_admin: address,
        new_admin: address
    }

    const E_TOKEN_NOT_INITIALIZED: u64 = 1;
    const E_ONLY_BURNER_OR_BRIDGE: u64 = 2;
    const E_ONLY_MINTER_OR_BRIDGE: u64 = 3;
    const E_INVALID_AMOUNT: u64 = 4;
    const E_INVALID_ASSET: u64 = 5;
    const E_ZERO_ADDRESS_NOT_ALLOWED: u64 = 6;
    const E_CANNOT_TRANSFER_TO_REGULATED_TOKEN: u64 = 7;
    const E_PAUSED: u64 = 8;
    const E_ACCOUNT_FROZEN: u64 = 9;
    const E_INVALID_ROLE_NUMBER: u64 = 10;
    const E_INVALID_STORE: u64 = 11;

    #[view]
    public fun token_address(): address {
        token_address_internal()
    }

    inline fun token_address_internal(): address {
        object::create_object_address(&@regulated_token, REGULATED_TOKEN_SYMBOL)
    }

    #[view]
    public fun token_metadata(): Object<Metadata> {
        assert!(
            exists<TokenState>(token_address_internal()),
            E_TOKEN_NOT_INITIALIZED
        );
        token_metadata_internal()
    }

    inline fun token_metadata_internal(): Object<Metadata> {
        object::address_to_object(token_address_internal())
    }

    #[view]
    public fun is_paused(): bool acquires TokenState {
        is_paused_internal()
    }

    inline fun is_paused_internal(): bool {
        TokenState[token_address_internal()].paused
    }

    #[view]
    public fun get_role_members(role_number: u8): vector<address> {
        let role = get_role(role_number);
        access_control::get_role_members(token_metadata_internal(), role)
    }

    #[view]
    public fun get_role_member_count(role_number: u8): u64 {
        let role = get_role(role_number);
        access_control::get_role_member_count(token_metadata_internal(), role)
    }

    #[view]
    public fun get_role_member(role_number: u8, index: u64): address {
        let role = get_role(role_number);
        access_control::get_role_member(token_metadata_internal(), role, index)
    }

    #[view]
    public fun get_admin(): address {
        access_control::admin<Metadata, Role>(token_metadata_internal())
    }

    #[view]
    public fun get_minters(): vector<address> {
        access_control::get_role_members(token_metadata_internal(), minter_role())
    }

    #[view]
    public fun get_bridge_minters_or_burners(): vector<address> {
        access_control::get_role_members(
            token_metadata_internal(), bridge_minter_or_burner_role()
        )
    }

    #[view]
    public fun get_burners(): vector<address> {
        access_control::get_role_members(token_metadata_internal(), burner_role())
    }

    #[view]
    public fun get_freezers(): vector<address> {
        access_control::get_role_members(token_metadata_internal(), freezer_role())
    }

    #[view]
    public fun get_unfreezers(): vector<address> {
        access_control::get_role_members(token_metadata_internal(), unfreezer_role())
    }

    #[view]
    public fun get_pausers(): vector<address> {
        access_control::get_role_members(token_metadata_internal(), pauser_role())
    }

    #[view]
    public fun get_unpausers(): vector<address> {
        access_control::get_role_members(token_metadata_internal(), unpauser_role())
    }

    #[view]
    public fun get_recovery_managers(): vector<address> {
        access_control::get_role_members(token_metadata_internal(), recovery_role())
    }

    #[view]
    public fun get_pending_admin(): address {
        access_control::pending_admin<Metadata, Role>(token_metadata_internal())
    }

    #[view]
    public fun is_frozen(account: address): bool acquires TokenState {
        TokenState[token_address_internal()].frozen_accounts.contains(&account)
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
        let frozen_accounts = &TokenState[token_address_internal()].frozen_accounts;
        let result = vector[];

        let current_key_opt = frozen_accounts.next_key(&start_key);
        if (max_count == 0 || current_key_opt.is_none()) {
            return (result, start_key, current_key_opt.is_some())
        };

        let current_key = *current_key_opt.borrow();

        result.push_back(current_key);

        if (max_count == 1) {
            let has_more = frozen_accounts.next_key(&current_key).is_some();
            return (result, current_key, has_more);
        };

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
        access_control::has_role(token_metadata_internal(), account, get_role(role))
    }

    public fun deposit<T: key>(
        store: Object<T>, fa: FungibleAsset, transfer_ref: &TransferRef
    ) acquires TokenState {
        let token_metadata = token_metadata_internal();
        assert_not_paused();
        assert_not_frozen(store, token_metadata);
        assert_correct_asset(transfer_ref, token_metadata);

        fungible_asset::deposit_with_ref(transfer_ref, store, fa);
    }

    public fun withdraw<T: key>(
        store: Object<T>, amount: u64, transfer_ref: &TransferRef
    ): FungibleAsset acquires TokenState {
        let token_metadata = token_metadata_internal();
        assert_not_paused();
        assert_not_frozen(store, token_metadata);
        assert_correct_asset(transfer_ref, token_metadata);

        fungible_asset::withdraw_with_ref(transfer_ref, store, amount)
    }

    fun init_module(publisher: &signer) {
        let constructor_ref =
            &object::create_named_object(publisher, REGULATED_TOKEN_SYMBOL);
        let token_state_signer = &object::generate_signer(constructor_ref);

        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            constructor_ref,
            option::none(),
            string::utf8(REGULATED_TOKEN_NAME),
            string::utf8(REGULATED_TOKEN_SYMBOL),
            REGULATED_TOKEN_DECIMALS,
            string::utf8(REGULATED_TOKEN_ICON_URI),
            string::utf8(REGULATED_TOKEN_PROJECT_URI)
        );

        fungible_asset::set_untransferable(constructor_ref);

        move_to(
            token_state_signer,
            TokenMetadataRefs {
                extend_ref: object::generate_extend_ref(constructor_ref),
                mint_ref: fungible_asset::generate_mint_ref(constructor_ref),
                burn_ref: fungible_asset::generate_burn_ref(constructor_ref),
                transfer_ref: fungible_asset::generate_transfer_ref(constructor_ref)
            }
        );

        let deposit =
            function_info::new_function_info(
                publisher,
                string::utf8(b"regulated_token"),
                string::utf8(b"deposit")
            );
        let withdraw =
            function_info::new_function_info(
                publisher,
                string::utf8(b"regulated_token"),
                string::utf8(b"withdraw")
            );
        dispatchable_fungible_asset::register_dispatch_functions(
            constructor_ref,
            option::some(withdraw),
            option::some(deposit),
            option::none()
        );

        event::emit(
            InitializeToken {
                publisher: signer::address_of(publisher),
                max_supply: option::none(),
                decimals: REGULATED_TOKEN_DECIMALS,
                icon: string::utf8(REGULATED_TOKEN_ICON_URI),
                project: string::utf8(REGULATED_TOKEN_PROJECT_URI)
            }
        );

        move_to(
            token_state_signer,
            TokenState {
                extend_ref: object::generate_extend_ref(constructor_ref),
                transfer_ref: object::generate_transfer_ref(constructor_ref),
                paused: false,
                frozen_accounts: big_ordered_map::new_with_config(0, 0, false),
                ownable_state: ownable::new(publisher, @regulated_token)
            }
        );

        // Initialize the access control module with `@admin` as the admin
        access_control::init<Role>(constructor_ref, @admin);
    }

    public entry fun mint(
        caller: &signer, to: address, amount: u64
    ) acquires TokenMetadataRefs, TokenState {
        assert_not_paused();
        assert!(amount != 0, E_INVALID_AMOUNT);

        let token_metadata = token_metadata_internal();
        let to_store =
            primary_fungible_store::ensure_primary_store_exists(to, token_metadata);

        assert_not_frozen(to_store, token_metadata);

        let minter = signer::address_of(caller);
        let is_bridge_minter =
            access_control::has_role(
                token_metadata, minter, bridge_minter_or_burner_role()
            );
        let is_native_minter =
            access_control::has_role(token_metadata, minter, minter_role());

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
        assert_not_paused();
        assert!(amount != 0, E_INVALID_AMOUNT);

        let token_metadata = token_metadata_internal();
        let from_store = primary_fungible_store::primary_store(from, token_metadata);
        assert_not_frozen(from_store, token_metadata);

        let burner = signer::address_of(caller);
        let (is_bridge_burner, _) = assert_burner_and_get_type(burner, token_metadata);

        primary_fungible_store::burn(
            &borrow_token_metadata_refs().burn_ref, from, amount
        );

        if (is_bridge_burner) {
            event::emit(BridgeBurn { burner, from, amount });
        } else {
            event::emit(NativeBurn { burner, from, amount });
        }
    }

    public entry fun batch_burn_frozen_funds(
        caller: &signer, accounts: vector<address>
    ) acquires TokenMetadataRefs, TokenState {
        for (i in 0..accounts.length()) {
            burn_frozen_funds(caller, accounts[i]);
        }
    }

    public entry fun burn_frozen_funds(
        caller: &signer, from: address
    ) acquires TokenMetadataRefs, TokenState {
        assert_not_paused();

        let burner = signer::address_of(caller);
        let token_metadata = token_metadata_internal();

        let (is_bridge_burner, _) = assert_burner_and_get_type(burner, token_metadata);

        if (primary_fungible_store::is_frozen(from, token_metadata)) {
            let balance = primary_fungible_store::balance(from, token_metadata);
            if (balance > 0) {
                primary_fungible_store::burn(
                    &borrow_token_metadata_refs().burn_ref, from, balance
                );

                if (is_bridge_burner) {
                    event::emit(BridgeBurn { burner, from, amount: balance });
                } else {
                    event::emit(NativeBurn { burner, from, amount: balance });
                }
            }
        };
    }

    /// Periphery function to apply roles to accounts
    /// This is because we cannot pass enums to entry functions
    public entry fun grant_role(
        caller: &signer, role_number: u8, account: address
    ) {
        let role = get_role(role_number);

        access_control::grant_role(
            caller,
            token_metadata_internal(),
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

    public entry fun freeze_accounts(
        caller: &signer, accounts: vector<address>
    ) acquires TokenMetadataRefs, TokenState {
        for (i in 0..accounts.length()) {
            freeze_account(caller, accounts[i]);
        }
    }

    public entry fun freeze_account(
        caller: &signer, account: address
    ) acquires TokenMetadataRefs, TokenState {
        let caller_addr = signer::address_of(caller);
        assert_freezer(caller, token_metadata_internal());

        primary_fungible_store::set_frozen_flag(
            &borrow_token_metadata_refs().transfer_ref, account, true
        );

        TokenState[token_address_internal()].frozen_accounts.upsert(account, true);

        event::emit(AccountFrozen { freezer: caller_addr, account });
    }

    public entry fun unfreeze_accounts(
        caller: &signer, accounts: vector<address>
    ) acquires TokenMetadataRefs, TokenState {
        for (i in 0..accounts.length()) {
            unfreeze_account(caller, accounts[i]);
        }
    }

    public entry fun unfreeze_account(
        caller: &signer, account: address
    ) acquires TokenMetadataRefs, TokenState {
        assert_unfreezer(caller, token_metadata_internal());

        primary_fungible_store::set_frozen_flag(
            &borrow_token_metadata_refs().transfer_ref, account, false
        );

        TokenState[token_address_internal()].frozen_accounts.remove(&account);

        event::emit(AccountUnfrozen { freezer: signer::address_of(caller), account });
    }

    /// Batch revoke and grant pauser roles
    /// `revoke_role` and `grant_role` assert that the caller is the admin
    public entry fun apply_pauser_updates(
        caller: &signer,
        pausers_to_remove: vector<address>,
        pausers_to_add: vector<address>
    ) {
        for (i in 0..pausers_to_remove.length()) {
            access_control::revoke_role(
                caller,
                token_metadata_internal(),
                pauser_role(),
                pausers_to_remove[i]
            );
        };
        for (i in 0..pausers_to_add.length()) {
            access_control::grant_role(
                caller,
                token_metadata_internal(),
                pauser_role(),
                pausers_to_add[i]
            );
        };
    }

    /// Batch revoke and grant freezer roles
    /// `revoke_role` and `grant_role` assert that the caller is the admin
    public entry fun apply_freezer_updates(
        caller: &signer,
        freezers_to_remove: vector<address>,
        freezers_to_add: vector<address>
    ) {
        for (i in 0..freezers_to_remove.length()) {
            access_control::revoke_role(
                caller,
                token_metadata_internal(),
                freezer_role(),
                freezers_to_remove[i]
            );
        };
        for (i in 0..freezers_to_add.length()) {
            access_control::grant_role(
                caller,
                token_metadata_internal(),
                freezer_role(),
                freezers_to_add[i]
            );
        };
    }

    /// Batch revoke and grant unfreezer roles
    /// `revoke_role` and `grant_role` assert that the caller is the admin
    public entry fun apply_unfreezer_updates(
        caller: &signer,
        unfreezers_to_remove: vector<address>,
        unfreezers_to_add: vector<address>
    ) {
        for (i in 0..unfreezers_to_remove.length()) {
            access_control::revoke_role(
                caller,
                token_metadata_internal(),
                unfreezer_role(),
                unfreezers_to_remove[i]
            );
        };
        for (i in 0..unfreezers_to_add.length()) {
            access_control::grant_role(
                caller,
                token_metadata_internal(),
                unfreezer_role(),
                unfreezers_to_add[i]
            );
        };
    }

    public entry fun pause(caller: &signer) acquires TokenState {
        let token_metadata = token_metadata_internal();
        assert_pauser(caller, token_metadata);

        let state = &mut TokenState[token_address_internal()];
        if (!state.paused) {
            state.paused = true;
            event::emit(Paused { pauser: signer::address_of(caller) });
        }
    }

    public entry fun unpause(caller: &signer) acquires TokenState {
        let token_metadata = token_metadata_internal();
        assert_unpauser(caller, token_metadata);

        let state = &mut TokenState[token_address_internal()];
        if (state.paused) {
            state.paused = false;
            event::emit(Unpaused { unpauser: signer::address_of(caller) });
        }
    }

    /// In case regulated tokens get stuck in the contract or token state, this function can be used to recover them
    /// This function can only be called by the recovery role
    public entry fun recover_tokens(caller: &signer, to: address) acquires TokenMetadataRefs {
        let token_state_address = token_address_internal();
        assert!(to != @0x0, E_ZERO_ADDRESS_NOT_ALLOWED);
        assert!(
            to != @regulated_token && to != token_state_address,
            E_CANNOT_TRANSFER_TO_REGULATED_TOKEN
        );

        let token_metadata = object::address_to_object(token_state_address);
        assert_recovery_role(caller, token_metadata);

        let transfer_ref = &borrow_token_metadata_refs().transfer_ref;

        // Recover regulated tokens sent to contract
        let balance = primary_fungible_store::balance(@regulated_token, token_metadata);
        primary_fungible_store::transfer_with_ref(
            transfer_ref, @regulated_token, to, balance
        );

        // Recover regulated tokens sent to token state address
        let balance = primary_fungible_store::balance(
            token_state_address, token_metadata
        );
        primary_fungible_store::transfer_with_ref(
            transfer_ref, token_state_address, to, balance
        );

        event::emit(
            TokensRecovered {
                caller: signer::address_of(caller),
                token_metadata,
                to,
                balance
            }
        );
    }

    fun assert_not_paused() acquires TokenState {
        assert!(!is_paused_internal(), E_PAUSED);
    }

    inline fun assert_pauser(
        caller: &signer, token_metadata: Object<Metadata>
    ) {
        access_control::assert_role(
            token_metadata,
            signer::address_of(caller),
            pauser_role()
        );
    }

    inline fun assert_unpauser(
        caller: &signer, token_metadata: Object<Metadata>
    ) {
        access_control::assert_role(
            token_metadata,
            signer::address_of(caller),
            unpauser_role()
        );
    }

    inline fun assert_freezer(
        caller: &signer, token_metadata: Object<Metadata>
    ) {
        access_control::assert_role(
            token_metadata,
            signer::address_of(caller),
            freezer_role()
        );
    }

    inline fun assert_unfreezer(
        caller: &signer, token_metadata: Object<Metadata>
    ) {
        access_control::assert_role(
            token_metadata,
            signer::address_of(caller),
            unfreezer_role()
        );
    }

    inline fun assert_recovery_role(
        caller: &signer, token_metadata: Object<Metadata>
    ) {
        access_control::assert_role(
            token_metadata, signer::address_of(caller), recovery_role()
        );
    }

    inline fun assert_burner_and_get_type(
        burner: address, token_metadata: Object<Metadata>
    ): (bool, bool) {
        let is_bridge_burner =
            access_control::has_role(
                token_metadata, burner, bridge_minter_or_burner_role()
            );
        let is_native_burner =
            access_control::has_role(token_metadata, burner, burner_role());

        assert!(is_bridge_burner || is_native_burner, E_ONLY_BURNER_OR_BRIDGE);

        (is_bridge_burner, is_native_burner)
    }

    fun assert_not_frozen<T: key>(
        store: Object<T>, token_metadata: Object<Metadata>
    ) {
        if (fungible_asset::store_exists(object::object_address(&store))) {
            assert!(
                !fungible_asset::is_frozen(store),
                E_ACCOUNT_FROZEN
            );
            assert!(
                fungible_asset::store_metadata(store) == token_metadata,
                E_INVALID_STORE
            );
        }
    }

    fun assert_correct_asset(
        transfer_ref: &TransferRef, token_metadata: Object<Metadata>
    ) {
        assert!(
            fungible_asset::transfer_ref_metadata(transfer_ref) == token_metadata,
            E_INVALID_ASSET
        );
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
        &TokenMetadataRefs[token_address_internal()]
    }

    public fun pauser_role(): Role {
        Role::PAUSER_ROLE(PAUSER_ROLE)
    }

    public fun unpauser_role(): Role {
        Role::UNPAUSER_ROLE(UNPAUSER_ROLE)
    }

    public fun freezer_role(): Role {
        Role::FREEZER_ROLE(FREEZER_ROLE)
    }

    public fun unfreezer_role(): Role {
        Role::UNFREEZER_ROLE(UNFREEZER_ROLE)
    }

    public fun minter_role(): Role {
        Role::MINTER_ROLE(MINTER_ROLE)
    }

    public fun burner_role(): Role {
        Role::BURNER_ROLE(BURNER_ROLE)
    }

    public fun bridge_minter_or_burner_role(): Role {
        Role::BRIDGE_MINTER_OR_BURNER_ROLE(BRIDGE_MINTER_OR_BURNER_ROLE)
    }

    public fun recovery_role(): Role {
        Role::RECOVERY_ROLE(RECOVERY_ROLE)
    }

    // ====================== Ownable Functions ======================

    #[view]
    public fun owner(): address acquires TokenState {
        ownable::owner(&TokenState[token_address_internal()].ownable_state)
    }

    #[view]
    public fun has_pending_transfer(): bool acquires TokenState {
        ownable::has_pending_transfer(&TokenState[token_address_internal()].ownable_state)
    }

    #[view]
    public fun pending_transfer_from(): Option<address> acquires TokenState {
        ownable::pending_transfer_from(
            &TokenState[token_address_internal()].ownable_state
        )
    }

    #[view]
    public fun pending_transfer_to(): Option<address> acquires TokenState {
        ownable::pending_transfer_to(&TokenState[token_address_internal()].ownable_state)
    }

    #[view]
    public fun pending_transfer_accepted(): Option<bool> acquires TokenState {
        ownable::pending_transfer_accepted(
            &TokenState[token_address_internal()].ownable_state
        )
    }

    public entry fun transfer_ownership(caller: &signer, to: address) acquires TokenState {
        let state = &mut TokenState[token_address_internal()];
        ownable::transfer_ownership(caller, &mut state.ownable_state, to)
    }

    public entry fun accept_ownership(caller: &signer) acquires TokenState {
        let state = &mut TokenState[token_address_internal()];
        ownable::accept_ownership(caller, &mut state.ownable_state)
    }

    public entry fun execute_ownership_transfer(
        caller: &signer, to: address
    ) acquires TokenState {
        let state = &mut TokenState[token_address_internal()];
        ownable::execute_ownership_transfer(caller, &mut state.ownable_state, to)
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }
}
