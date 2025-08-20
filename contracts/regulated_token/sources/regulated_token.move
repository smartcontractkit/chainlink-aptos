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

    const PAUSER_ROLE: u8 = 0;
    const UNPAUSER_ROLE: u8 = 1;
    const FREEZER_ROLE: u8 = 2;
    const UNFREEZER_ROLE: u8 = 3;
    const MINTER_ROLE: u8 = 4;
    const BURNER_ROLE: u8 = 5;
    const BRIDGE_MINTER_OR_BURNER_ROLE: u8 = 6;
    const TOKEN_POOL_ROLE: u8 = 7;

    enum Role has copy, drop, store {
        PAUSER_ROLE(u8),
        UNPAUSER_ROLE(u8),
        FREEZER_ROLE(u8),
        UNFREEZER_ROLE(u8),
        MINTER_ROLE(u8),
        BURNER_ROLE(u8),
        BRIDGE_MINTER_OR_BURNER_ROLE(u8),
        TOKEN_POOL_ROLE(u8)
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
        frozen_accounts: BigOrderedMap<address, bool>
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
    struct MinterAdded has drop, store {
        admin: address,
        minter: address,
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
    struct TransferAdmin has drop, store {
        admin: address,
        pending_admin: address
    }

    #[event]
    struct AcceptAdmin has drop, store {
        old_admin: address,
        new_admin: address
    }

    const E_NOT_PUBLISHER: u64 = 1;
    const E_NOT_ALLOWED_BURNER: u64 = 2;
    const E_TOKEN_NOT_INITIALIZED: u64 = 3;
    const E_TOKEN_ALREADY_INITIALIZED: u64 = 4;
    const E_NOT_ALLOWED_MINTER: u64 = 5;
    const E_NOT_ALLOWED_TOKEN_POOL_MINTER: u64 = 6;
    const E_INVALID_AMOUNT: u64 = 7;
    const E_NOT_ALLOWED_BRIDGE_BURNER: u64 = 8;
    const E_NOT_AUTHORIZED_UNPAUSER: u64 = 9;
    const E_INVALID_ASSET: u64 = 10;
    const E_ACCOUNT_NOT_FROZEN: u64 = 11;
    const E_INVALID_OPERATION_TYPE: u64 = 12;
    const E_ZERO_ADDRESS_NOT_ALLOWED: u64 = 13;
    const E_NOT_ADMIN: u64 = 14;
    const E_PAUSED: u64 = 15;
    const E_ACCOUNT_FROZEN: u64 = 16;
    const E_INVALID_ROLE_NUMBER: u64 = 17;
    const E_INVALID_STORE: u64 = 18;

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
                frozen_accounts: big_ordered_map::new_with_config(0, 0, false)
            }
        );

        // Initialize the access control module with `@admin` as the admin
        access_control::init<Role>(constructor_ref, @admin);
    }

    public entry fun mint(
        minter: &signer, to: address, amount: u64
    ) acquires TokenMetadataRefs, TokenState {
        assert_not_paused();

        let token_metadata = token_metadata_internal();
        let to_store =
            primary_fungible_store::ensure_primary_store_exists(to, token_metadata);

        assert_not_frozen(to_store, token_metadata);
        assert!(amount != 0, E_INVALID_AMOUNT);

        let minter_addr = signer::address_of(minter);
        let is_bridge_minter =
            access_control::has_role(
                token_metadata, minter_addr, bridge_minter_or_burner_role()
            );
        let is_token_pool_minter =
            access_control::has_role(token_metadata, minter_addr, token_pool_role());
        let is_native_minter =
            access_control::has_role(token_metadata, minter_addr, minter_role());

        assert!(
            is_bridge_minter || is_native_minter || is_token_pool_minter,
            E_NOT_ALLOWED_MINTER
        );

        primary_fungible_store::mint(&borrow_token_metadata_refs().mint_ref, to, amount);

        if (is_token_pool_minter) {
            event::emit(TokenPoolMint { minter: minter_addr, to, amount });
        } else if (is_bridge_minter) {
            event::emit(BridgeMint { minter: minter_addr, to, amount });
        } else {
            event::emit(NativeMint { minter: minter_addr, to, amount });
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

        let caller_addr = signer::address_of(caller);
        let (is_bridge_burner, is_token_pool_burner, _is_native_burner) =
            assert_burner_and_get_type(caller_addr, token_metadata);

        primary_fungible_store::burn(
            &borrow_token_metadata_refs().burn_ref, from, amount
        );

        emit_burn_event(
            is_bridge_burner,
            is_token_pool_burner,
            caller_addr,
            from,
            amount
        );
    }

    public entry fun batch_burn_frozen_funds(
        caller: &signer, accounts: vector<address>
    ) acquires TokenMetadataRefs, TokenState {
        for (i in 0..accounts.length()) {
            burn_frozen_funds(caller, accounts[i]);
        }
    }

    public entry fun burn_frozen_funds(
        caller: &signer, account: address
    ) acquires TokenMetadataRefs, TokenState {
        assert_not_paused();

        let caller_addr = signer::address_of(caller);
        let token_metadata = token_metadata_internal();

        let (is_bridge_burner, is_token_pool_burner, _is_native_burner) =
            assert_burner_and_get_type(caller_addr, token_metadata);

        if (primary_fungible_store::is_frozen(account, token_metadata)) {
            let balance = primary_fungible_store::balance(account, token_metadata);
            if (balance > 0) {
                primary_fungible_store::burn(
                    &borrow_token_metadata_refs().burn_ref, account, balance
                );

                emit_burn_event(
                    is_bridge_burner,
                    is_token_pool_burner,
                    caller_addr,
                    account,
                    balance
                );
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

        if (role == minter_role()
            || role == bridge_minter_or_burner_role()
            || role == token_pool_role()) {
            event::emit(
                MinterAdded {
                    admin: signer::address_of(caller),
                    minter: account,
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
        let caller_addr = signer::address_of(caller);
        assert_unfreezer(caller, token_metadata_internal());

        primary_fungible_store::set_frozen_flag(
            &borrow_token_metadata_refs().transfer_ref, account, false
        );

        TokenState[token_address_internal()].frozen_accounts.remove(&account);

        event::emit(AccountUnfrozen { freezer: caller_addr, account });
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

    /// Returns (is_bridge_burner, is_token_pool_burner, is_native_burner)
    /// and asserts the caller has at least one burner role
    inline fun assert_burner_and_get_type(
        caller_addr: address, token_metadata: Object<Metadata>
    ): (bool, bool, bool) {
        let is_bridge_burner =
            access_control::has_role(
                token_metadata, caller_addr, bridge_minter_or_burner_role()
            );
        let is_native_burner =
            access_control::has_role(token_metadata, caller_addr, burner_role());
        let is_token_pool_burner =
            access_control::has_role(token_metadata, caller_addr, token_pool_role());

        assert!(
            is_bridge_burner || is_native_burner || is_token_pool_burner,
            E_NOT_ALLOWED_BURNER
        );

        (is_bridge_burner, is_token_pool_burner, is_native_burner)
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
        } else if (role_number == TOKEN_POOL_ROLE) {
            token_pool_role()
        } else {
            abort E_INVALID_ROLE_NUMBER
        }
    }

    inline fun borrow_token_metadata_refs(): &TokenMetadataRefs {
        &TokenMetadataRefs[token_address_internal()]
    }

    inline fun emit_burn_event(
        is_bridge_burner: bool,
        is_token_pool_burner: bool,
        burner: address,
        from: address,
        amount: u64
    ) {
        if (is_bridge_burner) {
            event::emit(BridgeBurn { burner, from, amount });
        } else if (is_token_pool_burner) {
            event::emit(TokenPoolBurn { burner, from, amount });
        } else {
            event::emit(NativeBurn { burner, from, amount });
        }
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

    public fun token_pool_role(): Role {
        Role::TOKEN_POOL_ROLE(TOKEN_POOL_ROLE)
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }
}
