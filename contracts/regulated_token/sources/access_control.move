module regulated_token::access_control {
    use std::event;
    use std::ordered_map::{Self, OrderedMap};
    use std::object::{Self, Object};
    use std::signer;
    use std::object::ConstructorRef;

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct AccessControlState<Role: copy + drop + store> has key, store {
        /// Mapping from role to list of addresses that have the role
        roles: OrderedMap<Role, vector<address>>,
        /// The admin address who can manage all roles
        admin: address,
        /// Pending admin for two-step admin transfer
        pending_admin: address
    }

    #[event]
    struct RoleGranted<Role: copy + drop + store> has drop, store {
        role: Role,
        account: address,
        sender: address
    }

    #[event]
    struct RoleRevoked<Role: copy + drop + store> has drop, store {
        role: Role,
        account: address,
        sender: address
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

    /// Role state not initialized
    const E_ROLE_STATE_NOT_INITIALIZED: u64 = 1;
    /// Caller does not have the required role
    const E_MISSING_ROLE: u64 = 2;
    /// Caller is not the admin
    const E_NOT_ADMIN: u64 = 3;
    /// Cannot transfer admin to same address
    const E_SAME_ADMIN: u64 = 4;
    /// Index out of bounds
    const E_INDEX_OUT_OF_BOUNDS: u64 = 5;

    public fun init<Role: copy + drop + store>(
        constructor_ref: &ConstructorRef, admin: address
    ) {
        let obj_signer = object::generate_signer(constructor_ref);
        move_to(
            &obj_signer,
            AccessControlState<Role> {
                admin,
                pending_admin: @0x0,
                roles: ordered_map::new()
            }
        );
    }

    #[view]
    public fun has_role<T: key, Role: copy + drop + store>(
        state_obj: Object<T>, account: address, role: Role
    ): bool acquires AccessControlState {
        let roles = &borrow<T, Role>(state_obj).roles;
        roles.contains(&role) && roles.borrow(&role).contains(&account)
    }

    #[view]
    public fun get_role_members<T: key, Role: copy + drop + store>(
        state_obj: Object<T>, role: Role
    ): vector<address> acquires AccessControlState {
        let state = borrow(state_obj);
        if (state.roles.contains(&role)) {
            *state.roles.borrow(&role)
        } else {
            vector[]
        }
    }

    #[view]
    public fun get_role_member_count<T: key, Role: copy + drop + store>(
        state_obj: Object<T>, role: Role
    ): u64 acquires AccessControlState {
        let roles = &borrow<T, Role>(state_obj).roles;
        if (roles.contains(&role)) {
            roles.borrow(&role).length()
        } else { 0 }
    }

    #[view]
    public fun get_role_member<T: key, Role: copy + drop + store>(
        state_obj: Object<T>, role: Role, index: u64
    ): address acquires AccessControlState {
        let roles = &borrow<T, Role>(state_obj).roles;
        assert!(roles.contains(&role), E_MISSING_ROLE);

        let addresses = roles.borrow(&role);
        assert!(index < addresses.length(), E_INDEX_OUT_OF_BOUNDS);
        addresses[index]
    }

    #[view]
    public fun admin<T: key, Role: copy + drop + store>(
        state_obj: Object<T>
    ): address acquires AccessControlState {
        borrow<T, Role>(state_obj).admin
    }

    #[view]
    public fun pending_admin<T: key, Role: copy + drop + store>(
        state_obj: Object<T>
    ): address acquires AccessControlState {
        borrow<T, Role>(state_obj).pending_admin
    }

    public entry fun batch_grant_role<T: key, Role: copy + drop + store>(
        caller: &signer,
        state_obj: Object<T>,
        role: Role,
        accounts: vector<address>
    ) acquires AccessControlState {
        if (accounts.length() == 0) return;

        let state = authorized_borrow_mut<T, Role>(caller, state_obj);
        let sender = signer::address_of(caller);

        for (i in 0..accounts.length()) {
            grant_role_internal(state, role, accounts[i], sender);
        };
    }

    public entry fun grant_role<T: key, Role: copy + drop + store>(
        caller: &signer, state_obj: Object<T>, role: Role, account: address
    ) acquires AccessControlState {
        let state = authorized_borrow_mut<T, Role>(caller, state_obj);
        let sender = signer::address_of(caller);

        grant_role_internal(state, role, account, sender);
    }

    fun grant_role_internal<Role: copy + drop + store>(
        state: &mut AccessControlState<Role>,
        role: Role,
        account: address,
        sender: address
    ) {
        if (state.roles.contains(&role)) {
            let addresses = state.roles.borrow_mut(&role);
            if (!addresses.contains(&account)) {
                addresses.push_back(account);
                event::emit(RoleGranted { role, account, sender });
            }
        } else {
            state.roles.add(role, vector[account]);
            event::emit(RoleGranted { role, account, sender });
        }
    }

    public entry fun batch_revoke_role<T: key, Role: copy + drop + store>(
        caller: &signer,
        state_obj: Object<T>,
        role: Role,
        accounts: vector<address>
    ) acquires AccessControlState {
        if (accounts.length() == 0) return;

        let state = authorized_borrow_mut<T, Role>(caller, state_obj);
        let sender = signer::address_of(caller);

        for (i in 0..accounts.length()) {
            revoke_role_internal(state, role, accounts[i], sender);
        };
    }

    public entry fun revoke_role<T: key, Role: copy + drop + store>(
        caller: &signer, state_obj: Object<T>, role: Role, account: address
    ) acquires AccessControlState {
        let state = authorized_borrow_mut<T, Role>(caller, state_obj);
        let sender = signer::address_of(caller);

        revoke_role_internal(state, role, account, sender);
    }

    fun revoke_role_internal<Role: copy + drop + store>(
        state: &mut AccessControlState<Role>,
        role: Role,
        account: address,
        sender: address
    ) {
        if (state.roles.contains(&role)) {
            let addresses = state.roles.borrow_mut(&role);
            let (found, index) = addresses.index_of(&account);
            if (found) {
                addresses.remove(index);
                event::emit(RoleRevoked { role, account, sender });
            }
        }
    }

    public entry fun renounce_role<T: key, Role: copy + drop + store>(
        caller: &signer, state_obj: Object<T>, role: Role
    ) acquires AccessControlState {
        let state = borrow_mut<T, Role>(state_obj);
        let caller_addr = signer::address_of(caller);

        if (state.roles.contains(&role)) {
            let addresses = state.roles.borrow_mut(&role);
            let (found, index) = addresses.index_of(&caller_addr);
            if (found) {
                addresses.remove(index);
                event::emit(RoleRevoked { role, account: caller_addr, sender: caller_addr });
            };
        };
    }

    public fun assert_role<T: key, Role: copy + drop + store>(
        state_obj: Object<T>, caller: address, role: Role
    ) acquires AccessControlState {
        assert!(
            has_role(state_obj, caller, role),
            E_MISSING_ROLE
        );
    }

    public entry fun transfer_admin<T: key, Role: copy + drop + store>(
        admin: &signer, state_obj: Object<T>, new_admin: address
    ) acquires AccessControlState {
        let state = authorized_borrow_mut<T, Role>(admin, state_obj);
        assert!(signer::address_of(admin) != new_admin, E_SAME_ADMIN);

        state.pending_admin = new_admin;

        event::emit(TransferAdmin { admin: state.admin, pending_admin: new_admin });
    }

    public entry fun accept_admin<T: key, Role: copy + drop + store>(
        pending_admin: &signer, state_obj: Object<T>
    ) acquires AccessControlState {
        let state = borrow_mut<T, Role>(state_obj);
        let pending_admin_addr = signer::address_of(pending_admin);

        assert!(pending_admin_addr == state.pending_admin, E_NOT_ADMIN);

        let old_admin = state.admin;
        state.admin = state.pending_admin;
        state.pending_admin = @0x0;

        event::emit(AcceptAdmin { old_admin, new_admin: state.admin });
    }

    inline fun authorized_borrow_mut<T: key, Role: copy + drop + store>(
        caller: &signer, state_obj: Object<T>
    ): &mut AccessControlState<Role> {
        let state = borrow_mut<T, Role>(state_obj);
        assert!(state.admin == signer::address_of(caller), E_NOT_ADMIN);
        state
    }

    inline fun borrow_mut<T: key, Role: copy + drop + store>(
        state_obj: Object<T>
    ): &mut AccessControlState<Role> {
        let obj_addr = assert_exists<T, Role>(state_obj);
        &mut AccessControlState<Role>[obj_addr]
    }

    inline fun borrow<T: key, Role: copy + drop + store>(state_obj: Object<T>)
        : &AccessControlState<Role> {
        let obj_addr = assert_exists<T, Role>(state_obj);
        &AccessControlState<Role>[obj_addr]
    }

    inline fun assert_exists<T: key, Role: copy + drop + store>(
        state_obj: Object<T>
    ): address {
        let obj_addr = object::object_address(&state_obj);
        assert!(
            exists<AccessControlState<Role>>(obj_addr),
            E_ROLE_STATE_NOT_INITIALIZED
        );
        obj_addr
    }
}
