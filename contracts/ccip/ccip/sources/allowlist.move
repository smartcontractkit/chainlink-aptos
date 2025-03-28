module ccip::allowlist {
    use std::account;
    use std::event::{Self, EventHandle};
    use std::error;

    struct AllowlistState has store {
        allowlist_enabled: bool,
        allowlist: vector<address>,
        allowlist_add_events: EventHandle<AllowlistAdd>,
        allowlist_remove_events: EventHandle<AllowlistRemove>
    }

    #[event]
    struct AllowlistRemove has store, drop {
        sender: address
    }

    #[event]
    struct AllowlistAdd has store, drop {
        sender: address
    }

    const E_ALLOWLIST_NOT_ENABLED: u64 = 1;

    public fun new(event_account: &signer, allowlist: vector<address>): AllowlistState {
        AllowlistState {
            allowlist_enabled: !allowlist.is_empty(),
            allowlist,
            allowlist_add_events: account::new_event_handle(event_account),
            allowlist_remove_events: account::new_event_handle(event_account)
        }
    }

    public fun get_allowlist_enabled(state: &AllowlistState): bool {
        state.allowlist_enabled
    }

    public fun set_allowlist_enabled(
        state: &mut AllowlistState, enabled: bool
    ) {
        state.allowlist_enabled = enabled;
    }

    public fun get_allowlist(state: &AllowlistState): vector<address> {
        state.allowlist
    }

    public fun is_allowed(state: &AllowlistState, sender: address): bool {
        if (!state.allowlist_enabled) {
            return true
        };

        state.allowlist.contains(&sender)
    }

    public fun apply_allowlist_updates(
        state: &mut AllowlistState, removes: vector<address>, adds: vector<address>
    ) {
        removes.for_each_ref(|remove_address| {
            let (found, i) = state.allowlist.index_of(remove_address);
            if (found) {
                state.allowlist.swap_remove(i);
                event::emit(AllowlistRemove { sender: *remove_address });
                event::emit_event(
                    &mut state.allowlist_remove_events,
                    AllowlistRemove { sender: *remove_address }
                );
            }
        });

        if (!adds.is_empty()) {
            assert!(
                state.allowlist_enabled,
                error::invalid_state(E_ALLOWLIST_NOT_ENABLED)
            );

            adds.for_each_ref(|add_address| {
                let add_address: address = *add_address;
                let (found, _) = state.allowlist.index_of(&add_address);
                if (add_address != @0x0 && !found) {
                    state.allowlist.push_back(add_address);
                    event::emit(AllowlistAdd { sender: add_address });
                    event::emit_event(
                        &mut state.allowlist_add_events,
                        AllowlistAdd { sender: add_address }
                    );
                }
            });
        }
    }

    public fun destroy_allowlist(state: AllowlistState) {
        let AllowlistState {
            allowlist_enabled: _,
            allowlist: _,
            allowlist_add_events: add_events,
            allowlist_remove_events: remove_events
        } = state;

        event::destroy_handle(add_events);
        event::destroy_handle(remove_events);
    }

    #[test_only]
    public fun new_add_event(add: address): AllowlistAdd {
        AllowlistAdd { sender: add }
    }

    #[test_only]
    public fun new_remove_event(remove: address): AllowlistRemove {
        AllowlistRemove { sender: remove }
    }
}

#[test_only]
module ccip::allowlist_test {
    use std::account;
    use std::event;
    use std::signer;
    use std::vector;

    use ccip::allowlist;

    #[test(owner = @0x0)]
    fun init_empty_is_empty_and_disabled(owner: &signer) {
        let state = set_up_test(owner, vector::empty());

        assert!(!allowlist::get_allowlist_enabled(&state), 1);
        assert!(vector::is_empty(&allowlist::get_allowlist(&state)), 1);

        // Any address is allowed when the allowlist is disabled
        assert!(allowlist::is_allowed(&state, @0x1111111111111), 1);

        allowlist::destroy_allowlist(state);
    }

    #[test(owner = @0x0)]
    fun init_non_empty_is_non_empty_and_enabled(owner: &signer) {
        let init_allowlist = vector[@0x1, @0x2];

        let state = set_up_test(owner, init_allowlist);

        assert!(allowlist::get_allowlist_enabled(&state), 1);
        assert!(vector::length(&allowlist::get_allowlist(&state)) == 2, 1);

        // The given addresses are allowed
        assert!(
            allowlist::is_allowed(&state, init_allowlist[0]),
            1
        );
        assert!(
            allowlist::is_allowed(&state, init_allowlist[1]),
            1
        );

        // Other addresses are not allowed
        assert!(!allowlist::is_allowed(&state, @0x3), 1);

        allowlist::destroy_allowlist(state);
    }

    #[test(owner = @0x0)]
    #[expected_failure(abort_code = 0x30001, location = allowlist)]
    fun cannot_add_to_disabled_allowlist(owner: &signer) {
        let state = set_up_test(owner, vector::empty());

        let adds = vector[@0x1];

        allowlist::apply_allowlist_updates(&mut state, vector::empty(), adds);

        allowlist::destroy_allowlist(state);
    }

    #[test(owner = @0x0)]
    fun apply_allowlist_updates_mutates_state(owner: &signer) {
        let state = set_up_test(owner, vector::empty());
        allowlist::set_allowlist_enabled(&mut state, true);

        assert!(vector::is_empty(&allowlist::get_allowlist(&state)), 1);

        allowlist::apply_allowlist_updates(&mut state, vector::empty(), vector::empty());

        assert!(vector::is_empty(&allowlist::get_allowlist(&state)), 1);

        let adds = vector[@0x1, @0x2];

        allowlist::apply_allowlist_updates(&mut state, vector::empty(), adds);

        assert_add_events_emitted(adds);

        let removes = vector[@0x1];

        allowlist::apply_allowlist_updates(&mut state, removes, vector::empty());

        assert_remove_events_emitted(removes);

        assert!(vector::length(&allowlist::get_allowlist(&state)) == 1, 1);
        assert!(allowlist::is_allowed(&state, @0x2), 1);
        assert!(!allowlist::is_allowed(&state, @0x1), 1);

        allowlist::destroy_allowlist(state);
    }

    #[test(owner = @0x0)]
    fun apply_allowlist_updates_removes_before_adds(owner: &signer) {
        let account_to_allow = @0x1;
        let state = set_up_test(owner, vector::empty());
        allowlist::set_allowlist_enabled(&mut state, true);

        let adds_and_removes = vector[account_to_allow];

        allowlist::apply_allowlist_updates(&mut state, vector::empty(), adds_and_removes);

        assert!(vector::length(&allowlist::get_allowlist(&state)) == 1, 1);
        assert!(allowlist::is_allowed(&state, account_to_allow), 1);

        allowlist::apply_allowlist_updates(&mut state, adds_and_removes, adds_and_removes);

        // Since removes happen before adds, the account should still be allowed
        assert!(allowlist::is_allowed(&state, account_to_allow), 1);

        assert_remove_events_emitted(adds_and_removes);
        // Events don't get purged after calling event::emitted_events so we'll have
        // both the first and the second add event in the emitted events
        vector::push_back(&mut adds_and_removes, account_to_allow);
        assert_add_events_emitted(adds_and_removes);

        allowlist::destroy_allowlist(state);
    }

    inline fun assert_add_events_emitted(
        added_addresses: vector<address>
    ) {
        let expected =
            added_addresses.map::<address, allowlist::AllowlistAdd> (|add| allowlist::new_add_event(
                add
            ));
        let got = event::emitted_events<allowlist::AllowlistAdd>();
        let number_of_adds = vector::length(&expected);

        // Assert that exactly one event was emitted for each add
        assert!(vector::length(&got) == number_of_adds, 1);

        // Assert that the emitted events match the expected events
        for (i in 0..number_of_adds) {
            assert!(
                vector::borrow(&expected, i) == vector::borrow(&got, i),
                1
            );
        }
    }

    inline fun assert_remove_events_emitted(
        added_addresses: vector<address>
    ) {
        let expected =
            added_addresses.map::<address, allowlist::AllowlistRemove> (|add| allowlist::new_remove_event(
                add
            ));
        let got = event::emitted_events<allowlist::AllowlistRemove>();
        let number_of_adds = vector::length(&expected);

        // Assert that exactly one event was emitted for each add
        assert!(vector::length(&got) == number_of_adds, 1);

        // Assert that the emitted events match the expected events
        for (i in 0..number_of_adds) {
            assert!(
                vector::borrow(&expected, i) == vector::borrow(&got, i),
                1
            );
        }
    }

    inline fun set_up_test(owner: &signer, allowlist: vector<address>):
        allowlist::AllowlistState {
        account::create_account_for_test(signer::address_of(owner));

        allowlist::new(owner, allowlist)
    }
}
