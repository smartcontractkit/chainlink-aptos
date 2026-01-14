module ccip::allowlist {
    use std::account;
    use std::event::{Self, EventHandle};
    use std::error;
    use std::string::{Self, String};

    struct AllowlistState has store {
        allowlist_name: String,
        allowlist_enabled: bool,
        allowlist: vector<address>,
        allowlist_add_events: EventHandle<AllowlistAdd>,
        allowlist_remove_events: EventHandle<AllowlistRemove>
    }

    #[event]
    struct AllowlistRemove has store, drop {
        allowlist_name: String,
        removed_address: address
    }

    #[event]
    struct AllowlistAdd has store, drop {
        allowlist_name: String,
        added_address: address
    }

    const E_ALLOWLIST_NOT_ENABLED: u64 = 1;

    public fun new(event_account: &signer, allowlist: vector<address>): AllowlistState {
        new_with_name(event_account, allowlist, string::utf8(b"default"))
    }

    public fun new_with_name(
        event_account: &signer, allowlist: vector<address>, allowlist_name: String
    ): AllowlistState {
        AllowlistState {
            allowlist_name,
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
        removes.for_each_ref(
            |removed_address| {
                let removed_address: address = *removed_address;
                let (found, i) = state.allowlist.index_of(&removed_address);
                if (found) {
                    state.allowlist.swap_remove(i);
                    event::emit_event(
                        &mut state.allowlist_remove_events,
                        AllowlistRemove {
                            allowlist_name: state.allowlist_name,
                            removed_address
                        }
                    );
                }
            }
        );

        if (!adds.is_empty()) {
            assert!(
                state.allowlist_enabled,
                error::invalid_state(E_ALLOWLIST_NOT_ENABLED)
            );

            adds.for_each_ref(
                |added_address| {
                    let added_address: address = *added_address;
                    if (added_address != @0x0
                        && !state.allowlist.contains(&added_address)) {
                        state.allowlist.push_back(added_address);
                        event::emit_event(
                            &mut state.allowlist_add_events,
                            AllowlistAdd {
                                allowlist_name: state.allowlist_name,
                                added_address
                            }
                        );
                    }
                }
            );
        }
    }

    public fun destroy_allowlist(state: AllowlistState) {
        let AllowlistState {
            allowlist_name: _,
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
        AllowlistAdd {
            added_address: add,
            allowlist_name: string::utf8(b"default")
        }
    }

    #[test_only]
    public fun new_remove_event(remove: address): AllowlistRemove {
        AllowlistRemove {
            removed_address: remove,
            allowlist_name: string::utf8(b"default")
        }
    }

    #[test_only]
    public fun get_allowlist_add_events(state: &AllowlistState): &EventHandle<AllowlistAdd> {
        &state.allowlist_add_events
    }

    #[test_only]
    public fun get_allowlist_remove_events(state: &AllowlistState)
        : &EventHandle<AllowlistRemove> {
        &state.allowlist_remove_events
    }
}

#[test_only]
module ccip::allowlist_test {
    use std::account;
    use std::event;
    use std::signer;
    use std::vector;

    use ccip::allowlist::{Self, AllowlistAdd, AllowlistRemove};

    #[test(owner = @0x0)]
    fun init_empty_is_empty_and_disabled(owner: &signer) {
        let state = set_up_test(owner, vector::empty());

        assert!(!allowlist::get_allowlist_enabled(&state));
        assert!(allowlist::get_allowlist(&state).is_empty());

        // Any address is allowed when the allowlist is disabled
        assert!(allowlist::is_allowed(&state, @0x1111111111111));

        allowlist::destroy_allowlist(state);
    }

    #[test(owner = @0x0)]
    fun init_non_empty_is_non_empty_and_enabled(owner: &signer) {
        let init_allowlist = vector[@0x1, @0x2];

        let state = set_up_test(owner, init_allowlist);

        assert!(allowlist::get_allowlist_enabled(&state));
        assert!(allowlist::get_allowlist(&state).length() == 2);

        // The given addresses are allowed
        assert!(allowlist::is_allowed(&state, init_allowlist[0]));
        assert!(allowlist::is_allowed(&state, init_allowlist[1]));

        // Other addresses are not allowed
        assert!(!allowlist::is_allowed(&state, @0x3));

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

        assert!(allowlist::get_allowlist(&state).is_empty());

        allowlist::apply_allowlist_updates(&mut state, vector::empty(), vector::empty());

        assert!(allowlist::get_allowlist(&state).is_empty());

        let adds = vector[@0x1, @0x2];

        allowlist::apply_allowlist_updates(&mut state, vector::empty(), adds);

        assert_add_events_emitted(adds, &state);

        let removes = vector[@0x1];

        allowlist::apply_allowlist_updates(&mut state, removes, vector::empty());

        assert_remove_events_emitted(removes, &state);

        assert!(allowlist::get_allowlist(&state).length() == 1);
        assert!(allowlist::is_allowed(&state, @0x2));
        assert!(!allowlist::is_allowed(&state, @0x1));

        allowlist::destroy_allowlist(state);
    }

    #[test(owner = @0x0)]
    fun apply_allowlist_updates_removes_before_adds(owner: &signer) {
        let account_to_allow = @0x1;
        let state = set_up_test(owner, vector::empty());
        allowlist::set_allowlist_enabled(&mut state, true);

        let adds_and_removes = vector[account_to_allow];

        allowlist::apply_allowlist_updates(&mut state, vector::empty(), adds_and_removes);

        assert!(allowlist::get_allowlist(&state).length() == 1);
        assert!(allowlist::is_allowed(&state, account_to_allow));

        allowlist::apply_allowlist_updates(&mut state, adds_and_removes, adds_and_removes);

        // Since removes happen before adds, the account should still be allowed
        assert!(allowlist::is_allowed(&state, account_to_allow));

        assert_remove_events_emitted(adds_and_removes, &state);
        // Events don't get purged after calling event::emitted_events so we'll have
        // both the first and the second add event in the emitted events
        adds_and_removes.push_back(account_to_allow);
        assert_add_events_emitted(adds_and_removes, &state);

        allowlist::destroy_allowlist(state);
    }

    inline fun assert_add_events_emitted(
        added_addresses: vector<address>, state: &allowlist::AllowlistState
    ) {
        let expected =
            added_addresses.map::<address, AllowlistAdd> (
                |add| allowlist::new_add_event(add)
            );
        let got =
            event::emitted_events_by_handle<AllowlistAdd>(
                allowlist::get_allowlist_add_events(state)
            );
        let number_of_adds = expected.length();

        // Assert that exactly one event was emitted for each add
        assert!(got.length() == number_of_adds);

        // Assert that the emitted events match the expected events
        for (i in 0..number_of_adds) {
            assert!(expected.borrow(i) == got.borrow(i));
        }
    }

    inline fun assert_remove_events_emitted(
        added_addresses: vector<address>, state: &allowlist::AllowlistState
    ) {
        let expected =
            added_addresses.map::<address, AllowlistRemove> (
                |add| allowlist::new_remove_event(add)
            );
        let got =
            event::emitted_events_by_handle<AllowlistRemove>(
                allowlist::get_allowlist_remove_events(state)
            );
        let number_of_adds = expected.length();

        // Assert that exactly one event was emitted for each add
        assert!(got.length() == number_of_adds);

        // Assert that the emitted events match the expected events
        for (i in 0..number_of_adds) {
            assert!(expected.borrow(i) == got.borrow(i));
        }
    }

    inline fun set_up_test(owner: &signer, allowlist: vector<address>)
        : allowlist::AllowlistState {
        account::create_account_for_test(signer::address_of(owner));

        allowlist::new(owner, allowlist)
    }
}
