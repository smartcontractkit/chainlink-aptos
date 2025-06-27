module ccip::allowlist;

use sui::event;

public struct AllowlistState has key, store {
    id: UID,
    allowlist_enabled: bool,
    // it's possible to use vec_set for allowlist
    allowlist: vector<address>,
}

public struct AllowlistRemove has copy, drop {
    sender: address,
}

public struct AllowlistAdd has copy, drop {
    sender: address,
}

const EAllowlistNotEnabled: u64 = 1;

public fun new(allowlist: vector<address>, ctx: &mut TxContext): AllowlistState {
    AllowlistState {
        id: object::new(ctx),
        allowlist_enabled: !allowlist.is_empty(),
        allowlist,
    }
}

public fun get_allowlist_enabled(state: &AllowlistState): bool {
    state.allowlist_enabled
}

public fun set_allowlist_enabled(state: &mut AllowlistState, enabled: bool) {
    state.allowlist_enabled = enabled
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
    state: &mut AllowlistState,
    removes: vector<address>,
    adds: vector<address>,
) {
    let mut i = 0;
    let mut len = removes.length();
    while (i < len) {
        // get the address to remove
        let remove_address = &removes[i];
        // find the index of the address in the allowlist
        let (found, j) = vector::index_of(&state.allowlist, remove_address);
        if (found) {
            vector::swap_remove(&mut state.allowlist, j);
            event::emit(
                AllowlistRemove {
                    sender: *remove_address
                }
            );
        };
        i = i + 1;
    };

    if (!adds.is_empty()) {
        assert!(state.allowlist_enabled, EAllowlistNotEnabled);

        i = 0;
        len = adds.length();
        while (i < len) {
            let add_address = &adds[i];
            let (found, _) = vector::index_of(&state.allowlist, add_address);
            if (add_address != @0x0 && !found) {
                state.allowlist.push_back(*add_address);
                event::emit(
                    AllowlistAdd {
                        sender: *add_address
                    }
                );
            };
            i = i + 1;
        };
    }
}

public fun destroy_allowlist(state: AllowlistState) {
    let AllowlistState {
        id,
        allowlist_enabled: _,
        allowlist: _,
    } = state;
    object::delete(id);
}
