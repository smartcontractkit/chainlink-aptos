module ccip::ownable {
  use std::error;
  use std::event;

  struct OwnableState has store {
    owner: address,
    pending_owner: address,
  }

  const E_OWNER_CANNOT_BE_ZERO: u64 = 1;
  const E_MUST_BE_PROPOSED_OWNER: u64 = 2;
  const E_CANNOT_TRANSFER_TO_SELF: u64 = 3;
  const E_ONLY_CALLABLE_BY_OWNER: u64 = 4;

  #[event]
  struct OwnershipTransferRequested has store, drop {
    from: address,
    to: address,
  }

  #[event]
  struct OwnershipTransferred has store, drop {
    from: address,
    to: address,
  }

  public fun new(new_owner: address, pending_owner: address): OwnableState {
    assert!(new_owner != @0x0, error::invalid_argument(E_OWNER_CANNOT_BE_ZERO));

    let new_state = OwnableState {
      owner: new_owner,
      pending_owner: @0x0,
    };

    if (pending_owner != @0x0) {
      transfer_ownership(new_owner, &mut new_state, pending_owner);
    };

    new_state
  }

  public fun owner(state: &OwnableState): address {
    state.owner
  }

  public fun transfer_ownership(caller: address, state: &mut OwnableState, to: address) {
    assert_only_owner(caller, state);
    assert!(caller != to, error::invalid_argument(E_CANNOT_TRANSFER_TO_SELF));

    state.pending_owner = to;

    event::emit(OwnershipTransferRequested {
      from: state.owner,
      to,
    });
  }

  public fun accept_ownership(caller: address, state: &mut OwnableState) {
    assert!(caller == state.pending_owner, error::permission_denied(E_MUST_BE_PROPOSED_OWNER));

    let previous_owner = state.owner;
    state.owner = caller;
    state.pending_owner = @0x0;

    event::emit(OwnershipTransferred {
      from: previous_owner,
      to: state.owner,
    });
  }

  public fun assert_only_owner(caller: address, state: &OwnableState) {
    assert!(caller == state.owner, error::permission_denied(E_ONLY_CALLABLE_BY_OWNER));
  }
}
