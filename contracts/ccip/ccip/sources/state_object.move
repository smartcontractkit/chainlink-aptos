module ccip::state_object;

use std::ascii;
use std::type_name;

use sui::address;
use sui::dynamic_object_field as dof;
use sui::event;

const E_MODULE_ALREADY_EXISTS: u64 = 1;
const E_MODULE_DOES_NOT_EXISTS: u64 = 2;
const E_CANNOT_TRANSFER_TO_SELF: u64 = 3;
const E_OWNER_CHANGED: u64 = 4;
const E_NO_PENDING_TRANSFER: u64 = 5;
const E_TRANSFER_NOT_ACCEPTED: u64 = 6;
const E_TRANSFER_ALREADY_ACCEPTED: u64 = 7;
const E_MUST_BE_PROPOSED_OWNER: u64 = 8;
const E_PROPOSED_OWNER_MISMATCH: u64 = 9;
const E_UNAUTHORIZED: u64 = 10;

public struct OwnershipTransferRequested has copy, drop {
    from: address,
    to: address,
}

public struct OwnershipTransferAccepted has copy, drop {
    from: address,
    to: address,
}

public struct OwnershipTransferred has copy, drop {
    from: address,
    to: address,
}

public struct OwnerCap has key, store {
    id: UID,
}

public struct CCIPObjectRef has key, store {
    id: UID,
    // this is not the owner of the CCIP object ref in SUI's concept
    // this object is a shared object and cannot be transferred and has no owner according to SUI
    // the owner here refers to the address which has the power to manage this ref
    current_owner: address,
    pending_transfer: Option<PendingTransfer>,
}

public struct CCIPObjectRefPointer has key, store {
    id: UID,
    object_ref_id: address,
    owner_cap_id: address,
}

public struct PendingTransfer has copy, drop, store {
    from: address,
    to: address,
    accepted: bool,
}

public struct STATE_OBJECT has drop {}

fun init(_witness: STATE_OBJECT, ctx: &mut TxContext) {
    let ref = CCIPObjectRef {
        id: object::new(ctx),
        current_owner: ctx.sender(),
        pending_transfer: option::none(),
    };
    let owner_cap = OwnerCap {
        id: object::new(ctx),
    };

    let pointer = CCIPObjectRefPointer {
        id: object::new(ctx),
        object_ref_id: object::id_to_address(object::borrow_id(&ref)),
        owner_cap_id: object::id_to_address(object::borrow_id(&owner_cap)),
    };

    let tn = type_name::get_with_original_ids<STATE_OBJECT>();
    let package_bytes = ascii::into_bytes(tn.get_address());
    let package_id = address::from_ascii_bytes(&package_bytes);

    transfer::share_object(ref);
    transfer::transfer(owner_cap, ctx.sender());
    transfer::transfer(pointer, package_id);
}

public(package) fun add<T: key + store>(
    ref: &mut CCIPObjectRef,
    obj: T,
    ctx: &TxContext,
) {
    assert!(ctx.sender() == ref.current_owner, E_UNAUTHORIZED);
    let tn = type_name::get<T>();
    assert!(!dof::exists_(&ref.id, tn), E_MODULE_ALREADY_EXISTS);
    dof::add(&mut ref.id, tn, obj);
}

public(package) fun contains<T>(ref: &CCIPObjectRef): bool {
    let tn = type_name::get<T>();
    dof::exists_(&ref.id, tn)
}

public(package) fun remove<T: key + store>(
    ref: &mut CCIPObjectRef,
    ctx: &TxContext,
): T {
    assert!(ctx.sender() == ref.current_owner, E_UNAUTHORIZED);
    let tn = type_name::get<T>();
    assert!(dof::exists_(&ref.id, tn), E_MODULE_DOES_NOT_EXISTS);
    dof::remove(&mut ref.id, tn)
}

public(package) fun borrow<T: key + store>(ref: &CCIPObjectRef): &T {
    let tn = type_name::get<T>();
    dof::borrow(&ref.id, tn)
}

public(package) fun borrow_mut<T: key + store>(ref: &mut CCIPObjectRef): &mut T {
    let tn = type_name::get<T>();
    dof::borrow_mut(&mut ref.id, tn)
}

public fun transfer_ownership(ref: &mut CCIPObjectRef, to: address, ctx: &mut TxContext) {
    let caller = ctx.sender();
    assert!(caller != to, E_CANNOT_TRANSFER_TO_SELF);
    assert!(ref.current_owner == caller, E_UNAUTHORIZED);

    ref.pending_transfer = option::some(PendingTransfer { from: caller, to, accepted: false });

    event::emit(OwnershipTransferRequested { from: caller, to });
}

public fun accept_ownership(ref: &mut CCIPObjectRef, ctx: &mut TxContext) {
    assert!(ref.pending_transfer.is_some(), E_NO_PENDING_TRANSFER);

    let caller = ctx.sender();
    let pending_transfer = ref.pending_transfer.borrow_mut();

    assert!(pending_transfer.from == ref.current_owner, E_OWNER_CHANGED);
    assert!(pending_transfer.to == caller, E_MUST_BE_PROPOSED_OWNER);
    assert!(!pending_transfer.accepted, E_TRANSFER_ALREADY_ACCEPTED);

    pending_transfer.accepted = true;

    event::emit(OwnershipTransferAccepted { from: pending_transfer.from, to: caller });
}

public fun execute_ownership_transfer(
    ref: &mut CCIPObjectRef,
    to: address,
    ctx: &mut TxContext,
) {
    let caller = ctx.sender();
    assert!(caller == ref.current_owner, E_UNAUTHORIZED);

    let pending_transfer = ref.pending_transfer.extract();

    // since ref is a shared object now, it's impossible to transfer its ownership
    assert!(pending_transfer.from == ref.current_owner, E_OWNER_CHANGED);
    assert!(pending_transfer.to == to, E_PROPOSED_OWNER_MISMATCH);
    assert!(pending_transfer.accepted, E_TRANSFER_NOT_ACCEPTED);

    // transfer the owner cap to the new owner
    // cannot transfer the shared object anymore
    ref.current_owner = pending_transfer.to;
    // the extract will remove the object within option wrapper
    // state.pending_transfer = option::none();

    event::emit(OwnershipTransferred { from: caller, to })
}

public(package) fun get_current_owner(ref: &CCIPObjectRef): address {
    ref.current_owner
}

#[test_only]
public fun test_init(ctx: &mut TxContext) {
    init(STATE_OBJECT {}, ctx);
}

#[test_only]
public(package) fun create(ctx: &mut TxContext): (OwnerCap, CCIPObjectRef) {
    let ref = CCIPObjectRef {
        id: object::new(ctx),
        current_owner: ctx.sender(),
        pending_transfer: option::none(),
    };
    let owner_cap = OwnerCap {
        id: object::new(ctx),
    };
    (owner_cap, ref)
}

#[test_only]
public fun destroy_state_object(ref: CCIPObjectRef) {
    let CCIPObjectRef { id, current_owner: _owner, pending_transfer: _pending_transfer } = ref;
    object::delete(id);
}

#[test_only]
public fun destroy_owner_cap(cap: OwnerCap) {
    let OwnerCap { id } = cap;
    object::delete(id);
}

#[test_only]
public fun pending_transfer(ref: &CCIPObjectRef): (address, address, bool) {
    let pt = ref.pending_transfer;
    if (pt.is_none()) {
        return (@0x0, @0x0, false)
    };
    let pt = option::borrow(&ref.pending_transfer);

    (pt.from, pt.to, pt.accepted)
}
