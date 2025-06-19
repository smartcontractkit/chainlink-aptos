module ccip::receiver_registry;

use std::ascii;
use std::type_name::{Self, TypeName};
use std::string::{Self, String};

use sui::address;
use sui::event;
use sui::vec_map::{Self, VecMap};

use ccip::state_object::{Self, CCIPObjectRef, OwnerCap};

public struct ReceiverConfig has store, copy, drop {
    module_name: String,
    // technically not needed, bc it is always "ccip_receive"
    function_name: String,
    // if the receiver state is an empty address, we assume that the receiver has a function sign like
    // receiver::module_name::ccip_receive(ref: &CCIPObjectRef, receiver_package_id: address, receiver_params: osh::ReceiverParams): osh::ReceiverParams
    // if the receiver state is not an empty address, we assume that the receiver has a function signature like
    // receiver::module_name::ccip_receive(ref: &CCIPObjectRef, receiver_state: &mut ReceiverState, receiver_package_id: address, receiver_params: osh::ReceiverParams): osh::ReceiverParams
    receiver_state_id: address,
    proof_typename: TypeName,
}

// TODO: rethink the use of vec_map here, as it is O(N) for lookups. consider a bag or other map-like structure.
public struct ReceiverRegistry has key, store {
    id: UID,
    receiver_configs: VecMap<address, ReceiverConfig>
}

public struct ReceiverRegistered has copy, drop {
    receiver_package_id: address,
    receiver_state_id: address,
    receiver_module_name: String,
    proof_typename: TypeName,
}

public struct ReceiverUnregistered has copy, drop {
    receiver_package_id: address,
}

const E_ALREADY_REGISTERED: u64 = 1;
const E_ALREADY_INITIALIZED: u64 = 2;
const E_UNKNOWN_RECEIVER: u64 = 3;
const E_NOT_ALLOWED: u64 = 4;

public fun type_and_version(): String {
    string::utf8(b"ReceiverRegistry 1.6.0")
}

public fun initialize(
    ref: &mut CCIPObjectRef,
    _: &OwnerCap,
    ctx: &mut TxContext
) {
    assert!(
        !state_object::contains<ReceiverRegistry>(ref),
        E_ALREADY_INITIALIZED
    );
    let state = ReceiverRegistry {
        id: object::new(ctx),
        receiver_configs: vec_map::empty()
    };

    state_object::add(ref, state, ctx);
}

public fun register_receiver<ProofType: drop>(
    ref: &mut CCIPObjectRef,
    receiver_state_id: address,
    _proof: ProofType,
) {
    let registry = state_object::borrow_mut<ReceiverRegistry>(ref);
    let proof_tn = type_name::get<ProofType>();
    let address_str = type_name::get_address(&proof_tn);
    let receiver_module_name = std::string::from_ascii(type_name::get_module(&proof_tn));
    let receiver_package_id = address::from_ascii_bytes(&ascii::into_bytes(address_str));
    assert!(!registry.receiver_configs.contains(&receiver_package_id), E_ALREADY_REGISTERED);

    let proof_typename = type_name::get<ProofType>();
    let receiver_config = ReceiverConfig {
        module_name: receiver_module_name,
        function_name: string::utf8(b"ccip_receive"),
        receiver_state_id,
        proof_typename,
    };
    registry.receiver_configs.insert(receiver_package_id, receiver_config);

    event::emit(ReceiverRegistered {
        receiver_package_id,
        receiver_state_id,
        receiver_module_name,
        proof_typename,
    });
}

public fun unregister_receiver(
    ref: &mut CCIPObjectRef,
    receiver_package_id: address,
    ctx: &TxContext,
) {
    let current_owner = state_object::get_current_owner(ref);
    let registry = state_object::borrow_mut<ReceiverRegistry>(ref);
    
    assert!(
        registry.receiver_configs.contains(&receiver_package_id),
        E_UNKNOWN_RECEIVER
    );

    assert!(ctx.sender() == current_owner, E_NOT_ALLOWED);

    registry.receiver_configs.remove(&receiver_package_id);

    event::emit(ReceiverUnregistered {
        receiver_package_id,
    });
}

public fun get_receiver_config(
    ref: &CCIPObjectRef,
    receiver_package_id: address,
): ReceiverConfig {
    let registry = state_object::borrow<ReceiverRegistry>(ref);

    assert!(
        registry.receiver_configs.contains(&receiver_package_id),
        E_UNKNOWN_RECEIVER
    );
    *registry.receiver_configs.get(&receiver_package_id)
}

public fun get_receiver_config_fields(rc: ReceiverConfig): (String, String, address, TypeName) {
    (rc.module_name, rc.function_name, rc.receiver_state_id, rc.proof_typename)
}

// This function checks if a receiver is registered in the registry but not if the type proof matches.
// this is not needed anymore?
public fun is_registered_receiver(ref: &CCIPObjectRef, receiver_package_id: address): bool {
    let registry = state_object::borrow<ReceiverRegistry>(ref);
    registry.receiver_configs.contains(&receiver_package_id)
}

// this will return empty string if the receiver is not registered. this can be called by the PTB to get the module name of the receiver and confirm if this receiver is registered.
// this is used by the PTB to get the module name of the receiver and confirm if this receiver is registered.
public fun get_receiver_module_and_state(ref: &CCIPObjectRef, receiver_package_id: address): (String, address) {
    let registry = state_object::borrow<ReceiverRegistry>(ref);

    if (registry.receiver_configs.contains(&receiver_package_id)) {
        let receiver_config = registry.receiver_configs.get(&receiver_package_id);
        return (receiver_config.module_name, receiver_config.receiver_state_id)
    };

    (string::utf8(b""), @0x0)
}
