/// This module creates a single object for storing CCIP state resources in order to:
///
/// - simplify ownership management
/// - simplify observability: all resources and events can be queried and viewed at a single address
/// - decouple module deployment and initialization: the CCIP module will be deployed using the
///   recommended object code deployment approach, but initialization requires various
///   "constructor" parameters that cannot be passed it at deploy (ie. init_module()) time.
///   Object code deployment only allows for publishing and upgrading modules, with no way to
///   retrieve a signer to store resources (see: 0x1::object_code_deployment), so a different
///   object is necessary.
module ccip::state_object {
    use std::error;
    use std::object::{Self, ExtendRef, ObjectCore, TransferRef};
    use std::signer;

    friend ccip::offramp;
    friend ccip::onramp;
    friend ccip::token_admin_registry;

    struct StateObjectRefs has key {
        extend_ref: ExtendRef,
        transfer_ref: TransferRef
    }

    const E_NOT_OBJECT_DEPLOYMENT: u64 = 1;
    const E_NOT_CCIP_OBJECT_OWNER: u64 = 2;

    fun init_module(publisher: &signer) {
        assert!(
            object::is_object(signer::address_of(publisher)),
            error::invalid_state(E_NOT_OBJECT_DEPLOYMENT)
        );

        let constructor_ref = object::create_named_object(publisher, b"CCIPStateObject");

        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let transfer_ref = object::generate_transfer_ref(&constructor_ref);
        let object_signer = object::generate_signer(&constructor_ref);

        move_to(&object_signer, StateObjectRefs { extend_ref, transfer_ref });
    }

    #[view]
    public inline fun object_address(): address {
        // hard code the object seed directly in order to keep the function inline.
        object::create_object_address(&@ccip, b"CCIPStateObject")
    }

    public(friend) fun object_signer(): signer acquires StateObjectRefs {
        let store = borrow_global<StateObjectRefs>(object_address());
        object::generate_signer_for_extending(&store.extend_ref)
    }

    public(friend) fun assert_can_initialize(caller: &signer) {
        let caller_address = signer::address_of(caller);
        let ccip_object = object::address_to_object<ObjectCore>(@ccip);

        assert!(
            caller_address == object::owner(ccip_object)
                || caller_address == object::root_owner(ccip_object),
            error::permission_denied(E_NOT_CCIP_OBJECT_OWNER)
        );
    }
}
