module ccip_router::router {
    use std::string::{Self, String};

    use sui::event;
    use sui::table::{Self, Table};

    public struct ROUTER has drop {}

    public struct OwnerCap has key, store {
        id: UID,
    }

    public struct OnRampSet has copy, drop {
        dest_chain_selector: u64,
        on_ramp_info: OnRampInfo,
    }

    public struct OnRampInfo has copy, store, drop {
        onramp_address: address,
        onramp_version: vector<u8>,
    }

    public struct RouterState has key {
        id: UID,
        // ownable_state: ownable::OwnableState,
        on_ramp_infos: Table<u64, OnRampInfo>,
    }

    const EParamsLengthMismatch: u64 = 1;
    const EOnrampInfoNotFound: u64 = 2;
    const EInvalidOnrampVersion: u64 = 3;

    fun init(_witness: ROUTER, ctx: &mut TxContext) {
        let router = RouterState {
            id: object::new(ctx),
            on_ramp_infos: table::new(ctx),
        };
        let owner_cap = OwnerCap {
            id: object::new(ctx),
        };

        transfer::share_object(router);
        transfer::transfer(owner_cap, ctx.sender());
    }

    public fun type_and_version(): String {
        string::utf8(b"Router 1.6.0")
    }

    public fun is_chain_supported(router: &RouterState, dest_chain_selector: u64): bool {
        router.on_ramp_infos.contains(dest_chain_selector)
    }

    public fun get_on_ramp_info(router: &RouterState, dest_chain_selector: u64): (address, vector<u8>) {
        assert!(
            router.on_ramp_infos.contains(dest_chain_selector),
            EOnrampInfoNotFound
        );

        let on_ramp_info = *router.on_ramp_infos.borrow(dest_chain_selector);

        (on_ramp_info.onramp_address, on_ramp_info.onramp_version)
    }

    /// Returns the onRamp versions for the given destination chains.
    public fun get_on_ramp_infos(
        router: &RouterState, dest_chain_selectors: vector<u64>
    ): vector<OnRampInfo> {
        dest_chain_selectors.map!(
            |dest_chain_selector| {
                if (router.on_ramp_infos.contains(dest_chain_selector)) {
                    *router.on_ramp_infos.borrow(dest_chain_selector)
                } else {
                    OnRampInfo {
                        onramp_address: @0x0,
                        onramp_version: vector[],
                    }
                }
            },
        )
    }

    public fun get_on_ramp_version(info: OnRampInfo): vector<u8> {
        info.onramp_version
    }

    public fun get_on_ramp_address(info: OnRampInfo): address {
        info.onramp_address
    }

    /// Sets the onRamp info for the given destination chains.
    /// This function will overwrite the existing infos.
    /// This function can only be called by the owner of the contract.
    /// @param owner_cap The owner capability.
    /// @param router The router state.
    /// @param dest_chain_selectors The destination chain selectors.
    /// @param on_ramp_addresses The onRamp addresses.
    /// @param on_ramp_versions The onRamp versions, the inner vector must be of length 0 or 3. 0 indicates
    /// the destination chain is no longer supported. Length 3 encodes the version of the onRamp contract.
    public fun set_on_ramp_infos(
        _: &OwnerCap,
        router: &mut RouterState,
        dest_chain_selectors: vector<u64>,
        on_ramp_addresses: vector<address>,
        on_ramp_versions: vector<vector<u8>>,
    ) {
        assert!(
            dest_chain_selectors.length() == on_ramp_addresses.length(),
            EParamsLengthMismatch
        );
        assert!(
            dest_chain_selectors.length() == on_ramp_versions.length(),
            EParamsLengthMismatch
        );

        let mut i = 0;
        let selector_len = dest_chain_selectors.length();
        while (i < selector_len) {
            let dest_chain_selector = dest_chain_selectors[i];
            let version = on_ramp_versions[i];

            if (version.length() == 0) {
                if (router.on_ramp_infos.contains(dest_chain_selector)) {
                    router.on_ramp_infos.remove(dest_chain_selector);
                };
                event::emit(
                    OnRampSet {
                        dest_chain_selector,
                        on_ramp_info: OnRampInfo{
                            onramp_address: @0x0,
                            onramp_version: vector[],
                        }
                    }
                );
            } else {
                assert!(version.length() == 3, EInvalidOnrampVersion);
                if (router.on_ramp_infos.contains(dest_chain_selector)) {
                    router.on_ramp_infos.remove(dest_chain_selector);
                };

                let info = OnRampInfo {
                    onramp_address: on_ramp_addresses[i],
                    onramp_version: on_ramp_versions[i],
                };
                router.on_ramp_infos.add(dest_chain_selector, info);

                event::emit(OnRampSet { dest_chain_selector, on_ramp_info: info });
            };
            i = i + 1;
        };
    }

    // ===================== TESTS =====================

    #[test_only]
    public fun test_init(ctx: &mut TxContext) {
        init(ROUTER {}, ctx);
    }
}