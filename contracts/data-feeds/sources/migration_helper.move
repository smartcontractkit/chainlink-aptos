module data_feeds::migration_helper {
    use std::signer;

    // Errors
    const ENOT_OWNER: u64 = 1;

    // This module is required to access the original data-feeds signer during an upgrade *after* the initial deployment.
    // The original signer is necessary to correctly construct the `on_report` callbacks in the Registry.
    // This signer cannot be recovered outside of an `init_module` call, and it does not match the deployer's signer
    // if the Data Feeds package was deployed to a new object address.
    fun init_module(publisher: &signer) {
        assert!(signer::address_of(publisher) == @data_feeds, ENOT_OWNER);

        if (!data_feeds::registry::get_migration_status()) {
            data_feeds::registry::register_callbacks(publisher);
        }
    }
}
