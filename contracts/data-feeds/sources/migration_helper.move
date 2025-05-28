module data_feeds::migration_helper {
    use std::event;
    use std::signer;

    // Errors
    const ENOT_OWNER: u64 = 1;

    fun init_module(publisher: &signer) {
        assert!(signer::address_of(publisher) == @data_feeds, ENOT_OWNER);

        if (!data_feeds::registry::get_migration_status()) {
            data_feeds::registry::register_callbacks(publisher);
        }
    }
}
