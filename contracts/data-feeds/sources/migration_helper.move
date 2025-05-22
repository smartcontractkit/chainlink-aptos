module data_feeds::migration_helper {
    use std::event;
    use std::signer;

    // Errors
    const ENOT_OWNER: u64 = 1;

    #[event]
    struct MigrationPerformed has drop, store {
        publisher: address
    }

    fun init_module(publisher: &signer) {
        assert!(signer::address_of(publisher) == @data_feeds, ENOT_OWNER);

        data_feeds::registry::register_callbacks(publisher);

        event::emit(MigrationPerformed { publisher: signer::address_of(publisher) });
    }
}
