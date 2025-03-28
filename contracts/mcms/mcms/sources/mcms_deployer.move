/// This module is a modified version of Aptos' large_packages package, providing functions for publishing and upgrading
/// MCMS-owned modules of arbitrary sizes via object code deployment.
module mcms::mcms_deployer {
    use std::code::PackageRegistry;
    use std::error;
    use std::smart_table::{Self, SmartTable};
    use std::object;
    use std::object_code_deployment;

    use mcms::mcms_account;
    use mcms::mcms_registry;

    const E_CODE_MISMATCH: u64 = 1;

    struct StagingArea has key {
        metadata_serialized: vector<u8>,
        code: SmartTable<u64, vector<u8>>,
        last_module_idx: u64
    }

    /// Stages a chunk of code in the StagingArea.
    /// This function allows for incremental building of a large package.
    public entry fun stage_code_chunk(
        caller: &signer,
        metadata_chunk: vector<u8>,
        code_indices: vector<u16>,
        code_chunks: vector<vector<u8>>
    ) acquires StagingArea {
        mcms_account::assert_is_owner(caller);

        stage_code_chunk_internal(metadata_chunk, code_indices, code_chunks);
    }

    /// Stages a code chunk and immediately publishes it to a new object.
    public entry fun stage_code_chunk_and_publish_to_object(
        caller: &signer,
        metadata_chunk: vector<u8>,
        code_indices: vector<u16>,
        code_chunks: vector<vector<u8>>,
        new_owner_seed: vector<u8>
    ) acquires StagingArea {
        mcms_account::assert_is_owner(caller);

        let staging_area =
            stage_code_chunk_internal(metadata_chunk, code_indices, code_chunks);
        let code = assemble_module_code(staging_area);

        let owner_signer =
            &mcms_registry::create_owner_for_new_code_object(new_owner_seed);

        object_code_deployment::publish(
            owner_signer, staging_area.metadata_serialized, code
        );

        cleanup_staging_area_internal();
    }

    /// Stages a code chunk and immediately upgrades an existing code object.
    public entry fun stage_code_chunk_and_upgrade_object_code(
        caller: &signer,
        metadata_chunk: vector<u8>,
        code_indices: vector<u16>,
        code_chunks: vector<vector<u8>>,
        code_object_address: address
    ) acquires StagingArea {
        mcms_account::assert_is_owner(caller);

        let staging_area =
            stage_code_chunk_internal(metadata_chunk, code_indices, code_chunks);
        let code = assemble_module_code(staging_area);

        let owner_signer =
            &mcms_registry::get_signer_for_code_object_upgrade(code_object_address);

        object_code_deployment::upgrade(
            owner_signer,
            staging_area.metadata_serialized,
            code,
            object::address_to_object<PackageRegistry>(code_object_address)
        );

        cleanup_staging_area_internal();
    }

    /// Cleans up the staging area, removing any staged code chunks.
    /// This function can be called to reset the staging area without publishing or upgrading.
    public entry fun cleanup_staging_area(caller: &signer) acquires StagingArea {
        mcms_account::assert_is_owner(caller);

        cleanup_staging_area_internal();
    }

    inline fun stage_code_chunk_internal(
        metadata_chunk: vector<u8>,
        code_indices: vector<u16>,
        code_chunks: vector<vector<u8>>
    ): &mut StagingArea {
        assert!(
            code_indices.length() == code_chunks.length(),
            error::invalid_argument(E_CODE_MISMATCH)
        );

        if (!exists<StagingArea>(@mcms)) {
            move_to(
                &mcms_account::get_signer(),
                StagingArea {
                    metadata_serialized: vector[],
                    code: smart_table::new(),
                    last_module_idx: 0
                }
            );
        };

        let staging_area = borrow_global_mut<StagingArea>(@mcms);

        if (!metadata_chunk.is_empty()) {
            staging_area.metadata_serialized.append(metadata_chunk);
        };

        for (i in 0..code_chunks.length()) {
            let inner_code = code_chunks[i];
            let idx = (code_indices[i] as u64);

            if (staging_area.code.contains(idx)) {
                staging_area.code.borrow_mut(idx).append(inner_code);
            } else {
                staging_area.code.add(idx, inner_code);
                if (idx > staging_area.last_module_idx) {
                    staging_area.last_module_idx = idx;
                }
            };
        };

        staging_area
    }

    inline fun assemble_module_code(staging_area: &mut StagingArea): vector<vector<u8>> {
        let last_module_idx = staging_area.last_module_idx;
        let code = vector[];
        for (i in 0..(last_module_idx + 1)) {
            code.push_back(*staging_area.code.borrow(i));
        };
        code
    }

    inline fun cleanup_staging_area_internal() {
        let StagingArea { metadata_serialized: _, code, last_module_idx: _ } =
            move_from<StagingArea>(@mcms);
        code.destroy();
    }
}
