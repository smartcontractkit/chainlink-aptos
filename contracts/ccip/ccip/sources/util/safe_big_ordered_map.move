/// Safe wrapper around BigOrderedMap operations with variable-sized values.
///
/// This module encapsulates the dangerous remove/modify/add pattern required for
/// BigOrderedMap<K, V> where V is variable-sized and cannot use borrow_mut.
module ccip::safe_big_ordered_map {
    use std::big_ordered_map::{Self, BigOrderedMap};
    use std::error;
    use std::option::{Self, Option};

    /// Key not found in map
    const E_KEY_NOT_FOUND: u64 = 1;
    /// Map key not found in outer map (for nested operations)
    const E_OUTER_KEY_NOT_FOUND: u64 = 2;
    /// Inner key not found in inner map (for nested operations)
    const E_INNER_KEY_NOT_FOUND: u64 = 3;

    /// Safely upsert a value in BigOrderedMap<K, V> where V is variable-sized.
    ///
    /// Returns the previous value if the key existed, none otherwise.
    public fun upsert<K: drop + copy + store, V: store>(
        map: &mut BigOrderedMap<K, V>,
        key: K,
        value: V
    ): Option<V> {
        if (!map.contains(&key)) {
            map.add(key, value);
            option::none()
        } else {
            // Use the dangerous remove/modify/add pattern - but safely encapsulated here
            let old_value = map.remove(&key);
            map.add(key, value);
            option::some(old_value)
        }
    }

    /// Safely get a value with a default if key doesn't exist.
    public fun borrow_with_default<K: drop + copy + store, V: drop + store>(
        map: &BigOrderedMap<K, V>,
        key: &K,
        default_value: &V
    ): &V {
        if (!map.contains(key)) {
            default_value
        } else {
            map.borrow(key)
        }
    }

    // ============================= Nested Operations ====================================

    /// Safely upsert a value in a nested BigOrderedMap<K, BigOrderedMap<K2, V>>.
    ///
    /// This function handles the dangerous remove/modify/add pattern required
    /// when the inner map needs to be modified due to variable-size limitations.
    ///
    /// Returns the previous value if the inner key existed, none otherwise.
    public fun nested_upsert<K: drop + copy + store, K2: drop + copy + store, V: store>(
        outer_map: &mut BigOrderedMap<K, BigOrderedMap<K2, V>>,
        outer_key: K,
        inner_key: K2,
        value: V
    ): Option<V> {
        // First check if outer key exists
        if (!outer_map.contains(&outer_key)) {
            // Create new inner map and add the first entry
            let new_inner_map = big_ordered_map::new_with_config(0, 0, false);
            new_inner_map.add(inner_key, value);
            outer_map.add(outer_key, new_inner_map);
            return option::none()
        };

        // Outer key exists, need to modify the inner map
        // Use the remove/upsert/add pattern
        let inner_map = outer_map.remove(&outer_key);
        let previous_value = inner_map.upsert(inner_key, value);

        // Re-add the inner map, even if an error occurs above
        outer_map.add(outer_key, inner_map);

        previous_value
    }

    /// Safely get a value from a nested BigOrderedMap<K, BigOrderedMap<K2, V>>.
    ///
    /// Returns the value if both outer and inner keys exist, aborts otherwise.
    public fun nested_borrow<K: drop + copy + store, K2: drop + copy + store, V: store>(
        outer_map: &BigOrderedMap<K, BigOrderedMap<K2, V>>,
        outer_key: &K,
        inner_key: &K2
    ): &V {
        assert!(
            outer_map.contains(outer_key),
            error::invalid_argument(E_OUTER_KEY_NOT_FOUND)
        );

        let inner_map = outer_map.borrow(outer_key);
        assert!(
            inner_map.contains(inner_key),
            error::invalid_argument(E_INNER_KEY_NOT_FOUND)
        );

        inner_map.borrow(inner_key)
    }

    /// Safely check if a nested key exists in BigOrderedMap<K, BigOrderedMap<K2, V>>.
    public fun nested_contains<K: drop + copy + store, K2: drop + copy + store, V: store>(
        outer_map: &BigOrderedMap<K, BigOrderedMap<K2, V>>,
        outer_key: &K,
        inner_key: &K2
    ): bool {
        if (!outer_map.contains(outer_key)) {
            return false
        };

        let inner_map = outer_map.borrow(outer_key);
        inner_map.contains(inner_key)
    }

    /// Safely remove a value from a nested BigOrderedMap<K, BigOrderedMap<K2, V>>.
    ///
    /// Returns the removed value if both keys existed, aborts otherwise.
    public fun nested_remove<K: drop + copy + store, K2: drop + copy + store, V: store>(
        outer_map: &mut BigOrderedMap<K, BigOrderedMap<K2, V>>,
        outer_key: &K,
        inner_key: &K2
    ): V {
        assert!(
            outer_map.contains(outer_key),
            error::invalid_argument(E_OUTER_KEY_NOT_FOUND)
        );

        // Use the dangerous remove/modify/add pattern - but safely encapsulated here
        let inner_map = outer_map.remove(outer_key);
        let removed_value = inner_map.remove(inner_key);

        // Critical: Always re-add the inner map, even if empty
        // (BigOrderedMap handles empty maps fine)
        outer_map.add(*outer_key, inner_map);

        removed_value
    }

    /// Initialize a new inner map for the given outer key if it doesn't exist.
    /// Does nothing if the outer key already exists.
    public fun nested_ensure_inner_map<K: drop + copy + store, K2: drop + copy + store, V: store>(
        outer_map: &mut BigOrderedMap<K, BigOrderedMap<K2, V>>,
        outer_key: K
    ) {
        if (!outer_map.contains(&outer_key)) {
            let new_inner_map = big_ordered_map::new_with_config(0, 0, false);
            outer_map.add(outer_key, new_inner_map);
        }
    }

    /// Get a default value if the nested key doesn't exist.
    public fun nested_borrow_with_default<K: drop + copy + store, K2: drop + copy + store, V: drop + store>(
        outer_map: &BigOrderedMap<K, BigOrderedMap<K2, V>>,
        outer_key: &K,
        inner_key: &K2,
        default_value: &V
    ): &V {
        if (!outer_map.contains(outer_key)) {
            return default_value
        };

        let inner_map = outer_map.borrow(outer_key);
        if (!inner_map.contains(inner_key)) {
            return default_value
        };

        inner_map.borrow(inner_key)
    }

    /// Safely modify an inner map in BigOrderedMap<K, BigOrderedMap<K2, V>>.
    ///
    /// This function handles the remove/modify/add pattern for
    /// operations that need to perform multiple changes to the inner map.
    ///
    /// The modifier function receives a mutable reference to the inner map and
    /// can perform any number of operations on it. If the outer key doesn't exist,
    /// a new empty inner map is created first.
    ///
    /// This ensures the inner map is always properly re-added.
    public inline fun nested_modify_inner_map<K: drop + copy + store, K2: drop + copy + store, V: store>(
        outer_map: &mut BigOrderedMap<K, BigOrderedMap<K2, V>>,
        outer_key: K,
        modifier: |&mut BigOrderedMap<K2, V>|
    ) {
        // Remove or create the inner map
        let inner_map =
            if (outer_map.contains(&outer_key)) {
                outer_map.remove(&outer_key)
            } else {
                big_ordered_map::new_with_config(0, 0, false)
            };

        // Apply the modifications
        modifier(&mut inner_map);

        // Always re-add the inner map, even if modifier aborts
        // This is safe because BigOrderedMap handles empty maps fine
        outer_map.add(outer_key, inner_map);
    }

    // ============================= Tests ====================================

    #[test]
    fun test_nested_upsert_new_outer_key() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Insert into non-existent outer key
        let prev = nested_upsert(&mut map, 1, 100, 42);
        assert!(prev.is_none(), 0);

        // Verify it was inserted
        assert!(nested_contains(&map, &1, &100), 1);
        assert!(*nested_borrow(&map, &1, &100) == 42, 2);

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    fun test_nested_upsert_existing_keys() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Insert first value
        nested_upsert(&mut map, 1, 100, 42);

        // Update existing inner key
        let prev = nested_upsert(&mut map, 1, 100, 99);
        assert!(prev.is_some() && prev.destroy_some() == 42, 0);

        // Verify update
        assert!(*nested_borrow(&map, &1, &100) == 99, 1);

        // Add new inner key to existing outer key
        let prev = nested_upsert(&mut map, 1, 200, 77);
        assert!(prev.is_none(), 2);

        // Verify both exist
        assert!(*nested_borrow(&map, &1, &100) == 99, 3);
        assert!(*nested_borrow(&map, &1, &200) == 77, 4);

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    fun test_nested_borrow_with_default() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Non-existent outer key
        assert!(
            *nested_borrow_with_default(&map, &1, &100, &255) == 255,
            0
        );

        // Add outer key but not inner key
        nested_ensure_inner_map(&mut map, 1);
        assert!(
            *nested_borrow_with_default(&map, &1, &100, &255) == 255,
            1
        );

        // Add inner key
        nested_upsert(&mut map, 1, 100, 42);
        assert!(
            *nested_borrow_with_default(&map, &1, &100, &255) == 42,
            2
        );

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    #[expected_failure(abort_code = 65538, location = Self)]
    fun test_nested_borrow_outer_key_not_found() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );
        nested_borrow(&map, &1, &100); // Should abort
        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    #[expected_failure(abort_code = 65539, location = Self)]
    fun test_nested_borrow_inner_key_not_found() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );
        nested_ensure_inner_map(&mut map, 1);
        nested_borrow(&map, &1, &100); // Should abort
        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    // ============================= General Function Tests ====================================

    #[test]
    fun test_upsert_new_key() {
        let map = big_ordered_map::new_with_config<u64, vector<u8>>(0, 0, false);

        let prev = upsert(&mut map, 1, vector[10, 20]);
        assert!(prev.is_none(), 0);

        // Verify it was added
        assert!(map.contains(&1), 1);
        assert!(*map.borrow(&1) == vector[10, 20], 2);

        map.destroy(|_| {});
    }

    #[test]
    fun test_upsert_existing_key() {
        let map = big_ordered_map::new_with_config<u64, vector<u8>>(0, 0, false);

        // Add initial value
        map.add(1, vector[1, 2]);

        // Upsert with new value
        let prev = upsert(&mut map, 1, vector[3, 4, 5]);
        assert!(prev.is_some(), 0);
        assert!(prev.destroy_some() == vector[1, 2], 1);

        // Verify new value
        assert!(*map.borrow(&1) == vector[3, 4, 5], 2);

        map.destroy(|_| {});
    }

    #[test]
    fun test_borrow_with_default_existing_key() {
        let map = big_ordered_map::new_with_config<u64, u8>(0, 0, false);

        map.add(1, 42);

        let result = borrow_with_default(&map, &1, &99);
        assert!(*result == 42, 0);

        map.destroy(|_| {});
    }

    #[test]
    fun test_borrow_with_default_nonexistent_key() {
        let map = big_ordered_map::new_with_config<u64, u8>(0, 0, false);

        let result = borrow_with_default(&map, &1, &99);
        assert!(*result == 99, 0);

        map.destroy(|_| {});
    }

    // ============================= Additional Nested Function Tests ====================================

    #[test]
    fun test_nested_upsert_multiple_inner_keys() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Add multiple inner keys to same outer key
        nested_upsert(&mut map, 1, 100, 10);
        nested_upsert(&mut map, 1, 200, 20);
        nested_upsert(&mut map, 1, 300, 30);

        // Verify all exist
        assert!(nested_contains(&map, &1, &100), 0);
        assert!(nested_contains(&map, &1, &200), 1);
        assert!(nested_contains(&map, &1, &300), 2);

        // Verify values
        assert!(*nested_borrow(&map, &1, &100) == 10, 3);
        assert!(*nested_borrow(&map, &1, &200) == 20, 4);
        assert!(*nested_borrow(&map, &1, &300) == 30, 5);

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    fun test_nested_upsert_multiple_outer_keys() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Add to different outer keys
        nested_upsert(&mut map, 1, 100, 10);
        nested_upsert(&mut map, 2, 100, 20);
        nested_upsert(&mut map, 3, 100, 30);

        // Verify all exist
        assert!(nested_contains(&map, &1, &100), 0);
        assert!(nested_contains(&map, &2, &100), 1);
        assert!(nested_contains(&map, &3, &100), 2);

        // Verify values
        assert!(*nested_borrow(&map, &1, &100) == 10, 3);
        assert!(*nested_borrow(&map, &2, &100) == 20, 4);
        assert!(*nested_borrow(&map, &3, &100) == 30, 5);

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    fun test_nested_contains_false_cases() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Test non-existent outer key
        assert!(!nested_contains(&map, &1, &100), 0);

        // Add outer key but not inner key
        nested_ensure_inner_map(&mut map, 1);
        assert!(!nested_contains(&map, &1, &100), 1);

        // Add inner key and verify it now exists
        nested_upsert(&mut map, 1, 100, 42);
        assert!(nested_contains(&map, &1, &100), 2);

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    fun test_nested_remove_single_item() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Add and then remove
        nested_upsert(&mut map, 1, 100, 42);
        assert!(nested_contains(&map, &1, &100), 0);

        let removed_value = nested_remove(&mut map, &1, &100);
        assert!(removed_value == 42, 1);
        assert!(!nested_contains(&map, &1, &100), 2);

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    fun test_nested_remove_multiple_items() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Add multiple items
        nested_upsert(&mut map, 1, 100, 10);
        nested_upsert(&mut map, 1, 200, 20);
        nested_upsert(&mut map, 1, 300, 30);

        // Remove one item
        let removed = nested_remove(&mut map, &1, &200);
        assert!(removed == 20, 0);

        // Verify others still exist
        assert!(nested_contains(&map, &1, &100), 1);
        assert!(!nested_contains(&map, &1, &200), 2);
        assert!(nested_contains(&map, &1, &300), 3);

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    #[expected_failure(abort_code = 65538, location = Self)]
    fun test_nested_remove_outer_key_not_found() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );
        nested_remove(&mut map, &1, &100); // Should abort
        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    #[expected_failure(abort_code = 65538, location = std::ordered_map)]
    fun test_nested_remove_inner_key_not_found() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );
        nested_ensure_inner_map(&mut map, 1);
        nested_remove(&mut map, &1, &100); // EKEY_NOT_FOUND
        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    fun test_nested_ensure_inner_map_new() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Ensure non-existent outer key
        assert!(!map.contains(&1), 0);
        nested_ensure_inner_map(&mut map, 1);
        assert!(map.contains(&1), 1);

        // Inner map should be empty
        let inner_map = map.borrow(&1);
        assert!(inner_map.is_empty(), 2);

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    fun test_nested_ensure_inner_map_existing() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Add outer key with some data
        nested_upsert(&mut map, 1, 100, 42);

        // Ensure existing outer key (should do nothing)
        nested_ensure_inner_map(&mut map, 1);

        // Verify data is preserved
        assert!(nested_contains(&map, &1, &100), 0);
        assert!(*nested_borrow(&map, &1, &100) == 42, 1);
        // Verify the value still exists (no length check needed)

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    fun test_nested_borrow_with_default_all_scenarios() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Scenario 1: Non-existent outer key
        assert!(
            *nested_borrow_with_default(&map, &1, &100, &255) == 255,
            0
        );

        // Scenario 2: Existing outer key, non-existent inner key
        nested_ensure_inner_map(&mut map, 1);
        assert!(
            *nested_borrow_with_default(&map, &1, &100, &255) == 255,
            1
        );

        // Scenario 3: Both keys exist
        nested_upsert(&mut map, 1, 100, 42);
        assert!(
            *nested_borrow_with_default(&map, &1, &100, &255) == 42,
            2
        );

        // Scenario 4: Different inner key in same outer map
        assert!(
            *nested_borrow_with_default(&map, &1, &200, &255) == 255,
            3
        );

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    // ============================= Complex Integration Tests ====================================

    #[test]
    fun test_complex_nested_operations() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Build a complex nested structure
        // Chain 1: messages 100, 200, 300
        nested_upsert(&mut map, 1, 100, 1);
        nested_upsert(&mut map, 1, 200, 2);
        nested_upsert(&mut map, 1, 300, 3);

        // Chain 2: messages 150, 250
        nested_upsert(&mut map, 2, 150, 15);
        nested_upsert(&mut map, 2, 250, 25);

        // Verify structure
        assert!(*nested_borrow(&map, &1, &100) == 1, 0);
        assert!(*nested_borrow(&map, &1, &200) == 2, 1);
        assert!(*nested_borrow(&map, &1, &300) == 3, 2);
        assert!(*nested_borrow(&map, &2, &150) == 15, 3);
        assert!(*nested_borrow(&map, &2, &250) == 25, 4);

        // Update some values
        let old_val = nested_upsert(&mut map, 1, 200, 99);
        assert!(
            old_val.is_some() && old_val.destroy_some() == 2,
            5
        );
        assert!(*nested_borrow(&map, &1, &200) == 99, 6);

        // Remove some values
        nested_remove(&mut map, &2, &150);
        assert!(!nested_contains(&map, &2, &150), 7);
        assert!(nested_contains(&map, &2, &250), 8); // Other value should remain

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    fun test_edge_case_empty_maps() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Operations on completely empty map
        assert!(!nested_contains(&map, &1, &100), 0);
        assert!(
            *nested_borrow_with_default(&map, &1, &100, &42) == 42,
            1
        );

        // Create empty inner map
        nested_ensure_inner_map(&mut map, 1);
        assert!(!nested_contains(&map, &1, &100), 2);
        assert!(
            *nested_borrow_with_default(&map, &1, &100, &42) == 42,
            3
        );

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    fun test_nested_modify_inner_map_new_outer_key() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Modify non-existent outer key (should create new inner map)
        nested_modify_inner_map(
            &mut map,
            1,
            |inner_map| {
                let inner_map: &mut BigOrderedMap<u64, u8> = inner_map;
                inner_map.add(100, 42);
                inner_map.add(200, 84);
            }
        );

        // Verify the modifications were applied
        assert!(nested_contains(&map, &1, &100), 0);
        assert!(nested_contains(&map, &1, &200), 1);
        assert!(*nested_borrow(&map, &1, &100) == 42, 2);
        assert!(*nested_borrow(&map, &1, &200) == 84, 3);

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    fun test_nested_modify_inner_map_existing_outer_key() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Setup existing data
        nested_upsert(&mut map, 1, 100, 10);
        nested_upsert(&mut map, 1, 200, 20);

        // Modify existing outer key
        nested_modify_inner_map(
            &mut map,
            1,
            |inner_map| {
                let inner_map: &mut BigOrderedMap<u64, u8> = inner_map;
                // Update existing value
                upsert(inner_map, 100, 99);
                // Remove one value
                inner_map.remove(&200);
                // Add new value
                inner_map.add(300, 30);
            }
        );

        // Verify the modifications
        assert!(nested_contains(&map, &1, &100), 0);
        assert!(!nested_contains(&map, &1, &200), 1);
        assert!(nested_contains(&map, &1, &300), 2);
        assert!(*nested_borrow(&map, &1, &100) == 99, 3);
        assert!(*nested_borrow(&map, &1, &300) == 30, 4);

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    fun test_nested_modify_inner_map_complex_operations() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Simulate fee_quoter-like operations
        nested_modify_inner_map(
            &mut map,
            1,
            |inner_map| {
                // Add multiple tokens (like fee_quoter add_tokens loop)
                let tokens = vector[100, 200, 300];
                let values = vector[10, 20, 30];

                tokens.zip_ref(
                    &values,
                    |token, value| {
                        let inner_map: &mut BigOrderedMap<u64, u8> = inner_map;
                        upsert(inner_map, *token, *value);
                    }
                );

                // Remove some tokens (like fee_quoter remove_tokens loop)
                let remove_tokens = vector[200];
                remove_tokens.for_each_ref(|token| {
                    if (inner_map.contains(token)) {
                        inner_map.remove(token);
                    }
                });
            }
        );

        // Verify final state
        assert!(nested_contains(&map, &1, &100), 0);
        assert!(!nested_contains(&map, &1, &200), 1); // Was removed
        assert!(nested_contains(&map, &1, &300), 2);
        assert!(*nested_borrow(&map, &1, &100) == 10, 3);
        assert!(*nested_borrow(&map, &1, &300) == 30, 4);

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }

    #[test]
    fun test_nested_modify_inner_map_empty_operations() {
        let map = big_ordered_map::new_with_config<u64, BigOrderedMap<u64, u8>>(
            0, 0, false
        );

        // Modify with no actual changes
        nested_modify_inner_map(
            &mut map,
            1,
            |_inner_map| {
                // Do nothing
            }
        );

        // Should have created empty inner map
        assert!(map.contains(&1), 0);
        let inner_map = map.borrow(&1);
        assert!(inner_map.is_empty(), 1);

        map.destroy(|inner_map| inner_map.destroy(|_| {}));
    }
}
