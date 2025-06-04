package utils

import (
	"reflect"
	"testing"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/config"
)

// TestRenameFields contains multiple sub-tests to verify the behavior
// of renameMapFields under different conditions.
func TestRenameFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		jsonData map[string]any
		renames  map[string]config.RenamedField
		expected map[string]any // expected result after renameMapFields is applied
		wantErr  bool
		errMsg   string // expected error message (if any)
	}{
		{
			name:     "nil renames",
			jsonData: map[string]any{"a": 1, "b": "test"},
			renames:  nil,
			expected: map[string]any{"a": 1, "b": "test"},
			wantErr:  false,
		},
		{
			name:     "simple rename",
			jsonData: map[string]any{"a": 123, "b": "stuff"},
			renames: map[string]config.RenamedField{
				"a": {NewName: "alpha", SubFieldRenames: nil},
			},
			expected: map[string]any{"alpha": 123, "b": "stuff"},
			wantErr:  false,
		},
		{
			name:     "non-existing field",
			jsonData: map[string]any{"a": 1, "b": 2},
			renames: map[string]config.RenamedField{
				"c": {NewName: "gamma", SubFieldRenames: nil},
			},
			expected: nil,
			wantErr:  true,
			errMsg:   "no such field: c",
		},
		{
			name:     "empty renames",
			jsonData: map[string]any{"a": 1, "b": 2},
			renames:  map[string]config.RenamedField{},
			expected: map[string]any{"a": 1, "b": 2},
			wantErr:  false,
		},
		{
			name: "nested rename",
			jsonData: map[string]any{
				"a": map[string]any{"x": 1, "y": 2},
				"b": "hello",
			},
			renames: map[string]config.RenamedField{
				"a": {
					NewName: "alpha",
					SubFieldRenames: map[string]config.RenamedField{
						"x": {NewName: "x_new", SubFieldRenames: nil},
					},
				},
			},
			expected: map[string]any{
				"alpha": map[string]any{"x_new": 1, "y": 2},
				"b":     "hello",
			},
			wantErr: false,
		},
		{
			name:     "subfield non-map error (top-level)",
			jsonData: map[string]any{"a": "not a map"},
			renames: map[string]config.RenamedField{
				"a": {
					NewName: "alpha",
					SubFieldRenames: map[string]config.RenamedField{
						"x": {NewName: "x_new", SubFieldRenames: nil},
					},
				},
			},
			// an error should be returned because field "a" is not a map
			expected: nil,
			wantErr:  true,
			errMsg:   "sub field renames failed for field a: sub field renames provided but value is not a map or slice of maps: string",
		},
		{
			name: "nested subfield non-map error",
			jsonData: map[string]any{
				"a": map[string]any{"x": 100},
			},
			renames: map[string]config.RenamedField{
				"a": {
					NewName: "alpha",
					SubFieldRenames: map[string]config.RenamedField{
						"x": {
							NewName: "x_new",
							SubFieldRenames: map[string]config.RenamedField{
								"inner": {NewName: "inner_new", SubFieldRenames: nil},
							},
						},
					},
				},
			},
			// here the renaming for field "x" should cause an error because 100 is not a map.
			expected: nil,
			wantErr:  true,
			errMsg:   "sub field renames failed for field a: sub field renames failed for field x: sub field renames provided but value is not a map or slice of maps: int",
		},
		{
			name: "array of structs rename",
			jsonData: map[string]any{
				"items": []any{
					map[string]any{"id": 1, "name": "item1"},
					map[string]any{"id": 2, "name": "item2"},
				},
			},
			renames: map[string]config.RenamedField{
				"items": {
					NewName: "elements",
					SubFieldRenames: map[string]config.RenamedField{
						"id":   {NewName: "itemId", SubFieldRenames: nil},
						"name": {NewName: "itemName", SubFieldRenames: nil},
					},
				},
			},
			expected: map[string]any{
				"elements": []any{
					map[string]any{"itemId": 1, "itemName": "item1"},
					map[string]any{"itemId": 2, "itemName": "item2"},
				},
			},
			wantErr: false,
		},
		{
			name: "empty array of structs",
			jsonData: map[string]any{
				"items": []any{},
			},
			renames: map[string]config.RenamedField{
				"items": {
					NewName: "elements",
					SubFieldRenames: map[string]config.RenamedField{
						"id": {NewName: "itemId", SubFieldRenames: nil},
					},
				},
			},
			expected: map[string]any{
				"elements": []any{},
			},
			wantErr: false,
		},
		{
			name: "nested arrays of structs",
			jsonData: map[string]any{
				"parent": map[string]any{
					"children": []any{
						map[string]any{
							"childId": 1,
							"details": map[string]any{"age": 5, "grade": "A"},
						},
						map[string]any{
							"childId": 2,
							"details": map[string]any{"age": 7, "grade": "B"},
						},
					},
				},
			},
			renames: map[string]config.RenamedField{
				"parent": {
					NewName: "family",
					SubFieldRenames: map[string]config.RenamedField{
						"children": {
							NewName: "kids",
							SubFieldRenames: map[string]config.RenamedField{
								"childId": {NewName: "id", SubFieldRenames: nil},
								"details": {
									NewName: "info",
									SubFieldRenames: map[string]config.RenamedField{
										"grade": {NewName: "level", SubFieldRenames: nil},
									},
								},
							},
						},
					},
				},
			},
			expected: map[string]any{
				"family": map[string]any{
					"kids": []any{
						map[string]any{
							"id":   1,
							"info": map[string]any{"age": 5, "level": "A"},
						},
						map[string]any{
							"id":   2,
							"info": map[string]any{"age": 7, "level": "B"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "array with non-map elements",
			jsonData: map[string]any{
				"items": []any{1, 2, 3},
			},
			renames: map[string]config.RenamedField{
				"items": {
					NewName: "numbers",
					SubFieldRenames: map[string]config.RenamedField{
						"value": {NewName: "val", SubFieldRenames: nil},
					},
				},
			},
			expected: nil,
			wantErr:  true,
			errMsg:   "sub field renames failed for field items: sub field renames provided but array element at index 0 is not a map: int",
		},
		{
			name: "mixed array elements",
			jsonData: map[string]any{
				"items": []any{
					map[string]any{"id": 1},
					"not a map",
				},
			},
			renames: map[string]config.RenamedField{
				"items": {
					NewName: "elements",
					SubFieldRenames: map[string]config.RenamedField{
						"id": {NewName: "itemId", SubFieldRenames: nil},
					},
				},
			},
			expected: nil,
			wantErr:  true,
			errMsg:   "sub field renames failed for field items: sub field renames provided but array element at index 1 is not a map: string",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := RenameMapFields(tc.jsonData, tc.renames)
			if tc.wantErr {
				if err == nil {
					t.Errorf("%q: expected error but got nil", tc.name)
				} else if err.Error() != tc.errMsg {
					t.Errorf("%q: expected error message %q; got %q", tc.name, tc.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("%q: unexpected error: %v", tc.name, err)
				} else if !reflect.DeepEqual(tc.jsonData, tc.expected) {
					t.Errorf("%q: expected result %v; got %v", tc.name, tc.expected, tc.jsonData)
				}
			}
		})
	}
}
