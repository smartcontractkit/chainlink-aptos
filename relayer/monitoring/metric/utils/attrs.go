package utils

// GetTimestampLocal returns the timestamp_local attribute value from the given attribute key-values
func GetTimestampLocal(attrKVs []any) int64 {
	for i := 0; i < len(attrKVs); i += 2 {
		if key, ok := attrKVs[i].(string); ok && key == "timestamp_local" {
			if ts, ok := attrKVs[i+1].(int64); ok {
				return ts
			}
		}
	}
	return 0
}
