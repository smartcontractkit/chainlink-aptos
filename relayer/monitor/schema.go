package monitor

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/runtime/protoimpl"
)

const (
	AttrKeyBeholderDataSchema = "beholder_data_schema"
	AttrKeyBeholderDataType   = "beholder_data_type"
)

// toSneakCase converts a CamelCase to snake_case (used for type -> file name mapping)
func toSneakCase(s string) string {
	// \p{Lu} matches all charaters in the unicode class for uppercase letters
	pattern := regexp.MustCompile("(\\p{Lu}+\\P{Lu}*)")
	s = pattern.ReplaceAllString(s, "_${1}")
	s, _ = strings.CutPrefix(strings.ToLower(s), "_")
	return s
}

// toSchemaName returns a protobuf message full name
func toSchemaName(m proto.Message) string {
	return string(protoimpl.X.MessageTypeOf(m).Descriptor().FullName())
}

// toSchemaPath maps a protobuf message to a Beholder schema path
func toSchemaPath(m proto.Message, basePath string) (string, error) {
	// Notice: a name like 'keystone.on_chain.forwarder.ReportProcessed'
	protoName := toSchemaName(m)

	// We map to a Beholder schema path like '<basePath>/keystone/on-chain/forwarder/report_processed.proto'
	protoPath := protoName
	protoPath = strings.ReplaceAll(protoPath, ".", "/")
	protoPath = strings.ReplaceAll(protoPath, "_", "-")

	// Split the path and convert the last component to snake_case
	pp := strings.Split(protoPath, "/")
	if len(pp) == 0 {
		return "", fmt.Errorf("invalid proto path: %s", protoPath)
	}
	pp[len(pp)-1] = toSneakCase(pp[len(pp)-1])

	// Join the path components again
	protoPath = strings.Join(pp, "/")
	protoPath = fmt.Sprintf("%s.proto", protoPath)

	// Return the full schema path
	return path.Join(basePath, protoPath), nil
}

// Add the message type as an attribute (required)
func appendSchemaIfMissing(m proto.Message, attrKVs []any, basePath string) ([]any, error) {
	key := AttrKeyBeholderDataSchema
	hasSchema := false
	for i := 0; i < len(attrKVs); i += 2 {
		if attrKVs[i] == key {
			hasSchema = true
			break
		}
	}

	if !hasSchema {
		attrKVs = append(attrKVs, key)
		// Needs to be an URI (Beholder requirement)
		val, err := toSchemaPath(m, basePath)
		if err != nil {
			return nil, fmt.Errorf("failed to map to schema path: %w", err)
		}
		attrKVs = append(attrKVs, val)

		// Add the message type as an attribute (optional)
		key = AttrKeyBeholderDataType
		attrKVs = append(attrKVs, key)
		attrKVs = append(attrKVs, toSchemaName(m))
	}

	return attrKVs, nil
}

// appendSchemaUnknown adds an unknown schema path to the attributes
func appendSchemaUnknown(attrKVs []any, basePath string) []any {
	key := AttrKeyBeholderDataSchema
	attrKVs = append(attrKVs, key)
	attrKVs = append(attrKVs, path.Join(basePath, "unknown.proto"))

	// Add the message type as an attribute (optional)
	key = AttrKeyBeholderDataType
	attrKVs = append(attrKVs, key)
	attrKVs = append(attrKVs, "unknown")
	return attrKVs
}
