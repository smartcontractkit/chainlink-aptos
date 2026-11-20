package cre

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestZones(t *testing.T) {
	zones, err := zonesOrAll(nil)
	require.NoError(t, err)
	require.Equal(t, []Zone{ZoneA, ZoneB}, zones)

	zones, err = zonesOrAll([]Zone{ZoneB})
	require.NoError(t, err)
	require.Equal(t, []Zone{ZoneB}, zones)

	_, err = zonesOrAll([]Zone{ZoneA, ZoneA})
	require.ErrorContains(t, err, "listed twice")
	_, err = zonesOrAll([]Zone{"zone-c"})
	require.ErrorContains(t, err, "invalid zone")

	require.Equal(t, "platform", ZoneA.PackageName())
	require.Equal(t, "platform_secondary", ZoneB.PackageName())
	require.Equal(t, "ChainlinkPlatformSecondary", ZoneB.onChainPackageName())
}

func TestDONValidation(t *testing.T) {
	require.ErrorContains(t, DON{F: 0, NodeIDs: []string{"a"}}.Validate(), "F must be greater than 0")
	require.ErrorContains(t, DON{F: 1}.Validate(), "node IDs are required")
	require.NoError(t, DON{F: 1, NodeIDs: []string{"a"}}.Validate())

	require.ErrorContains(t, validateSignerCount(1, 3), "at least 3F+1 = 4")
	require.NoError(t, validateSignerCount(1, 4))
	require.NoError(t, validateSignerCount(10, 31))
	require.ErrorContains(t, validateSignerCount(10, 32), "at most 31")
}

func TestQualifierDefault(t *testing.T) {
	require.Equal(t, DefaultQualifier, qualifierOrDefault(""))
	require.Equal(t, "other", qualifierOrDefault("other"))
}
