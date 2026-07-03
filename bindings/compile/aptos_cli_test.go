package compile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeFakeCLI(t *testing.T, dir, name string, script string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return path
}

func Test_resolveAptosCLI_APTOS_CLIOverride(t *testing.T) {
	dir := t.TempDir()
	cli := writeFakeCLI(t, dir, "aptos-labs", "#!/bin/sh\nexit 0\n")

	t.Setenv(aptosCLIEnvVar, cli)
	t.Setenv("PATH", "")

	got, err := resolveAptosCLI()
	require.NoError(t, err)
	require.Equal(t, cli, got)
}

func Test_resolveAptosCLI_APTOS_CLIOverride_missing(t *testing.T) {
	t.Setenv(aptosCLIEnvVar, filepath.Join(t.TempDir(), "missing"))
	t.Setenv("PATH", "")

	_, err := resolveAptosCLI()
	require.Error(t, err)
	require.Contains(t, err.Error(), aptosCLIEnvVar)
}

func Test_resolveAptosCLI_PATHPrefersLabsCLI(t *testing.T) {
	loopOnlyDir := t.TempDir()
	writeFakeCLI(t, loopOnlyDir, "aptos", "#!/bin/sh\nif [ \"$1\" = move ]; then exit 1; fi\nexit 0\n")
	labsAsAptosDir := t.TempDir()
	writeFakeCLI(t, labsAsAptosDir, "aptos", "#!/bin/sh\nif [ \"$1\" = move ] && [ \"$2\" = --help ]; then exit 0; fi\nexit 1\n")

	t.Setenv(aptosCLIEnvVar, "")
	t.Setenv("PATH", loopOnlyDir+string(filepath.ListSeparator)+labsAsAptosDir)

	got, err := resolveAptosCLI()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(labsAsAptosDir, "aptos"), got)
}

func Test_resolveAptosCLI_noValidCLI(t *testing.T) {
	dir := t.TempDir()
	writeFakeCLI(t, dir, "aptos", "#!/bin/sh\nexit 1\n")

	t.Setenv(aptosCLIEnvVar, "")
	t.Setenv("PATH", dir)

	_, err := resolveAptosCLI()
	require.Error(t, err)
	require.Contains(t, err.Error(), aptosCLIEnvVar)
}

func Test_isAptosLabsCLI(t *testing.T) {
	dir := t.TempDir()
	labs := writeFakeCLI(t, dir, "labs", "#!/bin/sh\nif [ \"$1\" = move ] && [ \"$2\" = --help ]; then exit 0; fi\nexit 1\n")
	loop := writeFakeCLI(t, dir, "loop", "#!/bin/sh\nif [ \"$1\" = move ]; then exit 1; fi\nexit 0\n")

	require.True(t, isAptosCLI(labs))
	require.False(t, isAptosCLI(loop))
	require.False(t, isAptosCLI(filepath.Join(dir, "missing")))
}
