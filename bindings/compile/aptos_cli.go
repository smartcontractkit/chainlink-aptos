package compile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const aptosCLIEnvVar = "APTOS_CLI"

// resolveAptosCLI returns the Aptos Labs CLI binary used for Move compilation.
// APTOS_CLI overrides PATH lookup when set.
func resolveAptosCLI() (string, error) {
	if cli := os.Getenv(aptosCLIEnvVar); cli != "" {
		if err := assertExecutable(cli); err != nil {
			return "", fmt.Errorf("%s=%q: %w", aptosCLIEnvVar, cli, err)
		}
		return cli, nil
	}

	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, "aptos")
		if !isAptosCLI(candidate) {
			continue
		}
		return candidate, nil
	}

	return "", fmt.Errorf(
		"aptos CLI not found on PATH; set %s to the binary path)",
		aptosCLIEnvVar,
	)
}

func assertExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("not an executable file")
	}
	return nil
}

func isAptosCLI(path string) bool {
	if err := assertExecutable(path); err != nil {
		return false
	}
	cmd := exec.Command(path, "move", "--help")
	return cmd.Run() == nil
}
