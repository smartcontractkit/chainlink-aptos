package testutils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	TestnetUrl = "https://api.testnet.aptoslabs.com/v1"
	DevnetUrl  = "https://api.devnet.aptoslabs.com/v1"
)

// Finds the closest git repo root, assuming that a directory with a .git directory is a git repo.
func FindGitRoot() (string, error) {
	currentDir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		gitDir := filepath.Join(currentDir, ".git")
		if _, err := os.Stat(gitDir); err == nil {
			return currentDir, nil
		}

		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir {
			return "", fmt.Errorf("no Git repository found")
		}

		currentDir = parentDir
	}
}

func StartAptosNode() error {
	gitRoot, err := FindGitRoot()
	if err != nil {
		return fmt.Errorf("failed to find Git root: %v", err)
	}

	scriptPath := filepath.Join(gitRoot, "scripts/devnet.sh")
	cmd := exec.Command(scriptPath)

	output, err := cmd.CombinedOutput()

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			fmt.Printf("Failed to start devnet, dumping output:\n%s\n", string(output))
			return fmt.Errorf("Failed to start devnet, bad exit code: %v", exitError.ExitCode())
		}
		return fmt.Errorf("Failed to start devnet: %+v", err)
	}

	return nil
}
