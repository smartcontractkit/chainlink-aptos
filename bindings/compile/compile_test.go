package compile

import "testing"

func TestFirstAptosImageFromOutput(t *testing.T) {
	t.Run("returns first aptos image from docker ps output", func(t *testing.T) {
		output := "postgres:15\naptoslabs/tools:aptos-node-v1.41.5\nbusybox:latest\n"

		got := firstAptosImageFromOutput(output)

		if got != "aptoslabs/tools:aptos-node-v1.41.5" {
			t.Fatalf("expected aptos image, got %q", got)
		}
	})

	t.Run("supports unofficial arm image names", func(t *testing.T) {
		output := "ghcr.io/friedemannf/aptos-tools:aptos-node-v1.41.5\n"

		got := firstAptosImageFromOutput(output)

		if got != "ghcr.io/friedemannf/aptos-tools:aptos-node-v1.41.5" {
			t.Fatalf("expected unofficial aptos image, got %q", got)
		}
	})

	t.Run("returns empty string when output has no aptos image", func(t *testing.T) {
		output := "postgres:15\nbusybox:latest\n"

		got := firstAptosImageFromOutput(output)

		if got != "" {
			t.Fatalf("expected empty image, got %q", got)
		}
	})
}
