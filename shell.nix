{
  stdenv,
  pkgs,
  lib,
}:
# juno requires building with clang, not gcc
(pkgs.mkShell.override {stdenv = pkgs.clangStdenv;}) {
  buildInputs = with pkgs;
    [
      # Go 1.23 + tools
      go_1_23
      gopls
      delve
      (golangci-lint.override {buildGoModule = buildGo122Module;})
      gotools
      # Official golang implementation of the Ethereum protocol (e.g., geth, abigen, rlpdump, etc.)
      go-ethereum

      # Protobuf + plugins/tools
      protobuf
      # Go support for Google's protocol buffers
      protoc-gen-go
      protolint

      # Atlas + Beholder tools
      redpanda

      # Extra tools
      python3
      postgresql_15
      jq
    ]
    ++ lib.optionals stdenv.isLinux [
      # Notice: currently only available on Linux, needs to be packaged for other platforms (e.g. macOS)
      (pkgs.callPackage ./aptos.nix {})
    ]
    ++ lib.optionals stdenv.hostPlatform.isDarwin [
      libiconv
    ];
}
