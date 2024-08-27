{
  stdenv,
  pkgs,
  lib,
}:
# juno requires building with clang, not gcc
(pkgs.mkShell.override {stdenv = pkgs.clangStdenv;}) {
  buildInputs = with pkgs;
    [
      python3

      go_1_22
      gopls
      delve
      (golangci-lint.override {buildGoModule = buildGo122Module;})
      gotools

      go-ethereum

      postgresql_15
      jq
    ]
    ++ lib.optionals stdenv.isLinux [
      # Notice: currently only available on Linux, needs to be packaged for other platforms (e.g. macOS)
      (pkgs.callPackage ./aptos.nix {})
    ];
}
