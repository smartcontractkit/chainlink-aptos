{ stdenv, pkgs, lib }:
# juno requires building with clang, not gcc
(pkgs.mkShell.override { stdenv = pkgs.clangStdenv; }) {
  buildInputs = with pkgs; [
    python3
    (pkgs.callPackage ./aptos.nix {})

    go_1_21
    gopls
    delve
    (golangci-lint.override { buildGoModule = buildGo121Module; })
    gotools
  ];
}
