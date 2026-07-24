{
  stdenv,
  pkgs,
  lib,
}:
# juno requires building with clang, not gcc
(pkgs.mkShell.override {stdenv = pkgs.clangStdenv;}) {
  buildInputs = with pkgs;
    [
      go_1_26
      gopls
      delve
      # override to lock 1.64 version that is currently used by CI
      (golangci-lint.overrideAttrs (old: rec {
          version = "1.64.8";
          src = fetchFromGitHub {
            owner = "golangci";
            repo = "golangci-lint";
            rev = "v${version}";
            hash = "sha256-H7IdXAleyzJeDFviISitAVDNJmiwrMysYcGm6vAoWso=";
          };
         vendorHash = "sha256-i7ec4U4xXmRvHbsDiuBjbQ0xP7xRuilky3gi+dT1H10=";

         ldflags = [
             "-s"
             "-X main.version=${version}"
             "-X main.commit=v${version}"
             "-X main.date=19700101-00:00:00"
           ];
        }))
      gotools
      # Official golang implementation of the Ethereum protocol (e.g., geth, abigen, rlpdump, etc.)
      go-ethereum
      go-mockery

      # Protobuf + plugins/tools
      protobuf
      # Go support for Google's protocol buffers
      protoc-gen-go
      protolint

      # Extra tools
      python3
      postgresql_15
      jq
      git
      (pkgs.callPackage ./aptos.nix {})
    ]
    ++ lib.optionals stdenv.hostPlatform.isDarwin [
      libiconv
    ];
}
