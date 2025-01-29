{
  stdenv,
  pkgs,
  lib,
  fetchzip,
  autoPatchelfHook,
}:
stdenv.mkDerivation rec {
  name = "aptos-${version}";
  version = "6.0.2";

  src = fetchzip {
    url = "https://github.com/aptos-labs/aptos-core/releases/download/aptos-cli-v${version}/aptos-cli-${version}-Ubuntu-22.04-x86_64.zip";
    sha256 = "sha256-k2E53j3dvqNwFJrpVvjcSXEqAD6Nu4bzuMJTWWBupBU=";
  };

  nativeBuildInputs = [
    autoPatchelfHook
  ];

  buildInputs = with pkgs; [openssl cacert libudev-zero stdenv.cc.cc.libgcc stdenv.cc.cc.lib];

  sourceRoot = ".";

  installPhase = ''
    mkdir -p $out/bin
    mv source/aptos $out/bin
  '';
}
