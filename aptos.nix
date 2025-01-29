{
  stdenv,
  pkgs,
  lib,
  fetchzip,
  autoPatchelfHook,
}:
stdenv.mkDerivation rec {
  name = "aptos-${version}";
  version = "4.1.0";

  # Do we need to upgrade the CLI version to make the tests pass?
  # MISSING_DEPENDENCY (code 1021) error with error message: "Missing Native Function `move_range`".
  src = fetchzip {
    url = "https://github.com/aptos-labs/aptos-core/releases/download/aptos-cli-v${version}/aptos-cli-${version}-Ubuntu-22.04-x86_64.zip";
    sha256 = "sha256-8PTE/6kaq3dnU/bdgfofAQ8RN6otAoq7Vi4xXXP1Z8M=";
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
