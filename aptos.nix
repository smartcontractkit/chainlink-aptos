{
  stdenv,
  pkgs,
  lib,
  fetchzip,
  autoPatchelfHook,
}:
stdenv.mkDerivation rec {
  name = "aptos-${version}";
  version = "9.4.0";

  aptosPlatform =
    if stdenv.hostPlatform.isDarwin then
      "macOS-arm64" # Assume Apple Silicon; Intel Macs can use macOS-x86_64 if needed
    else
      "Ubuntu-22.04-x86_64";

  aptosHash =
    if stdenv.hostPlatform.isDarwin then
      "sha256-4UpwaVq0/OQGXvTp9SlgkJtD02c9ePk3IhqsMw9jF2k="
    else
      "sha256-lDZOykNy+xl9esXX9ZzOHtSBiQJ5JLW7h3P8HSH3Kr8=";

  src = fetchzip {
    name = "aptos-cli-${version}-${aptosPlatform}";
    url = "https://github.com/aptos-labs/aptos-core/releases/download/aptos-cli-v${version}/aptos-cli-${version}-${aptosPlatform}.zip";
    sha256 = aptosHash;
  };

  nativeBuildInputs = lib.optionals stdenv.isLinux [
    autoPatchelfHook
  ];

  buildInputs = with pkgs;
    lib.optionals stdenv.isLinux [
      openssl
      cacert
      libudev-zero
      stdenv.cc.cc.libgcc
      stdenv.cc.cc.lib
    ]
    ++ lib.optionals stdenv.hostPlatform.isDarwin [
      libiconv
    ];

  dontUnpack = true;

  installPhase = ''
    mkdir -p $out/bin
    cp $src/aptos $out/bin/
    chmod +x $out/bin/aptos
  '';
}
