{ stdenv, pkgs, lib
, fetchzip, autoPatchelfHook
}:

stdenv.mkDerivation rec {
  name = "aptos-${version}";
  version = "3.5.0";

  src = fetchzip {
    url = "https://github.com/aptos-labs/aptos-core/releases/download/aptos-cli-v${version}/aptos-cli-${version}-Ubuntu-22.04-x86_64.zip";
    sha256 = "sha256-BW516fZvyw4tnFi6jFeSlXEhcUJy7eGLvhKT5hNxX34=";
  };

  nativeBuildInputs = [
    autoPatchelfHook
  ];

  buildInputs = with pkgs; [ openssl cacert libudev-zero stdenv.cc.cc.libgcc stdenv.cc.cc.lib ];

  sourceRoot = ".";

  installPhase = ''
    mkdir -p $out/bin
    mv source/aptos $out/bin
  '';
}
