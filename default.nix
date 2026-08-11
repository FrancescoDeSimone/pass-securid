{ lib
, stdenv
, bash
, python3
}:

stdenv.mkDerivation {
  pname = "pass-securid";
  version = "1.0.0";
  src = ./.;

  dontBuild = true;

  buildInputs = [ python3 ];

  # Embed the absolute path to python3 so the engine is found even though the
  # pass wrapper only carries a fixed PATH (mirrors how pass-otp patches
  # oathtool into its script).
  patchPhase = ''
    sed -i -e 's|SECURID_PYTHON=''${PASSWORD_STORE_SECURID_PYTHON:-python3}|SECURID_PYTHON=${python3}/bin/python3|' securid.bash
  '';

  installFlags = [
    "PREFIX=$(out)"
    "BASHCOMPDIR=$(out)/share/bash-completions/completions"
  ];

  meta = with lib; {
    description = "A pass extension for managing RSA SecurID software tokens";
    homepage = "https://www.passwordstore.org/";
    license = licenses.gpl3Plus;
    platforms = platforms.unix;
    mainProgram = "pass";
  };
}
