{ lib
, stdenv
, bash
}:

stdenv.mkDerivation {
  pname = "pass-securid";
  version = "1.0.0";
  src = ./.;

  dontBuild = true;

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
