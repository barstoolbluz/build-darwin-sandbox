{ lib
, buildGoModule
, fetchFromGitHub
}:

buildGoModule {
  pname = "sbx";
  version = "unstable-2026-04-13";

  src = fetchFromGitHub {
    owner = "syumai";
    repo = "sbx";
    rev = "46f080449bf56b42fc4dc3cadaa3eaaa17980596";
    hash = "sha256-WDSyvooRDXQXqLW/Jh6H/P7JHbzb3UktIw5EBW7Q0WI=";
  };

  vendorHash = "sha256-nciWOxAAnokVigB39tdikizvSEQ45YvgD7lJgxRIHw0=";

  subPackages = [ "cmd/sbx" ];

  meta = with lib; {
    description = "CLI wrapper for macOS sandbox-exec with a flag-based interface";
    homepage = "https://github.com/syumai/sbx";
    license = licenses.mit;
    platforms = platforms.darwin;
    mainProgram = "sbx";
  };
}
