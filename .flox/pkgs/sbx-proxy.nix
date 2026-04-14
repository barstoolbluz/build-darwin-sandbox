{ buildGoModule, lib }:

buildGoModule {
  pname = "sbx-proxy";
  version = "0.1.0";

  src = ../proxy;

  # Standard library only — no external imports, no vendor dir.
  vendorHash = null;

  # Strip symbols for a smaller binary.
  ldflags = [ "-s" "-w" ];

  meta = with lib; {
    description = "Local CONNECT-style HTTPS proxy with hostname allowlisting";
    license = licenses.mit;
    platforms = platforms.darwin;
    mainProgram = "sbx-proxy";
  };
}
