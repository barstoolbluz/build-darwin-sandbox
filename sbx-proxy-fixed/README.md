# sbx-proxy (patched)

This package is a corrected version of the uploaded localhost-only CONNECT proxy.

Changes:
- fixed the broken test suite import
- added tests for fragmented TLS ClientHello parsing
- changed the SNI-gated path so a bad or missing SNI does not open an upstream socket first
- kept the localhost-only operating model for macOS-first use

Notes:
- For --tls-sni-policy=off, upstream dial still happens before 200 Connection established.
- For SNI-enforced modes, the proxy sends 200, waits for the client hello, validates SNI, then dials upstream. That avoids wasting upstream sockets on bad SNI from local clients.
- This is tuned for loopback use on macOS first.
