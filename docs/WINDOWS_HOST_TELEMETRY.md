# Windows Host Network Telemetry

This optional sensor gives Sentinel-43 real connection metadata from a Windows host without decrypting or capturing application payloads.

## Trust and privacy boundary

The sensor submits bounded connection facts only: host/local/remote addresses, ports, TCP state, PID, and process name. It does **not** capture packet payloads, HTTP bodies, TLS plaintext, cookies, credentials, form contents, or browser page contents.

The ingest token authenticates the producer. The server assigns the canonical source identity and event type. Producer input cannot choose severity, threat labels, governance decisions, or response actions.

## Coverage

The initial Windows producer observes TCP connections returned by `Get-NetTCPConnection`. This covers ordinary TCP HTTPS traffic and inbound TCP connections visible to the host.

It does **not** claim complete Internet visibility. In particular, browser HTTP/3/QUIC uses UDP and is not represented by `Get-NetTCPConnection`. DNS and generic UDP need a separate Windows-native telemetry adapter before S43 can claim full host-network coverage.

Connection direction is reported as `unknown` because `Get-NetTCPConnection` does not provide authoritative direction and port-number heuristics are not reliable.

## Activation

Keep `S43_HOST_NETWORK_ENABLED=false` until the host installation is ready. Configure a dedicated high-entropy `S43_HOST_NETWORK_INGEST_TOKEN` and `S43_HOST_NETWORK_API_URL`, recreate the API container, then run `scripts/windows-host-network-sensor.ps1` from the Windows host.

The endpoint remains evidence-only and feeds the existing MonitoringManager/Fenrir path. It does not create a second detector or enforcement authority.
