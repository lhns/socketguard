# ADR 0015: API Authentication via Bearer Token

## Status

Accepted

## Date

2026-03-13

## Context

SocketGuard's HTTP API (REST + SSE) runs on localhost and controls security-critical functionality: reading socket state and modifying firewall rules and ACLs. Without authentication, any local process can call these endpoints, which violates the principle of least privilege. A malicious or compromised process on the same machine could silently open firewall holes.

We need a lightweight authentication mechanism that:
- Prevents unauthorized local processes from accessing the API
- Requires no user-managed passwords or certificates
- Works transparently for the CLI, Tauri UI, and SSE connections
- Handles daemon restarts (new token) gracefully

## Decision

We implement a **file-based bearer token** scheme:

1. **Token generation**: The daemon generates a cryptographically random 256-bit token (64 hex characters) at startup using `rand`.

2. **Token file**: The token is written to `%LOCALAPPDATA%\SocketGuard\api-token` (Windows) or `$XDG_RUNTIME_DIR/socketguard/api-token` (Unix). This path inherits user-only filesystem ACLs from the parent directory, so only the same user can read it.

3. **Authentication**: All API endpoints are protected by an axum middleware layer that validates the `Authorization: Bearer <token>` header. Requests without a valid token receive a 401 response with a JSON error body.

4. **Client integration**: Both the CLI and Tauri UI read the token file automatically. The CLI also accepts a `--token` flag for manual override. The Tauri UI retries on 401 by re-reading the token file (handles daemon restart with a new token).

5. **Cleanup**: The token file is deleted on daemon shutdown to avoid stale tokens.

### Shared token path

`socketguard_core::api_token_path()` provides the canonical path, ensuring daemon, CLI, and UI all agree on the file location.

## Consequences

### Positive
- Any local process without filesystem access to the token file cannot call the API
- Zero user configuration — token is generated and consumed automatically
- CLI `--token` flag enables scripting and testing scenarios
- 401 retry logic in the UI handles daemon restarts seamlessly
- Middleware-based approach ensures no endpoint can accidentally skip auth

### Negative
- Processes running as the same user can still read the token file (acceptable trade-off for a localhost daemon)
- Token file must be cleaned up on shutdown; abnormal termination leaves a stale file (harmless — next startup overwrites it)
- Adds a small amount of latency to every request for header validation (negligible)
