# ADR 0032: Local API Transport and Authorization

## Status

Accepted. Supersedes ADR 0015; replaces the transport and endpoint list of ADR 0006.

## Date

2026-11-09

## Context

The API listened on `127.0.0.1:9476` with permissive CORS, so any web page in a local browser could try to call it. ADR 0015's bearer token was written on Unix to a predictable path with default permissions. Any local process able to reach the port or read the file could open firewall holes. A remote API is not a goal.

## Decision

- **Unix:** a Unix socket at `/run/socketguard.sock`, mode 0660, group `socketguard`, plus a peer-credential check on connect.
- **Windows:** a named pipe with an ACL granting Administrators plus a local group `SocketGuard Users`, mirroring the Unix group.
- **Removed:** the TCP listener, the token, and CORS. There is no remote API.
- Authorization is OS identity: membership of the group or the pipe ACL. Refusals are covered by API tests (ADR 0035).
- **Kept from ADR 0006:** REST with JSON bodies on axum, SSE for push, types in `socketguard-core::api_types`, and mutations that trigger enforcement.
- **Resources:** `/api/apps`, `/api/addresses`, `/api/peers`, `/api/peer-groups`, `/api/grants`, `/api/networks`, `/api/settings`, `/api/activity`, with typed SSE events including `activity`.
- The Tauri backend reaches the socket through the shared client crate (ADR 0033).

## Amendment: pipe ACL hardening (security review)

- The group's ACE is an explicit mask, `0x12008B` (FILE_GENERIC_READ with SYNCHRONIZE, plus FILE_WRITE_DATA), not `GRGW`: GENERIC_WRITE includes FILE_APPEND_DATA, the same bit as FILE_CREATE_PIPE_INSTANCE, which would let a group member add a rogue server instance and capture other users' requests.
- The first server instance is created with FILE_FLAG_FIRST_PIPE_INSTANCE, so startup fails if the name was squatted.
- The client opens the pipe with exactly the group's rights and `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, so a rogue server cannot impersonate the caller.
- The `SocketGuard Users` name is used only if it resolves to a group or alias; any other account type is ignored with a warning.

## Consequences

- Browsers cannot reach the API, and no secret file needs managing.
- Access is managed with standard OS tools (`usermod -aG socketguard`, Windows groups).
- `curl --unix-socket` still works for debugging; plain `curl localhost` does not.
- Remote management requires SSH to the host and the CLI there.
