# ADR-0006: REST API Design

## Status

Accepted

## Date

2026-03-12

## Context

The daemon needs an interface for the CLI and Tauri UI to query state and manage ACLs. Options:
1. **Unix domain socket / named pipe**: Platform-specific, harder to debug.
2. **gRPC**: Strong typing but heavier dependency, code generation required.
3. **REST over HTTP**: Simple, universally supported, easy to debug with curl.

## Decision

Use a **REST API** served by `axum` on `127.0.0.1:9476` (configurable). JSON request/response bodies. CORS enabled for the Tauri frontend.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/sockets` | List all detected sockets |
| `GET` | `/api/sockets/{id}` | Get socket detail with ACL entries |
| `PUT` | `/api/sockets/{id}/acl` | Replace all ACL entries for a socket |
| `POST` | `/api/sockets/{id}/acl/allow` | Add a single allowed IP |
| `DELETE` | `/api/sockets/{id}/acl/{entry_id}` | Remove an ACL entry |
| `PUT` | `/api/sockets/{id}/policy` | Set policy (open/closed/managed) |
| `GET` | `/api/config` | Get daemon configuration |
| `PUT` | `/api/config` | Update daemon configuration |
| `GET` | `/api/backends` | List available IPv6 backends |

### Design Principles

- **Mutation triggers enforcement**: Any ACL or policy change immediately calls `engine.apply_socket_acl()` to update firewall rules. The API response reflects whether the firewall update succeeded.
- **Shared state via `Arc<AppState>`**: The axum router holds an `Arc` to the application state containing the database, config (behind `RwLock`), and engine.
- **Type-safe API types**: All request/response types are defined in `socketguard-core::api_types`, shared between daemon, CLI, and UI.

### Port Choice

`9476` was chosen as an unregistered port unlikely to conflict with common services.

## Consequences

- Any HTTP client can interact with the daemon — enables scripting, automation, and custom integrations.
- Listening on localhost only by default — not exposed to the network.
- The CLI is a thin wrapper: it sends HTTP requests and formats JSON responses as tables.
- The Tauri app calls the same API via Tauri commands that use `reqwest` internally.
- No authentication on the API — it relies on localhost-only binding. Network-exposed deployments would need auth (future enhancement).
