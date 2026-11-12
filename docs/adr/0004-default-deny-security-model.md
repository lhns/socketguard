# ADR-0004: Default-Deny Security Model

## Status

Superseded by ADR 0026

## Date

2026-03-12

## Context

When SocketGuard detects a new listening socket and assigns it an IPv6 address, we must decide the initial access policy. Three options:

1. **Default open**: Allow all traffic. The socket is reachable by anyone until the user restricts it. This is the current behavior without SocketGuard and offers no security improvement.
2. **Default deny (closed)**: Block all traffic. The socket is unreachable until the user explicitly allows specific IPs. Maximally secure but requires user action before the service is usable.
3. **Default managed with empty ACL**: Same effect as deny, but signals intent that the user should add entries.

## Decision

New sockets start with **policy = "closed"** (deny all). The daemon immediately creates a firewall rule blocking all traffic to the newly assigned IPv6 address and port.

Three policies are available per socket:
- **closed** — Drop all incoming connections to this IPv6:port. Default for new sockets.
- **open** — Allow all incoming connections (remove firewall restrictions). For trusted services.
- **managed** — Allow only source IPs listed in the socket's ACL. The primary operating mode.

The user must explicitly change the policy to `managed` or `open` and add ACL entries before traffic is permitted.

## Consequences

- Security by default: newly exposed services are not accidentally reachable.
- The user is forced to make a conscious decision about who can access each socket.
- Services that need immediate accessibility require manual intervention after first detection.
- The CLI and UI make it easy to change policy: `socketguard policy <id> managed` followed by `socketguard acl allow <id> <ip>`.
- Firewall rules are applied immediately when policy or ACL changes, via the engine's `apply_socket_acl()` method.
