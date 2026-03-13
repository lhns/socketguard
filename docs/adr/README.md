# Architecture Decision Records

This directory contains the Architecture Decision Records (ADRs) for SocketGuard.

ADRs document significant architectural decisions made during the project's development. Each record captures the context, decision, and consequences of a choice.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-project-architecture.md) | Project Architecture | Accepted |
| [0002](0002-platform-abstraction-via-traits.md) | Platform Abstraction via Traits | Accepted |
| [0003](0003-ipv6-backend-strategy.md) | IPv6 Backend Strategy | Accepted |
| [0004](0004-default-deny-security-model.md) | Default-Deny Security Model | Accepted |
| [0005](0005-sqlite-for-state-persistence.md) | SQLite for State Persistence | Accepted |
| [0006](0006-rest-api-design.md) | REST API Design | Accepted |
| [0007](0007-reconciliation-loop-pattern.md) | Reconciliation Loop Pattern | Accepted |
| [0008](0008-firewall-implementation-strategy.md) | Firewall Implementation Strategy | Accepted |
| [0009](0009-socket-identity-scheme.md) | Socket Identity Scheme | Accepted |
| [0010](0010-tauri-desktop-app.md) | Tauri Desktop App with React Frontend | Accepted |
| [0011](0011-network-interface-management.md) | Network Interface IPv6 Management | Accepted |
| [0012](0012-declarative-reconciliation-and-lifecycle.md) | Declarative Reconciliation and Lifecycle Management | Accepted |
| [0013](0013-slaac-backend-and-per-backend-config.md) | SLAAC Backend and Per-Backend Configuration | Accepted |
| [0014](0014-sse-push-and-native-socket-detection.md) | SSE Push Notifications and Native Socket Detection | Accepted |

## Format

Each ADR follows this structure:

- **Status**: Accepted, Deprecated, or Superseded
- **Date**: When the decision was made
- **Context**: The problem or situation that prompted the decision
- **Decision**: What was decided and why
- **Consequences**: The resulting impact, both positive and negative
