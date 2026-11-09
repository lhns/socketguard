# Architecture Decision Records

This directory contains the Architecture Decision Records (ADRs) for SocketGuard.

ADRs document significant architectural decisions made during the project's development. Each record captures the context, decision, and consequences of a choice.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-project-architecture.md) | Project Architecture | Accepted |
| [0002](0002-platform-abstraction-via-traits.md) | Platform Abstraction via Traits | Accepted |
| [0003](0003-ipv6-backend-strategy.md) | IPv6 Backend Strategy | Superseded by 0031 |
| [0004](0004-default-deny-security-model.md) | Default-Deny Security Model | Superseded by 0026 |
| [0005](0005-sqlite-for-state-persistence.md) | SQLite for State Persistence | Accepted (schema superseded by 0027) |
| [0006](0006-rest-api-design.md) | REST API Design | Accepted (transport and endpoints superseded by 0032) |
| [0007](0007-reconciliation-loop-pattern.md) | Reconciliation Loop Pattern | Accepted (stale deletion superseded by 0027) |
| [0008](0008-firewall-implementation-strategy.md) | Firewall Implementation Strategy | Superseded by 0029, 0030 |
| [0009](0009-socket-identity-scheme.md) | Socket Identity Scheme | Superseded by 0027 |
| [0010](0010-tauri-desktop-app.md) | Tauri Desktop App with React Frontend | Accepted (amended by 0033) |
| [0011](0011-network-interface-management.md) | Network Interface IPv6 Management | Accepted |
| [0012](0012-declarative-reconciliation-and-lifecycle.md) | Declarative Reconciliation and Lifecycle Management | Accepted (start/stop cleanup superseded by 0026) |
| [0013](0013-slaac-backend-and-per-backend-config.md) | SLAAC Backend and Per-Backend Configuration | Accepted |
| [0014](0014-sse-push-and-native-socket-detection.md) | SSE Push Notifications and Native Socket Detection | Accepted |
| [0015](0015-api-authentication.md) | API Authentication via Bearer Token | Superseded by 0032 |
| [0016](0016-multi-backend-architecture.md) | Multi-Backend Architecture | Superseded by 0027 |
| [0017](0017-per-backend-policy-and-acl.md) | Per-Backend Policy and ACL with Disabled Mode | Superseded by 0027 |
| [0018](0018-tree-view-acl-groups.md) | Tree View UX with ACL Groups and Socket Groups | Superseded by 0027 |
| [0019](0019-ui-tree-structure.md) | UI Tree Structure | Superseded by 0027 |
| [0020](0020-socket-group-acl-group-inheritance.md) | Socket Group ACL Group Inheritance | Superseded by 0027 |
| [0021](0021-opacity-fix-and-checkbox-member-management.md) | Opacity Fix and Checkbox-Based Member Management | Superseded by 0027 |
| [0022](0022-acl-group-manage-members-rename-port-styling.md) | ACL Group Manage Members, Rename Groups, Port/Protocol Styling | Superseded by 0027 |
| [0023](0023-badge-consolidation-ux.md) | Badge Consolidation and UX Improvements | Superseded by 0027 |
| [0024](0024-label-consistency-acl-group-checkboxes.md) | Label Consistency and ACL Group Checkboxes in Socket Groups | Superseded by 0027 |
| [0025](0025-engine-integration-tests.md) | Engine Integration Tests | Accepted (extended by 0035) |
| [0026](0026-secure-by-default-protection-scope.md) | Secure-by-Default Protection Scope and Daemon-Stop Semantics | Accepted |
| [0027](0027-domain-model-apps-peers-grants.md) | Domain Model: Apps, Networks, Addresses, Peers and Grants | Accepted |
| [0028](0028-credentials-and-verification.md) | Credentials and Verification | Accepted |
| [0029](0029-firewall-desired-state-seam.md) | Firewall Desired-State Seam | Accepted |
| [0030](0030-windows-enforcement-via-wfp.md) | Windows Enforcement via the WFP API | Accepted |
| [0031](0031-yggdrasil-subnet-backend.md) | Yggdrasil Backend from the Node Subnet | Accepted |
| [0032](0032-local-api-transport-and-auth.md) | Local API Transport and Authorization | Accepted |
| [0033](0033-frontends-shared-client-cli-first.md) | Frontends: Shared Client, CLI First, UI as API Client | Accepted |
| [0034](0034-observability-and-activity.md) | Observability with OpenTelemetry and a Local Activity Store | Accepted |
| [0035](0035-test-strategy-and-ci.md) | Test Strategy and CI | Accepted |
| [0036](0036-future-directions.md) | Future Directions: WireGuard, mTLS Gateway, IPv4 | Accepted |
| [0037](0037-pluggable-networks-and-onion-backend.md) | Pluggable Networks and the Onion Backend | Accepted |

## Format

Each ADR follows this structure:

- **Status**: Accepted, Deprecated, or Superseded
- **Date**: When the decision was made
- **Context**: The problem or situation that prompted the decision
- **Decision**: What was decided and why
- **Consequences**: The resulting impact, both positive and negative
