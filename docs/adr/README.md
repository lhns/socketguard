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
| [0005](0005-sqlite-for-state-persistence.md) | SQLite for State Persistence | Accepted; superseded in part by 0027 (schema and migrations) and 0050 (database location) |
| [0006](0006-rest-api-design.md) | REST API Design | Accepted; superseded in part by 0032 (transport, CORS and endpoint list) |
| [0007](0007-reconciliation-loop-pattern.md) | Reconciliation Loop Pattern | Accepted; superseded in part by 0027 (stale-socket deletion) |
| [0008](0008-firewall-implementation-strategy.md) | Firewall Implementation Strategy | Superseded by 0029, 0030 |
| [0009](0009-socket-identity-scheme.md) | Socket Identity Scheme | Superseded by 0027 |
| [0010](0010-tauri-desktop-app.md) | Tauri Desktop App with React Frontend | Accepted; amended by 0033 |
| [0011](0011-network-interface-management.md) | Network Interface IPv6 Management | Accepted |
| [0012](0012-declarative-reconciliation-and-lifecycle.md) | Declarative Reconciliation and Lifecycle Management | Accepted; superseded in part by 0026 (startup and shutdown cleanup) and 0049 (reconcile under the read lock) |
| [0013](0013-slaac-backend-and-per-backend-config.md) | SLAAC Backend and Per-Backend Configuration | Accepted |
| [0014](0014-sse-push-and-native-socket-detection.md) | SSE Push Notifications and Native Socket Detection | Accepted |
| [0015](0015-api-authentication.md) | API Authentication via Bearer Token | Superseded by 0032 |
| [0016](0016-multi-backend-architecture.md) | Multi-Backend Architecture | Superseded by 0027 |
| [0017](0017-per-backend-policy-and-acl.md) | Per-Backend Policy and ACL with Disabled Mode | Superseded by 0027 |
| [0018](0018-tree-view-acl-groups.md) | Tree View UX with ACL Groups and Socket Groups | Superseded by 0027 |
| [0019](0019-ui-tree-structure.md) | UI Tree Structure | Superseded by 0027 |
| [0020](0020-socket-group-acl-group-inheritance.md) | Socket Group ACL Group Inheritance | Superseded by 0027 |
| [0021](0021-opacity-fix-and-checkbox-member-management.md) | Opacity Fix and Checkbox-Based Socket Group Member Management | Superseded by 0027 |
| [0022](0022-acl-group-manage-members-rename-port-styling.md) | ACL Group Manage Members, Rename Groups, Port/Protocol Styling | Superseded by 0027 |
| [0023](0023-badge-consolidation-ux.md) | Badge Consolidation and UX Improvements | Superseded by 0027 |
| [0024](0024-label-consistency-acl-group-checkboxes.md) | Label Consistency and ACL Group Checkboxes in Socket Groups | Superseded by 0027 |
| [0025](0025-engine-integration-tests.md) | Engine Integration Tests | Accepted (extended by 0035) |
| [0026](0026-secure-by-default-protection-scope.md) | Secure-by-Default Protection Scope and Daemon-Stop Semantics | Accepted; amended (also by 0044) (supersedes 0004 and 0012's startup and shutdown cleanup; refined by 0038; extended by 0051; portable-mode exception in 0054) |
| [0027](0027-domain-model-apps-peers-grants.md) | Domain Model: Apps, Networks, Addresses, Peers and Grants | Accepted; amended (also by 0046); superseded in part by 0047 (address mode, split/merge, every app has an address) and 0053 (reviewed flag) (supersedes 0009, 0016–0024 and parts of 0005 and 0007; refined by 0041, 0043) |
| [0028](0028-credentials-and-verification.md) | Credentials and Verification | Accepted; amended by 0044, 0045 |
| [0029](0029-firewall-desired-state-seam.md) | Firewall Desired-State Seam | Accepted; amended (supersedes 0008 with 0030) |
| [0030](0030-windows-enforcement-via-wfp.md) | Windows Enforcement via the WFP API | Accepted; amended (supersedes 0008 with 0029; portable-mode exception in 0054) |
| [0031](0031-yggdrasil-subnet-backend.md) | Yggdrasil Backend from the Node Subnet | Accepted (supersedes 0003) |
| [0032](0032-local-api-transport-and-auth.md) | Local API Transport and Authorization | Accepted; amended (also by 0050: macOS socket path) (supersedes 0015 and 0006's transport and endpoint list; refined by 0038) |
| [0033](0033-frontends-shared-client-cli-first.md) | Frontends: Shared Client, CLI First, UI as API Client | Accepted; superseded in part by 0042 (UI scope) and 0034 (client-side trace propagation) (amends 0010) |
| [0034](0034-observability-and-activity.md) | Observability with OpenTelemetry and a Local Activity Store | Accepted; amended |
| [0035](0035-test-strategy-and-ci.md) | Test Strategy and CI | Accepted (extends 0025) |
| [0036](0036-future-directions.md) | Future Directions: WireGuard, mTLS Gateway, IPv4 | Accepted |
| [0037](0037-pluggable-networks-and-onion-backend.md) | Pluggable Networks and the Onion Backend | Accepted (refined by 0039, then 0040) |
| [0038](0038-disabled-latch-and-persisted-networks.md) | Disabled Latch and Persisted Networks | Accepted; amended; superseded in part by 0050 (config file location) (refines 0026, 0032; extended by 0048) |
| [0039](0039-onion-service-lifecycle.md) | Onion Service Lifecycle | Superseded by 0040 |
| [0040](0040-onion-service-lifecycle-consolidated.md) | Onion Service Lifecycle (Consolidated) | Accepted; amended in part by 0047 (supersedes 0039; refines 0037; refined by 0045) |
| [0041](0041-unique-grants.md) | Grants Are Unique in the Database | Accepted; amended (refines 0027; refined by 0043; extended by 0047) |
| [0042](0042-ui-covers-the-whole-api.md) | The UI Covers the Whole API | Accepted; amended; superseded in part by 0053 (review actions) (supersedes 0033's UI scope) |
| [0043](0043-app-tags.md) | App Tags as Grant Targets | Accepted; amended (refines 0027, 0041; extended by 0047) |
| [0044](0044-ipv4-and-network-segments.md) | IPv4 and Network Segments on Protect-Host | Accepted (amends 0026, 0028) |
| [0045](0045-batch-changes-credential-parsing-tor-keys.md) | Batch Changes, One Credential Parser, Stored Tor Client Keys | Accepted; superseded in part by 0053 (`Review` batch operation) (refines 0028, 0040) |
| [0046](0046-unidentified-sockets-and-system-flag.md) | Unidentified Sockets Become Apps; System Components Are Flagged | Accepted; superseded in part by 0053 (pending state) (amends 0027) |
| [0047](0047-addresses-on-demand-reservations-port-groups.md) | Addresses on Demand, Reservations and Port Groups | Accepted (supersedes 0027 in part; extends 0041, 0043) |
| [0048](0048-network-setup-detect-install-configure.md) | Networks Are Set Up by Detect, Install, Configure | Accepted; superseded in part by 0052 (install and configure steps) (extends 0038, 0040; extended by 0051) |
| [0049](0049-reconcile-under-the-read-lock.md) | The Reconcile Pass Runs Under the Engine's Read Lock | Accepted (supersedes 0012 in part) |
| [0050](0050-install-service-uninstall.md) | Installed as a Service, with Fixed Paths and an Uninstall That Leaves Nothing | Accepted; amended (supersedes 0005 and 0038 in part: locations; amends 0032: macOS socket; fulfils 0026's uninstaller; portable-mode exception in 0054) |
| [0051](0051-nothing-socketguard-adds-opens-the-host.md) | Nothing SocketGuard Adds Opens the Host | Accepted; amended; superseded in part by 0052 (setup installing or starting third-party software) (extends 0026, 0048) |
| [0052](0052-bundled-tor-and-yggdrasil.md) | SocketGuard Ships and Runs Its Own Tor and Yggdrasil | Accepted; amended (supersedes 0048 and 0051 in part; builds on 0040, 0050, 0051) |
| [0053](0053-no-review-state.md) | New Apps Are Just Closed; There Is No Review State | Accepted (supersedes 0027 and 0042 in part) |
| [0054](0054-portable-mode-on-windows.md) | A Portable Mode on Windows That Leaves Nothing Behind | Accepted; amended (exception to 0026, 0030, 0050) |
| [0055](0055-no-compatibility-before-the-first-release.md) | No Compatibility With States From Before the First Release | Accepted |
| [0056](0056-only-socketguards-own-tor-and-yggdrasil.md) | Only SocketGuard's Own Tor and Yggdrasil | Accepted (supersedes 0040; 0048, 0051, 0052 in part) |
| [0057](0057-one-staged-tree-and-one-purge-list.md) | One Staged Tree per System, One Purge List | Accepted (refines 0050, 0052; superseded in part by 0058) |
| [0058](0058-freeing-a-reservations-rows-is-a-change-of-reach.md) | Freeing a Reservation's Rows Is a Change of Reach | Accepted (extends 0047; supersedes 0057 in part) |

## Format

Each ADR follows this structure:

- **Status**: `Accepted`, optionally followed by notes (`Supersedes ADR n`, `Refines ADR n`, `Amended below`, `Superseded in part by ADR n: <what>`), or `Superseded by ADR n`. An accepted ADR's decision is not rewritten: later changes are appended as `Amendment` sections (read in order), or a later ADR supersedes it in whole or in part, which the older ADR's Status then notes
- **Date**: When the decision was made
- **Context**: The problem or situation that prompted the decision
- **Decision**: What was decided and why
- **Consequences**: The resulting impact, both positive and negative
