# ADR 0025: Engine Integration Tests

## Status

Accepted (extended by ADR 0035)

## Context

SocketGuard had ~43 unit tests covering database operations, firewall sync
logic, and backend parsing, but no integration tests for the core reconciliation
loop that ties everything together: socket detection, IPv6 allocation, firewall
enforcement, and ACL policy resolution.

The `Engine` struct hardcoded platform dependencies (`create_firewall()`,
`iface::create()`, `create_monitor()`) in 11 `spawn_blocking`
closures, making it impossible to inject mocks and test the reconciliation
pipeline without real OS resources.

## Decision

### 1. Extract `lib.rs` from `main.rs`

Moved all module declarations and `AppState` into `lib.rs` so that integration
tests in `tests/` can import daemon internals via `socketguard_daemon::*`.
`main.rs` retains only `main()` and `load_config_sync()`.

### 2. Make Engine injectable

Changed `Engine` fields from `Box<dyn Firewall>` to `Arc<dyn Firewall>` (and
added `Arc<dyn InterfaceManager>`), enabling cloning into `spawn_blocking`
closures instead of creating new platform instances each time.

Added two constructors:
- `new_with_deps()` — accepts pre-built deps, used by `new()` internally
- `new_injectable()` — accepts pre-built backends too, for full test control

Replaced all 11 inline `create_*()` calls with `self.firewall.clone()` /
`self.network.clone()`.

### 3. Mock infrastructure (`test_support` module)

Created `MockFirewall`, `MockInterfaceManager`, `MockSocketMonitor`, and
`MockIpv6Backend` — all using `Arc<Mutex<Vec<_>>>` for call recording. A
`test_app_state()` helper creates an in-memory SQLite `AppState`.

### 4. Integration test suite (`tests/reconcile.rs`)

16 test scenarios covering the critical paths:

**Core orchestration (tests 1–10):**
1. New socket provisioning (address + firewall)
2. Closed policy with ACL entries
3. Open policy (remove restrictions)
4. Policy change closed→open
5. Stale socket cleanup
6. Multi-backend provisioning
7. ACL group inheritance
8. Process filter
9. Startup reconcile (restore state)
10. Shutdown cleanup (remove all addresses)

**Extended coverage (tests 11–16):**
11. Error resilience — `add_address` fails for one backend; other succeeds, DB consistent
12. Backend add/remove — `add_backend_instance`/`remove_backend_instance` allocate/clean addresses
13. Socket group provisioning + ACL — group address allocation and `apply_socket_group_acl`
14. Idempotency — 3 reconciles with no state change; no duplicate `add_address` calls
15. PID change — same process/port with stable socket identity across reconciles
16. Event emission — `SocketsChanged` fires on new/stale sockets, not on no-op reconciles

### 5. `FailingInterfaceManager` mock

Added `FailingInterfaceManager` to `test_support` — a network mock that returns
`Err` for `add_address` on a configurable interface name. Used by test 11 to
verify that the engine handles partial backend failures gracefully.

## Consequences

- Engine is now fully testable without OS-level firewall/network access
- 16 integration tests exercise the reconciliation pipeline end-to-end
- `Arc` overhead for firewall/network is negligible (one clone per
  `spawn_blocking` call, same as the previous `Box::new(create_*())`)
- `ActiveBackend` and `test_support` are public for integration test access
- No production behavior changes — `Engine::new()` delegates to
  `new_with_deps()` with the same platform constructors
