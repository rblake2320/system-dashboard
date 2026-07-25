# Dashboard Wiring Audit — 2026-07-24

Scope: trace visible controls and background features through UI, Flask route,
implementation, state/effect, and test coverage.

## Confirmed working paths

| Capability | UI/API | Implementation/effect | Coverage |
|---|---|---|---|
| Fleet telemetry | Fleet panel and `/api/fleet` | `fleet_registry` heartbeat/process sampling | Fleet and guard tests |
| Guard escalation | Guard banner and `/api/fleet/event` | Sticky state, thresholds, evidence capture | `test_fleet_guard.py` |
| Agent termination | Fleet-card Kill control and `/api/fleet/<name>/kill` | `psutil.Process(pid).kill()` | Wiring contract plus fleet tests |
| BPC generation/revocation/rotation | Governance panel routes | BPC API, custody vault, ownership, chained audit | Governance/BPC tests |
| TSK/BPC/VPS monitoring | Governance panel | HTTP/NDJSON monitoring and health summaries | Governance/integration tests |
| Provider key management | Key panel | `.env.local` persistence and validation | Key-monitor paths |
| Issue lifecycle | Issue controls | acknowledge, suppress, resolve, persistence | Issue tests |
| Automated fixes | Issue Fix control | authenticated ticket + SSE fixer execution | Fixer/auth paths |
| System review/export | Top-bar Review and Export controls | fresh review and downloadable JSON evidence bundle | Wiring contract |

## Zombies found and corrected

1. `/api/review` had no UI caller. A Review control now renders its result.
2. `/api/export` had no UI caller. An Export control now downloads the bundle.
3. `/api/fleet/<name>/kill` had no fleet-card control. Active agents now expose it.
4. `_setChatModelLabel()` made an unused network request and set no label. It was removed.
5. A root `_fleet_test.py` could execute live HTTP during pytest discovery. Pytest is now constrained to the maintained `tests/` directory.
6. A static wiring contract now detects literal UI fetch paths without Flask routes and inline click handlers without JavaScript functions.

## Deliberate non-enforcement, not a hidden zombie

`fleet_guard` intentionally detects, records, and recommends/declares containment;
it does not itself terminate processes. The separate kill endpoint is real. A
future enforcement controller must explicitly bind `hard_stop` to whole-fleet,
inference, credential, and service controls with safe allowlists, idempotency,
operator authorization, audit logging, and post-stop verification. Silent
automatic process killing was not added during this audit because that policy
decision affects live systems and must be implemented as an explicit control
plane rather than an accidental side effect of monitoring.

## Remaining hardening backlog

- Enforce token scopes consistently across all mutating routes.
- Add an authenticated, audited whole-fleet containment command.
- Add configurable automatic enforcement for sticky `hard_stop`, defaulting to
  dry-run until allowlists and recovery behavior are verified.
- Add inference throttling, user/account suspension, capability restriction,
  service shutdown, fallback, notification, and shutdown-verification adapters.
- Exercise browser behavior in CI in addition to static wiring tests.

## 2026-07-25 canonical snapshot correction

Status, Review, and Export previously assembled different data, allowing a
successful export to omit fleet guard, governance, keys, mesh, and daemon state
and to disagree with Review's health score. They now consume the versioned
`core.system_snapshot` contract.

Every canonical snapshot has a UUID, UTC generation time, schema and score
versions, application commit SHA, required-section validation, explicit
component availability, score-input hash, and evidence SHA-256. Review retains
the exact snapshot for the next Export, and the top bar exposes an Evidence
Complete/Partial/Invalid indicator. Regression tests cover required sections,
failure visibility, and cross-endpoint agreement.
