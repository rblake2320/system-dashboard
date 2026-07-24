# AI Fleet Auto-Halt Provenance Record

Record created: **2026-07-24 14:34:08 CDT (UTC−05:00; America/Chicago)**

Repository: `rblake2320/system-dashboard`

Historical implementation commit: `6c98b1e4df5a71b9e4e3dfe2a3cdff18f94eb19f`

## Verified chronology

| Timestamp | Verifiable event |
|---|---|
| 2026-06-20 15:33:00 CDT | Initial system dashboard committed (`bb7aac1`). |
| 2026-06-20 16:28:56 CDT | Claude session monitoring, MemoryWeb health, and the BPC/TSK governance panel committed (`2e41ebf`). |
| **2026-06-21 13:12:15 CDT** | The AI-agent fleet auto-halt engine, fleet registry, evidence capture, BPC audit chain, UI controls, and 681 lines of fleet-guard tests were committed together (`6c98b1e`). |
| 2026-06-21 15:59:33 CDT | Separate governance profiles and BPC credential custody were committed (`80bc839`). |
| 2026-06-22 09:24:13–13:14:38 CDT | Witness/replica integration, audit lock, credential cache, governance entry banner, and webhook notification were committed. |
| **2026-07-23** | Representatives Ted Lieu and Nathaniel Moran announced introduction of the AI Kill Switch Act. |
| 2026-07-24 | This provenance and wiring audit was added to the repository. |

The Git commit metadata establishes that the repository contained the auto-halt
implementation **32 calendar days before** the official July 23 announcement.
The commit can be independently inspected with:

```text
git show --format=fuller 6c98b1e4df5a71b9e4e3dfe2a3cdff18f94eb19f
```

## What existed on June 21

`core/fleet_guard.py` described itself in the June 21 commit as an “alert
evaluation engine for the AI agent fleet auto-halt system.” It continuously
evaluated:

- free RAM and, in local-model mode, free VRAM;
- fleet heartbeats and missed acknowledgments;
- repeated local-narration violations;
- identity and integrity failures: `wrong_window_guard_failure`, `wrong_nonce`,
  `wrong_hash`, and `wrong_sender`.

Its state machine was:

```text
ok → halt_recommended → degraded → blocked → hard_stop
```

An immediate integrity event entered a sticky `hard_stop` and captured evidence.
The same commit also included a process-enforcement primitive in
`core/fleet_registry.py`: `kill_agent(name)` terminates the registered PID.

## Important technical distinction

The June 21 design deliberately separated detection/governance from enforcement:

- `fleet_guard.py` set a sticky containment state and captured forensic evidence;
- `fleet_registry.py` provided per-agent process termination;
- the Flask API exposed per-agent termination;
- an orchestrator was expected to honor the guard state.

Accordingly, it is accurate to call this a working **fleet auto-halt and
containment-control system** with a process kill capability. It would be
inaccurate to claim that the June 21 guard state, by itself, automatically
terminated every process. That precision strengthens rather than weakens the
historical record.

## Comparison with the introduced bill

The July 23 announcement says the proposed Act would require covered developers
to maintain the ability to throttle, suspend, or fully shut down covered AI
systems, use a graduated response, report incidents, and preserve forensic
records. The draft text additionally discusses stopping inference, terminating
or suspending user access, compute throttling, capability restriction, fallback
systems, preservation of model weights and telemetry, notification, confirmation,
and forensic verification.

The June system already demonstrated several of those concepts:

- graduated containment states;
- continuous telemetry and heartbeat evaluation;
- identity/integrity-based immediate hard-stop triggers;
- evidence capture and chained audit records;
- credential revocation and custody tracking;
- a separate process termination mechanism.

Still to build for a bill-aligned production control plane:

- fail-closed orchestration that automatically enforces `hard_stop`;
- inference, user, account, capability, and compute throttles;
- whole-fleet and whole-service shutdown with independent verification;
- model-weight and full telemetry preservation;
- incident-report and affected-user notification workflows;
- tested backup/earlier-model transition.

## Sources and evidentiary limits

- Official announcement: <https://lieu.house.gov/media-center/press-releases/reps-lieu-and-moran-introduce-bill-require-kill-switch-ai-systems-can>
- Draft bill text: <https://lieu.house.gov/sites/evo-subsites/lieu-evo.house.gov/files/evo-media-document/ai-kill-switch-act.pdf>
- Repository history: immutable Git object IDs listed above.

This document records engineering chronology. It is not a legal conclusion about
patent priority, statutory compliance, inventorship, or ownership. Preserve the
Git objects, signed releases, build artifacts, test output, and any contemporaneous
design notes if formal evidentiary use is anticipated.
