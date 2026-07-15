<!-- SPDX-FileCopyrightText: 2026 Robert Flanagan and macadmin-toolbox contributors -->
<!-- SPDX-License-Identifier: MIT -->

# Intel App Auditor: a Jamf Pro Extension Attribute for the Rosetta 2 wind-down

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE) ![Platform: macOS 12 through 26](https://img.shields.io/badge/platform-macOS%2012%E2%80%9326-lightgrey.svg) ![Shell: zsh](https://img.shields.io/badge/shell-zsh-89e051.svg) ![Jamf Pro: any tier](https://img.shields.io/badge/Jamf%20Pro-any%20tier-orange.svg) ![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

Answer one fleet question ahead of Rosetta 2's removal: **which Macs still have Intel-classified application bundles, and which apps are they?** This is a Jamf Pro Extension Attribute (EA), fed by a background collector, that inventories every Intel-only (`x86_64`) application on a managed Mac so you can scope, track, and close out an Apple silicon migration. The collector classifies every application bundle under `/Applications` and `/Applications/Utilities` (and, optionally, the console user's `~/Applications`) as IntelOnly / Universal / AppleSilicon / iOS / Other / Unknown, records whether the Rosetta 2 runtime file is present, and caches the result. The EA reads that cached value into the computer record so it is usable as Smart Group scope criteria and Advanced Search reporting.

Classification is on the machine field `arch_kind` from `system_profiler -json SPApplicationsDataType` (never the localized "Kind: Intel" text), cross-checked against an independent `lipo`-based direct bundle scan. A broken or omission-prone inventory degrades to `ScanStatus:Partial` — never a false clean zero.

> Where it fits: **SEE** (which Macs still run Intel-only apps, and which apps) → **DECIDE** (target replacement, repackaging, or retirement at exactly those Macs) → **PROVE** (a `ScanStatus:Complete` + `IntelOnly:0` Smart Group is your audit-ready record that a Mac is Rosetta-free before Rosetta 2 goes away). It runs on any Jamf Pro tier with zero external dependencies: the only moving parts are the Jamf binary you already have and one small launchd-scheduled collector.

## Table of contents

- [Quick start](#quick-start)
- [Repository layout](#repository-layout)
- [Architecture: collector → file → reader EA](#architecture-collector--file--reader-ea)
- [Install via a Jamf policy](#install-via-a-jamf-policy)
- [Output format](#output-format)
- [Smart Group scoping recipes](#smart-group-scoping-recipes)
- [Detection details](#detection-details)
- [launchd behavior](#launchd-behavior)
- [Maintenance and tests](#maintenance-and-tests)
- [Security note](#security-note)
- [Verification snapshot](#verification-snapshot)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)

## Quick start

1. Deploy [`install.sh`](./install.sh) fleet-wide from a Jamf Pro policy (as root, once per computer). It installs the collector engine, creates the root-only state directory, and loads the LaunchDaemon; the first scan runs immediately (`RunAtLoad`).
2. Create a computer Extension Attribute (Data Type **String**, Input Type **Script**) and paste in [`intel-app-auditor-ea.zsh`](./intel-app-auditor-ea.zsh) — the thin reader, **not** the engine. Leave the `both` trigger word uncommented, or switch it to `counts` / `apps` (and add a second EA for the other view if you want both columns).
3. Build Smart Groups on the value (see [Smart Group scoping recipes](#smart-group-scoping-recipes)).

> **The reader is useless without the collector running.** Deploy step 1 before (or in the same scope as) the EA, or every Mac reports `NOT_COLLECTED` forever.

## Repository layout

| File | Purpose |
| --- | --- |
| [`intel-app-auditor-ea.zsh`](./intel-app-auditor-ea.zsh) | The thin EA reader. Paste this into Jamf Pro. |
| [`intel-app-auditor.zsh`](./intel-app-auditor.zsh) | The detection engine (single source of truth); runs as the collector under `MODE=collector`. |
| [`install.sh`](./install.sh) | Self-contained installer (generated; the collector is embedded via heredoc). Deploy this from a Jamf policy. |
| [`install.sh.in`](./install.sh.in) | Installer template consumed by the build script. |
| [`build-installer.sh`](./build-installer.sh) | Regenerates `install.sh` after any engine edit. |
| [`io.github.intel-app-auditor.collector.plist`](./io.github.intel-app-auditor.collector.plist) | Reference LaunchDaemon plist (the installer generates the deployed copy). |
| [`test_intel-app-auditor.zsh`](./test_intel-app-auditor.zsh) | Local test suite; non-zero exit on any failure. |
| [`LICENSE`](./LICENSE) | MIT license. |

## Architecture: collector → file → reader EA

This is a **two-piece split**, not a single recon-time script. The heavy scan runs on the collector's own schedule; the Jamf EA only ever reads a small local file.

```text
LaunchDaemon (MODE=collector, background, scheduled)
        │
        ▼
intel-app-auditor.zsh   ──writes──▶  /var/db/intel-app-auditor/result.txt
  (scans, classifies, runs as root)          │
                                             │ reads (root, at recon)
                                             ▼
                                  intel-app-auditor-ea.zsh
                                     (thin reader: the Jamf EA)
                                             │
                                             ▼
                                 Jamf Pro computer record
                                 + Smart Group criteria
```

[`intel-app-auditor.zsh`](./intel-app-auditor.zsh) is the detection engine with exactly **two run modes** (anything else logs `invalid MODE ...; defaulting to ea`):

- **`collector`** — run by the installed LaunchDaemon. Scans on its own timer and atomically caches the reader payload — the counts summary line plus the Intel-only app list — to the state file. It writes no `<result>` wrapper and produces no stdout the EA depends on.
- **`ea`** — a standalone / command-line convenience that scans now and prints one counts `<result>` line. This is **not** the Jamf recon path; the reader is. It exists for spot checks and testing.

There is no report, swiftDialog, Self Service, or export mode. The engine only scans and (in collector mode) caches.

[`intel-app-auditor-ea.zsh`](./intel-app-auditor-ea.zsh) is the thin reader you paste into Jamf. It **never scans**: recon pays only a `stat` plus a file read. It slices the cached file to the requested view, applies the freshness / integrity sentinels, and wraps the result in `<result>…</result>`. It completes in well under a second at every recon.

### The engine's own parameter contract

When the engine runs standalone (CLI, or pasted directly as a script), it reads the Jamf custom parameters `$4`–`$7` (Jamf reserves `$1`–`$3` for mount point / computer name / username):

| Param | Meaning | Default |
| --- | --- | --- |
| `$4` | `MODE`: `ea` or `collector` | `ea` |
| `$5` | `SCAN_USER_APPS`: `1` also audits the console user's `~/Applications` | `0` |
| `$6` | `SP_TIMEOUT`: `system_profiler` timeout seconds (1–3600) | `120` |
| `$7` | `EXTRA_ROOT`: one extra absolute application dir to audit | none |

Each parameter also has an environment-variable equivalent of the same name. When the engine runs as the installed LaunchDaemon there are no positional parameters — `install.sh` delivers `MODE=collector`, `SCAN_USER_APPS`, `SP_TIMEOUT`, `EXTRA_ROOT`, and `INTEL_STATE_DIR` through the plist's `EnvironmentVariables` instead.

### One reader, three trigger words — all Smart-Group-able

A Jamf EA is a pasted script and takes no policy parameters. The reader is a single file with **three trigger words** at the bottom; each names one view, and every view is a single `<result>` value, so every view is usable as Smart Group criteria:

| Trigger word | Emits | Match in a Smart Group on… |
| --- | --- | --- |
| `counts` | the compact summary line only | `IntelOnly:0`, `ScanStatus:Partial`, `RosettaRuntimePresent:Yes`, `Arch:x86_64`, … |
| `apps` | the Intel-only app list (name + path), or `IntelApps:None` | a specific app by name or path, e.g. `like "Final Cut Pro"` |
| `both` | summary line, then the app list (default) | either of the above, against one EA |

To pick a view, keep exactly **one** of the three trigger words uncommented at the bottom of the reader (the other two stay commented — two uncommented would emit two `<result>` lines and be invalid):

```zsh
# ── Jamf EA trigger: keep exactly ONE uncommented ──
both
# counts
# apps
```

From the command line you can also pass the trigger word as the first argument — `intel-app-auditor-ea.zsh counts` — which is how the test suite exercises all three. Want a **Counts** column *and* an **Apps** column in Jamf? Create two EAs from this one reader, uncommenting `counts` in one and `apps` in the other; the scan still runs only once, in the collector, and both EAs slice the same cached file. Prefer a single column? Leave `both` — you can still match counts *and* app names against that one multi-line value.

**Why split it?** A script EA that scans adds its `system_profiler` runtime to every inventory update (`jamf recon` / Update Inventory) — for state that barely changes. The split moves that scan onto the collector's own scheduled `launchd` budget so recon just reads one small local file, and it adds freshness / integrity sentinels the monolith never had. Intel-to-Apple migration is a slow, monthly-scale trend, so a weekly scan captures it fine for most fleets — but the cadence is yours: set the collector interval at install time and the reader's staleness threshold (2× the interval) tracks it automatically. (The LaunchDaemon also runs at load; missed `StartInterval` firings during sleep are not replayed.)

## Install via a Jamf policy

[`install.sh`](./install.sh) is fully self-contained: the engine ([`intel-app-auditor.zsh`](./intel-app-auditor.zsh)) is embedded inside it via a heredoc, so deliver it as one **Scripts** payload. It is idempotent — scope it to run once per computer (re-running just reinstalls in place).

```bash
sudo ./install.sh
```

### install.sh Jamf script parameters

Jamf consumes `$1`–`$3` (mount point / computer name / username); the installer's own parameters start at `$4`. **These are the installer's parameters, distinct from the engine's `$4`–`$7` contract above.**

| Parameter | Meaning | Default |
| --- | --- | --- |
| **4** | Action: blank / `install` installs; `--uninstall` / `uninstall` removes | install |
| **5** | `REVERSE_DOMAIN`: reverse-DNS namespace for the LaunchDaemon label + plist filename | `io.github.intel-app-auditor` |
| **6** | Collection interval seconds (integer, ≥ 600) | `604800` (7 days) |
| **7** | Collector log path (absolute) | `/var/log/intel-app-auditor.collector.log` |
| **8** | `SCAN_USER_APPS`: `1` also audits the console user's `~/Applications` | `0` |
| **9** | `SP_TIMEOUT`: `system_profiler` timeout seconds (1–3600) | `120` |
| **10** | `EXTRA_ROOT`: one extra absolute application dir to audit | none |

Parameters 8–10 tune the scan; the installer passes them to the daemon through the plist's `EnvironmentVariables` (alongside `MODE=collector` and `INTEL_STATE_DIR`), because the installer's own `$4`–`$7` are its action / namespace / interval / log.

> **Two cross-contracts to respect.** (1) The installer records parameter 6 in `/var/db/intel-app-auditor/interval`, and the reader flags `STALE` at 2× that value (falling back to 28800 s if the file is missing), so a custom interval propagates to the staleness check automatically. (2) An **uninstall policy must pass the same parameter 5** used at install time, or `bootout` targets the wrong LaunchDaemon label; the uninstaller falls back to the recorded label when it can and warns when the expected plist is absent.

What it does:

- Installs the engine under `/usr/local/` (`root:wheel`).
- Creates `/var/db/intel-app-auditor/` (`root:wheel`, `0700`), the root-only state directory, and records the interval.
- Writes `/Library/LaunchDaemons/<REVERSE_DOMAIN>.collector.plist`, then lints it before loading.
- Loads it with modern `launchctl` subcommands: `bootout` → `enable` → `bootstrap system` → `kickstart -k` (forces an immediate first run). It never touches the deprecated `load` / `unload`.

> **Maintainers.** `install.sh` is generated; do not hand-edit it. Edit the engine ([`intel-app-auditor.zsh`](./intel-app-auditor.zsh)) and/or the template ([`install.sh.in`](./install.sh.in)), then run [`./build-installer.sh`](./build-installer.sh) to re-embed the engine verbatim. The test suite includes a **build-drift guard** that fails if `install.sh` ever diverges from a fresh build.

### Point a Jamf Extension Attribute at the reader

1. Jamf Pro → **Settings → Computer Management → Extension Attributes → New**.
2. Display Name: `Intel App Auditor`
3. Data Type: `String`
4. Inventory Display: **Extension Attributes** (keeps this signal grouped with your other EAs in the computer record and in the Advanced Search / report column pickers).
5. Input Type: `Script` → paste the full contents of [`intel-app-auditor-ea.zsh`](./intel-app-auditor-ea.zsh): the thin reader, not the engine.
6. Save. The EA is collected at every inventory (recon) and completes in well under a second, because it isn't scanning anything.

> **Retain history when you disable it.** If you ever remove or disable this EA, set **Manage Existing Data → RETAIN** rather than *Delete*. RETAIN preserves the last-collected value on every computer record, so your migration audit history (and any Smart Group built on it) survives the change instead of being wiped fleet-wide.

### Uninstall

```bash
sudo ./install.sh --uninstall
```

`bootout`s the daemon and removes the installed engine, plist, and state directory (the log file is left in place; rotate or remove it separately). If you also disable/delete the Jamf EA, set **Manage Existing Data → RETAIN** to keep historical Smart Group data.

## Output format

The collector caches this: line 1 is the counts summary; each subsequent line is one Intel-only app (app names and paths are XML-escaped and control-character-scrubbed):

```text
IntelOnly:3;Universal:41;AppleSilicon:112;iOS:2;Other:1;Unknown:0;ScanStatus:Complete;DetectionSource:SystemProfiler+DirectReconciled;RosettaRuntimePresent:Yes;Arch:arm64;Scope:/Applications,/Applications/Utilities
INTEL_APP | Final Cut Pro | /Applications/Final Cut Pro.app
INTEL_APP | Some Old Utility | /Applications/Some Old Utility.app
```

The reader emits one `<result>` value, sliced to the active trigger word: `counts` returns line 1; `apps` returns the `INTEL_APP …` lines (or `IntelApps:None`); `both` (default) returns everything.

### DetectionSource values

The scan runs two engines — the `system_profiler` primary and the direct `lipo` disk scan — and reconciles them. `DetectionSource` records which path produced the value and whether it was cross-checked:

| Value | Meaning |
| --- | --- |
| `SystemProfiler+DirectReconciled` | Primary was Complete **and** agreed with the direct disk scan on the Intel-only count and total in-scope bundle count. Trusted; primary inventory presented. |
| `SystemProfiler+DirectMismatch` | Primary was Complete but disagreed with disk (or disk was Partial). Failed closed to `Partial`; the direct scan's inventory is presented (it surfaces the omitted app). |
| `SystemProfiler+ReconcileUnavailable` | Primary was Complete but the reconciling disk scan could not run. Primary inventory kept, marked `Partial`. |
| `DirectBundleScan` | Primary was Partial to begin with, so the direct disk scan is the engine of record. |
| `SystemProfiler+FallbackFailed` | Primary was Partial and the fallback disk scan could not run either. |
| `SystemProfiler` | Standalone primary path before any fallback (rare in practice). |

**Reconciliation, briefly.** `system_profiler` can return a well-formed list that silently omits installed bundles, and nothing in its own output proves the list is exhaustive. So a Complete primary is not trusted on its own — it is cross-checked against an independent filesystem walk. The two must agree on the Intel-only count and the total in-scope bundle count, and the disk scan must itself be Complete. Any disagreement, or a disk scan that is itself Partial or cannot run, fails closed to `ScanStatus:Partial`. On a real mismatch the direct scan's inventory wins, because that is the engine that just found the bundle `system_profiler` missed.

### Reader sentinels

| Sentinel | Meaning |
| --- | --- |
| `NOT_COLLECTED` | No state file yet, or its mtime is unreadable (collector installed moments ago, or this Mac is out of scope for the install policy). |
| `STALE (collector has not run in <n>s, threshold <t>s; last collected: <time>). Cached value follows:\n<value>` | The state file is older than 2× the configured interval. The last-known-good value (sliced to the same view) is still surfaced beneath the flag. |
| `MALFORMED_CACHE` | The `apps` view found a cache that exists but has no recognizable app-list section — counts-only, truncated, or an older/foreign format. Returned instead of a reassuring `IntelApps:None`, so a corrupt cache can never masquerade as a migrated Mac. |
| `TRUNCATED: <n> Intel-only app(s) omitted...` | The `apps` list hit the 24000-char cap; the remaining `<n>` Intel-only apps are counted but not listed. The `counts` view still reports the full `IntelOnly:` total. |
| `IntelApps:None` | Reserved for a **validated** result: the collector wrote this marker because the machine genuinely has zero Intel-only apps. |

## Smart Group scoping recipes

Assumes an EA named **Intel App Auditor**. Count- and status-based criteria need the `counts` or `both` trigger word; app-name criteria need `apps` or `both`.

| Intent | Criteria |
| --- | --- |
| **Trustworthy migrated Mac** (compound — use all six) | `Intel App Auditor` `does not contain` `NOT_COLLECTED` **and** `does not contain` `STALE` **and** `does not contain` `MALFORMED_CACHE` **and** `contains` `ScanStatus:Complete` **and** `contains` `Unknown:0` **and** `contains` `IntelOnly:0` |
| **Still has Intel apps** | `Intel App Auditor` `matches regex` `IntelOnly:[1-9]` |
| **Has a specific Intel-only app installed** | `Intel App Auditor` `like` `INTEL_APP \| Final Cut Pro` (apps / both view) |
| **Needs attention / untrustworthy read** | `Intel App Auditor` `like` `ScanStatus:Partial` **or** `like` `STALE` **or** `is` `NOT_COLLECTED` **or** `like` `MALFORMED_CACHE` |
| **Rosetta runtime present** | `Intel App Auditor` `like` `RosettaRuntimePresent:Yes` |

> **Never smart-group "migrated" on `IntelOnly:0` alone.** `IntelOnly:0` also appears in a `Partial` scan, a stale cache, and every other view that happens to contain the substring. A Mac is only trustworthy-migrated when it is **not** `NOT_COLLECTED`, **not** `STALE`, **not** `MALFORMED_CACHE`, is `ScanStatus:Complete`, has `Unknown:0`, and has `IntelOnly:0` — hence the compound criteria above. Build the "still has Intel apps" group as the compound-inverse (any of the untrustworthy states, or `IntelOnly` matching `[1-9]`), so a degraded read never lands in either clean bucket by accident.

## Detection details

- **Classification (primary).** `arch_i64` → IntelOnly; `arch_arm_i64` → Universal; `arch_arm` → AppleSilicon; `arch_ios` → iOS; `arch_other` → Other. Missing or unrecognized `arch_kind` → Unknown, which forces `ScanStatus:Partial`.
- **Classification (direct `lipo` scan).** `x86_64` → IntelOnly; `x86_64`+`arm64` → Universal; `arm64` / `arm64e` → AppleSilicon. A pure `i386` (32-bit) binary → **Unknown**, not IntelOnly: only `x86_64` is a Rosetta 2 translation target, and 32-bit Intel code has not run on macOS since Catalina. A `lipo`-unrecognized main executable is `Other` only when `file(1)` reports a real text (shebang-script) executable; anything else stays Unknown → Partial.
- **Never a silent drop.** A record with no path is counted as Unknown and forces Partial (validated *before* scope filtering), so a missing-path record can never disappear into a clean zero.
- **Scope.** Application bundles under the configured roots (default `/Applications`, `/Applications/Utilities`), matched component-wise so `/ApplicationsBackup` is rejected. `~/Applications` is added only when `SCAN_USER_APPS=1` **and** it exists. `EXTRA_ROOT` adds one absolute directory if it exists and contains no EA-delimiter characters. Only each bundle's **top-level** architecture is classified — not nested helpers, frameworks, plug-ins, login items, or CLI tools (a Universal app can bundle an Intel-only helper), and not execution history.
- **Rosetta.** `RosettaRuntimePresent` is `Yes`/`No` on Apple silicon and `N/A` on Intel Macs. It is a **file-presence signal only** — it checks for `/Library/Apple/usr/libexec/oah/libRosettaRuntime` and nothing more. It is not proof that Rosetta is installed correctly or that any Intel app can launch.

## launchd behavior

The installed collector plist sets:

- **`StartInterval 604800`** — a 7-day default cadence (one install parameter; any interval ≥ 600 s).
- **`RunAtLoad true`** — the collector runs once the moment it is loaded, so the first value appears without waiting a full interval.
- **`ProcessType Background`** — a Background classification that applies CPU/I/O resource limits to protect the user experience. This is resource-limited scheduling, **not** "lowest priority."

`StartInterval` firings are missed while the Mac is asleep or while a prior run is still in progress — expected for a periodic background job, and the reader's `STALE` sentinel surfaces it if a Mac goes quiet for longer than 2× the interval.

## Maintenance and tests

`install.sh` is **generated**; do not hand-edit it. Edit the engine ([`intel-app-auditor.zsh`](./intel-app-auditor.zsh)) and/or the template ([`install.sh.in`](./install.sh.in)), then run [`./build-installer.sh`](./build-installer.sh) to re-embed the engine verbatim. The test suite includes a **build-drift guard** that fails if `install.sh` ever diverges from a fresh build.

```sh
zsh test_intel-app-auditor.zsh   # full suite: 179 assertions, 0 failures on a stock Mac
./build-installer.sh             # regenerate install.sh after an engine edit
```

The suite covers the pure classifiers, the JXA parser against captured fixtures, the direct `lipo` fallback, primary/direct reconciliation (an agreeing pair stays Complete; a mismatch flips a false-clean to Partial and surfaces the omitted Intel app), the collector's atomic state write, the reader's three trigger words and its `NOT_COLLECTED` / `STALE` / `MALFORMED_CACHE` sentinels (a counts-only cache returns `MALFORMED_CACHE`, never `IntelApps:None`), the i386 and garbage-executable edge cases, and the installer / plist contract (modern `launchctl` subcommands, `--uninstall`, `StartInterval`, `ProcessType`, `MODE=collector` env), plus the build-drift guard.

Both scripts are written in **zsh** (`#!/bin/zsh --no-rcs`). zsh has been the macOS default login shell since Catalina (10.15) and ships in every currently supported macOS. `--no-rcs` skips all user/site zsh startup files, so both scripts run in a clean, deterministic environment no matter whose account or dotfiles are present. Verification is `zsh -n` on the zsh scripts (shellcheck has no zsh mode), `sh -n` on `install.sh`, and `plutil -lint` on the plist.

## Security note

- The collector runs **as root** under `launchd` and writes the state file **root-only** (`/var/db/intel-app-auditor` is `0700`, `result.txt` is `0600`). A non-root user must not be able to forge a `<result>` the root reader trusts verbatim at recon.
- Writes are **atomic**: the collector writes a temp file in the same directory, then `mv -f`s it into place, so a reader only ever sees a complete file.
- App names and paths are **XML-escaped and control-character-scrubbed** by the collector before they enter the cache, so a hostile app name can't inject a second `<result>` tag when the reader wraps the value; the reader does not re-escape.
- **Zero network calls**, ever. Every check (`system_profiler`, `lipo`) is local. Nothing in this project makes an HTTP request.

## Verification snapshot

A single dated run on one Mac (macOS 15.4.1, arm64, Spotlight disabled) — one machine, one moment, not a fleet figure:

```text
IntelOnly:27;Universal:109;AppleSilicon:28;iOS:6;Other:5;Unknown:0;ScanStatus:Complete;DetectionSource:DirectBundleScan;RosettaRuntimePresent:Yes;Arch:arm64;Scope:/Applications,/Applications/Utilities
```

Here `system_profiler` returned an empty application array, so the direct `lipo` disk scan was the engine of record (`DetectionSource:DirectBundleScan`). Scan time is machine-dependent; the point of the split is to keep whatever it costs off Jamf's recon clock, not to hit a fixed duration.

## FAQ

**Why does this matter now?** Apple has signaled that Rosetta 2 is on a wind-down: it remains available through the next couple of macOS releases largely for developer and gaming use, then narrows. Before it goes away, you want a hard answer to "which Macs still depend on Intel-only apps, and which apps," so you can replace, repackage, or retire them on your schedule instead of discovering the gap when an app stops launching.

**Does it slow down Jamf recon?** No. Recon runs the thin reader, which `stat`s and reads one small local file and finishes in well under a second. The `system_profiler` + `lipo` scan happens on the collector's own launchd schedule, never during recon.

**Does it send any data off the Mac?** No. There are no network calls anywhere in the project; both `system_profiler` and `lipo` are local. Findings leave the Mac only inside the normal Jamf inventory submission.

**Which Jamf Pro tiers does it work with?** Any tier that supports script Extension Attributes and policies. It has no dependency on any Jamf add-on.

**Why not just match `IntelOnly:0`?** Because that substring also appears in a `Partial` scan, a `STALE` cache, and a `NOT_COLLECTED` read. A Mac is only trustworthy-migrated under the compound criteria in [Smart Group scoping recipes](#smart-group-scoping-recipes) — `ScanStatus:Complete`, `Unknown:0`, `IntelOnly:0`, and none of the failure sentinels.

**Does `RosettaRuntimePresent:Yes` mean an app can run?** No. It is a file-presence signal only (`/Library/Apple/usr/libexec/oah/libRosettaRuntime`). It is not proof Rosetta is installed correctly or that any specific Intel app will launch.

**Can I change how often it scans?** Yes. Jamf policy script parameter 6 sets the interval (default 7 days, minimum 10 minutes). The installer records the value in `/var/db/intel-app-auditor/interval` and the reader treats 2× that as its staleness threshold, so no reader edit is needed.

**Does it detect Intel-only helpers or frameworks inside a Universal app?** No. Only each bundle's top-level architecture is classified. A Universal app can still ship an Intel-only helper; that is out of scope for a top-level bundle audit.

## Contributing

Pull requests are welcome. Edit the engine ([`intel-app-auditor.zsh`](./intel-app-auditor.zsh)) or the template ([`install.sh.in`](./install.sh.in)) — never the generated `install.sh` — then run [`./build-installer.sh`](./build-installer.sh) to re-embed the engine. Run `zsh test_intel-app-auditor.zsh` before and after any change and keep the suite green (the build-drift guard fails if `install.sh` is out of sync). See the repository [`CONTRIBUTING.md`](../../../CONTRIBUTING.md) for the ground rules on script headers, secrets, and testing.

## License

This project is released under the [MIT License](./LICENSE). Every script carries an `SPDX-License-Identifier: MIT` header; the full license text lives in [`LICENSE`](./LICENSE). Copyright (c) 2026 Robert Flanagan.

<!-- analytics: view-count pixel to be added in a follow-up pass (mint the ID in the Umami dashboard at analytics.mdm.tools, matching the sibling READMEs), the same way the existing pixels were batch-added repo-wide. -->
