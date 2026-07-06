<!-- SPDX-FileCopyrightText: 2026 Robert Flanagan and macadmin-toolbox contributors -->
<!-- SPDX-License-Identifier: MIT -->

# AI Software Inventory: a Jamf Pro Extension Attribute for macOS

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE) ![Platform: macOS 12 through 26](https://img.shields.io/badge/platform-macOS%2012%E2%80%9326-lightgrey.svg) ![Shell: zsh](https://img.shields.io/badge/shell-zsh-89e051.svg) ![Jamf Pro: any tier](https://img.shields.io/badge/Jamf%20Pro-any%20tier-orange.svg) ![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

Find shadow AI on managed Macs. This is a Jamf Pro Extension Attribute (EA) with a background collector that inventories the AI software installed on each Mac: desktop apps (ChatGPT, Claude, Cursor, Windsurf, Ollama, LM Studio, Perplexity, and many more), CLI coding agents (Claude Code, OpenAI Codex, Gemini CLI, GitHub Copilot CLI, Aider), editor AI extensions, browser AI extensions, and MCP (Model Context Protocol) configuration. The result is readable in the computer record and usable as Smart Group scope criteria. It reports *local, installed* AI tooling; it does not see browser-based web AI, tenant/cloud AI, or personal-account use (see [What it does not detect](#what-it-does-not-detect-by-design)).

This is the free, any-tier complement to the **SEE** phase of Jamf's AI Governance product. Jamf's native discovery watches live usage events on-device (Jamf's launch demo describes events "collected from the endpoints themselves using the endpoint security API"; the launch press release says its telemetry agent "uses native and high-performance macOS frameworks") and ships as part of the Jamf for Mac, Hi-Ed, Business, and Enterprise plans. This EA answers the static version of the same first question (*which Macs have AI tooling installed, and of what kind?*) on any Jamf Pro tier, today. The only moving parts are the Jamf binary you already have and the small launchd-scheduled collector script this project installs. You then use its value to scope manual governance profiles to exactly the machines that run those tools.

> Where it fits: **SEE** (discover) → **DECIDE** (this EA scopes managed configuration profiles that enforce policy) → **PROVE** (Smart Group membership is your audit-ready record of who has what).

## Table of contents

- [Quick start](#quick-start)
- [Repository layout](#repository-layout)
- [Architecture: collector → file → EA](#architecture-collector--file--ea)
- [Install via a Jamf policy](#install-via-a-jamf-policy)
- [Output format](#output-format)
- [Verify-and-annotate](#verify-and-annotate)
- [Smart Group scoping recipes](#smart-group-scoping-recipes)
- [Detection layers](#detection-layers)
- [Where it looks](#where-it-looks)
- [What it does not detect by design](#what-it-does-not-detect-by-design)
- [Cadence and performance cost](#cadence-and-performance-cost)
- [Staleness / NOT_COLLECTED sentinels](#staleness--not_collected-sentinels)
- [Uninstall](#uninstall)
- [Security note](#security-note)
- [Optional Full Disk Access](#optional-full-disk-access)
- [Rebranding this open-source project](#rebranding-this-open-source-project)
- [Shell & portability](#shell--portability)
- [Maintenance](#maintenance)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)

## Quick start

1. Deploy [`install.sh`](./install.sh) fleet-wide from a Jamf Pro policy (as root, once per computer). It installs the collector and LaunchDaemon; the first scan runs within seconds.
2. Create a computer Extension Attribute (Data Type **String**, Input Type **Script**) and paste in [`ai-software-inventory-ea.zsh`](./ai-software-inventory-ea.zsh).
3. Build Smart Groups on the value. Start with `AI Software Inventory` `like` `SUMMARY:` for "any AI software present", then see [Smart Group scoping recipes](#smart-group-scoping-recipes).

## Repository layout

| File | Purpose |
| --- | --- |
| [`ai-software-inventory-ea.zsh`](./ai-software-inventory-ea.zsh) | The thin EA reader. Paste this into Jamf Pro. |
| [`ai-inventory-collector.zsh`](./ai-inventory-collector.zsh) | The background scanner, and the single source of truth for detection logic. |
| [`install.sh`](./install.sh) | Self-contained installer for a Jamf policy (generated; collector embedded). |
| [`install.sh.in`](./install.sh.in) | Installer template consumed by the build script. |
| [`build-installer.sh`](./build-installer.sh) | Regenerates `install.sh` after any collector edit. |
| [`io.github.ai-software-inventory.collector.plist`](./io.github.ai-software-inventory.collector.plist) | Reference LaunchDaemon plist (the installer generates the deployed copy). |
| [`pppc-full-disk-access.mobileconfig`](./pppc-full-disk-access.mobileconfig) | Optional PPPC profile granting Full Disk Access, with caveats documented inside. |
| [`test-ai-ea.zsh`](./test-ai-ea.zsh) | Local test harness; non-zero exit on any failure. |
| [`LICENSE`](./LICENSE) | MIT license. |

---

## Architecture: collector → file → EA

This project is a **two-piece split**, not a single script:

```text
LaunchDaemon (every 4h, background)
        │
        ▼
ai-inventory-collector.zsh   ──writes──▶  /var/db/ai-software-inventory/result.txt
  (heavy scanner, runs as root)                   │
                                                   │ reads (root, at recon)
                                                   ▼
                                    ai-software-inventory-ea.zsh
                                       (thin reader: the Jamf EA)
                                                   │
                                                   ▼
                                          Jamf Pro computer record
                                          + Smart Group criteria
```

1. `ai-inventory-collector.zsh`: the heavy scanner. Walks every `/Applications` tree, every user's CLI/config directories, editor extension folders, browser extension manifests, and MCP config files; runs `codesign` on unmatched apps to catch AI-native vendors by Developer ID. It runs on its own schedule via a **LaunchDaemon**, decoupled from Jamf recon, and writes its findings to a small state file on disk.
2. `ai-software-inventory-ea.zsh`: the thin reader. This is the script you paste into the Jamf EA. It does no scanning; it just `stat`s and `cat`s the collector's state file and wraps the cached value in `<result>...</result>`. It runs in well under a second, every time.

### Why a background LaunchDaemon + file beats a heavy recon-time EA

A single-file EA that does the full filesystem sweep works, and is what version 1 of this project was, but it pays scan cost at every recon, on Jamf's clock. Recon runs every EA script serially and waits on each one, so a slow EA stretches (and a hung EA stalls) the whole inventory submission. That's backwards for a scan whose underlying state barely changes minute-to-minute: someone installing Ollama at 2:14pm doesn't need it reflected in inventory at 2:14pm, and if it is, the *reason* was an expensive scan blocking recon to get there.

Splitting the work fixes both problems:

- Recon never scans. The EA reads one small local file, with no `find` walk, no `codesign` calls, and no per-user directory iteration at recon time, so this EA can never be the reason recon took four minutes on a given Mac.
- The scan runs on its own budget: every 4 hours under `launchd`, with `ProcessType Background` (lowest scheduling/thermal priority; it yields to anything the user is actively doing) and its own execution window.
- Freshness is bounded and observable. The EA also tells you whether its value is current (see **Staleness** below), so "the collector silently stopped running two weeks ago" becomes a visible, scopable Smart Group condition instead of a silent blind spot.

---

## Install via a Jamf policy

### 1. Deploy the collector + LaunchDaemon fleet-wide

`install.sh` is fully self-contained: the collector (`ai-inventory-collector.zsh`) is embedded inside it via a heredoc, so there is nothing to co-locate: no second Script payload, no staged collector file, no `.pkg`/DMG. Deliver it as one Jamf Pro policy **Scripts** payload (or a **Files and Processes** "Execute Command" that runs `install.sh`) that runs the single file, and it writes the collector, state directory, and LaunchDaemon itself. `install.sh` is idempotent, so scope the policy to run once per computer (or recurring check-in with an idempotent-safe cadence, since re-running it just reinstalls in place) rather than "once every day."

```bash
sudo ./install.sh
```

### Jamf Pro script parameters

Everything an admin may want to customize is exposed as policy script parameters, with no need to edit the script for a standard deployment (Jamf consumes `$1`–`$3` with mount point / computer name / username; your parameters start at 4):

| Parameter | Meaning | Default |
| --- | --- | --- |
| **4** | Action: blank or `install` installs; `--uninstall` / `uninstall` removes | install |
| **5** | `REVERSE_DOMAIN`: your org's reverse-DNS namespace for the LaunchDaemon label + plist filename | `io.github.ai-software-inventory` |
| **6** | Collection interval in seconds (validated: integer, ≥ 600) | `14400` (4 h) |
| **7** | Collector log path (validated: absolute) | `/var/log/ai-software-inventory.collector.log` |
| 8–11 | unused | none |

> **Two cross-contracts to respect.** (1) The installer records parameter 6 in `/var/db/ai-software-inventory/interval`, and the EA reader flags `STALE` at 2× that value (falling back to 28800 s if the file is missing), so a custom interval propagates to the staleness check on its own. (2) An **uninstall policy must pass the same parameter 5** used at install time, or the `bootout` targets the wrong LaunchDaemon label; the uninstaller warns when the expected plist is absent.

What it does:

- Installs the collector to `/usr/local/ai-software-inventory/ai-inventory-collector.zsh` (`root:wheel`, `0755`).
- Creates `/var/db/ai-software-inventory/` (`root:wheel`, `0700`), the root-only state directory.
- Writes `/Library/LaunchDaemons/io.github.ai-software-inventory.collector.plist` (`root:wheel`, `0644`).
- Loads it with modern `launchctl` subcommands: `bootout` (clean any prior instance) → `enable` → `bootstrap system` → `kickstart -k` (force an immediate first run). It never touches the deprecated `load`/`unload`.

Uninstall the same way:

```bash
sudo ./install.sh --uninstall
```

which `bootout`s the daemon and removes the installed script, plist, and state directory (the log file is left in place; rotate or remove it separately if you want).

> **Maintainers.** `install.sh` is generated; do not hand-edit it. Edit [`ai-inventory-collector.zsh`](./ai-inventory-collector.zsh) (the single source of truth for detection) and/or the installer template [`install.sh.in`](./install.sh.in), then run `./build-installer.sh` to regenerate `install.sh` with the collector re-embedded verbatim. The build is idempotent (same inputs → byte-identical `install.sh`), and `test-ai-ea.zsh` includes a drift guard that fails if the embedded copy ever diverges from `ai-inventory-collector.zsh`.

### 2. Point a Jamf Extension Attribute at the reader

1. Jamf Pro → **Settings → Computer Management → Extension Attributes → New**.
2. Display Name: `AI Software Inventory`
3. Data Type: `String`
4. Inventory Display: **Extension Attributes** (keeps this audit signal grouped with your other EAs in the computer record and in Advanced Search / report column pickers).
5. Input Type: `Script` → paste the full contents of [`ai-software-inventory-ea.zsh`](./ai-software-inventory-ea.zsh): the thin reader, not the collector.
6. Save. The EA is collected at every inventory (recon) and completes in well under a second, because it isn't scanning anything.

> **The reader is useless without the collector running somewhere.** Deploy step 1 to your fleet *before* (or in the same policy scope as) this EA, or every Mac will just report `NOT_COLLECTED` forever.
>
> **Retain history when you disable it.** If you ever remove or disable this EA, set **Manage Existing Data → RETAIN** rather than *Delete*. RETAIN preserves the last-collected value on every computer record, so your AI-inventory audit history (and any Smart Group built on it) survives the change instead of being wiped fleet-wide.

---

## Output format

The reader emits one `<result>` value, in one of four shapes:

### Normal: collector has run recently

```text
SUMMARY: 7 finding(s); categories: ai-app, ai-cli, ai-unknown-review, ide-ai-extension, mcp-config
APP | Claude (Anthropic) | com.anthropic.claudefordesktop | /Applications/Claude.app
APP | Ollama (local LLM runtime) | com.electron.ollama | /Applications/Ollama.app
CLI | Claude Code (Anthropic) | claude | /opt/homebrew/bin/claude; /Users/jdoe/.claude
CLI | OpenAI Codex | codex | /opt/homebrew/bin/codex; /Users/jdoe/.codex
HEURISTIC | Grammarly Desktop (AI keyword) | com.grammarly.ProjectLlama | /Applications/Grammarly Desktop.app
IDE-EXT | github.copilot | .vscode | /Users/jdoe/.vscode/extensions/github.copilot-1.2.3
MCP | Claude Desktop MCP | configured | /Users/jdoe/Library/Application Support/Claude/claude_desktop_config.json
```

Findings are sorted by category, and each line is **one tool**: when several detection prongs hit the same tool (binary + config dir + npm/pipx/uv package, or the same binary in two bin dirs), the evidence paths are merged into the location field, `;`-separated, so the count is a true tool count, not an evidence count.

### Nothing found

```text
None
```

### Collector has never run on this Mac

```text
NOT_COLLECTED
```

The LaunchDaemon hasn't produced a state file yet, usually because the collector was installed moments ago (`RunAtLoad` fires it immediately, so this should self-resolve within seconds) or because this Mac is out of scope for the collector-install policy.

### Stale: collector stopped running

```text
STALE (collector has not run in 93600s, threshold 28800s; last collected: 2026-06-28 14:02:11 UTC). Cached value follows:
SUMMARY: 8 finding(s); categories: ai-app, ai-cli
APP | Claude (Anthropic) | com.anthropic.claudefordesktop | /Applications/Claude.app
...
```

The state file's mtime is older than the **staleness threshold** (8 hours, twice the 4-hour collection interval, so one missed cycle doesn't false-alarm, but two in a row does). The reader still surfaces the last-known-good cached value beneath the flag. A stale answer is more useful to an admin triaging a broken LaunchDaemon than no answer at all, and the flag itself is the signal that something needs attention on that Mac (check `launchctl print system/io.github.ai-software-inventory.collector` and `/var/log/ai-software-inventory.collector.log`).

- Line 1 is a machine-scopable summary: a count plus the category keywords present.
- Each finding is `CATEGORY | Friendly Name | identifier | location(s)`, pipe-delimited (parseable), sorted, and collapsed to one line per tool (multi-prong evidence merges into the location field, `;`-separated), so the value is stable across recons and doesn't create inventory-change noise. Multi-line `<result>` values are valid in Jamf Pro.

### Categories

| Category | Summary keyword | Meaning |
| --- | --- | --- |
| `APP` | `ai-app` | AI desktop application (Claude, ChatGPT, Cursor, Ollama, LM Studio, …) |
| `CLI` | `ai-cli` | AI command-line agent / config dir / npm / pipx (claude, codex, gemini, aider, …) |
| `IDE-EXT` | `ide-ai-extension` | Editor AI extension/plugin (Copilot, Continue, Cody, Cline, Codeium, JetBrains AI, …) |
| `BROWSER-EXT` | `browser-ai-extension` | Browser AI extension (best-effort manifest scan of Chromium-family browsers) |
| `MCP` | `mcp-config` | Model Context Protocol configured; an agentic tool-calling surface exists |
| `HEURISTIC` | `ai-unknown-review` | Matched the AI keyword heuristic, or failed a signature check, but is not a confirmed signature. Review it |

The `HEURISTIC` bucket is intentional: emerging/unknown AI tools, and any signature-verify failure, surface for a human decision instead of being silently trusted or quietly dropped.

---

## Verify-and-annotate

Detection has three layers (most authoritative first): known signatures → Developer ID (Team Identifier) → keyword heuristic. The Developer-ID layer trusts an app because Apple's code-signing chain says it belongs to a curated AI-native vendor (`teamid_known()`: Anthropic, OpenAI, Ollama's publisher, and others). That's powerful, because it catches renamed or brand-new apps from those vendors, but it's also the layer most worth double-checking: a Team ID string alone doesn't prove the on-disk binary hasn't been tampered with since it was signed.

So for every app that matches via the Team-ID layer, the **collector** also runs an offline `codesign --verify` against the app bundle (this checks the on-disk signature against its own embedded seal and does not touch the network; that's `spctl`'s notarization/revocation check, which this project deliberately never calls):

- Pass → the app is emitted as `APP`, and its `[Team XXXX]` annotation gains a `verified` suffix: `[Team Q6L2SF6YDW verified]`.
- Fail → the app is not dropped: it's still emitted, but rerouted into the `HEURISTIC` review category with `[Team XXXX UNVERIFIED]`, plus a `(Developer ID: <vendor>, signature FAILED verify)` clause. An allowlisted vendor's Team ID whose on-disk signature no longer validates is exactly the spoof/tamper scenario that should be loud, not silently trusted through.

This is the one new behavior on top of the original single-file EA's detection logic; every signature table, scan path, and the heuristic regex are otherwise unchanged (see **Detection layers** below).

---

## Smart Group scoping recipes

Use positive matches. A Mac whose collector has never run reports `NOT_COLLECTED`, and a Mac with nothing found reports `None`; neither is an empty string, but a naïve `is not "None"` would still false-match a `NOT_COLLECTED` Mac as having AI software, so match the summary keywords or specific tool names instead. Keep the criteria list short: each of these is a substring (`like`) match against a multi-line text value, and every Smart Group you add is one more thing Jamf recalculates at inventory submission.

| Smart Group intent | Criteria |
| --- | --- |
| **Any AI software present** | `AI Software Inventory`  `like`  `SUMMARY:` |
| **No AI software (confirmed)** | `AI Software Inventory`  `is`  `None` |
| **Collector has never run** | `AI Software Inventory`  `is`  `NOT_COLLECTED` |
| **Collector stalled / stopped** | `AI Software Inventory`  `like`  `STALE` |
| **Has an AI coding-agent CLI** | `AI Software Inventory`  `like`  `ai-cli` |
| **Has an AI desktop app** | `AI Software Inventory`  `like`  `ai-app` |
| **Has an editor AI extension** | `AI Software Inventory`  `like`  `ide-ai-extension` |
| **Has MCP configured** (agentic risk surface) | `AI Software Inventory`  `like`  `mcp-config` |
| **Needs human review** (unknown AI, or a failed signature check) | `AI Software Inventory`  `like`  `ai-unknown-review` |
| **Runs Claude Code specifically** | `AI Software Inventory`  `like`  `Claude Code` |
| **Runs OpenAI Codex specifically** | `AI Software Inventory`  `like`  `Codex` |
| **Runs a local LLM runtime** | `AI Software Inventory`  `like`  `local LLM runtime` |

### Discovery-driven targeting, not detection-gated enforcement

Use this inventory to target governance, but don't make first-time enforcement wait on detection. If a Mac only receives controls *after* it's been detected running a tool, its **first use is ungoverned** (there's a collection-interval lag), and later removal or renaming of the tool could silently drop it from a detection-based scope. The safer pattern:

1. Deploy baseline controls by role/group: e.g. everyone in an engineering group gets the Claude Code / Codex managed-preference profiles, so enforcement is never gated on detection latency.
2. Use this EA for discovery, review, and *tighter* targeting: find Macs running tools your baseline didn't anticipate, triage `ai-unknown-review` items, and scope *additional* or stricter profiles where the data warrants.

Build a Smart Group per tool (e.g. `AI Software Inventory` `like` `Claude Code`) for visibility and incremental tightening, as a complement to role-based baselines, not a replacement for them.

---

## Detection layers

Findings are produced by three layers, most-authoritative first:

1. Known signatures: curated bundle IDs, binary names, extension `publisher.name` IDs, and 32-char Chrome Web Store extension IDs. Low false positive.
2. Developer ID (code-signing Team Identifier): each unmatched app is run through `codesign` and its Apple-verified **Team Identifier** is checked against a curated allowlist of **AI-native vendors** (`teamid_known()`). Because these vendors' entire business is AI, *any* app they sign is AI, so this catches unknown, renamed, or future apps from them (Anthropic, OpenAI, Perplexity, Ollama, LM Studio, Granola, Otter, Krisp, Cluely, BoltAI, and more). Vendors that also ship non-AI products (e.g. Zed, Sourcegraph) are deliberately *not* in the Team-ID allowlist; they're detected by their specific bundle ID / extension / CLI instead.
   - Deliberately excluded (they sign non-AI software too, so allowlisting their Team ID would false-positive): Microsoft `UBF8T346G9` (Word/Excel/VS Code), Google `EQHXZ8M8AV` (Chrome/Drive), Amazon `94KV3E626L` (also signs Kiro), ByteDance, and ToDesktop `VDXQ22DGB9` (Cursor's packager, a shared cert across many Electron apps). Detected by bundle ID / name instead.
   - Every Team-ID match is also verify-and-annotated by the collector; see above.
3. Heuristic: distinctive AI keyword or `.ai` reverse-domain hits not in any table (or a failed signature check) land in the `HEURISTIC` (`ai-unknown-review`) bucket for human review.

## Where it looks

- Desktop apps: `/Applications`, `/Applications/Utilities`, `/System/Applications/Utilities`, and every user's `~/Applications`.
- CLIs: binaries in system + per-user bin dirs (`/usr/local/bin`, `/opt/homebrew/bin`, `~/.local/bin`, `~/.cargo/bin`, `~/.deno/bin`, `~/.bun/bin`, `~/Library/pnpm`, `~/.volta/bin`, `~/.asdf/shims`, `~/.claude/local`, …); per-user **config dirs** (`~/.claude`, `~/.codex`, `~/.continue`, `~/.factory`, `~/.grok`, `~/.aws/amazonq`, …), which is also how agents with generic binary names (Amazon Q `q`, Continue `cn`, ForgeCode `forge`, Grok `grok`) are caught without false-positiving on unrelated tools; global npm/yarn packages; pipx venvs; and uv tools.
- Editor extensions: VS Code / Insiders / VSCodium / Cursor / Windsurf / Antigravity extension dirs, plus JetBrains plugin folders.
- Browser extensions: Chromium-family (`Chrome`, `Edge`, `Brave`, `Chromium`, `Vivaldi`, `Comet`, `Arc`, `Dia`): known store IDs matched precisely, plus a bounded manifest-name heuristic for the rest.
- MCP: every stable per-user (and system-scope) on-disk MCP surface across the mainstream clients:
- Claude Desktop: `claude_desktop_config.json` *and* Desktop Extensions (`.mcpb`/`.dxt` bundles under `~/Library/Application Support/Claude/Claude Extensions/`, which never appear in the config file).
- Claude Code: `~/.claude.json` (user scope), plugin-provided MCP manifests under `~/.claude/plugins/`, and the fleet-managed `/Library/Application Support/ClaudeCode/managed-mcp.json`.
- VS Code family: user-profile `mcp.json` (`~/Library/Application Support/Code/User/mcp.json`, incl. non-default profiles, plus Insiders and VSCodium). This is the file behind **MCP: Open User Configuration**, not `~/.vscode`, which only holds extensions.
- Cursor: `~/.cursor/mcp.json`.
- OpenAI Codex: `~/.codex/config.toml` (`[mcp_servers.*]`).
- Gemini CLI: `~/.gemini/settings.json` (`mcpServers`).
- Kiro: `~/.kiro/settings/mcp.json`.
- Windsurf: `~/.codeium/windsurf/mcp_config.json`.
- Zed: `~/.config/zed/settings.json` (`context_servers`).
- LM Studio: `~/.lmstudio/mcp.json`.
- Goose: `~/.config/goose/config.yaml` (`extensions`).

## What it does not detect by design

Consistent with the project's own research, an endpoint scanner cannot see:

- Browser-based web AI (e.g. `chatgpt.com` in a tab): govern at the network/DNS/SASE or browser-policy layer.
- Tenant / cloud AI (e.g. Microsoft 365 Copilot): govern at the tenant.
- Personal-account use of an approved app: needs identity/tenant controls, not endpoint discovery.
- Per-project MCP configs (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` inside arbitrary repos): finding those means walking every checkout on disk; the per-user scopes above are the stable, bounded signal.
- Remote / hosted MCP connectors (e.g. claude.ai connectors, in-app OAuth'd remote servers): they live server-side and never touch the local disk.

---

## Cadence and performance cost

- 4-hour interval (`StartInterval 14400`): frequent enough that new AI tooling shows up in inventory the same day it's installed, without scanning so often that it's ever meaningfully competing for I/O. Per Apple's `launchd.plist(5)`, a `StartInterval` firing that comes due while the Mac is **asleep** is silently skipped (not queued for wake), so a laptop that sleeps through a window collects on its next awake interval. That's acceptable for a 4-hour inventory cadence, and any prolonged gap surfaces via the reader's `STALE` sentinel. If you require guaranteed post-wake collection instead, swap `StartInterval` for a `StartCalendarInterval`, which `launchd` runs at the next wake after a missed slot.
- `ProcessType Background`: tells `launchd` this daemon is the lowest scheduling and I/O priority class on the system. It runs opportunistically and yields to anything the user (or a higher-priority daemon) is actively doing, so a scan landing while someone's mid-task doesn't cost them anything perceptible.
- `RunAtLoad true`: the first scan fires immediately on install/boot rather than waiting up to 4 hours for the first data point, so `NOT_COLLECTED` resolves fast on newly-provisioned Macs.
- No network calls, ever: every check (`codesign --verify` included) is purely local. Nothing in this project makes an HTTP request, hits Apple's notarization service, or calls `spctl`.
- Recon cost is now a `stat` + a `cat`: the actual EA that Jamf recon executes reads one small local file. That's it.

---

## Staleness / NOT_COLLECTED sentinels

Two failure sentinels exist so "nothing to report" and "something is broken" are never confused with each other:

- `NOT_COLLECTED`: the state file doesn't exist yet. Either the collector was installed recently (should self-resolve within seconds, since `RunAtLoad` fires an immediate first run) or this Mac never got the collector-install policy.
- `STALE (...)`: the state file exists, but its mtime is older than `STALE_THRESHOLD` (28800s / 8h, twice the 4h collection interval, so one missed cycle doesn't alarm, but two in a row does). The reader still returns the last-known-good cached value beneath the flag, because a stale-but-present answer is strictly more useful to an admin than nothing: you can still see what was last known to be installed, you just also know to go check why the LaunchDaemon stopped running (`launchctl print system/io.github.ai-software-inventory.collector`, `/var/log/ai-software-inventory.collector.log`).

Both sentinels are directly scopable; see the Smart Group table above.

The collector is careful never to convert an infrastructure failure into a clean answer: if it cannot create its scratch workspace at all, it exits **without touching the state file**, so the failure surfaces as `STALE` (or `NOT_COLLECTED` on a Mac where no run has ever succeeded) rather than being recorded as a confirmed `None`.

---

## Uninstall

```bash
sudo ./install.sh --uninstall
```

Removes the LaunchDaemon (`launchctl bootout`), the installed collector script, the plist, and the state directory. If you also disabled/deleted the Jamf Extension Attribute, set **Manage Existing Data → RETAIN** (see **Install** above) to keep historical Smart Group data intact.

---

## Security note

- The collector runs **as root** (under `launchd`, system context) and writes the state file **root-only**: the state directory is `root:wheel 0700` and the state file itself is `root:wheel 0600`.
- Root-only, and not world-writable. The Jamf EA reader also runs as root at recon, so it is the *only* consumer; no other user needs to read the file. And its contents (usernames, application and MCP-config paths, the full AI-tool inventory) are **mildly sensitive**, so `0600` is the correct default rather than world-readable; inspect it with `sudo cat /var/db/ai-software-inventory/result.txt`. What **does** matter is that it is **not world-writable**: if a non-root local user could write this file, they could forge a fake `<result>` value (e.g. to spoof `None` and hide real findings, or spoof a finding to trigger unwanted Smart Group / policy behavior). Because the reader trusts the file's contents verbatim at recon (as root), that would be a local-privilege-adjacent integrity issue. Root-only write access closes that off.
- Writes are atomic. The collector writes to a temp file in the *same* directory as the state file, then `mv -f`s it into place. `mv` within one filesystem is an atomic rename, so a reader can only ever observe the previous complete file or the new complete file, never a half-written one, even if recon fires mid-write.
- Every user-controllable field (app names, paths, extension folder names) is XML-escaped and control-character-scrubbed (`xesc()`) by the **collector** before it ever reaches the state file, so a hostile app/file name can't inject a second `<result>` tag or malform the EA's output; the reader does not need to (and does not) re-escape.
- Zero network calls anywhere in this project, including the verify-and-annotate `codesign --verify` check (fully offline; it is distinct from `spctl`, which this project never invokes).

---

## Optional Full Disk Access

Running as **root does not bypass TCC** on modern macOS (Sonoma/Sequoia). The good news: the paths this collector reads (third-party `~/Library/Application Support/<app>` dirs, `~/.config`, `~/.vscode`, `/Applications`) are not individually TCC-protected, so in practice the daemon reads them without Full Disk Access.

**Recommended approach: deploy first, test empirically.** After installing the collector, watch `/var/log/ai-software-inventory.collector.log` for `operation not permitted` / TCC denials. If none appear, you don't need FDA.

If you *do* see denials, or you extend the scan to genuinely protected paths (`~/Desktop`, `~/Documents`, `~/Downloads`, `~/Library/Safari`, `~/Library/Mail`, iCloud Drive, removable volumes), apply the bundled optional profile:

- [`pppc-full-disk-access.mobileconfig`](./pppc-full-disk-access.mobileconfig): a PPPC profile granting `SystemPolicyAllFiles` (Full Disk Access) to `/bin/zsh`, matched by its Apple designated requirement (`identifier "com.apple.zsh" and anchor apple`). Deliver it via Jamf Pro → **Configuration Profiles** (unsigned `.mobileconfig` is fine for MDM delivery). MDM is the only way to grant FDA non-interactively; a root daemon can't self-authorize and there's no GUI prompt for a LaunchDaemon.

> **Caveat:** this grants FDA to `/bin/zsh` broadly, not just this collector, because a script's TCC identity is its *interpreter*. That's the inherent limitation of PPPC for script-based daemons. If that breadth is unacceptable in your environment, compile the collector into a signed standalone binary and scope the grant to *that* instead. Before deploying, change `PayloadOrganization` / the identifier prefix to your reverse-DNS and regenerate the two `PayloadUUID`s with `uuidgen`.

---

## Rebranding this open-source project

This project ships vendor-neutral by default (`io.github.ai-software-inventory` as the reverse-DNS namespace). If you're deploying it inside an organization and want your own namespace in the LaunchDaemon label and plist filename, set **Jamf policy script parameter 5** (see the parameters table above), or, for direct/non-Jamf runs, change exactly one variable default at the top of [`install.sh`](./install.sh):

```bash
REVERSE_DOMAIN="${5:-io.github.ai-software-inventory}"   # Jamf parameter 5, or edit the default
```

`install.sh` generates the LaunchDaemon plist at install time from this variable, so the Label and the plist filename update together; no other file needs editing. The log file name (and the install/state directories) derive from the separate `PROJECT` variable just below it; leave `PROJECT` alone, because the EA reader's state-file path contract (`/var/db/ai-software-inventory/result.txt`) depends on it.

---

## Shell & portability

Both `ai-inventory-collector.zsh` and `ai-software-inventory-ea.zsh` are written in **zsh** (`#!/bin/zsh --no-rcs`). zsh has been the macOS default login shell since Catalina (10.15) and ships in every currently supported macOS. `--no-rcs` skips all user/site zsh startup files, so both scripts run in a clean, deterministic environment no matter whose account or dotfiles are present (the collector always runs as root anyway; the reader does too, at recon).

The collector uses **real zsh arrays** (not word-split scalars) to iterate directory lists (`user_homes`, `roots`, `bindirs`, `npmroots`), so a path containing a space is one element, not two. Glob-bearing paths (e.g. `~/.nvm/versions/node/*/lib/node_modules`) use the **`(N)` null-glob qualifier** so an unmatched glob vanishes rather than aborting the script; user homes use `/Users/*(N/)` (`(N/)` = directories only, null if none). The `xesc()` XML-escaper is pure zsh parameter expansion (zero subprocesses), while `plutil` and `codesign` remain the native tools they always were.

### Tested / expected-compatible

- Tested: macOS Sequoia 15.7.7 (Apple Silicon).
- Expected-compatible: macOS 12 Monterey through macOS 26 Tahoe, on both Intel and Apple Silicon. Both scripts use only version-stable native binaries (`plutil -extract … raw` (the compatibility floor: `raw` output requires macOS 12), `codesign -dv` / `--verify`, `mktemp -t`, `find -maxdepth/-path/-prune`, `tr`, `sed -E`, `awk`, `sort -u`, `grep -E`, `stat -f`, `mv -f`) and probe both `/opt/homebrew` (Apple Silicon Homebrew) and `/usr/local` (Intel Homebrew).
- Untested: macOS 12 / 13 / 14, macOS 26, and Intel hardware (expected to work; not yet verified on hardware).

---

## Maintenance

AI tooling changes weekly. Extend `ai-inventory-collector.zsh` as the fleet evolves; the reader never needs to change for a signature update, since all detection logic lives in the collector:

- New known app → add a `case` arm to `app_known()` (use the bundle ID for generic-word names like *Dia*, *Void*, *Zed*, *Trae*).
- New known CLI → add to `cli_known()` **and** the binary-name list in `scan_cli()`. If the binary name is generic (collides with a non-AI tool), add a **config-dir** check instead of a PATH match.
- New editor extension → add the `publisher.name` prefix to `ext_is_ai()`.
- New browser extension → add its 32-char store ID to `chrome_ext_known()`.
- New MCP client → add its per-user config path (and, when the file can exist without servers configured, a content grep for its server key) to `scan_mcp()`.
- New AI-native vendor → run `codesign -dv --verbose=4 /Applications/<App>.app`, confirm the vendor's whole business is AI (not a diversified company), and add its `TeamIdentifier` to `teamid_known()`. Never add a diversified vendor's Team ID. New Team-ID vendors automatically get verify-and-annotate treatment without extra work.
- New keyword for the catch-all → extend the `AI_HEURISTIC` regex (keep it distinctive; avoid bare `ai`/`gpt` to prevent false positives like *Airmail*).

When you add or edit a glob-bearing path, keep the **`(N)`** qualifier on it so a non-existent path can never abort the run (zsh's default `nomatch` would).

**Design note (do not "fix"):** neither script enables `err_exit` (zsh's `set -e`) or any nomatch-abort. The collector probes dozens of optional paths and runs greps that legitimately return non-zero; the reader must always emit exactly one `<result>` even if `stat`/`cat` hiccup. Fail-fast would abort mid-scan (collector) or mid-read (reader) and produce an incomplete or empty value. Every glob that can miss carries the `(N)` null-glob qualifier locally instead of flipping a global option.

**Performance:** the collector's Developer-ID layer runs `codesign -dv` (and, for Team-ID matches, an additional `codesign --verify`) once per *unmatched* app (known AI apps match earlier and skip both). On a typical fleet Mac this totals well under 15 seconds, and it happens on the collector's own 4-hour LaunchDaemon budget, never during recon. The reader itself completes in well under a second.

**Verification:** both scripts are parse-checked with `zsh -n` (shellcheck does **not** support zsh, so it is not used on these files); `install.sh` with `sh -n`; the plist with `plutil -lint`. Detection tables in the collector are a **superset** of the original single-file EA this project split from: same lineage, plus expanded MCP-client coverage, additional CLI/package roots, and per-tool output collapse (`app_known` 50 arms, `cli_known` 35 arms, `ext_is_ai` 44 publisher prefixes, `chrome_ext_known` 20 arms, `teamid_known` 19 vendors).

### Test harness

A re-runnable local suite lives beside the scripts. Run it after any edit:

```sh
zsh ./test-ai-ea.zsh          # full assertion suite (non-zero exit on any failure)
sudo zsh ./test-ai-ea.zsh     # also exercises the root-owned path
```

It covers: syntax (`zsh -n`, `sh -n`, `plutil -lint`), the collector's **atomic write** contract (well-formed state file, no leftover temp files, byte-identical across repeated runs), the reader's **`NOT_COLLECTED` / `STALE` / normal** sentinel branches (including that `STALE` still carries the last-known-good cached value), reader **performance** (<1s) and stdout hygiene (exactly one `<result>`), **security** hardening (`umask`, `/var/root` tempfile fallback, `--no-rcs` ignoring a planted `~/.zshenv`, zero network commands anywhere), **data-table integrity** (Team-ID / Chrome-ID format + dedupe, forbidden entries stay absent), a zsh **lint** pass (`warn_create_global`), **pure-function unit tests** (`app_known` / `cli_known` / `teamid_known` / `chrome_ext_known` / `ext_is_ai` / `xesc`), presence and correctness of the **verify-and-annotate** behavior (including a live positive/negative control against `codesign --verify`), `install.sh`/plist contract checks (modern `launchctl` subcommands, `REVERSE_DOMAIN`, `--uninstall`, `StartInterval`, `ProcessType`), a live **per-tool dedupe invariant** (no two output lines may share a category + canonical-tool key), and, when the original monolithic EA is present alongside this split, an informational diff against it (expected to differ: this collector detects a superset and collapses per tool). Exit code is non-zero on any failure.

---

## FAQ

**Does the collector need Full Disk Access?** Usually not. The paths it reads are not individually TCC-protected. Deploy first, watch the collector log for TCC denials, and apply the bundled PPPC profile only if you see them. See [Optional Full Disk Access](#optional-full-disk-access).

**Does it send any data off the Mac?** No. There are no network calls anywhere in the project; even the signature check (`codesign --verify`) is offline. Findings leave the Mac only inside the normal Jamf inventory submission.

**Will it slow down Jamf recon?** No. Recon runs the thin reader, which stats and cats one small local file and finishes in well under a second. Scanning happens on the collector's own launchd schedule.

**Which Jamf Pro tiers does it work with?** Any tier that supports script Extension Attributes and policies. It has no dependency on Jamf's AI Governance product or any add-on.

**Does it detect ChatGPT used in a browser tab, or Microsoft 365 Copilot?** No. Browser-session and tenant-side AI are invisible to an endpoint scanner; govern those at the network or tenant layer. See [What it does not detect](#what-it-does-not-detect-by-design).

**Can I change how often it scans?** Yes. Jamf policy script parameter 6 sets the interval (default 4 hours, minimum 10 minutes). The installer records the value in `/var/db/ai-software-inventory/interval` and the reader treats 2× that as its staleness threshold, so no reader edit is needed.

---

## Contributing

AI tooling changes weekly, and the detection tables are built to absorb that: [Maintenance](#maintenance) says exactly where a new app, CLI, editor extension, browser extension, Team ID, or MCP client belongs. Run `zsh ./test-ai-ea.zsh` before and after any change and keep the suite green; if you edit the collector, re-run `./build-installer.sh` so the embedded copy in `install.sh` stays in sync.

---

## License

This project is released under the [MIT License](./LICENSE). Every script carries an `SPDX-License-Identifier: MIT` header; the full license text lives in [`LICENSE`](./LICENSE). Copyright (c) 2026 Robert Flanagan.
