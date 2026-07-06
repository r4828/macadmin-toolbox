#!/bin/zsh
# SPDX-FileCopyrightText: 2026 Robert Flanagan and macadmin-toolbox contributors
# SPDX-License-Identifier: MIT
#
# Name:        test-ai-ea.zsh
# Purpose:     Local test harness for the collector/reader split.
# Context:     Standalone, run by a maintainer beside the sibling scripts:
#              zsh ./test-ai-ea.zsh        (sudo also exercises the root path)
# Parameters:  none
# Tested on:   macOS 15.7.7 Sequoia
# Author:      Robert Flanagan (@r4828)
#
# Re-runnable assurance suite covering:
#   ai-inventory-collector.zsh   (heavy scanner -> writes STATE_FILE)
#   ai-software-inventory-ea.zsh (thin reader -> emits <result> from STATE_FILE)
#   install.sh / the LaunchDaemon plist (static syntax/lint checks)
#
# It extends the original single-file-EA harness: the None-sentinel /
# idempotency / stdout-hygiene / security / lint / unit-test coverage that
# harness had now applies across the two split scripts, PLUS new coverage for
# the state-file contract itself: atomic writes, the reader's NOT_COLLECTED /
# STALE / normal sentinels, presence of the verify-and-annotate behavior, the
# per-tool dedupe invariant, and an informational diff against the original
# monolithic EA (when present).
#
# Usage:  zsh ./test-ai-ea.zsh            (run against the sibling scripts)
#         sudo zsh ./test-ai-ea.zsh       (also exercises the root-owned path)
# Exit code is non-zero if any test fails.
# =============================================================================
emulate -L zsh
set -o pipefail
zmodload zsh/datetime   # $EPOCHREALTIME for the T5 timing assertion

DIR="${0:A:h}"
READER="$DIR/ai-software-inventory-ea.zsh"
COLLECTOR="$DIR/ai-inventory-collector.zsh"
INSTALLER="$DIR/install.sh"
PLIST="$DIR/io.github.ai-software-inventory.collector.plist"
# Detection-logic source of truth this split was built from. Only used for
# the parity test (T13); gracefully skipped if absent or already thinned out
# (e.g. once this candidate has been promoted and the monolithic original no
# longer exists alongside it).
ORIGINAL_EA="$DIR/../ai-software-inventory-ea.zsh"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
pass=0 fail=0
ok()   { print "  PASS  $1"; ((pass++)); }
bad()  { print "  FAIL  $1"; ((fail++)); }
skip() { print "  SKIP  $1"; }
have() { [[ -n "$1" ]] }

print "== AI Software Inventory collector/reader split -- test harness =="
print "READER:    $READER"
print "COLLECTOR: $COLLECTOR"
print "INSTALLER: $INSTALLER"
print "PLIST:     $PLIST"
[[ -r "$READER" ]]    || { print "FATAL: reader not readable"; exit 2 }
[[ -r "$COLLECTOR" ]] || { print "FATAL: collector not readable"; exit 2 }

# ---- T1 syntax: every shipped file parses clean ----
print "\n[T1] syntax checks"
if zsh -n "$READER" 2>"$TMP/t1r"; then ok "reader: zsh -n parses clean"; else bad "reader zsh -n failed: $(<$TMP/t1r)"; fi
if zsh -n "$COLLECTOR" 2>"$TMP/t1c"; then ok "collector: zsh -n parses clean"; else bad "collector zsh -n failed: $(<$TMP/t1c)"; fi
if [[ -r "$INSTALLER" ]]; then
    if sh -n "$INSTALLER" 2>"$TMP/t1i"; then ok "install.sh: sh -n parses clean"; else bad "install.sh sh -n failed: $(<$TMP/t1i)"; fi
else
    skip "install.sh not present"
fi
if [[ -r "$PLIST" ]]; then
    if plutil -lint "$PLIST" >"$TMP/t1p" 2>&1; then ok "plist: plutil -lint OK"; else bad "plist lint failed: $(<$TMP/t1p)"; fi
else
    skip "plist not present"
fi

# ---- Helper: run the collector against a fresh temp state dir ----
run_collector() {
    local statedir=$1
    AI_INV_STATE_DIR="$statedir" zsh "$COLLECTOR" >/dev/null 2>"$TMP/collector_stderr"
}
run_reader() {
    local statedir=$1
    AI_INV_STATE_DIR="$statedir" zsh "$READER" 2>"$TMP/reader_stderr"
}

# ---- T2 collector: writes a well-formed atomic state file ----
print "\n[T2] collector writes a well-formed atomic file to a TEMP AI_INV_STATE_DIR"
S1="$TMP/state1"
run_collector "$S1"; rc=$?
[[ $rc -eq 0 ]] && ok "collector exits 0" || bad "collector exit code $rc"
[[ -z "$(<$TMP/collector_stderr)" ]] && ok "collector stderr empty" || bad "collector stderr non-empty: $(<$TMP/collector_stderr)"
[[ -d "$S1" ]] && ok "STATE_DIR created" || bad "STATE_DIR not created"
[[ -f "$S1/result.txt" ]] && ok "result.txt created" || bad "result.txt not created"
[[ -s "$S1/result.txt" ]] && ok "result.txt non-empty" || bad "result.txt empty"
body1="$(<"$S1/result.txt")"
{ [[ "$body1" == 'None' ]] || [[ "$body1" == SUMMARY:* ]]; } && ok "result.txt body starts with 'None' or 'SUMMARY:'" || bad "result.txt body malformed: '${body1:0:60}...'"
[[ "$body1" != '<result>'* ]] && ok "result.txt is NOT wrapped in <result> (collector must not double-wrap)" || bad "result.txt is wrapped -- double-wrap bug"
leftover=("$S1"/*.tmp.*(N))
(( ${#leftover} == 0 )) && ok "no leftover .tmp.* files after atomic mv" || bad "leftover tmp file(s): $leftover"
grep -q '\.tmp\.\$\$' "$COLLECTOR" && grep -q '"\$MV" -f' "$COLLECTOR" && ok "atomic tmp+mv pattern present in source" || bad "atomic tmp+mv pattern missing from source"

print "\n[T2b] collector fails visibly when the state file cannot be written"
AI_INV_STATE_DIR=/dev/null/nope zsh "$COLLECTOR" >/dev/null 2>"$TMP/write_failure_stderr"
write_rc=$?
(( write_rc != 0 )) && ok "collector exits non-zero on state write failure" || bad "collector exited 0 despite state write failure"
grep -qiE 'state|write|rename|directory|failed|unavailable' "$TMP/write_failure_stderr" && ok "collector reports the write failure on stderr" || bad "collector did not explain write failure: $(<$TMP/write_failure_stderr)"

# ---- T3 collector: idempotency (re-run produces the same shape) ----
print "\n[T3] collector idempotency"
S2="$TMP/state2"
run_collector "$S2"
run_collector "$S2"
body2a="$(<"$S2/result.txt")"
run_collector "$S2"
body2b="$(<"$S2/result.txt")"
[[ "$body2a" == "$body2b" ]] && ok "repeated collector runs produce byte-identical output" || bad "collector output drifted across repeated runs"

# ---- T4 reader: NOT_COLLECTED / STALE / normal sentinels ----
print "\n[T4] reader sentinels"
S3="$TMP/state3"
# 4a. NOT_COLLECTED -- state dir doesn't even exist yet
out_missing="$(run_reader "$S3")"; rc=$?
[[ $rc -eq 0 ]] && ok "reader exits 0 when state dir absent" || bad "reader exit code $rc on missing state dir"
[[ "$out_missing" == '<result>NOT_COLLECTED</result>' ]] && ok "emits <result>NOT_COLLECTED</result> when never collected" || bad "NOT_COLLECTED path wrong: '$out_missing'"

# 4b. normal -- collector runs, file is fresh
run_collector "$S3"
out_normal="$(run_reader "$S3")"
[[ "$out_normal" == '<result>'* && "$out_normal" == *'</result>' ]] && ok "normal path wrapped in exactly one <result>...</result>" || bad "normal path not properly wrapped: '$out_normal'"
body3="$(<"$S3/result.txt")"
[[ "$out_normal" == "<result>${body3}</result>" ]] && ok "normal path wraps the cached value verbatim (no double-escaping)" || bad "normal path does not match STATE_FILE contents verbatim"

# 4c. STALE -- backdate the mtime past STALE_THRESHOLD (28800s / 8h)
touch -t 202001010000 "$S3/result.txt"
out_stale="$(run_reader "$S3")"
[[ "$out_stale" == '<result>STALE'* ]] && ok "STALE path prefixes with STALE marker" || bad "STALE path missing marker: '${out_stale:0:80}'"
print -r -- "$out_stale" | grep -q '2020-01-01' && ok "STALE path reports the last-collected timestamp" || bad "STALE path missing last-collected timestamp"
print -r -- "$out_stale" | grep -qF "$body3" && ok "STALE path still includes the cached value beneath the flag" || bad "STALE path dropped the cached value"
[[ "$out_stale" == *'</result>' ]] && ok "STALE path still closes with exactly one </result>" || bad "STALE path malformed closing tag"

# 4d. also verify NOT_COLLECTED once the dir exists but the file was removed
rm -f "$S3/result.txt"
out_removed="$(run_reader "$S3")"
[[ "$out_removed" == '<result>NOT_COLLECTED</result>' ]] && ok "NOT_COLLECTED also fires when STATE_DIR exists but result.txt was removed" || bad "NOT_COLLECTED (post-removal) path wrong: '$out_removed'"

# ---- T5 reader: fast (<1s), stdout hygiene, idempotent ----
print "\n[T5] reader performance + hygiene"
S4="$TMP/state4"; run_collector "$S4"
t0=$EPOCHREALTIME
run_reader "$S4" >/dev/null
t1=$EPOCHREALTIME
elapsed=$(( t1 - t0 ))
(( elapsed < 1.0 )) && ok "reader completes in <1s (${elapsed}s)" || bad "reader took ${elapsed}s (>=1s)"
r1="$(run_reader "$S4")"; r2="$(run_reader "$S4")"
[[ "$r1" == "$r2" ]] && ok "reader idempotent across repeated reads" || bad "reader output differs between reads"
opens=$(print -r -- "$r1" | grep -o '<result>'  | grep -c .)
closes=$(print -r -- "$r1" | grep -o '</result>' | grep -c .)
[[ $opens -eq 1 && $closes -eq 1 ]] && ok "exactly one <result> block ($opens open / $closes close)" || bad "expected 1/1, got $opens/$closes"

# ---- T6 security + hardening static checks ----
print "\n[T6] security + hardening"
[[ "$(head -1 "$READER")" == '#!/bin/zsh --no-rcs' ]] && ok "reader shebang is '#!/bin/zsh --no-rcs'" || bad "reader wrong shebang"
[[ "$(head -1 "$COLLECTOR")" == '#!/bin/zsh --no-rcs' ]] && ok "collector shebang is '#!/bin/zsh --no-rcs'" || bad "collector wrong shebang"
grep -q 'umask 077' "$COLLECTOR" && ok "collector: umask 077 present" || bad "collector: umask 077 missing"
grep -q '/var/root/' "$COLLECTOR" && ok "collector: root-only tempfile fallback (not world-writable /tmp)" || bad "collector: no /var/root fallback"
grep -q "trap 'rm -f" "$COLLECTOR" && ok "collector: cleanup trap present" || bad "collector: no cleanup trap"
for f in "$READER" "$COLLECTOR"; do
    # Exclude full-line comments so documentation like "this does NOT call
    # spctl" doesn't self-trigger the check; only code lines count.
    if grep -v '^[[:space:]]*#' "$f" | grep -nE '\b(curl|wget|nc|ncat|spctl|networksetup|ping|nscurl|ssh|scp)\b' >/dev/null; then
        bad "$(basename "$f"): network/remote command found (must be offline)"
    else
        ok "$(basename "$f"): zero network/remote commands"
    fi
done
grep -q 'AI_INV_STATE_DIR' "$READER" && grep -q 'AI_INV_STATE_DIR' "$COLLECTOR" && ok "both scripts honor \$AI_INV_STATE_DIR override" || bad "state-dir override missing from one side"

# ---- T7 --no-rcs efficacy on the reader (hostile ~/.zshenv must NOT be sourced) ----
print "\n[T7] --no-rcs blocks a planted rc file (reader)"
mkdir -p "$TMP/zdot"
print 'print INJECTED > '"$TMP"'/injected.flag' > "$TMP/zdot/.zshenv"
HOME="$TMP/zdot" ZDOTDIR="$TMP/zdot" AI_INV_STATE_DIR="$TMP/state4" "$READER" >/dev/null 2>&1
[[ -f "$TMP/injected.flag" ]] && bad "planted .zshenv WAS sourced (--no-rcs not effective)" || ok "planted .zshenv ignored (--no-rcs effective)"

# ---- T8 data-table integrity (tables now live in the collector) ----
print "\n[T8] data-table integrity (collector)"
tids=("${(@f)$(awk '/^teamid_known/,/^}/' "$COLLECTOR" | grep -oE '^[[:space:]]*[A-Z0-9]{10}\)' | tr -d ' )')}")
badfmt=0; for t in $tids; do [[ "$t" =~ '^[A-Z0-9]{10}$' ]] || badfmt=1; done
(( badfmt == 0 )) && ok "all ${#tids} Team IDs are 10-char upper-alnum" || bad "malformed Team ID present"
dups=$(print -l -- $tids | sort | uniq -d)
have "$dups" && bad "duplicate Team ID(s): $dups" || ok "no duplicate Team IDs"
cids=("${(@f)$(awk '/^chrome_ext_known/,/^}/' "$COLLECTOR" | grep -oE '[a-p]{32}')}")
cdup=$(print -l -- $cids | sort | uniq -d)
have "$cdup" && bad "duplicate Chrome ID(s): $cdup" || ok "no duplicate Chrome IDs (${#cids} total)"
grep -q 'Zed Industries' "$COLLECTOR" && bad "Zed Industries back in Team-ID allowlist" || ok "Zed absent from Team-ID allowlist"
awk '/^teamid_known/,/^}/' "$COLLECTOR" | grep -q 'Sourcegraph' && bad "Sourcegraph back in Team-ID allowlist" || ok "Sourcegraph absent from Team-ID allowlist"
grep -qE 'googlecloudtools.cloudcode|amazonwebservices.aws-toolkit' "$COLLECTOR" && bad "broad cloud toolkit ext re-added" || ok "cloudcode/aws-toolkit absent from ext patterns"

# ---- T9 zsh lint: collector functions must not create globals ----
print "\n[T9] zsh lint (warn_create_global -- locals hygiene, isolated, collector)"
sed '/^# Each scan section/,$ s/^/#/' "$COLLECTOR" > "$TMP/funcs9.zsh"
zsh -o warn_create_global -c "source '$TMP/funcs9.zsh'; unset h d name; scan_mcp; scan_apps; scan_cli; scan_ide_ext; scan_browser_ext; ext_is_ai github.copilot; true" >/dev/null 2>"$TMP/wcg" || true
globals=$(grep -c 'created globally' "$TMP/wcg" 2>/dev/null); globals=${globals:-0}
if (( globals == 0 )); then ok "collector functions create no globals (isolated warn_create_global probe)"; else
    bad "$globals 'created globally' notice(s) -- add 'local':"; sed 's/^/         /' "$TMP/wcg" | head -20; fi

# ---- T10 pure-function unit tests (collector) ----
print "\n[T10] function unit tests (collector)"
sed '/^# Each scan section/,$ s/^/#/' "$COLLECTOR" > "$TMP/funcs10.zsh"
source "$TMP/funcs10.zsh" 2>/dev/null
u() { local desc=$1 got=$2 want=$3; [[ "$got" == "$want" ]] && ok "$desc" || bad "$desc (got '$got' want '$want')"; }
u "app_known Claude"            "$(app_known 'claude com.anthropic.claudefordesktop')" "Claude (Anthropic)"
u "app_known unknown->empty"    "$(app_known 'microsoft word com.microsoft.word')"     ""
u "cli_known codex"             "$(cli_known codex)"        "OpenAI Codex"
u "cli_known non-ai->empty"     "$(cli_known ls)"           ""
u "teamid_known Anthropic"      "$(teamid_known Q6L2SF6YDW)" "Anthropic"
u "teamid_known Microsoft->''"  "$(teamid_known UBF8T346G9)" ""
u "chrome_ext_known Grammarly"  "$(chrome_ext_known kbfnbcaeplbcioakkpcpgfkobkghlhen)" "Grammarly"
u "chrome_ext_known junk->''"   "$(chrome_ext_known abcdefghijklmnopqrstuvwxyzabcdef)" ""
ext_is_ai 'github.copilot'      && ok "ext_is_ai github.copilot=true"  || bad "ext_is_ai github.copilot"
ext_is_ai 'ms-vscode.cpptools'  && bad "ext_is_ai false-positive on cpptools" || ok "ext_is_ai cpptools=false (negative)"
u "xesc neutralizes injection"  "$(xesc 'Foo </result><result>x & <b>')" "Foo &lt;/result&gt;&lt;result&gt;x &amp; &lt;b&gt;"

# ---- T11 verify-and-annotate presence + function behavior ----
print "\n[T11] verify-and-annotate"
grep -q 'verify_signature' "$COLLECTOR" && ok "verify_signature() helper present" || bad "verify_signature() helper missing"
grep -q '\[Team \$team verified\]' "$COLLECTOR" && ok "pass path appends ' verified' to the Team annotation" || bad "verified annotation string missing"
grep -q '\[Team \$team UNVERIFIED\]' "$COLLECTOR" && ok "fail path marks the Team annotation UNVERIFIED" || bad "UNVERIFIED annotation string missing"
grep -qE 'emit "HEURISTIC".*signature FAILED verify' "$COLLECTOR" && ok "fail path reroutes the app to HEURISTIC (loud review) instead of dropping it" || bad "fail path does not reroute to HEURISTIC"
verify_fn_line="$(grep -E '^verify_signature\(\)' "$COLLECTOR")"
print -r -- "$verify_fn_line" | grep -q -- '--quiet' && bad "collector's verify_signature() passes the nonexistent codesign --quiet flag (will always fail)" || ok "collector's verify_signature() does not pass the nonexistent codesign --quiet flag"
# Functional check: verify_signature is sourced from T10's funcs10.zsh above.
# Deterministic positive control: ad-hoc-sign a throwaway Mach-O copy. Using a
# real system app (e.g. Calculator) is brittle -- `codesign --verify` on sealed
# system apps can return CSSMERR_TP_NOT_TRUSTED on some Macs/OS builds for
# reasons unrelated to this code, so it is NOT a reliable positive control.
probe="$TMP/probe.bin"
if cp /bin/echo "$probe" 2>/dev/null && codesign -f -s - "$probe" >/dev/null 2>&1; then
    verify_signature "$probe" && ok "verify_signature() true on an ad-hoc-signed binary (deterministic control)" || bad "verify_signature() false-negative on an ad-hoc-signed binary"
else
    skip "could not create an ad-hoc-signed probe for the positive control"
fi
verify_signature "$TMP/no-such-app-$$.app" && bad "verify_signature() true-positive on a nonexistent path" || ok "verify_signature() false on a nonexistent path (negative control)"

# ---- T12 install.sh / plist contract checks ----
print "\n[T12] install.sh / LaunchDaemon contract"
if [[ -r "$INSTALLER" ]]; then
    grep -q 'REVERSE_DOMAIN=' "$INSTALLER" && ok "install.sh exposes a single REVERSE_DOMAIN rebrand variable" || bad "REVERSE_DOMAIN variable missing"
    grep -q 'launchctl bootout' "$INSTALLER" && grep -qE 'launchctl bootstrap system' "$INSTALLER" && \
    grep -qE 'launchctl enable "?system' "$INSTALLER" && grep -qE 'launchctl kickstart -k "?system' "$INSTALLER" && \
        ok "install.sh uses modern launchctl bootout/bootstrap/enable/kickstart" || bad "install.sh missing modern launchctl subcommands"
    grep -qE '\bload\b.*\.plist|launchctl load' "$INSTALLER" && bad "install.sh still uses deprecated 'launchctl load'" || ok "install.sh does not use deprecated launchctl load/unload"
    grep -q -- '--uninstall' "$INSTALLER" && ok "install.sh supports --uninstall" || bad "install.sh missing --uninstall support"
else
    skip "install.sh not present"
fi
if [[ -r "$PLIST" ]]; then
    label="$(plutil -extract Label raw -o - "$PLIST" 2>/dev/null)"
    [[ "$label" == *.collector ]] && ok "plist Label ends in .collector ($label)" || bad "plist Label unexpected: '$label'"
    interval="$(plutil -extract StartInterval raw -o - "$PLIST" 2>/dev/null)"
    [[ "$interval" == "14400" ]] && ok "plist StartInterval is 14400 (4h)" || bad "plist StartInterval wrong: '$interval'"
    ptype="$(plutil -extract ProcessType raw -o - "$PLIST" 2>/dev/null)"
    [[ "$ptype" == "Background" ]] && ok "plist ProcessType is Background" || bad "plist ProcessType wrong: '$ptype'"
    runatload="$(plutil -extract RunAtLoad raw -o - "$PLIST" 2>/dev/null)"
    [[ "$runatload" == "1" || "$runatload" == "true" ]] && ok "plist RunAtLoad is true" || bad "plist RunAtLoad wrong: '$runatload'"
    # launchd runs ProgramArguments directly, bypassing the script's shebang -- so
    # --no-rcs MUST be passed explicitly here or the rc-file isolation is lost.
    progargs="$(plutil -extract ProgramArguments json -o - "$PLIST" 2>/dev/null)"
    [[ "$progargs" == *'--no-rcs'* ]] && ok "plist ProgramArguments passes --no-rcs (rc isolation applies under launchd)" || bad "plist ProgramArguments missing --no-rcs -- launchd would bypass the shebang's --no-rcs"
else
    skip "plist not present"
fi

# ---- T13 per-tool dedupe invariant + informational diff vs. original EA ----
# The collector has intentionally DIVERGED from the original monolithic EA:
# it detects a superset of surfaces (more MCP clients, more CLI roots, more
# browsers) and collapses multi-prong evidence to ONE line per tool with
# merged locations. Byte-parity is therefore no longer the contract. What IS
# the contract now:
#   (a) no two output lines may describe the same (category, canonical tool)
#       -- the dedupe invariant the collapse pass exists to guarantee;
#   (b) differences vs. the original EA are surfaced for human review as an
#       informational diff, not a failure.
print "\n[T13] per-tool dedupe invariant (+ informational diff vs. original EA)"
S5="$TMP/state5"
run_collector "$S5"
coll_inner="$(<"$S5/result.txt")"

# (a) Dedupe invariant: recompute the collapse pass's canonical key for every
# emitted line; any key seen twice is a dedupe regression. Mirrors the awk
# normalization in the collector (strip npm:/pipx:/uv:, parentheticals,
# [-_/@] -> space).
dupes="$(print -r -- "$coll_inner" | tail -n +2 | awk -F' \\| ' '
    NF >= 4 {
        key = tolower($2)
        sub(/^(npm|pipx|uv): /, "", key)
        gsub(/ *\([^)]*\)/, "", key)
        gsub(/[-_\/@]/, " ", key)
        gsub(/  +/, " ", key); sub(/^ +/, "", key); sub(/ +$/, "", key)
        k = $1 SUBSEP key
        if (k in seen) print $1 " | " $2
        seen[k] = 1
    }')"
if [[ -z "$dupes" ]]; then
    ok "no two findings share a (category, canonical tool) key -- dedupe holds"
else
    bad "duplicate tool lines survived the collapse pass:"
    print -r -- "$dupes" | sed 's/^/         /' | head -10
fi

# (b) Informational diff against the original monolithic EA, when present.
if [[ -r "$ORIGINAL_EA" ]] && grep -q '^scan_apps()' "$ORIGINAL_EA"; then
    orig_out="$(zsh "$ORIGINAL_EA" 2>/dev/null)"
    orig_inner="${orig_out#<result>}"
    orig_inner="${orig_inner%</result>}"
    norm() { sed -E 's/ verified\]/]/g; s/ UNVERIFIED\]/]/g' | sort -u; }
    norm_orig="$(print -r -- "$orig_inner" | tail -n +2 | norm)"
    norm_coll="$(print -r -- "$coll_inner" | tail -n +2 | norm)"
    print "  NOTE  informational diff vs. original EA (expected to differ: superset detection + per-tool collapse):"
    diff <(print -r -- "$norm_orig") <(print -r -- "$norm_coll") | sed 's/^/         /' | head -40
    ok "informational diff emitted (review above; not a pass/fail contract)"
else
    skip "original monolithic EA not present alongside this candidate (nothing to diff against)"
fi

# ---- T14 self-contained installer: embedded collector must not drift ----
print "\n[T14] embedded-collector drift guard (install.sh is fully self-contained)"
if [[ -r "$INSTALLER" ]]; then
    DELIM='__AI_COLLECTOR_EOF__'
    # Extract the bytes between the two ${DELIM} delimiter lines (the heredoc
    # opener line and the closing delimiter line). '1d;$d' drops those two
    # boundary lines, leaving the embedded collector body verbatim.
    sed -n "/${DELIM}/,/${DELIM}/p" "$INSTALLER" | sed '1d;$d' > "$TMP/embedded_collector.zsh"
    if [[ -s "$TMP/embedded_collector.zsh" ]]; then
        ok "install.sh contains an embedded collector heredoc (delimiter ${DELIM})"
    else
        bad "install.sh has no embedded collector between ${DELIM} delimiters"
    fi
    if diff -q "$TMP/embedded_collector.zsh" "$COLLECTOR" >/dev/null 2>&1; then
        ok "embedded collector is BYTE-IDENTICAL to ai-inventory-collector.zsh (no drift)"
    else
        bad "embedded collector DRIFTED from ai-inventory-collector.zsh -- re-run ./build-installer.sh"
        diff "$TMP/embedded_collector.zsh" "$COLLECTOR" | sed 's/^/         /' | head -20
    fi
    # The self-contained installer must NOT reintroduce the old "collector must
    # sit next to install.sh" co-location dependency.
    if grep -qE 'SRC_COLLECTOR|next to install\.sh|Stage .*in the same directory|Cannot find .*next to' "$INSTALLER"; then
        bad "install.sh still carries a co-location check (SRC_COLLECTOR / 'next to install.sh')"
    else
        ok "install.sh has no 'must be beside' / SRC_COLLECTOR co-location check"
    fi
    grep -q 'cp "\${SRC_COLLECTOR}"' "$INSTALLER" && bad "install.sh still copies a co-located SRC_COLLECTOR" || ok "install.sh does not cp a co-located collector"
else
    skip "install.sh not present"
fi

# ---- summary ----
print "\n== RESULT: $pass passed, $fail failed =="
(( fail == 0 )) && print "ALL GREEN" || print "SEE FAILURES ABOVE"
exit $(( fail > 0 ))
