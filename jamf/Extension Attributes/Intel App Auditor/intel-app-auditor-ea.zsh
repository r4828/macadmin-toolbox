#!/bin/zsh --no-rcs
# SPDX-FileCopyrightText: 2026 Robert Flanagan and macadmin-toolbox contributors
# SPDX-License-Identifier: MIT
#
# Name:        intel-app-auditor-ea.zsh
# Purpose:     Jamf Extension Attribute reader for the Intel App Auditor.
#              The reader NEVER scans; recon only pays for stat + a file read.
# Context:     Jamf Pro computer EA (Data Type String, Input Type Script).
#              Deploy install.sh first so the collector writes result.txt.
# Tested on:   macOS 15.4.1 (live, 24E263, arm64) + macOS 15 Sequoia (Tart VM)
# Author:      Robert Flanagan (@r4828)
#
# ===========================================================================
# ONE reader, three trigger words. Each trigger word calls one mode, and every
# mode is a single <result> value, so every mode is usable as Smart Group
# criteria. The heavy system_profiler scan runs only once, in the background
# collector; each trigger just slices the same cached file.
#
#   counts   summary line only  -> IntelOnly:0, ScanStatus:Partial,
#                                  RosettaRuntimePresent:Yes, Arch:x86_64, ...
#   apps     Intel-only app list (name + path), or IntelApps:None
#                                  -> match a specific app by name/path
#   both     summary line, then the app list                       (default)
#
# HOW TO PICK A MODE
#   * As a Jamf EA (no arguments): keep exactly ONE of the three trigger lines
#     at the very bottom of this file; comment out the other two. Whichever
#     word is left uncommented is the mode this EA reports.
#   * From the command line / testing: pass the trigger word as the first
#     argument, e.g.  intel-app-auditor-ea.zsh counts
# ===========================================================================

export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

STAT=/usr/bin/stat
DATE=/bin/date
CAT=/bin/cat
GREP=/usr/bin/grep
HEAD=/usr/bin/head

# Must match intel-app-auditor.zsh (the collector).
: ${INTEL_STATE_DIR:=/var/db/intel-app-auditor}
_iaa_state_dir="$INTEL_STATE_DIR"
_iaa_state_file="$_iaa_state_dir/result.txt"

# _iaa_state_path_safe <path>: refuse to trust a state dir/file that is not what
# the collector's root-only guarantee promises. Rejects a symlink (an attacker
# redirecting the trust path), a group- or world-writable node (someone else can
# rewrite the cache), and -- when the reader itself runs as root at recon -- a
# node not owned by root. Returns 0 when safe (publication finding 12).
_iaa_state_path_safe() {
    local p="$1" perm owner
    [[ -L "$p" ]] && return 1
    perm="$("$STAT" -f '%Sp' "$p" 2>/dev/null)" || return 1
    [[ "${perm[6]}" == w ]] && return 1          # group-writable
    [[ "${perm[9]}" == w ]] && return 1          # world-writable
    if (( UID == 0 )); then
        owner="$("$STAT" -f '%u' "$p" 2>/dev/null)"
        [[ "$owner" == 0 ]] || return 1
    fi
    return 0
}

# _iaa_validate_cache <file>: prove the WHOLE cache is a well-formed collector
# payload BEFORE any view is sliced from it. A cache is valid only when it has
#   1. a line-1 counts summary with the six numeric class counts and a
#      ScanStatus of Complete or Partial, AND
#   2. an app-list section: one or more `INTEL_APP |` lines, the literal
#      `IntelApps:None` marker, or a `TRUNCATED:` line, AND
#   3. count/list agreement -- the IntelOnly count equals the number of
#      INTEL_APP lines (IntelApps:None requires IntelOnly:0; a TRUNCATED cache
#      is exempt from the exact equality because it intentionally omits lines).
# Returns 0 when valid, non-zero otherwise. This is the fix for publication
# finding 1: a counts-only, empty, truncated-header-only, duplicated, invalid-
# numeric, or mismatched-count cache must NOT be able to masquerade as a clean
# validated result in ANY view -- not just `apps`.
_iaa_validate_cache() {
    local file="$1" first icount napps
    first="$("$HEAD" -n 1 "$file" 2>/dev/null)"
    # 1. counts summary schema on line 1.
    print -r -- "$first" | "$GREP" -qE \
        '^IntelOnly:[0-9]+;Universal:[0-9]+;AppleSilicon:[0-9]+;iOS:[0-9]+;Other:[0-9]+;Unknown:[0-9]+;ScanStatus:(Complete|Partial);' \
        || return 1
    # 2. an app-list section must exist.
    "$GREP" -qE '^(INTEL_APP \||IntelApps:None|TRUNCATED:)' "$file" || return 1
    icount="${first#IntelOnly:}"; icount="${icount%%;*}"
    # 3. count/list agreement.
    if "$GREP" -qE '^TRUNCATED:' "$file"; then
        return 0                                  # list intentionally clipped
    fi
    if "$GREP" -qE '^IntelApps:None$' "$file"; then
        [[ "$icount" == 0 ]] && return 0 || return 1
    fi
    napps="$("$GREP" -cE '^INTEL_APP \|' "$file")"
    [[ "$napps" == "$icount" ]] || return 1
    return 0
}

# _iaa_read <counts|apps|both>: stat the cached state file, VALIDATE the whole
# cache, then slice it to the requested view, apply the NOT_COLLECTED / STALE /
# MALFORMED_CACHE sentinels, and print exactly one <result> value. This is the
# whole reader; the trigger words below are one-line wrappers so each mode has
# its own name.
_iaa_read() {
    local view="$1" threshold=28800 interval mtime now age body last
    case "$view" in counts|apps|both) ;; *) view=both ;; esac

    # install.sh records the configured interval; stale = 2x that when present.
    if [[ -r "$_iaa_state_dir/interval" ]]; then
        interval="$("$CAT" "$_iaa_state_dir/interval" 2>/dev/null)"
        if [[ "$interval" == <-> ]] && (( interval >= 600 )); then
            threshold=$(( interval * 2 ))
        fi
    fi

    if [[ ! -f "$_iaa_state_file" ]]; then
        printf '<result>NOT_COLLECTED</result>\n'; return 0
    fi
    mtime="$("$STAT" -f '%m' "$_iaa_state_file" 2>/dev/null)"
    if [[ -z "$mtime" ]]; then
        printf '<result>NOT_COLLECTED</result>\n'; return 0
    fi

    now="$("$DATE" +%s)"
    age=$(( now - mtime ))
    (( age < 0 )) && age=0

    # Reject an unsafe state path (symlink / group- or world-writable / not root-
    # owned when we are root) before reading its contents. A path someone else can
    # rewrite is not a cache we can certify (publication finding 12).
    if ! _iaa_state_path_safe "$_iaa_state_dir" || ! _iaa_state_path_safe "$_iaa_state_file"; then
        printf '<result>MALFORMED_CACHE</result>\n'; return 0
    fi

    # Validate the ENTIRE cache before slicing ANY view. A counts-only, empty,
    # truncated-header, invalid-numeric, or mismatched-count/list cache is not a
    # trustworthy state in any view -- return MALFORMED_CACHE and stop, so a
    # corrupt cache can never masquerade as a clean migrated Mac in counts, apps,
    # or both (publication finding 1). MALFORMED_CACHE dominates staleness.
    if ! _iaa_validate_cache "$_iaa_state_file"; then
        printf '<result>MALFORMED_CACHE</result>\n'; return 0
    fi

    # The cache is validated. Slice the body to the requested view.
    #   counts -> line 1 (the summary)
    #   apps   -> the INTEL_APP / IntelApps:None / TRUNCATED lines
    #   both   -> the whole file
    case "$view" in
        counts) body="$("$CAT" "$_iaa_state_file" 2>/dev/null | "$HEAD" -n 1)" ;;
        apps)   body="$("$CAT" "$_iaa_state_file" 2>/dev/null | "$GREP" -E '^(INTEL_APP \||IntelApps:None|TRUNCATED:)')" ;;
        *)      body="$("$CAT" "$_iaa_state_file" 2>/dev/null)" ;;
    esac
    [[ -z "$body" ]] && body="NOT_COLLECTED"

    if (( age > threshold )); then
        last="$("$DATE" -u -r "$mtime" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null)"
        [[ -z "$last" ]] && last="unknown"
        printf '<result>STALE (collector has not run in %ss, threshold %ss; last collected: %s). Cached value follows:\n%s</result>\n' \
            "$age" "$threshold" "$last" "$body"
    else
        printf '<result>%s</result>\n' "$body"
    fi
    return 0
}

# The three trigger words. Each names one mode; calling it reports that mode.
counts() { _iaa_read counts; }
apps()   { _iaa_read apps; }
both()   { _iaa_read both; }

# A trigger word passed as the first argument wins (command line / testing) and
# short-circuits the fixed EA trigger below.
case "${1:-}" in
    counts|apps|both) "$1"; exit 0 ;;
esac

# ─────────────────────────────────────────────────────────────────────────────
# Jamf EA trigger: keep exactly ONE of these three words uncommented. That word
# is the mode this EA reports. (Two uncommented => two <result> lines => invalid.)
# ─────────────────────────────────────────────────────────────────────────────
both
# counts
# apps
