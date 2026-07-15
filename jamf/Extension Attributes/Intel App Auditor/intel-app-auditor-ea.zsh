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
# One reader, three trigger words (counts = summary; apps = Intel-only list or
# IntelApps:None; both = default), each a single <result> usable as Smart Group
# criteria. The heavy scan runs once in the collector; each mode slices the cache.
# As a Jamf EA keep exactly ONE trigger line uncommented; from the CLI pass the word.

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

# _iaa_state_path_safe <path>: reject a state node that breaks the collector's root-only
# guarantee -- a symlink, group/world-writable, or (when root) not root-owned. 0 when safe.
_iaa_state_path_safe() {
    emulate -L zsh   # /etc/zshenv could set KSH_ARRAYS and skew perm[6]/perm[9]
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

# _iaa_validate_cache <file>: prove the whole cache is well-formed before any view is
# sliced -- (1) a line-1 counts summary, (2) an app-list section, (3) count/list agreement
# (IntelOnly count == INTEL_APP lines; IntelApps:None requires 0; TRUNCATED exempt). So a
# malformed cache can't masquerade as a clean result in any view.
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

# _iaa_read <counts|apps|both>: stat + validate the cache, slice to the view, apply the
# NOT_COLLECTED / STALE / MALFORMED_CACHE sentinels, print one <result>.
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

    # Reject an unsafe state path (symlink / writable / not root-owned) before reading it.
    if ! _iaa_state_path_safe "$_iaa_state_dir" || ! _iaa_state_path_safe "$_iaa_state_file"; then
        printf '<result>MALFORMED_CACHE</result>\n'; return 0
    fi

    # Validate the whole cache before slicing; MALFORMED_CACHE dominates staleness.
    if ! _iaa_validate_cache "$_iaa_state_file"; then
        printf '<result>MALFORMED_CACHE</result>\n'; return 0
    fi

    # Cache validated; slice to the view (counts = line 1, apps = list lines, both = whole file).
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

# A trigger word as the first argument wins (CLI/testing); short-circuits the EA trigger.
case "${1:-}" in
    counts|apps|both) "$1"; exit 0 ;;
esac

# Jamf EA trigger: keep exactly ONE of these three words uncommented. That word
# is the mode this EA reports. (Two uncommented => two <result> lines => invalid.)
both
# counts
# apps
