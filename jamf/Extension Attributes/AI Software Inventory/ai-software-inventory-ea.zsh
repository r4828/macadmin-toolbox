#!/bin/zsh --no-rcs
# SPDX-FileCopyrightText: 2026 Robert Flanagan and macadmin-toolbox contributors
# SPDX-License-Identifier: MIT
#
# Name:        ai-software-inventory-ea.zsh
# Purpose:     Jamf Extension Attribute reader for AI Software Inventory.
#              The reader does no scanning; recon only pays for stat + cat.
# Context:     Jamf Pro computer EA (Data Type String, Input Type Script).
#              Deploy install.sh first so the collector writes result.txt.
# Parameters:  none
# Tested on:   macOS 15.7.7 Sequoia
# Author:      Robert Flanagan (@r4828)

export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

STAT=/usr/bin/stat
DATE=/bin/date
CAT=/bin/cat

# Must match ai-inventory-collector.zsh.
: ${AI_INV_STATE_DIR:=/var/db/ai-software-inventory}
STATE_DIR="$AI_INV_STATE_DIR"
STATE_FILE="$STATE_DIR/result.txt"
STALE_THRESHOLD=28800   # fallback: 8h = 2x the default 4h interval (StartInterval 14400)

# install.sh records the configured interval; stale = 2x that when present.
if [[ -r "$STATE_DIR/interval" ]]; then
    interval="$("$CAT" "$STATE_DIR/interval" 2>/dev/null)"
    if [[ "$interval" == <-> ]] && (( interval >= 600 )); then
        STALE_THRESHOLD=$(( interval * 2 ))
    fi
fi

# Always print one Jamf <result> value.
if [[ ! -f "$STATE_FILE" ]]; then
    printf '<result>NOT_COLLECTED</result>\n'
    exit 0
fi

mtime="$("$STAT" -f '%m' "$STATE_FILE" 2>/dev/null)"
if [[ -z "$mtime" ]]; then
    printf '<result>NOT_COLLECTED</result>\n'
    exit 0
fi

now="$("$DATE" +%s)"
age=$(( now - mtime ))
(( age < 0 )) && age=0

body="$("$CAT" "$STATE_FILE" 2>/dev/null)"
[[ -z "$body" ]] && body="None"

if (( age > STALE_THRESHOLD )); then
    last="$("$DATE" -u -r "$mtime" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null)"
    [[ -z "$last" ]] && last="unknown"
    printf '<result>STALE (collector has not run in %ss, threshold %ss; last collected: %s). Cached value follows:\n%s</result>\n' \
        "$age" "$STALE_THRESHOLD" "$last" "$body"
else
    printf '<result>%s</result>\n' "$body"
fi
exit 0
