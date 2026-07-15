#!/bin/zsh --no-rcs
# SPDX-FileCopyrightText: 2026 Robert Flanagan and macadmin-toolbox contributors
# SPDX-License-Identifier: MIT
# =============================================================================
# intel-app-auditor.zsh
#
# Fleet auditor for the Rosetta 2 wind-down: "Which Macs have Intel-classified
# application bundles, and which apps are they?"  One detection engine, two ways
# to run it:
#   * MODE=collector Background LaunchDaemon -> runs the scan on its own timer and
#                    caches the reader payload (counts summary + Intel-only app
#                    list, no <result> wrapper) atomically to
#                    ${INTEL_STATE_DIR:-/var/db/intel-app-auditor}/result.txt. The
#                    thin reader EA (intel-app-auditor-ea.zsh) then stat+cats that
#                    file at recon in well under a second. This is the split that
#                    keeps the system_profiler scan (seconds, not sub-second) off
#                    Jamf's recon clock;
#                    install.sh installs this script as the collector and schedules
#                    it.
#   * MODE=ea        Standalone / CLI convenience -> scans and prints one counts
#                    <result> line. NOT the Jamf recon path (that is the reader).
#
# Side effects: EA mode makes no change to the audited machine beyond a
# diagnostic syslog line (logger) and its stdout. Collector mode additionally
# writes ONE cache file to ${INTEL_STATE_DIR:-/var/db/intel-app-auditor} (atomic
# rename; root-only). It never uses sudo; when run by the jamf binary or the
# LaunchDaemon it is already root. It does not modify, move, or delete any
# application it audits.
#
# ---------------------------------------------------------------------------
# JSON-parsing method: JavaScriptCore via `osascript -l JavaScript` (JXA).
# ---------------------------------------------------------------------------
# Why JXA and not jq/python/plutil:
#   * jq / python3 are NOT guaranteed on a stock Mac (python was removed; jq
#     never shipped). Depending on them would break zero-dependency policy.
#   * `plutil` can convert JSON but has no query language, so classification
#     logic would still land back in fragile shell text parsing.
#   * `osascript -l JavaScript` (JavaScriptCore + the Foundation ObjC bridge)
#     is present on every macOS since 10.10. It parses JSON with a real parser,
#     lets us read a temp file via Foundation, and emit NUL-delimited records
#     that survive app names containing spaces, tabs, newlines, pipes, colons
#     and emoji. Records therefore stay structured across the one unavoidable
#     shell boundary (NUL cannot appear in a macOS path or in these strings),
#     honoring AUD-04 (never a `name|path|kind` split the data can corrupt).
#
# Classification is on the machine field `arch_kind` from
# `system_profiler -json SPApplicationsDataType`, NEVER the localized text
# "Kind: Intel" (which is 0 on a non-English Mac). `arch_kind` is treated as an
# OBSERVED private field: unknown/missing values become Unknown, never a silent
# IntelOnly:0 (AUD-01/AUD-02). A timeout or malformed/empty JSON yields
# ScanStatus:Partial, never a clean zero (AUD-03, verified: `-timeout` returns
# exit 0 with "{}").
#
# ---------------------------------------------------------------------------
# Command adapter + source guard
# ---------------------------------------------------------------------------
# Every mutating / external side-effect (system_profiler, chown, chmod, mv)
# routes through the single `run_cmd` adapter so
# the test suite can inject a spy (define a `CMD_ADAPTER_SPY` function) and so
# DRY_RUN=1 performs no mutation. `main` runs only when the script is executed,
# not when it is sourced (detected via ZSH_EVAL_CONTEXT; overridable with
# INTEL_AUDITOR_NO_MAIN=1), so tests can source and unit-test pure functions.
#
# Jamf parameter contract (jamf reserves $1=mount $2=computer $3=user):
#   $4 MODE            ea | collector          (env MODE)           default ea
#   $5 SCAN_USER_APPS  0 | 1                  (env SCAN_USER_APPS)  default 0
#   $6 SP_TIMEOUT      integer seconds 1..3600(env SP_TIMEOUT)      default 120
#   $7 EXTRA_ROOT      absolute dir to add    (env EXTRA_ROOT)      default none
#
# When run as the LaunchDaemon collector, there are no Jamf positional params;
# install.sh passes MODE=collector plus SCAN_USER_APPS / SP_TIMEOUT / EXTRA_ROOT
# and INTEL_STATE_DIR through the plist's EnvironmentVariables instead.
# =============================================================================

emulate -L zsh
setopt local_options pipe_fail no_glob_subst

# This script runs as ROOT (jamf binary / LaunchDaemon). Pin a trusted system
# PATH before invoking ANY external command (id, mkdir, chown, chmod, launchctl,
# mktemp, osascript, uname, logger, ...). Without this the collector would trust
# the PATH it inherits from its caller; a caller PATH with a user-writable dir
# ahead of the system dirs could shadow a command and run attacker code as root
# (publication finding 3). Absolute paths are used for the privileged file ops
# below; this line closes the gap for the remaining bare command names.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

: ${DRY_RUN:=0}

# Collector state directory. Must match intel-app-auditor-ea.zsh (the reader).
# Overridable for tests; the LaunchDaemon sets it via EnvironmentVariables.
: ${INTEL_STATE_DIR:=/var/db/intel-app-auditor}

# ----------------------------------------------------------------------------
# Logging: stdout (jamf captures) + logger (unless DRY_RUN). Diagnostic only;
# not a state change to the audited machine, so it does not route through the
# command adapter (which is reserved for genuine mutations the tests spy on).
# ----------------------------------------------------------------------------
logmsg() {
  print -r -- "$*"
  (( ${DRY_RUN:-0} )) && return 0
  command logger -t "intel-app-auditor" -- "$*" 2>/dev/null || true
}

# ----------------------------------------------------------------------------
# The ONE command adapter. All mutating / external commands go through here.
#   * If a CMD_ADAPTER_SPY function is defined (tests), delegate to it.
#   * Else if DRY_RUN, log the intent and do nothing.
#   * Else run it for real.
# stdout of the real command flows to the caller (needed for system_profiler).
# ----------------------------------------------------------------------------
run_cmd() {
  if typeset -f CMD_ADAPTER_SPY >/dev/null 2>&1; then
    CMD_ADAPTER_SPY "$@"
    return $?
  fi
  if (( ${DRY_RUN:-0} )); then
    logmsg "[dry-run] would exec: $*"
    return 0
  fi
  command "$@"
}

# ----------------------------------------------------------------------------
# Embedded JXA parser program, materialized to a temp file on first use.
# ----------------------------------------------------------------------------
ensure_jxa_parser() {
  [[ -n ${JXA_PARSER_FILE:-} && -f ${JXA_PARSER_FILE:-/nonexistent} ]] && return 0
  JXA_PARSER_FILE=$(mktemp -t iaa.parser.XXXXXX) || return 1
  cat > "$JXA_PARSER_FILE" <<'JSEOF'
// argv[0] = input JSON file, argv[1] = status output file.
// Emits NUL-delimited flat triples (arch_kind, path, _name) to stdout.
// Writes "Complete" or "Partial" to the status file. Structural failure
// (bad JSON, no top-level array, empty {} or empty array) => Partial + no
// records. A per-record missing arch_kind is emitted as an empty field and
// classified as Unknown by the shell (which then escalates to Partial).
function run(argv) {
  ObjC.import('Foundation');
  var inPath = argv[0], statusPath = argv[1];
  function writeStatus(s) {
    $(s).writeToFileAtomicallyEncodingError(statusPath, true, $.NSUTF8StringEncoding, $());
  }
  var nsdata = $.NSString.stringWithContentsOfFileEncodingError(inPath, $.NSUTF8StringEncoding, $());
  if (nsdata.isNil()) { writeStatus('Partial'); return; }
  var text = ObjC.unwrap(nsdata);
  var obj;
  try { obj = JSON.parse(text); } catch (e) { writeStatus('Partial'); return; }
  if (obj === null || typeof obj !== 'object') { writeStatus('Partial'); return; }
  var arr = obj['SPApplicationsDataType'];
  if (!Array.isArray(arr) || arr.length === 0) { writeStatus('Partial'); return; }
  var md = $.NSMutableData.data;
  var NUL = $.NSMutableData.dataWithLength(1);
  function emit(t) {
    if (typeof t !== 'string') t = '';
    md.appendData($(t).dataUsingEncoding($.NSUTF8StringEncoding));
    md.appendData(NUL);
  }
  var skipped = false;
  for (var i = 0; i < arr.length; i++) {
    var a = arr[i];
    // A null / non-object array element is unclassifiable. Real
    // SPApplicationsDataType only emits objects, but per AUD-02 ("never
    // silently drop to keep a clean zero") an unexpected element escalates
    // the scan to Partial rather than being dropped invisibly (F2).
    if (a === null || typeof a !== 'object') { skipped = true; continue; }
    emit(a['arch_kind']);
    emit(a['path']);
    emit(a['_name']);
  }
  $.NSFileHandle.fileHandleWithStandardOutput.writeData(md);
  writeStatus(skipped ? 'Partial' : 'Complete');
}
JSEOF
  [[ -f $JXA_PARSER_FILE ]]
}

# ----------------------------------------------------------------------------
# sp_json: raw system_profiler JSON (timeout-capped) via the command adapter.
# FIXTURE_JSON short-circuits to a captured fixture (tests + manual dry runs)
# so the real (multi-second) scan is not required.
# ----------------------------------------------------------------------------
sp_json() {
  if [[ -n ${FIXTURE_JSON:-} && -f ${FIXTURE_JSON:-/nonexistent} ]]; then
    print -r -- "$(<${FIXTURE_JSON})"
    return 0
  fi
  run_cmd /usr/sbin/system_profiler -json -timeout "${SP_TIMEOUT:-120}" SPApplicationsDataType
}

# ----------------------------------------------------------------------------
# parse_records (PURE w.r.t. its stdin): raw JSON on stdin -> validated
# NUL-delimited records on stdout; sets global PARSE_STATUS (Complete|Partial).
# ----------------------------------------------------------------------------
parse_records() {
  emulate -L zsh
  local intmp stmp
  intmp=$(mktemp -t iaa.in.XXXXXX) || { PARSE_STATUS=Partial; return 1; }
  stmp=$(mktemp -t iaa.st.XXXXXX)  || { command rm -f "$intmp"; PARSE_STATUS=Partial; return 1; }
  cat > "$intmp"
  if ! ensure_jxa_parser; then
    command rm -f "$intmp" "$stmp"; PARSE_STATUS=Partial; return 1
  fi
  local osa_rc
  osascript -l JavaScript "$JXA_PARSER_FILE" "$intmp" "$stmp"; osa_rc=$?
  PARSE_STATUS=$(<"$stmp" 2>/dev/null)
  # A crashed/killed parser (nonzero exit) or an empty status file cannot be
  # trusted to have emitted every record: fail closed to Partial.
  if (( osa_rc != 0 )) || [[ -z $PARSE_STATUS ]]; then
    PARSE_STATUS=Partial
  fi
  command rm -f "$intmp" "$stmp"
  (( osa_rc == 0 )) && return 0 || return 1
}

# ----------------------------------------------------------------------------
# classify_arch (PURE): arch_kind -> category. Unknown for missing/unrecognized.
# ----------------------------------------------------------------------------
classify_arch() {
  case $1 in
    arch_i64)      print -r -- IntelOnly ;;
    arch_arm_i64)  print -r -- Universal ;;
    arch_arm)      print -r -- AppleSilicon ;;
    arch_ios)      print -r -- iOS ;;
    arch_other)    print -r -- Other ;;
    *)             print -r -- Unknown ;;
  esac
}

# ----------------------------------------------------------------------------
# classify_arch_list (PURE): lipo architecture list -> auditor category.
# The direct scanner uses the main executable declared by CFBundleExecutable.
# ----------------------------------------------------------------------------
classify_arch_list() {
  emulate -L zsh
  local archs=" ${1:l} "
  local has_intel=0 has_arm=0 has_i386=0
  # Only x86_64 is a Rosetta 2 translation target. 32-bit i386 code has not run
  # on macOS since Catalina and is not translated by Rosetta 2, so an i386-only
  # slice must NOT be grouped with the Rosetta migration count.
  [[ $archs == *" x86_64 "* ]] && has_intel=1
  [[ $archs == *" arm64 "* || $archs == *" arm64e "* ]] && has_arm=1
  [[ $archs == *" i386 "* ]] && has_i386=1
  if (( has_intel && has_arm )); then
    print -r -- Universal
  elif (( has_intel )); then
    print -r -- IntelOnly
  elif (( has_arm )); then
    print -r -- AppleSilicon
  elif (( has_i386 )); then
    # Legacy 32-bit Intel: real but unsupported and non-translatable. Report as
    # Unknown so it surfaces as Partial rather than a clean Rosetta target.
    print -r -- Unknown
  else
    print -r -- Unknown
  fi
}

# ----------------------------------------------------------------------------
# in_scope (PURE): component-wise path match against SCOPE_ROOTS. Rejects
# /ApplicationsBackup; accepts /Applications and /Applications/Utilities/*.
# ----------------------------------------------------------------------------
in_scope() {
  emulate -L zsh
  local p=${1%/} root
  for root in "${SCOPE_ROOTS[@]}"; do
    root=${root%/}
    [[ -z $root ]] && continue
    if [[ $p == "$root" || $p == "$root"/* ]]; then
      return 0
    fi
  done
  return 1
}

# ----------------------------------------------------------------------------
# rosetta_status: N/A on Intel (gated on uname -m); Yes/No on Apple silicon.
# ----------------------------------------------------------------------------
rosetta_status() {
  emulate -L zsh
  local arch=${1:-${MACHINE_ARCH:-$(uname -m)}}
  if [[ $arch == x86_64 ]]; then
    print -r -- "N/A"
    return 0
  fi
  if [[ -e ${ROSETTA_RUNTIME:-/Library/Apple/usr/libexec/oah/libRosettaRuntime} ]]; then
    print -r -- "Yes"
  else
    print -r -- "No"
  fi
}

# ----------------------------------------------------------------------------
# Console-user helpers (overridable for tests via *_OVERRIDE vars).
# ----------------------------------------------------------------------------
console_user() {
  if [[ -n ${CONSOLE_USER_OVERRIDE+x} ]]; then
    print -r -- "$CONSOLE_USER_OVERRIDE"
    return 0
  fi
  command stat -f%Su /dev/console 2>/dev/null
}

is_valid_console_user() {
  local u=$1
  [[ -n $u && $u != root && $u != loginwindow && $u != _* ]]
}

console_home() {
  emulate -L zsh
  local u=$1 line
  if [[ -n ${CONSOLE_HOME_OVERRIDE+x} ]]; then
    print -r -- "$CONSOLE_HOME_OVERRIDE"
    return 0
  fi
  line=$(command dscl . -read "/Users/$u" NFSHomeDirectory 2>/dev/null) || return 1
  print -r -- "${line#NFSHomeDirectory: }"
}

# ----------------------------------------------------------------------------
# build_scope: assemble SCOPE_ROOTS + SCOPE_LABEL from config.
# ----------------------------------------------------------------------------
build_scope() {
  emulate -L zsh
  typeset -ga SCOPE_ROOTS
  SCOPE_ROOTS=(/Applications /Applications/Utilities)
  if [[ ${SCAN_USER_APPS:-0} == 1 ]]; then
    local u home
    u=$(console_user)
    if is_valid_console_user "$u"; then
      home=$(console_home "$u")
      # Only advertise ~/Applications if it actually exists, matching the
      # EXTRA_ROOT -d treatment (F3): scope should not name a non-existent root.
      [[ -n $home && -d ${home%/}/Applications ]] && SCOPE_ROOTS+=("${home%/}/Applications")
    fi
  fi
  if [[ -n ${EXTRA_ROOT:-} ]]; then
    # Reject roots containing the EA delimiters (';', '<', '>', newline) before
    # anything else (F1): SCOPE_LABEL is emitted verbatim inside the ';'-delimited
    # <result>...</result> EA line, so such a root would distort the EA / tags.
    if [[ $EXTRA_ROOT == *[$';\n<>']* ]]; then
      logmsg "ignoring EXTRA_ROOT with EA-delimiter character(s) '$EXTRA_ROOT'"
    elif [[ $EXTRA_ROOT == /* && -d $EXTRA_ROOT ]]; then
      SCOPE_ROOTS+=("${EXTRA_ROOT%/}")
    else
      logmsg "ignoring invalid EXTRA_ROOT '$EXTRA_ROOT'"
    fi
  fi
  typeset -g SCOPE_LABEL=${(j:,:)SCOPE_ROOTS}
}

# ----------------------------------------------------------------------------
# audit_apps: sp_json -> parse_records -> scope filter + classify + count.
# Sets AUDIT_* globals and INTEL_NAMES / INTEL_PATHS arrays.
# ----------------------------------------------------------------------------
audit_apps() {
  emulate -L zsh
  local rawfile recfile
  rawfile=$(mktemp -t iaa.raw.XXXXXX) || return 1
  recfile=$(mktemp -t iaa.rec.XXXXXX) || { command rm -f "$rawfile"; return 1; }
  integer sp_rc parse_rc
  sp_json > "$rawfile"; sp_rc=$?
  parse_records < "$rawfile" > "$recfile"; parse_rc=$?
  local scan_status=${PARSE_STATUS:-Partial}
  # A failed inventory or parser must never present as Complete (never a false
  # zero): degrade to Partial so the fallback engine is triggered.
  (( sp_rc == 0 && parse_rc == 0 )) || scan_status=Partial
  integer c_intel=0 c_uni=0 c_as=0 c_ios=0 c_other=0 c_unknown=0
  typeset -ga INTEL_NAMES INTEL_PATHS
  INTEL_NAMES=() INTEL_PATHS=()
  local -a fields
  local tok
  while IFS= read -r -d '' tok; do fields+=("$tok"); done < "$recfile"
  command rm -f "$rawfile" "$recfile"
  integer i
  for ((i = 1; i + 2 <= ${#fields}; i += 3)); do
    local ak=${fields[i]} app_path=${fields[i+1]} app_name=${fields[i+2]}
    # Validate BEFORE scope filtering. A record with no path cannot be scope-
    # tested at all, so the scope filter would silently drop it into a
    # reassuring clean zero. Count it as an invalid/Unknown record and force
    # Partial instead (AUD-01/02). An in-scope record whose arch_kind is empty
    # is still handled below by classify_arch -> Unknown.
    if [[ -z $app_path ]]; then
      (( c_unknown++ )); scan_status=Partial; continue
    fi
    in_scope "$app_path" || continue
    case "$(classify_arch "$ak")" in
      IntelOnly)    (( c_intel++ ));   INTEL_NAMES+=("$app_name"); INTEL_PATHS+=("$app_path") ;;
      Universal)    (( c_uni++ )) ;;
      AppleSilicon) (( c_as++ )) ;;
      iOS)          (( c_ios++ )) ;;
      Other)        (( c_other++ )) ;;
      Unknown)      (( c_unknown++ )); scan_status=Partial ;;
    esac
  done
  (( c_unknown > 0 )) && scan_status=Partial
  typeset -g AUDIT_INTEL=$c_intel AUDIT_UNI=$c_uni AUDIT_AS=$c_as \
             AUDIT_IOS=$c_ios AUDIT_OTHER=$c_other AUDIT_UNKNOWN=$c_unknown \
             AUDIT_STATUS=$scan_status AUDIT_SOURCE=SystemProfiler
  return 0
}

# ----------------------------------------------------------------------------
# direct_audit_apps: fallback for systems where SPApplicationsDataType is empty
# or unusable (for example, when Spotlight indexing is disabled). It walks the
# configured roots without following symlinks, prunes at each .app bundle, reads
# CFBundleExecutable, and classifies that Mach-O with stock `lipo`.
#
# Missing metadata, unreadable bundles, and non-Mach-O main executables become
# Unknown and make the result Partial. A completely empty scan is also Partial.
# ----------------------------------------------------------------------------
direct_audit_apps() {
  emulate -L zsh
  setopt local_options pipe_fail
  integer c_intel=0 c_uni=0 c_as=0 c_ios=0 c_other=0 c_unknown=0
  integer bundle_count=0 scan_failed=0
  typeset -ga INTEL_NAMES INTEL_PATHS
  INTEL_NAMES=() INTEL_PATHS=()
  typeset -A seen
  local root listfile app plist exe bin archs category app_name file_kind
  local is_ios_wrapper
  local -a wrapped_plists

  listfile=$(mktemp -t iaa.apps.XXXXXX) || return 1
  for root in "${SCOPE_ROOTS[@]}"; do
    [[ -d $root ]] || { scan_failed=1; continue; }
    if ! run_cmd /usr/bin/find "$root" -type d -name '*.app' -prune -print0 >> "$listfile" 2>/dev/null; then
      scan_failed=1
    fi
  done

  while IFS= read -r -d '' app; do
    [[ -n ${seen[$app]:-} ]] && continue
    seen[$app]=1
    (( bundle_count++ ))
    is_ios_wrapper=0
    plist="$app/Contents/Info.plist"
    if [[ ! -f $plist ]]; then
      wrapped_plists=("$app"/Wrapper/*.app/Info.plist(N))
      if (( ${#wrapped_plists} == 1 )); then
        plist=${wrapped_plists[1]}
        is_ios_wrapper=1
      else
        (( c_unknown++ )); scan_failed=1; continue
      fi
    fi
    exe=$(run_cmd /usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$plist" 2>/dev/null)
    if [[ -z $exe || $exe == */* ]]; then
      (( c_unknown++ )); scan_failed=1; continue
    fi
    if (( is_ios_wrapper )); then
      bin="${plist:h}/$exe"
    else
      bin="$app/Contents/MacOS/$exe"
    fi
    if [[ ! -f $bin ]]; then
      (( c_unknown++ )); scan_failed=1; continue
    fi
    archs=$(run_cmd /usr/bin/lipo -archs "$bin" 2>/dev/null)
    category=$(classify_arch_list "$archs")
    if (( is_ios_wrapper )) && [[ $category != Unknown ]]; then
      category=iOS
    elif [[ $category == Unknown ]]; then
      # lipo found no recognized architecture. Only an interpreter script with a
      # valid shebang is legitimately "Other" (a non-Mach-O launcher). file(1)
      # reports "text executable" only for an executable file with a #! shebang;
      # arbitrary data, truncated files, and unknown Mach-O types describe as
      # something else and must remain Unknown -> Partial, not a Complete Other.
      file_kind=$(run_cmd /usr/bin/file -b "$bin" 2>/dev/null)
      [[ ${file_kind:l} == *"text executable"* ]] && category=Other
    fi
    app_name=$(run_cmd /usr/libexec/PlistBuddy -c 'Print :CFBundleDisplayName' "$plist" 2>/dev/null)
    [[ -n $app_name ]] || app_name=$(run_cmd /usr/libexec/PlistBuddy -c 'Print :CFBundleName' "$plist" 2>/dev/null)
    [[ -n $app_name ]] || app_name=${app:t:r}
    case $category in
      IntelOnly)    (( c_intel++ )); INTEL_NAMES+=("$app_name"); INTEL_PATHS+=("$app") ;;
      Universal)    (( c_uni++ )) ;;
      AppleSilicon) (( c_as++ )) ;;
      iOS)           (( c_ios++ )) ;;
      Other)         (( c_other++ )) ;;
      *)             (( c_unknown++ )); scan_failed=1 ;;
    esac
  done < "$listfile"
  command rm -f "$listfile"

  (( bundle_count > 0 )) || scan_failed=1
  typeset -g AUDIT_INTEL=$c_intel AUDIT_UNI=$c_uni AUDIT_AS=$c_as \
             AUDIT_IOS=$c_ios AUDIT_OTHER=$c_other AUDIT_UNKNOWN=$c_unknown \
             AUDIT_SOURCE=DirectBundleScan
  if (( scan_failed || c_unknown > 0 )); then
    typeset -g AUDIT_STATUS=Partial
  else
    typeset -g AUDIT_STATUS=Complete
  fi
  return 0
}

# audit_apps_with_fallback: run the primary system_profiler engine, then
# guarantee the result before trusting it.
#
#   * Primary ambiguous/failed (Partial): the direct bundle scanner becomes the
#     engine of record. If it cannot run either, stay Partial.
#   * Primary Complete: system_profiler can return a well-formed list that
#     silently OMITS installed bundles, and nothing in its own output proves the
#     list is exhaustive (publication finding 1 / red-team finding 6). So a
#     Complete primary is NOT trusted on its own: it is reconciled against an
#     independent filesystem walk (direct_audit_apps). The two inventories must
#     agree on the Intel-only count AND the total in-scope bundle count, and the
#     direct scan must itself be Complete. Any disagreement, or a direct scan
#     that cannot run or is itself Partial, fails closed to Partial. On a real
#     mismatch the DIRECT scan's inventory is presented, because that is the
#     engine that just found the bundle(s) system_profiler omitted.
#
# This is what makes "never a false zero" true for the case the reviews found:
# an arm-only system_profiler response while a real x86_64 app sits on disk now
# reconciles to Partial and surfaces the Intel app, instead of IntelOnly:0/Complete.
audit_apps_with_fallback() {
  audit_apps || return 1

  if [[ $AUDIT_STATUS != Complete ]]; then
    if ! direct_audit_apps; then
      typeset -g AUDIT_STATUS=Partial AUDIT_SOURCE=SystemProfiler+FallbackFailed
    fi
    return 0
  fi

  # Capture the primary (system_profiler) result; direct_audit_apps overwrites
  # the AUDIT_*/INTEL_* globals.
  local p_intel=$AUDIT_INTEL p_uni=$AUDIT_UNI p_as=$AUDIT_AS \
        p_ios=$AUDIT_IOS p_other=$AUDIT_OTHER p_unknown=$AUDIT_UNKNOWN
  local -a p_names=("${INTEL_NAMES[@]}") p_paths=("${INTEL_PATHS[@]}")
  integer p_total=$(( p_intel + p_uni + p_as + p_ios + p_other + p_unknown ))

  restore_primary() {
    typeset -ga INTEL_NAMES INTEL_PATHS
    INTEL_NAMES=("${p_names[@]}") INTEL_PATHS=("${p_paths[@]}")
    typeset -g AUDIT_INTEL=$p_intel AUDIT_UNI=$p_uni AUDIT_AS=$p_as \
               AUDIT_IOS=$p_ios AUDIT_OTHER=$p_other AUDIT_UNKNOWN=$p_unknown
  }

  if ! direct_audit_apps; then
    # Cannot verify completeness. An unverifiable Complete primary must not stand
    # as a trusted zero: keep the primary inventory but mark it Partial.
    restore_primary
    typeset -g AUDIT_STATUS=Partial AUDIT_SOURCE=SystemProfiler+ReconcileUnavailable
    return 0
  fi

  integer d_total=$(( AUDIT_INTEL + AUDIT_UNI + AUDIT_AS + AUDIT_IOS + AUDIT_OTHER + AUDIT_UNKNOWN ))

  # Reconcile the exact Intel-only PATH SETS, not only the aggregate counts.
  # Matching counts do not prove matching inventories: a primary listing
  # /Applications/PrimaryIntel.app and a direct scan listing
  # /Applications/DifferentIntel.app both have IntelOnly:1 yet describe different
  # machines. Comparing only counts would stamp that disagreement Complete and
  # cache the WRONG Intel app list with ScanStatus:Complete (publication finding
  # 2). Normalize (strip a trailing slash), sort, and require the primary and
  # direct Intel-only path sets to be identical before trusting the primary.
  local -a d_paths=("${INTEL_PATHS[@]}")
  local pth prim_set dir_set
  local -a p_norm d_norm
  for pth in "${p_paths[@]}"; do p_norm+=("${pth%/}"); done
  for pth in "${d_paths[@]}"; do d_norm+=("${pth%/}"); done
  prim_set=${(pj:\n:)${(o)p_norm}}
  dir_set=${(pj:\n:)${(o)d_norm}}

  if [[ $AUDIT_STATUS == Complete ]] && (( AUDIT_INTEL == p_intel && d_total == p_total )) \
     && [[ $prim_set == $dir_set ]]; then
    # Both engines completed and agree on counts AND on the exact Intel-only path
    # set: trust it, and present the primary (system_profiler) inventory, which
    # carries the richer _name values.
    restore_primary
    typeset -g AUDIT_STATUS=Complete AUDIT_SOURCE=SystemProfiler+DirectReconciled
    return 0
  fi

  # Disagreement, or the direct scan was itself Partial. The primary Complete
  # cannot be trusted. Fail closed to Partial and KEEP the direct scan's
  # inventory (already in AUDIT_*/INTEL_*), which surfaces the omitted bundle(s).
  typeset -g AUDIT_STATUS=Partial AUDIT_SOURCE=SystemProfiler+DirectMismatch
  return 0
}

# ----------------------------------------------------------------------------
# xesc (PURE): XML-escape a user-controlled string (app name / path) and scrub
# control characters before it is cached and later wrapped verbatim in <result>
# by the reader. Pure zsh parameter expansion, no subprocesses.
# ----------------------------------------------------------------------------
xesc() {
  emulate -L zsh
  local s=$1
  s=${s//[[:cntrl:]]/ }
  s=${s//&/&amp;}
  s=${s//</&lt;}
  s=${s//>/&gt;}
  print -r -- "$s"
}

# ----------------------------------------------------------------------------
# counts_line: the compact machine-readable summary (VIEW=counts). This is the
# single source of the counts payload: MODE=ea wraps it inline, the collector
# caches it as line 1, and the reader can slice it back out.
# ----------------------------------------------------------------------------
counts_line() {
  print -r -- "IntelOnly:${AUDIT_INTEL};Universal:${AUDIT_UNI};AppleSilicon:${AUDIT_AS};iOS:${AUDIT_IOS};Other:${AUDIT_OTHER};Unknown:${AUDIT_UNKNOWN};ScanStatus:${AUDIT_STATUS};DetectionSource:${AUDIT_SOURCE};RosettaRuntimePresent:${ROSETTA_STATUS};Arch:${MACHINE_ARCH};Scope:${SCOPE_LABEL}"
}

# Backward-compatible alias: earlier revisions called this ea_inner.
ea_inner() { counts_line; }

# ----------------------------------------------------------------------------
# app_lines: one line per Intel-ONLY application bundle, escaped and bounded, in
# the shape `INTEL_APP | <name> | <path>` (VIEW=apps). Substring-matchable in a
# Smart Group by app name or path. When nothing is Intel-only, emits a single
# `IntelApps:None` marker so "no Intel-only apps" is itself a Smart Group value.
# The list is capped so the cached EA value stays within Jamf's per-record bound.
# ----------------------------------------------------------------------------
app_lines() {
  emulate -L zsh
  integer i n=${#INTEL_NAMES}
  if (( n == 0 )); then
    print -r -- "IntelApps:None"
    return 0
  fi
  integer max_chars=${IAA_APPS_MAX_CHARS:-24000} used=0 omitted=0
  local nm pt line
  for ((i = 1; i <= n; i++)); do
    nm=$(xesc "${INTEL_NAMES[i]}")
    pt=$(xesc "${INTEL_PATHS[i]}")
    line="INTEL_APP | ${nm} | ${pt}"
    if (( used + ${#line} + 1 <= max_chars )); then
      print -r -- "$line"
      (( used += ${#line} + 1 ))
    else
      (( omitted++ ))
    fi
  done
  (( omitted > 0 )) && print -r -- "TRUNCATED: ${omitted} Intel-only app(s) omitted to bound the EA value size"
  return 0
}

# ----------------------------------------------------------------------------
# cache_body: exactly what the collector writes and the reader slices. Line 1 is
# the counts summary; the remaining lines are the Intel-only app list (or the
# IntelApps:None marker). VIEW=both is this whole body; VIEW=counts is line 1;
# VIEW=apps is everything after line 1.
# ----------------------------------------------------------------------------
cache_body() {
  counts_line
  app_lines
}

# ----------------------------------------------------------------------------
# ea_string: the live counts <result> line (MODE=ea, standalone / CLI use). The
# Jamf recon path is the thin reader EA, which reads cache instead of scanning.
# ----------------------------------------------------------------------------
ea_string() {
  print -r -- "<result>$(counts_line)</result>"
}

# ----------------------------------------------------------------------------
# write_state (MODE=collector): atomically cache cache_body to the collector
# state file, root-only. Mirrors the AI Software Inventory collector: write a
# temp file in the SAME directory, then mv -f (an atomic rename within one
# filesystem), so the reader EA can only ever observe the previous complete file
# or the new one, never a half-written value. Never wraps in <result>; the
# reader does that. The chown/chmod/mv side effects route through run_cmd so
# DRY_RUN and the test spy are honored; the state-dir/root-owner steps are gated
# on being root.
# ----------------------------------------------------------------------------
write_state() {
  emulate -L zsh
  local dir=${INTEL_STATE_DIR:-/var/db/intel-app-auditor}
  local statefile="$dir/result.txt" tmpfile body
  body=$(cache_body)

  if (( ${DRY_RUN:-0} )); then
    logmsg "[dry-run] would cache collector state to $statefile"
    logmsg "$body"
    typeset -g STATE_FILE_PATH=$statefile
    return 0
  fi

  if ! command mkdir -p "$dir" 2>/dev/null; then
    logmsg "collector: could not create state directory $dir"
    return 1
  fi
  # FAIL CLOSED on ownership/mode. The public guarantee is a root-only, non-world-
  # writable state path; if we cannot actually establish that, we must NOT publish
  # a cache the reader would then trust (publication finding 12). Every hardening
  # step below is required, not best-effort. run_cmd returns success under DRY_RUN
  # and the test spy, so this does not break dry runs or unit tests.
  if (( UID == 0 )); then
    if ! run_cmd /usr/sbin/chown root:wheel "$dir"; then
      logmsg "collector: refusing to publish -- could not chown $dir to root:wheel"
      return 1
    fi
  fi
  # The only reader (the EA) runs as root at recon, and the contents (app paths,
  # usernames) are mildly sensitive; 0700 (not world/group-writable) is the point.
  if ! run_cmd /bin/chmod 0700 "$dir"; then
    logmsg "collector: refusing to publish -- could not chmod 0700 $dir"
    return 1
  fi

  tmpfile="$statefile.tmp.$$"
  if ! printf '%s' "$body" > "$tmpfile"; then
    command rm -f "$tmpfile" 2>/dev/null
    logmsg "collector: failed to write temporary state file $tmpfile"
    return 1
  fi
  if ! run_cmd /bin/chmod 0600 "$tmpfile"; then
    command rm -f "$tmpfile" 2>/dev/null
    logmsg "collector: refusing to publish -- could not chmod 0600 $tmpfile"
    return 1
  fi
  if (( UID == 0 )); then
    if ! run_cmd /usr/sbin/chown root:wheel "$tmpfile"; then
      command rm -f "$tmpfile" 2>/dev/null
      logmsg "collector: refusing to publish -- could not chown $tmpfile to root:wheel"
      return 1
    fi
  fi
  if ! command mv -f "$tmpfile" "$statefile"; then
    command rm -f "$tmpfile" 2>/dev/null
    logmsg "collector: failed to rename temporary state file into place ($statefile)"
    return 1
  fi
  logmsg "collector: cached state to $statefile"
  typeset -g STATE_FILE_PATH=$statefile
  return 0
}

# ----------------------------------------------------------------------------
# main: validate config, run the engine, dispatch on MODE.
# ----------------------------------------------------------------------------
main() {
  emulate -L zsh
  setopt local_options pipe_fail

  # Remove the materialized JXA parser file on any exit, including a signal, so
  # an interrupted run never leaves temp files behind.
  trap '[[ -n ${JXA_PARSER_FILE:-} ]] && command rm -f "$JXA_PARSER_FILE"' EXIT INT TERM

  # Jamf custom params start at $4; env fallback; safe defaults.
  local p_mode=${4:-} p_scan=${5:-} p_timeout=${6:-} p_root=${7:-}
  typeset -g MODE=${p_mode:-${MODE:-ea}}
  typeset -g SCAN_USER_APPS=${p_scan:-${SCAN_USER_APPS:-0}}
  typeset -g SP_TIMEOUT=${p_timeout:-${SP_TIMEOUT:-120}}
  typeset -g EXTRA_ROOT=${p_root:-${EXTRA_ROOT:-}}

  # Validate every input before use.
  case $MODE in
    ea|collector) ;;
    *) logmsg "invalid MODE '$MODE'; defaulting to ea"; MODE=ea ;;
  esac
  [[ $SCAN_USER_APPS == (0|1) ]] || { logmsg "invalid SCAN_USER_APPS '$SCAN_USER_APPS'; defaulting to 0"; SCAN_USER_APPS=0; }
  if [[ $SP_TIMEOUT != <-> ]] || (( SP_TIMEOUT < 1 || SP_TIMEOUT > 3600 )); then
    logmsg "invalid SP_TIMEOUT '$SP_TIMEOUT'; defaulting to 120"
    SP_TIMEOUT=120
  fi

  typeset -g MACHINE_ARCH=${MACHINE_ARCH:-$(uname -m)}
  typeset -g ROSETTA_STATUS
  ROSETTA_STATUS=$(rosetta_status)

  build_scope
  audit_apps_with_fallback || { logmsg "audit failed"; return 1; }

  case $MODE in
    ea)     ea_string ;;
    collector)
      # Background LaunchDaemon: cache the value for the thin reader EAs. Never
      # print <result> here; recon reads the file, not this stdout.
      write_state || { logmsg "collector: state write failed"; return 1; }
      ;;
  esac
  return 0
}

# ----------------------------------------------------------------------------
# Source guard: run main only when executed, not when sourced. When executed,
# ZSH_EVAL_CONTEXT is "toplevel"; when sourced it contains ":file".
# ----------------------------------------------------------------------------
if [[ $ZSH_EVAL_CONTEXT != *:file* && -z ${INTEL_AUDITOR_NO_MAIN:-} ]]; then
  main "$@"
  exit $?
fi
