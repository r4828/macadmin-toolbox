#!/bin/zsh
# SPDX-FileCopyrightText: 2026 Robert Flanagan and macadmin-toolbox contributors
# SPDX-License-Identifier: MIT
# =============================================================================
# test_intel-app-auditor.zsh
#
# Runnable on any stock Mac:  zsh test_intel-app-auditor.zsh
# Sets DRY_RUN=1 and INTEL_AUDITOR_NO_MAIN=1, sources the auditor (so main does
# NOT run), injects a command-adapter spy, and exercises the pure functions and
# the engine against captured JSON fixtures. Non-destructive. Exits non-zero on
# any failed assertion.
#
# JXA (osascript) is exercised for real against fixtures because it is a stock,
# read-only parser; the live (multi-second) system_profiler scan is never run.
# =============================================================================

emulate -L zsh
setopt local_options

export DRY_RUN=1
export INTEL_AUDITOR_NO_MAIN=1

SCRIPT_DIR=${0:A:h}
AUDITOR="$SCRIPT_DIR/intel-app-auditor.zsh"

if [[ ! -f $AUDITOR ]]; then
  print -u2 -- "FATAL: cannot find auditor at $AUDITOR"
  exit 2
fi

# --- assertion harness -------------------------------------------------------
integer PASS=0 FAIL=0
pass() { (( PASS++ )); print -r -- "  ok   - $1"; }
fail() { (( FAIL++ )); print -r -- "  FAIL - $1"; }

assert_eq() {  # expected actual message
  local exp=$1 act=$2 msg=$3
  if [[ $act == "$exp" ]]; then pass "$msg"
  else fail "$msg (expected <$exp> got <$act>)"; fi
}
assert_contains() {  # haystack needle message
  local hay=$1 needle=$2 msg=$3
  if [[ $hay == *"$needle"* ]]; then pass "$msg"
  else fail "$msg (missing <$needle> in <$hay>)"; fi
}
assert_not_contains() {  # haystack needle message
  local hay=$1 needle=$2 msg=$3
  if [[ $hay != *"$needle"* ]]; then pass "$msg"
  else fail "$msg (unexpected <$needle> present)"; fi
}
assert_rc() {  # expected_rc actual_rc message
  assert_eq "$1" "$2" "$3"
}

# --- command-adapter spy -----------------------------------------------------
typeset -ga SPY_CALLS
SPY_CALLS=()
CMD_ADAPTER_SPY() {
  SPY_CALLS+=("$*")
  case ${1:t} in
    system_profiler)
      [[ -n ${SPY_SP_FIXTURE:-} && -f ${SPY_SP_FIXTURE:-/nonexistent} ]] && print -r -- "$(<${SPY_SP_FIXTURE})"
      return 0 ;;
    find|PlistBuddy)
      command "$@"
      return $? ;;
    lipo)
      case ${3:t} in
        IntelTool) print -r -- x86_64; return 0 ;;
        UniversalTool) print -r -- 'x86_64 arm64'; return 0 ;;
        NativeTool) print -r -- arm64; return 0 ;;
        IOSTool) print -r -- arm64; return 0 ;;
        *) return 1 ;;
      esac ;;
    file)
      [[ ${3:t} == ScriptTool ]] && { print -r -- 'POSIX shell script text executable'; return 0; }
      return 1 ;;
  esac
  return 0
}
spy_has() {  # substring -> 0 if any recorded call contains it
  local needle=$1 c
  for c in "${SPY_CALLS[@]}"; do [[ $c == *"$needle"* ]] && return 0; done
  return 1
}

# --- source the auditor (main must NOT run) ----------------------------------
source "$AUDITOR"
if [[ -n ${MAIN_RAN:-} ]]; then fail "source guard: main ran on source"; fi
pass "sourced auditor without running main"

# --- fixtures ----------------------------------------------------------------
FIX=$(mktemp -d -t iaa.fix.XXXXXX) || exit 2
cleanup() { command rm -rf "$FIX"; }
trap cleanup EXIT

# normal: 3 in-scope Intel (2 under /Applications incl. a malicious name,
# 1 under /Applications/Utilities); 1 universal, 1 arm, 1 ios, 1 other;
# 2 Intel apps OUT of scope (/Library and /ApplicationsBackup) that must be
# excluded -> proves component-wise scope (AUD-06).
cat > "$FIX/normal.json" <<'JSON'
{"SPApplicationsDataType":[
 {"_name":"IntelApp1","path":"/Applications/IntelApp1.app","arch_kind":"arch_i64"},
 {"_name":"Ev|il:App\n<x> 😀 \"q\"","path":"/Applications/Evil.app","arch_kind":"arch_i64"},
 {"_name":"UtilIntel","path":"/Applications/Utilities/UtilIntel.app","arch_kind":"arch_i64"},
 {"_name":"UniApp","path":"/Applications/UniApp.app","arch_kind":"arch_arm_i64"},
 {"_name":"NativeApp","path":"/Applications/NativeApp.app","arch_kind":"arch_arm"},
 {"_name":"iOSApp","path":"/Applications/iOSApp.app","arch_kind":"arch_ios"},
 {"_name":"OtherApp","path":"/Applications/OtherApp.app","arch_kind":"arch_other"},
 {"_name":"LibIntel","path":"/Library/Foo/LibIntel.app","arch_kind":"arch_i64"},
 {"_name":"BackupIntel","path":"/ApplicationsBackup/BackupIntel.app","arch_kind":"arch_i64"}
]}
JSON

# non-English locale: SAME arch_kind values as normal for the in-scope Intel
# apps, but the human-readable "kind" field is Japanese and names are non-ASCII.
# A `grep "Kind: Intel"` would return 0 here; arch_kind still yields Intel:3.
cat > "$FIX/nonenglish.json" <<'JSON'
{"SPApplicationsDataType":[
 {"_name":"インテルアプリ1","path":"/Applications/JIntel1.app","arch_kind":"arch_i64","kind":"アプリケーション（Intel）"},
 {"_name":"悪意アプリ","path":"/Applications/JEvil.app","arch_kind":"arch_i64","kind":"アプリケーション（Intel）"},
 {"_name":"ユーティリティ","path":"/Applications/Utilities/JUtil.app","arch_kind":"arch_i64","kind":"アプリケーション（Intel）"},
 {"_name":"ネイティブ","path":"/Applications/JNative.app","arch_kind":"arch_arm","kind":"アプリケーション（Appleシリコン）"}
]}
JSON

print -n '{}' > "$FIX/empty.json"
print -n '{"SPApplicationsDataType":[]}' > "$FIX/emptyarray.json"
print -n 'this is not json {{' > "$FIX/malformed.json"

# in-scope app with NO arch_kind field + one normal Intel app
cat > "$FIX/missingarch.json" <<'JSON'
{"SPApplicationsDataType":[
 {"_name":"NoArch","path":"/Applications/NoArch.app"},
 {"_name":"IntelApp1","path":"/Applications/IntelApp1.app","arch_kind":"arch_i64"}
]}
JSON

# in-scope app with an UNKNOWN arch_kind enum value
cat > "$FIX/unknownarch.json" <<'JSON'
{"SPApplicationsDataType":[
 {"_name":"Martian","path":"/Applications/Martian.app","arch_kind":"arch_martian"}
]}
JSON

# array containing a non-object element alongside a valid Intel app: the valid
# app is still emitted, but the unclassifiable element must escalate to Partial
# (F2 / AUD-02: never silently drop to keep a clean status).
cat > "$FIX/nonobject.json" <<'JSON'
{"SPApplicationsDataType":[
 {"_name":"IntelApp1","path":"/Applications/IntelApp1.app","arch_kind":"arch_i64"},
 "not_an_object",
 null
]}
JSON

# =============================================================================
print -r -- "== unit: classify_arch =="
assert_eq IntelOnly     "$(classify_arch arch_i64)"      "arch_i64 -> IntelOnly"
assert_eq Universal     "$(classify_arch arch_arm_i64)"  "arch_arm_i64 -> Universal"
assert_eq AppleSilicon  "$(classify_arch arch_arm)"      "arch_arm -> AppleSilicon"
assert_eq iOS           "$(classify_arch arch_ios)"      "arch_ios -> iOS"
assert_eq Other         "$(classify_arch arch_other)"    "arch_other -> Other"
assert_eq Unknown       "$(classify_arch '')"            "empty -> Unknown"
assert_eq Unknown       "$(classify_arch arch_martian)"  "unknown enum -> Unknown"

print -r -- "== unit: classify_arch_list =="
assert_eq IntelOnly    "$(classify_arch_list 'x86_64')"       "x86_64 executable -> IntelOnly"
assert_eq IntelOnly    "$(classify_arch_list 'i386 x86_64')"  "legacy Intel executable -> IntelOnly"
assert_eq Universal    "$(classify_arch_list 'x86_64 arm64')" "fat Intel/arm executable -> Universal"
assert_eq AppleSilicon "$(classify_arch_list 'arm64')"        "arm64 executable -> AppleSilicon"
assert_eq Unknown      "$(classify_arch_list '')"             "missing lipo result -> Unknown"
# finding 5: i386 is NOT a Rosetta 2 target. Pure 32-bit Intel must not be
# grouped with the IntelOnly migration count.
assert_eq Unknown      "$(classify_arch_list 'i386')"         "pure i386 (legacy 32-bit) -> Unknown, not IntelOnly (finding 5)"
assert_eq IntelOnly    "$(classify_arch_list 'i386 x86_64')"  "i386+x86_64 fat binary -> IntelOnly (x86_64 is the Rosetta target)"
assert_eq Universal    "$(classify_arch_list 'i386 x86_64 arm64')" "i386+x86_64+arm64 -> Universal"

print -r -- "== unit: in_scope (component-wise) =="
SCOPE_ROOTS=(/Applications /Applications/Utilities)
in_scope /Applications/Foo.app            && pass "/Applications/Foo.app in scope"        || fail "/Applications/Foo.app should be in scope"
in_scope /Applications/Utilities/Bar.app  && pass "/Applications/Utilities/Bar.app in scope" || fail "utilities should be in scope"
in_scope /Applications                    && pass "/Applications root in scope"           || fail "/Applications root should be in scope"
in_scope /ApplicationsBackup/Baz.app      && fail "/ApplicationsBackup must be excluded"  || pass "/ApplicationsBackup excluded (AUD-06)"
in_scope /Library/Foo.app                 && fail "/Library must be excluded"             || pass "/Library excluded"
SCOPE_ROOTS=(/Applications /Applications/Utilities /Users/x/Applications)
in_scope /Users/x/Applications/User.app   && pass "~/Applications included when configured" || fail "~/Applications should be in scope when added"
SCOPE_ROOTS=(/Applications /Applications/Utilities)
in_scope /Users/x/Applications/User.app   && fail "~/Applications excluded by default"     || pass "~/Applications excluded by default"

print -r -- "== unit: rosetta_status (gated on arch) =="
assert_eq "N/A" "$(rosetta_status x86_64)" "Intel Mac -> N/A (AUD-08)"
ROSETTA_RUNTIME="$FIX/fake_rosetta"
: > "$ROSETTA_RUNTIME"
assert_eq "Yes" "$(rosetta_status arm64)" "Apple silicon + runtime present -> Yes"
ROSETTA_RUNTIME="$FIX/does_not_exist"
assert_eq "No"  "$(rosetta_status arm64)" "Apple silicon + runtime absent -> No"
unset ROSETTA_RUNTIME

print -r -- "== unit: parse_records status + record extraction =="
count_records() {  # fixture -> sets globals REC_COUNT and PARSE_STATUS (no subshell)
  local f=$1 rec
  rec=$(mktemp -t iaa.t.XXXXXX)
  parse_records < "$f" > "$rec"
  local -a fld; local t
  while IFS= read -r -d '' t; do fld+=("$t"); done < "$rec"
  command rm -f "$rec"
  typeset -g REC_COUNT=$(( ${#fld} / 3 ))
}
count_records "$FIX/normal.json";     assert_eq Complete "$PARSE_STATUS" "normal -> Complete"; assert_eq 9 "$REC_COUNT" "normal -> 9 records"
count_records "$FIX/empty.json";      assert_eq Partial  "$PARSE_STATUS" "empty {} -> Partial (AUD-03)"; assert_eq 0 "$REC_COUNT" "empty {} -> 0 records"
count_records "$FIX/emptyarray.json"; assert_eq Partial  "$PARSE_STATUS" "empty array -> Partial"
count_records "$FIX/malformed.json";  assert_eq Partial  "$PARSE_STATUS" "malformed -> Partial (no crash)"
count_records "$FIX/nonobject.json";  assert_eq Partial  "$PARSE_STATUS" "non-object array element -> Partial (F2/AUD-02)"; assert_eq 1 "$REC_COUNT" "non-object array element: valid app still emitted"

print -r -- "== engine: audit_apps against fixtures =="
run_audit() {  # fixture
  FIXTURE_JSON=$1
  SCOPE_ROOTS=(/Applications /Applications/Utilities)
  MACHINE_ARCH=arm64
  audit_apps
}

# Case 2 + 9: normal mix; scope excludes /Library and /ApplicationsBackup.
run_audit "$FIX/normal.json"
assert_eq 3 "$AUDIT_INTEL"   "normal: 3 in-scope Intel (2 excluded by scope, AUD-06)"
assert_eq 1 "$AUDIT_UNI"     "normal: 1 Universal"
assert_eq 1 "$AUDIT_AS"      "normal: 1 AppleSilicon"
assert_eq 1 "$AUDIT_IOS"     "normal: 1 iOS"
assert_eq 1 "$AUDIT_OTHER"   "normal: 1 Other"
assert_eq 0 "$AUDIT_UNKNOWN" "normal: 0 Unknown"
assert_eq Complete "$AUDIT_STATUS" "normal: ScanStatus Complete"

# Case 10: malicious app name survived intact as structured data.
found_evil=0
for nm in "${INTEL_NAMES[@]}"; do [[ $nm == *"Ev|il:App"* ]] && found_evil=1; done
assert_eq 1 "$found_evil" "malicious name (pipe/colon/newline/emoji) preserved as JSON record (AUD-04)"

# Case 5: NON-ENGLISH locale fixture -> SAME Intel count, proving arch_kind is
# used, not the localized 'kind' text (which is Japanese here).
run_audit "$FIX/nonenglish.json"
assert_eq 3 "$AUDIT_INTEL" "non-English locale: Intel still 3 (classified by arch_kind, AUD-01)"
assert_eq Complete "$AUDIT_STATUS" "non-English locale: Complete"

# Case 4: empty {} (system_profiler -timeout exit-0) -> Partial, NOT a clean 0.
run_audit "$FIX/empty.json"
assert_eq 0 "$AUDIT_INTEL"  "empty {}: IntelOnly 0"
assert_eq Partial "$AUDIT_STATUS" "empty {}: ScanStatus Partial, never a silent clean zero (AUD-02/03)"

# Case 6: in-scope app missing arch_kind -> Unknown + Partial.
run_audit "$FIX/missingarch.json"
assert_eq 1 "$AUDIT_INTEL"   "missing arch_kind: the 1 real Intel app still counted"
assert_eq 1 "$AUDIT_UNKNOWN" "missing arch_kind: Unknown incremented"
assert_eq Partial "$AUDIT_STATUS" "missing arch_kind: ScanStatus Partial (AUD-02)"

# Case 7: unknown arch_kind enum -> Unknown + Partial.
run_audit "$FIX/unknownarch.json"
assert_eq 1 "$AUDIT_UNKNOWN" "unknown enum: counted Unknown"
assert_eq 0 "$AUDIT_INTEL"   "unknown enum: not miscounted as Intel"
assert_eq Partial "$AUDIT_STATUS" "unknown enum: ScanStatus Partial"

# Case 8: malformed JSON -> Partial, no crash, no false zero of any kind.
run_audit "$FIX/malformed.json"
assert_eq Partial "$AUDIT_STATUS" "malformed: ScanStatus Partial"

print -r -- "== engine: ea_string format =="
run_audit "$FIX/empty.json"
ROSETTA_STATUS="N/A"; MACHINE_ARCH=x86_64; SCOPE_LABEL="/Applications,/Applications/Utilities"
ea=$(ea_string)
assert_contains "$ea" "<result>" "ea_string has result tag"
assert_contains "$ea" "ScanStatus:Partial" "ea_string surfaces Partial on empty scan"
assert_contains "$ea" "IntelOnly:0" "ea_string shows IntelOnly:0..."
assert_contains "$ea" "RosettaRuntimePresent:N/A" "ea_string N/A rosetta on Intel arch"
assert_contains "$ea" "DetectionSource:SystemProfiler" "ea_string identifies its detector"
assert_not_contains "$ea" "ScanStatus:Complete" "empty scan is never Complete"

print -r -- "== engine: direct bundle fallback =="
make_test_bundle() {  # root name executable
  local root=$1 name=$2 executable=$3 app
  app="$root/$name.app"
  command mkdir -p "$app/Contents/MacOS"
  cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>$executable</string>
<key>CFBundleName</key><string>$name</string>
</dict></plist>
PLIST
  : > "$app/Contents/MacOS/$executable"
}

FALLBACK_ROOT="$FIX/fallback-clean"
command mkdir -p "$FALLBACK_ROOT"
make_test_bundle "$FALLBACK_ROOT" IntelTool IntelTool
make_test_bundle "$FALLBACK_ROOT" UniversalTool UniversalTool
make_test_bundle "$FALLBACK_ROOT" NativeTool NativeTool
make_test_bundle "$FALLBACK_ROOT" ScriptTool ScriptTool
# App Store iOS apps use an outer .app container and an inner Wrapper/*.app.
IOS_OUTER="$FALLBACK_ROOT/MobileTool.app"
command mkdir -p "$IOS_OUTER/Wrapper/MobilePayload.app"
cat > "$IOS_OUTER/Wrapper/MobilePayload.app/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>IOSTool</string>
<key>CFBundleName</key><string>MobileTool</string>
</dict></plist>
PLIST
: > "$IOS_OUTER/Wrapper/MobilePayload.app/IOSTool"
FIXTURE_JSON="$FIX/empty.json"
SCOPE_ROOTS=("$FALLBACK_ROOT")
audit_apps_with_fallback
assert_eq DirectBundleScan "$AUDIT_SOURCE" "Partial system_profiler result triggers direct fallback"
assert_eq Complete "$AUDIT_STATUS" "clean direct fallback is Complete"
assert_eq 1 "$AUDIT_INTEL" "direct fallback counts Intel-only app"
assert_eq 1 "$AUDIT_UNI" "direct fallback counts Universal app"
assert_eq 1 "$AUDIT_AS" "direct fallback counts Apple-silicon app"
assert_eq 1 "$AUDIT_IOS" "direct fallback recognizes wrapped iOS app"
assert_eq 1 "$AUDIT_OTHER" "direct fallback classifies script launcher as Other"
assert_eq 0 "$AUDIT_UNKNOWN" "clean direct fallback has no Unknown bundles"
assert_contains "${(j:,:)INTEL_NAMES}" IntelTool "direct fallback retains Intel app name"

BROKEN_ROOT="$FIX/fallback-broken"
command mkdir -p "$BROKEN_ROOT/Broken.app/Contents"
SCOPE_ROOTS=("$BROKEN_ROOT")
audit_apps_with_fallback
assert_eq DirectBundleScan "$AUDIT_SOURCE" "broken bundle still reports direct detector"
assert_eq Partial "$AUDIT_STATUS" "broken bundle makes fallback Partial"
assert_eq 1 "$AUDIT_UNKNOWN" "broken bundle increments Unknown"
unset FIXTURE_JSON

print -r -- "== adapter: system_profiler routes through run_cmd spy =="
unset FIXTURE_JSON
SPY_CALLS=()
SPY_SP_FIXTURE="$FIX/normal.json"
SCOPE_ROOTS=(/Applications /Applications/Utilities)
MACHINE_ARCH=arm64
SP_TIMEOUT=120
audit_apps
if spy_has "system_profiler"; then pass "sp_json routed through command adapter"; else fail "system_profiler not seen by spy"; fi
assert_eq 3 "$AUDIT_INTEL" "adapter-fed fixture produced correct Intel count"
unset SPY_SP_FIXTURE

print -r -- "== build_scope: EXTRA_ROOT EA-delimiter rejection (F1) =="
# A root containing ';' '<' '>' or newline would corrupt the ';'-delimited
# <result>...</result> EA line; it must be rejected regardless of -d.
SCAN_USER_APPS=0
EXTRA_ROOT="/tmp/ev;il<x>"
build_scope
assert_not_contains "$SCOPE_LABEL" "ev;il" "EXTRA_ROOT with EA delimiters rejected from scope (F1)"
unset EXTRA_ROOT
build_scope
assert_eq "/Applications,/Applications/Utilities" "$SCOPE_LABEL" "clean scope after rejecting bad EXTRA_ROOT (F1)"

print -r -- "== build_scope: SCAN_USER_APPS existence guard (F3) =="
CONSOLE_USER_OVERRIDE="alice"
CONSOLE_HOME_OVERRIDE="$FIX/f3home"
command mkdir -p "$FIX/f3home"
SCAN_USER_APPS=1
EXTRA_ROOT=""
build_scope
assert_not_contains "$SCOPE_LABEL" "$FIX/f3home/Applications" "non-existent ~/Applications not advertised in scope (F3)"
command mkdir -p "$FIX/f3home/Applications"
build_scope
assert_contains "$SCOPE_LABEL" "$FIX/f3home/Applications" "existing ~/Applications added to scope (F3)"
SCAN_USER_APPS=0
unset CONSOLE_USER_OVERRIDE CONSOLE_HOME_OVERRIDE EXTRA_ROOT

print -r -- "== regression: missing-path record is not a false clean zero (finding 1) =="
# An Intel record with a valid arch_kind but NO path cannot be scope-tested. It
# must count as Unknown and force Partial, never be dropped by the scope filter
# into IntelOnly:0 / Complete.
cat > "$FIX/missingpath.json" <<'JSON'
{"SPApplicationsDataType":[
 {"_name":"NoPathIntel","arch_kind":"arch_i64"}
]}
JSON
run_audit "$FIX/missingpath.json"
assert_eq 0 "$AUDIT_INTEL"   "missing path: not miscounted as Intel"
assert_eq 1 "$AUDIT_UNKNOWN" "missing path: counted as Unknown (finding 1)"
assert_eq Partial "$AUDIT_STATUS" "missing path: ScanStatus Partial, never a clean zero (finding 1)"
# A record with a missing path alongside a real in-scope Intel app: the real app
# is still counted, and the invalid record still forces Partial.
cat > "$FIX/missingpath_mixed.json" <<'JSON'
{"SPApplicationsDataType":[
 {"_name":"NoPathIntel","arch_kind":"arch_i64"},
 {"_name":"RealIntel","path":"/Applications/RealIntel.app","arch_kind":"arch_i64"}
]}
JSON
run_audit "$FIX/missingpath_mixed.json"
assert_eq 1 "$AUDIT_INTEL"   "missing path mixed: the real Intel app is still counted"
assert_eq 1 "$AUDIT_UNKNOWN" "missing path mixed: invalid record counted Unknown"
assert_eq Partial "$AUDIT_STATUS" "missing path mixed: ScanStatus Partial"
unset FIXTURE_JSON

print -r -- "== regression: unclassifiable executable is not a Complete Other (finding 4) =="
# lipo finds no architecture and file(1) does not describe an interpreter
# script: the bundle must stay Unknown -> Partial, not become a Complete Other.
GARBAGE_ROOT="$FIX/fallback-garbage"
command mkdir -p "$GARBAGE_ROOT/Garbage.app/Contents/MacOS"
cat > "$GARBAGE_ROOT/Garbage.app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>Garbage</string>
<key>CFBundleName</key><string>Garbage</string>
</dict></plist>
PLIST
printf '\x01\x02\x03\xff\xfe not a shebang, arbitrary data' > "$GARBAGE_ROOT/Garbage.app/Contents/MacOS/Garbage"
# Use the REAL find/lipo/file here (no spy, DRY_RUN off) so file(1) genuinely
# reports "data" and run_cmd actually executes the tools.
_saved_spy_f4=$functions[CMD_ADAPTER_SPY]
unset -f CMD_ADAPTER_SPY 2>/dev/null
_saved_dry_f4=$DRY_RUN; DRY_RUN=0
FIXTURE_JSON="$FIX/empty.json"
SCOPE_ROOTS=("$GARBAGE_ROOT")
direct_audit_apps
assert_eq 0 "$AUDIT_OTHER"   "garbage executable: NOT classified Other (finding 4)"
assert_eq 1 "$AUDIT_UNKNOWN" "garbage executable: counted Unknown"
assert_eq Partial "$AUDIT_STATUS" "garbage executable: ScanStatus Partial (finding 4)"
# A real interpreter script (valid shebang) is still legitimately Other.
SCRIPT_ROOT="$FIX/fallback-script"
command mkdir -p "$SCRIPT_ROOT/ScriptApp.app/Contents/MacOS"
cat > "$SCRIPT_ROOT/ScriptApp.app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>launch</string>
<key>CFBundleName</key><string>ScriptApp</string>
</dict></plist>
PLIST
printf '#!/bin/sh\necho hi\n' > "$SCRIPT_ROOT/ScriptApp.app/Contents/MacOS/launch"
command chmod +x "$SCRIPT_ROOT/ScriptApp.app/Contents/MacOS/launch"
SCOPE_ROOTS=("$SCRIPT_ROOT")
direct_audit_apps
assert_eq 1 "$AUDIT_OTHER"   "real shebang script: still classified Other"
assert_eq Complete "$AUDIT_STATUS" "real shebang script: Complete"
# restore DRY_RUN and the spy for any later tests
DRY_RUN=$_saved_dry_f4
functions[CMD_ADAPTER_SPY]=$_saved_spy_f4
unset FIXTURE_JSON

print -r -- "== regression: Complete primary is reconciled against disk, never a false clean (finding 1) =="
# The headline publication blocker: a well-formed system_profiler response that
# reports ScanStatus:Complete can still OMIT an installed Intel app. The primary
# here sees only a native app; a real x86_64 bundle sits on disk in the same
# scope. audit_apps_with_fallback must reconcile the Complete primary against the
# direct disk scan, detect the mismatch, fail closed to Partial, and SURFACE the
# omitted Intel app. This mirrors the VM review1-false-clean probe.
RECON_ROOT="$FIX/reconcile-mismatch"
command mkdir -p "$RECON_ROOT"
make_test_bundle "$RECON_ROOT" IntelTool IntelTool   # real Intel bundle on disk (spy lipo -> x86_64)
cat > "$FIX/recon-omits-intel.json" <<JSON
{"SPApplicationsDataType":[
 {"_name":"NativeApp","path":"$RECON_ROOT/NativeApp.app","arch_kind":"arch_arm"}
]}
JSON
FIXTURE_JSON="$FIX/recon-omits-intel.json"
SCOPE_ROOTS=("$RECON_ROOT")
MACHINE_ARCH=arm64
audit_apps_with_fallback
assert_eq Partial "$AUDIT_STATUS" "false-clean: Complete primary that omits an Intel app reconciles to Partial (finding 1)"
assert_eq 1 "$AUDIT_INTEL" "false-clean: the omitted Intel app is surfaced by reconciliation (finding 1)"
assert_contains "$AUDIT_SOURCE" "DirectMismatch" "false-clean: DetectionSource records the reconciliation mismatch"
assert_contains "${(j:,:)INTEL_NAMES}" IntelTool "false-clean: the surfaced inventory names the Intel app"

print -r -- "== regression: agreeing engines stay Complete and keep the primary inventory =="
# When system_profiler and the direct disk scan agree on the Intel-only count and
# the total in-scope bundle count, the result is trustworthy: it stays Complete,
# records SystemProfiler+DirectReconciled, and presents the primary inventory.
RECON_OK="$FIX/reconcile-agree"
command mkdir -p "$RECON_OK"
make_test_bundle "$RECON_OK" IntelTool IntelTool
cat > "$FIX/recon-agree.json" <<JSON
{"SPApplicationsDataType":[
 {"_name":"PrimaryIntelName","path":"$RECON_OK/IntelTool.app","arch_kind":"arch_i64"}
]}
JSON
FIXTURE_JSON="$FIX/recon-agree.json"
SCOPE_ROOTS=("$RECON_OK")
MACHINE_ARCH=arm64
audit_apps_with_fallback
assert_eq Complete "$AUDIT_STATUS" "reconcile-agree: agreeing engines stay Complete"
assert_eq 1 "$AUDIT_INTEL" "reconcile-agree: Intel count preserved"
assert_eq "SystemProfiler+DirectReconciled" "$AUDIT_SOURCE" "reconcile-agree: DetectionSource records the reconciliation"
assert_contains "${(j:,:)INTEL_NAMES}" PrimaryIntelName "reconcile-agree: primary (system_profiler) inventory is presented"
unset FIXTURE_JSON

print -r -- "== regression: same Intel COUNT but different PATH set reconciles to Partial (finding 2) =="
# Matching aggregate counts do NOT prove matching inventories. The primary claims
# one Intel app at PhantomIntel.app; the direct disk scan finds one Intel app at a
# DIFFERENT path (IntelTool.app). Counts agree (IntelOnly:1, total:1) but the path
# sets disagree. Comparing only counts would stamp this Complete and cache the
# WRONG Intel app list with ScanStatus:Complete. audit_apps_with_fallback must
# compare the exact Intel-only path sets, fail closed to Partial, and surface the
# direct scan's real inventory (publication finding 2).
RECON_DIFF="$FIX/reconcile-diffpath"
command mkdir -p "$RECON_DIFF"
make_test_bundle "$RECON_DIFF" IntelTool IntelTool   # real Intel bundle on disk (spy lipo -> x86_64)
cat > "$FIX/recon-diffpath.json" <<JSON
{"SPApplicationsDataType":[
 {"_name":"PhantomIntel","path":"$RECON_DIFF/PhantomIntel.app","arch_kind":"arch_i64"}
]}
JSON
FIXTURE_JSON="$FIX/recon-diffpath.json"
SCOPE_ROOTS=("$RECON_DIFF")
MACHINE_ARCH=arm64
audit_apps_with_fallback
assert_eq Partial "$AUDIT_STATUS" "diff-path: same count / different Intel path reconciles to Partial (finding 2)"
assert_eq 1 "$AUDIT_INTEL" "diff-path: the real on-disk Intel app count is preserved (finding 2)"
assert_contains "$AUDIT_SOURCE" "DirectMismatch" "diff-path: DetectionSource records the reconciliation mismatch (finding 2)"
assert_contains "${(j:,:)INTEL_NAMES}" IntelTool "diff-path: the direct scan's real inventory is surfaced, not the phantom (finding 2)"
assert_not_contains "${(j:,:)INTEL_NAMES}" PhantomIntel "diff-path: the unverified primary phantom path is not presented (finding 2)"
unset FIXTURE_JSON

# =============================================================================
# Split deployment: collector mode + reader EA + installer/plist contract.
# These exercise the "collector -> file -> reader" pieces added on top of the
# standalone MODE=ea engine, mirroring the AI Software Inventory EA.
# =============================================================================

print -r -- "== collector: MODE=collector caches counts + Intel app list (no <result>) =="
# The cache FORMAT is tested by setting the AUDIT_*/INTEL_* result globals
# directly and calling write_state. This deliberately decouples the cache-format
# assertions from the detection engine: the engine (including reconciliation) is
# covered by its own sections, and audit_apps_with_fallback now runs the direct
# disk scanner whenever the primary is Complete, which a fixture-only test must
# not depend on. Known in-scope inventory: two IntelOnly (one name carries an XML
# metachar), one Universal, one AppleSilicon. Only Intel-only apps are listed.
CO_STATE=$(mktemp -d -t iaa.costate.XXXXXX)
(
  INTEL_STATE_DIR="$CO_STATE"; DRY_RUN=0
  MACHINE_ARCH=arm64; ROSETTA_STATUS=Yes
  SCOPE_LABEL="/Applications,/Applications/Utilities"
  AUDIT_INTEL=2 AUDIT_UNI=1 AUDIT_AS=1 AUDIT_IOS=0 AUDIT_OTHER=0 AUDIT_UNKNOWN=0
  AUDIT_STATUS=Complete AUDIT_SOURCE=SystemProfiler+DirectReconciled
  INTEL_NAMES=("OldTool <beta>" "LegacyCo")
  INTEL_PATHS=("/Applications/OldTool.app" "/Applications/LegacyCo.app")
  write_state
) >/dev/null 2>&1
if [[ -f "$CO_STATE/result.txt" ]]; then pass "collector wrote result.txt"; else fail "collector did not write result.txt"; fi
co_body=$(command cat "$CO_STATE/result.txt")
co_line1=$(print -r -- "$co_body" | command head -n 1)
assert_contains "$co_line1" "IntelOnly:2;" "cache line 1 is the counts summary (IntelOnly:2)"
assert_contains "$co_line1" "Universal:1;" "cache line 1 carries Universal:1"
assert_contains "$co_body" "INTEL_APP | OldTool &lt;beta&gt; | /Applications/OldTool.app" "cache lists Intel app with XML-escaped name"
assert_contains "$co_body" "INTEL_APP | LegacyCo | /Applications/LegacyCo.app" "cache lists the second Intel-only app"
assert_not_contains "$co_body" "Both.app" "cache app list excludes Universal apps"
assert_not_contains "$co_body" "Sil.app"  "cache app list excludes AppleSilicon apps"
assert_not_contains "$co_body" "<result>" "collector state has no <result> wrapper (reader adds it)"
# A clean Mac (no Intel-only apps) caches the IntelApps:None marker.
CO_CLEAN=$(mktemp -d -t iaa.coclean.XXXXXX)
(
  INTEL_STATE_DIR="$CO_CLEAN"; DRY_RUN=0
  MACHINE_ARCH=arm64; ROSETTA_STATUS=No
  SCOPE_LABEL="/Applications,/Applications/Utilities"
  AUDIT_INTEL=0 AUDIT_UNI=1 AUDIT_AS=0 AUDIT_IOS=0 AUDIT_OTHER=0 AUDIT_UNKNOWN=0
  AUDIT_STATUS=Complete AUDIT_SOURCE=SystemProfiler+DirectReconciled
  INTEL_NAMES=() INTEL_PATHS=()
  write_state
) >/dev/null 2>&1
assert_contains "$(command cat "$CO_CLEAN/result.txt")" "IntelApps:None" "no Intel-only apps -> IntelApps:None marker cached"
command rm -rf "$CO_CLEAN"
# counts_line and the <result> wrapper share one source of truth.
INTEL_NAMES=() INTEL_PATHS=()
AUDIT_INTEL=2 AUDIT_UNI=3 AUDIT_AS=4 AUDIT_IOS=0 AUDIT_OTHER=1 AUDIT_UNKNOWN=0
AUDIT_STATUS=Complete AUDIT_SOURCE=SystemProfiler
MACHINE_ARCH=arm64 ROSETTA_STATUS=No SCOPE_LABEL=/Applications
assert_eq "<result>$(counts_line)</result>" "$(ea_string)" "ea_string == <result> + counts_line"
assert_eq "$(counts_line)" "$(ea_inner)" "ea_inner is an alias of counts_line"
# xesc escapes XML metacharacters.
assert_eq "a &amp;&lt;&gt; b" "$(xesc 'a &<> b')" "xesc escapes & < >"
# DRY_RUN never writes.
DR_STATE=$(mktemp -d -t iaa.drstate.XXXXXX)
( INTEL_STATE_DIR="$DR_STATE"; DRY_RUN=1; write_state ) >/dev/null 2>&1
if [[ ! -f "$DR_STATE/result.txt" ]]; then pass "DRY_RUN collector writes no state file"; else fail "DRY_RUN collector wrote a state file"; fi
command rm -rf "$DR_STATE"

print -r -- "== reader EA: three trigger words (counts / apps / both) + sentinels =="
READER="$SCRIPT_DIR/intel-app-auditor-ea.zsh"
if [[ -f $READER ]]; then pass "reader EA present"; else fail "reader EA missing at $READER"; fi
assert_eq 0 "$(command zsh -n "$READER" >/dev/null 2>&1; print $?)" "reader EA passes zsh -n"
# Exactly one of the three EA trigger lines is uncommented (default 'both'), so a
# no-argument (Jamf EA) run emits exactly one <result>.
active_trigger=$(command grep -cE '^(counts|apps|both)$' "$READER")
assert_eq 1 "$active_trigger" "exactly one EA trigger word is active by default"
r_default=$(INTEL_STATE_DIR="$CO_STATE" command zsh "$READER" 2>/dev/null)
assert_eq 1 "$(print -r -- "$r_default" | command grep -c '<result>')" "no-arg (Jamf EA) run: exactly one <result>"
assert_contains "$r_default" "<result>IntelOnly:2;" "default trigger (both): starts with the summary"
# Trigger word: both.
r_both=$(INTEL_STATE_DIR="$CO_STATE" command zsh "$READER" both 2>/dev/null)
assert_eq 1 "$(print -r -- "$r_both" | command grep -c '<result>')" "both: exactly one <result>"
assert_contains "$r_both" "<result>IntelOnly:2;" "both: starts with the counts summary"
assert_contains "$r_both" "INTEL_APP | LegacyCo" "both: includes the app list"
# Trigger word: counts.
r_counts=$(INTEL_STATE_DIR="$CO_STATE" command zsh "$READER" counts 2>/dev/null)
assert_contains "$r_counts" "<result>IntelOnly:2;" "counts: wraps the summary"
assert_not_contains "$r_counts" "INTEL_APP" "counts: omits the app list"
# Trigger word: apps.
r_apps=$(INTEL_STATE_DIR="$CO_STATE" command zsh "$READER" apps 2>/dev/null)
assert_contains "$r_apps" "INTEL_APP | OldTool &lt;beta&gt;" "apps: lists the escaped Intel app"
assert_not_contains "$r_apps" "IntelOnly:2;" "apps: omits the summary line"
assert_eq 1 "$(print -r -- "$r_apps" | command grep -c '<result>')" "apps: exactly one <result>"
# An unrecognized trigger word falls back to 'both' (never crashes / empty).
r_bad=$(INTEL_STATE_DIR="$CO_STATE" command zsh "$READER" bogus 2>/dev/null)
assert_contains "$r_bad" "<result>IntelOnly:2;" "unknown trigger word -> defaults to both"
# Sentinels.
r_nc=$(INTEL_STATE_DIR="$CO_STATE.missing" command zsh "$READER" apps 2>/dev/null)
assert_eq "<result>NOT_COLLECTED</result>" "$r_nc" "missing state file -> NOT_COLLECTED"
# STALE: interval=600 -> threshold 1200s; backdate the state file well past it.
printf '600\n' > "$CO_STATE/interval"
command touch -t 202001010000 "$CO_STATE/result.txt"
r_stale=$(INTEL_STATE_DIR="$CO_STATE" command zsh "$READER" counts 2>/dev/null)
assert_contains "$r_stale" "<result>STALE (" "old mtime -> STALE"
assert_contains "$r_stale" "IntelOnly:2;" "STALE still carries the last-known-good value"
command rm -rf "$CO_STATE"

print -r -- "== reader EA: whole-cache validation guards ALL THREE views (finding 1) =="
# A valid collector cache always writes a counts summary AND an app-list section
# (INTEL_APP lines or the literal IntelApps:None marker), with the IntelOnly count
# matching the number of app lines. A counts-only / empty / mismatched-count cache
# fails that contract. The pre-fix reader only validated the `apps` view, so a
# counts-only cache read as `counts` or `both` (the SHIPPED default) passed
# through as a reassuring clean result. Every view must now return MALFORMED_CACHE
# for an invalid cache, and every view must still pass a genuinely valid one.
MAL_STATE=$(mktemp -d -t iaa.malstate.XXXXXX)
# (a) Counts-only body: a summary that even claims IntelOnly:5, but NO app list.
printf 'IntelOnly:5;Universal:0;AppleSilicon:0;iOS:0;Other:0;Unknown:0;ScanStatus:Complete;DetectionSource:SystemProfiler;RosettaRuntimePresent:Yes;Arch:arm64;Scope:/Applications\n' > "$MAL_STATE/result.txt"
for v in counts apps both; do
  r_mal=$(INTEL_STATE_DIR="$MAL_STATE" command zsh "$READER" "$v" 2>/dev/null)
  assert_eq "<result>MALFORMED_CACHE</result>" "$r_mal" "counts-only cache -> MALFORMED_CACHE in '$v' view (finding 1)"
  assert_not_contains "$r_mal" "IntelApps:None" "counts-only cache never reports IntelApps:None in '$v' view (finding 1)"
done
# The exact audit reproduction: a clean-LOOKING counts-only line (IntelOnly:0,
# ScanStatus:Complete) must not certify as clean in the default 'both' view.
printf 'IntelOnly:0;Universal:1;AppleSilicon:0;iOS:0;Other:0;Unknown:0;ScanStatus:Complete;DetectionSource:SystemProfiler+DirectReconciled;RosettaRuntimePresent:Yes;Arch:arm64;Scope:/Applications\n' > "$MAL_STATE/result.txt"
r_repro=$(INTEL_STATE_DIR="$MAL_STATE" command zsh "$READER" both 2>/dev/null)
assert_eq "<result>MALFORMED_CACHE</result>" "$r_repro" "audit reproduction: clean-looking counts-only cache is MALFORMED in default both view (finding 1)"
# (b) Empty cache file -> MALFORMED in every view.
: > "$MAL_STATE/result.txt"
for v in counts apps both; do
  r_empty=$(INTEL_STATE_DIR="$MAL_STATE" command zsh "$READER" "$v" 2>/dev/null)
  assert_eq "<result>MALFORMED_CACHE</result>" "$r_empty" "empty cache -> MALFORMED_CACHE in '$v' view (finding 1)"
done
# (c) Mismatched count/list: claims IntelOnly:2 but lists a single INTEL_APP line.
printf 'IntelOnly:2;Universal:0;AppleSilicon:0;iOS:0;Other:0;Unknown:0;ScanStatus:Complete;DetectionSource:DirectBundleScan;RosettaRuntimePresent:Yes;Arch:arm64;Scope:/Applications\nINTEL_APP | OneApp | /Applications/OneApp.app\n' > "$MAL_STATE/result.txt"
for v in counts apps both; do
  r_mm=$(INTEL_STATE_DIR="$MAL_STATE" command zsh "$READER" "$v" 2>/dev/null)
  assert_eq "<result>MALFORMED_CACHE</result>" "$r_mm" "count/list mismatch -> MALFORMED_CACHE in '$v' view (finding 1)"
done
# (d) A genuinely clean cache (validated IntelApps:None marker) still reads clean.
printf 'IntelOnly:0;Universal:1;AppleSilicon:0;iOS:0;Other:0;Unknown:0;ScanStatus:Complete;DetectionSource:SystemProfiler+DirectReconciled;RosettaRuntimePresent:Yes;Arch:arm64;Scope:/Applications\nIntelApps:None\n' > "$MAL_STATE/result.txt"
r_none=$(INTEL_STATE_DIR="$MAL_STATE" command zsh "$READER" apps 2>/dev/null)
assert_eq "<result>IntelApps:None</result>" "$r_none" "validated clean cache still reads IntelApps:None (apps)"
r_none_counts=$(INTEL_STATE_DIR="$MAL_STATE" command zsh "$READER" counts 2>/dev/null)
assert_contains "$r_none_counts" "<result>IntelOnly:0;" "validated clean cache passes counts view"
# (e) A valid populated cache (IntelOnly:1 + one matching INTEL_APP line) passes all views.
printf 'IntelOnly:1;Universal:0;AppleSilicon:0;iOS:0;Other:0;Unknown:0;ScanStatus:Complete;DetectionSource:DirectBundleScan;RosettaRuntimePresent:Yes;Arch:arm64;Scope:/Applications\nINTEL_APP | RealTool | /Applications/RealTool.app\n' > "$MAL_STATE/result.txt"
r_ok_both=$(INTEL_STATE_DIR="$MAL_STATE" command zsh "$READER" both 2>/dev/null)
assert_contains "$r_ok_both" "INTEL_APP | RealTool" "valid populated cache passes both view"
assert_not_contains "$r_ok_both" "MALFORMED_CACHE" "valid populated cache is never flagged malformed"
command rm -rf "$MAL_STATE"

print -r -- "== reader EA: unsafe (world-writable) state path is rejected (finding 12) =="
# The reader must refuse to trust a state path anyone else can rewrite. A
# world-writable state dir -> MALFORMED_CACHE even when the cache body is valid.
UNSAFE_STATE=$(mktemp -d -t iaa.unsafe.XXXXXX)
printf 'IntelOnly:0;Universal:1;AppleSilicon:0;iOS:0;Other:0;Unknown:0;ScanStatus:Complete;DetectionSource:DirectBundleScan;RosettaRuntimePresent:Yes;Arch:arm64;Scope:/Applications\nIntelApps:None\n' > "$UNSAFE_STATE/result.txt"
command chmod 0777 "$UNSAFE_STATE"
r_unsafe=$(INTEL_STATE_DIR="$UNSAFE_STATE" command zsh "$READER" both 2>/dev/null)
assert_eq "<result>MALFORMED_CACHE</result>" "$r_unsafe" "world-writable state dir -> MALFORMED_CACHE (finding 12)"
command chmod 0700 "$UNSAFE_STATE"
r_safe=$(INTEL_STATE_DIR="$UNSAFE_STATE" command zsh "$READER" both 2>/dev/null)
assert_contains "$r_safe" "IntelApps:None" "same cache under a 0700 dir reads clean (finding 12)"
command rm -rf "$UNSAFE_STATE"

print -r -- "== installer + plist contract =="
INSTALL_IN="$SCRIPT_DIR/install.sh.in"
INSTALL_SH="$SCRIPT_DIR/install.sh"
BUILD_SH="$SCRIPT_DIR/build-installer.sh"
REF_PLIST="$SCRIPT_DIR/io.github.intel-app-auditor.collector.plist"
for f in "$INSTALL_IN" "$INSTALL_SH" "$BUILD_SH" "$REF_PLIST"; do
  if [[ -f $f ]]; then pass "present: ${f:t}"; else fail "missing: ${f:t}"; fi
done
assert_eq 0 "$(command sh -n "$INSTALL_SH" >/dev/null 2>&1; print $?)" "install.sh passes sh -n"
assert_eq 0 "$(command sh -n "$INSTALL_IN" >/dev/null 2>&1; print $?)" "install.sh.in passes sh -n"
assert_eq 0 "$(command plutil -lint "$REF_PLIST" >/dev/null 2>&1; print $?)" "reference plist passes plutil -lint"
in_txt=$(command cat "$INSTALL_SH")
assert_contains "$in_txt" "launchctl bootout"    "install.sh uses modern launchctl bootout"
assert_contains "$in_txt" "launchctl bootstrap"  "install.sh uses modern launchctl bootstrap"
assert_not_contains "$in_txt" "launchctl load"   "install.sh avoids deprecated launchctl load"
assert_contains "$in_txt" "REVERSE_DOMAIN"       "install.sh exposes REVERSE_DOMAIN (param 5)"
assert_contains "$in_txt" "--uninstall"          "install.sh supports --uninstall"
assert_contains "$in_txt" "do_uninstall"         "install.sh has an uninstall path"
assert_contains "$in_txt" "MODE</key>"           "install.sh plist sets MODE env"
assert_contains "$in_txt" "collector"            "install.sh runs the collector"
assert_contains "$in_txt" "StartInterval"        "install.sh plist sets StartInterval"
assert_contains "$in_txt" "ProcessType"          "install.sh plist sets ProcessType Background"

print -r -- "== privileged PATH pinning: both root-run scripts fix PATH (finding 3) =="
# Root-run entry points must not trust an inherited PATH; a user-writable dir
# ahead of the system dirs could shadow a bare command and run as root.
coll_txt=$(command cat "$SCRIPT_DIR/intel-app-auditor.zsh")
assert_contains "$coll_txt" "PATH=/usr/bin:/bin:/usr/sbin:/sbin" "collector pins a trusted system PATH (finding 3)"
assert_contains "$in_txt"   "PATH=/usr/bin:/bin:/usr/sbin:/sbin" "install.sh pins a trusted system PATH (finding 3)"
# The collector's write_state must FAIL CLOSED, not swallow chown/chmod errors.
assert_contains "$coll_txt" "refusing to publish" "collector fails closed when ownership/mode cannot be set (finding 12)"
assert_not_contains "$coll_txt" 'chmod 0700 "$dir" 2>/dev/null || true' "collector no longer ignores state-dir hardening failures (finding 12)"

print -r -- "== build drift: install.sh embeds current collector verbatim =="
# The generated install.sh must contain the collector byte-for-byte. Re-embed a
# fresh copy to a temp file and diff; drift means someone edited install.sh by
# hand or forgot to re-run build-installer.sh.
if command -v bash >/dev/null 2>&1; then
  regen=$(mktemp -d -t iaa.regen.XXXXXX)
  command cp "$INSTALL_IN" "$BUILD_SH" "$SCRIPT_DIR/intel-app-auditor.zsh" "$regen/" 2>/dev/null
  ( cd "$regen" && command bash ./build-installer.sh >/dev/null 2>&1 )
  if command diff -q "$regen/install.sh" "$INSTALL_SH" >/dev/null 2>&1; then
    pass "install.sh is in sync with build-installer.sh output (no drift)"
  else
    fail "install.sh differs from a fresh build; run ./build-installer.sh"
  fi
  command rm -rf "$regen"
else
  fail "bash unavailable; cannot run build drift guard"
fi

print -r -- "== syntax gate: zsh -n / bash -n emit NOTHING on stderr (finding 11) =="
# A peer running the documented syntax checks must see a silent pass, not an
# alarming "no such file or directory" from a command substitution evaluated
# during the no-exec parse. Assert both a clean exit AND empty stderr for every
# shipped script.
syntax_gate() {  # checker file
  local checker=$1 file=$2 errout rc
  errout=$(command $checker -n "$file" 2>&1 >/dev/null); rc=$?
  if (( rc == 0 )) && [[ -z $errout ]]; then
    pass "$checker -n ${file:t}: clean exit, silent stderr"
  else
    fail "$checker -n ${file:t}: rc=$rc stderr=[$errout]"
  fi
}
syntax_gate zsh  "$SCRIPT_DIR/intel-app-auditor.zsh"
syntax_gate zsh  "$SCRIPT_DIR/intel-app-auditor-ea.zsh"
syntax_gate zsh  "$SCRIPT_DIR/test_intel-app-auditor.zsh"
syntax_gate zsh  "$INSTALL_SH"
syntax_gate zsh  "$INSTALL_IN"
syntax_gate bash "$BUILD_SH"

print -r -- "== shipped file modes: reader is executable (finding 9) =="
# The command-line examples run the reader directly; it must ship executable.
reader_mode=$(command stat -f '%Sp' "$READER" 2>/dev/null)
if [[ ${reader_mode[4]} == x ]]; then
  pass "reader EA is owner-executable (mode $reader_mode)"
else
  fail "reader EA is not executable (mode $reader_mode) -- direct-run examples will fail"
fi

# --- summary -----------------------------------------------------------------
print -r -- ""
print -r -- "==================================================="
print -r -- "PASS: $PASS   FAIL: $FAIL"
print -r -- "==================================================="
(( FAIL == 0 )) || exit 1
exit 0
