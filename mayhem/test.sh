#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Two parts, both asserting values magic computes:
#  1) upstream's own regression suite, RTimothyEdwards/magic_regression_tests (Apache-2.0), vendored
#     unchanged at e8bb2315 in mayhem/regression-tests/ (the suite upstream's .github/workflows/
#     regression.yml runs on every pull request). It is run with the Tcl build installed in
#     mayhem/out/regress (normal flags, no sanitizers). 27 of its 57 tests need the sky130A /
#     gf180mcuD open PDKs (26 call `require_pdk`; drc/stdcell_libs looks for the PDKs' standard-cell
#     libraries), which upstream's CI installs with ciel (hundreds of MB, network) and which are not in
#     the image; the suite itself reports those as SKIP (exit 77), and any other SKIP fails here. The
#     other 30 (scmos and built-in techs: database, cif, drc, resis/extresist incl. triangle_order and
#     invalid_skip) run and must PASS.
#  2) a known-answer suite over upstream's tutorial cells (doc/tutcells), run with the non-Tcl build
#     (mayhem/out/test-build): extracted device counts, netlist sizes, DRC error counts, cells
#     recovered from GDS/CIF round trips, and what the LEF/DEF writers and the LEF reader produce.
M="$SRC/mayhem/out/test-build/magic/magic"
RM="$SRC/mayhem/out/regress/bin/magic"
for bin in "$M" "$RM"; do
  if [ ! -x "$bin" ]; then
    echo "test.sh: $bin is missing — mayhem/build.sh must build it" >&2
    emit_ctrf "magic-regression+known-answer" 0 1 0
    exit 1
  fi
done
export CAD_ROOT="$SRC/mayhem/out/cad"
export HOME="$CAD_ROOT/home"
TUT="$SRC/doc/tutcells"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/magic-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

passed=0 failed=0 skipped=0

# ---- upstream regression suite ----
# Run from a copy, since each test writes its work/ directory next to its run.sh.
mkdir -p "$WORK/regression-home"
NOPDK="$WORK/no-pdk"   # deliberately absent: no open PDKs in the image
cp -a "$SRC/mayhem/regression-tests" "$WORK/regression"
env -u CAD_ROOT HOME="$WORK/regression-home" PDK_ROOT="$NOPDK" MAGIC="$RM" JOBS="$MAYHEM_JOBS" \
  bash "$WORK/regression/run_tests.sh" > "$WORK/regression.log" 2>&1
cat "$WORK/regression.log"
summary=$(sed -n 's/^Passed: \([0-9]*\)  Failed: \([0-9]*\)  Skipped: \([0-9]*\) .*/\1 \2 \3/p' "$WORK/regression.log" | tail -1)
if [ -n "$summary" ]; then
  read -r rp rf rs <<< "$summary"
  passed=$((passed + rp)); failed=$((failed + rf)); skipped=$((skipped + rs))
  # Only tests that need an open PDK may skip; their SKIP reason names the (empty) PDK_ROOT. Any
  # other SKIP (e.g. `magic --version` failing in require_magic_version) is a failure.
  unexpected=$(grep '^SKIP: ' "$WORK/regression.log" | grep -v -c -F "$NOPDK" || true)
  if [ "$unexpected" -ne 0 ]; then
    echo "FAIL regression-suite: $unexpected tests skipped for a reason other than a missing PDK"
    failed=$((failed + 1))
  fi
else
  echo "FAIL regression-suite: run_tests.sh printed no summary"
  failed=$((failed + 1))
fi

# ---- known-answer checks ----
check() {  # <name> <expected> <actual>
  if [ "$2" = "$3" ]; then
    passed=$((passed + 1)); echo "PASS $1"
  else
    failed=$((failed + 1)); echo "FAIL $1: expected '$2', got '$3'"
  fi
}
# run <dir> <cell> <command>... : run magic headless in <dir> on <cell> with the given commands.
run() {
  local dir="$1" cell="$2"; shift 2
  (cd "$dir" && printf '%s\n' "$@" ':quit 0 -noprompt' | "$M" -d null -T scmos "$cell" 2>&1) || true
}
count() { grep -c -E "$1" "$2" 2>/dev/null || true; }

# 1) Extraction and netlisting of the tut11a hierarchy.
W1="$WORK/extract"; mkdir -p "$W1"; cp "$TUT"/tut11?.mag "$W1/"
run "$W1" tut11a ':extract all' ':ext2spice tut11a' ':ext2sim tut11a' ':gds write rt.gds' \
    ':cif write rt' ':lef write' ':def write tut11a' > "$W1/log"
check extract-tut11d-devices 24 "$(count '^device mosfet' "$W1/tut11d.ext")"
check extract-tut11a-subcells 4 "$(count '^use ' "$W1/tut11a.ext")"
check extract-tut11b-devices 3 "$(count '^device mosfet' "$W1/tut11b.ext")"
check ext2spice-tut11a-transistors 108 "$(count '^M' "$W1/tut11a.spice")"
check ext2sim-tut11a-transistors 108 "$(count '^[np] ' "$W1/tut11a.sim")"
check lef-write-macro 1 "$(count '^MACRO tut11a$' "$W1/tut11a.lef")"
check def-write-components 1 "$(count '^COMPONENTS 4 ;' "$W1/tut11a.def")"

# 2) GDS round trip: read the written stream back and re-extract a cell from it.
W2="$WORK/gds"; mkdir -p "$W2"
run "$W2" scratch ':gds read ../extract/rt.gds' ':load tut11d' ':extract all' > "$W2/log"
check gds-read-cells 4 "$(count '^Reading "tut11[abcd]"' "$W2/log")"
check gds-roundtrip-devices 24 "$(count '^device mosfet' "$W2/tut11d.ext")"

# 3) CIF round trip.
W3="$WORK/cif"; mkdir -p "$W3"
run "$W3" scratch ':cif read ../extract/rt' ':load tut11d' ':extract all' > "$W3/log"
check cif-roundtrip-devices 24 "$(count '^device mosfet' "$W3/tut11d.ext")"

# 4) DRC error counts (tutorial 6 cells contain deliberate violations).
W4="$WORK/drc"; mkdir -p "$W4"; cp "$TUT"/tut6a.mag "$TUT"/tut6b.mag "$TUT"/tut3a.mag "$W4/"
for want in tut6a:5 tut6b:10 tut3a:0; do
  cell=${want%%:*}; n=${want##*:}
  got=$(run "$W4" "$cell" ':drc check' ':drc catchup' ':drc count total' \
        | sed -n 's/^Total DRC errors found: \([0-9]*\).*/\1/p' | head -1)
  check "drc-count-$cell" "$n" "$got"
done

# 5) LEF reader on the fixed LEF library used by the def fuzz target.
W5="$WORK/lef"; mkdir -p "$W5"
out=$(run "$W5" scratch ":lef read $CAD_ROOT/fixtures/cells.lef" ':cellname list allcells')
check lef-read-lines 1 "$(printf '%s\n' "$out" | grep -c '^LEF read: Processed 84 lines\.')"
check lef-read-macro 1 "$(printf '%s\n' "$out" | grep -c -w 'inv')"

emit_ctrf "magic-regression+known-answer" "$passed" "$failed" "$skipped"
