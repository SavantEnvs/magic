#!/usr/bin/env bash
#
# mayhem/build.sh — build magic's fuzz driver and the functional-test build.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. Everything it writes goes
# under mayhem/out/ (gitignored by mayhem/.gitignore), using upstream's own out-of-tree build support
# (`<builddir>$ <srcdir>/configure`), so the source tree stays pristine:
#
#   mayhem/out/fuzz-build/   magic built with afl-clang-fast + $SANITIZER_FLAGS + $DEBUG_FLAGS
#   mayhem/out/fuzz_magic    the AFL file-input driver: magic's objects + mayhem/harness/fuzz_magic.c
#                            (replaces magic/magicTop.c's main; see that file for the modes)
#   mayhem/out/cad/          the read-only runtime directory magic needs (CAD_ROOT): tech files,
#                            display styles, glyphs, plus mayhem/out/cad/fixtures/ (fixed layouts)
#   mayhem/out/test-build/   magic built with upstream's NORMAL flags (clang, no sanitizers) — the
#                            binary mayhem/test.sh's known-answer checks run
#   mayhem/out/regress-build/, mayhem/out/regress/
#                            the Tcl build of magic (normal flags, --without-tk --without-x) that
#                            upstream's regression suite needs, `make install`ed into regress/ —
#                            mayhem/test.sh runs mayhem/regression-tests/run_tests.sh with it
#
# Idempotent and offline: no network access; re-running on a built tree re-configures and re-makes.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/out"
mkdir -p "$OUT"

# magic's own configure options for a headless build: no Tcl/Tk, no X11/OpenGL/Cairo, no readline.
# The null graphics device (-d null) is always compiled in.
CONFIG_OPTS=(--with-interpreter=no --without-x --disable-readline --disable-ccache --disable-magic-builddate)

# UBSan relaxations, each for a benign pattern hit on (nearly) every run (with halting UBSan nothing would fuzz):
#  * pointer-overflow (global): tiles/tile.c's tile allocator computes `NULL + sizeof(Tile)` at startup
#    (tile.c:708) before its first mmap, on every invocation.
#  * object-size (global): property records (database/DBprop.c, PropertyRecord) are allocated with
#    strPropertyRecordSize(n), i.e. sized to the string they hold, which is smaller than the declared
#    struct; every "lef read" (lefRead.c:2454) and other DBPropPut callers trip it. ASan still checks
#    the real bounds of those allocations.
#  * signed-integer-overflow, on utils/ihash.c only: iHash() accumulates `hash*10 + c` in an int and
#    relies on wrap-around; every "extract" overflows it (ihash.c:344).
#  * nonnull-attribute, on dbwind/DBWfdback.c only: DBWFeedbackAdd() grows its array with
#    memcpy(new, NULL, 0) on the first feedback (DBWfdback.c:450), which every extraction or DRC run
#    that reports feedback reaches.
# ASan and every other UBSan check stay on and halting.
FUZZ_CFLAGS="$SANITIZER_FLAGS -fno-sanitize=pointer-overflow,object-size $DEBUG_FLAGS -O1"
AFLCC=afl-clang-fast
# The fuzz build keeps magic's ASSERT()s live: without --enable-assertions, configure adds -DNDEBUG
# to every compile (scripts/defs.mak.in DFLAGS) and utils/magic_assert.h's assert() becomes a no-op.
FUZZ_CONFIG_OPTS=("${CONFIG_OPTS[@]}" --enable-assertions)
FUZZ_STAMP="$FUZZ_CFLAGS ${FUZZ_CONFIG_OPTS[*]}"

# ---- 1) sanitized, AFL-instrumented build -------------------------------------------------------
FB="$OUT/fuzz-build"
mkdir -p "$FB"
(
  cd "$FB"
  # magic's makefiles do not track compiler flags: a re-run with different flags starts clean.
  if [ -f Makefile ] && [ "$(cat mayhem-flags 2>/dev/null)" != "$FUZZ_STAMP" ]; then
    make clean > /dev/null 2>&1 || true
  fi
  CC="$AFLCC" CFLAGS="$FUZZ_CFLAGS" "$SRC/configure" "${FUZZ_CONFIG_OPTS[@]}" > configure.log 2>&1 \
    || { tail -40 configure.log; exit 1; }
  printf '%s' "$FUZZ_STAMP" > mayhem-flags
  AFL_QUIET=1 make -j"$MAYHEM_JOBS" > make.log 2>&1 || { tail -60 make.log; exit 1; }
  # The per-file relaxations: recompile those objects with their extra flag (the generated headers
  # exist now), then make again to relink the module objects that contain them.
  relax_obj() {  # <dir> <object> <-fno-sanitize=...>
    rm -f "$1/$2"
    AFL_QUIET=1 make -C "$1" "$2" CPPFLAGS="-I\${GENINC} -I\${MAGICSRC} -I\${srcdir} $3" > /dev/null
  }
  relax_obj utils ihash.o -fno-sanitize=signed-integer-overflow
  relax_obj dbwind DBWfdback.o -fno-sanitize=nonnull-attribute
  AFL_QUIET=1 make -j"$MAYHEM_JOBS" >> make.log 2>&1 || { tail -60 make.log; exit 1; }
)

# Link the driver from the same objects magic/magic is linked from (magic/Makefile's EXTRA_LIBS and
# LIBS), with fuzz_magic.c in place of magicTop.c.
LINK_OBJS=$(make -s -C "$FB/magic" --no-print-directory --eval 'mayhem-print-objs: ; @echo $(EXTRA_LIBS)' mayhem-print-objs)
LINK_LIBS=$(make -s -C "$FB/magic" --no-print-directory --eval 'mayhem-print-libs: ; @echo $(LIBS)' mayhem-print-libs)
(
  cd "$FB/magic"
  AFL_QUIET=1 $AFLCC $FUZZ_CFLAGS -I"$SRC" -c "$SRC/mayhem/harness/fuzz_magic.c" -o fuzz_magic.o
  AFL_QUIET=1 $AFLCC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o lsan_off.o
  # shellcheck disable=SC2086
  AFL_QUIET=1 $AFLCC $FUZZ_CFLAGS fuzz_magic.o lsan_off.o $LINK_OBJS -o "$OUT/fuzz_magic.tmp" $LINK_LIBS
)
mv -f "$OUT/fuzz_magic.tmp" "$OUT/fuzz_magic"

# ---- 2) runtime directory (CAD_ROOT) --------------------------------------------------------------
# What `make install` would put in $CAD_ROOT/magic/sys, minus the Tcl parts: the generated tech files,
# display styles / colormaps, glyphs and the startup file.
CAD="$OUT/cad"
rm -rf "$CAD"
mkdir -p "$CAD/magic/sys" "$CAD/fixtures" "$CAD/home"   # home/: empty $HOME + start dir for fuzz_magic
cp "$FB"/scmos/*.tech "$CAD/magic/sys/"
cp "$SRC"/scmos/*.dstyle "$SRC"/scmos/*.cmap "$SRC"/graphics/*.glyphs "$SRC"/windows/*.glyphs "$CAD/magic/sys/"
cp "$FB/magic/proto.magicrc" "$CAD/magic/sys/"
# Fixed layouts used by the extresist-ext, commands and net modes (upstream's tutorial cells).
cp "$SRC"/doc/tutcells/tut11[abcd].mag "$SRC"/doc/tutcells/tut7[bc].mag "$CAD/fixtures/"
# A small LEF library (mayhem/harness/fixtures/cells.lef) read before each fuzzed DEF file.
cp "$SRC/mayhem/harness/fixtures/cells.lef" "$CAD/fixtures/"
chmod -R a+rX "$CAD"

# ---- 3) functional-test build: upstream's normal flags, no sanitizers ---------------------------
TB="$OUT/test-build"
mkdir -p "$TB"
(
  cd "$TB"
  env -u CFLAGS -u LDFLAGS CC="$CC" CFLAGS="-g $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" \
    "$SRC/configure" "${CONFIG_OPTS[@]}" > configure.log 2>&1 || { tail -40 configure.log; exit 1; }
  make -j"$MAYHEM_JOBS" > make.log 2>&1 || { tail -60 make.log; exit 1; }
)
test -x "$TB/magic/magic"

# ---- 4) regression-suite build: upstream's normal flags, Tcl interpreter, no Tk/X --------------
# Upstream's regression suite (mayhem/regression-tests, RTimothyEdwards/magic_regression_tests) drives
# magic with Tcl scripts, so it needs the Tcl build; installed into a prefix as its README says.
RB="$OUT/regress-build"
RP="$OUT/regress"
mkdir -p "$RB"
(
  cd "$RB"
  env -u CFLAGS -u LDFLAGS CC="$CC" CFLAGS="-g $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" \
    "$SRC/configure" --prefix="$RP" --with-tcl --without-tk --without-x --disable-readline \
    --disable-ccache --disable-magic-builddate > configure.log 2>&1 || { tail -40 configure.log; exit 1; }
  grep -q -- '-DMAGIC_WRAPPER' Makefile ../regress-build/defs.mak 2>/dev/null \
    || grep -rq -- 'MAGIC_WRAPPER' defs.mak 2>/dev/null \
    || { echo "build.sh: the regression build did not configure with Tcl" >&2; tail -40 configure.log; exit 1; }
  make -j"$MAYHEM_JOBS" > make.log 2>&1 || { tail -60 make.log; exit 1; }
  make install > install.log 2>&1 || { tail -40 install.log; exit 1; }
)
test -x "$RP/bin/magic"
echo "build.sh: built $OUT/fuzz_magic, $TB/magic/magic and $RP/bin/magic"
