/*
 * fuzz_magic.c -- file-input fuzz driver for the headless (non-Tcl) magic binary.
 *
 *   fuzz_magic <mode> <input-file>
 *
 * Magic has no library API: every reader is reached through a command
 * ("gds read", "lef read", "extresist", ...) executed by magicMain() on its
 * command line.  This driver replaces magic/magicTop.c's main(): it starts
 * magic (magicMainInit, null graphics device, scmos technology), creates a
 * private scratch directory under $TMPDIR, stages the fuzzed bytes there
 * under the file name the mode's reader expects, writes the mode's fixed
 * command list to a file and makes that file magic's standard input for its
 * command dispatcher (TxDispatch), as when magic is driven through a pipe.
 *
 * Every input runs in a fresh process (AFL fork server) in a fresh scratch
 * directory, so nothing an input writes (.ext/.res.ext/.spice files) is seen
 * by another input.  HOME points at an empty directory so no user
 * ~/.magicrc is read; the runtime files (tech files, display styles, glyphs)
 * come read-only from the "cad" directory next to this binary.
 *
 * Modes (one Mayhemfile each):
 *   mag            fuzzed .mag layout loaded as the top cell, then DRC + expand
 *   gds            "gds read" of a fuzzed GDSII stream
 *   cif            "cif read" of a fuzzed CIF file
 *   lef            "lef read" of a fuzzed LEF file
 *   def            "def read" of a fuzzed DEF file (after a fixed LEF library)
 *   extresist      fuzzed .mag layout, "extract all" then "extresist all"
 *   extresist-ext  fixed layout tut11d.mag with a fuzzed tut11d.ext, "extresist all"
 *   ext2spice      fuzzed .ext netlist through ext2spice and ext2sim (extflat)
 *   tech           fuzzed technology file loaded with -T
 *   net            fixed layout tut7b.mag with a fuzzed tut7b.net netlist, "route"
 *                  (the router reads <cell>.net itself, netmenu/NMnetlist.c)
 *   commands       fuzzed command lines, allow-listed (see below), on a fixed layout
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <ftw.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

extern int magicMainInit(int argc, char *argv[]);
extern void TxDispatch(FILE *f);

static char scratch[PATH_MAX];

static int rm_entry(const char *path, const struct stat *sb, int flag, struct FTW *ftw)
{
    (void)sb; (void)flag; (void)ftw;
    remove(path);
    return 0;
}

static void cleanup(void)
{
    if (scratch[0]) {
        if (chdir("/") == 0) { /* leave the directory before removing it */ }
        nftw(scratch, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
        scratch[0] = '\0';
    }
}

/*
 * Remove scratch directories left behind by earlier inputs that never reached
 * cleanup() (a sanitizer abort, or a timeout kill).  Only fuzz_magic.XXXXXX
 * directories owned by this user and untouched for STALE_SECS are removed:
 * far longer than any Mayhemfile timeout, so a live input's directory (another
 * fuzzer worker's, sharing $TMPDIR) is never touched.  This only bounds disk
 * use; no input ever reads another's directory.
 */
#define STALE_SECS 900
static void sweep_stale(const char *tmp)
{
    DIR *d = opendir(tmp);
    if (!d) return;
    time_t now = time(NULL);
    struct dirent *e;
    char path[PATH_MAX];
    struct stat st;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "fuzz_magic.", 11) != 0 || strlen(e->d_name) != 17)
            continue;
        if (snprintf(path, sizeof path, "%s/%s", tmp, e->d_name) >= (int)sizeof path)
            continue;
        if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid())
            continue;
        if (now - st.st_mtime < STALE_SECS)
            continue;
        nftw(path, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
    }
    closedir(d);
}

static void die(const char *what)
{
    perror(what);
    exit(2);
}

static void write_file(const char *name, const char *data, size_t len)
{
    FILE *f = fopen(name, "wb");
    if (!f) die(name);
    if (len && fwrite(data, 1, len, f) != len) die(name);
    if (fclose(f) != 0) die(name);
}

static char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) die(path);
    size_t cap = 4096, n = 0;
    char *buf = malloc(cap + 1);
    if (!buf) die("malloc");
    size_t r;
    while ((r = fread(buf + n, 1, cap - n, f)) > 0) {
        n += r;
        if (n == cap) {
            cap *= 2;
            buf = realloc(buf, cap + 1);
            if (!buf) die("realloc");
        }
    }
    fclose(f);
    buf[n] = '\0';
    *len = n;
    return buf;
}

/* Copy a fixture file from <cad>/fixtures/ into the scratch directory. */
static void copy_fixture(const char *cad, const char *name)
{
    char path[PATH_MAX];
    size_t len;
    snprintf(path, sizeof path, "%s/fixtures/%s", cad, name);
    char *data = read_file(path, &len);
    write_file(name, data, len);
    free(data);
}

/*
 * The "commands" mode: each input line becomes one magic command.  Only
 * commands that edit or analyse the in-memory layout are allowed, so an input
 * cannot write files outside the scratch directory, source scripts, or change
 * the process environment; lines are restricted to a small character set so
 * magic's own quoting and escaping cannot smuggle a different command past
 * the allow-list.  Every line is prefixed with ':' so it is always parsed as
 * a long command, never as a keyboard macro.
 */
static const char *const allowed_cmds[] = {
    "array", "box", "clockwise", "copy", "delete", "drc", "erase", "expand",
    "extract", "flatten", "flip", "getcell", "grid", "identify", "label", "move",
    "paint", "plow", "redo", "rotate", "select", "sideways", "snap", "spliterase",
    "splitpaint", "stretch", "undo", "unexpand", "upsidedown", "what", "wire",
    "findbox", "fill", "straighten", "shift", "extresist", "ext2spice", "ext2sim",
    "iroute", "route", "channels", "garoute", "feedback", "port", "property",
    "contact", "corner", "drop", "element", "findlabel", "getnode", "tool",
    NULL,
};

static int allowed_line(const char *line)
{
    for (const char *p = line; *p; p++)
        if (!(isalnum((unsigned char)*p) || strchr(" ._,+-", *p)))
            return 0;
    while (*line == ' ') line++;
    size_t n = strcspn(line, " ");
    if (n == 0) return 0;
    for (int i = 0; allowed_cmds[i]; i++)
        if (strlen(allowed_cmds[i]) == n && strncmp(line, allowed_cmds[i], n) == 0)
            return 1;
    return 0;
}

static void write_commands_from_input(FILE *cmds, char *data, size_t len)
{
    int lines = 0;
    char *end = data + len;
    char *p = data;
    while (p < end && lines < 256) {
        char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t n = nl ? (size_t)(nl - p) : (size_t)(end - p);
        if (n > 0 && n < 512) {
            char line[512];
            memcpy(line, p, n);
            line[n] = '\0';
            if (n && line[n - 1] == '\r') line[--n] = '\0';
            if (memchr(p, '\0', n) == NULL && allowed_line(line)) {
                fprintf(cmds, ":%s\n", line);
                lines++;
            }
        }
        if (!nl) break;
        p = nl + 1;
    }
}

static void magic_init(const char *tech)
{
    /* The cell argument (a new, empty cell) makes magic open its layout
     * window, which the editing and reading commands are sent to. */
    char *margv[] = { "magic", "-d", "null", "-T", (char *)tech, "fuzz_magic_top", NULL };
    if (magicMainInit(6, margv) != 0) {
        fprintf(stderr, "fuzz_magic: magic initialization failed\n");
        exit(2);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <mode> <input-file>\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    /* The input path may be relative to the caller's cwd: make it absolute
     * before leaving that directory.  (It need not exist yet: a fuzzer may
     * write it only after the fork server starts.) */
    char input[PATH_MAX], cwd[PATH_MAX];
    if (argv[2][0] == '/')
        snprintf(input, sizeof input, "%s", argv[2]);
    else if (getcwd(cwd, sizeof cwd))
        snprintf(input, sizeof input, "%s/%s", cwd, argv[2]);
    else
        die("getcwd");
    int tech_mode = !strcmp(mode, "tech");

    /* The runtime directory lives next to the binary: <dir>/cad. */
    char exe[PATH_MAX], cad[PATH_MAX], home[PATH_MAX];
    ssize_t el = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (el <= 0) die("readlink /proc/self/exe");
    exe[el] = '\0';
    snprintf(cad, sizeof cad, "%s/cad", dirname(exe));
    snprintf(home, sizeof home, "%s/home", cad);   /* empty: no ~/.magicrc */
    setenv("CAD_ROOT", cad, 1);
    setenv("HOME", home, 1);

    /* magic reads its commands from a file below, never from the terminal. */
    int devnull = open("/dev/null", O_RDONLY);
    if (devnull < 0 || dup2(devnull, 0) < 0) die("/dev/null");
    if (devnull > 0) close(devnull);

    /*
     * Start magic once with the scmos technology, then let AFL fork each
     * test case from here (deferred fork server), so the expensive
     * technology load is not repeated per input.  Every child starts from
     * the same freshly initialized state.  The tech mode fuzzes that load
     * itself, so it initializes per input instead.
     */
    if (chdir(home) != 0) die(home);   /* nor a ./.magicrc from the caller's cwd */
    if (!tech_mode)
        magic_init("scmos");
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    size_t len;
    char *data = read_file(input, &len);

    const char *tmp = getenv("TMPDIR");
    if (!tmp || !*tmp) tmp = "/tmp";
    sweep_stale(tmp);
    snprintf(scratch, sizeof scratch, "%s/fuzz_magic.XXXXXX", tmp);
    if (!mkdtemp(scratch)) die("mkdtemp");
    atexit(cleanup);
    if (chdir(scratch) != 0) die("chdir");

    FILE *cmds = fopen("fuzz_magic.cmds", "w");
    if (!cmds) die("fuzz_magic.cmds");

    if (!strcmp(mode, "mag")) {
        write_file("fuzz.mag", data, len);
        fputs(":load fuzz\n:box 0 0 1 1\n:expand\n:drc check\n:drc catchup\n:drc count\n:select top cell\n", cmds);
    } else if (!strcmp(mode, "gds")) {
        write_file("in.gds", data, len);
        fputs(":gds read in.gds\n", cmds);
    } else if (!strcmp(mode, "cif")) {
        write_file("in.cif", data, len);
        fputs(":cif read in\n", cmds);
    } else if (!strcmp(mode, "lef")) {
        write_file("in.lef", data, len);
        fputs(":lef read in.lef\n", cmds);
    } else if (!strcmp(mode, "def")) {
        /* A fixed LEF library first, so the DEF's components and vias can resolve. */
        copy_fixture(cad, "cells.lef");
        write_file("in.def", data, len);
        fputs(":lef read cells.lef\n:def read in.def\n", cmds);
    } else if (!strcmp(mode, "extresist")) {
        write_file("fuzz.mag", data, len);
        fputs(":load fuzz\n:box 0 0 1 1\n:extract all\n:extresist all\n", cmds);
    } else if (!strcmp(mode, "extresist-ext")) {
        copy_fixture(cad, "tut11d.mag");
        write_file("tut11d.ext", data, len);
        fputs(":load tut11d\n:box 0 0 1 1\n:extresist all\n", cmds);
    } else if (!strcmp(mode, "ext2spice")) {
        write_file("fuzz.ext", data, len);
        fputs(":ext2spice fuzz\n:ext2sim fuzz\n", cmds);
    } else if (tech_mode) {
        write_file("fuzz.tech", data, len);
        fputs(":drc check\n:extract all\n", cmds);
    } else if (!strcmp(mode, "net")) {
        /* The router reads the edit cell's netlist, <cell>.net, from the
         * current directory when none is selected (router/rtrMain.c Route()
         * -> NMNewNetlist), then routes the nets over the box area. */
        copy_fixture(cad, "tut7b.mag");
        copy_fixture(cad, "tut7c.mag");
        write_file("tut7b.net", data, len);
        fputs(":load tut7b\n:box -100 -200 120 120\n:route\n", cmds);
    } else if (!strcmp(mode, "commands")) {
        copy_fixture(cad, "tut11a.mag");
        copy_fixture(cad, "tut11b.mag");
        copy_fixture(cad, "tut11c.mag");
        copy_fixture(cad, "tut11d.mag");
        fputs(":load tut11a\n:box 0 0 1 1\n", cmds);
        write_commands_from_input(cmds, data, len);
    } else {
        fprintf(stderr, "unknown mode '%s'\n", mode);
        return 2;
    }
    /* A clean end exits 0 (magic's own EOF exit status is 1). */
    fputs(":quit 0 -noprompt\n", cmds);
    if (fclose(cmds) != 0) die("fuzz_magic.cmds");
    free(data);

    if (tech_mode)
        magic_init("fuzz");     /* reads ./fuzz.tech from the scratch directory */

    /* The commands become magic's standard input, read by its interactive
     * dispatcher exactly as when magic is driven through a pipe; at EOF it
     * exits ("EOF encountered on input stream"), running cleanup(). */
    int fd = open("fuzz_magic.cmds", O_RDONLY);
    if (fd < 0 || dup2(fd, 0) < 0) die("fuzz_magic.cmds");
    if (fd > 0) close(fd);
    clearerr(stdin);
    TxDispatch(NULL);
    exit(0);
}
