/* Disable LeakSanitizer for every fuzz binary (leaks are not the bug class fuzzed here);
 * ASan and UBSan stay fully active. Linked into the fuzz driver by mayhem/build.sh. */
int __lsan_is_turned_off(void) { return 1; }
