/*
 * Benign binary_info qualification fixture (ELF, hosted glibc).
 *
 * scripts/binary_info_qualification.py compiles this file on the CI runner and
 * hands the result to `file-scanner mcp-stdio`. The program is never executed:
 * it gives the parser a libc import (puts) and a named export
 * (fixture_export, kept in the dynamic symbol table by -rdynamic).
 */
#include <stdio.h>

int fixture_export(int value) { return value + 1; }

int main(void) {
    puts("file-scanner binary_info qualification fixture");
    return fixture_export(-1);
}
