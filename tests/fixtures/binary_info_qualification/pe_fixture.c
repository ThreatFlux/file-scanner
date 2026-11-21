/*
 * Benign binary_info qualification fixture (PE32+, freestanding).
 *
 * scripts/binary_info_qualification.py compiles this file on the CI runner with
 * clang for x86_64-w64-windows-gnu and lld, without any C runtime or import
 * library, and hands the result to `file-scanner mcp-stdio`. The image is never
 * executed. It has no imports and one named export (fixture_export).
 */
__declspec(dllexport) int fixture_export(int value) { return value + 1; }

int fixture_start(void) { return fixture_export(-1); }
