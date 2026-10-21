#!/bin/sh
set -eu
crate_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
"${CC:-cc}" -O1 -g -fsanitize=address -fno-omit-frame-pointer \
  -DSTDC -DHAVE_UNISTD_H -DHAVE_STDARG_H \
  -I "$crate_dir/src/zlib" \
  "$crate_dir/tests/gzwrite_nonblocking.c" "$crate_dir"/src/zlib/*.c \
  -o "$build_dir/gzwrite_nonblocking"
"$build_dir/gzwrite_nonblocking"
