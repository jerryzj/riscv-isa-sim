#!/bin/sh
# Compare the disassembler of a base revision against the working tree (or
# <new-rev>): disassembly output must be byte-identical, and speed is reported.
#
#   usage: compare.sh <base-rev> <configured-build-dir> [<new-rev>]
#
# The build dir only supplies config.h; both sides are compiled here.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
src=$(git -C "$here" rev-parse --show-toplevel)
usage="usage: $0 <base-rev> <configured-build-dir> [<new-rev>]"
base=${1:?$usage}
build=$(cd "${2:?$usage}" && pwd)
new=${3:-}
[ -f "$build/config.h" ] || { echo "$build is not a configured build dir" >&2; exit 1; }
out=$(mktemp -d)

# $1 = side name, $2 = source tree
build_side() {
  flags="-std=c++2a -O2 -iquote $build -I$2 -iquote $2/riscv -iquote $2/disasm -iquote $2/fesvr -iquote $2/softfloat"
  for f in disasm isa_parser regnames; do
    g++ $flags -c "$2/disasm/$f.cc" -o "$out/$1-$f.o" &
  done
  g++ $flags -O1 -c "$here/dump.cc" -o "$out/$1-dump.o" &
  g++ $flags -c "$here/bench.cc" -o "$out/$1-bench.o" &
  wait
  lib="$out/$1-disasm.o $out/$1-isa_parser.o $out/$1-regnames.o"
  g++ "$out/$1-dump.o" $lib -o "$out/$1-dump"
  g++ "$out/$1-bench.o" $lib -o "$out/$1-bench"
}

# $1 = side name, $2 = revision
export_rev() {
  mkdir "$out/$1-src"
  git -C "$src" archive "$2" | tar -x -C "$out/$1-src"
  # the softfloat submodule is not in the archive
  rmdir "$out/$1-src/berkeley-softfloat-3"
  ln -s "$src/berkeley-softfloat-3" "$out/$1-src/berkeley-softfloat-3"
}

export_rev base "$base"
build_side base "$out/base-src"
if [ -n "$new" ]; then
  export_rev new "$new"
  build_side new "$out/new-src"
  echo "base: $(git -C "$src" rev-parse --short "$base")  new: $(git -C "$src" rev-parse --short "$new")"
else
  build_side new "$src"
  echo "base: $(git -C "$src" rev-parse --short "$base")  new: working tree of $(git -C "$src" rev-parse --short HEAD)$(git -C "$src" diff --quiet HEAD -- disasm riscv/disasm.h || echo ' (modified)')"
fi

"$out/base-dump" > "$out/base.txt"
"$out/new-dump" > "$out/new.txt"
echo "golden: $(wc -l < "$out/base.txt") lines"
sha256sum "$out/base.txt" "$out/new.txt" | sed "s|$out/||"
if cmp -s "$out/base.txt" "$out/new.txt"; then
  echo "golden: IDENTICAL"
else
  echo "golden: DIFFERENT; changed lines by mnemonic (count, base -> new):"
  # inputs are identical on both sides, so line N of each file is the same word
  paste -d '\t' "$out/base.txt" "$out/new.txt" | awk -F '\t' '$1 != $2 {
    split($1, a, " "); split($2, b, " ")
    print a[2] (a[3] == "(args" ? " (args unknown)" : "") " -> " b[2] (b[3] == "(args" ? " (args unknown)" : "")
  }' | sort | uniq -c | sort -rn
  rm -rf "$out"/*-src "$out"/*.o "$out"/*-dump "$out"/*-bench
  echo "full outputs in $out"
  exit 1
fi

for side in base new; do
  echo "--- $side"
  "$out/$side-bench"
done
rm -rf "$out"
