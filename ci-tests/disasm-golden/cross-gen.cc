// Disassemble random encodings of the instructions named on stdin (encoding.h
// names) in strict mode, for comparison against llvm-mc by cross-check.py.
#include "disasm.h"
#include "isa_parser.h"
#include <cstdio>
#include <random>
#include <set>
#include <string>
#include <iostream>
int main(int argc, char** argv) {
  isa_parser_t isa(argv[1], "msu");
  disassembler_t d(&isa, true);
  std::set<std::string> want; for (std::string s; std::cin >> s;) want.insert(s);
  std::mt19937 rng(3);
  #define DECLARE_INSN(code, match, mask) if (want.count(#code)) for (int i = 0; i < 8; i++) { \
    uint32_t w = (match) | (rng() & ~(uint32_t)(mask) & (((match) & 3) == 3 ? ~0u : 0xffffu)); \
    printf(((match) & 3) == 3 ? "%08x\t%s\t%s\n" : "%04x\t%s\t%s\n", w, #code, d.disassemble(insn_t(w)).c_str()); }
  #include "encoding.h"
  #undef DECLARE_INSN
}
