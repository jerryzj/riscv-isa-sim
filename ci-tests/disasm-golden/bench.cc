// Disassembler speed: construction time, lookup() and disassemble() per
// instruction, for a mix of every encoding.h instruction with random operands.
#include "disasm.h"
#include "isa_parser.h"
#include <chrono>
#include <cstdio>
#include <random>
#include <vector>

using clk = std::chrono::steady_clock;

static double ns(clk::time_point a, clk::time_point b)
{
  return std::chrono::duration<double, std::nano>(b - a).count();
}

int main()
{
  isa_parser_t isa("rv64gcv_zba_zbb_zbs_zfh", "msu");

  std::mt19937 rng(1);
  std::vector<insn_t> insns;
  #define DECLARE_INSN(name, match, mask) \
    for (int i = 0; i < 4; i++) \
      insns.push_back(insn_t((match) | (rng() & ~(uint32_t)(mask) & (((match) & 3) == 3 ? ~0u : 0xffffu))));
  #include "encoding.h"
  #undef DECLARE_INSN

  for (bool strict : {false, true}) {
    const int C = 20, R = 50;
    auto t0 = clk::now();
    for (int i = 0; i < C; i++)
      disassembler_t tmp(&isa, strict);
    auto t1 = clk::now();

    disassembler_t d(&isa, strict);
    size_t sink = 0;
    auto t2 = clk::now();
    for (int r = 0; r < R; r++)
      for (auto i : insns)
        sink += (size_t)d.lookup(i);
    auto t3 = clk::now();
    for (int r = 0; r < R; r++)
      for (auto i : insns)
        sink += d.disassemble(i).size();
    auto t4 = clk::now();

    double n = (double)R * insns.size();
    printf("strict=%d construct %.2f ms, lookup %.0f ns/insn, disassemble %.0f ns/insn (%zu)\n",
           strict, ns(t0, t1) / C / 1e6, ns(t2, t3) / n, ns(t3, t4) / n, sink & 1);
  }
}
