// Golden dump of the disassembler: every encoding.h instruction with random
// and hand-picked operand fields (to hit pseudo-instructions such as ret,
// seqz, li), every 16-bit word and 200k random 32-bit words, under several
// ISA strings in strict and non-strict mode.  Output is deterministic, so
// two disassembler implementations can be compared with cmp.
#include "disasm.h"
#include "isa_parser.h"
#include "encoding.h"
#include <cstdio>
#include <random>
#include <stdexcept>

struct cfg { const char* isa; bool strict; };
static const cfg cfgs[] = {
  {"rv64gcvh_zfh_zfa_zvfh_zfbfmin_zvfbfmin_zvfbfwma_zicbom_zicboz_zicond_zimop_zcmop_zicfiss_zicfilp_zalasr_zacas_zabha_zawrs_zk_zks_zvbb_zvbc_zvkg_zvkned_zvknha_zvknhb_zvksed_zvksh_zvabd_zvzip_zvdot4a_zvqwbdota8i_zvfqwbdota8f_zvfwbdota16bf_zvfbdota32f_zvqwdota8i_zvfqwdota8f_zvfwdota16bf_zvfofp4min_zvfofp8min_zilx_zibi_svinval_zcb_zba_zbb_zbc_zbs_zbkb", true},
  {"rv64gcvh_zfh_zfa_zvfh_zfbfmin_zvfbfmin_zvfbfwma_zicbom_zicboz_zicond_zimop_zcmop_zicfiss_zicfilp_zalasr_zacas_zabha_zawrs_zk_zks_zvbb_zvbc_zvkg_zvkned_zvknha_zvknhb_zvksed_zvksh_zvabd_zvzip_zvdot4a_zvqwbdota8i_zvfqwbdota8f_zvfwbdota16bf_zvfbdota32f_zvqwdota8i_zvfqwdota8f_zvfwdota16bf_zvfofp4min_zvfofp8min_zilx_zibi_svinval_zcb_zba_zbb_zbc_zbs_zbkb", false},
  {"rv64gc", true},
  {"rv64gc", false},
  {"rv32gc", true},
  {"rv32gc", false},
  {"rv32gcv_zfa_zfh_zimop_zcmop_zicfiss_zkn_zks_zbkb", true},
  {"rv64gc_zimop_zcmop", true},
  {"rv32imafd_zca_zcb_zcmp_zcmt_zilsd_zclsd_zbb_zba_p", true},
  {"rv32imafd_zca_zcb_zcmp_zcmt_zilsd_zclsd_zbb_zba_p", false},
  {"rv64imafd_zca_zcb_zcmp_zcmt_zbb_zba_p", true},
  {"rv64i_zfinx_zdinx_zhinx", true},
  {"rv32i_zfinx_zdinx_zhinxmin", true},
  {"rv64iv_zve64d", true},
  {"rv64gcv_zvtbase_zvt8e_zvt16e_zvt64e_zvti8i32mm_zvtfmm_zvtdmm_zvtfp16fmm_zvtbf16fmm_zvtofp8fmm", true},
  {"rv32gcv_zvtbase_zvt8e_zvt16e_zvti8i32mm_zvtfmm", true},
  {"rv64gc_smrnmi", true},
  {"rv32gch_zalasr_zacas", true},
  {"rv32imafdqc_zfh_zfa", true},
};

// operand-field patterns (rd=ra, rs1=ra, imm=1, imm=-1, ...) and fields to clear
static const uint32_t pats[] = {0x80, 0x8000, 0x100000, 0x8080, 0xfff00000, 0xfff08080, 0x81080, 0x00100080, 0x28000, 0x2800, 0x80000000, 0x2000000};
static const uint32_t zeros[] = {0xf80, 0xf8000, 0x1f00000, 0xfff00000, 0x7c, 0xf8f80, 0x1ff8000, 0x7c|0x1000};
int main() {
  std::mt19937 rng(12345);
  for (auto& c : cfgs) {
    isa_parser_t* isa;
    try { isa = new isa_parser_t(c.isa, "msu"); }
    catch (std::exception& e) { fprintf(stderr, "bad ISA %s: %s\n", c.isa, e.what()); return 1; }
    disassembler_t d(isa, c.strict);
    printf("### %s strict=%d\n", c.isa, c.strict);
    auto dump = [&](uint64_t bits) { printf("%08lx %s\n", (unsigned long)bits, d.disassemble(insn_t(bits)).c_str()); };
    #define DECLARE_INSN(name, match, mask) { \
      uint32_t dc = ~(uint32_t)(mask); if (((match) & 3) != 3) dc &= 0xffff; \
      dump(match); dump((match) | dc); \
      for (int i = 0; i < 16; i++) dump((match) | (rng() & dc)); \
      for (uint32_t p : pats) { dump((match) | (p & dc)); \
        for (uint32_t z : zeros) dump((match) | (rng() & dc & ~z) | (p & dc & z)); } }
    #include "encoding.h"
    #undef DECLARE_INSN
    for (uint32_t i = 0; i < 0x10000; i++) if ((i & 3) != 3) dump(i);
    for (int i = 0; i < 200000; i++) dump(rng() | 3);
    delete isa;
  }

  // Instructions added after construction (as extensions do) must beat the
  // built-in ones, latest first; a mask-0 entry only catches what nothing
  // else matches.
  isa_parser_t isa("rv64gc", "msu");
  disassembler_t d(&isa, false);
  d.add_insn(new disasm_insn_t("custom_add", MATCH_ADD, MASK_ADD, {}));
  d.add_insn(new disasm_insn_t("custom_add_rd0", MATCH_ADD, MASK_ADD | (0x1f << 7), {}));
  d.add_insn(new disasm_insn_t("custom_slli_uw", MATCH_SLLI_UW, MASK_SLLI_UW, {}));
  d.add_insn(new disasm_insn_t("custom_c_lui", MATCH_C_LUI, MASK_C_LUI, {}));
  d.add_insn(new disasm_insn_t("custom_any", 0, 0, {}));
  printf("### custom\n");
  auto dump = [&](uint64_t bits) { printf("%08lx %s\n", (unsigned long)bits, d.disassemble(insn_t(bits)).c_str()); };
  #define DECLARE_INSN(name, match, mask) { \
    uint32_t dc = ~(uint32_t)(mask); if (((match) & 3) != 3) dc &= 0xffff; \
    dump(match); for (int i = 0; i < 4; i++) dump((match) | (rng() & dc)); }
  #include "encoding.h"
  #undef DECLARE_INSN
  for (uint32_t i = 0; i < 0x10000; i++) if ((i & 3) != 3) dump(i);
  for (int i = 0; i < 20000; i++) dump(rng() | 3);
}
