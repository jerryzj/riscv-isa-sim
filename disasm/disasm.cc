// See LICENSE for license details.

#include "disasm.h"
#include "decode_macros.h"
#include "platform.h"
#include <cassert>
#include <string>
#include <vector>
#include <cstdarg>
#include <sstream>
#include <stdlib.h>
// For std::reverse and std::array:
#include <algorithm>
#include <array>

#ifdef __GNUC__
# pragma GCC diagnostic ignored "-Wunused-variable"
#endif

// Indicates that the next arg (only) is optional.
// If the result of converting the next arg to a string is ""
// then it will not be printed.
static const arg_t* opt = nullptr;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.i_imm()) + '(' + xpr_name[insn.rs1()] + ')';
  }
} load_address;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.rvc_lbimm()) + '(' + xpr_name[insn.rvc_rs1s()] + ')';
  }
} rvb_b_address;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.rvc_lhimm()) + '(' + xpr_name[insn.rvc_rs1s()] + ')';
  }
} rvb_h_address;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.s_imm()) + '(' + xpr_name[insn.rs1()] + ')';
  }
} store_address;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::string("(") + xpr_name[insn.rs1()] + ')';
  }
} base_only_address;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return xpr_name[insn.rd()];
  }
} xrd;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return xpr_name[insn.rs1()];
  }
} xrs1;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((uint32_t)insn.rvc_index());
  }
} rvcm_jt_index;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    int rlist = insn.rvc_rlist();
    if (rlist >= 4) {
      switch(rlist) {
        case 4: return "{ra}";
        case 5: return "{ra, s0}";
        case 15: return "{ra, s0-s11}";
        default: return "{ra, s0-s" + std::to_string(rlist - 5)+'}';
      }
    } else {
      return "unsupport rlist";
    }
  }
} rvcm_pushpop_rlist;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return '-' + std::to_string(insn.zcmp_stack_adjustment(32));
  }
} rvcm_push_stack_adj_32;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return '-' + std::to_string(insn.zcmp_stack_adjustment(64));
  }
} rvcm_push_stack_adj_64;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string(insn.zcmp_stack_adjustment(32));
  }
} rvcm_pop_stack_adj_32;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string(insn.zcmp_stack_adjustment(64));
  }
} rvcm_pop_stack_adj_64;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return xpr_name[insn.rs2()];
  }
} xrs2;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return xpr_name[insn.rs3()];
  }
} xrs3;

// RV32 P-extension register pair arguments (even register number)
struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return xpr_name[insn.rd_p()];
  }
} xrd_p;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return xpr_name[insn.rs1_p()];
  }
} xrs1_p;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return xpr_name[insn.rs2_p()];
  }
} xrs2_p;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return frm_name(insn.rm());
  }
} rm;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return fpr_name[insn.rd()];
  }
} frd;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return fpr_name[insn.rs1()];
  }
} frs1;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return fpr_name[insn.rs2()];
  }
} frs2;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return fpr_name[insn.rs3()];
  }
} frs3;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    switch (insn.csr())
    {
      #define DECLARE_CSR(name, num) case num: return #name;
      #include "encoding.h"
      #undef DECLARE_CSR
      default:
      {
        char buf[16];
        snprintf(buf, sizeof buf, "unknown_%03" PRIx64, insn.csr());
        return std::string(buf);
      }
    }
  }
} csr;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.i_imm());
  }
} imm;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.shamt());
  }
} shamt;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    std::stringstream s;
    s << std::hex << "0x" << ((uint32_t)insn.u_imm() >> 12);
    return s.str();
  }
} bigimm;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string(insn.rs1());
  }
} zimm5;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string(insn.v_zimm6());
  }
} v_zimm6;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    static const char* table[32] = {
      "-1.0",
      "min",
      "1.52587890625e-05",
      "3.0517578125e-05",
      "0.00390625",
      "0.0078125",
      "0.0625",
      "0.125",
      "0.25",
      "0.3125",
      "0.375",
      "0.4375",
      "0.5",
      "0.625",
      "0.75",
      "0.875",
      "1.0",
      "1.25",
      "1.5",
      "1.75",
      "2.0",
      "2.5",
      "3.0",
      "4.0",
      "8.0",
      "16.0",
      "128.0",
      "256.0",
      "32768.0",
      "65536.0",
      "inf",
      "nan"
    };

    return table[insn.rs1()];
  }
} fli_imm;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    int32_t target = insn.sb_imm();
    std::string s = target >= 0 ? "pc + " : "pc - ";
    s += std::to_string(abs(target));
    return s;
  }
} branch_target;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    std::stringstream s;
    int32_t target = insn.uj_imm();
    char sign = target >= 0 ? '+' : '-';
    s << "pc " << sign << std::hex << " 0x" << abs(target);
    return s.str();
  }
} jump_target;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return xpr_name[insn.rvc_rs1()];
  }
} rvc_rs1;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return xpr_name[insn.rvc_rs2()];
  }
} rvc_rs2;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return fpr_name[insn.rvc_rs2()];
  }
} rvc_fp_rs2;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return xpr_name[insn.rvc_rs1s()];
  }
} rvc_rs1s;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return xpr_name[insn.rvc_rs2s()];
  }
} rvc_rs2s;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return xpr_name[RVC_R1S];
  }
} rvc_r1s;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return xpr_name[RVC_R2S];
  }
} rvc_r2s;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return fpr_name[insn.rvc_rs2s()];
  }
} rvc_fp_rs2s;

struct : public arg_t {
  std::string to_string(insn_t UNUSED insn) const {
    return xpr_name[X_SP];
  }
} rvc_sp;

struct : public arg_t {
  std::string to_string(insn_t UNUSED insn) const {
    return xpr_name[X_RA];
  }
} rvc_ra;

struct : public arg_t {
  std::string to_string(insn_t UNUSED insn) const {
    return xpr_name[X_T0];
  }
} rvc_t0;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.rvc_imm());
  }
} rvc_imm;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.rvc_addi4spn_imm());
  }
} rvc_addi4spn_imm;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.rvc_addi16sp_imm());
  }
} rvc_addi16sp_imm;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.rvc_lwsp_imm());
  }
} rvc_lwsp_imm;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)(insn.rvc_imm() & 0x3f));
  }
} rvc_shamt;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    std::stringstream s;
    s << std::hex << "0x" << ((uint32_t)insn.rvc_imm() << 12 >> 12);
    return s.str();
  }
} rvc_uimm;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.rvc_lwsp_imm()) + '(' + xpr_name[X_SP] + ')';
  }
} rvc_lwsp_address;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.rvc_ldsp_imm()) + '(' + xpr_name[X_SP] + ')';
  }
} rvc_ldsp_address;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.rvc_swsp_imm()) + '(' + xpr_name[X_SP] + ')';
  }
} rvc_swsp_address;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.rvc_sdsp_imm()) + '(' + xpr_name[X_SP] + ')';
  }
} rvc_sdsp_address;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.rvc_lw_imm()) + '(' + xpr_name[insn.rvc_rs1s()] + ')';
  }
} rvc_lw_address;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.rvc_ld_imm()) + '(' + xpr_name[insn.rvc_rs1s()] + ')';
  }
} rvc_ld_address;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    int32_t target = insn.rvc_b_imm();
    std::string s = target >= 0 ? "pc + " : "pc - ";
    s += std::to_string(abs(target));
    return s;
  }
} rvc_branch_target;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    int32_t target = insn.rvc_j_imm();
    std::string s = target >= 0 ? "pc + " : "pc - ";
    s += std::to_string(abs(target));
    return s;
  }
} rvc_jump_target;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::string("(") + xpr_name[insn.rs1()] + ')';
  }
} v_address;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return vr_name[insn.rd()];
  }
} vd;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return vr_name[insn.rs1()];
  }
} vs1;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return vr_name[insn.rs2()];
  }
} vs2;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return vr_name[insn.rd()];
  }
} vs3;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return insn.v_vm() ? "" : "v0.t";
  }
} vm;

struct : public arg_t {
  std::string to_string(insn_t UNUSED insn) const {
    return "v0";
  }
} v0;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.v_simm5());
  }
} v_simm5;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    std::stringstream s;
    int sew = insn.v_sew();
    int lmul = insn.v_lmul();
    auto vta = insn.v_vta() == 1 ? "ta" : "tu";
    auto vma = insn.v_vma() == 1 ? "ma" : "mu";
    int newType = (insn.bits() & 0x80000000) ? insn.v_zimm10() : insn.v_zimm11();
    // if bit 31 is set, this is vsetivli and there is a 10-bit vtype, else this is vsetvli and there is an 11-bit vtype
    // If the provided vtype has reserved bits, display the hex version of the vtype instead
    if ((newType >> 8) != 0) {
      s << "0x" << std::hex << newType;
    } else {
      s << "e" << sew;
      if(insn.v_frac_lmul()) {
        std::string lmul_str = "";
        switch(lmul){
          case 3:
            lmul_str = "f2";
            break;
          case 2:
            lmul_str = "f4";
            break;
          case 1:
            lmul_str = "f8";
            break;
          default:
            assert(true && "unsupport fractional LMUL");
        }
        s << ", m" << lmul_str;
      } else {
        s << ", m" << (1 << lmul);
      }
      s << ", " << vta << ", " << vma;
    }

    return s.str();
  }
} v_vtype;

struct : public arg_t {
  std::string to_string(insn_t UNUSED insn) const {
    return "x0";
  }
} x0;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    std::string s;
    auto iorw = insn.iorw();
    bool has_pre = false;
    static const char type[] = "wroi";
    for (int i = 7; i >= 4; --i) {
      if (iorw & (1ul << i)) {
        s += type[i - 4];
        has_pre = true;
      }
    }

    s += (has_pre ? "," : "");
    for (int i = 3; i >= 0; --i) {
      if (iorw & (1ul << i)) {
        s += type[i];
      }
    }

    return s;
  }
} iorw;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.p_imm8());
  }
} p_imm8;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.p_imm10csl());
  }
} p_imm10csl;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.p_imm10csr());
  }
} p_imm10csr;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.p_imm10csrw());
  }
} p_imm10csrw;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.shamtd());
  }
} shamtd;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.shamtw());
  }
} shamtw;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.shamth());
  }
} shamth;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.shamtb());
  }
} shamtb;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.b_imm5());
  }
} b_imm5;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.bs());
  }
} bs;

struct : public arg_t {
  std::string to_string(insn_t insn) const {
    return std::to_string((int)insn.rcon());
  }
} rcon;

typedef struct {
  reg_t match;
  reg_t mask;
  const char *fmt;
  std::vector<const arg_t*>& arg;
} custom_fmt_t;

std::string disassembler_t::disassemble(insn_t insn) const
{
  const disasm_insn_t* disasm_insn = lookup(insn);
  return disasm_insn ? disasm_insn->to_string(insn) : "unknown";
}


static void NOINLINE add_xamo_insn(disassembler_t* d, const char* name, uint32_t match, uint32_t mask)
{
  const char *suffix[] = {"", ".rl", ".aq", ".aqrl"};
  char new_name[128];
  uint32_t new_mask = mask | (0x3 << 25);
  uint32_t new_match;

  for (uint32_t idx = 0; idx < sizeof(suffix) / sizeof(suffix[0]); ++idx) {
    snprintf(new_name, sizeof(new_name), "%s%s", name, suffix[idx]);
    new_match = match | (idx << 25);

    d->add_insn(new disasm_insn_t(new_name, new_match, new_mask, {&xrd, &xrs2, &base_only_address}));
  }
}

static void NOINLINE add_unknown_insn(disassembler_t* d, const char* name, uint32_t match, uint32_t mask)
{
  std::string s = name;
  s += " (args unknown)";

  d->add_insn(new disasm_insn_t(s.c_str(), match, mask, {}));
}


static void NOINLINE add_unknown_insns(disassembler_t* d)
{
  // provide a default disassembly for all instructions as a fallback
  #define DECLARE_INSN(code, match, mask) \
   add_unknown_insn(d, #code, match, mask);
  #include "encoding.h"
  #undef DECLARE_INSN
}

#define ext_enabled_strict(x) (isa->extension_enabled(x))
#define ext_enabled(x) (ext_enabled_strict(x) || !strict)
#define xlen_eq(x) (xlen_eq_strict(x) || !strict)
#define xlen_eq_strict(x) (isa->get_max_xlen() == (x))


// ---------------------------------------------------------------------------
// insn_class: extension conditions for the flat opcode table.
// Mirrors binutils' riscv_insn_class — each value names the ISA subset that
// must be active. insn_class_enabled() performs the actual check.
// ---------------------------------------------------------------------------
enum class insn_class : uint8_t {
  always = 0,       // no extension required
  rv64,             // xlen_eq(64)
  rv32,             // xlen_eq_strict(32) — no !strict fallback on xlen
  zalrsc,           // EXT_ZALRSC
  zalrsc_rv64,      // EXT_ZALRSC + rv64
  zacas_rv64,       // EXT_ZACAS + rv64
  zawrs,            zicfilp,
  ext_s,
  ext_m,            ext_m_rv64,
  zba,              zba_rv64,
  zbb,              zbb_rv64,
  zbc,              zbs,
  zbkb,             zbkb_rv64,
  svinval,
  ext_f,
  f_or_zfinx,       f_or_zfinx_rv64,
  ext_d,            d_rv64,
  d_or_zdinx,       d_or_zdinx_rv64,
  zfa,
  zfa_zfh,          // EXT_ZFA + (EXT_ZFH || EXT_ZVFH)
  zfa_d,            // EXT_ZFA + 'D'
  zfa_d_rv32,       // EXT_ZFA + 'D' + xlen_strict==32
  zfa_q,            // EXT_ZFA + 'Q'
  zfa_q_rv64,       // EXT_ZFA + 'Q' + rv64
  zfh,              zhinx,
  zfhmin,           zfh_move,
  zhinxmin,         zibi,
  ext_q,            zfbfmin,
  ext_h,
  zca,
  zca_rv32,         // EXT_ZCA + xlen_strict==32
  zca_not_rv32,     // EXT_ZCA + xlen != 32 (c.addiw)
  zca_rv64,
  zca_ld,           // EXT_ZCA + (xlen_strict==64 || EXT_ZCLSD_strict)
  zcd,              zcf,
  zcb,              zcb_rv64,
  zcmp_rv32,        // EXT_ZCMP + xlen_strict==32
  zcmp_not_rv32,    // EXT_ZCMP + xlen != 32
  zcmp,             zcmt,
  zmmul,            zmmul_rv64,
  zicbom,           zicboz,   zicond,
  zknd_or_zkne,     // EXT_ZKND || EXT_ZKNE
  zknd_rv64,        zkne_rv64,
  zknh,             zknh_rv64,   zknh_rv32,
  zksed,            zksh,
  zalasr,
  zicfiss,
  zicfiss_zca,      // EXT_ZICFISS + EXT_ZCA
  ext_p,
  ext_p_rv32,       // EXT_P + xlen_strict==32
  ext_p_rv64,       // EXT_P + rv64
};

// Map insn_class to an ISA enablement predicate.
// Matches binutils' riscv_subset_supports() in spirit.
static bool insn_class_enabled(insn_class cls, const isa_parser_t *isa, bool s)
{
  using ic = insn_class;
  const auto ext  = [&](unsigned e)              { return isa->extension_enabled(e) || !s; };
  const auto ext2 = [&](unsigned a, unsigned b)  { return isa->extension_enabled(a) || isa->extension_enabled(b) || !s; };
  const auto xv   = [&](unsigned x) -> bool     { return isa->get_max_xlen() == x || !s; };
  const auto xvs  = [&](unsigned x) -> bool     { return isa->get_max_xlen() == x; };

  switch (cls) {
    case ic::always:          return true;
    case ic::rv64:            return xv(64);
    case ic::rv32:            return xvs(32);
    case ic::zalrsc:          return ext(EXT_ZALRSC);
    case ic::zalrsc_rv64:     return ext(EXT_ZALRSC)  && xv(64);
    case ic::zacas_rv64:      return ext(EXT_ZACAS)   && xv(64);
    case ic::zawrs:           return ext(EXT_ZAWRS);
    case ic::zicfilp:         return ext(EXT_ZICFILP);
    case ic::ext_s:           return ext('S');
    case ic::ext_m:           return ext('M');
    case ic::ext_m_rv64:      return ext('M')        && xv(64);
    case ic::zba:             return ext(EXT_ZBA);
    case ic::zba_rv64:        return ext(EXT_ZBA)      && xv(64);
    case ic::zbb:             return ext(EXT_ZBB);
    case ic::zbb_rv64:        return ext(EXT_ZBB)      && xv(64);
    case ic::zbc:             return ext(EXT_ZBC);
    case ic::zbs:             return ext(EXT_ZBS);
    case ic::zbkb:            return ext(EXT_ZBKB);
    case ic::zbkb_rv64:       return ext(EXT_ZBKB)     && xv(64);
    case ic::svinval:         return ext(EXT_SVINVAL);
    case ic::ext_f:           return ext('F');
    case ic::f_or_zfinx:      return ext2('F', EXT_ZFINX);
    case ic::f_or_zfinx_rv64: return ext2('F', EXT_ZFINX) && xv(64);
    case ic::ext_d:           return ext('D');
    case ic::d_rv64:          return ext('D')         && xv(64);
    case ic::d_or_zdinx:      return ext2('D', EXT_ZDINX);
    case ic::d_or_zdinx_rv64: return ext2('D', EXT_ZDINX) && xv(64);
    case ic::zfa:             return ext(EXT_ZFA);
    case ic::zfa_zfh:         return ext(EXT_ZFA) && (isa->extension_enabled(EXT_ZFH) || isa->extension_enabled(EXT_ZVFH) || !s);
    case ic::zfa_d:           return ext(EXT_ZFA) && ext('D');
    case ic::zfa_d_rv32:      return (ext(EXT_ZFA) || !s) && ext('D') && xvs(32);
    case ic::zfa_q:           return ext(EXT_ZFA) && ext('Q');
    case ic::zfa_q_rv64:      return ext(EXT_ZFA) && ext('Q') && xv(64);
    case ic::zfh:             return ext(EXT_ZFH);
    case ic::zhinx:           return ext(EXT_ZHINX);
    case ic::zfhmin:          return ext(EXT_ZFHMIN);
    case ic::zfh_move:        return ext(EXT_INTERNAL_ZFH_MOVE);
    case ic::zhinxmin:        return ext(EXT_ZHINXMIN);
    case ic::zibi:            return ext(EXT_ZIBI);
    case ic::ext_q:           return ext('Q');
    case ic::zfbfmin:         return ext(EXT_ZFBFMIN);
    case ic::ext_h:           return ext('H');
    case ic::zca:             return ext(EXT_ZCA);
    case ic::zca_rv32:        return (ext(EXT_ZCA) || !s) && xvs(32);
    case ic::zca_not_rv32:    return (ext(EXT_ZCA) || !s) && !xvs(32);
    case ic::zca_rv64:        return ext(EXT_ZCA)     && xv(64);
    case ic::zca_ld:          return (ext(EXT_ZCA) || !s) && (xvs(64) || isa->extension_enabled(EXT_ZCLSD));
    case ic::zcd:             return ext(EXT_ZCD);
    case ic::zcf:             return ext(EXT_ZCF);
    case ic::zcb:             return ext(EXT_ZCB);
    case ic::zcb_rv64:        return ext(EXT_ZCB)     && xv(64);
    case ic::zcmp_rv32:       return (ext(EXT_ZCMP) || !s) && xvs(32);
    case ic::zcmp_not_rv32:   return (ext(EXT_ZCMP) || !s) && !xvs(32);
    case ic::zcmp:            return ext(EXT_ZCMP);
    case ic::zcmt:            return ext(EXT_ZCMT);
    case ic::zmmul:           return ext(EXT_ZMMUL);
    case ic::zmmul_rv64:      return ext(EXT_ZMMUL)   && xv(64);
    case ic::zicbom:          return ext(EXT_ZICBOM);
    case ic::zicboz:          return ext(EXT_ZICBOZ);
    case ic::zicond:          return ext(EXT_ZICOND);
    case ic::zknd_or_zkne:    return isa->extension_enabled(EXT_ZKND) || isa->extension_enabled(EXT_ZKNE) || !s;
    case ic::zknd_rv64:       return ext(EXT_ZKND)    && xv(64);
    case ic::zkne_rv64:       return ext(EXT_ZKNE)    && xv(64);
    case ic::zknh:            return ext(EXT_ZKNH);
    case ic::zknh_rv64:       return ext(EXT_ZKNH)    && xv(64);
    case ic::zknh_rv32:       return ext(EXT_ZKNH)    && xv(32);
    case ic::zksed:           return ext(EXT_ZKSED);
    case ic::zksh:            return ext(EXT_ZKSH);
    case ic::zalasr:          return ext(EXT_ZALASR);
    case ic::zicfiss:         return ext(EXT_ZICFISS);
    case ic::zicfiss_zca:     return ext(EXT_ZICFISS) && ext(EXT_ZCA);
    case ic::ext_p:           return ext('P');
    case ic::ext_p_rv32:      return (ext('P') || !s) && xvs(32);
    case ic::ext_p_rv64:      return ext('P')        && xv(64);
  }
  return false;
}

struct disasm_opcode_t {
  const char *name;
  uint32_t match;
  uint32_t mask;
  const char *fmt;
  insn_class cls;   // like binutils' insn_class field — see insn_class_enabled()
};

// Array-based fmt_char_to_arg: O(1) lookup, reads like a flat table.
static const arg_t *fmt_char_to_arg(char c)
{
  static const auto table = []() {
    std::array<const arg_t*, 128> t{};
    // Integer registers
    t['d'] = &xrd;   t['s'] = &xrs1;  t['t'] = &xrs2;  t['r'] = &xrs3;
    // Float registers
    t['D'] = &frd;   t['S'] = &frs1;  t['T'] = &frs2;  t['R'] = &frs3;
    // Vector registers
    t['A'] = &vd;    t['B'] = &vs1;   t['C'] = &vs2;   t['G'] = &vs3;
    // P-extension register pairs
    t['P'] = &xrd_p; t['Q'] = &xrs1_p; t['U'] = &xrs2_p;
    // Immediates
    t['j'] = &imm;      t['Z'] = &shamt;      t['u'] = &bigimm;    t['z'] = &zimm5;
    t['5'] = &v_simm5;  t['6'] = &v_zimm6;    t['L'] = &fli_imm;   t['>'] = &b_imm5;
    t['\'']=&shamtd;   t['<'] = &shamtw;     t[';'] = &shamth;    t[':'] = &shamtb;
    t['7'] = &p_imm8;   t['$'] = &p_imm10csl; t['%'] = &p_imm10csr; t['&'] = &p_imm10csrw;
    t['-'] = &bs;         t['+'] = &rcon;
    // Memory addresses
    t['o'] = &load_address;  t['q'] = &store_address;  t['('] = &base_only_address;
    // Special
    t['E'] = &csr;   t['m'] = &rm;     t['I'] = &iorw;   t['0'] = &x0;
    t['k'] = &vm;    t['K'] = &v0;     t['W'] = &v_vtype;
    t['p'] = &branch_target;  t['a'] = &jump_target;
    // RVC
    t['e'] = &rvc_rs1;    t['f'] = &rvc_rs2;    t['F'] = &rvc_fp_rs2;
    t['H'] = &rvc_rs1s;   t['J'] = &rvc_rs2s;   t['#'] = &rvc_fp_rs2s;
    t['N'] = &rvc_sp;     t['X'] = &rvc_ra;     t['Y'] = &rvc_t0;
    t['V'] = &rvc_r1s;    t['O'] = &rvc_r2s;
    t['i'] = &rvc_imm;    t['n'] = &rvc_addi4spn_imm;  t['x'] = &rvc_addi16sp_imm;
    t['l'] = &rvc_lwsp_imm;  t['h'] = &rvc_shamt;  t['b'] = &rvc_uimm;
    t['@'] = &rvc_lwsp_address;  t['M'] = &rvc_ldsp_address;
    t['_'] = &rvc_swsp_address;  t['g'] = &rvc_sdsp_address;
    t['c'] = &rvc_lw_address;    t['v'] = &rvc_ld_address;
    t['y'] = &rvc_branch_target; t['w'] = &rvc_jump_target;
    t['1'] = &rvcm_jt_index;
    t['!'] = &rvcm_pushpop_rlist;
    t['2'] = &rvcm_push_stack_adj_32;  t['4'] = &rvcm_push_stack_adj_64;
    t['3'] = &rvcm_pop_stack_adj_32;   t['8'] = &rvcm_pop_stack_adj_64;
    t['*'] = &rvb_b_address;  t['/'] = &rvb_h_address;
    return t;
  }();
  return static_cast<unsigned char>(c) < 128 ? table[static_cast<unsigned char>(c)] : nullptr;
}

static std::vector<const arg_t *> parse_fmt(const char *fmt)
{
  std::vector<const arg_t *> args;
  for (const char *p = fmt; *p; p++) {
    if (*p == '?') { args.push_back(opt); continue; }
    const arg_t *a = fmt_char_to_arg(*p);
    assert(a != nullptr);
    args.push_back(a);
  }
  return args;
}

// C++20: import insn_class enumerators into file scope for the table below
using enum insn_class;

// Single flat opcode table (like binutils riscv_opcodes[]).
// Entry order determines disassembly priority (first = highest after reversal).
static const disasm_opcode_t all_insns[] = {
  // prefetch_insns
  {"prefetch_r", MATCH_PREFETCH_R, MASK_PREFETCH_R, "q", always},
  {"prefetch_w", MATCH_PREFETCH_W, MASK_PREFETCH_W, "q", always},
  {"prefetch_i", MATCH_PREFETCH_I, MASK_PREFETCH_I, "q", always},
  {"pause",      MATCH_PAUSE,      MASK_PAUSE,      "", always},
  // base_load_store_insns
  {"lb",  MATCH_LB,  MASK_LB,  "do", always},
  {"lbu", MATCH_LBU, MASK_LBU, "do", always},
  {"lh",  MATCH_LH,  MASK_LH,  "do", always},
  {"lhu", MATCH_LHU, MASK_LHU, "do", always},
  {"lw",  MATCH_LW,  MASK_LW,  "do", always},
  {"sb",  MATCH_SB,  MASK_SB,  "tq", always},
  {"sh",  MATCH_SH,  MASK_SH,  "tq", always},
  {"sw",  MATCH_SW,  MASK_SW,  "tq", always},
  // rv64_load_store_insns
  {"lwu", MATCH_LWU, MASK_LWU, "do", rv64},
  {"ld",  MATCH_LD,  MASK_LD,  "do", rv64},
  {"sd",  MATCH_SD,  MASK_SD,  "tq", rv64},
  // zalrsc_insns
  {"lr.w", MATCH_LR_W, MASK_LR_W, "d(", zalrsc},
  // zalrsc64_insns
  {"lr.d", MATCH_LR_D, MASK_LR_D, "d(", zalrsc_rv64},
  // zacas64_insns
  // amocas.q handled by add_xamo_insn in add_instructions
  // zawrs_insns
  {"wrs_sto", MATCH_WRS_STO, MASK_WRS_STO, "", zawrs},
  {"wrs_nto", MATCH_WRS_NTO, MASK_WRS_NTO, "", zawrs},
  // zicfilp_insns
  {"lpad", MATCH_LPAD, MASK_LPAD, "u", zicfilp},
  // jump_insns
  {"j",    MATCH_JAL,              MASK_JAL | 0xf80u,             "a", always},
  {"jal",  MATCH_JAL | 0x80u,     MASK_JAL | 0xf80u,             "a", always},
  {"jal",  MATCH_JAL,             MASK_JAL,                       "da", always},
  {"ret",  MATCH_JALR | 0x8000u,  MASK_JALR | 0xf80u | 0xf8000u | 0xfff00000u, "", always},
  {"jr",   MATCH_JALR,            MASK_JALR | 0xf80u | 0xfff00000u, "s", always},
  {"jalr", MATCH_JALR | 0x80u,   MASK_JALR | 0xf80u | 0xfff00000u, "s", always},
  {"jalr", MATCH_JALR,            MASK_JALR,                        "dsj", always},
  // branch_insns
  {"beqz", MATCH_BEQ, MASK_BEQ | 0x1f00000u, "sp", always},
  {"bnez", MATCH_BNE, MASK_BNE | 0x1f00000u, "sp", always},
  {"bltz", MATCH_BLT, MASK_BLT | 0x1f00000u, "sp", always},
  {"bgez", MATCH_BGE, MASK_BGE | 0x1f00000u, "sp", always},
  {"beq",  MATCH_BEQ, MASK_BEQ,  "stp", always},
  {"bne",  MATCH_BNE, MASK_BNE,  "stp", always},
  {"blt",  MATCH_BLT, MASK_BLT,  "stp", always},
  {"bge",  MATCH_BGE, MASK_BGE,  "stp", always},
  {"bltu", MATCH_BLTU, MASK_BLTU, "stp", always},
  {"bgeu", MATCH_BGEU, MASK_BGEU, "stp", always},
  // utype_insns
  {"lui",   MATCH_LUI,   MASK_LUI,   "du", always},
  {"auipc", MATCH_AUIPC, MASK_AUIPC, "du", always},
  // base_int_insns
  // nop: addi x0,x0,0
  {"nop",  MATCH_ADDI, MASK_ADDI | 0xf80u | 0xf8000u | 0xfff00000u, "", always},
  // li: addi rd, x0, imm  (mask_rs1 = 0xf8000 locks rs1=0)
  {"li",   MATCH_ADDI, MASK_ADDI | 0xf8000u, "dj", always},
  // mv: addi rd, rs1, 0  (mask_imm locks imm=0)
  {"mv",   MATCH_ADDI, MASK_ADDI | 0xfff00000u, "ds", always},
  {"addi", MATCH_ADDI, MASK_ADDI, "dsj", always},
  {"slti", MATCH_SLTI, MASK_SLTI, "dsj", always},
  // seqz: sltiu rd, rs1, 1
  {"seqz", MATCH_SLTIU | (1u << 20), MASK_SLTIU | 0xfff00000u, "ds", always},
  {"sltiu", MATCH_SLTIU, MASK_SLTIU, "dsj", always},
  // not: xori rd, rs1, -1  (imm=0xfff=-1)
  {"not",  MATCH_XORI | 0xfff00000u, MASK_XORI | 0xfff00000u, "ds", always},
  {"xori", MATCH_XORI, MASK_XORI, "dsj", always},
  {"slli", MATCH_SLLI, MASK_SLLI, "dsZ", always},
  {"srli", MATCH_SRLI, MASK_SRLI, "dsZ", always},
  {"srai", MATCH_SRAI, MASK_SRAI, "dsZ", always},
  {"ori",  MATCH_ORI,  MASK_ORI,  "dsj", always},
  {"andi", MATCH_ANDI, MASK_ANDI, "dsj", always},
  {"add",  MATCH_ADD,  MASK_ADD,  "dst", always},
  {"sub",  MATCH_SUB,  MASK_SUB,  "dst", always},
  {"sll",  MATCH_SLL,  MASK_SLL,  "dst", always},
  {"slt",  MATCH_SLT,  MASK_SLT,  "dst", always},
  // snez: sltu rd, x0, rs2  (mask_rs1 locks rs1=0)
  {"snez", MATCH_SLTU, MASK_SLTU | 0xf8000u, "dt", always},
  {"sltu", MATCH_SLTU, MASK_SLTU, "dst", always},
  {"xor",  MATCH_XOR,  MASK_XOR,  "dst", always},
  {"srl",  MATCH_SRL,  MASK_SRL,  "dst", always},
  {"sra",  MATCH_SRA,  MASK_SRA,  "dst", always},
  {"or",   MATCH_OR,   MASK_OR,   "dst", always},
  {"and",  MATCH_AND,  MASK_AND,  "dst", always},
  // rv64_int_insns
  // sext.w: addiw rd, rs1, 0
  {"sext.w", MATCH_ADDIW, MASK_ADDIW | 0xfff00000u, "ds", rv64},
  {"addiw",  MATCH_ADDIW, MASK_ADDIW, "dsj", rv64},
  {"slliw",  MATCH_SLLIW, MASK_SLLIW, "dsZ", rv64},
  {"srliw",  MATCH_SRLIW, MASK_SRLIW, "dsZ", rv64},
  {"sraiw",  MATCH_SRAIW, MASK_SRAIW, "dsZ", rv64},
  {"addw",   MATCH_ADDW,  MASK_ADDW,  "dst", rv64},
  {"subw",   MATCH_SUBW,  MASK_SUBW,  "dst", rv64},
  {"sllw",   MATCH_SLLW,  MASK_SLLW,  "dst", rv64},
  {"srlw",   MATCH_SRLW,  MASK_SRLW,  "dst", rv64},
  {"sraw",   MATCH_SRAW,  MASK_SRAW,  "dst", rv64},
  // system_insns
  {"ecall",   MATCH_ECALL,   MASK_ECALL,   "", always},
  {"ebreak",  MATCH_EBREAK,  MASK_EBREAK,  "", always},
  {"mret",    MATCH_MRET,    MASK_MRET,    "", always},
  {"dret",    MATCH_DRET,    MASK_DRET,    "", always},
  {"wfi",     MATCH_WFI,     MASK_WFI,     "", always},
  {"fence",   MATCH_FENCE,   MASK_FENCE,   "I", always},
  {"fence.i", MATCH_FENCE_I, MASK_FENCE_I, "", always},
  // CSR pseudo-instructions (more specific masks first)
  {"csrr",  MATCH_CSRRS,  MASK_CSRRS  | 0xf8000u,    "dE", always},
  {"csrw",  MATCH_CSRRW,  MASK_CSRRW  | 0xf80u,      "Es", always},
  {"csrs",  MATCH_CSRRS,  MASK_CSRRS  | 0xf80u,      "Es", always},
  {"csrc",  MATCH_CSRRC,  MASK_CSRRC  | 0xf80u,      "Es", always},
  {"csrwi", MATCH_CSRRWI, MASK_CSRRWI | 0xf80u,      "Ez", always},
  {"csrsi", MATCH_CSRRSI, MASK_CSRRSI | 0xf80u,      "Ez", always},
  {"csrci", MATCH_CSRRCI, MASK_CSRRCI | 0xf80u,      "Ez", always},
  {"csrrw",  MATCH_CSRRW,  MASK_CSRRW,  "dEs", always},
  {"csrrs",  MATCH_CSRRS,  MASK_CSRRS,  "dEs", always},
  {"csrrc",  MATCH_CSRRC,  MASK_CSRRC,  "dEs", always},
  {"csrrwi", MATCH_CSRRWI, MASK_CSRRWI, "dEz", always},
  {"csrrsi", MATCH_CSRRSI, MASK_CSRRSI, "dEz", always},
  {"csrrci", MATCH_CSRRCI, MASK_CSRRCI, "dEz", always},
  // s_ext_insns
  {"sret",       MATCH_SRET,       MASK_SRET,       "", ext_s},
  {"sfence.vma", MATCH_SFENCE_VMA, MASK_SFENCE_VMA, "st", ext_s},
  // m_ext_insns
  {"mul",    MATCH_MUL,    MASK_MUL,    "dst", ext_m},
  {"mulh",   MATCH_MULH,   MASK_MULH,   "dst", ext_m},
  {"mulhu",  MATCH_MULHU,  MASK_MULHU,  "dst", ext_m},
  {"mulhsu", MATCH_MULHSU, MASK_MULHSU, "dst", ext_m},
  {"div",    MATCH_DIV,    MASK_DIV,    "dst", ext_m},
  {"divu",   MATCH_DIVU,   MASK_DIVU,   "dst", ext_m},
  {"rem",    MATCH_REM,    MASK_REM,    "dst", ext_m},
  {"remu",   MATCH_REMU,   MASK_REMU,   "dst", ext_m},
  // m_ext64_insns
  {"mulw",  MATCH_MULW,  MASK_MULW,  "dst", ext_m_rv64},
  {"divw",  MATCH_DIVW,  MASK_DIVW,  "dst", ext_m_rv64},
  {"divuw", MATCH_DIVUW, MASK_DIVUW, "dst", ext_m_rv64},
  {"remw",  MATCH_REMW,  MASK_REMW,  "dst", ext_m_rv64},
  {"remuw", MATCH_REMUW, MASK_REMUW, "dst", ext_m_rv64},
  // zba_insns
  {"sh1add", MATCH_SH1ADD, MASK_SH1ADD, "dst", zba},
  {"sh2add", MATCH_SH2ADD, MASK_SH2ADD, "dst", zba},
  {"sh3add", MATCH_SH3ADD, MASK_SH3ADD, "dst", zba},
  // zba64_insns
  {"slli.uw", MATCH_SLLI_UW, MASK_SLLI_UW, "dsZ", zba_rv64},
  // zext.w: add.uw rd, rs1, zero  (mask_rs2 locks rs2=0)
  {"zext.w",  MATCH_ADD_UW, MASK_ADD_UW | 0x1f00000u, "ds", zba_rv64},
  {"add.uw",  MATCH_ADD_UW,  MASK_ADD_UW,  "dst", zba_rv64},
  {"sh1add.uw", MATCH_SH1ADD_UW, MASK_SH1ADD_UW, "dst", zba_rv64},
  {"sh2add.uw", MATCH_SH2ADD_UW, MASK_SH2ADD_UW, "dst", zba_rv64},
  {"sh3add.uw", MATCH_SH3ADD_UW, MASK_SH3ADD_UW, "dst", zba_rv64},
  // zbb_insns
  {"ror",    MATCH_ROR,    MASK_ROR,    "dst", zbb},
  {"rol",    MATCH_ROL,    MASK_ROL,    "dst", zbb},
  {"rori",   MATCH_RORI,   MASK_RORI,   "dsZ", zbb},
  {"ctz",    MATCH_CTZ,    MASK_CTZ,    "ds", zbb},
  {"clz",    MATCH_CLZ,    MASK_CLZ,    "ds", zbb},
  {"cpop",   MATCH_CPOP,   MASK_CPOP,   "ds", zbb},
  {"min",    MATCH_MIN,    MASK_MIN,    "dst", zbb},
  {"minu",   MATCH_MINU,   MASK_MINU,   "dst", zbb},
  {"max",    MATCH_MAX,    MASK_MAX,    "dst", zbb},
  {"maxu",   MATCH_MAXU,   MASK_MAXU,   "dst", zbb},
  {"andn",   MATCH_ANDN,   MASK_ANDN,   "dst", zbb},
  {"orn",    MATCH_ORN,    MASK_ORN,    "dst", zbb},
  {"xnor",   MATCH_XNOR,   MASK_XNOR,   "dst", zbb},
  {"sext.b", MATCH_SEXT_B, MASK_SEXT_B, "ds", zbb},
  {"sext.h", MATCH_SEXT_H, MASK_SEXT_H, "ds", zbb},
  {"rev8",   MATCH_REV8,   MASK_REV8,   "ds", zbb},
  {"orc.b",  MATCH_ORC_B,  MASK_ORC_B,  "ds", zbb},
  // zbb64_insns
  {"rorw",  MATCH_RORW,  MASK_RORW,  "dst", zbb_rv64},
  {"rolw",  MATCH_ROLW,  MASK_ROLW,  "dst", zbb_rv64},
  {"roriw", MATCH_RORIW, MASK_RORIW, "dsZ", zbb_rv64},
  {"ctzw",  MATCH_CTZW,  MASK_CTZW,  "ds", zbb_rv64},
  {"clzw",  MATCH_CLZW,  MASK_CLZW,  "ds", zbb_rv64},
  {"cpopw", MATCH_CPOPW, MASK_CPOPW, "ds", zbb_rv64},
  // zbc_insns
  {"clmul",  MATCH_CLMUL,  MASK_CLMUL,  "dst", zbc},
  {"clmulh", MATCH_CLMULH, MASK_CLMULH, "dst", zbc},
  {"clmulr", MATCH_CLMULR, MASK_CLMULR, "dst", zbc},
  // zbs_insns
  {"bclr",  MATCH_BCLR,  MASK_BCLR,  "dst", zbs},
  {"binv",  MATCH_BINV,  MASK_BINV,  "dst", zbs},
  {"bset",  MATCH_BSET,  MASK_BSET,  "dst", zbs},
  {"bext",  MATCH_BEXT,  MASK_BEXT,  "dst", zbs},
  {"bclri", MATCH_BCLRI, MASK_BCLRI, "dsZ", zbs},
  {"binvi", MATCH_BINVI, MASK_BINVI, "dsZ", zbs},
  {"bseti", MATCH_BSETI, MASK_BSETI, "dsZ", zbs},
  {"bexti", MATCH_BEXTI, MASK_BEXTI, "dsZ", zbs},
  // zbkb_insns
  {"brev8", MATCH_BREV8, MASK_BREV8, "ds", zbkb},
  {"rev8",  MATCH_REV8,  MASK_REV8,  "ds", zbkb},
  {"pack",  MATCH_PACK,  MASK_PACK,  "dst", zbkb},
  {"packh", MATCH_PACKH, MASK_PACKH, "dst", zbkb},
  // zbkb64_insns
  {"packw", MATCH_PACKW, MASK_PACKW, "dst", zbkb_rv64},
  // svinval_insns
  {"sfence.w.inval",  MATCH_SFENCE_W_INVAL,  MASK_SFENCE_W_INVAL,  "", svinval},
  {"sfence.inval.ir", MATCH_SFENCE_INVAL_IR, MASK_SFENCE_INVAL_IR, "", svinval},
  {"sinval.vma",      MATCH_SINVAL_VMA,      MASK_SINVAL_VMA,      "st", svinval},
  {"hinval.vvma",     MATCH_HINVAL_VVMA,     MASK_HINVAL_VVMA,     "st", svinval},
  {"hinval.gvma",     MATCH_HINVAL_GVMA,     MASK_HINVAL_GVMA,     "st", svinval},
  // f_ext_insns
  {"flw",    MATCH_FLW,    MASK_FLW,    "Do", ext_f},
  {"fsw",    MATCH_FSW,    MASK_FSW,    "Tq", ext_f},
  {"fmv.w.x", MATCH_FMV_W_X, MASK_FMV_W_X, "Ds", ext_f},
  {"fmv.x.w", MATCH_FMV_X_W, MASK_FMV_X_W, "dS", ext_f},
  // f_or_zfinx_insns
  {"fadd.s",    MATCH_FADD_S,    MASK_FADD_S,    "DST", f_or_zfinx},
  {"fsub.s",    MATCH_FSUB_S,    MASK_FSUB_S,    "DST", f_or_zfinx},
  {"fmul.s",    MATCH_FMUL_S,    MASK_FMUL_S,    "DST", f_or_zfinx},
  {"fdiv.s",    MATCH_FDIV_S,    MASK_FDIV_S,    "DST", f_or_zfinx},
  {"fsqrt.s",   MATCH_FSQRT_S,   MASK_FSQRT_S,   "DS", f_or_zfinx},
  {"fmin.s",    MATCH_FMIN_S,    MASK_FMIN_S,    "DST", f_or_zfinx},
  {"fmax.s",    MATCH_FMAX_S,    MASK_FMAX_S,    "DST", f_or_zfinx},
  {"fmadd.s",   MATCH_FMADD_S,   MASK_FMADD_S,   "DSTR", f_or_zfinx},
  {"fmsub.s",   MATCH_FMSUB_S,   MASK_FMSUB_S,   "DSTR", f_or_zfinx},
  {"fnmadd.s",  MATCH_FNMADD_S,  MASK_FNMADD_S,  "DSTR", f_or_zfinx},
  {"fnmsub.s",  MATCH_FNMSUB_S,  MASK_FNMSUB_S,  "DSTR", f_or_zfinx},
  {"fsgnj.s",   MATCH_FSGNJ_S,   MASK_FSGNJ_S,   "DST", f_or_zfinx},
  {"fsgnjn.s",  MATCH_FSGNJN_S,  MASK_FSGNJN_S,  "DST", f_or_zfinx},
  {"fsgnjx.s",  MATCH_FSGNJX_S,  MASK_FSGNJX_S,  "DST", f_or_zfinx},
  {"fcvt.s.d",  MATCH_FCVT_S_D,  MASK_FCVT_S_D,  "DS", f_or_zfinx},
  {"fcvt.s.q",  MATCH_FCVT_S_Q,  MASK_FCVT_S_Q,  "DS", f_or_zfinx},
  {"fcvt.s.w",  MATCH_FCVT_S_W,  MASK_FCVT_S_W,  "Ds", f_or_zfinx},
  {"fcvt.s.wu", MATCH_FCVT_S_WU, MASK_FCVT_S_WU, "Ds", f_or_zfinx},
  {"fcvt.w.s",  MATCH_FCVT_W_S,  MASK_FCVT_W_S,  "dS", f_or_zfinx},
  {"fcvt.wu.s", MATCH_FCVT_WU_S, MASK_FCVT_WU_S, "dS", f_or_zfinx},
  {"fclass.s",  MATCH_FCLASS_S,  MASK_FCLASS_S,  "dS", f_or_zfinx},
  {"feq.s",     MATCH_FEQ_S,     MASK_FEQ_S,     "dST", f_or_zfinx},
  {"flt.s",     MATCH_FLT_S,     MASK_FLT_S,     "dST", f_or_zfinx},
  {"fle.s",     MATCH_FLE_S,     MASK_FLE_S,     "dST", f_or_zfinx},
  // f_or_zfinx64_insns
  {"fcvt.s.l",  MATCH_FCVT_S_L,  MASK_FCVT_S_L,  "Ds", f_or_zfinx_rv64},
  {"fcvt.s.lu", MATCH_FCVT_S_LU, MASK_FCVT_S_LU, "Ds", f_or_zfinx_rv64},
  {"fcvt.l.s",  MATCH_FCVT_L_S,  MASK_FCVT_L_S,  "dS", f_or_zfinx_rv64},
  {"fcvt.lu.s", MATCH_FCVT_LU_S, MASK_FCVT_LU_S, "dS", f_or_zfinx_rv64},
  // d_ext_insns
  {"fld", MATCH_FLD, MASK_FLD, "Do", ext_d},
  {"fsd", MATCH_FSD, MASK_FSD, "Tq", ext_d},
  // d_ext64_insns
  {"fmv.d.x", MATCH_FMV_D_X, MASK_FMV_D_X, "Ds", d_rv64},
  {"fmv.x.d", MATCH_FMV_X_D, MASK_FMV_X_D, "dS", d_rv64},
  // d_or_zdinx_insns
  {"fadd.d",    MATCH_FADD_D,    MASK_FADD_D,    "DST", d_or_zdinx},
  {"fsub.d",    MATCH_FSUB_D,    MASK_FSUB_D,    "DST", d_or_zdinx},
  {"fmul.d",    MATCH_FMUL_D,    MASK_FMUL_D,    "DST", d_or_zdinx},
  {"fdiv.d",    MATCH_FDIV_D,    MASK_FDIV_D,    "DST", d_or_zdinx},
  {"fsqrt.d",   MATCH_FSQRT_D,   MASK_FSQRT_D,   "DS", d_or_zdinx},
  {"fmin.d",    MATCH_FMIN_D,    MASK_FMIN_D,    "DST", d_or_zdinx},
  {"fmax.d",    MATCH_FMAX_D,    MASK_FMAX_D,    "DST", d_or_zdinx},
  {"fmadd.d",   MATCH_FMADD_D,   MASK_FMADD_D,   "DSTR", d_or_zdinx},
  {"fmsub.d",   MATCH_FMSUB_D,   MASK_FMSUB_D,   "DSTR", d_or_zdinx},
  {"fnmadd.d",  MATCH_FNMADD_D,  MASK_FNMADD_D,  "DSTR", d_or_zdinx},
  {"fnmsub.d",  MATCH_FNMSUB_D,  MASK_FNMSUB_D,  "DSTR", d_or_zdinx},
  {"fsgnj.d",   MATCH_FSGNJ_D,   MASK_FSGNJ_D,   "DST", d_or_zdinx},
  {"fsgnjn.d",  MATCH_FSGNJN_D,  MASK_FSGNJN_D,  "DST", d_or_zdinx},
  {"fsgnjx.d",  MATCH_FSGNJX_D,  MASK_FSGNJX_D,  "DST", d_or_zdinx},
  {"fcvt.d.s",  MATCH_FCVT_D_S,  MASK_FCVT_D_S,  "DS", d_or_zdinx},
  {"fcvt.d.q",  MATCH_FCVT_D_Q,  MASK_FCVT_D_Q,  "DS", d_or_zdinx},
  {"fcvt.d.w",  MATCH_FCVT_D_W,  MASK_FCVT_D_W,  "Ds", d_or_zdinx},
  {"fcvt.d.wu", MATCH_FCVT_D_WU, MASK_FCVT_D_WU, "Ds", d_or_zdinx},
  {"fcvt.w.d",  MATCH_FCVT_W_D,  MASK_FCVT_W_D,  "dS", d_or_zdinx},
  {"fcvt.wu.d", MATCH_FCVT_WU_D, MASK_FCVT_WU_D, "dS", d_or_zdinx},
  {"fclass.d",  MATCH_FCLASS_D,  MASK_FCLASS_D,  "dS", d_or_zdinx},
  {"feq.d",     MATCH_FEQ_D,     MASK_FEQ_D,     "dST", d_or_zdinx},
  {"flt.d",     MATCH_FLT_D,     MASK_FLT_D,     "dST", d_or_zdinx},
  {"fle.d",     MATCH_FLE_D,     MASK_FLE_D,     "dST", d_or_zdinx},
  // d_or_zdinx64_insns
  {"fcvt.d.l",  MATCH_FCVT_D_L,  MASK_FCVT_D_L,  "Ds", d_or_zdinx_rv64},
  {"fcvt.d.lu", MATCH_FCVT_D_LU, MASK_FCVT_D_LU, "Ds", d_or_zdinx_rv64},
  {"fcvt.l.d",  MATCH_FCVT_L_D,  MASK_FCVT_L_D,  "dS", d_or_zdinx_rv64},
  {"fcvt.lu.d", MATCH_FCVT_LU_D, MASK_FCVT_LU_D, "dS", d_or_zdinx_rv64},
  // zfa_insns
  {"fli.s",    MATCH_FLI_S,    MASK_FLI_S,    "dL", zfa},
  {"fminm.s",  MATCH_FMINM_S,  MASK_FMINM_S,  "DST", zfa},
  {"fmaxm.s",  MATCH_FMAXM_S,  MASK_FMAXM_S,  "DST", zfa},
  {"fround.s",   MATCH_FROUND_S,   MASK_FROUND_S,   "DS", zfa},
  {"froundnx.s", MATCH_FROUNDNX_S, MASK_FROUNDNX_S, "DS", zfa},
  {"fleq.s",   MATCH_FLEQ_S,   MASK_FLEQ_S,   "dST", zfa},
  {"fltq.s",   MATCH_FLTQ_S,   MASK_FLTQ_S,   "dST", zfa},
  // zfa_zfh_insns
  {"fli.h",    MATCH_FLI_H,    MASK_FLI_H,    "dL", zfa_zfh},
  {"fminm.h",  MATCH_FMINM_H,  MASK_FMINM_H,  "DST", zfa_zfh},
  {"fmaxm.h",  MATCH_FMAXM_H,  MASK_FMAXM_H,  "DST", zfa_zfh},
  {"fround.h",   MATCH_FROUND_H,   MASK_FROUND_H,   "DS", zfa_zfh},
  {"froundnx.h", MATCH_FROUNDNX_H, MASK_FROUNDNX_H, "DS", zfa_zfh},
  {"fleq.h",   MATCH_FLEQ_H,   MASK_FLEQ_H,   "dST", zfa_zfh},
  {"fltq.h",   MATCH_FLTQ_H,   MASK_FLTQ_H,   "dST", zfa_zfh},
  // zfa_d_insns
  {"fli.d",      MATCH_FLI_D,      MASK_FLI_D,      "dL", zfa_d},
  {"fminm.d",    MATCH_FMINM_D,    MASK_FMINM_D,    "DST", zfa_d},
  {"fmaxm.d",    MATCH_FMAXM_D,    MASK_FMAXM_D,    "DST", zfa_d},
  {"fround.d",   MATCH_FROUND_D,   MASK_FROUND_D,   "DS", zfa_d},
  {"froundnx.d", MATCH_FROUNDNX_D, MASK_FROUNDNX_D, "DS", zfa_d},
  {"fleq.d",     MATCH_FLEQ_D,     MASK_FLEQ_D,     "dST", zfa_d},
  {"fltq.d",     MATCH_FLTQ_D,     MASK_FLTQ_D,     "dST", zfa_d},
  {"fcvtmod.w.d",MATCH_FCVTMOD_W_D,MASK_FCVTMOD_W_D,"dSm", zfa_d},
  // zfa_d32_insns
  {"fmvp.d.x", MATCH_FMVP_D_X, MASK_FMVP_D_X, "Dst", zfa_d_rv32},
  {"fmvh.x.d", MATCH_FMVH_X_D, MASK_FMVH_X_D, "dS", zfa_d_rv32},
  // zfa_q_insns
  {"fli.q",      MATCH_FLI_Q,      MASK_FLI_Q,      "dL", zfa_q},
  {"fminm.q",    MATCH_FMINM_Q,    MASK_FMINM_Q,    "DST", zfa_q},
  {"fmaxm.q",    MATCH_FMAXM_Q,    MASK_FMAXM_Q,    "DST", zfa_q},
  {"fround.q",   MATCH_FROUND_Q,   MASK_FROUND_Q,   "DS", zfa_q},
  {"froundnx.q", MATCH_FROUNDNX_Q, MASK_FROUNDNX_Q, "DS", zfa_q},
  {"fleq.q",     MATCH_FLEQ_Q,     MASK_FLEQ_Q,     "dST", zfa_q},
  {"fltq.q",     MATCH_FLTQ_Q,     MASK_FLTQ_Q,     "dST", zfa_q},
  // zfa_q64_insns
  {"fmvp.q.x", MATCH_FMVP_Q_X, MASK_FMVP_Q_X, "Dst", zfa_q_rv64},
  {"fmvh.x.q", MATCH_FMVH_X_Q, MASK_FMVH_X_Q, "dS", zfa_q_rv64},
  // zfh_insns
  {"fadd.h",    MATCH_FADD_H,    MASK_FADD_H,    "DST", zfh},
  {"fsub.h",    MATCH_FSUB_H,    MASK_FSUB_H,    "DST", zfh},
  {"fmul.h",    MATCH_FMUL_H,    MASK_FMUL_H,    "DST", zfh},
  {"fdiv.h",    MATCH_FDIV_H,    MASK_FDIV_H,    "DST", zfh},
  {"fsqrt.h",   MATCH_FSQRT_H,   MASK_FSQRT_H,   "DS", zfh},
  {"fmin.h",    MATCH_FMIN_H,    MASK_FMIN_H,    "DST", zfh},
  {"fmax.h",    MATCH_FMAX_H,    MASK_FMAX_H,    "DST", zfh},
  {"fmadd.h",   MATCH_FMADD_H,   MASK_FMADD_H,   "DSTR", zfh},
  {"fmsub.h",   MATCH_FMSUB_H,   MASK_FMSUB_H,   "DSTR", zfh},
  {"fnmadd.h",  MATCH_FNMADD_H,  MASK_FNMADD_H,  "DSTR", zfh},
  {"fnmsub.h",  MATCH_FNMSUB_H,  MASK_FNMSUB_H,  "DSTR", zfh},
  {"fsgnj.h",   MATCH_FSGNJ_H,   MASK_FSGNJ_H,   "DST", zfh},
  {"fsgnjn.h",  MATCH_FSGNJN_H,  MASK_FSGNJN_H,  "DST", zfh},
  {"fsgnjx.h",  MATCH_FSGNJX_H,  MASK_FSGNJX_H,  "DST", zfh},
  {"fcvt.h.l",  MATCH_FCVT_H_L,  MASK_FCVT_H_L,  "Ds", zfh},
  {"fcvt.h.lu", MATCH_FCVT_H_LU, MASK_FCVT_H_LU, "Ds", zfh},
  {"fcvt.h.w",  MATCH_FCVT_H_W,  MASK_FCVT_H_W,  "Ds", zfh},
  {"fcvt.h.wu", MATCH_FCVT_H_WU, MASK_FCVT_H_WU, "Ds", zfh},
  {"fcvt.l.h",  MATCH_FCVT_L_H,  MASK_FCVT_L_H,  "dS", zfh},
  {"fcvt.lu.h", MATCH_FCVT_LU_H, MASK_FCVT_LU_H, "dS", zfh},
  {"fcvt.w.h",  MATCH_FCVT_W_H,  MASK_FCVT_W_H,  "dS", zfh},
  {"fcvt.wu.h", MATCH_FCVT_WU_H, MASK_FCVT_WU_H, "dS", zfh},
  {"fclass.h",  MATCH_FCLASS_H,  MASK_FCLASS_H,  "dS", zfh},
  {"feq.h",     MATCH_FEQ_H,     MASK_FEQ_H,     "dST", zfh},
  {"flt.h",     MATCH_FLT_H,     MASK_FLT_H,     "dST", zfh},
  {"fle.h",     MATCH_FLE_H,     MASK_FLE_H,     "dST", zfh},
  // zhinx_insns
  {"fadd.h",    MATCH_FADD_H,    MASK_FADD_H,    "dst", zhinx},
  {"fsub.h",    MATCH_FSUB_H,    MASK_FSUB_H,    "dst", zhinx},
  {"fmul.h",    MATCH_FMUL_H,    MASK_FMUL_H,    "dst", zhinx},
  {"fdiv.h",    MATCH_FDIV_H,    MASK_FDIV_H,    "dst", zhinx},
  {"fsqrt.h",   MATCH_FSQRT_H,   MASK_FSQRT_H,   "ds", zhinx},
  {"fmin.h",    MATCH_FMIN_H,    MASK_FMIN_H,    "dst", zhinx},
  {"fmax.h",    MATCH_FMAX_H,    MASK_FMAX_H,    "dst", zhinx},
  {"fmadd.h",   MATCH_FMADD_H,   MASK_FMADD_H,   "dstr", zhinx},
  {"fmsub.h",   MATCH_FMSUB_H,   MASK_FMSUB_H,   "dstr", zhinx},
  {"fnmadd.h",  MATCH_FNMADD_H,  MASK_FNMADD_H,  "dstr", zhinx},
  {"fnmsub.h",  MATCH_FNMSUB_H,  MASK_FNMSUB_H,  "dstr", zhinx},
  {"fsgnj.h",   MATCH_FSGNJ_H,   MASK_FSGNJ_H,   "dst", zhinx},
  {"fsgnjn.h",  MATCH_FSGNJN_H,  MASK_FSGNJN_H,  "dst", zhinx},
  {"fsgnjx.h",  MATCH_FSGNJX_H,  MASK_FSGNJX_H,  "dst", zhinx},
  {"fcvt.h.l",  MATCH_FCVT_H_L,  MASK_FCVT_H_L,  "ds", zhinx},
  {"fcvt.h.lu", MATCH_FCVT_H_LU, MASK_FCVT_H_LU, "ds", zhinx},
  {"fcvt.h.w",  MATCH_FCVT_H_W,  MASK_FCVT_H_W,  "ds", zhinx},
  {"fcvt.h.wu", MATCH_FCVT_H_WU, MASK_FCVT_H_WU, "ds", zhinx},
  {"fcvt.l.h",  MATCH_FCVT_L_H,  MASK_FCVT_L_H,  "ds", zhinx},
  {"fcvt.lu.h", MATCH_FCVT_LU_H, MASK_FCVT_LU_H, "ds", zhinx},
  {"fcvt.w.h",  MATCH_FCVT_W_H,  MASK_FCVT_W_H,  "ds", zhinx},
  {"fcvt.wu.h", MATCH_FCVT_WU_H, MASK_FCVT_WU_H, "ds", zhinx},
  {"fclass.h",  MATCH_FCLASS_H,  MASK_FCLASS_H,  "ds", zhinx},
  {"feq.h",     MATCH_FEQ_H,     MASK_FEQ_H,     "dst", zhinx},
  {"flt.h",     MATCH_FLT_H,     MASK_FLT_H,     "dst", zhinx},
  {"fle.h",     MATCH_FLE_H,     MASK_FLE_H,     "dst", zhinx},
  // zfhmin_insns
  {"fcvt.h.s", MATCH_FCVT_H_S, MASK_FCVT_H_S, "DS", zfhmin},
  {"fcvt.h.d", MATCH_FCVT_H_D, MASK_FCVT_H_D, "DS", zfhmin},
  {"fcvt.h.q", MATCH_FCVT_H_Q, MASK_FCVT_H_Q, "DS", zfhmin},
  {"fcvt.s.h", MATCH_FCVT_S_H, MASK_FCVT_S_H, "DS", zfhmin},
  {"fcvt.d.h", MATCH_FCVT_D_H, MASK_FCVT_D_H, "DS", zfhmin},
  {"fcvt.q.h", MATCH_FCVT_Q_H, MASK_FCVT_Q_H, "DS", zfhmin},
  // zfh_move_insns
  {"flh",    MATCH_FLH,    MASK_FLH,    "Do", zfh_move},
  {"fsh",    MATCH_FSH,    MASK_FSH,    "Tq", zfh_move},
  {"fmv.h.x", MATCH_FMV_H_X, MASK_FMV_H_X, "Ds", zfh_move},
  {"fmv.x.h", MATCH_FMV_X_H, MASK_FMV_X_H, "dS", zfh_move},
  // zhinxmin_insns
  {"fcvt.h.s", MATCH_FCVT_H_S, MASK_FCVT_H_S, "ds", zhinxmin},
  {"fcvt.h.d", MATCH_FCVT_H_D, MASK_FCVT_H_D, "ds", zhinxmin},
  {"fcvt.s.h", MATCH_FCVT_S_H, MASK_FCVT_S_H, "ds", zhinxmin},
  {"fcvt.d.h", MATCH_FCVT_D_H, MASK_FCVT_D_H, "ds", zhinxmin},
  // zibi_insns
  {"beqi", MATCH_BEQI, MASK_BEQI, "s>p", zibi},
  {"bnei", MATCH_BNEI, MASK_BNEI, "s>p", zibi},
  // q_ext_insns
  {"flq", MATCH_FLQ, MASK_FLQ, "Do", ext_q},
  {"fsq", MATCH_FSQ, MASK_FSQ, "Tq", ext_q},
  {"fadd.q",    MATCH_FADD_Q,    MASK_FADD_Q,    "DST", ext_q},
  {"fsub.q",    MATCH_FSUB_Q,    MASK_FSUB_Q,    "DST", ext_q},
  {"fmul.q",    MATCH_FMUL_Q,    MASK_FMUL_Q,    "DST", ext_q},
  {"fdiv.q",    MATCH_FDIV_Q,    MASK_FDIV_Q,    "DST", ext_q},
  {"fsqrt.q",   MATCH_FSQRT_Q,   MASK_FSQRT_Q,   "DS", ext_q},
  {"fmin.q",    MATCH_FMIN_Q,    MASK_FMIN_Q,    "DST", ext_q},
  {"fmax.q",    MATCH_FMAX_Q,    MASK_FMAX_Q,    "DST", ext_q},
  {"fmadd.q",   MATCH_FMADD_Q,   MASK_FMADD_Q,   "DSTR", ext_q},
  {"fmsub.q",   MATCH_FMSUB_Q,   MASK_FMSUB_Q,   "DSTR", ext_q},
  {"fnmadd.q",  MATCH_FNMADD_Q,  MASK_FNMADD_Q,  "DSTR", ext_q},
  {"fnmsub.q",  MATCH_FNMSUB_Q,  MASK_FNMSUB_Q,  "DSTR", ext_q},
  {"fsgnj.q",   MATCH_FSGNJ_Q,   MASK_FSGNJ_Q,   "DST", ext_q},
  {"fsgnjn.q",  MATCH_FSGNJN_Q,  MASK_FSGNJN_Q,  "DST", ext_q},
  {"fsgnjx.q",  MATCH_FSGNJX_Q,  MASK_FSGNJX_Q,  "DST", ext_q},
  {"fcvt.q.s",  MATCH_FCVT_Q_S,  MASK_FCVT_Q_S,  "DS", ext_q},
  {"fcvt.q.d",  MATCH_FCVT_Q_D,  MASK_FCVT_Q_D,  "DS", ext_q},
  {"fcvt.q.l",  MATCH_FCVT_Q_L,  MASK_FCVT_Q_L,  "Ds", ext_q},
  {"fcvt.q.lu", MATCH_FCVT_Q_LU, MASK_FCVT_Q_LU, "Ds", ext_q},
  {"fcvt.q.w",  MATCH_FCVT_Q_W,  MASK_FCVT_Q_W,  "Ds", ext_q},
  {"fcvt.q.wu", MATCH_FCVT_Q_WU, MASK_FCVT_Q_WU, "Ds", ext_q},
  {"fcvt.l.q",  MATCH_FCVT_L_Q,  MASK_FCVT_L_Q,  "dS", ext_q},
  {"fcvt.lu.q", MATCH_FCVT_LU_Q, MASK_FCVT_LU_Q, "dS", ext_q},
  {"fcvt.w.q",  MATCH_FCVT_W_Q,  MASK_FCVT_W_Q,  "dS", ext_q},
  {"fcvt.wu.q", MATCH_FCVT_WU_Q, MASK_FCVT_WU_Q, "dS", ext_q},
  {"fclass.q",  MATCH_FCLASS_Q,  MASK_FCLASS_Q,  "dS", ext_q},
  {"feq.q",     MATCH_FEQ_Q,     MASK_FEQ_Q,     "dST", ext_q},
  {"flt.q",     MATCH_FLT_Q,     MASK_FLT_Q,     "dST", ext_q},
  {"fle.q",     MATCH_FLE_Q,     MASK_FLE_Q,     "dST", ext_q},
  // zfbfmin_insns
  {"fcvt.bf16.s", MATCH_FCVT_BF16_S, MASK_FCVT_BF16_S, "DS", zfbfmin},
  {"fcvt.s.bf16", MATCH_FCVT_S_BF16, MASK_FCVT_S_BF16, "DS", zfbfmin},
  // h_ext_insns
  {"hlv.b",   MATCH_HLV_B,   MASK_HLV_B,   "d(", ext_h},
  {"hlv.bu",  MATCH_HLV_BU,  MASK_HLV_BU,  "d(", ext_h},
  {"hlv.h",   MATCH_HLV_H,   MASK_HLV_H,   "d(", ext_h},
  {"hlv.hu",  MATCH_HLV_HU,  MASK_HLV_HU,  "d(", ext_h},
  {"hlv.w",   MATCH_HLV_W,   MASK_HLV_W,   "d(", ext_h},
  {"hlv.wu",  MATCH_HLV_WU,  MASK_HLV_WU,  "d(", ext_h},
  {"hlv.d",   MATCH_HLV_D,   MASK_HLV_D,   "d(", ext_h},
  {"hlvx.hu", MATCH_HLVX_HU, MASK_HLVX_HU, "d(", ext_h},
  {"hlvx.wu", MATCH_HLVX_WU, MASK_HLVX_WU, "d(", ext_h},
  {"hsv.b",   MATCH_HSV_B,   MASK_HSV_B,   "t(", ext_h},
  {"hsv.h",   MATCH_HSV_H,   MASK_HSV_H,   "t(", ext_h},
  {"hsv.w",   MATCH_HSV_W,   MASK_HSV_W,   "t(", ext_h},
  {"hsv.d",   MATCH_HSV_D,   MASK_HSV_D,   "t(", ext_h},
  {"hfence.gvma", MATCH_HFENCE_GVMA, MASK_HFENCE_GVMA, "st", ext_h},
  {"hfence.vvma", MATCH_HFENCE_VVMA, MASK_HFENCE_VVMA, "st", ext_h},
  // zca_insns
  {"c.ebreak",   MATCH_C_ADD,  MASK_C_ADD | 0xf80u | 0x7cu,         "", zca},
  {"ret",        MATCH_C_JR  | 0x80u, MASK_C_JR | 0xf80u | 0x107cu, "", zca},
  {"c.jr",       MATCH_C_JR,   MASK_C_JR  | 0x107cu,                "e", zca},
  {"c.jalr",     MATCH_C_JALR, MASK_C_JALR | 0x107cu,               "e", zca},
  {"c.nop",      MATCH_C_ADDI, MASK_C_ADDI | 0xf80u | 0x107cu,      "", zca},
  {"c.addi16sp", MATCH_C_ADDI16SP, MASK_C_ADDI16SP | 0xf80u,        "Nx", zca},
  {"c.addi4spn", MATCH_C_ADDI4SPN, MASK_C_ADDI4SPN,                 "JNn", zca},
  {"c.li",       MATCH_C_LI,   MASK_C_LI,   "di", zca},
  {"c.lui",      MATCH_C_LUI,  MASK_C_LUI,  "db", zca},
  {"c.addi",     MATCH_C_ADDI, MASK_C_ADDI, "di", zca},
  {"c.slli",     MATCH_C_SLLI, MASK_C_SLLI, "eh", zca},
  {"c.srli",     MATCH_C_SRLI, MASK_C_SRLI, "Hh", zca},
  {"c.srai",     MATCH_C_SRAI, MASK_C_SRAI, "Hh", zca},
  {"c.andi",     MATCH_C_ANDI, MASK_C_ANDI, "Hi", zca},
  {"c.mv",       MATCH_C_MV,   MASK_C_MV,   "df", zca},
  {"c.add",      MATCH_C_ADD,  MASK_C_ADD,  "df", zca},
  {"c.sub",      MATCH_C_SUB,  MASK_C_SUB,  "HJ", zca},
  {"c.and",      MATCH_C_AND,  MASK_C_AND,  "HJ", zca},
  {"c.or",       MATCH_C_OR,   MASK_C_OR,   "HJ", zca},
  {"c.xor",      MATCH_C_XOR,  MASK_C_XOR,  "HJ", zca},
  {"c.lwsp",     MATCH_C_LWSP, MASK_C_LWSP, "d@", zca},
  {"c.swsp",     MATCH_C_SWSP, MASK_C_SWSP, "f_", zca},
  {"c.lw",       MATCH_C_LW,   MASK_C_LW,   "Jc", zca},
  {"c.sw",       MATCH_C_SW,   MASK_C_SW,   "Jc", zca},
  {"c.beqz",     MATCH_C_BEQZ, MASK_C_BEQZ, "Hy", zca},
  {"c.bnez",     MATCH_C_BNEZ, MASK_C_BNEZ, "Hy", zca},
  {"c.j",        MATCH_C_J,    MASK_C_J,    "w", zca},
  // zca32_insns
  {"c.jal", MATCH_C_JAL, MASK_C_JAL, "w", zca_rv32},
  // zca_not32_insns
  {"c.addiw", MATCH_C_ADDIW, MASK_C_ADDIW, "di", zca_not_rv32},
  // zca64_insns
  {"c.addw", MATCH_C_ADDW, MASK_C_ADDW, "HJ", zca_rv64},
  {"c.subw", MATCH_C_SUBW, MASK_C_SUBW, "HJ", zca_rv64},
  // zca_ld_insns
  {"c.ld",   MATCH_C_LD,   MASK_C_LD,   "Jv", zca_ld},
  {"c.ldsp", MATCH_C_LDSP, MASK_C_LDSP, "dM", zca_ld},
  {"c.sd",   MATCH_C_SD,   MASK_C_SD,   "Jv", zca_ld},
  {"c.sdsp", MATCH_C_SDSP, MASK_C_SDSP, "fg", zca_ld},
  // zcd_insns
  {"c.fld",   MATCH_C_FLD,   MASK_C_FLD,   "#v", zcd},
  {"c.fldsp", MATCH_C_FLDSP, MASK_C_FLDSP, "DM", zcd},
  {"c.fsd",   MATCH_C_FSD,   MASK_C_FSD,   "#v", zcd},
  {"c.fsdsp", MATCH_C_FSDSP, MASK_C_FSDSP, "Fg", zcd},
  // zcf_insns
  {"c.flw",   MATCH_C_FLW,   MASK_C_FLW,   "#c", zcf},
  {"c.flwsp", MATCH_C_FLWSP, MASK_C_FLWSP, "D@", zcf},
  {"c.fsw",   MATCH_C_FSW,   MASK_C_FSW,   "#c", zcf},
  {"c.fswsp", MATCH_C_FSWSP, MASK_C_FSWSP, "F_", zcf},
  // zcb_insns
  {"c.zext.b", MATCH_C_ZEXT_B, MASK_C_ZEXT_B, "H", zcb},
  {"c.sext.b", MATCH_C_SEXT_B, MASK_C_SEXT_B, "H", zcb},
  {"c.zext.h", MATCH_C_ZEXT_H, MASK_C_ZEXT_H, "H", zcb},
  {"c.sext.h", MATCH_C_SEXT_H, MASK_C_SEXT_H, "H", zcb},
  {"c.not",    MATCH_C_NOT,    MASK_C_NOT,    "H", zcb},
  {"c.mul",    MATCH_C_MUL,    MASK_C_MUL,    "HJ", zcb},
  {"c.lbu",    MATCH_C_LBU,    MASK_C_LBU,    "J*", zcb},
  {"c.lhu",    MATCH_C_LHU,    MASK_C_LHU,    "J/", zcb},
  {"c.lh",     MATCH_C_LH,     MASK_C_LH,     "J/", zcb},
  {"c.sb",     MATCH_C_SB,     MASK_C_SB,     "J*", zcb},
  {"c.sh",     MATCH_C_SH,     MASK_C_SH,     "J/", zcb},
  // zcb64_insns
  {"c.zext.w", MATCH_C_ZEXT_W, MASK_C_ZEXT_W, "H", zcb_rv64},
  // zcmp32_insns
  {"cm.push",    MATCH_CM_PUSH,    MASK_CM_PUSH,    "!2", zcmp_rv32},
  {"cm.pop",     MATCH_CM_POP,     MASK_CM_POP,     "!3", zcmp_rv32},
  {"cm.popret",  MATCH_CM_POPRET,  MASK_CM_POPRET,  "!3", zcmp_rv32},
  {"cm.popretz", MATCH_CM_POPRETZ, MASK_CM_POPRETZ, "!3", zcmp_rv32},
  // zcmp64_insns
  {"cm.push",    MATCH_CM_PUSH,    MASK_CM_PUSH,    "!4", zcmp_not_rv32},
  {"cm.pop",     MATCH_CM_POP,     MASK_CM_POP,     "!8", zcmp_not_rv32},
  {"cm.popret",  MATCH_CM_POPRET,  MASK_CM_POPRET,  "!8", zcmp_not_rv32},
  {"cm.popretz", MATCH_CM_POPRETZ, MASK_CM_POPRETZ, "!8", zcmp_not_rv32},
  // zcmp_common_insns
  {"cm.mva01s", MATCH_CM_MVA01S, MASK_CM_MVA01S, "VO", zcmp},
  {"cm.mvsa01", MATCH_CM_MVSA01, MASK_CM_MVSA01, "VO", zcmp},
  // zcmt_insns
  {"cm.jt",   MATCH_CM_JALT, MASK_CM_JALT | 0x380u, "1", zcmt},
  {"cm.jalt", MATCH_CM_JALT, MASK_CM_JALT,           "1", zcmt},
  // zmmul_insns
  {"mul",    MATCH_MUL,    MASK_MUL,    "dst", zmmul},
  {"mulh",   MATCH_MULH,   MASK_MULH,   "dst", zmmul},
  {"mulhu",  MATCH_MULHU,  MASK_MULHU,  "dst", zmmul},
  {"mulhsu", MATCH_MULHSU, MASK_MULHSU, "dst", zmmul},
  // zmmul64_insns
  {"mulw",   MATCH_MULW,   MASK_MULW,   "dst", zmmul_rv64},
  // zicbom_insns
  {"cbo.clean", MATCH_CBO_CLEAN, MASK_CBO_CLEAN, "(", zicbom},
  {"cbo.flush", MATCH_CBO_FLUSH, MASK_CBO_FLUSH, "(", zicbom},
  {"cbo.inval", MATCH_CBO_INVAL, MASK_CBO_INVAL, "(", zicbom},
  // zicboz_insns
  {"cbo.zero",  MATCH_CBO_ZERO,  MASK_CBO_ZERO,  "(", zicboz},
  // zicond_insns
  {"czero.eqz", MATCH_CZERO_EQZ, MASK_CZERO_EQZ, "dst", zicond},
  {"czero.nez", MATCH_CZERO_NEZ, MASK_CZERO_NEZ, "dst", zicond},
  // zknd_zknde_insns
  // aes64ks1i is explicit (has rcon immediate)
  {"aes64ks2", MATCH_AES64KS2, MASK_AES64KS2, "dst", zknd_or_zkne},
  // zknd64_insns
  {"aes64ds",  MATCH_AES64DS,  MASK_AES64DS,  "dst", zknd_rv64},
  {"aes64dsm", MATCH_AES64DSM, MASK_AES64DSM, "dst", zknd_rv64},
  {"aes64im",  MATCH_AES64IM,  MASK_AES64IM,  "ds", zknd_rv64},
  // zkne64_insns
  {"aes64es",  MATCH_AES64ES,  MASK_AES64ES,  "dst", zkne_rv64},
  {"aes64esm", MATCH_AES64ESM, MASK_AES64ESM, "dst", zkne_rv64},
  // zknh_insns
  {"sha256sig0", MATCH_SHA256SIG0, MASK_SHA256SIG0, "ds", zknh},
  {"sha256sig1", MATCH_SHA256SIG1, MASK_SHA256SIG1, "ds", zknh},
  {"sha256sum0", MATCH_SHA256SUM0, MASK_SHA256SUM0, "ds", zknh},
  {"sha256sum1", MATCH_SHA256SUM1, MASK_SHA256SUM1, "ds", zknh},
  // zknh64_insns
  {"sha512sig0", MATCH_SHA512SIG0, MASK_SHA512SIG0, "ds", zknh_rv64},
  {"sha512sig1", MATCH_SHA512SIG1, MASK_SHA512SIG1, "ds", zknh_rv64},
  {"sha512sum0", MATCH_SHA512SUM0, MASK_SHA512SUM0, "ds", zknh_rv64},
  {"sha512sum1", MATCH_SHA512SUM1, MASK_SHA512SUM1, "ds", zknh_rv64},
  // zknh32_insns
  {"sha512sig0h", MATCH_SHA512SIG0H, MASK_SHA512SIG0H, "dst", zknh_rv32},
  {"sha512sig0l", MATCH_SHA512SIG0L, MASK_SHA512SIG0L, "dst", zknh_rv32},
  {"sha512sig1h", MATCH_SHA512SIG1H, MASK_SHA512SIG1H, "dst", zknh_rv32},
  {"sha512sig1l", MATCH_SHA512SIG1L, MASK_SHA512SIG1L, "dst", zknh_rv32},
  {"sha512sum0r", MATCH_SHA512SUM0R, MASK_SHA512SUM0R, "dst", zknh_rv32},
  {"sha512sum1r", MATCH_SHA512SUM1R, MASK_SHA512SUM1R, "dst", zknh_rv32},
  // zksed_insns
  {"sm4ed", MATCH_SM4ED, MASK_SM4ED, "dst-", zksed},
  {"sm4ks", MATCH_SM4KS, MASK_SM4KS, "dst-", zksed},
  // zksh_insns
  {"sm3p0", MATCH_SM3P0, MASK_SM3P0, "ds", zksh},
  {"sm3p1", MATCH_SM3P1, MASK_SM3P1, "ds", zksh},
  // zalasr_insns
  {"lb.aq",  MATCH_LB_AQ,  MASK_LB_AQ,  "d(", zalasr},
  {"lh.aq",  MATCH_LH_AQ,  MASK_LH_AQ,  "d(", zalasr},
  {"lw.aq",  MATCH_LW_AQ,  MASK_LW_AQ,  "d(", zalasr},
  {"ld.aq",  MATCH_LD_AQ,  MASK_LD_AQ,  "d(", zalasr},
  {"sb.rl",  MATCH_SB_RL,  MASK_SB_RL,  "t(", zalasr},
  {"sh.rl",  MATCH_SH_RL,  MASK_SH_RL,  "t(", zalasr},
  {"sw.rl",  MATCH_SW_RL,  MASK_SW_RL,  "t(", zalasr},
  {"sd.rl",  MATCH_SD_RL,  MASK_SD_RL,  "t(", zalasr},
  // zicfiss_insns
  {"sspush",   MATCH_SSPUSH_X1, MASK_SSPUSH_X1, "t", zicfiss},
  {"sspush",   MATCH_SSPUSH_X5, MASK_SSPUSH_X5, "t", zicfiss},
  {"sspopchk", MATCH_SSPOPCHK_X1, MASK_SSPOPCHK_X1, "s", zicfiss},
  {"sspopchk", MATCH_SSPOPCHK_X5, MASK_SSPOPCHK_X5, "s", zicfiss},
  {"ssrdp",    MATCH_SSRDP,    MASK_SSRDP,    "d", zicfiss},
  // zicfiss_zca_insns
  {"c.sspush",   MATCH_C_SSPUSH_X1,   MASK_C_SSPUSH_X1,   "X", zicfiss_zca},
  {"c.sspopchk", MATCH_C_SSPOPCHK_X5, MASK_C_SSPOPCHK_X5, "Y", zicfiss_zca},
  // P-extension
  {"aadd", MATCH_AADD, MASK_AADD, "dst", ext_p_rv32},
  {"aaddu", MATCH_AADDU, MASK_AADDU, "dst", ext_p_rv32},
  {"asub", MATCH_ASUB, MASK_ASUB, "dst", ext_p_rv32},
  {"asubu", MATCH_ASUBU, MASK_ASUBU, "dst", ext_p_rv32},
  {"mseq", MATCH_MSEQ, MASK_MSEQ, "dst", ext_p_rv32},
  {"mslt", MATCH_MSLT, MASK_MSLT, "dst", ext_p_rv32},
  {"msltu", MATCH_MSLTU, MASK_MSLTU, "dst", ext_p_rv32},
  {"addd", MATCH_ADDD, MASK_ADDD, "PQU", ext_p},
  {"subd", MATCH_SUBD, MASK_SUBD, "PQU", ext_p},
  {"merge", MATCH_MERGE, MASK_MERGE, "dst", ext_p},
  {"mvm", MATCH_MVM, MASK_MVM, "dst", ext_p},
  {"mvmn", MATCH_MVMN, MASK_MVMN, "dst", ext_p},
  {"nclip", MATCH_NCLIP, MASK_NCLIP, "dQt", ext_p},
  {"nclipr", MATCH_NCLIPR, MASK_NCLIPR, "dQt", ext_p},
  {"nclipu", MATCH_NCLIPU, MASK_NCLIPU, "dQt", ext_p},
  {"nclipru", MATCH_NCLIPRU, MASK_NCLIPRU, "dQt", ext_p},
  {"nsra", MATCH_NSRA, MASK_NSRA, "dQt", ext_p},
  {"nsrar", MATCH_NSRAR, MASK_NSRAR, "dQt", ext_p},
  {"nsrl", MATCH_NSRL, MASK_NSRL, "dQt", ext_p},
  {"sadd", MATCH_SADD, MASK_SADD, "dst", ext_p_rv32},
  {"saddu", MATCH_SADDU, MASK_SADDU, "dst", ext_p_rv32},
  {"ssub", MATCH_SSUB, MASK_SSUB, "dst", ext_p_rv32},
  {"ssubu", MATCH_SSUBU, MASK_SSUBU, "dst", ext_p_rv32},
  {"ssh1sadd", MATCH_SSH1SADD, MASK_SSH1SADD, "dst", ext_p_rv32},
  {"ssha", MATCH_SSHA, MASK_SSHA, "dst", ext_p_rv32},
  {"sshar", MATCH_SSHAR, MASK_SSHAR, "dst", ext_p_rv32},
  {"sshl", MATCH_SSHL, MASK_SSHL, "dst", ext_p_rv32},
  {"sshlr", MATCH_SSHLR, MASK_SSHLR, "dst", ext_p_rv32},
  {"sha", MATCH_SHA, MASK_SHA, "PQU", ext_p},
  {"shar", MATCH_SHAR, MASK_SHAR, "PQU", ext_p},
  {"slx", MATCH_SLX, MASK_SLX, "dst", ext_p},
  {"srx", MATCH_SRX, MASK_SRX, "dst", ext_p},
  {"wadd", MATCH_WADD, MASK_WADD, "Pst", ext_p},
  {"wadda", MATCH_WADDA, MASK_WADDA, "Pst", ext_p},
  {"waddu", MATCH_WADDU, MASK_WADDU, "Pst", ext_p},
  {"waddau", MATCH_WADDAU, MASK_WADDAU, "Pst", ext_p},
  {"wsub", MATCH_WSUB, MASK_WSUB, "Pst", ext_p},
  {"wsuba", MATCH_WSUBA, MASK_WSUBA, "Pst", ext_p},
  {"wsubu", MATCH_WSUBU, MASK_WSUBU, "Pst", ext_p},
  {"wsubau", MATCH_WSUBAU, MASK_WSUBAU, "Pst", ext_p},
  {"wsll", MATCH_WSLL, MASK_WSLL, "Pst", ext_p},
  {"wsla", MATCH_WSLA, MASK_WSLA, "Pst", ext_p},
  {"wmul", MATCH_WMUL, MASK_WMUL, "Pst", ext_p},
  {"wmulu", MATCH_WMULU, MASK_WMULU, "Pst", ext_p},
  {"wmulsu", MATCH_WMULSU, MASK_WMULSU, "Pst", ext_p},
  {"wmacc", MATCH_WMACC, MASK_WMACC, "Pst", ext_p},
  {"wmaccu", MATCH_WMACCU, MASK_WMACCU, "Pst", ext_p},
  {"wmaccsu", MATCH_WMACCSU, MASK_WMACCSU, "Pst", ext_p},
  {"macc.h00", MATCH_MACC_H00, MASK_MACC_H00, "dst", ext_p_rv32},
  {"macc.h01", MATCH_MACC_H01, MASK_MACC_H01, "dst", ext_p_rv32},
  {"macc.h11", MATCH_MACC_H11, MASK_MACC_H11, "dst", ext_p_rv32},
  {"maccu.h00", MATCH_MACCU_H00, MASK_MACCU_H00, "dst", ext_p_rv32},
  {"maccu.h01", MATCH_MACCU_H01, MASK_MACCU_H01, "dst", ext_p_rv32},
  {"maccu.h11", MATCH_MACCU_H11, MASK_MACCU_H11, "dst", ext_p_rv32},
  {"maccsu.h00", MATCH_MACCSU_H00, MASK_MACCSU_H00, "dst", ext_p_rv32},
  {"maccsu.h11", MATCH_MACCSU_H11, MASK_MACCSU_H11, "dst", ext_p_rv32},
  {"mul.h00", MATCH_MUL_H00, MASK_MUL_H00, "dst", ext_p_rv32},
  {"mul.h01", MATCH_MUL_H01, MASK_MUL_H01, "dst", ext_p_rv32},
  {"mul.h11", MATCH_MUL_H11, MASK_MUL_H11, "dst", ext_p_rv32},
  {"mulu.h00", MATCH_MULU_H00, MASK_MULU_H00, "dst", ext_p_rv32},
  {"mulu.h01", MATCH_MULU_H01, MASK_MULU_H01, "dst", ext_p_rv32},
  {"mulu.h11", MATCH_MULU_H11, MASK_MULU_H11, "dst", ext_p_rv32},
  {"mulsu.h00", MATCH_MULSU_H00, MASK_MULSU_H00, "dst", ext_p_rv32},
  {"mulsu.h11", MATCH_MULSU_H11, MASK_MULSU_H11, "dst", ext_p_rv32},
  {"mulh.h0", MATCH_MULH_H0, MASK_MULH_H0, "dst", ext_p_rv32},
  {"mulh.h1", MATCH_MULH_H1, MASK_MULH_H1, "dst", ext_p_rv32},
  {"mulhsu.h0", MATCH_MULHSU_H0, MASK_MULHSU_H0, "dst", ext_p_rv32},
  {"mulhsu.h1", MATCH_MULHSU_H1, MASK_MULHSU_H1, "dst", ext_p_rv32},
  {"mulhr", MATCH_MULHR, MASK_MULHR, "dst", ext_p_rv32},
  {"mulhru", MATCH_MULHRU, MASK_MULHRU, "dst", ext_p_rv32},
  {"mulhrsu", MATCH_MULHRSU, MASK_MULHRSU, "dst", ext_p_rv32},
  {"mulq", MATCH_MULQ, MASK_MULQ, "dst", ext_p_rv32},
  {"mulqr", MATCH_MULQR, MASK_MULQR, "dst", ext_p_rv32},
  {"mhacc", MATCH_MHACC, MASK_MHACC, "dst", ext_p_rv32},
  {"mhaccu", MATCH_MHACCU, MASK_MHACCU, "dst", ext_p_rv32},
  {"mhaccsu", MATCH_MHACCSU, MASK_MHACCSU, "dst", ext_p_rv32},
  {"mhacc.h0", MATCH_MHACC_H0, MASK_MHACC_H0, "dst", ext_p_rv32},
  {"mhacc.h1", MATCH_MHACC_H1, MASK_MHACC_H1, "dst", ext_p_rv32},
  {"mhaccsu.h0", MATCH_MHACCSU_H0, MASK_MHACCSU_H0, "dst", ext_p_rv32},
  {"mhaccsu.h1", MATCH_MHACCSU_H1, MASK_MHACCSU_H1, "dst", ext_p_rv32},
  {"mhracc", MATCH_MHRACC, MASK_MHRACC, "dst", ext_p_rv32},
  {"mhraccu", MATCH_MHRACCU, MASK_MHRACCU, "dst", ext_p_rv32},
  {"mhraccsu", MATCH_MHRACCSU, MASK_MHRACCSU, "dst", ext_p_rv32},
  {"mqacc.h00", MATCH_MQACC_H00, MASK_MQACC_H00, "dst", ext_p},
  {"mqacc.h01", MATCH_MQACC_H01, MASK_MQACC_H01, "dst", ext_p},
  {"mqacc.h11", MATCH_MQACC_H11, MASK_MQACC_H11, "dst", ext_p},
  {"mqracc.h00", MATCH_MQRACC_H00, MASK_MQRACC_H00, "dst", ext_p},
  {"mqracc.h01", MATCH_MQRACC_H01, MASK_MQRACC_H01, "dst", ext_p},
  {"mqracc.h11", MATCH_MQRACC_H11, MASK_MQRACC_H11, "dst", ext_p},
  {"abs", MATCH_ABS, MASK_ABS, "ds", ext_p},
  {"cls", MATCH_CLS, MASK_CLS, "ds", ext_p},
  {"nclipi", MATCH_NCLIPI, MASK_NCLIPI, "ds'", ext_p},
  {"nclipiu", MATCH_NCLIPIU, MASK_NCLIPIU, "ds'", ext_p},
  {"nclipri", MATCH_NCLIPRI, MASK_NCLIPRI, "ds'", ext_p},
  {"nclipriu", MATCH_NCLIPRIU, MASK_NCLIPRIU, "ds'", ext_p},
  {"nsrai", MATCH_NSRAI, MASK_NSRAI, "ds'", ext_p},
  {"nsrari", MATCH_NSRARI, MASK_NSRARI, "ds'", ext_p},
  {"nsrli", MATCH_NSRLI, MASK_NSRLI, "ds'", ext_p},
  {"sslai", MATCH_SSLAI, MASK_SSLAI, "dsZ", ext_p_rv32},
  {"wslli", MATCH_WSLLI, MASK_WSLLI, "dsZ", ext_p},
  {"wslai", MATCH_WSLAI, MASK_WSLAI, "dsZ", ext_p},
  {"sati", MATCH_SATI, MASK_SATI, "dsZ", ext_p_rv64},
  {"usati", MATCH_USATI, MASK_USATI, "dsZ", ext_p_rv64},
  {"srari", MATCH_SRARI, MASK_SRARI, "dsZ", ext_p_rv64},
  {"sati", MATCH_SATI_RV32, MASK_SATI_RV32, "dsZ", ext_p_rv64},
  {"usati", MATCH_USATI_RV32, MASK_USATI_RV32, "dsZ", ext_p_rv64},
  {"srari", MATCH_SRARI_RV32, MASK_SRARI_RV32, "dsZ", ext_p_rv64},
  {"paadd.b", MATCH_PAADD_B, MASK_PAADD_B, "dst", ext_p},
  {"paadd.h", MATCH_PAADD_H, MASK_PAADD_H, "dst", ext_p},
  {"paadd.db", MATCH_PAADD_DB, MASK_PAADD_DB, "PQU", ext_p},
  {"paadd.dh", MATCH_PAADD_DH, MASK_PAADD_DH, "PQU", ext_p},
  {"paadd.dw", MATCH_PAADD_DW, MASK_PAADD_DW, "PQU", ext_p},
  {"paaddu.b", MATCH_PAADDU_B, MASK_PAADDU_B, "dst", ext_p},
  {"paaddu.h", MATCH_PAADDU_H, MASK_PAADDU_H, "dst", ext_p},
  {"paaddu.db", MATCH_PAADDU_DB, MASK_PAADDU_DB, "PQU", ext_p},
  {"paaddu.dh", MATCH_PAADDU_DH, MASK_PAADDU_DH, "PQU", ext_p},
  {"paaddu.dw", MATCH_PAADDU_DW, MASK_PAADDU_DW, "PQU", ext_p},
  {"paas.hx", MATCH_PAAS_HX, MASK_PAAS_HX, "dst", ext_p},
  {"paas.dhx", MATCH_PAAS_DHX, MASK_PAAS_DHX, "PQU", ext_p},
  {"pabd.b", MATCH_PABD_B, MASK_PABD_B, "dst", ext_p},
  {"pabd.h", MATCH_PABD_H, MASK_PABD_H, "dst", ext_p},
  {"pabd.db", MATCH_PABD_DB, MASK_PABD_DB, "PQU", ext_p},
  {"pabd.dh", MATCH_PABD_DH, MASK_PABD_DH, "PQU", ext_p},
  {"pabdu.b", MATCH_PABDU_B, MASK_PABDU_B, "dst", ext_p},
  {"pabdu.h", MATCH_PABDU_H, MASK_PABDU_H, "dst", ext_p},
  {"pabdu.db", MATCH_PABDU_DB, MASK_PABDU_DB, "PQU", ext_p},
  {"pabdu.dh", MATCH_PABDU_DH, MASK_PABDU_DH, "PQU", ext_p},
  {"pabdsumu.b", MATCH_PABDSUMU_B, MASK_PABDSUMU_B, "dst", ext_p},
  {"pabdsumau.b", MATCH_PABDSUMAU_B, MASK_PABDSUMAU_B, "dst", ext_p},
  {"padd.b", MATCH_PADD_B, MASK_PADD_B, "dst", ext_p},
  {"padd.h", MATCH_PADD_H, MASK_PADD_H, "dst", ext_p},
  {"padd.bs", MATCH_PADD_BS, MASK_PADD_BS, "dst", ext_p},
  {"padd.hs", MATCH_PADD_HS, MASK_PADD_HS, "dst", ext_p},
  {"padd.db", MATCH_PADD_DB, MASK_PADD_DB, "PQU", ext_p},
  {"padd.dh", MATCH_PADD_DH, MASK_PADD_DH, "PQU", ext_p},
  {"padd.dw", MATCH_PADD_DW, MASK_PADD_DW, "PQU", ext_p},
  {"padd.dbs", MATCH_PADD_DBS, MASK_PADD_DBS, "PQt", ext_p},
  {"padd.dhs", MATCH_PADD_DHS, MASK_PADD_DHS, "PQt", ext_p},
  {"padd.dws", MATCH_PADD_DWS, MASK_PADD_DWS, "PQt", ext_p},
  {"pasub.b", MATCH_PASUB_B, MASK_PASUB_B, "dst", ext_p},
  {"pasub.h", MATCH_PASUB_H, MASK_PASUB_H, "dst", ext_p},
  {"pasub.db", MATCH_PASUB_DB, MASK_PASUB_DB, "PQU", ext_p},
  {"pasub.dh", MATCH_PASUB_DH, MASK_PASUB_DH, "PQU", ext_p},
  {"pasub.dw", MATCH_PASUB_DW, MASK_PASUB_DW, "PQU", ext_p},
  {"pasubu.b", MATCH_PASUBU_B, MASK_PASUBU_B, "dst", ext_p},
  {"pasubu.h", MATCH_PASUBU_H, MASK_PASUBU_H, "dst", ext_p},
  {"pasubu.db", MATCH_PASUBU_DB, MASK_PASUBU_DB, "PQU", ext_p},
  {"pasubu.dh", MATCH_PASUBU_DH, MASK_PASUBU_DH, "PQU", ext_p},
  {"pasubu.dw", MATCH_PASUBU_DW, MASK_PASUBU_DW, "PQU", ext_p},
  {"pasa.hx", MATCH_PASA_HX, MASK_PASA_HX, "dst", ext_p},
  {"pasa.dhx", MATCH_PASA_DHX, MASK_PASA_DHX, "PQU", ext_p},
  {"pas.hx", MATCH_PAS_HX, MASK_PAS_HX, "dst", ext_p},
  {"pas.dhx", MATCH_PAS_DHX, MASK_PAS_DHX, "PQU", ext_p},
  {"psadd.b", MATCH_PSADD_B, MASK_PSADD_B, "dst", ext_p},
  {"psadd.h", MATCH_PSADD_H, MASK_PSADD_H, "dst", ext_p},
  {"psadd.db", MATCH_PSADD_DB, MASK_PSADD_DB, "PQU", ext_p},
  {"psadd.dh", MATCH_PSADD_DH, MASK_PSADD_DH, "PQU", ext_p},
  {"psadd.dw", MATCH_PSADD_DW, MASK_PSADD_DW, "PQU", ext_p},
  {"psaddu.b", MATCH_PSADDU_B, MASK_PSADDU_B, "dst", ext_p},
  {"psaddu.h", MATCH_PSADDU_H, MASK_PSADDU_H, "dst", ext_p},
  {"psaddu.db", MATCH_PSADDU_DB, MASK_PSADDU_DB, "PQU", ext_p},
  {"psaddu.dh", MATCH_PSADDU_DH, MASK_PSADDU_DH, "PQU", ext_p},
  {"psaddu.dw", MATCH_PSADDU_DW, MASK_PSADDU_DW, "PQU", ext_p},
  {"psub.b", MATCH_PSUB_B, MASK_PSUB_B, "dst", ext_p},
  {"psub.h", MATCH_PSUB_H, MASK_PSUB_H, "dst", ext_p},
  {"psub.db", MATCH_PSUB_DB, MASK_PSUB_DB, "PQU", ext_p},
  {"psub.dh", MATCH_PSUB_DH, MASK_PSUB_DH, "PQU", ext_p},
  {"psub.dw", MATCH_PSUB_DW, MASK_PSUB_DW, "PQU", ext_p},
  {"pssub.b", MATCH_PSSUB_B, MASK_PSSUB_B, "dst", ext_p},
  {"pssub.h", MATCH_PSSUB_H, MASK_PSSUB_H, "dst", ext_p},
  {"pssub.db", MATCH_PSSUB_DB, MASK_PSSUB_DB, "PQU", ext_p},
  {"pssub.dh", MATCH_PSSUB_DH, MASK_PSSUB_DH, "PQU", ext_p},
  {"pssub.dw", MATCH_PSSUB_DW, MASK_PSSUB_DW, "PQU", ext_p},
  {"pssubu.b", MATCH_PSSUBU_B, MASK_PSSUBU_B, "dst", ext_p},
  {"pssubu.h", MATCH_PSSUBU_H, MASK_PSSUBU_H, "dst", ext_p},
  {"pssubu.db", MATCH_PSSUBU_DB, MASK_PSSUBU_DB, "PQU", ext_p},
  {"pssubu.dh", MATCH_PSSUBU_DH, MASK_PSSUBU_DH, "PQU", ext_p},
  {"pssubu.dw", MATCH_PSSUBU_DW, MASK_PSSUBU_DW, "PQU", ext_p},
  {"psa.hx", MATCH_PSA_HX, MASK_PSA_HX, "dst", ext_p},
  {"psa.dhx", MATCH_PSA_DHX, MASK_PSA_DHX, "PQU", ext_p},
  {"psas.hx", MATCH_PSAS_HX, MASK_PSAS_HX, "dst", ext_p},
  {"psas.dhx", MATCH_PSAS_DHX, MASK_PSAS_DHX, "PQU", ext_p},
  {"pssa.hx", MATCH_PSSA_HX, MASK_PSSA_HX, "dst", ext_p},
  {"pssa.dhx", MATCH_PSSA_DHX, MASK_PSSA_DHX, "PQU", ext_p},
  {"pmax.b", MATCH_PMAX_B, MASK_PMAX_B, "dst", ext_p},
  {"pmax.h", MATCH_PMAX_H, MASK_PMAX_H, "dst", ext_p},
  {"pmax.db", MATCH_PMAX_DB, MASK_PMAX_DB, "PQU", ext_p},
  {"pmax.dh", MATCH_PMAX_DH, MASK_PMAX_DH, "PQU", ext_p},
  {"pmax.dw", MATCH_PMAX_DW, MASK_PMAX_DW, "PQU", ext_p},
  {"pmaxu.b", MATCH_PMAXU_B, MASK_PMAXU_B, "dst", ext_p},
  {"pmaxu.h", MATCH_PMAXU_H, MASK_PMAXU_H, "dst", ext_p},
  {"pmaxu.db", MATCH_PMAXU_DB, MASK_PMAXU_DB, "PQU", ext_p},
  {"pmaxu.dh", MATCH_PMAXU_DH, MASK_PMAXU_DH, "PQU", ext_p},
  {"pmaxu.dw", MATCH_PMAXU_DW, MASK_PMAXU_DW, "PQU", ext_p},
  {"pmin.b", MATCH_PMIN_B, MASK_PMIN_B, "dst", ext_p},
  {"pmin.h", MATCH_PMIN_H, MASK_PMIN_H, "dst", ext_p},
  {"pmin.db", MATCH_PMIN_DB, MASK_PMIN_DB, "PQU", ext_p},
  {"pmin.dh", MATCH_PMIN_DH, MASK_PMIN_DH, "PQU", ext_p},
  {"pmin.dw", MATCH_PMIN_DW, MASK_PMIN_DW, "PQU", ext_p},
  {"pminu.b", MATCH_PMINU_B, MASK_PMINU_B, "dst", ext_p},
  {"pminu.h", MATCH_PMINU_H, MASK_PMINU_H, "dst", ext_p},
  {"pminu.db", MATCH_PMINU_DB, MASK_PMINU_DB, "PQU", ext_p},
  {"pminu.dh", MATCH_PMINU_DH, MASK_PMINU_DH, "PQU", ext_p},
  {"pminu.dw", MATCH_PMINU_DW, MASK_PMINU_DW, "PQU", ext_p},
  {"pmseq.b", MATCH_PMSEQ_B, MASK_PMSEQ_B, "dst", ext_p},
  {"pmseq.h", MATCH_PMSEQ_H, MASK_PMSEQ_H, "dst", ext_p},
  {"pmseq.db", MATCH_PMSEQ_DB, MASK_PMSEQ_DB, "PQU", ext_p},
  {"pmseq.dh", MATCH_PMSEQ_DH, MASK_PMSEQ_DH, "PQU", ext_p},
  {"pmseq.dw", MATCH_PMSEQ_DW, MASK_PMSEQ_DW, "PQU", ext_p},
  {"pmslt.b", MATCH_PMSLT_B, MASK_PMSLT_B, "dst", ext_p},
  {"pmslt.h", MATCH_PMSLT_H, MASK_PMSLT_H, "dst", ext_p},
  {"pmslt.db", MATCH_PMSLT_DB, MASK_PMSLT_DB, "PQU", ext_p},
  {"pmslt.dh", MATCH_PMSLT_DH, MASK_PMSLT_DH, "PQU", ext_p},
  {"pmslt.dw", MATCH_PMSLT_DW, MASK_PMSLT_DW, "PQU", ext_p},
  {"pmsltu.b", MATCH_PMSLTU_B, MASK_PMSLTU_B, "dst", ext_p},
  {"pmsltu.h", MATCH_PMSLTU_H, MASK_PMSLTU_H, "dst", ext_p},
  {"pmsltu.db", MATCH_PMSLTU_DB, MASK_PMSLTU_DB, "PQU", ext_p},
  {"pmsltu.dh", MATCH_PMSLTU_DH, MASK_PMSLTU_DH, "PQU", ext_p},
  {"pmsltu.dw", MATCH_PMSLTU_DW, MASK_PMSLTU_DW, "PQU", ext_p},
  {"psll.bs", MATCH_PSLL_BS, MASK_PSLL_BS, "dst", ext_p},
  {"psll.hs", MATCH_PSLL_HS, MASK_PSLL_HS, "dst", ext_p},
  {"psll.dbs", MATCH_PSLL_DBS, MASK_PSLL_DBS, "PQt", ext_p},
  {"psll.dhs", MATCH_PSLL_DHS, MASK_PSLL_DHS, "PQt", ext_p},
  {"psll.dws", MATCH_PSLL_DWS, MASK_PSLL_DWS, "PQt", ext_p},
  {"psra.bs", MATCH_PSRA_BS, MASK_PSRA_BS, "dst", ext_p},
  {"psra.hs", MATCH_PSRA_HS, MASK_PSRA_HS, "dst", ext_p},
  {"psra.dbs", MATCH_PSRA_DBS, MASK_PSRA_DBS, "PQt", ext_p},
  {"psra.dhs", MATCH_PSRA_DHS, MASK_PSRA_DHS, "PQt", ext_p},
  {"psra.dws", MATCH_PSRA_DWS, MASK_PSRA_DWS, "PQt", ext_p},
  {"psrl.bs", MATCH_PSRL_BS, MASK_PSRL_BS, "dst", ext_p},
  {"psrl.hs", MATCH_PSRL_HS, MASK_PSRL_HS, "dst", ext_p},
  {"psrl.dbs", MATCH_PSRL_DBS, MASK_PSRL_DBS, "PQt", ext_p},
  {"psrl.dhs", MATCH_PSRL_DHS, MASK_PSRL_DHS, "PQt", ext_p},
  {"psrl.dws", MATCH_PSRL_DWS, MASK_PSRL_DWS, "PQt", ext_p},
  {"pssha.hs", MATCH_PSSHA_HS, MASK_PSSHA_HS, "dst", ext_p},
  {"pssha.dhs", MATCH_PSSHA_DHS, MASK_PSSHA_DHS, "PQt", ext_p},
  {"pssha.dws", MATCH_PSSHA_DWS, MASK_PSSHA_DWS, "PQt", ext_p},
  {"psshar.hs", MATCH_PSSHAR_HS, MASK_PSSHAR_HS, "dst", ext_p},
  {"psshar.dhs", MATCH_PSSHAR_DHS, MASK_PSSHAR_DHS, "PQt", ext_p},
  {"psshar.dws", MATCH_PSSHAR_DWS, MASK_PSSHAR_DWS, "PQt", ext_p},
  {"psshl.hs", MATCH_PSSHL_HS, MASK_PSSHL_HS, "dst", ext_p},
  {"psshl.dhs", MATCH_PSSHL_DHS, MASK_PSSHL_DHS, "PQt", ext_p},
  {"psshl.dws", MATCH_PSSHL_DWS, MASK_PSSHL_DWS, "PQt", ext_p},
  {"psshlr.hs", MATCH_PSSHLR_HS, MASK_PSSHLR_HS, "dst", ext_p},
  {"psshlr.dhs", MATCH_PSSHLR_DHS, MASK_PSSHLR_DHS, "PQt", ext_p},
  {"psshlr.dws", MATCH_PSSHLR_DWS, MASK_PSSHLR_DWS, "PQt", ext_p},
  {"psh1add.h", MATCH_PSH1ADD_H, MASK_PSH1ADD_H, "dst", ext_p},
  {"psh1add.dh", MATCH_PSH1ADD_DH, MASK_PSH1ADD_DH, "PQU", ext_p},
  {"psh1add.dw", MATCH_PSH1ADD_DW, MASK_PSH1ADD_DW, "PQU", ext_p},
  {"pssh1sadd.h", MATCH_PSSH1SADD_H, MASK_PSSH1SADD_H, "dst", ext_p},
  {"pssh1sadd.dh", MATCH_PSSH1SADD_DH, MASK_PSSH1SADD_DH, "PQU", ext_p},
  {"pssh1sadd.dw", MATCH_PSSH1SADD_DW, MASK_PSSH1SADD_DW, "PQU", ext_p},
  {"pnclip.bs", MATCH_PNCLIP_BS, MASK_PNCLIP_BS, "dQt", ext_p},
  {"pnclip.hs", MATCH_PNCLIP_HS, MASK_PNCLIP_HS, "dQt", ext_p},
  {"pnclipr.bs", MATCH_PNCLIPR_BS, MASK_PNCLIPR_BS, "dQt", ext_p},
  {"pnclipr.hs", MATCH_PNCLIPR_HS, MASK_PNCLIPR_HS, "dQt", ext_p},
  {"pnclipu.bs", MATCH_PNCLIPU_BS, MASK_PNCLIPU_BS, "dQt", ext_p},
  {"pnclipu.hs", MATCH_PNCLIPU_HS, MASK_PNCLIPU_HS, "dQt", ext_p},
  {"pnclipru.bs", MATCH_PNCLIPRU_BS, MASK_PNCLIPRU_BS, "dQt", ext_p},
  {"pnclipru.hs", MATCH_PNCLIPRU_HS, MASK_PNCLIPRU_HS, "dQt", ext_p},
  {"pnsra.bs", MATCH_PNSRA_BS, MASK_PNSRA_BS, "dQt", ext_p},
  {"pnsra.hs", MATCH_PNSRA_HS, MASK_PNSRA_HS, "dQt", ext_p},
  {"pnsrar.bs", MATCH_PNSRAR_BS, MASK_PNSRAR_BS, "dQt", ext_p},
  {"pnsrar.hs", MATCH_PNSRAR_HS, MASK_PNSRAR_HS, "dQt", ext_p},
  {"pnsrl.bs", MATCH_PNSRL_BS, MASK_PNSRL_BS, "dQt", ext_p},
  {"pnsrl.hs", MATCH_PNSRL_HS, MASK_PNSRL_HS, "dQt", ext_p},
  {"pwsll.bs", MATCH_PWSLL_BS, MASK_PWSLL_BS, "Pst", ext_p},
  {"pwsll.hs", MATCH_PWSLL_HS, MASK_PWSLL_HS, "Pst", ext_p},
  {"pwsla.bs", MATCH_PWSLA_BS, MASK_PWSLA_BS, "Pst", ext_p},
  {"pwsla.hs", MATCH_PWSLA_HS, MASK_PWSLA_HS, "Pst", ext_p},
  {"ppaire.b", MATCH_PPAIRE_B, MASK_PPAIRE_B, "dst", ext_p},
  {"ppaire.h", MATCH_PPAIRE_H, MASK_PPAIRE_H, "dst", ext_p},
  {"ppaire.db", MATCH_PPAIRE_DB, MASK_PPAIRE_DB, "PQU", ext_p},
  {"ppaire.dh", MATCH_PPAIRE_DH, MASK_PPAIRE_DH, "PQU", ext_p},
  {"ppaireo.b", MATCH_PPAIREO_B, MASK_PPAIREO_B, "dst", ext_p},
  {"ppaireo.h", MATCH_PPAIREO_H, MASK_PPAIREO_H, "dst", ext_p},
  {"ppaireo.db", MATCH_PPAIREO_DB, MASK_PPAIREO_DB, "PQU", ext_p},
  {"ppaireo.dh", MATCH_PPAIREO_DH, MASK_PPAIREO_DH, "PQU", ext_p},
  {"ppairo.b", MATCH_PPAIRO_B, MASK_PPAIRO_B, "dst", ext_p},
  {"ppairo.h", MATCH_PPAIRO_H, MASK_PPAIRO_H, "dst", ext_p},
  {"ppairo.db", MATCH_PPAIRO_DB, MASK_PPAIRO_DB, "PQU", ext_p},
  {"ppairo.dh", MATCH_PPAIRO_DH, MASK_PPAIRO_DH, "PQU", ext_p},
  {"ppairoe.b", MATCH_PPAIROE_B, MASK_PPAIROE_B, "dst", ext_p},
  {"ppairoe.h", MATCH_PPAIROE_H, MASK_PPAIROE_H, "dst", ext_p},
  {"ppairoe.db", MATCH_PPAIROE_DB, MASK_PPAIROE_DB, "PQU", ext_p},
  {"ppairoe.dh", MATCH_PPAIROE_DH, MASK_PPAIROE_DH, "PQU", ext_p},
  {"predsum.bs", MATCH_PREDSUM_BS, MASK_PREDSUM_BS, "dst", ext_p},
  {"predsum.hs", MATCH_PREDSUM_HS, MASK_PREDSUM_HS, "dst", ext_p},
  {"predsum.dbs", MATCH_PREDSUM_DBS, MASK_PREDSUM_DBS, "dQt", ext_p},
  {"predsum.dhs", MATCH_PREDSUM_DHS, MASK_PREDSUM_DHS, "dQt", ext_p},
  {"predsumu.bs", MATCH_PREDSUMU_BS, MASK_PREDSUMU_BS, "dst", ext_p},
  {"predsumu.hs", MATCH_PREDSUMU_HS, MASK_PREDSUMU_HS, "dst", ext_p},
  {"predsumu.dbs", MATCH_PREDSUMU_DBS, MASK_PREDSUMU_DBS, "dQt", ext_p},
  {"predsumu.dhs", MATCH_PREDSUMU_DHS, MASK_PREDSUMU_DHS, "dQt", ext_p},
  {"psabs.b", MATCH_PSABS_B, MASK_PSABS_B, "ds", ext_p},
  {"psabs.h", MATCH_PSABS_H, MASK_PSABS_H, "ds", ext_p},
  {"psabs.db", MATCH_PSABS_DB, MASK_PSABS_DB, "PQ", ext_p},
  {"psabs.dh", MATCH_PSABS_DH, MASK_PSABS_DH, "PQ", ext_p},
  {"psext.h.b", MATCH_PSEXT_H_B, MASK_PSEXT_H_B, "ds", ext_p},
  {"psext.dh.b", MATCH_PSEXT_DH_B, MASK_PSEXT_DH_B, "PQ", ext_p},
  {"psext.dw.b", MATCH_PSEXT_DW_B, MASK_PSEXT_DW_B, "PQ", ext_p},
  {"psext.dw.h", MATCH_PSEXT_DW_H, MASK_PSEXT_DW_H, "PQ", ext_p},
  {"pslli.b", MATCH_PSLLI_B, MASK_PSLLI_B, "ds:", ext_p},
  {"pslli.h", MATCH_PSLLI_H, MASK_PSLLI_H, "ds;", ext_p},
  {"pslli.db", MATCH_PSLLI_DB, MASK_PSLLI_DB, "PQ:", ext_p},
  {"pslli.dh", MATCH_PSLLI_DH, MASK_PSLLI_DH, "PQ;", ext_p},
  {"pslli.dw", MATCH_PSLLI_DW, MASK_PSLLI_DW, "PQ<", ext_p},
  {"psrai.b", MATCH_PSRAI_B, MASK_PSRAI_B, "ds:", ext_p},
  {"psrai.h", MATCH_PSRAI_H, MASK_PSRAI_H, "ds;", ext_p},
  {"psrai.db", MATCH_PSRAI_DB, MASK_PSRAI_DB, "PQ:", ext_p},
  {"psrai.dh", MATCH_PSRAI_DH, MASK_PSRAI_DH, "PQ;", ext_p},
  {"psrai.dw", MATCH_PSRAI_DW, MASK_PSRAI_DW, "PQ<", ext_p},
  {"psrli.b", MATCH_PSRLI_B, MASK_PSRLI_B, "ds:", ext_p},
  {"psrli.h", MATCH_PSRLI_H, MASK_PSRLI_H, "ds;", ext_p},
  {"psrli.db", MATCH_PSRLI_DB, MASK_PSRLI_DB, "PQ:", ext_p},
  {"psrli.dh", MATCH_PSRLI_DH, MASK_PSRLI_DH, "PQ;", ext_p},
  {"psrli.dw", MATCH_PSRLI_DW, MASK_PSRLI_DW, "PQ<", ext_p},
  {"psrari.h", MATCH_PSRARI_H, MASK_PSRARI_H, "ds;", ext_p},
  {"psrari.dh", MATCH_PSRARI_DH, MASK_PSRARI_DH, "PQ;", ext_p},
  {"psrari.dw", MATCH_PSRARI_DW, MASK_PSRARI_DW, "PQ<", ext_p},
  {"psati.h", MATCH_PSATI_H, MASK_PSATI_H, "ds;", ext_p},
  {"psati.dh", MATCH_PSATI_DH, MASK_PSATI_DH, "PQ;", ext_p},
  {"psati.dw", MATCH_PSATI_DW, MASK_PSATI_DW, "PQ<", ext_p},
  {"pusati.h", MATCH_PUSATI_H, MASK_PUSATI_H, "ds;", ext_p},
  {"pusati.dh", MATCH_PUSATI_DH, MASK_PUSATI_DH, "PQ;", ext_p},
  {"pusati.dw", MATCH_PUSATI_DW, MASK_PUSATI_DW, "PQ<", ext_p},
  {"psslai.h", MATCH_PSSLAI_H, MASK_PSSLAI_H, "ds;", ext_p},
  {"psslai.dh", MATCH_PSSLAI_DH, MASK_PSSLAI_DH, "PQ;", ext_p},
  {"psslai.dw", MATCH_PSSLAI_DW, MASK_PSSLAI_DW, "PQ<", ext_p},
  {"pnclipi.b", MATCH_PNCLIPI_B, MASK_PNCLIPI_B, "dQ;", ext_p},
  {"pnclipi.h", MATCH_PNCLIPI_H, MASK_PNCLIPI_H, "dQ<", ext_p},
  {"pnclipiu.b", MATCH_PNCLIPIU_B, MASK_PNCLIPIU_B, "dQ;", ext_p},
  {"pnclipiu.h", MATCH_PNCLIPIU_H, MASK_PNCLIPIU_H, "dQ<", ext_p},
  {"pnclipri.b", MATCH_PNCLIPRI_B, MASK_PNCLIPRI_B, "dQ;", ext_p},
  {"pnclipri.h", MATCH_PNCLIPRI_H, MASK_PNCLIPRI_H, "dQ<", ext_p},
  {"pnclipriu.b", MATCH_PNCLIPRIU_B, MASK_PNCLIPRIU_B, "dQ;", ext_p},
  {"pnclipriu.h", MATCH_PNCLIPRIU_H, MASK_PNCLIPRIU_H, "dQ<", ext_p},
  {"pnsrai.b", MATCH_PNSRAI_B, MASK_PNSRAI_B, "dQ;", ext_p},
  {"pnsrai.h", MATCH_PNSRAI_H, MASK_PNSRAI_H, "dQ<", ext_p},
  {"pnsrari.b", MATCH_PNSRARI_B, MASK_PNSRARI_B, "dQ;", ext_p},
  {"pnsrari.h", MATCH_PNSRARI_H, MASK_PNSRARI_H, "dQ<", ext_p},
  {"pnsrli.b", MATCH_PNSRLI_B, MASK_PNSRLI_B, "dQ;", ext_p},
  {"pnsrli.h", MATCH_PNSRLI_H, MASK_PNSRLI_H, "dQ<", ext_p},
  {"pwslli.b", MATCH_PWSLLI_B, MASK_PWSLLI_B, "Ps:", ext_p},
  {"pwslli.h", MATCH_PWSLLI_H, MASK_PWSLLI_H, "Ps;", ext_p},
  {"pwslai.b", MATCH_PWSLAI_B, MASK_PWSLAI_B, "Ps:", ext_p},
  {"pwslai.h", MATCH_PWSLAI_H, MASK_PWSLAI_H, "Ps;", ext_p},
  {"pli.b", MATCH_PLI_B, MASK_PLI_B, "d7", ext_p},
  {"pli.h", MATCH_PLI_H, MASK_PLI_H, "d$", ext_p},
  {"pli.db", MATCH_PLI_DB, MASK_PLI_DB, "P7", ext_p},
  {"pli.dh", MATCH_PLI_DH, MASK_PLI_DH, "P$", ext_p},
  {"plui.h", MATCH_PLUI_H, MASK_PLUI_H, "d%", ext_p},
  {"plui.dh", MATCH_PLUI_DH, MASK_PLUI_DH, "P%", ext_p},
  {"pmul.h.b00", MATCH_PMUL_H_B00, MASK_PMUL_H_B00, "dst", ext_p},
  {"pmul.h.b01", MATCH_PMUL_H_B01, MASK_PMUL_H_B01, "dst", ext_p},
  {"pmul.h.b11", MATCH_PMUL_H_B11, MASK_PMUL_H_B11, "dst", ext_p},
  {"pmulu.h.b00", MATCH_PMULU_H_B00, MASK_PMULU_H_B00, "dst", ext_p},
  {"pmulu.h.b01", MATCH_PMULU_H_B01, MASK_PMULU_H_B01, "dst", ext_p},
  {"pmulu.h.b11", MATCH_PMULU_H_B11, MASK_PMULU_H_B11, "dst", ext_p},
  {"pmulsu.h.b00", MATCH_PMULSU_H_B00, MASK_PMULSU_H_B00, "dst", ext_p},
  {"pmulsu.h.b11", MATCH_PMULSU_H_B11, MASK_PMULSU_H_B11, "dst", ext_p},
  {"pmulh.h", MATCH_PMULH_H, MASK_PMULH_H, "dst", ext_p},
  {"pmulhu.h", MATCH_PMULHU_H, MASK_PMULHU_H, "dst", ext_p},
  {"pmulhsu.h", MATCH_PMULHSU_H, MASK_PMULHSU_H, "dst", ext_p},
  {"pmulh.h.b0", MATCH_PMULH_H_B0, MASK_PMULH_H_B0, "dst", ext_p},
  {"pmulh.h.b1", MATCH_PMULH_H_B1, MASK_PMULH_H_B1, "dst", ext_p},
  {"pmulhsu.h.b0", MATCH_PMULHSU_H_B0, MASK_PMULHSU_H_B0, "dst", ext_p},
  {"pmulhsu.h.b1", MATCH_PMULHSU_H_B1, MASK_PMULHSU_H_B1, "dst", ext_p},
  {"pmulhr.h", MATCH_PMULHR_H, MASK_PMULHR_H, "dst", ext_p},
  {"pmulhru.h", MATCH_PMULHRU_H, MASK_PMULHRU_H, "dst", ext_p},
  {"pmulhrsu.h", MATCH_PMULHRSU_H, MASK_PMULHRSU_H, "dst", ext_p},
  {"pmulq.h", MATCH_PMULQ_H, MASK_PMULQ_H, "dst", ext_p},
  {"pmulqr.h", MATCH_PMULQR_H, MASK_PMULQR_H, "dst", ext_p},
  {"pmhacc.h", MATCH_PMHACC_H, MASK_PMHACC_H, "dst", ext_p},
  {"pmhaccu.h", MATCH_PMHACCU_H, MASK_PMHACCU_H, "dst", ext_p},
  {"pmhaccsu.h", MATCH_PMHACCSU_H, MASK_PMHACCSU_H, "dst", ext_p},
  {"pmhacc.h.b0", MATCH_PMHACC_H_B0, MASK_PMHACC_H_B0, "dst", ext_p},
  {"pmhacc.h.b1", MATCH_PMHACC_H_B1, MASK_PMHACC_H_B1, "dst", ext_p},
  {"pmhaccsu.h.b0", MATCH_PMHACCSU_H_B0, MASK_PMHACCSU_H_B0, "dst", ext_p},
  {"pmhaccsu.h.b1", MATCH_PMHACCSU_H_B1, MASK_PMHACCSU_H_B1, "dst", ext_p},
  {"pmhracc.h", MATCH_PMHRACC_H, MASK_PMHRACC_H, "dst", ext_p},
  {"pmhraccu.h", MATCH_PMHRACCU_H, MASK_PMHRACCU_H, "dst", ext_p},
  {"pmhraccsu.h", MATCH_PMHRACCSU_H, MASK_PMHRACCSU_H, "dst", ext_p},
  {"pmq2add.h", MATCH_PMQ2ADD_H, MASK_PMQ2ADD_H, "dst", ext_p},
  {"pmq2adda.h", MATCH_PMQ2ADDA_H, MASK_PMQ2ADDA_H, "dst", ext_p},
  {"pmqr2add.h", MATCH_PMQR2ADD_H, MASK_PMQR2ADD_H, "dst", ext_p},
  {"pmqr2adda.h", MATCH_PMQR2ADDA_H, MASK_PMQR2ADDA_H, "dst", ext_p},
  {"pwadd.b", MATCH_PWADD_B, MASK_PWADD_B, "Pst", ext_p},
  {"pwadd.h", MATCH_PWADD_H, MASK_PWADD_H, "Pst", ext_p},
  {"pwaddu.b", MATCH_PWADDU_B, MASK_PWADDU_B, "Pst", ext_p},
  {"pwaddu.h", MATCH_PWADDU_H, MASK_PWADDU_H, "Pst", ext_p},
  {"pwadda.b", MATCH_PWADDA_B, MASK_PWADDA_B, "Pst", ext_p},
  {"pwadda.h", MATCH_PWADDA_H, MASK_PWADDA_H, "Pst", ext_p},
  {"pwaddau.b", MATCH_PWADDAU_B, MASK_PWADDAU_B, "Pst", ext_p},
  {"pwaddau.h", MATCH_PWADDAU_H, MASK_PWADDAU_H, "Pst", ext_p},
  {"pwsub.b", MATCH_PWSUB_B, MASK_PWSUB_B, "Pst", ext_p},
  {"pwsub.h", MATCH_PWSUB_H, MASK_PWSUB_H, "Pst", ext_p},
  {"pwsubu.b", MATCH_PWSUBU_B, MASK_PWSUBU_B, "Pst", ext_p},
  {"pwsubu.h", MATCH_PWSUBU_H, MASK_PWSUBU_H, "Pst", ext_p},
  {"pwsuba.b", MATCH_PWSUBA_B, MASK_PWSUBA_B, "Pst", ext_p},
  {"pwsuba.h", MATCH_PWSUBA_H, MASK_PWSUBA_H, "Pst", ext_p},
  {"pwsubau.b", MATCH_PWSUBAU_B, MASK_PWSUBAU_B, "Pst", ext_p},
  {"pwsubau.h", MATCH_PWSUBAU_H, MASK_PWSUBAU_H, "Pst", ext_p},
  {"pwmul.b", MATCH_PWMUL_B, MASK_PWMUL_B, "Pst", ext_p},
  {"pwmul.h", MATCH_PWMUL_H, MASK_PWMUL_H, "Pst", ext_p},
  {"pwmulu.b", MATCH_PWMULU_B, MASK_PWMULU_B, "Pst", ext_p},
  {"pwmulu.h", MATCH_PWMULU_H, MASK_PWMULU_H, "Pst", ext_p},
  {"pwmulsu.b", MATCH_PWMULSU_B, MASK_PWMULSU_B, "Pst", ext_p},
  {"pwmulsu.h", MATCH_PWMULSU_H, MASK_PWMULSU_H, "Pst", ext_p},
  {"pwmacc.h", MATCH_PWMACC_H, MASK_PWMACC_H, "Pst", ext_p},
  {"pwmaccu.h", MATCH_PWMACCU_H, MASK_PWMACCU_H, "Pst", ext_p},
  {"pwmaccsu.h", MATCH_PWMACCSU_H, MASK_PWMACCSU_H, "Pst", ext_p},
  {"pm2add.h", MATCH_PM2ADD_H, MASK_PM2ADD_H, "dst", ext_p},
  {"pm2add.hx", MATCH_PM2ADD_HX, MASK_PM2ADD_HX, "dst", ext_p},
  {"pm2addu.h", MATCH_PM2ADDU_H, MASK_PM2ADDU_H, "dst", ext_p},
  {"pm2addsu.h", MATCH_PM2ADDSU_H, MASK_PM2ADDSU_H, "dst", ext_p},
  {"pm2adda.h", MATCH_PM2ADDA_H, MASK_PM2ADDA_H, "dst", ext_p},
  {"pm2adda.hx", MATCH_PM2ADDA_HX, MASK_PM2ADDA_HX, "dst", ext_p},
  {"pm2addau.h", MATCH_PM2ADDAU_H, MASK_PM2ADDAU_H, "dst", ext_p},
  {"pm2addasu.h", MATCH_PM2ADDASU_H, MASK_PM2ADDASU_H, "dst", ext_p},
  {"pm2sub.h", MATCH_PM2SUB_H, MASK_PM2SUB_H, "dst", ext_p},
  {"pm2sub.hx", MATCH_PM2SUB_HX, MASK_PM2SUB_HX, "dst", ext_p},
  {"pm2suba.h", MATCH_PM2SUBA_H, MASK_PM2SUBA_H, "dst", ext_p},
  {"pm2suba.hx", MATCH_PM2SUBA_HX, MASK_PM2SUBA_HX, "dst", ext_p},
  {"pm2sadd.h", MATCH_PM2SADD_H, MASK_PM2SADD_H, "dst", ext_p},
  {"pm2sadd.hx", MATCH_PM2SADD_HX, MASK_PM2SADD_HX, "dst", ext_p},
  {"pm2wadd.h", MATCH_PM2WADD_H, MASK_PM2WADD_H, "Pst", ext_p},
  {"pm2wadd.hx", MATCH_PM2WADD_HX, MASK_PM2WADD_HX, "Pst", ext_p},
  {"pm2waddu.h", MATCH_PM2WADDU_H, MASK_PM2WADDU_H, "Pst", ext_p},
  {"pm2waddsu.h", MATCH_PM2WADDSU_H, MASK_PM2WADDSU_H, "Pst", ext_p},
  {"pm2wadda.h", MATCH_PM2WADDA_H, MASK_PM2WADDA_H, "Pst", ext_p},
  {"pm2wadda.hx", MATCH_PM2WADDA_HX, MASK_PM2WADDA_HX, "Pst", ext_p},
  {"pm2waddau.h", MATCH_PM2WADDAU_H, MASK_PM2WADDAU_H, "Pst", ext_p},
  {"pm2waddasu.h", MATCH_PM2WADDASU_H, MASK_PM2WADDASU_H, "Pst", ext_p},
  {"pm2wsub.h", MATCH_PM2WSUB_H, MASK_PM2WSUB_H, "Pst", ext_p},
  {"pm2wsub.hx", MATCH_PM2WSUB_HX, MASK_PM2WSUB_HX, "Pst", ext_p},
  {"pm2wsuba.h", MATCH_PM2WSUBA_H, MASK_PM2WSUBA_H, "Pst", ext_p},
  {"pm2wsuba.hx", MATCH_PM2WSUBA_HX, MASK_PM2WSUBA_HX, "Pst", ext_p},
  {"pm4add.b", MATCH_PM4ADD_B, MASK_PM4ADD_B, "dst", ext_p},
  {"pm4addu.b", MATCH_PM4ADDU_B, MASK_PM4ADDU_B, "dst", ext_p},
  {"pm4addsu.b", MATCH_PM4ADDSU_B, MASK_PM4ADDSU_B, "dst", ext_p},
  {"pm4adda.b", MATCH_PM4ADDA_B, MASK_PM4ADDA_B, "dst", ext_p},
  {"pm4addau.b", MATCH_PM4ADDAU_B, MASK_PM4ADDAU_B, "dst", ext_p},
  {"pm4addasu.b", MATCH_PM4ADDASU_B, MASK_PM4ADDASU_B, "dst", ext_p},
  {"zip8p", MATCH_ZIP8P, MASK_ZIP8P, "ds", ext_p},
  {"zip8hp", MATCH_ZIP8HP, MASK_ZIP8HP, "ds", ext_p},
  {"unzip8p", MATCH_UNZIP8P, MASK_UNZIP8P, "ds", ext_p},
  {"unzip8hp", MATCH_UNZIP8HP, MASK_UNZIP8HP, "ds", ext_p},
  {"unzip16p", MATCH_UNZIP16P, MASK_UNZIP16P, "ds", ext_p},
  {"unzip16hp", MATCH_UNZIP16HP, MASK_UNZIP16HP, "ds", ext_p},
  {"wzip8p", MATCH_WZIP8P, MASK_WZIP8P, "Ps", ext_p},
  {"wzip16p", MATCH_WZIP16P, MASK_WZIP16P, "Ps", ext_p},
  {"mqwacc", MATCH_MQWACC, MASK_MQWACC, "Pst", ext_p},
  {"mqrwacc", MATCH_MQRWACC, MASK_MQRWACC, "Pst", ext_p},
  {"pmqwacc.h", MATCH_PMQWACC_H, MASK_PMQWACC_H, "Pst", ext_p},
  {"pmqrwacc.h", MATCH_PMQRWACC_H, MASK_PMQRWACC_H, "Pst", ext_p},
  {"absw", MATCH_ABSW, MASK_ABSW, "ds", ext_p_rv64},
  {"clsw", MATCH_CLSW, MASK_CLSW, "ds", ext_p_rv64},
  {"macc.w00", MATCH_MACC_W00, MASK_MACC_W00, "dst", ext_p_rv64},
  {"macc.w01", MATCH_MACC_W01, MASK_MACC_W01, "dst", ext_p_rv64},
  {"macc.w11", MATCH_MACC_W11, MASK_MACC_W11, "dst", ext_p_rv64},
  {"maccu.w00", MATCH_MACCU_W00, MASK_MACCU_W00, "dst", ext_p_rv64},
  {"maccu.w01", MATCH_MACCU_W01, MASK_MACCU_W01, "dst", ext_p_rv64},
  {"maccu.w11", MATCH_MACCU_W11, MASK_MACCU_W11, "dst", ext_p_rv64},
  {"maccsu.w00", MATCH_MACCSU_W00, MASK_MACCSU_W00, "dst", ext_p_rv64},
  {"maccsu.w11", MATCH_MACCSU_W11, MASK_MACCSU_W11, "dst", ext_p_rv64},
  {"mul.w00", MATCH_MUL_W00, MASK_MUL_W00, "dst", ext_p_rv64},
  {"mul.w01", MATCH_MUL_W01, MASK_MUL_W01, "dst", ext_p_rv64},
  {"mul.w11", MATCH_MUL_W11, MASK_MUL_W11, "dst", ext_p_rv64},
  {"mulu.w00", MATCH_MULU_W00, MASK_MULU_W00, "dst", ext_p_rv64},
  {"mulu.w01", MATCH_MULU_W01, MASK_MULU_W01, "dst", ext_p_rv64},
  {"mulu.w11", MATCH_MULU_W11, MASK_MULU_W11, "dst", ext_p_rv64},
  {"mulsu.w00", MATCH_MULSU_W00, MASK_MULSU_W00, "dst", ext_p_rv64},
  {"mulsu.w11", MATCH_MULSU_W11, MASK_MULSU_W11, "dst", ext_p_rv64},
  {"mqacc.w00", MATCH_MQACC_W00, MASK_MQACC_W00, "dst", ext_p_rv64},
  {"mqacc.w01", MATCH_MQACC_W01, MASK_MQACC_W01, "dst", ext_p_rv64},
  {"mqacc.w11", MATCH_MQACC_W11, MASK_MQACC_W11, "dst", ext_p_rv64},
  {"mqracc.w00", MATCH_MQRACC_W00, MASK_MQRACC_W00, "dst", ext_p_rv64},
  {"mqracc.w01", MATCH_MQRACC_W01, MASK_MQRACC_W01, "dst", ext_p_rv64},
  {"mqracc.w11", MATCH_MQRACC_W11, MASK_MQRACC_W11, "dst", ext_p_rv64},
  {"paadd.w", MATCH_PAADD_W, MASK_PAADD_W, "dst", ext_p_rv64},
  {"paaddu.w", MATCH_PAADDU_W, MASK_PAADDU_W, "dst", ext_p_rv64},
  {"paas.wx", MATCH_PAAS_WX, MASK_PAAS_WX, "dst", ext_p_rv64},
  {"padd.w", MATCH_PADD_W, MASK_PADD_W, "dst", ext_p_rv64},
  {"padd.ws", MATCH_PADD_WS, MASK_PADD_WS, "dst", ext_p_rv64},
  {"pasa.wx", MATCH_PASA_WX, MASK_PASA_WX, "dst", ext_p_rv64},
  {"pasub.w", MATCH_PASUB_W, MASK_PASUB_W, "dst", ext_p_rv64},
  {"pasubu.w", MATCH_PASUBU_W, MASK_PASUBU_W, "dst", ext_p_rv64},
  {"pas.wx", MATCH_PAS_WX, MASK_PAS_WX, "dst", ext_p_rv64},
  {"pmax.w", MATCH_PMAX_W, MASK_PMAX_W, "dst", ext_p_rv64},
  {"pmaxu.w", MATCH_PMAXU_W, MASK_PMAXU_W, "dst", ext_p_rv64},
  {"pmin.w", MATCH_PMIN_W, MASK_PMIN_W, "dst", ext_p_rv64},
  {"pminu.w", MATCH_PMINU_W, MASK_PMINU_W, "dst", ext_p_rv64},
  {"pmseq.w", MATCH_PMSEQ_W, MASK_PMSEQ_W, "dst", ext_p_rv64},
  {"pmslt.w", MATCH_PMSLT_W, MASK_PMSLT_W, "dst", ext_p_rv64},
  {"pmsltu.w", MATCH_PMSLTU_W, MASK_PMSLTU_W, "dst", ext_p_rv64},
  {"psadd.w", MATCH_PSADD_W, MASK_PSADD_W, "dst", ext_p_rv64},
  {"psaddu.w", MATCH_PSADDU_W, MASK_PSADDU_W, "dst", ext_p_rv64},
  {"psa.wx", MATCH_PSA_WX, MASK_PSA_WX, "dst", ext_p_rv64},
  {"psas.wx", MATCH_PSAS_WX, MASK_PSAS_WX, "dst", ext_p_rv64},
  {"pssa.wx", MATCH_PSSA_WX, MASK_PSSA_WX, "dst", ext_p_rv64},
  {"pssub.w", MATCH_PSSUB_W, MASK_PSSUB_W, "dst", ext_p_rv64},
  {"pssubu.w", MATCH_PSSUBU_W, MASK_PSSUBU_W, "dst", ext_p_rv64},
  {"psub.w", MATCH_PSUB_W, MASK_PSUB_W, "dst", ext_p_rv64},
  {"psh1add.w", MATCH_PSH1ADD_W, MASK_PSH1ADD_W, "dst", ext_p_rv64},
  {"pssh1sadd.w", MATCH_PSSH1SADD_W, MASK_PSSH1SADD_W, "dst", ext_p_rv64},
  {"psll.ws", MATCH_PSLL_WS, MASK_PSLL_WS, "dst", ext_p_rv64},
  {"psra.ws", MATCH_PSRA_WS, MASK_PSRA_WS, "dst", ext_p_rv64},
  {"psrl.ws", MATCH_PSRL_WS, MASK_PSRL_WS, "dst", ext_p_rv64},
  {"pssha.ws", MATCH_PSSHA_WS, MASK_PSSHA_WS, "dst", ext_p_rv64},
  {"psshar.ws", MATCH_PSSHAR_WS, MASK_PSSHAR_WS, "dst", ext_p_rv64},
  {"psshl.ws", MATCH_PSSHL_WS, MASK_PSSHL_WS, "dst", ext_p_rv64},
  {"psshlr.ws", MATCH_PSSHLR_WS, MASK_PSSHLR_WS, "dst", ext_p_rv64},
  {"shl", MATCH_SHL, MASK_SHL, "dst", ext_p_rv64},
  {"shlr", MATCH_SHLR, MASK_SHLR, "dst", ext_p_rv64},
  {"pnclipp.b", MATCH_PNCLIPP_B, MASK_PNCLIPP_B, "dst", ext_p_rv64},
  {"pnclipp.h", MATCH_PNCLIPP_H, MASK_PNCLIPP_H, "dst", ext_p_rv64},
  {"pnclipp.w", MATCH_PNCLIPP_W, MASK_PNCLIPP_W, "dst", ext_p_rv64},
  {"pnclipup.b", MATCH_PNCLIPUP_B, MASK_PNCLIPUP_B, "dst", ext_p_rv64},
  {"pnclipup.h", MATCH_PNCLIPUP_H, MASK_PNCLIPUP_H, "dst", ext_p_rv64},
  {"pnclipup.w", MATCH_PNCLIPUP_W, MASK_PNCLIPUP_W, "dst", ext_p_rv64},
  {"ppaireo.w", MATCH_PPAIREO_W, MASK_PPAIREO_W, "dst", ext_p_rv64},
  {"ppairoe.w", MATCH_PPAIROE_W, MASK_PPAIROE_W, "dst", ext_p_rv64},
  {"ppairo.w", MATCH_PPAIRO_W, MASK_PPAIRO_W, "dst", ext_p_rv64},
  {"predsum.ws", MATCH_PREDSUM_WS, MASK_PREDSUM_WS, "dst", ext_p_rv64},
  {"predsumu.ws", MATCH_PREDSUMU_WS, MASK_PREDSUMU_WS, "dst", ext_p_rv64},
  {"pmul.w.h00", MATCH_PMUL_W_H00, MASK_PMUL_W_H00, "dst", ext_p_rv64},
  {"pmul.w.h01", MATCH_PMUL_W_H01, MASK_PMUL_W_H01, "dst", ext_p_rv64},
  {"pmul.w.h11", MATCH_PMUL_W_H11, MASK_PMUL_W_H11, "dst", ext_p_rv64},
  {"pmulu.w.h00", MATCH_PMULU_W_H00, MASK_PMULU_W_H00, "dst", ext_p_rv64},
  {"pmulu.w.h01", MATCH_PMULU_W_H01, MASK_PMULU_W_H01, "dst", ext_p_rv64},
  {"pmulu.w.h11", MATCH_PMULU_W_H11, MASK_PMULU_W_H11, "dst", ext_p_rv64},
  {"pmulsu.w.h00", MATCH_PMULSU_W_H00, MASK_PMULSU_W_H00, "dst", ext_p_rv64},
  {"pmulsu.w.h11", MATCH_PMULSU_W_H11, MASK_PMULSU_W_H11, "dst", ext_p_rv64},
  {"pmulh.w", MATCH_PMULH_W, MASK_PMULH_W, "dst", ext_p_rv64},
  {"pmulhu.w", MATCH_PMULHU_W, MASK_PMULHU_W, "dst", ext_p_rv64},
  {"pmulhsu.w", MATCH_PMULHSU_W, MASK_PMULHSU_W, "dst", ext_p_rv64},
  {"pmulh.w.h0", MATCH_PMULH_W_H0, MASK_PMULH_W_H0, "dst", ext_p_rv64},
  {"pmulh.w.h1", MATCH_PMULH_W_H1, MASK_PMULH_W_H1, "dst", ext_p_rv64},
  {"pmulhsu.w.h0", MATCH_PMULHSU_W_H0, MASK_PMULHSU_W_H0, "dst", ext_p_rv64},
  {"pmulhsu.w.h1", MATCH_PMULHSU_W_H1, MASK_PMULHSU_W_H1, "dst", ext_p_rv64},
  {"pmulhr.w", MATCH_PMULHR_W, MASK_PMULHR_W, "dst", ext_p_rv64},
  {"pmulhru.w", MATCH_PMULHRU_W, MASK_PMULHRU_W, "dst", ext_p_rv64},
  {"pmulhrsu.w", MATCH_PMULHRSU_W, MASK_PMULHRSU_W, "dst", ext_p_rv64},
  {"pmulq.w", MATCH_PMULQ_W, MASK_PMULQ_W, "dst", ext_p_rv64},
  {"pmulqr.w", MATCH_PMULQR_W, MASK_PMULQR_W, "dst", ext_p_rv64},
  {"pmacc.w.h00", MATCH_PMACC_W_H00, MASK_PMACC_W_H00, "dst", ext_p_rv64},
  {"pmacc.w.h01", MATCH_PMACC_W_H01, MASK_PMACC_W_H01, "dst", ext_p_rv64},
  {"pmacc.w.h11", MATCH_PMACC_W_H11, MASK_PMACC_W_H11, "dst", ext_p_rv64},
  {"pmaccu.w.h00", MATCH_PMACCU_W_H00, MASK_PMACCU_W_H00, "dst", ext_p_rv64},
  {"pmaccu.w.h01", MATCH_PMACCU_W_H01, MASK_PMACCU_W_H01, "dst", ext_p_rv64},
  {"pmaccu.w.h11", MATCH_PMACCU_W_H11, MASK_PMACCU_W_H11, "dst", ext_p_rv64},
  {"pmaccsu.w.h00", MATCH_PMACCSU_W_H00, MASK_PMACCSU_W_H00, "dst", ext_p_rv64},
  {"pmaccsu.w.h11", MATCH_PMACCSU_W_H11, MASK_PMACCSU_W_H11, "dst", ext_p_rv64},
  {"pmhacc.w", MATCH_PMHACC_W, MASK_PMHACC_W, "dst", ext_p_rv64},
  {"pmhaccu.w", MATCH_PMHACCU_W, MASK_PMHACCU_W, "dst", ext_p_rv64},
  {"pmhaccsu.w", MATCH_PMHACCSU_W, MASK_PMHACCSU_W, "dst", ext_p_rv64},
  {"pmhacc.w.h0", MATCH_PMHACC_W_H0, MASK_PMHACC_W_H0, "dst", ext_p_rv64},
  {"pmhacc.w.h1", MATCH_PMHACC_W_H1, MASK_PMHACC_W_H1, "dst", ext_p_rv64},
  {"pmhaccsu.w.h0", MATCH_PMHACCSU_W_H0, MASK_PMHACCSU_W_H0, "dst", ext_p_rv64},
  {"pmhaccsu.w.h1", MATCH_PMHACCSU_W_H1, MASK_PMHACCSU_W_H1, "dst", ext_p_rv64},
  {"pmhracc.w", MATCH_PMHRACC_W, MASK_PMHRACC_W, "dst", ext_p_rv64},
  {"pmhraccu.w", MATCH_PMHRACCU_W, MASK_PMHRACCU_W, "dst", ext_p_rv64},
  {"pmhraccsu.w", MATCH_PMHRACCSU_W, MASK_PMHRACCSU_W, "dst", ext_p_rv64},
  {"pmqacc.w.h00", MATCH_PMQACC_W_H00, MASK_PMQACC_W_H00, "dst", ext_p_rv64},
  {"pmqacc.w.h01", MATCH_PMQACC_W_H01, MASK_PMQACC_W_H01, "dst", ext_p_rv64},
  {"pmqacc.w.h11", MATCH_PMQACC_W_H11, MASK_PMQACC_W_H11, "dst", ext_p_rv64},
  {"pmqracc.w.h00", MATCH_PMQRACC_W_H00, MASK_PMQRACC_W_H00, "dst", ext_p_rv64},
  {"pmqracc.w.h01", MATCH_PMQRACC_W_H01, MASK_PMQRACC_W_H01, "dst", ext_p_rv64},
  {"pmqracc.w.h11", MATCH_PMQRACC_W_H11, MASK_PMQRACC_W_H11, "dst", ext_p_rv64},
  {"pmq2add.w", MATCH_PMQ2ADD_W, MASK_PMQ2ADD_W, "dst", ext_p_rv64},
  {"pmq2adda.w", MATCH_PMQ2ADDA_W, MASK_PMQ2ADDA_W, "dst", ext_p_rv64},
  {"pmqr2add.w", MATCH_PMQR2ADD_W, MASK_PMQR2ADD_W, "dst", ext_p_rv64},
  {"pmqr2adda.w", MATCH_PMQR2ADDA_W, MASK_PMQR2ADDA_W, "dst", ext_p_rv64},
  {"pm2add.w", MATCH_PM2ADD_W, MASK_PM2ADD_W, "dst", ext_p_rv64},
  {"pm2add.wx", MATCH_PM2ADD_WX, MASK_PM2ADD_WX, "dst", ext_p_rv64},
  {"pm2addu.w", MATCH_PM2ADDU_W, MASK_PM2ADDU_W, "dst", ext_p_rv64},
  {"pm2addsu.w", MATCH_PM2ADDSU_W, MASK_PM2ADDSU_W, "dst", ext_p_rv64},
  {"pm2adda.w", MATCH_PM2ADDA_W, MASK_PM2ADDA_W, "dst", ext_p_rv64},
  {"pm2adda.wx", MATCH_PM2ADDA_WX, MASK_PM2ADDA_WX, "dst", ext_p_rv64},
  {"pm2addau.w", MATCH_PM2ADDAU_W, MASK_PM2ADDAU_W, "dst", ext_p_rv64},
  {"pm2addasu.w", MATCH_PM2ADDASU_W, MASK_PM2ADDASU_W, "dst", ext_p_rv64},
  {"pm2sub.w", MATCH_PM2SUB_W, MASK_PM2SUB_W, "dst", ext_p_rv64},
  {"pm2sub.wx", MATCH_PM2SUB_WX, MASK_PM2SUB_WX, "dst", ext_p_rv64},
  {"pm2suba.w", MATCH_PM2SUBA_W, MASK_PM2SUBA_W, "dst", ext_p_rv64},
  {"pm2suba.wx", MATCH_PM2SUBA_WX, MASK_PM2SUBA_WX, "dst", ext_p_rv64},
  {"pm4add.h", MATCH_PM4ADD_H, MASK_PM4ADD_H, "dst", ext_p_rv64},
  {"pm4addu.h", MATCH_PM4ADDU_H, MASK_PM4ADDU_H, "dst", ext_p_rv64},
  {"pm4addsu.h", MATCH_PM4ADDSU_H, MASK_PM4ADDSU_H, "dst", ext_p_rv64},
  {"pm4adda.h", MATCH_PM4ADDA_H, MASK_PM4ADDA_H, "dst", ext_p_rv64},
  {"pm4addau.h", MATCH_PM4ADDAU_H, MASK_PM4ADDAU_H, "dst", ext_p_rv64},
  {"pm4addasu.h", MATCH_PM4ADDASU_H, MASK_PM4ADDASU_H, "dst", ext_p_rv64},
  {"psext.w.b", MATCH_PSEXT_W_B, MASK_PSEXT_W_B, "ds", ext_p_rv64},
  {"psext.w.h", MATCH_PSEXT_W_H, MASK_PSEXT_W_H, "ds", ext_p_rv64},
  {"zip16p", MATCH_ZIP16P, MASK_ZIP16P, "ds", ext_p_rv64},
  {"zip16hp", MATCH_ZIP16HP, MASK_ZIP16HP, "ds", ext_p_rv64},
  {"pslli.w", MATCH_PSLLI_W, MASK_PSLLI_W, "ds<", ext_p_rv64},
  {"psrai.w", MATCH_PSRAI_W, MASK_PSRAI_W, "ds<", ext_p_rv64},
  {"psrli.w", MATCH_PSRLI_W, MASK_PSRLI_W, "ds<", ext_p_rv64},
  {"psrari.w", MATCH_PSRARI_W, MASK_PSRARI_W, "ds<", ext_p_rv64},
  {"psati.w", MATCH_PSATI_W, MASK_PSATI_W, "ds<", ext_p_rv64},
  {"pusati.w", MATCH_PUSATI_W, MASK_PUSATI_W, "ds<", ext_p_rv64},
  {"psslai.w", MATCH_PSSLAI_W, MASK_PSSLAI_W, "ds<", ext_p_rv64},
  {"pli.w", MATCH_PLI_W, MASK_PLI_W, "d$", ext_p_rv64},
  {"plui.w", MATCH_PLUI_W, MASK_PLUI_W, "d%", ext_p_rv64},
};

#undef EXT1
#undef XV
#undef XVS
#undef EXT1_XV
#undef EXT1_XVS
#undef EXT2
#undef EXT2_XV

// -- Helper: ZIMOP (loops over register numbers) --
static void NOINLINE add_zimop_insns(disassembler_t *d, const isa_parser_t *isa, bool strict)
{
  #define DECLARE_INSN(code, match, mask) \
   const uint32_t match_##code = match; \
   const uint32_t mask_##code = mask;
  #include "encoding.h"
  #undef DECLARE_INSN

  const auto add_r1type = [&](const char *name, uint32_t match, uint32_t mask) {
    d->add_insn(new disasm_insn_t(name, match, mask, {&xrd, &xrs1}));
  };
  const auto add_rtype = [&](const char *name, uint32_t match, uint32_t mask) {
    d->add_insn(new disasm_insn_t(name, match, mask, {&xrd, &xrs1, &xrs2}));
  };


  if (ext_enabled(EXT_ZIMOP)) {
    add_r1type("mop_r_0", match_mop_r_0, mask_mop_r_0);
    add_r1type("mop_r_1", match_mop_r_1, mask_mop_r_1);
    add_r1type("mop_r_2", match_mop_r_2, mask_mop_r_2);
    add_r1type("mop_r_3", match_mop_r_3, mask_mop_r_3);
    add_r1type("mop_r_4", match_mop_r_4, mask_mop_r_4);
    add_r1type("mop_r_5", match_mop_r_5, mask_mop_r_5);
    add_r1type("mop_r_6", match_mop_r_6, mask_mop_r_6);
    add_r1type("mop_r_7", match_mop_r_7, mask_mop_r_7);
    add_r1type("mop_r_8", match_mop_r_8, mask_mop_r_8);
    add_r1type("mop_r_9", match_mop_r_9, mask_mop_r_9);
    add_r1type("mop_r_10", match_mop_r_10, mask_mop_r_10);
    add_r1type("mop_r_11", match_mop_r_11, mask_mop_r_11);
    add_r1type("mop_r_12", match_mop_r_12, mask_mop_r_12);
    add_r1type("mop_r_13", match_mop_r_13, mask_mop_r_13);
    add_r1type("mop_r_14", match_mop_r_14, mask_mop_r_14);
    add_r1type("mop_r_15", match_mop_r_15, mask_mop_r_15);
    add_r1type("mop_r_16", match_mop_r_16, mask_mop_r_16);
    add_r1type("mop_r_17", match_mop_r_17, mask_mop_r_17);
    add_r1type("mop_r_18", match_mop_r_18, mask_mop_r_18);
    add_r1type("mop_r_19", match_mop_r_19, mask_mop_r_19);
    add_r1type("mop_r_20", match_mop_r_20, mask_mop_r_20);
    add_r1type("mop_r_21", match_mop_r_21, mask_mop_r_21);
    add_r1type("mop_r_22", match_mop_r_22, mask_mop_r_22);
    add_r1type("mop_r_23", match_mop_r_23, mask_mop_r_23);
    add_r1type("mop_r_24", match_mop_r_24, mask_mop_r_24);
    add_r1type("mop_r_25", match_mop_r_25, mask_mop_r_25);
    add_r1type("mop_r_26", match_mop_r_26, mask_mop_r_26);
    add_r1type("mop_r_27", match_mop_r_27, mask_mop_r_27);
    if (!ext_enabled_strict(EXT_ZICFISS)) {
      add_r1type("mop_r_28", match_mop_r_28, mask_mop_r_28);
    } else {
      // Add code points of mop_r_28 not used by Zicfiss
      for (unsigned rd_val = 0; rd_val <= 31; ++rd_val)
        for (unsigned rs1_val = 0; rs1_val <= 31; ++rs1_val)
          if ((rd_val != 0 && rs1_val !=0) || (rd_val == 0 && !(rs1_val == 1 || rs1_val == 5)))
            d->add_insn(new disasm_insn_t("mop_r_28", match_mop_r_28 | (rs1_val << 15) | (rd_val << 7), 0xFFFFFFFF, {&xrd, &xrs1}));
    }
    add_r1type("mop_r_29", match_mop_r_29, mask_mop_r_29);
    add_r1type("mop_r_30", match_mop_r_30, mask_mop_r_30);
    add_r1type("mop_r_31", match_mop_r_31, mask_mop_r_31);
    add_rtype("mop_rr_0", match_mop_rr_0, mask_mop_rr_0);
    add_rtype("mop_rr_1", match_mop_rr_1, mask_mop_rr_1);
    add_rtype("mop_rr_2", match_mop_rr_2, mask_mop_rr_2);
    add_rtype("mop_rr_3", match_mop_rr_3, mask_mop_rr_3);
    add_rtype("mop_rr_4", match_mop_rr_4, mask_mop_rr_4);
    add_rtype("mop_rr_5", match_mop_rr_5, mask_mop_rr_5);
    add_rtype("mop_rr_6", match_mop_rr_6, mask_mop_rr_6);
    if (!ext_enabled_strict(EXT_ZICFISS)) {
      add_rtype("mop_rr_7", match_mop_rr_7, mask_mop_rr_7);
    } else {
      // Add code points of mop_rr_7 not used by Zicfiss
      for (unsigned rd_val = 0; rd_val <= 31; ++rd_val)
        for (unsigned rs1_val = 0; rs1_val <= 31; ++rs1_val)
          for (unsigned rs2_val = 0; rs2_val <= 31; ++rs2_val)
            if ((rs2_val != 1 && rs2_val != 5) || rd_val != 0 || rs1_val != 0)
              d->add_insn(new disasm_insn_t("mop_rr_7", match_mop_rr_7 | (rs1_val << 15) | (rd_val << 7) | (rs2_val << 20), 0xFFFFFFFF, {&xrd, &xrs1, &xrs2}));
    }
  }

}

// -- Helper: vector extensions (complex loop-based generation) --
static void NOINLINE add_vector_insns(disassembler_t *d, const isa_parser_t *isa, bool strict)
{
  #define DECLARE_INSN(code, match, mask) \
   const uint32_t match_##code = match; \
   const uint32_t mask_##code = mask;
  #include "encoding.h"
  #undef DECLARE_INSN
  const uint32_t mask_nf    = 0x7Ul  << 29;
  const uint32_t mask_wd    = 0x1Ul  << 26;
  const uint32_t mask_vm    = 0x1Ul  << 25;
  const uint32_t mask_vldst = 0x7Ul  << 12 | 0x1UL << 28;
  const uint32_t mask_amoop = 0x1fUl << 27;
  const uint32_t mask_width = 0x7Ul  << 12;

  #define DISASM_INSN(name, code, extra, ...) \
    d->add_insn(new disasm_insn_t(name, match_##code, mask_##code | (extra), __VA_ARGS__));
  const auto add_rtype = [&](const char *name, uint32_t match, uint32_t mask) {
    d->add_insn(new disasm_insn_t(name, match, mask, {&xrd, &xrs1, &xrs2}));
  };

  #define DEFINE_VECTOR_V(code) \
    d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &vs2, opt, &vm}))
  #define DEFINE_VECTOR_VV(code) \
    d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &vs2, &vs1, opt, &vm}))
  #define DEFINE_VECTOR_MULTIPLYADD_VV(code) \
    d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &vs1, &vs2, opt, &vm}))
  #define DEFINE_VECTOR_VX(code) \
    d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &vs2, &xrs1, opt, &vm}))
  #define DEFINE_VECTOR_MULTIPLYADD_VX(code) \
    d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &xrs1, &vs2, opt, &vm}))
  #define DEFINE_VECTOR_VF(code) \
    d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &vs2, &frs1, opt, &vm}))
  #define DEFINE_VECTOR_MULTIPLYADD_VF(code) \
    d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &frs1, &vs2, opt, &vm}))
  #define DEFINE_VECTOR_VI(code) \
    d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &vs2, &v_simm5, opt, &vm}))
  #define DEFINE_VECTOR_VIU(code) \
    d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &vs2, &zimm5, opt, &vm}))

  if (isa->has_any_vector() || !strict) {
    DISASM_INSN("vsetivli", vsetivli, 0, {&xrd, &zimm5, &v_vtype});
    DISASM_INSN("vsetvli", vsetvli, 0, {&xrd, &xrs1, &v_vtype});
    add_rtype("vsetvl", match_vsetvl, mask_vsetvl);

    std::vector<const arg_t *> v_ld_unit = {&vd, &v_address, opt, &vm};
    std::vector<const arg_t *> v_st_unit = {&vs3, &v_address, opt, &vm};
    std::vector<const arg_t *> v_ld_stride = {&vd, &v_address, &xrs2, opt, &vm};
    std::vector<const arg_t *> v_st_stride = {&vs3, &v_address, &xrs2, opt, &vm};
    std::vector<const arg_t *> v_ld_index = {&vd, &v_address, &vs2, opt, &vm};
    std::vector<const arg_t *> v_st_index = {&vs3, &v_address, &vs2, opt, &vm};

    d->add_insn(new disasm_insn_t("vlm.v",  match_vlm_v,     mask_vlm_v, v_ld_unit));
    d->add_insn(new disasm_insn_t("vsm.v",  match_vsm_v,     mask_vsm_v, v_st_unit));

    // handle vector segment load/store
    for (size_t elt = 0; elt <= 7; ++elt) {
      const custom_fmt_t template_insn[] = {
        {match_vle8_v,   mask_vle8_v,   "vl%se%d.v",   v_ld_unit},
        {match_vse8_v,   mask_vse8_v,   "vs%se%d.v",   v_st_unit},

        {match_vluxei8_v, mask_vluxei8_v, "vlux%sei%d.v", v_ld_index},
        {match_vsuxei8_v, mask_vsuxei8_v, "vsux%sei%d.v", v_st_index},

        {match_vlse8_v,  mask_vlse8_v,  "vls%se%d.v",  v_ld_stride},
        {match_vsse8_v,  mask_vsse8_v,  "vss%se%d.v",  v_st_stride},

        {match_vloxei8_v, mask_vloxei8_v, "vlox%sei%d.v", v_ld_index},
        {match_vsoxei8_v, mask_vsoxei8_v, "vsox%sei%d.v", v_st_index},

        {match_vle8ff_v, mask_vle8ff_v, "vl%se%dff.v", v_ld_unit}
      };

      reg_t elt_map[] = {0x00000000, 0x00005000, 0x00006000, 0x00007000,
                         0x10000000, 0x10005000, 0x10006000, 0x10007000};

      for (unsigned nf = 0; nf <= 7; ++nf) {
        const auto seg_str = nf ? "seg" + std::to_string(nf + 1) : "";

        for (auto item : template_insn) {
          const reg_t match_nf = nf << 29;
          char buf[128];
          snprintf(buf, sizeof(buf), item.fmt, seg_str.c_str(), 8 << elt);
          d->add_insn(new disasm_insn_t(
            buf,
            ((item.match | match_nf) & ~mask_vldst) | elt_map[elt],
            item.mask | mask_nf,
            item.arg
            ));
        }
      }

      const custom_fmt_t template_insn2[] = {
        {match_vl1re8_v,   mask_vl1re8_v,   "vl%dre%d.v",   v_ld_unit},
      };

      for (reg_t i = 0, nf = 7; i < 4; i++, nf >>= 1) {
        for (auto item : template_insn2) {
          const reg_t match_nf = nf << 29;
          char buf[128];
          snprintf(buf, sizeof(buf), item.fmt, nf + 1, 8 << elt);
          d->add_insn(new disasm_insn_t(
            buf,
            item.match | match_nf | elt_map[elt],
            item.mask | mask_nf,
            item.arg
          ));
        }
      }
    }

    #define DISASM_ST_WHOLE_INSN(name, nf) \
      d->add_insn(new disasm_insn_t(#name, match_vs1r_v | (nf << 29), \
                                        mask_vs1r_v | mask_nf, \
                                        {&vs3, &v_address}));
    DISASM_ST_WHOLE_INSN(vs1r.v, 0);
    DISASM_ST_WHOLE_INSN(vs2r.v, 1);
    DISASM_ST_WHOLE_INSN(vs4r.v, 3);
    DISASM_ST_WHOLE_INSN(vs8r.v, 7);

    #undef DISASM_ST_WHOLE_INSN

    #define DEFINE_VECTOR_V(code) d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &vs2, opt, &vm}))
    #define DEFINE_VECTOR_VV(code) d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &vs2, &vs1, opt, &vm}))
    #define DEFINE_VECTOR_MULTIPLYADD_VV(code) d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &vs1, &vs2, opt, &vm}))
    #define DEFINE_VECTOR_VX(code) d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &vs2, &xrs1, opt, &vm}))
    #define DEFINE_VECTOR_MULTIPLYADD_VX(code) d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &xrs1, &vs2, opt, &vm}))
    #define DEFINE_VECTOR_VF(code) d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &vs2, &frs1, opt, &vm}))
    #define DEFINE_VECTOR_MULTIPLYADD_VF(code) d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &frs1, &vs2, opt, &vm}))
    #define DEFINE_VECTOR_VI(code) d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &vs2, &v_simm5, opt, &vm}))
    #define DEFINE_VECTOR_VIU(code) d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &vs2, &zimm5, opt, &vm}))

    #define DISASM_OPIV_VXI_INSN(name, sign, suf) \
      DEFINE_VECTOR_VV(name##_##suf##v); \
      DEFINE_VECTOR_VX(name##_##suf##x); \
      if (sign) \
        DEFINE_VECTOR_VI(name##_##suf##i); \
      else \
        DEFINE_VECTOR_VIU(name##_##suf##i)

    #define DISASM_OPIV_VX__INSN(name, sign) \
      DEFINE_VECTOR_VV(name##_vv); \
      DEFINE_VECTOR_VX(name##_vx)

    #define DISASM_OPIV_MULTIPLYADD_VX__INSN(name, sign) \
      DEFINE_VECTOR_MULTIPLYADD_VV(name##_vv); \
      DEFINE_VECTOR_MULTIPLYADD_VX(name##_vx)

    #define DISASM_OPIV__XI_INSN(name, sign) \
      DEFINE_VECTOR_VX(name##_vx); \
      if (sign) \
        DEFINE_VECTOR_VI(name##_vi); \
      else \
        DEFINE_VECTOR_VIU(name##_vi)

    #define DISASM_OPIV_V___INSN(name, sign) DEFINE_VECTOR_VV(name##_vv)

    #define DISASM_OPIV_S___INSN(name, sign) DEFINE_VECTOR_VV(name##_vs)

    #define DISASM_OPIV_W___INSN(name, sign) \
      DEFINE_VECTOR_VV(name##_wv); \
      DEFINE_VECTOR_VX(name##_wx)

    #define DISASM_OPIV_M___INSN(name, sign) DEFINE_VECTOR_VV(name##_mm)

    #define DISASM_OPIV__X__INSN(name, sign) DEFINE_VECTOR_VX(name##_vx)

    #define DISASM_OPIV_MULTIPLYADD__X__INSN(name, sign) DEFINE_VECTOR_MULTIPLYADD_VX(name##_vx)

    #define DEFINE_VECTOR_VVM(name) \
      d->add_insn(new disasm_insn_t(#name, match_##name, mask_##name | mask_vm, {&vd, &vs2, &vs1, &v0}))

    #define DEFINE_VECTOR_VXM(name) \
      d->add_insn(new disasm_insn_t(#name, match_##name, mask_##name | mask_vm, {&vd, &vs2, &xrs1, &v0}))

    #define DEFINE_VECTOR_VIM(name) \
      d->add_insn(new disasm_insn_t(#name, match_##name, mask_##name | mask_vm, {&vd, &vs2, &v_simm5, &v0}))

    #define DISASM_OPIV_VXIM_INSN(name) \
      DEFINE_VECTOR_VVM(name##_vvm); \
      DEFINE_VECTOR_VXM(name##_vxm); \
      DEFINE_VECTOR_VIM(name##_vim)

    #define DISASM_OPIV_VX_M_INSN(name) \
      DEFINE_VECTOR_VVM(name##_vvm); \
      DEFINE_VECTOR_VXM(name##_vxm)

    //OPFVV/OPFVF
    //0b00_0000
    DISASM_OPIV_VXI_INSN(vadd,         1, v);
    DISASM_OPIV_VX__INSN(vsub,         1);
    DISASM_OPIV__XI_INSN(vrsub,        1);
    DISASM_OPIV_VX__INSN(vminu,        0);
    DISASM_OPIV_VX__INSN(vmin,         1);
    DISASM_OPIV_VX__INSN(vmaxu,        1);
    DISASM_OPIV_VX__INSN(vmax,         0);
    DISASM_OPIV_VXI_INSN(vand,         1, v);
    DISASM_OPIV_VXI_INSN(vor,          1, v);
    DISASM_OPIV_VXI_INSN(vxor,         1, v);
    DISASM_OPIV_VXI_INSN(vrgather,     0, v);
    DISASM_OPIV_V___INSN(vrgatherei16, 0);
    DISASM_OPIV__XI_INSN(vslideup,     0);
    DISASM_OPIV__XI_INSN(vslidedown,   0);

    //0b01_0000
    DISASM_OPIV_VXIM_INSN(vadc);
    DISASM_OPIV_VX_M_INSN(vsbc);
    DISASM_OPIV_VXIM_INSN(vmadc);
    DISASM_OPIV_VXI_INSN(vmadc, 1, v);
    DISASM_OPIV_VX_M_INSN(vmsbc);
    DISASM_OPIV_VX__INSN(vmsbc, 1);
    DISASM_OPIV_VXIM_INSN(vmerge);
    DISASM_INSN("vmv.v.i", vmv_v_i, 0, {&vd, &v_simm5});
    DISASM_INSN("vmv.v.v", vmv_v_v, 0, {&vd, &vs1});
    DISASM_INSN("vmv.v.x", vmv_v_x, 0, {&vd, &xrs1});
    DISASM_OPIV_VXI_INSN(vmseq,     1, v);
    DISASM_OPIV_VXI_INSN(vmsne,     1, v);
    DISASM_OPIV_VX__INSN(vmsltu,    0);
    DISASM_OPIV_VX__INSN(vmslt,     1);
    DISASM_OPIV_VXI_INSN(vmsleu,    0, v);
    DISASM_OPIV_VXI_INSN(vmsle,     1, v);
    DISASM_OPIV__XI_INSN(vmsgtu,    0);
    DISASM_OPIV__XI_INSN(vmsgt,     1);

    //0b10_0000
    DISASM_OPIV_VXI_INSN(vsaddu,    0, v);
    DISASM_OPIV_VXI_INSN(vsadd,     1, v);
    DISASM_OPIV_VX__INSN(vssubu,    0);
    DISASM_OPIV_VX__INSN(vssub,     1);
    DISASM_OPIV_VXI_INSN(vsll,      1, v);
    DISASM_INSN("vmv1r.v", vmv1r_v, 0, {&vd, &vs2});
    DISASM_INSN("vmv2r.v", vmv2r_v, 0, {&vd, &vs2});
    DISASM_INSN("vmv4r.v", vmv4r_v, 0, {&vd, &vs2});
    DISASM_INSN("vmv8r.v", vmv8r_v, 0, {&vd, &vs2});
    DISASM_OPIV_VX__INSN(vsmul,     1);
    DISASM_OPIV_VXI_INSN(vsrl,      0, v);
    DISASM_OPIV_VXI_INSN(vsra,      0, v);
    DISASM_OPIV_VXI_INSN(vssrl,     0, v);
    DISASM_OPIV_VXI_INSN(vssra,     0, v);
    DISASM_OPIV_VXI_INSN(vnsrl,     0, w);
    DISASM_OPIV_VXI_INSN(vnsra,     0, w);
    DISASM_OPIV_VXI_INSN(vnclipu,   0, w);
    DISASM_OPIV_VXI_INSN(vnclip,    0, w);

    //0b11_0000
    DISASM_OPIV_S___INSN(vwredsumu, 0);
    DISASM_OPIV_S___INSN(vwredsum,  1);

    //OPMVV/OPMVX
    //0b00_0000
    DISASM_OPIV_VX__INSN(vaaddu,    0);
    DISASM_OPIV_VX__INSN(vaadd,     0);
    DISASM_OPIV_VX__INSN(vasubu,    0);
    DISASM_OPIV_VX__INSN(vasub,     0);

    DISASM_OPIV_S___INSN(vredsum,   1);
    DISASM_OPIV_S___INSN(vredand,   1);
    DISASM_OPIV_S___INSN(vredor,    1);
    DISASM_OPIV_S___INSN(vredxor,   1);
    DISASM_OPIV_S___INSN(vredminu,  0);
    DISASM_OPIV_S___INSN(vredmin,   1);
    DISASM_OPIV_S___INSN(vredmaxu,  0);
    DISASM_OPIV_S___INSN(vredmax,   1);
    DISASM_OPIV__X__INSN(vslide1up,  1);
    DISASM_OPIV__X__INSN(vslide1down,1);

    //0b01_0000
    //VWXUNARY0
    DISASM_INSN("vmv.x.s", vmv_x_s, 0, {&xrd, &vs2});
    DISASM_INSN("vcpop.m", vcpop_m, 0, {&xrd, &vs2, opt, &vm});
    DISASM_INSN("vfirst.m", vfirst_m, 0, {&xrd, &vs2, opt, &vm});

    //VRXUNARY0
    DISASM_INSN("vmv.s.x", vmv_s_x, 0, {&vd, &xrs1});

    //VXUNARY0
    DEFINE_VECTOR_V(vzext_vf2);
    DEFINE_VECTOR_V(vsext_vf2);
    DEFINE_VECTOR_V(vzext_vf4);
    DEFINE_VECTOR_V(vsext_vf4);
    DEFINE_VECTOR_V(vzext_vf8);
    DEFINE_VECTOR_V(vsext_vf8);

    //VMUNARY0
    DEFINE_VECTOR_V(vmsbf_m);
    DEFINE_VECTOR_V(vmsof_m);
    DEFINE_VECTOR_V(vmsif_m);
    DEFINE_VECTOR_V(viota_m);
    DISASM_INSN("vid.v", vid_v, 0, {&vd, opt, &vm});

    DISASM_INSN("vid.v", vid_v, 0, {&vd, opt, &vm});

    DISASM_INSN("vcompress.vm", vcompress_vm, 0, {&vd, &vs2, &vs1});

    DISASM_OPIV_M___INSN(vmandn,    1);
    DISASM_OPIV_M___INSN(vmand,     1);
    DISASM_OPIV_M___INSN(vmor,      1);
    DISASM_OPIV_M___INSN(vmxor,     1);
    DISASM_OPIV_M___INSN(vmorn,     1);
    DISASM_OPIV_M___INSN(vmnand,    1);
    DISASM_OPIV_M___INSN(vmnor,     1);
    DISASM_OPIV_M___INSN(vmxnor,    1);

    //0b10_0000
    DISASM_OPIV_VX__INSN(vdivu,     0);
    DISASM_OPIV_VX__INSN(vdiv,      1);
    DISASM_OPIV_VX__INSN(vremu,     0);
    DISASM_OPIV_VX__INSN(vrem,      1);
    DISASM_OPIV_VX__INSN(vmulhu,    0);
    DISASM_OPIV_VX__INSN(vmul,      1);
    DISASM_OPIV_VX__INSN(vmulhsu,   0);
    DISASM_OPIV_VX__INSN(vmulh,     1);
    DISASM_OPIV_MULTIPLYADD_VX__INSN(vmadd,     1);
    DISASM_OPIV_MULTIPLYADD_VX__INSN(vnmsub,    1);
    DISASM_OPIV_MULTIPLYADD_VX__INSN(vmacc,     1);
    DISASM_OPIV_MULTIPLYADD_VX__INSN(vnmsac,    1);

    //0b11_0000
    DISASM_OPIV_VX__INSN(vwaddu,    0);
    DISASM_OPIV_VX__INSN(vwadd,     1);
    DISASM_OPIV_VX__INSN(vwsubu,    0);
    DISASM_OPIV_VX__INSN(vwsub,     1);
    DISASM_OPIV_W___INSN(vwaddu,    0);
    DISASM_OPIV_W___INSN(vwadd,     1);
    DISASM_OPIV_W___INSN(vwsubu,    0);
    DISASM_OPIV_W___INSN(vwsub,     1);
    DISASM_OPIV_VX__INSN(vwmulu,    0);
    DISASM_OPIV_VX__INSN(vwmulsu,   0);
    DISASM_OPIV_VX__INSN(vwmul,     1);
    DISASM_OPIV_MULTIPLYADD_VX__INSN(vwmaccu,   0);
    DISASM_OPIV_MULTIPLYADD_VX__INSN(vwmacc,    1);
    DISASM_OPIV_MULTIPLYADD__X__INSN(vwmaccus,  1);
    DISASM_OPIV_MULTIPLYADD_VX__INSN(vwmaccsu,  0);

    if (ext_enabled(EXT_ZVQDOTQ)) {
      DISASM_OPIV_VX__INSN(vqdot,   0);
      DISASM_OPIV_VX__INSN(vqdotu,  0);
      DISASM_OPIV_VX__INSN(vqdotsu, 0);
      DISASM_OPIV__X__INSN(vqdotus, 0);
    }

    #undef DISASM_OPIV_VXI_INSN
    #undef DISASM_OPIV_VX__INSN
    #undef DISASM_OPIV__XI_INSN
    #undef DISASM_OPIV_V___INSN
    #undef DISASM_OPIV_S___INSN
    #undef DISASM_OPIV_W___INSN
    #undef DISASM_OPIV_M___INSN
    #undef DISASM_OPIV__X__INSN
    #undef DISASM_OPIV_VXIM_INSN
    #undef DISASM_OPIV_VX_M_INSN

    #define DISASM_OPIV_VF_INSN(name) \
      DEFINE_VECTOR_VV(name##_vv); \
      DEFINE_VECTOR_VF(name##_vf)

    #define DISASM_OPIV_MULTIPLYADD_VF_INSN(name) \
      DEFINE_VECTOR_MULTIPLYADD_VV(name##_vv); \
      DEFINE_VECTOR_MULTIPLYADD_VF(name##_vf)

    #define DISASM_OPIV_WF_INSN(name) \
      DEFINE_VECTOR_VV(name##_wv); \
      DEFINE_VECTOR_VF(name##_wf)

    #define DISASM_OPIV_S__INSN(name) \
      DEFINE_VECTOR_VV(name##_vs)

    #define DISASM_OPIV__F_INSN(name) \
      DEFINE_VECTOR_VF(name##_vf)

    #define DISASM_VFUNARY0_INSN(name, suf) \
      DEFINE_VECTOR_V(name##cvt_rtz_xu_f_##suf); \
      DEFINE_VECTOR_V(name##cvt_rtz_x_f_##suf); \
      DEFINE_VECTOR_V(name##cvt_xu_f_##suf); \
      DEFINE_VECTOR_V(name##cvt_x_f_##suf); \
      DEFINE_VECTOR_V(name##cvt_f_xu_##suf); \
      DEFINE_VECTOR_V(name##cvt_f_x_##suf)

    //OPFVV/OPFVF
    //0b00_0000
    DISASM_OPIV_VF_INSN(vfadd);
    DISASM_OPIV_S__INSN(vfredusum);
    DISASM_OPIV_VF_INSN(vfsub);
    DISASM_OPIV_S__INSN(vfredosum);
    DISASM_OPIV_VF_INSN(vfmin);
    DISASM_OPIV_S__INSN(vfredmin);
    DISASM_OPIV_VF_INSN(vfmax);
    DISASM_OPIV_S__INSN(vfredmax);
    DISASM_OPIV_VF_INSN(vfsgnj);
    DISASM_OPIV_VF_INSN(vfsgnjn);
    DISASM_OPIV_VF_INSN(vfsgnjx);
    DISASM_INSN("vfmv.f.s", vfmv_f_s, 0, {&frd, &vs2});
    DISASM_INSN("vfmv.s.f", vfmv_s_f, mask_vfmv_s_f, {&vd, &frs1});
    DISASM_OPIV__F_INSN(vfslide1up);
    DISASM_OPIV__F_INSN(vfslide1down);

    //0b01_0000
    DISASM_INSN("vfmerge.vfm", vfmerge_vfm, 0, {&vd, &vs2, &frs1, &v0});
    DISASM_INSN("vfmv.v.f", vfmv_v_f, 0, {&vd, &frs1});
    DISASM_OPIV_VF_INSN(vmfeq);
    DISASM_OPIV_VF_INSN(vmfle);
    DISASM_OPIV_VF_INSN(vmflt);
    DISASM_OPIV_VF_INSN(vmfne);
    DISASM_OPIV__F_INSN(vmfgt);
    DISASM_OPIV__F_INSN(vmfge);

    //0b10_0000
    DISASM_OPIV_VF_INSN(vfdiv);
    DISASM_OPIV__F_INSN(vfrdiv);

    //vfunary0
    DISASM_VFUNARY0_INSN(vf,  v);
    DISASM_VFUNARY0_INSN(vfw, v);
    DEFINE_VECTOR_V(vfwcvt_f_f_v);

    DISASM_VFUNARY0_INSN(vfn, w);
    DEFINE_VECTOR_V(vfncvt_f_f_w);
    DEFINE_VECTOR_V(vfncvt_rod_f_f_w);

    //vfunary1
    DEFINE_VECTOR_V(vfsqrt_v);
    DEFINE_VECTOR_V(vfrsqrt7_v);
    DEFINE_VECTOR_V(vfrec7_v);
    DEFINE_VECTOR_V(vfclass_v);

    DISASM_OPIV_VF_INSN(vfmul);
    DISASM_OPIV__F_INSN(vfrsub);
    DISASM_OPIV_MULTIPLYADD_VF_INSN(vfmadd);
    DISASM_OPIV_MULTIPLYADD_VF_INSN(vfnmadd);
    DISASM_OPIV_MULTIPLYADD_VF_INSN(vfmsub);
    DISASM_OPIV_MULTIPLYADD_VF_INSN(vfnmsub);
    DISASM_OPIV_MULTIPLYADD_VF_INSN(vfmacc);
    DISASM_OPIV_MULTIPLYADD_VF_INSN(vfnmacc);
    DISASM_OPIV_MULTIPLYADD_VF_INSN(vfmsac);
    DISASM_OPIV_MULTIPLYADD_VF_INSN(vfnmsac);

    //0b11_0000
    DISASM_OPIV_VF_INSN(vfwadd);
    DISASM_OPIV_S__INSN(vfwredusum);
    DISASM_OPIV_VF_INSN(vfwsub);
    DISASM_OPIV_S__INSN(vfwredosum);
    DISASM_OPIV_WF_INSN(vfwadd);
    DISASM_OPIV_WF_INSN(vfwsub);
    DISASM_OPIV_VF_INSN(vfwmul);
    DISASM_OPIV_MULTIPLYADD_VF_INSN(vfwmacc);
    DISASM_OPIV_MULTIPLYADD_VF_INSN(vfwnmacc);
    DISASM_OPIV_MULTIPLYADD_VF_INSN(vfwmsac);
    DISASM_OPIV_MULTIPLYADD_VF_INSN(vfwnmsac);

    #undef DISASM_OPIV_VF_INSN
    #undef DISASM_OPIV__F_INSN
    #undef DISASM_OPIV_S__INSN
    #undef DISASM_OPIV_W__INSN
    #undef DISASM_VFUNARY0_INSN
  }

  if (ext_enabled(EXT_ZVFOFP4MIN)) {
    DEFINE_VECTOR_V(vfext_vf2);
  }

  if (ext_enabled(EXT_ZVFOFP8MIN)) {
    DEFINE_VECTOR_V(vfncvt_f_f_q);
    DEFINE_VECTOR_V(vfncvt_sat_f_f_q);
    DEFINE_VECTOR_V(vfncvtbf16_sat_f_f_w);
  }

  if (ext_enabled(EXT_ZVFBFMIN)) {
    DEFINE_VECTOR_V(vfncvtbf16_f_f_w);
    DEFINE_VECTOR_V(vfwcvtbf16_f_f_v);
  }

  if (ext_enabled(EXT_ZVFBFWMA)) {
    DEFINE_VECTOR_VV(vfwmaccbf16_vv);
    DEFINE_VECTOR_VF(vfwmaccbf16_vf);
  }

  if (ext_enabled(EXT_ZVABD)) {
    DEFINE_VECTOR_V(vabs_v);
    DEFINE_VECTOR_VV(vabd_vv);
    DEFINE_VECTOR_VV(vabdu_vv);
    DEFINE_VECTOR_MULTIPLYADD_VV(vwabda_vv);
    DEFINE_VECTOR_MULTIPLYADD_VV(vwabdau_vv);
  }

  if (ext_enabled(EXT_ZVZIP)) {
    DEFINE_VECTOR_VV(vzip_vv);
    DEFINE_VECTOR_V(vunzipe_v);
    DEFINE_VECTOR_V(vunzipo_v);
    DEFINE_VECTOR_VV(vpaire_vv);
    DEFINE_VECTOR_VV(vpairo_vv);
  }

  if (ext_enabled(EXT_ZVBB)) {
#define DEFINE_VECTOR_VIU_ZIMM6(code) \
  d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&vd, &vs2, &v_zimm6, opt, &vm}))
#define DISASM_VECTOR_VV_VX(name) \
  DEFINE_VECTOR_VV(name##_vv); \
  DEFINE_VECTOR_VX(name##_vx)
#define DISASM_VECTOR_VV_VX_VIU(name) \
  DEFINE_VECTOR_VV(name##_vv); \
  DEFINE_VECTOR_VX(name##_vx); \
  DEFINE_VECTOR_VIU(name##_vi)
#define DISASM_VECTOR_VV_VX_VIU_ZIMM6(name) \
  DEFINE_VECTOR_VV(name##_vv); \
  DEFINE_VECTOR_VX(name##_vx); \
  DEFINE_VECTOR_VIU_ZIMM6(name##_vi)

    DISASM_VECTOR_VV_VX(vandn);
    DEFINE_VECTOR_V(vbrev_v);
    DEFINE_VECTOR_V(vbrev8_v);
    DEFINE_VECTOR_V(vrev8_v);
    DEFINE_VECTOR_V(vclz_v);
    DEFINE_VECTOR_V(vctz_v);
    DEFINE_VECTOR_V(vcpop_v);
    DISASM_VECTOR_VV_VX(vrol);
    DISASM_VECTOR_VV_VX_VIU_ZIMM6(vror);
    DISASM_VECTOR_VV_VX_VIU(vwsll);

#undef DEFINE_VECTOR_VIU_ZIMM6
#undef DISASM_VECTOR_VV_VX
#undef DISASM_VECTOR_VV_VX_VIU
#undef DISASM_VECTOR_VV_VX_VIU_ZIMM6
    }

  if (ext_enabled(EXT_ZVBC)) {
#define DISASM_VECTOR_VV_VX(name) \
    DEFINE_VECTOR_VV(name##_vv); \
    DEFINE_VECTOR_VX(name##_vx)

    DISASM_VECTOR_VV_VX(vclmul);
    DISASM_VECTOR_VV_VX(vclmulh);

#undef DISASM_VECTOR_VV_VX
  }

  if (ext_enabled(EXT_ZVKG)) {
    // Despite its suffix, the vgmul.vv instruction
    // is really ".v", with the form "vgmul.vv vd, vs2".
    DEFINE_VECTOR_V(vgmul_vv);
    DEFINE_VECTOR_VV(vghsh_vv);
  }

  if (ext_enabled(EXT_ZVKNED)) {
    // Despite their suffixes, the vaes*.{vv,vs} instructions
    // are really ".v", with the form "<op>.{vv,vs} vd, vs2".
#define DISASM_VECTOR_VV_VS(name) \
    DEFINE_VECTOR_V(name##_vv); \
    DEFINE_VECTOR_V(name##_vs)

    DISASM_VECTOR_VV_VS(vaesdm);
    DISASM_VECTOR_VV_VS(vaesdf);
    DISASM_VECTOR_VV_VS(vaesem);
    DISASM_VECTOR_VV_VS(vaesef);

    DEFINE_VECTOR_V(vaesz_vs);
    DEFINE_VECTOR_VIU(vaeskf1_vi);
    DEFINE_VECTOR_VIU(vaeskf2_vi);
#undef DISASM_VECTOR_VV_VS
  }

  if (ext_enabled(EXT_ZVKNHA) || ext_enabled(EXT_ZVKNHB)) {
    DEFINE_VECTOR_VV(vsha2ms_vv);
    DEFINE_VECTOR_VV(vsha2ch_vv);
    DEFINE_VECTOR_VV(vsha2cl_vv);
  }

  if (ext_enabled(EXT_ZVKSED)) {
    DEFINE_VECTOR_VIU(vsm4k_vi);
    // Despite their suffixes, the vsm4r.{vv,vs} instructions
    // are really ".v", with the form "vsm4r.{vv,vs} vd, vs2".
    DEFINE_VECTOR_V(vsm4r_vv);
    DEFINE_VECTOR_V(vsm4r_vs);
  }

  if (ext_enabled(EXT_ZVKSH)) {
    DEFINE_VECTOR_VIU(vsm3c_vi);
    DEFINE_VECTOR_VV(vsm3me_vv);
  }

  #undef DISASM_INSN
  #undef DEFINE_VECTOR_V
  #undef DEFINE_VECTOR_VV
  #undef DEFINE_VECTOR_MULTIPLYADD_VV
  #undef DEFINE_VECTOR_VX
  #undef DEFINE_VECTOR_MULTIPLYADD_VX
  #undef DEFINE_VECTOR_VF
  #undef DEFINE_VECTOR_MULTIPLYADD_VF
  #undef DEFINE_VECTOR_VI
  #undef DEFINE_VECTOR_VIU
}

void disassembler_t::add_instructions(const isa_parser_t* isa, bool strict)
{
  add_insn(new disasm_insn_t("unimp", MATCH_CSRRW|(CSR_CYCLE<<20), 0xffffffff, {}));
  add_insn(new disasm_insn_t("c.unimp", 0, 0xffff, {}));

  // Flat table iteration (like binutils riscv_opcodes[])
  for (const auto& op : all_insns)
    if (insn_class_enabled(op.cls, isa, strict))
      add_insn(new disasm_insn_t(op.name, op.match, op.mask, parse_fmt(op.fmt)));

  // AMO instructions: generate .rl/.aq/.aqrl suffix variants
  if (ext_enabled(EXT_ZAAMO)) {
    add_xamo_insn(this, "amoadd.w",  MATCH_AMOADD_W,  MASK_AMOADD_W);
    add_xamo_insn(this, "amoswap.w", MATCH_AMOSWAP_W, MASK_AMOSWAP_W);
    add_xamo_insn(this, "amoand.w",  MATCH_AMOAND_W,  MASK_AMOAND_W);
    add_xamo_insn(this, "amoor.w",   MATCH_AMOOR_W,   MASK_AMOOR_W);
    add_xamo_insn(this, "amoxor.w",  MATCH_AMOXOR_W,  MASK_AMOXOR_W);
    add_xamo_insn(this, "amomin.w",  MATCH_AMOMIN_W,  MASK_AMOMIN_W);
    add_xamo_insn(this, "amomax.w",  MATCH_AMOMAX_W,  MASK_AMOMAX_W);
    add_xamo_insn(this, "amominu.w", MATCH_AMOMINU_W, MASK_AMOMINU_W);
    add_xamo_insn(this, "amomaxu.w", MATCH_AMOMAXU_W, MASK_AMOMAXU_W);
    if (xlen_eq(64)) {
      add_xamo_insn(this, "amoadd.d",  MATCH_AMOADD_D,  MASK_AMOADD_D);
      add_xamo_insn(this, "amoswap.d", MATCH_AMOSWAP_D, MASK_AMOSWAP_D);
      add_xamo_insn(this, "amoand.d",  MATCH_AMOAND_D,  MASK_AMOAND_D);
      add_xamo_insn(this, "amoor.d",   MATCH_AMOOR_D,   MASK_AMOOR_D);
      add_xamo_insn(this, "amoxor.d",  MATCH_AMOXOR_D,  MASK_AMOXOR_D);
      add_xamo_insn(this, "amomin.d",  MATCH_AMOMIN_D,  MASK_AMOMIN_D);
      add_xamo_insn(this, "amomax.d",  MATCH_AMOMAX_D,  MASK_AMOMAX_D);
      add_xamo_insn(this, "amominu.d", MATCH_AMOMINU_D, MASK_AMOMINU_D);
      add_xamo_insn(this, "amomaxu.d", MATCH_AMOMAXU_D, MASK_AMOMAXU_D);
    }
  }
  if (ext_enabled(EXT_ZALRSC)) {
    add_xamo_insn(this, "sc.w", MATCH_SC_W, MASK_SC_W);
    if (xlen_eq(64)) add_xamo_insn(this, "sc.d", MATCH_SC_D, MASK_SC_D);
  }
  if (ext_enabled(EXT_ZACAS)) {
    add_xamo_insn(this, "amocas.w", MATCH_AMOCAS_W, MASK_AMOCAS_W);
    add_xamo_insn(this, "amocas.d", MATCH_AMOCAS_D, MASK_AMOCAS_D);
    if (xlen_eq(64)) add_xamo_insn(this, "amocas.q", MATCH_AMOCAS_Q, MASK_AMOCAS_Q);
  }
  if (ext_enabled(EXT_ZABHA)) {
    add_xamo_insn(this, "amoadd.b",  MATCH_AMOADD_B,  MASK_AMOADD_B);
    add_xamo_insn(this, "amoswap.b", MATCH_AMOSWAP_B, MASK_AMOSWAP_B);
    add_xamo_insn(this, "amoand.b",  MATCH_AMOAND_B,  MASK_AMOAND_B);
    add_xamo_insn(this, "amoor.b",   MATCH_AMOOR_B,   MASK_AMOOR_B);
    add_xamo_insn(this, "amoxor.b",  MATCH_AMOXOR_B,  MASK_AMOXOR_B);
    add_xamo_insn(this, "amomin.b",  MATCH_AMOMIN_B,  MASK_AMOMIN_B);
    add_xamo_insn(this, "amomax.b",  MATCH_AMOMAX_B,  MASK_AMOMAX_B);
    add_xamo_insn(this, "amominu.b", MATCH_AMOMINU_B, MASK_AMOMINU_B);
    add_xamo_insn(this, "amomaxu.b", MATCH_AMOMAXU_B, MASK_AMOMAXU_B);
    add_xamo_insn(this, "amocas.b",  MATCH_AMOCAS_B,  MASK_AMOCAS_B);
    add_xamo_insn(this, "amoadd.h",  MATCH_AMOADD_H,  MASK_AMOADD_H);
    add_xamo_insn(this, "amoswap.h", MATCH_AMOSWAP_H, MASK_AMOSWAP_H);
    add_xamo_insn(this, "amoand.h",  MATCH_AMOAND_H,  MASK_AMOAND_H);
    add_xamo_insn(this, "amoor.h",   MATCH_AMOOR_H,   MASK_AMOOR_H);
    add_xamo_insn(this, "amoxor.h",  MATCH_AMOXOR_H,  MASK_AMOXOR_H);
    add_xamo_insn(this, "amomin.h",  MATCH_AMOMIN_H,  MASK_AMOMIN_H);
    add_xamo_insn(this, "amomax.h",  MATCH_AMOMAX_H,  MASK_AMOMAX_H);
    add_xamo_insn(this, "amominu.h", MATCH_AMOMINU_H, MASK_AMOMINU_H);
    add_xamo_insn(this, "amomaxu.h", MATCH_AMOMAXU_H, MASK_AMOMAXU_H);
    add_xamo_insn(this, "amocas.h",  MATCH_AMOCAS_H,  MASK_AMOCAS_H);
  }

  // zext.h: xlen-dependent match, cannot be in static table
  if (ext_enabled(EXT_ZBB))
    add_insn(new disasm_insn_t("zext.h",
      (isa->get_max_xlen() == 32 ? MATCH_PACK : MATCH_PACKW),
      MASK_PACK | (0x1fUL << 20), {&xrd, &xrs1}));

  // ZCMOP: some entries conditional on !Zicfiss
  if (ext_enabled(EXT_ZCMOP)) {
    if (!ext_enabled_strict(EXT_ZICFISS))
      add_insn(new disasm_insn_t("c.mop.1", MATCH_C_MOP_1, MASK_C_MOP_1, {}));
    add_insn(new disasm_insn_t("c.mop.3",  MATCH_C_MOP_3,  MASK_C_MOP_3,  {}));
    if (!ext_enabled_strict(EXT_ZICFISS))
      add_insn(new disasm_insn_t("c.mop.5", MATCH_C_MOP_5, MASK_C_MOP_5, {}));
    add_insn(new disasm_insn_t("c.mop.7",  MATCH_C_MOP_7,  MASK_C_MOP_7,  {}));
    add_insn(new disasm_insn_t("c.mop.9",  MATCH_C_MOP_9,  MASK_C_MOP_9,  {}));
    add_insn(new disasm_insn_t("c.mop.11", MATCH_C_MOP_11, MASK_C_MOP_11, {}));
    add_insn(new disasm_insn_t("c.mop.13", MATCH_C_MOP_13, MASK_C_MOP_13, {}));
    add_insn(new disasm_insn_t("c.mop.15", MATCH_C_MOP_15, MASK_C_MOP_15, {}));
  }

  // aes64ks1i and aes32 variants carry explicit args not expressible in fmt strings
  if (ext_enabled(EXT_ZKND) || ext_enabled(EXT_ZKNE))
    add_insn(new disasm_insn_t("aes64ks1i", MATCH_AES64KS1I, MASK_AES64KS1I, {&xrd, &xrs1, &rcon}));
  if (ext_enabled(EXT_ZKND) && xlen_eq(32)) {
    add_insn(new disasm_insn_t("aes32dsi",  MATCH_AES32DSI,  MASK_AES32DSI,  {&xrd, &xrs1, &xrs2, &bs}));
    add_insn(new disasm_insn_t("aes32dsmi", MATCH_AES32DSMI, MASK_AES32DSMI, {&xrd, &xrs1, &xrs2, &bs}));
  }
  if (ext_enabled(EXT_ZKNE) && xlen_eq(32)) {
    add_insn(new disasm_insn_t("aes32esi",  MATCH_AES32ESI,  MASK_AES32ESI,  {&xrd, &xrs1, &xrs2, &bs}));
    add_insn(new disasm_insn_t("aes32esmi", MATCH_AES32ESMI, MASK_AES32ESMI, {&xrd, &xrs1, &xrs2, &bs}));
  }

  // Zicfiss AMO variants
  if (ext_enabled(EXT_ZICFISS)) {
    add_xamo_insn(this, "ssamoswap.w", MATCH_SSAMOSWAP_W, MASK_SSAMOSWAP_W);
    if (xlen_eq(64))
      add_xamo_insn(this, "ssamoswap.d", MATCH_SSAMOSWAP_D, MASK_SSAMOSWAP_D);
  }

  add_vector_insns(this, isa, strict);
  add_zimop_insns(this, isa, strict);
}


disassembler_t::disassembler_t(const isa_parser_t *isa, bool strict)
{
  // highest priority: instructions explicitly enabled
  add_instructions(isa, true);

  if (!strict) {
    // next-highest priority: other instructions in same base ISA
    add_instructions(isa, false);

    // finally: instructions with known opcodes but unknown arguments
    add_unknown_insns(this);
  }

  // Now, reverse the lists, because we search them back-to-front (so that
  // custom instructions later added with add_insn have highest priority).
  for (size_t i = 0; i < HASH_SIZE+1; i++)
    std::reverse(chain[i].begin(), chain[i].end());
}

const disasm_insn_t* disassembler_t::probe_once(insn_t insn, size_t idx) const
{
  for (auto it = chain[idx].rbegin(); it != chain[idx].rend(); ++it)
    if (*(*it) == insn)
      return *it;

  return NULL;
}

const disasm_insn_t* disassembler_t::lookup(insn_t insn) const
{
  if (auto p = probe_once(insn, hash(insn.bits(), MASK1)))
    return p;

  if (auto p = probe_once(insn, hash(insn.bits(), MASK2)))
    return p;

  return probe_once(insn, HASH_SIZE);
}

void NOINLINE disassembler_t::add_insn(disasm_insn_t* insn)
{
  size_t idx =
    (insn->get_mask() & MASK1) == MASK1 ? hash(insn->get_match(), MASK1) :
    (insn->get_mask() & MASK2) == MASK2 ? hash(insn->get_match(), MASK2) :
    HASH_SIZE;

  chain[idx].push_back(insn);
}

disassembler_t::~disassembler_t()
{
  for (size_t i = 0; i < HASH_SIZE+1; i++)
    for (size_t j = 0; j < chain[i].size(); j++)
      delete chain[i][j];
}
