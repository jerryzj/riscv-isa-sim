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

std::string disassembler_t::disassemble(insn_t insn) const
{
  const disasm_insn_t* disasm_insn = lookup(insn);
  return disasm_insn ? disasm_insn->to_string(insn) : "unknown";
}



// ---------------------------------------------------------------------------
// insn_class: extension conditions for the flat opcode table.
// Mirrors binutils' riscv_insn_class — each value names the ISA subset that
// must be active. insn_class_enabled() performs the actual check.
// ---------------------------------------------------------------------------
enum class insn_class : uint8_t {
  ALWAYS = 0,       // no extension required
  RV64,             // xlen_eq(64)
  RV32,             // xlen_eq_strict(32) — no !strict fallback on xlen
  ZALRSC,           // EXT_ZALRSC
  ZALRSC_RV64,      // EXT_ZALRSC + RV64
  ZACAS_RV64,       // EXT_ZACAS + RV64
  ZAWRS,            ZICFILP,
  EXT_S,
  EXT_M,            EXT_M_RV64,
  ZBA,              ZBA_RV64,
  ZBB,              ZBB_RV32,       // EXT_ZBB + xlen==32 (zext.h uses MATCH_PACK)
                    ZBB_RV64,       // EXT_ZBB + RV64    (zext.h uses MATCH_PACKW)
  ZBC,              ZBS,
  ZBKB,             ZBKB_RV64,
  SVINVAL,
  EXT_F,
  F_OR_ZFINX,       F_OR_ZFINX_RV64,
  EXT_D,            D_RV64,
  D_OR_ZDINX,       D_OR_ZDINX_RV64,
  ZFA,
  ZFA_ZFH,          // EXT_ZFA + (EXT_ZFH || EXT_ZVFH)
  ZFA_D,            // EXT_ZFA + 'D'
  ZFA_D_RV32,       // EXT_ZFA + 'D' + xlen_strict==32
  ZFA_Q,            // EXT_ZFA + 'Q'
  ZFA_Q_RV64,       // EXT_ZFA + 'Q' + RV64
  ZFH,              ZHINX,
  ZFHMIN,           ZFH_MOVE,
  ZHINXMIN,         ZIBI,
  EXT_Q,            ZFBFMIN,
  EXT_H,
  ZCA,
  ZCA_RV32,         // EXT_ZCA + xlen_strict==32
  ZCA_NOT_RV32,     // EXT_ZCA + xlen != 32 (c.addiw)
  ZCA_RV64,
  ZCA_LD,           // EXT_ZCA + (xlen_strict==64 || EXT_ZCLSD_strict)
  ZCD,              ZCF,
  ZCB,              ZCB_RV64,
  ZCMP_RV32,        // EXT_ZCMP + xlen_strict==32
  ZCMP_NOT_RV32,    // EXT_ZCMP + xlen != 32
  ZCMP,             ZCMT,
  ZCMOP,              // EXT_ZCMOP
  ZCMOP_NO_ZICFISS,   // EXT_ZCMOP + !EXT_ZICFISS_strict (those encodings reused by Zicfiss)
  ZMMUL,            ZMMUL_RV64,
  ZICBOM,           ZICBOZ,   ZICOND,
  ZKND_OR_ZKNE,     // EXT_ZKND || EXT_ZKNE (for aes64ks1i/aes64ks2)
  ZKND_RV64,        ZKNE_RV64,
  ZKND_RV32,        // EXT_ZKND + xlen==32 (for aes32dsi/dsmi)
  ZKNE_RV32,        // EXT_ZKNE + xlen==32 (for aes32esi/esmi)
  ZKNH,             ZKNH_RV64,   ZKNH_RV32,
  ZKSED,            ZKSH,
  ZALASR,
  ZAAMO,            // EXT_ZAAMO
  ZAAMO_RV64,       // EXT_ZAAMO + RV64
  ZACAS,            // EXT_ZACAS (amocas.w/d, any xlen)
  ZABHA,            // EXT_ZABHA
  ZIMOP,            // EXT_ZIMOP
  VECTOR,            // isa->has_any_vector() || !strict
  ZVQDOTQ,
  ZVFOFP4MIN,  ZVFOFP8MIN,
  ZVFBFMIN,    ZVFBFWMA,
  ZVABD,       ZVZIP,
  ZVBB,        ZVBC,
  ZVKG,        ZVKNED,
  ZVKNH,       // EXT_ZVKNHA || EXT_ZVKNHB
  ZVKSED,      ZVKSH,
  ZICFISS,
  ZICFISS_RV64,     // EXT_ZICFISS + RV64 (for ssamoswap.d)
  ZICFISS_ZCA,      // EXT_ZICFISS + EXT_ZCA
  EXT_P,
  EXT_P_RV32,       // EXT_P + xlen_strict==32
  EXT_P_RV64,       // EXT_P + RV64
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
    case ic::ALWAYS:          return true;
    case ic::RV64:            return xv(64);
    case ic::RV32:            return xvs(32);
    case ic::ZALRSC:          return ext(EXT_ZALRSC);
    case ic::ZALRSC_RV64:     return ext(EXT_ZALRSC)  && xv(64);
    case ic::ZACAS_RV64:      return ext(EXT_ZACAS)   && xv(64);
    case ic::ZAWRS:           return ext(EXT_ZAWRS);
    case ic::ZICFILP:         return ext(EXT_ZICFILP);
    case ic::EXT_S:           return ext('S');
    case ic::EXT_M:           return ext('M');
    case ic::EXT_M_RV64:      return ext('M')        && xv(64);
    case ic::ZBA:             return ext(EXT_ZBA);
    case ic::ZBA_RV64:        return ext(EXT_ZBA)      && xv(64);
    case ic::ZBB:             return ext(EXT_ZBB);
    case ic::ZBB_RV32:        return ext(EXT_ZBB)      && xv(32);
    case ic::ZBB_RV64:        return ext(EXT_ZBB)      && xv(64);
    case ic::ZBC:             return ext(EXT_ZBC);
    case ic::ZBS:             return ext(EXT_ZBS);
    case ic::ZBKB:            return ext(EXT_ZBKB);
    case ic::ZBKB_RV64:       return ext(EXT_ZBKB)     && xv(64);
    case ic::SVINVAL:         return ext(EXT_SVINVAL);
    case ic::EXT_F:           return ext('F');
    case ic::F_OR_ZFINX:      return ext2('F', EXT_ZFINX);
    case ic::F_OR_ZFINX_RV64: return ext2('F', EXT_ZFINX) && xv(64);
    case ic::EXT_D:           return ext('D');
    case ic::D_RV64:          return ext('D')         && xv(64);
    case ic::D_OR_ZDINX:      return ext2('D', EXT_ZDINX);
    case ic::D_OR_ZDINX_RV64: return ext2('D', EXT_ZDINX) && xv(64);
    case ic::ZFA:             return ext(EXT_ZFA);
    case ic::ZFA_ZFH:         return ext(EXT_ZFA) && (isa->extension_enabled(EXT_ZFH) || isa->extension_enabled(EXT_ZVFH) || !s);
    case ic::ZFA_D:           return ext(EXT_ZFA) && ext('D');
    case ic::ZFA_D_RV32:      return (ext(EXT_ZFA) || !s) && ext('D') && xvs(32);
    case ic::ZFA_Q:           return ext(EXT_ZFA) && ext('Q');
    case ic::ZFA_Q_RV64:      return ext(EXT_ZFA) && ext('Q') && xv(64);
    case ic::ZFH:             return ext(EXT_ZFH);
    case ic::ZHINX:           return ext(EXT_ZHINX);
    case ic::ZFHMIN:          return ext(EXT_ZFHMIN);
    case ic::ZFH_MOVE:        return ext(EXT_INTERNAL_ZFH_MOVE);
    case ic::ZHINXMIN:        return ext(EXT_ZHINXMIN);
    case ic::ZIBI:            return ext(EXT_ZIBI);
    case ic::EXT_Q:           return ext('Q');
    case ic::ZFBFMIN:         return ext(EXT_ZFBFMIN);
    case ic::EXT_H:           return ext('H');
    case ic::ZCA:             return ext(EXT_ZCA);
    case ic::ZCA_RV32:        return (ext(EXT_ZCA) || !s) && xvs(32);
    case ic::ZCA_NOT_RV32:    return (ext(EXT_ZCA) || !s) && !xvs(32);
    case ic::ZCA_RV64:        return ext(EXT_ZCA)     && xv(64);
    case ic::ZCA_LD:          return (ext(EXT_ZCA) || !s) && (xvs(64) || isa->extension_enabled(EXT_ZCLSD));
    case ic::ZCD:             return ext(EXT_ZCD);
    case ic::ZCF:             return ext(EXT_ZCF);
    case ic::ZCB:             return ext(EXT_ZCB);
    case ic::ZCB_RV64:        return ext(EXT_ZCB)     && xv(64);
    case ic::ZCMP_RV32:       return (ext(EXT_ZCMP) || !s) && xvs(32);
    case ic::ZCMP_NOT_RV32:   return (ext(EXT_ZCMP) || !s) && !xvs(32);
    case ic::ZCMP:              return ext(EXT_ZCMP);
    case ic::ZCMT:              return ext(EXT_ZCMT);
    case ic::ZCMOP:             return ext(EXT_ZCMOP);
    case ic::ZCMOP_NO_ZICFISS:  return ext(EXT_ZCMOP) && !isa->extension_enabled(EXT_ZICFISS);
    case ic::ZMMUL:             return ext(EXT_ZMMUL);
    case ic::ZMMUL_RV64:      return ext(EXT_ZMMUL)   && xv(64);
    case ic::ZICBOM:          return ext(EXT_ZICBOM);
    case ic::ZICBOZ:          return ext(EXT_ZICBOZ);
    case ic::ZICOND:          return ext(EXT_ZICOND);
    case ic::ZKND_OR_ZKNE:    return isa->extension_enabled(EXT_ZKND) || isa->extension_enabled(EXT_ZKNE) || !s;
    case ic::ZKND_RV64:       return ext(EXT_ZKND)    && xv(64);
    case ic::ZKNE_RV64:       return ext(EXT_ZKNE)    && xv(64);
    case ic::ZKND_RV32:       return ext(EXT_ZKND)    && xv(32);
    case ic::ZKNE_RV32:       return ext(EXT_ZKNE)    && xv(32);
    case ic::ZAAMO:           return ext(EXT_ZAAMO);
    case ic::ZAAMO_RV64:      return ext(EXT_ZAAMO)    && xv(64);
    case ic::ZACAS:           return ext(EXT_ZACAS);
    case ic::ZABHA:           return ext(EXT_ZABHA);
    case ic::ZIMOP:           return ext(EXT_ZIMOP);
    case ic::ZICFISS_RV64:    return ext(EXT_ZICFISS)  && xv(64);
    case ic::ZKNH:            return ext(EXT_ZKNH);
    case ic::ZKNH_RV64:       return ext(EXT_ZKNH)    && xv(64);
    case ic::ZKNH_RV32:       return ext(EXT_ZKNH)    && xv(32);
    case ic::ZKSED:           return ext(EXT_ZKSED);
    case ic::ZKSH:            return ext(EXT_ZKSH);
    case ic::ZALASR:          return ext(EXT_ZALASR);
    case ic::VECTOR:          return isa->has_any_vector() || !s;
    case ic::ZVQDOTQ:         return ext(EXT_ZVQDOTQ);
    case ic::ZVFOFP4MIN:      return ext(EXT_ZVFOFP4MIN);
    case ic::ZVFOFP8MIN:      return ext(EXT_ZVFOFP8MIN);
    case ic::ZVFBFMIN:        return ext(EXT_ZVFBFMIN);
    case ic::ZVFBFWMA:        return ext(EXT_ZVFBFWMA);
    case ic::ZVABD:           return ext(EXT_ZVABD);
    case ic::ZVZIP:           return ext(EXT_ZVZIP);
    case ic::ZVBB:            return ext(EXT_ZVBB);
    case ic::ZVBC:            return ext(EXT_ZVBC);
    case ic::ZVKG:            return ext(EXT_ZVKG);
    case ic::ZVKNED:          return ext(EXT_ZVKNED);
    case ic::ZVKNH:           return isa->extension_enabled(EXT_ZVKNHA) || isa->extension_enabled(EXT_ZVKNHB) || !s;
    case ic::ZVKSED:          return ext(EXT_ZVKSED);
    case ic::ZVKSH:           return ext(EXT_ZVKSH);
    case ic::ZICFISS:         return ext(EXT_ZICFISS);
    case ic::ZICFISS_ZCA:     return ext(EXT_ZICFISS) && ext(EXT_ZCA);
    case ic::EXT_P:           return ext('P');
    case ic::EXT_P_RV32:      return (ext('P') || !s) && xvs(32);
    case ic::EXT_P_RV64:      return ext('P')        && xv(64);
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

// Explicit format-character → arg_t* mapping table.
// This struct array is the definitive reference for all format characters —
// the lookup array is derived from it, so there is no hidden mapping elsewhere.
// '?' is the optional-argument marker and is handled separately in parse_fmt.
static const struct { char code; const arg_t *arg; } fmt_chars[] = {
  // Integer registers (follows binutils riscv-dis.c convention)
  {'d', &xrd},    // rd   — integer destination
  {'s', &xrs1},   // rs1  — integer source 1
  {'t', &xrs2},   // rs2  — integer source 2
  {'r', &xrs3},   // rs3  — integer source 3 (R4-type, e.g. fmadd)
  // Floating-point registers
  {'D', &frd},    // frd  — FP destination
  {'S', &frs1},   // frs1 — FP source 1
  {'T', &frs2},   // frs2 — FP source 2
  {'R', &frs3},   // frs3 — FP source 3 (FP fused multiply-add)
  // Vector registers
  {'A', &vd},     // vd   — VECTOR destination
  {'B', &vs1},    // vs1  — VECTOR source 1
  {'C', &vs2},    // vs2  — VECTOR source 2
  {'G', &vs3},    // vs3  — VECTOR source 3 (VECTOR store data)
  // P-extension register pairs (even-numbered registers)
  {'P', &xrd_p},  // rdp  — integer register pair destination
  {'Q', &xrs1_p}, // rs1p — integer register pair source 1
  {'U', &xrs2_p}, // rs2p — integer register pair source 2
  // Immediates — standard
  {'j', &imm},       // I-type signed immediate (addi, lw, jalr, ...)
  {'Z', &shamt},     // shift amount (slli, srli, srai, ...)
  {'u', &bigimm},    // U-type upper immediate >> 12, hex (lui, auipc)
  {'z', &zimm5},     // zero-extended 5-bit immediate (CSR uimm, vsetivli)
  // Immediates — VECTOR
  {'5', &v_simm5},   // VECTOR signed 5-bit immediate
  {'6', &v_zimm6},   // VECTOR zero-extended 6-bit immediate (Zvbb ror/vror)
  {'L', &fli_imm},   // FLI float-constant index (Zfa fli.s/d/h)
  {'W', &v_vtype},   // vtype field (vsetvli, vsetivli)
  // Immediates — branch/jump targets
  {'p', &branch_target}, // B-type PC-relative branch target
  {'a', &jump_target},   // J-type PC-relative jump target (jal)
  // Immediates — other
  {'>', &b_imm5},    // branch immediate (Zibi beqi/bnei)
  // Immediates — P-extension
  {'7', &p_imm8},       // packed 8-bit immediate
  {'$', &p_imm10csl},   // packed 10-bit immediate (left-shift)
  {'%', &p_imm10csr},   // packed 10-bit immediate (right-shift)
  {'&', &p_imm10csrw},  // packed 10-bit immediate (right-shift, wider)
  // Shamt variants (width-specific shift amounts for P-extension)
  {'\'', &shamtd},  // 64-bit shamt
  {'<',  &shamtw},  // 32-bit shamt
  {';',  &shamth},  // 16-bit shamt
  {':',  &shamtb},  // 8-bit  shamt
  // Scalar crypto arguments
  {'-', &bs},    // AES byte-select (aes32dsi, aes32esi, sm4ed, sm4ks)
  {'+', &rcon},  // AES round constant (aes64ks1i)
  // Memory addresses
  {'o', &load_address},       // imm(rs1)  — load  offset+base
  {'q', &store_address},      // imm(rs1)  — store offset+base
  {'(', &base_only_address},  // (rs1)     — base-only (AMO, VECTOR)
  // CSR / special
  {'E', &csr},            // CSR register number
  {'m', &rm},             // floating-point rounding mode
  {'I', &iorw},           // fence predecessor/successor bits
  {'0', &x0},             // literal x0 (vmv.x.s, vmv.s.x)
  // Vector mask operands
  {'k', &vm},   // optional mask (v0.t or absent)
  {'K', &v0},   // literal v0 (vadc, vsbc, vmerge destination mask)
  // RVC — full-width registers (5-bit fields in CR/CI formats)
  {'e', &rvc_rs1},     // rs1  5-bit (c.jr, c.jalr, c.slli, ...)
  {'f', &rvc_rs2},     // rs2  5-bit (c.mv, c.add, c.swsp, ...)
  {'F', &rvc_fp_rs2},  // frs2 5-bit (c.fswsp, c.fsdsp)
  // RVC — compressed registers (3-bit CL/CS/CA/CB fields, offset by 8)
  {'H', &rvc_rs1s},    // rs1' 3-bit (c.lw, c.sw, c.add, c.sub, ...)
  {'J', &rvc_rs2s},    // rs2' 3-bit
  {'#', &rvc_fp_rs2s}, // frs2' 3-bit (c.flw, c.fld, ...)
  // RVC — fixed-register aliases
  {'N', &rvc_sp},   // x2  (sp)  — c.lwsp, c.ldsp, c.addi16sp
  {'X', &rvc_ra},   // x1  (ra)  — c.sspush
  {'Y', &rvc_t0},   // x5  (t0)  — c.sspopchk
  {'V', &rvc_r1s},  // first  register of cm.mva01s / cm.mvsa01
  {'O', &rvc_r2s},  // second register of cm.mva01s / cm.mvsa01
  // RVC — immediates
  {'i', &rvc_imm},             // general nzimm6
  {'n', &rvc_addi4spn_imm},    // c.addi4spn (nzuimm8)
  {'x', &rvc_addi16sp_imm},    // c.addi16sp (nzimm10)
  {'l', &rvc_lwsp_imm},        // c.lwsp (uimm6)
  {'h', &rvc_shamt},           // c.slli/c.srli/c.srai shamt
  {'b', &rvc_uimm},            // c.lui upper immediate
  // RVC — memory addresses
  {'@', &rvc_lwsp_address},  // uimm6(sp) — c.lwsp
  {'M', &rvc_ldsp_address},  // uimm6(sp) — c.ldsp
  {'_', &rvc_swsp_address},  // uimm6(sp) — c.swsp
  {'g', &rvc_sdsp_address},  // uimm6(sp) — c.sdsp
  {'c', &rvc_lw_address},    // uimm5(rs1') — c.lw / c.sw
  {'v', &rvc_ld_address},    // uimm5(rs1') — c.ld / c.sd
  // RVC — branch/jump targets
  {'y', &rvc_branch_target}, // c.beqz / c.bnez target
  {'w', &rvc_jump_target},   // c.j target
  // Zcmp push/pop
  {'1', &rvcm_jt_index},          // cm.jt / cm.jalt index
  {'!', &rvcm_pushpop_rlist},     // {ra, s0-sN} register list
  {'2', &rvcm_push_stack_adj_32}, // stack adjustment (push, RV32)
  {'4', &rvcm_push_stack_adj_64}, // stack adjustment (push, RV64)
  {'3', &rvcm_pop_stack_adj_32},  // stack adjustment (pop,  RV32)
  {'8', &rvcm_pop_stack_adj_64},  // stack adjustment (pop,  RV64)
  // Zcb byte/halfword addresses
  {'*', &rvb_b_address}, // byte-scaled offset (c.lbu, c.sb)
  {'/', &rvb_h_address}, // halfword-scaled offset (c.lhu, c.lh, c.sh)
};

// Build an O(1) lookup array from the explicit fmt_chars table above.
static const arg_t *fmt_char_to_arg(char c)
{
  static const auto lut = []() {
    std::array<const arg_t*, 128> t{};
    for (const auto& e : fmt_chars) {
      assert(t[(uint8_t)e.code] == nullptr && "duplicate format character");
      t[(uint8_t)e.code] = e.arg;
    }
    return t;
  }();
  return static_cast<unsigned char>(c) < 128 ? lut[static_cast<unsigned char>(c)] : nullptr;
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

// Vector segment/element-width encoding constants
// SEG(n): encodes n segments into the nf field (bits 31:29); seg2 → NF=1, seg8 → NF=7
static constexpr uint32_t SEG(unsigned n) { return (n-1U) << 29; }
static constexpr uint32_t MASK_NF  = 0x7U << 29;   // nf field mask
static constexpr uint32_t EW16   = 0x00005000U;  // eew=101
static constexpr uint32_t EW32   = 0x00006000U;  // eew=110
static constexpr uint32_t EW64   = 0x00007000U;  // eew=111
static constexpr uint32_t EW128  = 0x10000000U;  // mew=1, eew=000
static constexpr uint32_t EW256  = 0x10005000U;  // mew=1, eew=101
static constexpr uint32_t EW512  = 0x10006000U;  // mew=1, eew=110
static constexpr uint32_t EW1024 = 0x10007000U;  // mew=1, eew=111

// Register-field match constants: encode a specific register number into a field.
static constexpr uint32_t MATCH_RD_RA  = 1U << 7;   // rd = x1 (ra)
static constexpr uint32_t MATCH_RS1_RA = 1U << 15;  // rs1 = x1 (ra)

// AMO ordering bits (bit 26 = aq, bit 25 = rl), like binutils OP_MASK_AQ/RL
static constexpr uint32_t MASK_RL   = 1U << 25; // release bit
static constexpr uint32_t MASK_AQ   = 1U << 26; // acquire bit
static constexpr uint32_t MASK_AQRL = MASK_AQ | MASK_RL; // both aq+rl bits

// Field mask constants (like binutils MASK_RS2 defined in riscv-opc.c).
// Used in all_insns[] to add extra match constraints for pseudo-instructions.
static constexpr uint32_t MASK_RD  = 0x1fU << 7;    // bits 11:7  (rd field)
static constexpr uint32_t MASK_RS1 = 0x1fU << 15;   // bits 19:15 (rs1 field)
static constexpr uint32_t MASK_RS2 = 0x1fU << 20;   // bits 24:20 (rs2 field)
static constexpr uint32_t MASK_IMM = 0xfffU << 20;  // bits 31:20 (I-type imm)
// Compressed instruction field masks
static constexpr uint32_t MASK_CRS2    = 0x1fU << 2;             // bits 6:2
static constexpr uint32_t MASK_CNZIMM6 = MASK_CRS2 | (1U << 12); // nzimm6 field

// C++20: import insn_class enumerators into file scope for the table below
using enum insn_class;

// Single flat opcode table (like binutils riscv_opcodes[]).
// Entry order determines disassembly priority (first = highest after reversal).
static const disasm_opcode_t all_insns[] = {
  // highest-priority exact matches
  {"unimp",   uint32_t(MATCH_CSRRW|(CSR_CYCLE<<20)), 0xffffffff,  "", ALWAYS},
  {"c.unimp", 0,                           0xffff,                "", ALWAYS},
  // prefetch_insns
  {"prefetch_r", MATCH_PREFETCH_R, MASK_PREFETCH_R, "q", ALWAYS},
  {"prefetch_w", MATCH_PREFETCH_W, MASK_PREFETCH_W, "q", ALWAYS},
  {"prefetch_i", MATCH_PREFETCH_I, MASK_PREFETCH_I, "q", ALWAYS},
  {"pause",      MATCH_PAUSE,      MASK_PAUSE,      "", ALWAYS},
  // base_load_store_insns
  {"lb",  MATCH_LB,  MASK_LB,  "do", ALWAYS},
  {"lbu", MATCH_LBU, MASK_LBU, "do", ALWAYS},
  {"lh",  MATCH_LH,  MASK_LH,  "do", ALWAYS},
  {"lhu", MATCH_LHU, MASK_LHU, "do", ALWAYS},
  {"lw",  MATCH_LW,  MASK_LW,  "do", ALWAYS},
  {"sb",  MATCH_SB,  MASK_SB,  "tq", ALWAYS},
  {"sh",  MATCH_SH,  MASK_SH,  "tq", ALWAYS},
  {"sw",  MATCH_SW,  MASK_SW,  "tq", ALWAYS},
  // rv64_load_store_insns
  {"lwu", MATCH_LWU, MASK_LWU, "do", RV64},
  {"ld",  MATCH_LD,  MASK_LD,  "do", RV64},
  {"sd",  MATCH_SD,  MASK_SD,  "tq", RV64},
  // zalrsc_insns
  {"lr.w", MATCH_LR_W, MASK_LR_W, "d(", ZALRSC},
  // zalrsc64_insns
  {"lr.d", MATCH_LR_D, MASK_LR_D, "d(", ZALRSC_RV64},
  // zacas64_insns
  // amocas.q handled by add_xamo_insn in add_instructions
  // zawrs_insns
  {"wrs_sto", MATCH_WRS_STO, MASK_WRS_STO, "", ZAWRS},
  {"wrs_nto", MATCH_WRS_NTO, MASK_WRS_NTO, "", ZAWRS},
  // zicfilp_insns
  {"lpad", MATCH_LPAD, MASK_LPAD, "u", ZICFILP},
  // jump_insns
  {"j",    MATCH_JAL,              MASK_JAL | MASK_RD,             "a", ALWAYS},
  {"jal",  MATCH_JAL | MATCH_RD_RA,     MASK_JAL | MASK_RD,             "a", ALWAYS},
  {"jal",  MATCH_JAL,             MASK_JAL,                       "da", ALWAYS},
  {"ret",  MATCH_JALR | MATCH_RS1_RA,  MASK_JALR | MASK_RD | MASK_RS1 | MASK_IMM, "", ALWAYS},
  {"jr",   MATCH_JALR,            MASK_JALR | MASK_RD | MASK_IMM, "s", ALWAYS},
  {"jalr", MATCH_JALR | MATCH_RD_RA,   MASK_JALR | MASK_RD | MASK_IMM, "s", ALWAYS},
  {"jalr", MATCH_JALR,            MASK_JALR,                        "dsj", ALWAYS},
  // branch_insns
  {"beqz", MATCH_BEQ, MASK_BEQ | MASK_RS2, "sp", ALWAYS},
  {"bnez", MATCH_BNE, MASK_BNE | MASK_RS2, "sp", ALWAYS},
  {"bltz", MATCH_BLT, MASK_BLT | MASK_RS2, "sp", ALWAYS},
  {"bgez", MATCH_BGE, MASK_BGE | MASK_RS2, "sp", ALWAYS},
  {"beq",  MATCH_BEQ, MASK_BEQ,  "stp", ALWAYS},
  {"bne",  MATCH_BNE, MASK_BNE,  "stp", ALWAYS},
  {"blt",  MATCH_BLT, MASK_BLT,  "stp", ALWAYS},
  {"bge",  MATCH_BGE, MASK_BGE,  "stp", ALWAYS},
  {"bltu", MATCH_BLTU, MASK_BLTU, "stp", ALWAYS},
  {"bgeu", MATCH_BGEU, MASK_BGEU, "stp", ALWAYS},
  // utype_insns
  {"lui",   MATCH_LUI,   MASK_LUI,   "du", ALWAYS},
  {"auipc", MATCH_AUIPC, MASK_AUIPC, "du", ALWAYS},
  // base_int_insns
  // nop: addi x0,x0,0
  {"nop",  MATCH_ADDI, MASK_ADDI | MASK_RD | MASK_RS1 | MASK_IMM, "", ALWAYS},
  // li: addi rd, x0, imm  (mask_rs1 = 0xf8000 locks rs1=0)
  {"li",   MATCH_ADDI, MASK_ADDI | MASK_RS1, "dj", ALWAYS},
  // mv: addi rd, rs1, 0  (mask_imm locks imm=0)
  {"mv",   MATCH_ADDI, MASK_ADDI | MASK_IMM, "ds", ALWAYS},
  {"addi", MATCH_ADDI, MASK_ADDI, "dsj", ALWAYS},
  {"slti", MATCH_SLTI, MASK_SLTI, "dsj", ALWAYS},
  // seqz: sltiu rd, rs1, 1
  {"seqz", MATCH_SLTIU | (1u << 20), MASK_SLTIU | MASK_IMM, "ds", ALWAYS},
  {"sltiu", MATCH_SLTIU, MASK_SLTIU, "dsj", ALWAYS},
  // not: xori rd, rs1, -1  (imm=0xfff=-1)
  {"not",  MATCH_XORI | MASK_IMM, MASK_XORI | MASK_IMM, "ds", ALWAYS},
  {"xori", MATCH_XORI, MASK_XORI, "dsj", ALWAYS},
  {"slli", MATCH_SLLI, MASK_SLLI, "dsZ", ALWAYS},
  {"srli", MATCH_SRLI, MASK_SRLI, "dsZ", ALWAYS},
  {"srai", MATCH_SRAI, MASK_SRAI, "dsZ", ALWAYS},
  {"ori",  MATCH_ORI,  MASK_ORI,  "dsj", ALWAYS},
  {"andi", MATCH_ANDI, MASK_ANDI, "dsj", ALWAYS},
  {"add",  MATCH_ADD,  MASK_ADD,  "dst", ALWAYS},
  {"sub",  MATCH_SUB,  MASK_SUB,  "dst", ALWAYS},
  {"sll",  MATCH_SLL,  MASK_SLL,  "dst", ALWAYS},
  {"slt",  MATCH_SLT,  MASK_SLT,  "dst", ALWAYS},
  // snez: sltu rd, x0, rs2  (mask_rs1 locks rs1=0)
  {"snez", MATCH_SLTU, MASK_SLTU | MASK_RS1, "dt", ALWAYS},
  {"sltu", MATCH_SLTU, MASK_SLTU, "dst", ALWAYS},
  {"xor",  MATCH_XOR,  MASK_XOR,  "dst", ALWAYS},
  {"srl",  MATCH_SRL,  MASK_SRL,  "dst", ALWAYS},
  {"sra",  MATCH_SRA,  MASK_SRA,  "dst", ALWAYS},
  {"or",   MATCH_OR,   MASK_OR,   "dst", ALWAYS},
  {"and",  MATCH_AND,  MASK_AND,  "dst", ALWAYS},
  // rv64_int_insns
  // sext.w: addiw rd, rs1, 0
  {"sext.w", MATCH_ADDIW, MASK_ADDIW | MASK_IMM, "ds", RV64},
  {"addiw",  MATCH_ADDIW, MASK_ADDIW, "dsj", RV64},
  {"slliw",  MATCH_SLLIW, MASK_SLLIW, "dsZ", RV64},
  {"srliw",  MATCH_SRLIW, MASK_SRLIW, "dsZ", RV64},
  {"sraiw",  MATCH_SRAIW, MASK_SRAIW, "dsZ", RV64},
  {"addw",   MATCH_ADDW,  MASK_ADDW,  "dst", RV64},
  {"subw",   MATCH_SUBW,  MASK_SUBW,  "dst", RV64},
  {"sllw",   MATCH_SLLW,  MASK_SLLW,  "dst", RV64},
  {"srlw",   MATCH_SRLW,  MASK_SRLW,  "dst", RV64},
  {"sraw",   MATCH_SRAW,  MASK_SRAW,  "dst", RV64},
  // system_insns
  {"ecall",   MATCH_ECALL,   MASK_ECALL,   "", ALWAYS},
  {"ebreak",  MATCH_EBREAK,  MASK_EBREAK,  "", ALWAYS},
  {"mret",    MATCH_MRET,    MASK_MRET,    "", ALWAYS},
  {"dret",    MATCH_DRET,    MASK_DRET,    "", ALWAYS},
  {"wfi",     MATCH_WFI,     MASK_WFI,     "", ALWAYS},
  {"fence",   MATCH_FENCE,   MASK_FENCE,   "I", ALWAYS},
  {"fence.i", MATCH_FENCE_I, MASK_FENCE_I, "", ALWAYS},
  // CSR pseudo-instructions (more specific masks first)
  {"csrr",  MATCH_CSRRS,  MASK_CSRRS  | MASK_RS1,    "dE", ALWAYS},
  {"csrw",  MATCH_CSRRW,  MASK_CSRRW  | MASK_RD,      "Es", ALWAYS},
  {"csrs",  MATCH_CSRRS,  MASK_CSRRS  | MASK_RD,      "Es", ALWAYS},
  {"csrc",  MATCH_CSRRC,  MASK_CSRRC  | MASK_RD,      "Es", ALWAYS},
  {"csrwi", MATCH_CSRRWI, MASK_CSRRWI | MASK_RD,      "Ez", ALWAYS},
  {"csrsi", MATCH_CSRRSI, MASK_CSRRSI | MASK_RD,      "Ez", ALWAYS},
  {"csrci", MATCH_CSRRCI, MASK_CSRRCI | MASK_RD,      "Ez", ALWAYS},
  {"csrrw",  MATCH_CSRRW,  MASK_CSRRW,  "dEs", ALWAYS},
  {"csrrs",  MATCH_CSRRS,  MASK_CSRRS,  "dEs", ALWAYS},
  {"csrrc",  MATCH_CSRRC,  MASK_CSRRC,  "dEs", ALWAYS},
  {"csrrwi", MATCH_CSRRWI, MASK_CSRRWI, "dEz", ALWAYS},
  {"csrrsi", MATCH_CSRRSI, MASK_CSRRSI, "dEz", ALWAYS},
  {"csrrci", MATCH_CSRRCI, MASK_CSRRCI, "dEz", ALWAYS},
  // s_ext_insns
  {"sret",       MATCH_SRET,       MASK_SRET,       "", EXT_S},
  {"sfence.vma", MATCH_SFENCE_VMA, MASK_SFENCE_VMA, "st", EXT_S},
  // m_ext_insns
  {"mul",    MATCH_MUL,    MASK_MUL,    "dst", EXT_M},
  {"mulh",   MATCH_MULH,   MASK_MULH,   "dst", EXT_M},
  {"mulhu",  MATCH_MULHU,  MASK_MULHU,  "dst", EXT_M},
  {"mulhsu", MATCH_MULHSU, MASK_MULHSU, "dst", EXT_M},
  {"div",    MATCH_DIV,    MASK_DIV,    "dst", EXT_M},
  {"divu",   MATCH_DIVU,   MASK_DIVU,   "dst", EXT_M},
  {"rem",    MATCH_REM,    MASK_REM,    "dst", EXT_M},
  {"remu",   MATCH_REMU,   MASK_REMU,   "dst", EXT_M},
  // m_ext64_insns
  {"mulw",  MATCH_MULW,  MASK_MULW,  "dst", EXT_M_RV64},
  {"divw",  MATCH_DIVW,  MASK_DIVW,  "dst", EXT_M_RV64},
  {"divuw", MATCH_DIVUW, MASK_DIVUW, "dst", EXT_M_RV64},
  {"remw",  MATCH_REMW,  MASK_REMW,  "dst", EXT_M_RV64},
  {"remuw", MATCH_REMUW, MASK_REMUW, "dst", EXT_M_RV64},
  // zba_insns
  {"sh1add", MATCH_SH1ADD, MASK_SH1ADD, "dst", ZBA},
  {"sh2add", MATCH_SH2ADD, MASK_SH2ADD, "dst", ZBA},
  {"sh3add", MATCH_SH3ADD, MASK_SH3ADD, "dst", ZBA},
  // zba64_insns
  {"slli.uw", MATCH_SLLI_UW, MASK_SLLI_UW, "dsZ", ZBA_RV64},
  // zext.w: add.uw rd, rs1, zero  (mask_rs2 locks rs2=0)
  {"zext.w",  MATCH_ADD_UW, MASK_ADD_UW | MASK_RS2, "ds", ZBA_RV64},
  {"add.uw",  MATCH_ADD_UW,  MASK_ADD_UW,  "dst", ZBA_RV64},
  {"sh1add.uw", MATCH_SH1ADD_UW, MASK_SH1ADD_UW, "dst", ZBA_RV64},
  {"sh2add.uw", MATCH_SH2ADD_UW, MASK_SH2ADD_UW, "dst", ZBA_RV64},
  {"sh3add.uw", MATCH_SH3ADD_UW, MASK_SH3ADD_UW, "dst", ZBA_RV64},
  // zbb_insns
  {"ror",    MATCH_ROR,    MASK_ROR,    "dst", ZBB},
  {"rol",    MATCH_ROL,    MASK_ROL,    "dst", ZBB},
  {"rori",   MATCH_RORI,   MASK_RORI,   "dsZ", ZBB},
  {"ctz",    MATCH_CTZ,    MASK_CTZ,    "ds", ZBB},
  {"clz",    MATCH_CLZ,    MASK_CLZ,    "ds", ZBB},
  {"cpop",   MATCH_CPOP,   MASK_CPOP,   "ds", ZBB},
  {"min",    MATCH_MIN,    MASK_MIN,    "dst", ZBB},
  {"minu",   MATCH_MINU,   MASK_MINU,   "dst", ZBB},
  {"max",    MATCH_MAX,    MASK_MAX,    "dst", ZBB},
  {"maxu",   MATCH_MAXU,   MASK_MAXU,   "dst", ZBB},
  {"andn",   MATCH_ANDN,   MASK_ANDN,   "dst", ZBB},
  {"orn",    MATCH_ORN,    MASK_ORN,    "dst", ZBB},
  {"xnor",   MATCH_XNOR,   MASK_XNOR,   "dst", ZBB},
  {"sext.b", MATCH_SEXT_B, MASK_SEXT_B, "ds", ZBB},
  {"sext.h", MATCH_SEXT_H, MASK_SEXT_H, "ds", ZBB},
  {"rev8",   MATCH_REV8,   MASK_REV8,   "ds", ZBB},
  {"orc.b",  MATCH_ORC_B,  MASK_ORC_B,  "ds", ZBB},
  // zbb64_insns
  {"rorw",  MATCH_RORW,  MASK_RORW,  "dst", ZBB_RV64},
  {"rolw",  MATCH_ROLW,  MASK_ROLW,  "dst", ZBB_RV64},
  {"roriw", MATCH_RORIW, MASK_RORIW, "dsZ", ZBB_RV64},
  {"ctzw",  MATCH_CTZW,  MASK_CTZW,  "ds", ZBB_RV64},
  {"clzw",  MATCH_CLZW,  MASK_CLZW,  "ds", ZBB_RV64},
  {"cpopw", MATCH_CPOPW, MASK_CPOPW, "ds", ZBB_RV64},
  // zext.h: like binutils, two entries with different xlen — MATCH_PACK (RV32)
  // and MATCH_PACKW (RV64) — so no runtime xlen check needed in add_instructions
  {"zext.h", MATCH_PACK,  MASK_PACK  | MASK_RS2, "ds", ZBB_RV32},
  {"zext.h", MATCH_PACKW, MASK_PACKW | MASK_RS2, "ds", ZBB_RV64},
  // zbc_insns
  {"clmul",  MATCH_CLMUL,  MASK_CLMUL,  "dst", ZBC},
  {"clmulh", MATCH_CLMULH, MASK_CLMULH, "dst", ZBC},
  {"clmulr", MATCH_CLMULR, MASK_CLMULR, "dst", ZBC},
  // zbs_insns
  {"bclr",  MATCH_BCLR,  MASK_BCLR,  "dst", ZBS},
  {"binv",  MATCH_BINV,  MASK_BINV,  "dst", ZBS},
  {"bset",  MATCH_BSET,  MASK_BSET,  "dst", ZBS},
  {"bext",  MATCH_BEXT,  MASK_BEXT,  "dst", ZBS},
  {"bclri", MATCH_BCLRI, MASK_BCLRI, "dsZ", ZBS},
  {"binvi", MATCH_BINVI, MASK_BINVI, "dsZ", ZBS},
  {"bseti", MATCH_BSETI, MASK_BSETI, "dsZ", ZBS},
  {"bexti", MATCH_BEXTI, MASK_BEXTI, "dsZ", ZBS},
  // zbkb_insns
  {"brev8", MATCH_BREV8, MASK_BREV8, "ds", ZBKB},
  {"rev8",  MATCH_REV8,  MASK_REV8,  "ds", ZBKB},
  {"pack",  MATCH_PACK,  MASK_PACK,  "dst", ZBKB},
  {"packh", MATCH_PACKH, MASK_PACKH, "dst", ZBKB},
  // zbkb64_insns
  {"packw", MATCH_PACKW, MASK_PACKW, "dst", ZBKB_RV64},
  // svinval_insns
  {"sfence.w.inval",  MATCH_SFENCE_W_INVAL,  MASK_SFENCE_W_INVAL,  "", SVINVAL},
  {"sfence.inval.ir", MATCH_SFENCE_INVAL_IR, MASK_SFENCE_INVAL_IR, "", SVINVAL},
  {"sinval.vma",      MATCH_SINVAL_VMA,      MASK_SINVAL_VMA,      "st", SVINVAL},
  {"hinval.vvma",     MATCH_HINVAL_VVMA,     MASK_HINVAL_VVMA,     "st", SVINVAL},
  {"hinval.gvma",     MATCH_HINVAL_GVMA,     MASK_HINVAL_GVMA,     "st", SVINVAL},
  // f_ext_insns
  {"flw",    MATCH_FLW,    MASK_FLW,    "Do", EXT_F},
  {"fsw",    MATCH_FSW,    MASK_FSW,    "Tq", EXT_F},
  {"fmv.w.x", MATCH_FMV_W_X, MASK_FMV_W_X, "Ds", EXT_F},
  {"fmv.x.w", MATCH_FMV_X_W, MASK_FMV_X_W, "dS", EXT_F},
  // f_or_zfinx_insns
  {"fadd.s",    MATCH_FADD_S,    MASK_FADD_S,    "DST", F_OR_ZFINX},
  {"fsub.s",    MATCH_FSUB_S,    MASK_FSUB_S,    "DST", F_OR_ZFINX},
  {"fmul.s",    MATCH_FMUL_S,    MASK_FMUL_S,    "DST", F_OR_ZFINX},
  {"fdiv.s",    MATCH_FDIV_S,    MASK_FDIV_S,    "DST", F_OR_ZFINX},
  {"fsqrt.s",   MATCH_FSQRT_S,   MASK_FSQRT_S,   "DS", F_OR_ZFINX},
  {"fmin.s",    MATCH_FMIN_S,    MASK_FMIN_S,    "DST", F_OR_ZFINX},
  {"fmax.s",    MATCH_FMAX_S,    MASK_FMAX_S,    "DST", F_OR_ZFINX},
  {"fmadd.s",   MATCH_FMADD_S,   MASK_FMADD_S,   "DSTR", F_OR_ZFINX},
  {"fmsub.s",   MATCH_FMSUB_S,   MASK_FMSUB_S,   "DSTR", F_OR_ZFINX},
  {"fnmadd.s",  MATCH_FNMADD_S,  MASK_FNMADD_S,  "DSTR", F_OR_ZFINX},
  {"fnmsub.s",  MATCH_FNMSUB_S,  MASK_FNMSUB_S,  "DSTR", F_OR_ZFINX},
  {"fsgnj.s",   MATCH_FSGNJ_S,   MASK_FSGNJ_S,   "DST", F_OR_ZFINX},
  {"fsgnjn.s",  MATCH_FSGNJN_S,  MASK_FSGNJN_S,  "DST", F_OR_ZFINX},
  {"fsgnjx.s",  MATCH_FSGNJX_S,  MASK_FSGNJX_S,  "DST", F_OR_ZFINX},
  {"fcvt.s.d",  MATCH_FCVT_S_D,  MASK_FCVT_S_D,  "DS", F_OR_ZFINX},
  {"fcvt.s.q",  MATCH_FCVT_S_Q,  MASK_FCVT_S_Q,  "DS", F_OR_ZFINX},
  {"fcvt.s.w",  MATCH_FCVT_S_W,  MASK_FCVT_S_W,  "Ds", F_OR_ZFINX},
  {"fcvt.s.wu", MATCH_FCVT_S_WU, MASK_FCVT_S_WU, "Ds", F_OR_ZFINX},
  {"fcvt.w.s",  MATCH_FCVT_W_S,  MASK_FCVT_W_S,  "dS", F_OR_ZFINX},
  {"fcvt.wu.s", MATCH_FCVT_WU_S, MASK_FCVT_WU_S, "dS", F_OR_ZFINX},
  {"fclass.s",  MATCH_FCLASS_S,  MASK_FCLASS_S,  "dS", F_OR_ZFINX},
  {"feq.s",     MATCH_FEQ_S,     MASK_FEQ_S,     "dST", F_OR_ZFINX},
  {"flt.s",     MATCH_FLT_S,     MASK_FLT_S,     "dST", F_OR_ZFINX},
  {"fle.s",     MATCH_FLE_S,     MASK_FLE_S,     "dST", F_OR_ZFINX},
  // f_or_zfinx64_insns
  {"fcvt.s.l",  MATCH_FCVT_S_L,  MASK_FCVT_S_L,  "Ds", F_OR_ZFINX_RV64},
  {"fcvt.s.lu", MATCH_FCVT_S_LU, MASK_FCVT_S_LU, "Ds", F_OR_ZFINX_RV64},
  {"fcvt.l.s",  MATCH_FCVT_L_S,  MASK_FCVT_L_S,  "dS", F_OR_ZFINX_RV64},
  {"fcvt.lu.s", MATCH_FCVT_LU_S, MASK_FCVT_LU_S, "dS", F_OR_ZFINX_RV64},
  // d_ext_insns
  {"fld", MATCH_FLD, MASK_FLD, "Do", EXT_D},
  {"fsd", MATCH_FSD, MASK_FSD, "Tq", EXT_D},
  // d_ext64_insns
  {"fmv.d.x", MATCH_FMV_D_X, MASK_FMV_D_X, "Ds", D_RV64},
  {"fmv.x.d", MATCH_FMV_X_D, MASK_FMV_X_D, "dS", D_RV64},
  // d_or_zdinx_insns
  {"fadd.d",    MATCH_FADD_D,    MASK_FADD_D,    "DST", D_OR_ZDINX},
  {"fsub.d",    MATCH_FSUB_D,    MASK_FSUB_D,    "DST", D_OR_ZDINX},
  {"fmul.d",    MATCH_FMUL_D,    MASK_FMUL_D,    "DST", D_OR_ZDINX},
  {"fdiv.d",    MATCH_FDIV_D,    MASK_FDIV_D,    "DST", D_OR_ZDINX},
  {"fsqrt.d",   MATCH_FSQRT_D,   MASK_FSQRT_D,   "DS", D_OR_ZDINX},
  {"fmin.d",    MATCH_FMIN_D,    MASK_FMIN_D,    "DST", D_OR_ZDINX},
  {"fmax.d",    MATCH_FMAX_D,    MASK_FMAX_D,    "DST", D_OR_ZDINX},
  {"fmadd.d",   MATCH_FMADD_D,   MASK_FMADD_D,   "DSTR", D_OR_ZDINX},
  {"fmsub.d",   MATCH_FMSUB_D,   MASK_FMSUB_D,   "DSTR", D_OR_ZDINX},
  {"fnmadd.d",  MATCH_FNMADD_D,  MASK_FNMADD_D,  "DSTR", D_OR_ZDINX},
  {"fnmsub.d",  MATCH_FNMSUB_D,  MASK_FNMSUB_D,  "DSTR", D_OR_ZDINX},
  {"fsgnj.d",   MATCH_FSGNJ_D,   MASK_FSGNJ_D,   "DST", D_OR_ZDINX},
  {"fsgnjn.d",  MATCH_FSGNJN_D,  MASK_FSGNJN_D,  "DST", D_OR_ZDINX},
  {"fsgnjx.d",  MATCH_FSGNJX_D,  MASK_FSGNJX_D,  "DST", D_OR_ZDINX},
  {"fcvt.d.s",  MATCH_FCVT_D_S,  MASK_FCVT_D_S,  "DS", D_OR_ZDINX},
  {"fcvt.d.q",  MATCH_FCVT_D_Q,  MASK_FCVT_D_Q,  "DS", D_OR_ZDINX},
  {"fcvt.d.w",  MATCH_FCVT_D_W,  MASK_FCVT_D_W,  "Ds", D_OR_ZDINX},
  {"fcvt.d.wu", MATCH_FCVT_D_WU, MASK_FCVT_D_WU, "Ds", D_OR_ZDINX},
  {"fcvt.w.d",  MATCH_FCVT_W_D,  MASK_FCVT_W_D,  "dS", D_OR_ZDINX},
  {"fcvt.wu.d", MATCH_FCVT_WU_D, MASK_FCVT_WU_D, "dS", D_OR_ZDINX},
  {"fclass.d",  MATCH_FCLASS_D,  MASK_FCLASS_D,  "dS", D_OR_ZDINX},
  {"feq.d",     MATCH_FEQ_D,     MASK_FEQ_D,     "dST", D_OR_ZDINX},
  {"flt.d",     MATCH_FLT_D,     MASK_FLT_D,     "dST", D_OR_ZDINX},
  {"fle.d",     MATCH_FLE_D,     MASK_FLE_D,     "dST", D_OR_ZDINX},
  // d_or_zdinx64_insns
  {"fcvt.d.l",  MATCH_FCVT_D_L,  MASK_FCVT_D_L,  "Ds", D_OR_ZDINX_RV64},
  {"fcvt.d.lu", MATCH_FCVT_D_LU, MASK_FCVT_D_LU, "Ds", D_OR_ZDINX_RV64},
  {"fcvt.l.d",  MATCH_FCVT_L_D,  MASK_FCVT_L_D,  "dS", D_OR_ZDINX_RV64},
  {"fcvt.lu.d", MATCH_FCVT_LU_D, MASK_FCVT_LU_D, "dS", D_OR_ZDINX_RV64},
  // zfa_insns
  {"fli.s",    MATCH_FLI_S,    MASK_FLI_S,    "dL", ZFA},
  {"fminm.s",  MATCH_FMINM_S,  MASK_FMINM_S,  "DST", ZFA},
  {"fmaxm.s",  MATCH_FMAXM_S,  MASK_FMAXM_S,  "DST", ZFA},
  {"fround.s",   MATCH_FROUND_S,   MASK_FROUND_S,   "DS", ZFA},
  {"froundnx.s", MATCH_FROUNDNX_S, MASK_FROUNDNX_S, "DS", ZFA},
  {"fleq.s",   MATCH_FLEQ_S,   MASK_FLEQ_S,   "dST", ZFA},
  {"fltq.s",   MATCH_FLTQ_S,   MASK_FLTQ_S,   "dST", ZFA},
  // zfa_zfh_insns
  {"fli.h",    MATCH_FLI_H,    MASK_FLI_H,    "dL", ZFA_ZFH},
  {"fminm.h",  MATCH_FMINM_H,  MASK_FMINM_H,  "DST", ZFA_ZFH},
  {"fmaxm.h",  MATCH_FMAXM_H,  MASK_FMAXM_H,  "DST", ZFA_ZFH},
  {"fround.h",   MATCH_FROUND_H,   MASK_FROUND_H,   "DS", ZFA_ZFH},
  {"froundnx.h", MATCH_FROUNDNX_H, MASK_FROUNDNX_H, "DS", ZFA_ZFH},
  {"fleq.h",   MATCH_FLEQ_H,   MASK_FLEQ_H,   "dST", ZFA_ZFH},
  {"fltq.h",   MATCH_FLTQ_H,   MASK_FLTQ_H,   "dST", ZFA_ZFH},
  // zfa_d_insns
  {"fli.d",      MATCH_FLI_D,      MASK_FLI_D,      "dL", ZFA_D},
  {"fminm.d",    MATCH_FMINM_D,    MASK_FMINM_D,    "DST", ZFA_D},
  {"fmaxm.d",    MATCH_FMAXM_D,    MASK_FMAXM_D,    "DST", ZFA_D},
  {"fround.d",   MATCH_FROUND_D,   MASK_FROUND_D,   "DS", ZFA_D},
  {"froundnx.d", MATCH_FROUNDNX_D, MASK_FROUNDNX_D, "DS", ZFA_D},
  {"fleq.d",     MATCH_FLEQ_D,     MASK_FLEQ_D,     "dST", ZFA_D},
  {"fltq.d",     MATCH_FLTQ_D,     MASK_FLTQ_D,     "dST", ZFA_D},
  {"fcvtmod.w.d",MATCH_FCVTMOD_W_D,MASK_FCVTMOD_W_D,"dSm", ZFA_D},
  // zfa_d32_insns
  {"fmvp.d.x", MATCH_FMVP_D_X, MASK_FMVP_D_X, "Dst", ZFA_D_RV32},
  {"fmvh.x.d", MATCH_FMVH_X_D, MASK_FMVH_X_D, "dS", ZFA_D_RV32},
  // zfa_q_insns
  {"fli.q",      MATCH_FLI_Q,      MASK_FLI_Q,      "dL", ZFA_Q},
  {"fminm.q",    MATCH_FMINM_Q,    MASK_FMINM_Q,    "DST", ZFA_Q},
  {"fmaxm.q",    MATCH_FMAXM_Q,    MASK_FMAXM_Q,    "DST", ZFA_Q},
  {"fround.q",   MATCH_FROUND_Q,   MASK_FROUND_Q,   "DS", ZFA_Q},
  {"froundnx.q", MATCH_FROUNDNX_Q, MASK_FROUNDNX_Q, "DS", ZFA_Q},
  {"fleq.q",     MATCH_FLEQ_Q,     MASK_FLEQ_Q,     "dST", ZFA_Q},
  {"fltq.q",     MATCH_FLTQ_Q,     MASK_FLTQ_Q,     "dST", ZFA_Q},
  // zfa_q64_insns
  {"fmvp.q.x", MATCH_FMVP_Q_X, MASK_FMVP_Q_X, "Dst", ZFA_Q_RV64},
  {"fmvh.x.q", MATCH_FMVH_X_Q, MASK_FMVH_X_Q, "dS", ZFA_Q_RV64},
  // zfh_insns
  {"fadd.h",    MATCH_FADD_H,    MASK_FADD_H,    "DST", ZFH},
  {"fsub.h",    MATCH_FSUB_H,    MASK_FSUB_H,    "DST", ZFH},
  {"fmul.h",    MATCH_FMUL_H,    MASK_FMUL_H,    "DST", ZFH},
  {"fdiv.h",    MATCH_FDIV_H,    MASK_FDIV_H,    "DST", ZFH},
  {"fsqrt.h",   MATCH_FSQRT_H,   MASK_FSQRT_H,   "DS", ZFH},
  {"fmin.h",    MATCH_FMIN_H,    MASK_FMIN_H,    "DST", ZFH},
  {"fmax.h",    MATCH_FMAX_H,    MASK_FMAX_H,    "DST", ZFH},
  {"fmadd.h",   MATCH_FMADD_H,   MASK_FMADD_H,   "DSTR", ZFH},
  {"fmsub.h",   MATCH_FMSUB_H,   MASK_FMSUB_H,   "DSTR", ZFH},
  {"fnmadd.h",  MATCH_FNMADD_H,  MASK_FNMADD_H,  "DSTR", ZFH},
  {"fnmsub.h",  MATCH_FNMSUB_H,  MASK_FNMSUB_H,  "DSTR", ZFH},
  {"fsgnj.h",   MATCH_FSGNJ_H,   MASK_FSGNJ_H,   "DST", ZFH},
  {"fsgnjn.h",  MATCH_FSGNJN_H,  MASK_FSGNJN_H,  "DST", ZFH},
  {"fsgnjx.h",  MATCH_FSGNJX_H,  MASK_FSGNJX_H,  "DST", ZFH},
  {"fcvt.h.l",  MATCH_FCVT_H_L,  MASK_FCVT_H_L,  "Ds", ZFH},
  {"fcvt.h.lu", MATCH_FCVT_H_LU, MASK_FCVT_H_LU, "Ds", ZFH},
  {"fcvt.h.w",  MATCH_FCVT_H_W,  MASK_FCVT_H_W,  "Ds", ZFH},
  {"fcvt.h.wu", MATCH_FCVT_H_WU, MASK_FCVT_H_WU, "Ds", ZFH},
  {"fcvt.l.h",  MATCH_FCVT_L_H,  MASK_FCVT_L_H,  "dS", ZFH},
  {"fcvt.lu.h", MATCH_FCVT_LU_H, MASK_FCVT_LU_H, "dS", ZFH},
  {"fcvt.w.h",  MATCH_FCVT_W_H,  MASK_FCVT_W_H,  "dS", ZFH},
  {"fcvt.wu.h", MATCH_FCVT_WU_H, MASK_FCVT_WU_H, "dS", ZFH},
  {"fclass.h",  MATCH_FCLASS_H,  MASK_FCLASS_H,  "dS", ZFH},
  {"feq.h",     MATCH_FEQ_H,     MASK_FEQ_H,     "dST", ZFH},
  {"flt.h",     MATCH_FLT_H,     MASK_FLT_H,     "dST", ZFH},
  {"fle.h",     MATCH_FLE_H,     MASK_FLE_H,     "dST", ZFH},
  // zhinx_insns
  {"fadd.h",    MATCH_FADD_H,    MASK_FADD_H,    "dst", ZHINX},
  {"fsub.h",    MATCH_FSUB_H,    MASK_FSUB_H,    "dst", ZHINX},
  {"fmul.h",    MATCH_FMUL_H,    MASK_FMUL_H,    "dst", ZHINX},
  {"fdiv.h",    MATCH_FDIV_H,    MASK_FDIV_H,    "dst", ZHINX},
  {"fsqrt.h",   MATCH_FSQRT_H,   MASK_FSQRT_H,   "ds", ZHINX},
  {"fmin.h",    MATCH_FMIN_H,    MASK_FMIN_H,    "dst", ZHINX},
  {"fmax.h",    MATCH_FMAX_H,    MASK_FMAX_H,    "dst", ZHINX},
  {"fmadd.h",   MATCH_FMADD_H,   MASK_FMADD_H,   "dstr", ZHINX},
  {"fmsub.h",   MATCH_FMSUB_H,   MASK_FMSUB_H,   "dstr", ZHINX},
  {"fnmadd.h",  MATCH_FNMADD_H,  MASK_FNMADD_H,  "dstr", ZHINX},
  {"fnmsub.h",  MATCH_FNMSUB_H,  MASK_FNMSUB_H,  "dstr", ZHINX},
  {"fsgnj.h",   MATCH_FSGNJ_H,   MASK_FSGNJ_H,   "dst", ZHINX},
  {"fsgnjn.h",  MATCH_FSGNJN_H,  MASK_FSGNJN_H,  "dst", ZHINX},
  {"fsgnjx.h",  MATCH_FSGNJX_H,  MASK_FSGNJX_H,  "dst", ZHINX},
  {"fcvt.h.l",  MATCH_FCVT_H_L,  MASK_FCVT_H_L,  "ds", ZHINX},
  {"fcvt.h.lu", MATCH_FCVT_H_LU, MASK_FCVT_H_LU, "ds", ZHINX},
  {"fcvt.h.w",  MATCH_FCVT_H_W,  MASK_FCVT_H_W,  "ds", ZHINX},
  {"fcvt.h.wu", MATCH_FCVT_H_WU, MASK_FCVT_H_WU, "ds", ZHINX},
  {"fcvt.l.h",  MATCH_FCVT_L_H,  MASK_FCVT_L_H,  "ds", ZHINX},
  {"fcvt.lu.h", MATCH_FCVT_LU_H, MASK_FCVT_LU_H, "ds", ZHINX},
  {"fcvt.w.h",  MATCH_FCVT_W_H,  MASK_FCVT_W_H,  "ds", ZHINX},
  {"fcvt.wu.h", MATCH_FCVT_WU_H, MASK_FCVT_WU_H, "ds", ZHINX},
  {"fclass.h",  MATCH_FCLASS_H,  MASK_FCLASS_H,  "ds", ZHINX},
  {"feq.h",     MATCH_FEQ_H,     MASK_FEQ_H,     "dst", ZHINX},
  {"flt.h",     MATCH_FLT_H,     MASK_FLT_H,     "dst", ZHINX},
  {"fle.h",     MATCH_FLE_H,     MASK_FLE_H,     "dst", ZHINX},
  // zfhmin_insns
  {"fcvt.h.s", MATCH_FCVT_H_S, MASK_FCVT_H_S, "DS", ZFHMIN},
  {"fcvt.h.d", MATCH_FCVT_H_D, MASK_FCVT_H_D, "DS", ZFHMIN},
  {"fcvt.h.q", MATCH_FCVT_H_Q, MASK_FCVT_H_Q, "DS", ZFHMIN},
  {"fcvt.s.h", MATCH_FCVT_S_H, MASK_FCVT_S_H, "DS", ZFHMIN},
  {"fcvt.d.h", MATCH_FCVT_D_H, MASK_FCVT_D_H, "DS", ZFHMIN},
  {"fcvt.q.h", MATCH_FCVT_Q_H, MASK_FCVT_Q_H, "DS", ZFHMIN},
  // zfh_move_insns
  {"flh",    MATCH_FLH,    MASK_FLH,    "Do", ZFH_MOVE},
  {"fsh",    MATCH_FSH,    MASK_FSH,    "Tq", ZFH_MOVE},
  {"fmv.h.x", MATCH_FMV_H_X, MASK_FMV_H_X, "Ds", ZFH_MOVE},
  {"fmv.x.h", MATCH_FMV_X_H, MASK_FMV_X_H, "dS", ZFH_MOVE},
  // zhinxmin_insns
  {"fcvt.h.s", MATCH_FCVT_H_S, MASK_FCVT_H_S, "ds", ZHINXMIN},
  {"fcvt.h.d", MATCH_FCVT_H_D, MASK_FCVT_H_D, "ds", ZHINXMIN},
  {"fcvt.s.h", MATCH_FCVT_S_H, MASK_FCVT_S_H, "ds", ZHINXMIN},
  {"fcvt.d.h", MATCH_FCVT_D_H, MASK_FCVT_D_H, "ds", ZHINXMIN},
  // zibi_insns
  {"beqi", MATCH_BEQI, MASK_BEQI, "s>p", ZIBI},
  {"bnei", MATCH_BNEI, MASK_BNEI, "s>p", ZIBI},
  // q_ext_insns
  {"flq", MATCH_FLQ, MASK_FLQ, "Do", EXT_Q},
  {"fsq", MATCH_FSQ, MASK_FSQ, "Tq", EXT_Q},
  {"fadd.q",    MATCH_FADD_Q,    MASK_FADD_Q,    "DST", EXT_Q},
  {"fsub.q",    MATCH_FSUB_Q,    MASK_FSUB_Q,    "DST", EXT_Q},
  {"fmul.q",    MATCH_FMUL_Q,    MASK_FMUL_Q,    "DST", EXT_Q},
  {"fdiv.q",    MATCH_FDIV_Q,    MASK_FDIV_Q,    "DST", EXT_Q},
  {"fsqrt.q",   MATCH_FSQRT_Q,   MASK_FSQRT_Q,   "DS", EXT_Q},
  {"fmin.q",    MATCH_FMIN_Q,    MASK_FMIN_Q,    "DST", EXT_Q},
  {"fmax.q",    MATCH_FMAX_Q,    MASK_FMAX_Q,    "DST", EXT_Q},
  {"fmadd.q",   MATCH_FMADD_Q,   MASK_FMADD_Q,   "DSTR", EXT_Q},
  {"fmsub.q",   MATCH_FMSUB_Q,   MASK_FMSUB_Q,   "DSTR", EXT_Q},
  {"fnmadd.q",  MATCH_FNMADD_Q,  MASK_FNMADD_Q,  "DSTR", EXT_Q},
  {"fnmsub.q",  MATCH_FNMSUB_Q,  MASK_FNMSUB_Q,  "DSTR", EXT_Q},
  {"fsgnj.q",   MATCH_FSGNJ_Q,   MASK_FSGNJ_Q,   "DST", EXT_Q},
  {"fsgnjn.q",  MATCH_FSGNJN_Q,  MASK_FSGNJN_Q,  "DST", EXT_Q},
  {"fsgnjx.q",  MATCH_FSGNJX_Q,  MASK_FSGNJX_Q,  "DST", EXT_Q},
  {"fcvt.q.s",  MATCH_FCVT_Q_S,  MASK_FCVT_Q_S,  "DS", EXT_Q},
  {"fcvt.q.d",  MATCH_FCVT_Q_D,  MASK_FCVT_Q_D,  "DS", EXT_Q},
  {"fcvt.q.l",  MATCH_FCVT_Q_L,  MASK_FCVT_Q_L,  "Ds", EXT_Q},
  {"fcvt.q.lu", MATCH_FCVT_Q_LU, MASK_FCVT_Q_LU, "Ds", EXT_Q},
  {"fcvt.q.w",  MATCH_FCVT_Q_W,  MASK_FCVT_Q_W,  "Ds", EXT_Q},
  {"fcvt.q.wu", MATCH_FCVT_Q_WU, MASK_FCVT_Q_WU, "Ds", EXT_Q},
  {"fcvt.l.q",  MATCH_FCVT_L_Q,  MASK_FCVT_L_Q,  "dS", EXT_Q},
  {"fcvt.lu.q", MATCH_FCVT_LU_Q, MASK_FCVT_LU_Q, "dS", EXT_Q},
  {"fcvt.w.q",  MATCH_FCVT_W_Q,  MASK_FCVT_W_Q,  "dS", EXT_Q},
  {"fcvt.wu.q", MATCH_FCVT_WU_Q, MASK_FCVT_WU_Q, "dS", EXT_Q},
  {"fclass.q",  MATCH_FCLASS_Q,  MASK_FCLASS_Q,  "dS", EXT_Q},
  {"feq.q",     MATCH_FEQ_Q,     MASK_FEQ_Q,     "dST", EXT_Q},
  {"flt.q",     MATCH_FLT_Q,     MASK_FLT_Q,     "dST", EXT_Q},
  {"fle.q",     MATCH_FLE_Q,     MASK_FLE_Q,     "dST", EXT_Q},
  // zfbfmin_insns
  {"fcvt.bf16.s", MATCH_FCVT_BF16_S, MASK_FCVT_BF16_S, "DS", ZFBFMIN},
  {"fcvt.s.bf16", MATCH_FCVT_S_BF16, MASK_FCVT_S_BF16, "DS", ZFBFMIN},
  // h_ext_insns
  {"hlv.b",   MATCH_HLV_B,   MASK_HLV_B,   "d(", EXT_H},
  {"hlv.bu",  MATCH_HLV_BU,  MASK_HLV_BU,  "d(", EXT_H},
  {"hlv.h",   MATCH_HLV_H,   MASK_HLV_H,   "d(", EXT_H},
  {"hlv.hu",  MATCH_HLV_HU,  MASK_HLV_HU,  "d(", EXT_H},
  {"hlv.w",   MATCH_HLV_W,   MASK_HLV_W,   "d(", EXT_H},
  {"hlv.wu",  MATCH_HLV_WU,  MASK_HLV_WU,  "d(", EXT_H},
  {"hlv.d",   MATCH_HLV_D,   MASK_HLV_D,   "d(", EXT_H},
  {"hlvx.hu", MATCH_HLVX_HU, MASK_HLVX_HU, "d(", EXT_H},
  {"hlvx.wu", MATCH_HLVX_WU, MASK_HLVX_WU, "d(", EXT_H},
  {"hsv.b",   MATCH_HSV_B,   MASK_HSV_B,   "t(", EXT_H},
  {"hsv.h",   MATCH_HSV_H,   MASK_HSV_H,   "t(", EXT_H},
  {"hsv.w",   MATCH_HSV_W,   MASK_HSV_W,   "t(", EXT_H},
  {"hsv.d",   MATCH_HSV_D,   MASK_HSV_D,   "t(", EXT_H},
  {"hfence.gvma", MATCH_HFENCE_GVMA, MASK_HFENCE_GVMA, "st", EXT_H},
  {"hfence.vvma", MATCH_HFENCE_VVMA, MASK_HFENCE_VVMA, "st", EXT_H},
  // zca_insns
  {"c.ebreak",   MATCH_C_ADD,  MASK_C_ADD | MASK_RD | MASK_CRS2,         "", ZCA},
  {"ret",        MATCH_C_JR  | 0x80u, MASK_C_JR | MASK_RD | MASK_CNZIMM6, "", ZCA},
  {"c.jr",       MATCH_C_JR,   MASK_C_JR  | MASK_CNZIMM6,                "e", ZCA},
  {"c.jalr",     MATCH_C_JALR, MASK_C_JALR | MASK_CNZIMM6,               "e", ZCA},
  {"c.nop",      MATCH_C_ADDI, MASK_C_ADDI | MASK_RD | MASK_CNZIMM6,      "", ZCA},
  {"c.addi16sp", MATCH_C_ADDI16SP, MASK_C_ADDI16SP | MASK_RD,        "Nx", ZCA},
  {"c.addi4spn", MATCH_C_ADDI4SPN, MASK_C_ADDI4SPN,                 "JNn", ZCA},
  {"c.li",       MATCH_C_LI,   MASK_C_LI,   "di", ZCA},
  {"c.lui",      MATCH_C_LUI,  MASK_C_LUI,  "db", ZCA},
  {"c.addi",     MATCH_C_ADDI, MASK_C_ADDI, "di", ZCA},
  {"c.slli",     MATCH_C_SLLI, MASK_C_SLLI, "eh", ZCA},
  {"c.srli",     MATCH_C_SRLI, MASK_C_SRLI, "Hh", ZCA},
  {"c.srai",     MATCH_C_SRAI, MASK_C_SRAI, "Hh", ZCA},
  {"c.andi",     MATCH_C_ANDI, MASK_C_ANDI, "Hi", ZCA},
  {"c.mv",       MATCH_C_MV,   MASK_C_MV,   "df", ZCA},
  {"c.add",      MATCH_C_ADD,  MASK_C_ADD,  "df", ZCA},
  {"c.sub",      MATCH_C_SUB,  MASK_C_SUB,  "HJ", ZCA},
  {"c.and",      MATCH_C_AND,  MASK_C_AND,  "HJ", ZCA},
  {"c.or",       MATCH_C_OR,   MASK_C_OR,   "HJ", ZCA},
  {"c.xor",      MATCH_C_XOR,  MASK_C_XOR,  "HJ", ZCA},
  {"c.lwsp",     MATCH_C_LWSP, MASK_C_LWSP, "d@", ZCA},
  {"c.swsp",     MATCH_C_SWSP, MASK_C_SWSP, "f_", ZCA},
  {"c.lw",       MATCH_C_LW,   MASK_C_LW,   "Jc", ZCA},
  {"c.sw",       MATCH_C_SW,   MASK_C_SW,   "Jc", ZCA},
  {"c.beqz",     MATCH_C_BEQZ, MASK_C_BEQZ, "Hy", ZCA},
  {"c.bnez",     MATCH_C_BNEZ, MASK_C_BNEZ, "Hy", ZCA},
  {"c.j",        MATCH_C_J,    MASK_C_J,    "w", ZCA},
  // zca32_insns
  {"c.jal", MATCH_C_JAL, MASK_C_JAL, "w", ZCA_RV32},
  // zca_not32_insns
  {"c.addiw", MATCH_C_ADDIW, MASK_C_ADDIW, "di", ZCA_NOT_RV32},
  // zca64_insns
  {"c.addw", MATCH_C_ADDW, MASK_C_ADDW, "HJ", ZCA_RV64},
  {"c.subw", MATCH_C_SUBW, MASK_C_SUBW, "HJ", ZCA_RV64},
  // zca_ld_insns
  {"c.ld",   MATCH_C_LD,   MASK_C_LD,   "Jv", ZCA_LD},
  {"c.ldsp", MATCH_C_LDSP, MASK_C_LDSP, "dM", ZCA_LD},
  {"c.sd",   MATCH_C_SD,   MASK_C_SD,   "Jv", ZCA_LD},
  {"c.sdsp", MATCH_C_SDSP, MASK_C_SDSP, "fg", ZCA_LD},
  // zcd_insns
  {"c.fld",   MATCH_C_FLD,   MASK_C_FLD,   "#v", ZCD},
  {"c.fldsp", MATCH_C_FLDSP, MASK_C_FLDSP, "DM", ZCD},
  {"c.fsd",   MATCH_C_FSD,   MASK_C_FSD,   "#v", ZCD},
  {"c.fsdsp", MATCH_C_FSDSP, MASK_C_FSDSP, "Fg", ZCD},
  // zcf_insns
  {"c.flw",   MATCH_C_FLW,   MASK_C_FLW,   "#c", ZCF},
  {"c.flwsp", MATCH_C_FLWSP, MASK_C_FLWSP, "D@", ZCF},
  {"c.fsw",   MATCH_C_FSW,   MASK_C_FSW,   "#c", ZCF},
  {"c.fswsp", MATCH_C_FSWSP, MASK_C_FSWSP, "F_", ZCF},
  // zcb_insns
  {"c.zext.b", MATCH_C_ZEXT_B, MASK_C_ZEXT_B, "H", ZCB},
  {"c.sext.b", MATCH_C_SEXT_B, MASK_C_SEXT_B, "H", ZCB},
  {"c.zext.h", MATCH_C_ZEXT_H, MASK_C_ZEXT_H, "H", ZCB},
  {"c.sext.h", MATCH_C_SEXT_H, MASK_C_SEXT_H, "H", ZCB},
  {"c.not",    MATCH_C_NOT,    MASK_C_NOT,    "H", ZCB},
  {"c.mul",    MATCH_C_MUL,    MASK_C_MUL,    "HJ", ZCB},
  {"c.lbu",    MATCH_C_LBU,    MASK_C_LBU,    "J*", ZCB},
  {"c.lhu",    MATCH_C_LHU,    MASK_C_LHU,    "J/", ZCB},
  {"c.lh",     MATCH_C_LH,     MASK_C_LH,     "J/", ZCB},
  {"c.sb",     MATCH_C_SB,     MASK_C_SB,     "J*", ZCB},
  {"c.sh",     MATCH_C_SH,     MASK_C_SH,     "J/", ZCB},
  // zcb64_insns
  {"c.zext.w", MATCH_C_ZEXT_W, MASK_C_ZEXT_W, "H", ZCB_RV64},
  // zcmp32_insns
  {"cm.push",    MATCH_CM_PUSH,    MASK_CM_PUSH,    "!2", ZCMP_RV32},
  {"cm.pop",     MATCH_CM_POP,     MASK_CM_POP,     "!3", ZCMP_RV32},
  {"cm.popret",  MATCH_CM_POPRET,  MASK_CM_POPRET,  "!3", ZCMP_RV32},
  {"cm.popretz", MATCH_CM_POPRETZ, MASK_CM_POPRETZ, "!3", ZCMP_RV32},
  // zcmp64_insns
  {"cm.push",    MATCH_CM_PUSH,    MASK_CM_PUSH,    "!4", ZCMP_NOT_RV32},
  {"cm.pop",     MATCH_CM_POP,     MASK_CM_POP,     "!8", ZCMP_NOT_RV32},
  {"cm.popret",  MATCH_CM_POPRET,  MASK_CM_POPRET,  "!8", ZCMP_NOT_RV32},
  {"cm.popretz", MATCH_CM_POPRETZ, MASK_CM_POPRETZ, "!8", ZCMP_NOT_RV32},
  // zcmp_common_insns
  {"cm.mva01s", MATCH_CM_MVA01S, MASK_CM_MVA01S, "VO", ZCMP},
  {"cm.mvsa01", MATCH_CM_MVSA01, MASK_CM_MVSA01, "VO", ZCMP},
  // zcmt_insns
  {"cm.jt",   MATCH_CM_JALT, MASK_CM_JALT | 0x380u, "1", ZCMT},
  {"cm.jalt", MATCH_CM_JALT, MASK_CM_JALT,           "1", ZCMT},
  // zmmul_insns
  {"mul",    MATCH_MUL,    MASK_MUL,    "dst", ZMMUL},
  {"mulh",   MATCH_MULH,   MASK_MULH,   "dst", ZMMUL},
  {"mulhu",  MATCH_MULHU,  MASK_MULHU,  "dst", ZMMUL},
  {"mulhsu", MATCH_MULHSU, MASK_MULHSU, "dst", ZMMUL},
  // zmmul64_insns
  {"mulw",   MATCH_MULW,   MASK_MULW,   "dst", ZMMUL_RV64},
  // zicbom_insns
  {"cbo.clean", MATCH_CBO_CLEAN, MASK_CBO_CLEAN, "(", ZICBOM},
  {"cbo.flush", MATCH_CBO_FLUSH, MASK_CBO_FLUSH, "(", ZICBOM},
  {"cbo.inval", MATCH_CBO_INVAL, MASK_CBO_INVAL, "(", ZICBOM},
  // zicboz_insns
  {"cbo.zero",  MATCH_CBO_ZERO,  MASK_CBO_ZERO,  "(", ZICBOZ},
  // zicond_insns
  {"czero.eqz", MATCH_CZERO_EQZ, MASK_CZERO_EQZ, "dst", ZICOND},
  {"czero.nez", MATCH_CZERO_NEZ, MASK_CZERO_NEZ, "dst", ZICOND},
  // zknd_zknde_insns
  // aes64ks1i is explicit (has rcon immediate)
  {"aes64ks2", MATCH_AES64KS2, MASK_AES64KS2, "dst", ZKND_OR_ZKNE},
  // zknd64_insns
  {"aes64ds",  MATCH_AES64DS,  MASK_AES64DS,  "dst", ZKND_RV64},
  {"aes64dsm", MATCH_AES64DSM, MASK_AES64DSM, "dst", ZKND_RV64},
  {"aes64im",  MATCH_AES64IM,  MASK_AES64IM,  "ds", ZKND_RV64},
  // zkne64_insns
  {"aes64es",  MATCH_AES64ES,  MASK_AES64ES,  "dst", ZKNE_RV64},
  {"aes64esm", MATCH_AES64ESM, MASK_AES64ESM, "dst", ZKNE_RV64},
  // zknh_insns
  {"sha256sig0", MATCH_SHA256SIG0, MASK_SHA256SIG0, "ds", ZKNH},
  {"sha256sig1", MATCH_SHA256SIG1, MASK_SHA256SIG1, "ds", ZKNH},
  {"sha256sum0", MATCH_SHA256SUM0, MASK_SHA256SUM0, "ds", ZKNH},
  {"sha256sum1", MATCH_SHA256SUM1, MASK_SHA256SUM1, "ds", ZKNH},
  // zknh64_insns
  {"sha512sig0", MATCH_SHA512SIG0, MASK_SHA512SIG0, "ds", ZKNH_RV64},
  {"sha512sig1", MATCH_SHA512SIG1, MASK_SHA512SIG1, "ds", ZKNH_RV64},
  {"sha512sum0", MATCH_SHA512SUM0, MASK_SHA512SUM0, "ds", ZKNH_RV64},
  {"sha512sum1", MATCH_SHA512SUM1, MASK_SHA512SUM1, "ds", ZKNH_RV64},
  // zknh32_insns
  {"sha512sig0h", MATCH_SHA512SIG0H, MASK_SHA512SIG0H, "dst", ZKNH_RV32},
  {"sha512sig0l", MATCH_SHA512SIG0L, MASK_SHA512SIG0L, "dst", ZKNH_RV32},
  {"sha512sig1h", MATCH_SHA512SIG1H, MASK_SHA512SIG1H, "dst", ZKNH_RV32},
  {"sha512sig1l", MATCH_SHA512SIG1L, MASK_SHA512SIG1L, "dst", ZKNH_RV32},
  {"sha512sum0r", MATCH_SHA512SUM0R, MASK_SHA512SUM0R, "dst", ZKNH_RV32},
  {"sha512sum1r", MATCH_SHA512SUM1R, MASK_SHA512SUM1R, "dst", ZKNH_RV32},
  // zksed_insns
  {"sm4ed", MATCH_SM4ED, MASK_SM4ED, "dst-", ZKSED},
  {"sm4ks", MATCH_SM4KS, MASK_SM4KS, "dst-", ZKSED},
  // zksh_insns
  {"sm3p0", MATCH_SM3P0, MASK_SM3P0, "ds", ZKSH},
  {"sm3p1", MATCH_SM3P1, MASK_SM3P1, "ds", ZKSH},
  // zalasr_insns
  {"lb.aq",  MATCH_LB_AQ,  MASK_LB_AQ,  "d(", ZALASR},
  {"lh.aq",  MATCH_LH_AQ,  MASK_LH_AQ,  "d(", ZALASR},
  {"lw.aq",  MATCH_LW_AQ,  MASK_LW_AQ,  "d(", ZALASR},
  {"ld.aq",  MATCH_LD_AQ,  MASK_LD_AQ,  "d(", ZALASR},
  {"sb.rl",  MATCH_SB_RL,  MASK_SB_RL,  "t(", ZALASR},
  {"sh.rl",  MATCH_SH_RL,  MASK_SH_RL,  "t(", ZALASR},
  {"sw.rl",  MATCH_SW_RL,  MASK_SW_RL,  "t(", ZALASR},
  {"sd.rl",  MATCH_SD_RL,  MASK_SD_RL,  "t(", ZALASR},
  // zicfiss_insns
  {"sspush",   MATCH_SSPUSH_X1, MASK_SSPUSH_X1, "t", ZICFISS},
  {"sspush",   MATCH_SSPUSH_X5, MASK_SSPUSH_X5, "t", ZICFISS},
  {"sspopchk", MATCH_SSPOPCHK_X1, MASK_SSPOPCHK_X1, "s", ZICFISS},
  {"sspopchk", MATCH_SSPOPCHK_X5, MASK_SSPOPCHK_X5, "s", ZICFISS},
  {"ssrdp",    MATCH_SSRDP,    MASK_SSRDP,    "d", ZICFISS},
  // zicfiss_zca_insns
  {"c.sspush",   MATCH_C_SSPUSH_X1,   MASK_C_SSPUSH_X1,   "X", ZICFISS_ZCA},
  {"c.sspopchk", MATCH_C_SSPOPCHK_X5, MASK_C_SSPOPCHK_X5, "Y", ZICFISS_ZCA},
  // P-extension
  {"aadd", MATCH_AADD, MASK_AADD, "dst", EXT_P_RV32},
  {"aaddu", MATCH_AADDU, MASK_AADDU, "dst", EXT_P_RV32},
  {"asub", MATCH_ASUB, MASK_ASUB, "dst", EXT_P_RV32},
  {"asubu", MATCH_ASUBU, MASK_ASUBU, "dst", EXT_P_RV32},
  {"mseq", MATCH_MSEQ, MASK_MSEQ, "dst", EXT_P_RV32},
  {"mslt", MATCH_MSLT, MASK_MSLT, "dst", EXT_P_RV32},
  {"msltu", MATCH_MSLTU, MASK_MSLTU, "dst", EXT_P_RV32},
  {"addd", MATCH_ADDD, MASK_ADDD, "PQU", EXT_P},
  {"subd", MATCH_SUBD, MASK_SUBD, "PQU", EXT_P},
  {"merge", MATCH_MERGE, MASK_MERGE, "dst", EXT_P},
  {"mvm", MATCH_MVM, MASK_MVM, "dst", EXT_P},
  {"mvmn", MATCH_MVMN, MASK_MVMN, "dst", EXT_P},
  {"nclip", MATCH_NCLIP, MASK_NCLIP, "dQt", EXT_P},
  {"nclipr", MATCH_NCLIPR, MASK_NCLIPR, "dQt", EXT_P},
  {"nclipu", MATCH_NCLIPU, MASK_NCLIPU, "dQt", EXT_P},
  {"nclipru", MATCH_NCLIPRU, MASK_NCLIPRU, "dQt", EXT_P},
  {"nsra", MATCH_NSRA, MASK_NSRA, "dQt", EXT_P},
  {"nsrar", MATCH_NSRAR, MASK_NSRAR, "dQt", EXT_P},
  {"nsrl", MATCH_NSRL, MASK_NSRL, "dQt", EXT_P},
  {"sadd", MATCH_SADD, MASK_SADD, "dst", EXT_P_RV32},
  {"saddu", MATCH_SADDU, MASK_SADDU, "dst", EXT_P_RV32},
  {"ssub", MATCH_SSUB, MASK_SSUB, "dst", EXT_P_RV32},
  {"ssubu", MATCH_SSUBU, MASK_SSUBU, "dst", EXT_P_RV32},
  {"ssh1sadd", MATCH_SSH1SADD, MASK_SSH1SADD, "dst", EXT_P_RV32},
  {"ssha", MATCH_SSHA, MASK_SSHA, "dst", EXT_P_RV32},
  {"sshar", MATCH_SSHAR, MASK_SSHAR, "dst", EXT_P_RV32},
  {"sshl", MATCH_SSHL, MASK_SSHL, "dst", EXT_P_RV32},
  {"sshlr", MATCH_SSHLR, MASK_SSHLR, "dst", EXT_P_RV32},
  {"sha", MATCH_SHA, MASK_SHA, "PQU", EXT_P},
  {"shar", MATCH_SHAR, MASK_SHAR, "PQU", EXT_P},
  {"slx", MATCH_SLX, MASK_SLX, "dst", EXT_P},
  {"srx", MATCH_SRX, MASK_SRX, "dst", EXT_P},
  {"wadd", MATCH_WADD, MASK_WADD, "Pst", EXT_P},
  {"wadda", MATCH_WADDA, MASK_WADDA, "Pst", EXT_P},
  {"waddu", MATCH_WADDU, MASK_WADDU, "Pst", EXT_P},
  {"waddau", MATCH_WADDAU, MASK_WADDAU, "Pst", EXT_P},
  {"wsub", MATCH_WSUB, MASK_WSUB, "Pst", EXT_P},
  {"wsuba", MATCH_WSUBA, MASK_WSUBA, "Pst", EXT_P},
  {"wsubu", MATCH_WSUBU, MASK_WSUBU, "Pst", EXT_P},
  {"wsubau", MATCH_WSUBAU, MASK_WSUBAU, "Pst", EXT_P},
  {"wsll", MATCH_WSLL, MASK_WSLL, "Pst", EXT_P},
  {"wsla", MATCH_WSLA, MASK_WSLA, "Pst", EXT_P},
  {"wmul", MATCH_WMUL, MASK_WMUL, "Pst", EXT_P},
  {"wmulu", MATCH_WMULU, MASK_WMULU, "Pst", EXT_P},
  {"wmulsu", MATCH_WMULSU, MASK_WMULSU, "Pst", EXT_P},
  {"wmacc", MATCH_WMACC, MASK_WMACC, "Pst", EXT_P},
  {"wmaccu", MATCH_WMACCU, MASK_WMACCU, "Pst", EXT_P},
  {"wmaccsu", MATCH_WMACCSU, MASK_WMACCSU, "Pst", EXT_P},
  {"macc.h00", MATCH_MACC_H00, MASK_MACC_H00, "dst", EXT_P_RV32},
  {"macc.h01", MATCH_MACC_H01, MASK_MACC_H01, "dst", EXT_P_RV32},
  {"macc.h11", MATCH_MACC_H11, MASK_MACC_H11, "dst", EXT_P_RV32},
  {"maccu.h00", MATCH_MACCU_H00, MASK_MACCU_H00, "dst", EXT_P_RV32},
  {"maccu.h01", MATCH_MACCU_H01, MASK_MACCU_H01, "dst", EXT_P_RV32},
  {"maccu.h11", MATCH_MACCU_H11, MASK_MACCU_H11, "dst", EXT_P_RV32},
  {"maccsu.h00", MATCH_MACCSU_H00, MASK_MACCSU_H00, "dst", EXT_P_RV32},
  {"maccsu.h11", MATCH_MACCSU_H11, MASK_MACCSU_H11, "dst", EXT_P_RV32},
  {"mul.h00", MATCH_MUL_H00, MASK_MUL_H00, "dst", EXT_P_RV32},
  {"mul.h01", MATCH_MUL_H01, MASK_MUL_H01, "dst", EXT_P_RV32},
  {"mul.h11", MATCH_MUL_H11, MASK_MUL_H11, "dst", EXT_P_RV32},
  {"mulu.h00", MATCH_MULU_H00, MASK_MULU_H00, "dst", EXT_P_RV32},
  {"mulu.h01", MATCH_MULU_H01, MASK_MULU_H01, "dst", EXT_P_RV32},
  {"mulu.h11", MATCH_MULU_H11, MASK_MULU_H11, "dst", EXT_P_RV32},
  {"mulsu.h00", MATCH_MULSU_H00, MASK_MULSU_H00, "dst", EXT_P_RV32},
  {"mulsu.h11", MATCH_MULSU_H11, MASK_MULSU_H11, "dst", EXT_P_RV32},
  {"mulh.h0", MATCH_MULH_H0, MASK_MULH_H0, "dst", EXT_P_RV32},
  {"mulh.h1", MATCH_MULH_H1, MASK_MULH_H1, "dst", EXT_P_RV32},
  {"mulhsu.h0", MATCH_MULHSU_H0, MASK_MULHSU_H0, "dst", EXT_P_RV32},
  {"mulhsu.h1", MATCH_MULHSU_H1, MASK_MULHSU_H1, "dst", EXT_P_RV32},
  {"mulhr", MATCH_MULHR, MASK_MULHR, "dst", EXT_P_RV32},
  {"mulhru", MATCH_MULHRU, MASK_MULHRU, "dst", EXT_P_RV32},
  {"mulhrsu", MATCH_MULHRSU, MASK_MULHRSU, "dst", EXT_P_RV32},
  {"mulq", MATCH_MULQ, MASK_MULQ, "dst", EXT_P_RV32},
  {"mulqr", MATCH_MULQR, MASK_MULQR, "dst", EXT_P_RV32},
  {"mhacc", MATCH_MHACC, MASK_MHACC, "dst", EXT_P_RV32},
  {"mhaccu", MATCH_MHACCU, MASK_MHACCU, "dst", EXT_P_RV32},
  {"mhaccsu", MATCH_MHACCSU, MASK_MHACCSU, "dst", EXT_P_RV32},
  {"mhacc.h0", MATCH_MHACC_H0, MASK_MHACC_H0, "dst", EXT_P_RV32},
  {"mhacc.h1", MATCH_MHACC_H1, MASK_MHACC_H1, "dst", EXT_P_RV32},
  {"mhaccsu.h0", MATCH_MHACCSU_H0, MASK_MHACCSU_H0, "dst", EXT_P_RV32},
  {"mhaccsu.h1", MATCH_MHACCSU_H1, MASK_MHACCSU_H1, "dst", EXT_P_RV32},
  {"mhracc", MATCH_MHRACC, MASK_MHRACC, "dst", EXT_P_RV32},
  {"mhraccu", MATCH_MHRACCU, MASK_MHRACCU, "dst", EXT_P_RV32},
  {"mhraccsu", MATCH_MHRACCSU, MASK_MHRACCSU, "dst", EXT_P_RV32},
  {"mqacc.h00", MATCH_MQACC_H00, MASK_MQACC_H00, "dst", EXT_P},
  {"mqacc.h01", MATCH_MQACC_H01, MASK_MQACC_H01, "dst", EXT_P},
  {"mqacc.h11", MATCH_MQACC_H11, MASK_MQACC_H11, "dst", EXT_P},
  {"mqracc.h00", MATCH_MQRACC_H00, MASK_MQRACC_H00, "dst", EXT_P},
  {"mqracc.h01", MATCH_MQRACC_H01, MASK_MQRACC_H01, "dst", EXT_P},
  {"mqracc.h11", MATCH_MQRACC_H11, MASK_MQRACC_H11, "dst", EXT_P},
  {"abs", MATCH_ABS, MASK_ABS, "ds", EXT_P},
  {"cls", MATCH_CLS, MASK_CLS, "ds", EXT_P},
  {"nclipi", MATCH_NCLIPI, MASK_NCLIPI, "ds'", EXT_P},
  {"nclipiu", MATCH_NCLIPIU, MASK_NCLIPIU, "ds'", EXT_P},
  {"nclipri", MATCH_NCLIPRI, MASK_NCLIPRI, "ds'", EXT_P},
  {"nclipriu", MATCH_NCLIPRIU, MASK_NCLIPRIU, "ds'", EXT_P},
  {"nsrai", MATCH_NSRAI, MASK_NSRAI, "ds'", EXT_P},
  {"nsrari", MATCH_NSRARI, MASK_NSRARI, "ds'", EXT_P},
  {"nsrli", MATCH_NSRLI, MASK_NSRLI, "ds'", EXT_P},
  {"sslai", MATCH_SSLAI, MASK_SSLAI, "dsZ", EXT_P_RV32},
  {"wslli", MATCH_WSLLI, MASK_WSLLI, "dsZ", EXT_P},
  {"wslai", MATCH_WSLAI, MASK_WSLAI, "dsZ", EXT_P},
  {"sati", MATCH_SATI, MASK_SATI, "dsZ", EXT_P_RV64},
  {"usati", MATCH_USATI, MASK_USATI, "dsZ", EXT_P_RV64},
  {"srari", MATCH_SRARI, MASK_SRARI, "dsZ", EXT_P_RV64},
  {"sati", MATCH_SATI_RV32, MASK_SATI_RV32, "dsZ", EXT_P_RV64},
  {"usati", MATCH_USATI_RV32, MASK_USATI_RV32, "dsZ", EXT_P_RV64},
  {"srari", MATCH_SRARI_RV32, MASK_SRARI_RV32, "dsZ", EXT_P_RV64},
  {"paadd.b", MATCH_PAADD_B, MASK_PAADD_B, "dst", EXT_P},
  {"paadd.h", MATCH_PAADD_H, MASK_PAADD_H, "dst", EXT_P},
  {"paadd.db", MATCH_PAADD_DB, MASK_PAADD_DB, "PQU", EXT_P},
  {"paadd.dh", MATCH_PAADD_DH, MASK_PAADD_DH, "PQU", EXT_P},
  {"paadd.dw", MATCH_PAADD_DW, MASK_PAADD_DW, "PQU", EXT_P},
  {"paaddu.b", MATCH_PAADDU_B, MASK_PAADDU_B, "dst", EXT_P},
  {"paaddu.h", MATCH_PAADDU_H, MASK_PAADDU_H, "dst", EXT_P},
  {"paaddu.db", MATCH_PAADDU_DB, MASK_PAADDU_DB, "PQU", EXT_P},
  {"paaddu.dh", MATCH_PAADDU_DH, MASK_PAADDU_DH, "PQU", EXT_P},
  {"paaddu.dw", MATCH_PAADDU_DW, MASK_PAADDU_DW, "PQU", EXT_P},
  {"paas.hx", MATCH_PAAS_HX, MASK_PAAS_HX, "dst", EXT_P},
  {"paas.dhx", MATCH_PAAS_DHX, MASK_PAAS_DHX, "PQU", EXT_P},
  {"pabd.b", MATCH_PABD_B, MASK_PABD_B, "dst", EXT_P},
  {"pabd.h", MATCH_PABD_H, MASK_PABD_H, "dst", EXT_P},
  {"pabd.db", MATCH_PABD_DB, MASK_PABD_DB, "PQU", EXT_P},
  {"pabd.dh", MATCH_PABD_DH, MASK_PABD_DH, "PQU", EXT_P},
  {"pabdu.b", MATCH_PABDU_B, MASK_PABDU_B, "dst", EXT_P},
  {"pabdu.h", MATCH_PABDU_H, MASK_PABDU_H, "dst", EXT_P},
  {"pabdu.db", MATCH_PABDU_DB, MASK_PABDU_DB, "PQU", EXT_P},
  {"pabdu.dh", MATCH_PABDU_DH, MASK_PABDU_DH, "PQU", EXT_P},
  {"pabdsumu.b", MATCH_PABDSUMU_B, MASK_PABDSUMU_B, "dst", EXT_P},
  {"pabdsumau.b", MATCH_PABDSUMAU_B, MASK_PABDSUMAU_B, "dst", EXT_P},
  {"padd.b", MATCH_PADD_B, MASK_PADD_B, "dst", EXT_P},
  {"padd.h", MATCH_PADD_H, MASK_PADD_H, "dst", EXT_P},
  {"padd.bs", MATCH_PADD_BS, MASK_PADD_BS, "dst", EXT_P},
  {"padd.hs", MATCH_PADD_HS, MASK_PADD_HS, "dst", EXT_P},
  {"padd.db", MATCH_PADD_DB, MASK_PADD_DB, "PQU", EXT_P},
  {"padd.dh", MATCH_PADD_DH, MASK_PADD_DH, "PQU", EXT_P},
  {"padd.dw", MATCH_PADD_DW, MASK_PADD_DW, "PQU", EXT_P},
  {"padd.dbs", MATCH_PADD_DBS, MASK_PADD_DBS, "PQt", EXT_P},
  {"padd.dhs", MATCH_PADD_DHS, MASK_PADD_DHS, "PQt", EXT_P},
  {"padd.dws", MATCH_PADD_DWS, MASK_PADD_DWS, "PQt", EXT_P},
  {"pasub.b", MATCH_PASUB_B, MASK_PASUB_B, "dst", EXT_P},
  {"pasub.h", MATCH_PASUB_H, MASK_PASUB_H, "dst", EXT_P},
  {"pasub.db", MATCH_PASUB_DB, MASK_PASUB_DB, "PQU", EXT_P},
  {"pasub.dh", MATCH_PASUB_DH, MASK_PASUB_DH, "PQU", EXT_P},
  {"pasub.dw", MATCH_PASUB_DW, MASK_PASUB_DW, "PQU", EXT_P},
  {"pasubu.b", MATCH_PASUBU_B, MASK_PASUBU_B, "dst", EXT_P},
  {"pasubu.h", MATCH_PASUBU_H, MASK_PASUBU_H, "dst", EXT_P},
  {"pasubu.db", MATCH_PASUBU_DB, MASK_PASUBU_DB, "PQU", EXT_P},
  {"pasubu.dh", MATCH_PASUBU_DH, MASK_PASUBU_DH, "PQU", EXT_P},
  {"pasubu.dw", MATCH_PASUBU_DW, MASK_PASUBU_DW, "PQU", EXT_P},
  {"pasa.hx", MATCH_PASA_HX, MASK_PASA_HX, "dst", EXT_P},
  {"pasa.dhx", MATCH_PASA_DHX, MASK_PASA_DHX, "PQU", EXT_P},
  {"pas.hx", MATCH_PAS_HX, MASK_PAS_HX, "dst", EXT_P},
  {"pas.dhx", MATCH_PAS_DHX, MASK_PAS_DHX, "PQU", EXT_P},
  {"psadd.b", MATCH_PSADD_B, MASK_PSADD_B, "dst", EXT_P},
  {"psadd.h", MATCH_PSADD_H, MASK_PSADD_H, "dst", EXT_P},
  {"psadd.db", MATCH_PSADD_DB, MASK_PSADD_DB, "PQU", EXT_P},
  {"psadd.dh", MATCH_PSADD_DH, MASK_PSADD_DH, "PQU", EXT_P},
  {"psadd.dw", MATCH_PSADD_DW, MASK_PSADD_DW, "PQU", EXT_P},
  {"psaddu.b", MATCH_PSADDU_B, MASK_PSADDU_B, "dst", EXT_P},
  {"psaddu.h", MATCH_PSADDU_H, MASK_PSADDU_H, "dst", EXT_P},
  {"psaddu.db", MATCH_PSADDU_DB, MASK_PSADDU_DB, "PQU", EXT_P},
  {"psaddu.dh", MATCH_PSADDU_DH, MASK_PSADDU_DH, "PQU", EXT_P},
  {"psaddu.dw", MATCH_PSADDU_DW, MASK_PSADDU_DW, "PQU", EXT_P},
  {"psub.b", MATCH_PSUB_B, MASK_PSUB_B, "dst", EXT_P},
  {"psub.h", MATCH_PSUB_H, MASK_PSUB_H, "dst", EXT_P},
  {"psub.db", MATCH_PSUB_DB, MASK_PSUB_DB, "PQU", EXT_P},
  {"psub.dh", MATCH_PSUB_DH, MASK_PSUB_DH, "PQU", EXT_P},
  {"psub.dw", MATCH_PSUB_DW, MASK_PSUB_DW, "PQU", EXT_P},
  {"pssub.b", MATCH_PSSUB_B, MASK_PSSUB_B, "dst", EXT_P},
  {"pssub.h", MATCH_PSSUB_H, MASK_PSSUB_H, "dst", EXT_P},
  {"pssub.db", MATCH_PSSUB_DB, MASK_PSSUB_DB, "PQU", EXT_P},
  {"pssub.dh", MATCH_PSSUB_DH, MASK_PSSUB_DH, "PQU", EXT_P},
  {"pssub.dw", MATCH_PSSUB_DW, MASK_PSSUB_DW, "PQU", EXT_P},
  {"pssubu.b", MATCH_PSSUBU_B, MASK_PSSUBU_B, "dst", EXT_P},
  {"pssubu.h", MATCH_PSSUBU_H, MASK_PSSUBU_H, "dst", EXT_P},
  {"pssubu.db", MATCH_PSSUBU_DB, MASK_PSSUBU_DB, "PQU", EXT_P},
  {"pssubu.dh", MATCH_PSSUBU_DH, MASK_PSSUBU_DH, "PQU", EXT_P},
  {"pssubu.dw", MATCH_PSSUBU_DW, MASK_PSSUBU_DW, "PQU", EXT_P},
  {"psa.hx", MATCH_PSA_HX, MASK_PSA_HX, "dst", EXT_P},
  {"psa.dhx", MATCH_PSA_DHX, MASK_PSA_DHX, "PQU", EXT_P},
  {"psas.hx", MATCH_PSAS_HX, MASK_PSAS_HX, "dst", EXT_P},
  {"psas.dhx", MATCH_PSAS_DHX, MASK_PSAS_DHX, "PQU", EXT_P},
  {"pssa.hx", MATCH_PSSA_HX, MASK_PSSA_HX, "dst", EXT_P},
  {"pssa.dhx", MATCH_PSSA_DHX, MASK_PSSA_DHX, "PQU", EXT_P},
  {"pmax.b", MATCH_PMAX_B, MASK_PMAX_B, "dst", EXT_P},
  {"pmax.h", MATCH_PMAX_H, MASK_PMAX_H, "dst", EXT_P},
  {"pmax.db", MATCH_PMAX_DB, MASK_PMAX_DB, "PQU", EXT_P},
  {"pmax.dh", MATCH_PMAX_DH, MASK_PMAX_DH, "PQU", EXT_P},
  {"pmax.dw", MATCH_PMAX_DW, MASK_PMAX_DW, "PQU", EXT_P},
  {"pmaxu.b", MATCH_PMAXU_B, MASK_PMAXU_B, "dst", EXT_P},
  {"pmaxu.h", MATCH_PMAXU_H, MASK_PMAXU_H, "dst", EXT_P},
  {"pmaxu.db", MATCH_PMAXU_DB, MASK_PMAXU_DB, "PQU", EXT_P},
  {"pmaxu.dh", MATCH_PMAXU_DH, MASK_PMAXU_DH, "PQU", EXT_P},
  {"pmaxu.dw", MATCH_PMAXU_DW, MASK_PMAXU_DW, "PQU", EXT_P},
  {"pmin.b", MATCH_PMIN_B, MASK_PMIN_B, "dst", EXT_P},
  {"pmin.h", MATCH_PMIN_H, MASK_PMIN_H, "dst", EXT_P},
  {"pmin.db", MATCH_PMIN_DB, MASK_PMIN_DB, "PQU", EXT_P},
  {"pmin.dh", MATCH_PMIN_DH, MASK_PMIN_DH, "PQU", EXT_P},
  {"pmin.dw", MATCH_PMIN_DW, MASK_PMIN_DW, "PQU", EXT_P},
  {"pminu.b", MATCH_PMINU_B, MASK_PMINU_B, "dst", EXT_P},
  {"pminu.h", MATCH_PMINU_H, MASK_PMINU_H, "dst", EXT_P},
  {"pminu.db", MATCH_PMINU_DB, MASK_PMINU_DB, "PQU", EXT_P},
  {"pminu.dh", MATCH_PMINU_DH, MASK_PMINU_DH, "PQU", EXT_P},
  {"pminu.dw", MATCH_PMINU_DW, MASK_PMINU_DW, "PQU", EXT_P},
  {"pmseq.b", MATCH_PMSEQ_B, MASK_PMSEQ_B, "dst", EXT_P},
  {"pmseq.h", MATCH_PMSEQ_H, MASK_PMSEQ_H, "dst", EXT_P},
  {"pmseq.db", MATCH_PMSEQ_DB, MASK_PMSEQ_DB, "PQU", EXT_P},
  {"pmseq.dh", MATCH_PMSEQ_DH, MASK_PMSEQ_DH, "PQU", EXT_P},
  {"pmseq.dw", MATCH_PMSEQ_DW, MASK_PMSEQ_DW, "PQU", EXT_P},
  {"pmslt.b", MATCH_PMSLT_B, MASK_PMSLT_B, "dst", EXT_P},
  {"pmslt.h", MATCH_PMSLT_H, MASK_PMSLT_H, "dst", EXT_P},
  {"pmslt.db", MATCH_PMSLT_DB, MASK_PMSLT_DB, "PQU", EXT_P},
  {"pmslt.dh", MATCH_PMSLT_DH, MASK_PMSLT_DH, "PQU", EXT_P},
  {"pmslt.dw", MATCH_PMSLT_DW, MASK_PMSLT_DW, "PQU", EXT_P},
  {"pmsltu.b", MATCH_PMSLTU_B, MASK_PMSLTU_B, "dst", EXT_P},
  {"pmsltu.h", MATCH_PMSLTU_H, MASK_PMSLTU_H, "dst", EXT_P},
  {"pmsltu.db", MATCH_PMSLTU_DB, MASK_PMSLTU_DB, "PQU", EXT_P},
  {"pmsltu.dh", MATCH_PMSLTU_DH, MASK_PMSLTU_DH, "PQU", EXT_P},
  {"pmsltu.dw", MATCH_PMSLTU_DW, MASK_PMSLTU_DW, "PQU", EXT_P},
  {"psll.bs", MATCH_PSLL_BS, MASK_PSLL_BS, "dst", EXT_P},
  {"psll.hs", MATCH_PSLL_HS, MASK_PSLL_HS, "dst", EXT_P},
  {"psll.dbs", MATCH_PSLL_DBS, MASK_PSLL_DBS, "PQt", EXT_P},
  {"psll.dhs", MATCH_PSLL_DHS, MASK_PSLL_DHS, "PQt", EXT_P},
  {"psll.dws", MATCH_PSLL_DWS, MASK_PSLL_DWS, "PQt", EXT_P},
  {"psra.bs", MATCH_PSRA_BS, MASK_PSRA_BS, "dst", EXT_P},
  {"psra.hs", MATCH_PSRA_HS, MASK_PSRA_HS, "dst", EXT_P},
  {"psra.dbs", MATCH_PSRA_DBS, MASK_PSRA_DBS, "PQt", EXT_P},
  {"psra.dhs", MATCH_PSRA_DHS, MASK_PSRA_DHS, "PQt", EXT_P},
  {"psra.dws", MATCH_PSRA_DWS, MASK_PSRA_DWS, "PQt", EXT_P},
  {"psrl.bs", MATCH_PSRL_BS, MASK_PSRL_BS, "dst", EXT_P},
  {"psrl.hs", MATCH_PSRL_HS, MASK_PSRL_HS, "dst", EXT_P},
  {"psrl.dbs", MATCH_PSRL_DBS, MASK_PSRL_DBS, "PQt", EXT_P},
  {"psrl.dhs", MATCH_PSRL_DHS, MASK_PSRL_DHS, "PQt", EXT_P},
  {"psrl.dws", MATCH_PSRL_DWS, MASK_PSRL_DWS, "PQt", EXT_P},
  {"pssha.hs", MATCH_PSSHA_HS, MASK_PSSHA_HS, "dst", EXT_P},
  {"pssha.dhs", MATCH_PSSHA_DHS, MASK_PSSHA_DHS, "PQt", EXT_P},
  {"pssha.dws", MATCH_PSSHA_DWS, MASK_PSSHA_DWS, "PQt", EXT_P},
  {"psshar.hs", MATCH_PSSHAR_HS, MASK_PSSHAR_HS, "dst", EXT_P},
  {"psshar.dhs", MATCH_PSSHAR_DHS, MASK_PSSHAR_DHS, "PQt", EXT_P},
  {"psshar.dws", MATCH_PSSHAR_DWS, MASK_PSSHAR_DWS, "PQt", EXT_P},
  {"psshl.hs", MATCH_PSSHL_HS, MASK_PSSHL_HS, "dst", EXT_P},
  {"psshl.dhs", MATCH_PSSHL_DHS, MASK_PSSHL_DHS, "PQt", EXT_P},
  {"psshl.dws", MATCH_PSSHL_DWS, MASK_PSSHL_DWS, "PQt", EXT_P},
  {"psshlr.hs", MATCH_PSSHLR_HS, MASK_PSSHLR_HS, "dst", EXT_P},
  {"psshlr.dhs", MATCH_PSSHLR_DHS, MASK_PSSHLR_DHS, "PQt", EXT_P},
  {"psshlr.dws", MATCH_PSSHLR_DWS, MASK_PSSHLR_DWS, "PQt", EXT_P},
  {"psh1add.h", MATCH_PSH1ADD_H, MASK_PSH1ADD_H, "dst", EXT_P},
  {"psh1add.dh", MATCH_PSH1ADD_DH, MASK_PSH1ADD_DH, "PQU", EXT_P},
  {"psh1add.dw", MATCH_PSH1ADD_DW, MASK_PSH1ADD_DW, "PQU", EXT_P},
  {"pssh1sadd.h", MATCH_PSSH1SADD_H, MASK_PSSH1SADD_H, "dst", EXT_P},
  {"pssh1sadd.dh", MATCH_PSSH1SADD_DH, MASK_PSSH1SADD_DH, "PQU", EXT_P},
  {"pssh1sadd.dw", MATCH_PSSH1SADD_DW, MASK_PSSH1SADD_DW, "PQU", EXT_P},
  {"pnclip.bs", MATCH_PNCLIP_BS, MASK_PNCLIP_BS, "dQt", EXT_P},
  {"pnclip.hs", MATCH_PNCLIP_HS, MASK_PNCLIP_HS, "dQt", EXT_P},
  {"pnclipr.bs", MATCH_PNCLIPR_BS, MASK_PNCLIPR_BS, "dQt", EXT_P},
  {"pnclipr.hs", MATCH_PNCLIPR_HS, MASK_PNCLIPR_HS, "dQt", EXT_P},
  {"pnclipu.bs", MATCH_PNCLIPU_BS, MASK_PNCLIPU_BS, "dQt", EXT_P},
  {"pnclipu.hs", MATCH_PNCLIPU_HS, MASK_PNCLIPU_HS, "dQt", EXT_P},
  {"pnclipru.bs", MATCH_PNCLIPRU_BS, MASK_PNCLIPRU_BS, "dQt", EXT_P},
  {"pnclipru.hs", MATCH_PNCLIPRU_HS, MASK_PNCLIPRU_HS, "dQt", EXT_P},
  {"pnsra.bs", MATCH_PNSRA_BS, MASK_PNSRA_BS, "dQt", EXT_P},
  {"pnsra.hs", MATCH_PNSRA_HS, MASK_PNSRA_HS, "dQt", EXT_P},
  {"pnsrar.bs", MATCH_PNSRAR_BS, MASK_PNSRAR_BS, "dQt", EXT_P},
  {"pnsrar.hs", MATCH_PNSRAR_HS, MASK_PNSRAR_HS, "dQt", EXT_P},
  {"pnsrl.bs", MATCH_PNSRL_BS, MASK_PNSRL_BS, "dQt", EXT_P},
  {"pnsrl.hs", MATCH_PNSRL_HS, MASK_PNSRL_HS, "dQt", EXT_P},
  {"pwsll.bs", MATCH_PWSLL_BS, MASK_PWSLL_BS, "Pst", EXT_P},
  {"pwsll.hs", MATCH_PWSLL_HS, MASK_PWSLL_HS, "Pst", EXT_P},
  {"pwsla.bs", MATCH_PWSLA_BS, MASK_PWSLA_BS, "Pst", EXT_P},
  {"pwsla.hs", MATCH_PWSLA_HS, MASK_PWSLA_HS, "Pst", EXT_P},
  {"ppaire.b", MATCH_PPAIRE_B, MASK_PPAIRE_B, "dst", EXT_P},
  {"ppaire.h", MATCH_PPAIRE_H, MASK_PPAIRE_H, "dst", EXT_P},
  {"ppaire.db", MATCH_PPAIRE_DB, MASK_PPAIRE_DB, "PQU", EXT_P},
  {"ppaire.dh", MATCH_PPAIRE_DH, MASK_PPAIRE_DH, "PQU", EXT_P},
  {"ppaireo.b", MATCH_PPAIREO_B, MASK_PPAIREO_B, "dst", EXT_P},
  {"ppaireo.h", MATCH_PPAIREO_H, MASK_PPAIREO_H, "dst", EXT_P},
  {"ppaireo.db", MATCH_PPAIREO_DB, MASK_PPAIREO_DB, "PQU", EXT_P},
  {"ppaireo.dh", MATCH_PPAIREO_DH, MASK_PPAIREO_DH, "PQU", EXT_P},
  {"ppairo.b", MATCH_PPAIRO_B, MASK_PPAIRO_B, "dst", EXT_P},
  {"ppairo.h", MATCH_PPAIRO_H, MASK_PPAIRO_H, "dst", EXT_P},
  {"ppairo.db", MATCH_PPAIRO_DB, MASK_PPAIRO_DB, "PQU", EXT_P},
  {"ppairo.dh", MATCH_PPAIRO_DH, MASK_PPAIRO_DH, "PQU", EXT_P},
  {"ppairoe.b", MATCH_PPAIROE_B, MASK_PPAIROE_B, "dst", EXT_P},
  {"ppairoe.h", MATCH_PPAIROE_H, MASK_PPAIROE_H, "dst", EXT_P},
  {"ppairoe.db", MATCH_PPAIROE_DB, MASK_PPAIROE_DB, "PQU", EXT_P},
  {"ppairoe.dh", MATCH_PPAIROE_DH, MASK_PPAIROE_DH, "PQU", EXT_P},
  {"predsum.bs", MATCH_PREDSUM_BS, MASK_PREDSUM_BS, "dst", EXT_P},
  {"predsum.hs", MATCH_PREDSUM_HS, MASK_PREDSUM_HS, "dst", EXT_P},
  {"predsum.dbs", MATCH_PREDSUM_DBS, MASK_PREDSUM_DBS, "dQt", EXT_P},
  {"predsum.dhs", MATCH_PREDSUM_DHS, MASK_PREDSUM_DHS, "dQt", EXT_P},
  {"predsumu.bs", MATCH_PREDSUMU_BS, MASK_PREDSUMU_BS, "dst", EXT_P},
  {"predsumu.hs", MATCH_PREDSUMU_HS, MASK_PREDSUMU_HS, "dst", EXT_P},
  {"predsumu.dbs", MATCH_PREDSUMU_DBS, MASK_PREDSUMU_DBS, "dQt", EXT_P},
  {"predsumu.dhs", MATCH_PREDSUMU_DHS, MASK_PREDSUMU_DHS, "dQt", EXT_P},
  {"psabs.b", MATCH_PSABS_B, MASK_PSABS_B, "ds", EXT_P},
  {"psabs.h", MATCH_PSABS_H, MASK_PSABS_H, "ds", EXT_P},
  {"psabs.db", MATCH_PSABS_DB, MASK_PSABS_DB, "PQ", EXT_P},
  {"psabs.dh", MATCH_PSABS_DH, MASK_PSABS_DH, "PQ", EXT_P},
  {"psext.h.b", MATCH_PSEXT_H_B, MASK_PSEXT_H_B, "ds", EXT_P},
  {"psext.dh.b", MATCH_PSEXT_DH_B, MASK_PSEXT_DH_B, "PQ", EXT_P},
  {"psext.dw.b", MATCH_PSEXT_DW_B, MASK_PSEXT_DW_B, "PQ", EXT_P},
  {"psext.dw.h", MATCH_PSEXT_DW_H, MASK_PSEXT_DW_H, "PQ", EXT_P},
  {"pslli.b", MATCH_PSLLI_B, MASK_PSLLI_B, "ds:", EXT_P},
  {"pslli.h", MATCH_PSLLI_H, MASK_PSLLI_H, "ds;", EXT_P},
  {"pslli.db", MATCH_PSLLI_DB, MASK_PSLLI_DB, "PQ:", EXT_P},
  {"pslli.dh", MATCH_PSLLI_DH, MASK_PSLLI_DH, "PQ;", EXT_P},
  {"pslli.dw", MATCH_PSLLI_DW, MASK_PSLLI_DW, "PQ<", EXT_P},
  {"psrai.b", MATCH_PSRAI_B, MASK_PSRAI_B, "ds:", EXT_P},
  {"psrai.h", MATCH_PSRAI_H, MASK_PSRAI_H, "ds;", EXT_P},
  {"psrai.db", MATCH_PSRAI_DB, MASK_PSRAI_DB, "PQ:", EXT_P},
  {"psrai.dh", MATCH_PSRAI_DH, MASK_PSRAI_DH, "PQ;", EXT_P},
  {"psrai.dw", MATCH_PSRAI_DW, MASK_PSRAI_DW, "PQ<", EXT_P},
  {"psrli.b", MATCH_PSRLI_B, MASK_PSRLI_B, "ds:", EXT_P},
  {"psrli.h", MATCH_PSRLI_H, MASK_PSRLI_H, "ds;", EXT_P},
  {"psrli.db", MATCH_PSRLI_DB, MASK_PSRLI_DB, "PQ:", EXT_P},
  {"psrli.dh", MATCH_PSRLI_DH, MASK_PSRLI_DH, "PQ;", EXT_P},
  {"psrli.dw", MATCH_PSRLI_DW, MASK_PSRLI_DW, "PQ<", EXT_P},
  {"psrari.h", MATCH_PSRARI_H, MASK_PSRARI_H, "ds;", EXT_P},
  {"psrari.dh", MATCH_PSRARI_DH, MASK_PSRARI_DH, "PQ;", EXT_P},
  {"psrari.dw", MATCH_PSRARI_DW, MASK_PSRARI_DW, "PQ<", EXT_P},
  {"psati.h", MATCH_PSATI_H, MASK_PSATI_H, "ds;", EXT_P},
  {"psati.dh", MATCH_PSATI_DH, MASK_PSATI_DH, "PQ;", EXT_P},
  {"psati.dw", MATCH_PSATI_DW, MASK_PSATI_DW, "PQ<", EXT_P},
  {"pusati.h", MATCH_PUSATI_H, MASK_PUSATI_H, "ds;", EXT_P},
  {"pusati.dh", MATCH_PUSATI_DH, MASK_PUSATI_DH, "PQ;", EXT_P},
  {"pusati.dw", MATCH_PUSATI_DW, MASK_PUSATI_DW, "PQ<", EXT_P},
  {"psslai.h", MATCH_PSSLAI_H, MASK_PSSLAI_H, "ds;", EXT_P},
  {"psslai.dh", MATCH_PSSLAI_DH, MASK_PSSLAI_DH, "PQ;", EXT_P},
  {"psslai.dw", MATCH_PSSLAI_DW, MASK_PSSLAI_DW, "PQ<", EXT_P},
  {"pnclipi.b", MATCH_PNCLIPI_B, MASK_PNCLIPI_B, "dQ;", EXT_P},
  {"pnclipi.h", MATCH_PNCLIPI_H, MASK_PNCLIPI_H, "dQ<", EXT_P},
  {"pnclipiu.b", MATCH_PNCLIPIU_B, MASK_PNCLIPIU_B, "dQ;", EXT_P},
  {"pnclipiu.h", MATCH_PNCLIPIU_H, MASK_PNCLIPIU_H, "dQ<", EXT_P},
  {"pnclipri.b", MATCH_PNCLIPRI_B, MASK_PNCLIPRI_B, "dQ;", EXT_P},
  {"pnclipri.h", MATCH_PNCLIPRI_H, MASK_PNCLIPRI_H, "dQ<", EXT_P},
  {"pnclipriu.b", MATCH_PNCLIPRIU_B, MASK_PNCLIPRIU_B, "dQ;", EXT_P},
  {"pnclipriu.h", MATCH_PNCLIPRIU_H, MASK_PNCLIPRIU_H, "dQ<", EXT_P},
  {"pnsrai.b", MATCH_PNSRAI_B, MASK_PNSRAI_B, "dQ;", EXT_P},
  {"pnsrai.h", MATCH_PNSRAI_H, MASK_PNSRAI_H, "dQ<", EXT_P},
  {"pnsrari.b", MATCH_PNSRARI_B, MASK_PNSRARI_B, "dQ;", EXT_P},
  {"pnsrari.h", MATCH_PNSRARI_H, MASK_PNSRARI_H, "dQ<", EXT_P},
  {"pnsrli.b", MATCH_PNSRLI_B, MASK_PNSRLI_B, "dQ;", EXT_P},
  {"pnsrli.h", MATCH_PNSRLI_H, MASK_PNSRLI_H, "dQ<", EXT_P},
  {"pwslli.b", MATCH_PWSLLI_B, MASK_PWSLLI_B, "Ps:", EXT_P},
  {"pwslli.h", MATCH_PWSLLI_H, MASK_PWSLLI_H, "Ps;", EXT_P},
  {"pwslai.b", MATCH_PWSLAI_B, MASK_PWSLAI_B, "Ps:", EXT_P},
  {"pwslai.h", MATCH_PWSLAI_H, MASK_PWSLAI_H, "Ps;", EXT_P},
  {"pli.b", MATCH_PLI_B, MASK_PLI_B, "d7", EXT_P},
  {"pli.h", MATCH_PLI_H, MASK_PLI_H, "d$", EXT_P},
  {"pli.db", MATCH_PLI_DB, MASK_PLI_DB, "P7", EXT_P},
  {"pli.dh", MATCH_PLI_DH, MASK_PLI_DH, "P$", EXT_P},
  {"plui.h", MATCH_PLUI_H, MASK_PLUI_H, "d%", EXT_P},
  {"plui.dh", MATCH_PLUI_DH, MASK_PLUI_DH, "P%", EXT_P},
  {"pmul.h.b00", MATCH_PMUL_H_B00, MASK_PMUL_H_B00, "dst", EXT_P},
  {"pmul.h.b01", MATCH_PMUL_H_B01, MASK_PMUL_H_B01, "dst", EXT_P},
  {"pmul.h.b11", MATCH_PMUL_H_B11, MASK_PMUL_H_B11, "dst", EXT_P},
  {"pmulu.h.b00", MATCH_PMULU_H_B00, MASK_PMULU_H_B00, "dst", EXT_P},
  {"pmulu.h.b01", MATCH_PMULU_H_B01, MASK_PMULU_H_B01, "dst", EXT_P},
  {"pmulu.h.b11", MATCH_PMULU_H_B11, MASK_PMULU_H_B11, "dst", EXT_P},
  {"pmulsu.h.b00", MATCH_PMULSU_H_B00, MASK_PMULSU_H_B00, "dst", EXT_P},
  {"pmulsu.h.b11", MATCH_PMULSU_H_B11, MASK_PMULSU_H_B11, "dst", EXT_P},
  {"pmulh.h", MATCH_PMULH_H, MASK_PMULH_H, "dst", EXT_P},
  {"pmulhu.h", MATCH_PMULHU_H, MASK_PMULHU_H, "dst", EXT_P},
  {"pmulhsu.h", MATCH_PMULHSU_H, MASK_PMULHSU_H, "dst", EXT_P},
  {"pmulh.h.b0", MATCH_PMULH_H_B0, MASK_PMULH_H_B0, "dst", EXT_P},
  {"pmulh.h.b1", MATCH_PMULH_H_B1, MASK_PMULH_H_B1, "dst", EXT_P},
  {"pmulhsu.h.b0", MATCH_PMULHSU_H_B0, MASK_PMULHSU_H_B0, "dst", EXT_P},
  {"pmulhsu.h.b1", MATCH_PMULHSU_H_B1, MASK_PMULHSU_H_B1, "dst", EXT_P},
  {"pmulhr.h", MATCH_PMULHR_H, MASK_PMULHR_H, "dst", EXT_P},
  {"pmulhru.h", MATCH_PMULHRU_H, MASK_PMULHRU_H, "dst", EXT_P},
  {"pmulhrsu.h", MATCH_PMULHRSU_H, MASK_PMULHRSU_H, "dst", EXT_P},
  {"pmulq.h", MATCH_PMULQ_H, MASK_PMULQ_H, "dst", EXT_P},
  {"pmulqr.h", MATCH_PMULQR_H, MASK_PMULQR_H, "dst", EXT_P},
  {"pmhacc.h", MATCH_PMHACC_H, MASK_PMHACC_H, "dst", EXT_P},
  {"pmhaccu.h", MATCH_PMHACCU_H, MASK_PMHACCU_H, "dst", EXT_P},
  {"pmhaccsu.h", MATCH_PMHACCSU_H, MASK_PMHACCSU_H, "dst", EXT_P},
  {"pmhacc.h.b0", MATCH_PMHACC_H_B0, MASK_PMHACC_H_B0, "dst", EXT_P},
  {"pmhacc.h.b1", MATCH_PMHACC_H_B1, MASK_PMHACC_H_B1, "dst", EXT_P},
  {"pmhaccsu.h.b0", MATCH_PMHACCSU_H_B0, MASK_PMHACCSU_H_B0, "dst", EXT_P},
  {"pmhaccsu.h.b1", MATCH_PMHACCSU_H_B1, MASK_PMHACCSU_H_B1, "dst", EXT_P},
  {"pmhracc.h", MATCH_PMHRACC_H, MASK_PMHRACC_H, "dst", EXT_P},
  {"pmhraccu.h", MATCH_PMHRACCU_H, MASK_PMHRACCU_H, "dst", EXT_P},
  {"pmhraccsu.h", MATCH_PMHRACCSU_H, MASK_PMHRACCSU_H, "dst", EXT_P},
  {"pmq2add.h", MATCH_PMQ2ADD_H, MASK_PMQ2ADD_H, "dst", EXT_P},
  {"pmq2adda.h", MATCH_PMQ2ADDA_H, MASK_PMQ2ADDA_H, "dst", EXT_P},
  {"pmqr2add.h", MATCH_PMQR2ADD_H, MASK_PMQR2ADD_H, "dst", EXT_P},
  {"pmqr2adda.h", MATCH_PMQR2ADDA_H, MASK_PMQR2ADDA_H, "dst", EXT_P},
  {"pwadd.b", MATCH_PWADD_B, MASK_PWADD_B, "Pst", EXT_P},
  {"pwadd.h", MATCH_PWADD_H, MASK_PWADD_H, "Pst", EXT_P},
  {"pwaddu.b", MATCH_PWADDU_B, MASK_PWADDU_B, "Pst", EXT_P},
  {"pwaddu.h", MATCH_PWADDU_H, MASK_PWADDU_H, "Pst", EXT_P},
  {"pwadda.b", MATCH_PWADDA_B, MASK_PWADDA_B, "Pst", EXT_P},
  {"pwadda.h", MATCH_PWADDA_H, MASK_PWADDA_H, "Pst", EXT_P},
  {"pwaddau.b", MATCH_PWADDAU_B, MASK_PWADDAU_B, "Pst", EXT_P},
  {"pwaddau.h", MATCH_PWADDAU_H, MASK_PWADDAU_H, "Pst", EXT_P},
  {"pwsub.b", MATCH_PWSUB_B, MASK_PWSUB_B, "Pst", EXT_P},
  {"pwsub.h", MATCH_PWSUB_H, MASK_PWSUB_H, "Pst", EXT_P},
  {"pwsubu.b", MATCH_PWSUBU_B, MASK_PWSUBU_B, "Pst", EXT_P},
  {"pwsubu.h", MATCH_PWSUBU_H, MASK_PWSUBU_H, "Pst", EXT_P},
  {"pwsuba.b", MATCH_PWSUBA_B, MASK_PWSUBA_B, "Pst", EXT_P},
  {"pwsuba.h", MATCH_PWSUBA_H, MASK_PWSUBA_H, "Pst", EXT_P},
  {"pwsubau.b", MATCH_PWSUBAU_B, MASK_PWSUBAU_B, "Pst", EXT_P},
  {"pwsubau.h", MATCH_PWSUBAU_H, MASK_PWSUBAU_H, "Pst", EXT_P},
  {"pwmul.b", MATCH_PWMUL_B, MASK_PWMUL_B, "Pst", EXT_P},
  {"pwmul.h", MATCH_PWMUL_H, MASK_PWMUL_H, "Pst", EXT_P},
  {"pwmulu.b", MATCH_PWMULU_B, MASK_PWMULU_B, "Pst", EXT_P},
  {"pwmulu.h", MATCH_PWMULU_H, MASK_PWMULU_H, "Pst", EXT_P},
  {"pwmulsu.b", MATCH_PWMULSU_B, MASK_PWMULSU_B, "Pst", EXT_P},
  {"pwmulsu.h", MATCH_PWMULSU_H, MASK_PWMULSU_H, "Pst", EXT_P},
  {"pwmacc.h", MATCH_PWMACC_H, MASK_PWMACC_H, "Pst", EXT_P},
  {"pwmaccu.h", MATCH_PWMACCU_H, MASK_PWMACCU_H, "Pst", EXT_P},
  {"pwmaccsu.h", MATCH_PWMACCSU_H, MASK_PWMACCSU_H, "Pst", EXT_P},
  {"pm2add.h", MATCH_PM2ADD_H, MASK_PM2ADD_H, "dst", EXT_P},
  {"pm2add.hx", MATCH_PM2ADD_HX, MASK_PM2ADD_HX, "dst", EXT_P},
  {"pm2addu.h", MATCH_PM2ADDU_H, MASK_PM2ADDU_H, "dst", EXT_P},
  {"pm2addsu.h", MATCH_PM2ADDSU_H, MASK_PM2ADDSU_H, "dst", EXT_P},
  {"pm2adda.h", MATCH_PM2ADDA_H, MASK_PM2ADDA_H, "dst", EXT_P},
  {"pm2adda.hx", MATCH_PM2ADDA_HX, MASK_PM2ADDA_HX, "dst", EXT_P},
  {"pm2addau.h", MATCH_PM2ADDAU_H, MASK_PM2ADDAU_H, "dst", EXT_P},
  {"pm2addasu.h", MATCH_PM2ADDASU_H, MASK_PM2ADDASU_H, "dst", EXT_P},
  {"pm2sub.h", MATCH_PM2SUB_H, MASK_PM2SUB_H, "dst", EXT_P},
  {"pm2sub.hx", MATCH_PM2SUB_HX, MASK_PM2SUB_HX, "dst", EXT_P},
  {"pm2suba.h", MATCH_PM2SUBA_H, MASK_PM2SUBA_H, "dst", EXT_P},
  {"pm2suba.hx", MATCH_PM2SUBA_HX, MASK_PM2SUBA_HX, "dst", EXT_P},
  {"pm2sadd.h", MATCH_PM2SADD_H, MASK_PM2SADD_H, "dst", EXT_P},
  {"pm2sadd.hx", MATCH_PM2SADD_HX, MASK_PM2SADD_HX, "dst", EXT_P},
  {"pm2wadd.h", MATCH_PM2WADD_H, MASK_PM2WADD_H, "Pst", EXT_P},
  {"pm2wadd.hx", MATCH_PM2WADD_HX, MASK_PM2WADD_HX, "Pst", EXT_P},
  {"pm2waddu.h", MATCH_PM2WADDU_H, MASK_PM2WADDU_H, "Pst", EXT_P},
  {"pm2waddsu.h", MATCH_PM2WADDSU_H, MASK_PM2WADDSU_H, "Pst", EXT_P},
  {"pm2wadda.h", MATCH_PM2WADDA_H, MASK_PM2WADDA_H, "Pst", EXT_P},
  {"pm2wadda.hx", MATCH_PM2WADDA_HX, MASK_PM2WADDA_HX, "Pst", EXT_P},
  {"pm2waddau.h", MATCH_PM2WADDAU_H, MASK_PM2WADDAU_H, "Pst", EXT_P},
  {"pm2waddasu.h", MATCH_PM2WADDASU_H, MASK_PM2WADDASU_H, "Pst", EXT_P},
  {"pm2wsub.h", MATCH_PM2WSUB_H, MASK_PM2WSUB_H, "Pst", EXT_P},
  {"pm2wsub.hx", MATCH_PM2WSUB_HX, MASK_PM2WSUB_HX, "Pst", EXT_P},
  {"pm2wsuba.h", MATCH_PM2WSUBA_H, MASK_PM2WSUBA_H, "Pst", EXT_P},
  {"pm2wsuba.hx", MATCH_PM2WSUBA_HX, MASK_PM2WSUBA_HX, "Pst", EXT_P},
  {"pm4add.b", MATCH_PM4ADD_B, MASK_PM4ADD_B, "dst", EXT_P},
  {"pm4addu.b", MATCH_PM4ADDU_B, MASK_PM4ADDU_B, "dst", EXT_P},
  {"pm4addsu.b", MATCH_PM4ADDSU_B, MASK_PM4ADDSU_B, "dst", EXT_P},
  {"pm4adda.b", MATCH_PM4ADDA_B, MASK_PM4ADDA_B, "dst", EXT_P},
  {"pm4addau.b", MATCH_PM4ADDAU_B, MASK_PM4ADDAU_B, "dst", EXT_P},
  {"pm4addasu.b", MATCH_PM4ADDASU_B, MASK_PM4ADDASU_B, "dst", EXT_P},
  {"zip8p", MATCH_ZIP8P, MASK_ZIP8P, "ds", EXT_P},
  {"zip8hp", MATCH_ZIP8HP, MASK_ZIP8HP, "ds", EXT_P},
  {"unzip8p", MATCH_UNZIP8P, MASK_UNZIP8P, "ds", EXT_P},
  {"unzip8hp", MATCH_UNZIP8HP, MASK_UNZIP8HP, "ds", EXT_P},
  {"unzip16p", MATCH_UNZIP16P, MASK_UNZIP16P, "ds", EXT_P},
  {"unzip16hp", MATCH_UNZIP16HP, MASK_UNZIP16HP, "ds", EXT_P},
  {"wzip8p", MATCH_WZIP8P, MASK_WZIP8P, "Ps", EXT_P},
  {"wzip16p", MATCH_WZIP16P, MASK_WZIP16P, "Ps", EXT_P},
  {"mqwacc", MATCH_MQWACC, MASK_MQWACC, "Pst", EXT_P},
  {"mqrwacc", MATCH_MQRWACC, MASK_MQRWACC, "Pst", EXT_P},
  {"pmqwacc.h", MATCH_PMQWACC_H, MASK_PMQWACC_H, "Pst", EXT_P},
  {"pmqrwacc.h", MATCH_PMQRWACC_H, MASK_PMQRWACC_H, "Pst", EXT_P},
  {"absw", MATCH_ABSW, MASK_ABSW, "ds", EXT_P_RV64},
  {"clsw", MATCH_CLSW, MASK_CLSW, "ds", EXT_P_RV64},
  {"macc.w00", MATCH_MACC_W00, MASK_MACC_W00, "dst", EXT_P_RV64},
  {"macc.w01", MATCH_MACC_W01, MASK_MACC_W01, "dst", EXT_P_RV64},
  {"macc.w11", MATCH_MACC_W11, MASK_MACC_W11, "dst", EXT_P_RV64},
  {"maccu.w00", MATCH_MACCU_W00, MASK_MACCU_W00, "dst", EXT_P_RV64},
  {"maccu.w01", MATCH_MACCU_W01, MASK_MACCU_W01, "dst", EXT_P_RV64},
  {"maccu.w11", MATCH_MACCU_W11, MASK_MACCU_W11, "dst", EXT_P_RV64},
  {"maccsu.w00", MATCH_MACCSU_W00, MASK_MACCSU_W00, "dst", EXT_P_RV64},
  {"maccsu.w11", MATCH_MACCSU_W11, MASK_MACCSU_W11, "dst", EXT_P_RV64},
  {"mul.w00", MATCH_MUL_W00, MASK_MUL_W00, "dst", EXT_P_RV64},
  {"mul.w01", MATCH_MUL_W01, MASK_MUL_W01, "dst", EXT_P_RV64},
  {"mul.w11", MATCH_MUL_W11, MASK_MUL_W11, "dst", EXT_P_RV64},
  {"mulu.w00", MATCH_MULU_W00, MASK_MULU_W00, "dst", EXT_P_RV64},
  {"mulu.w01", MATCH_MULU_W01, MASK_MULU_W01, "dst", EXT_P_RV64},
  {"mulu.w11", MATCH_MULU_W11, MASK_MULU_W11, "dst", EXT_P_RV64},
  {"mulsu.w00", MATCH_MULSU_W00, MASK_MULSU_W00, "dst", EXT_P_RV64},
  {"mulsu.w11", MATCH_MULSU_W11, MASK_MULSU_W11, "dst", EXT_P_RV64},
  {"mqacc.w00", MATCH_MQACC_W00, MASK_MQACC_W00, "dst", EXT_P_RV64},
  {"mqacc.w01", MATCH_MQACC_W01, MASK_MQACC_W01, "dst", EXT_P_RV64},
  {"mqacc.w11", MATCH_MQACC_W11, MASK_MQACC_W11, "dst", EXT_P_RV64},
  {"mqracc.w00", MATCH_MQRACC_W00, MASK_MQRACC_W00, "dst", EXT_P_RV64},
  {"mqracc.w01", MATCH_MQRACC_W01, MASK_MQRACC_W01, "dst", EXT_P_RV64},
  {"mqracc.w11", MATCH_MQRACC_W11, MASK_MQRACC_W11, "dst", EXT_P_RV64},
  {"paadd.w", MATCH_PAADD_W, MASK_PAADD_W, "dst", EXT_P_RV64},
  {"paaddu.w", MATCH_PAADDU_W, MASK_PAADDU_W, "dst", EXT_P_RV64},
  {"paas.wx", MATCH_PAAS_WX, MASK_PAAS_WX, "dst", EXT_P_RV64},
  {"padd.w", MATCH_PADD_W, MASK_PADD_W, "dst", EXT_P_RV64},
  {"padd.ws", MATCH_PADD_WS, MASK_PADD_WS, "dst", EXT_P_RV64},
  {"pasa.wx", MATCH_PASA_WX, MASK_PASA_WX, "dst", EXT_P_RV64},
  {"pasub.w", MATCH_PASUB_W, MASK_PASUB_W, "dst", EXT_P_RV64},
  {"pasubu.w", MATCH_PASUBU_W, MASK_PASUBU_W, "dst", EXT_P_RV64},
  {"pas.wx", MATCH_PAS_WX, MASK_PAS_WX, "dst", EXT_P_RV64},
  {"pmax.w", MATCH_PMAX_W, MASK_PMAX_W, "dst", EXT_P_RV64},
  {"pmaxu.w", MATCH_PMAXU_W, MASK_PMAXU_W, "dst", EXT_P_RV64},
  {"pmin.w", MATCH_PMIN_W, MASK_PMIN_W, "dst", EXT_P_RV64},
  {"pminu.w", MATCH_PMINU_W, MASK_PMINU_W, "dst", EXT_P_RV64},
  {"pmseq.w", MATCH_PMSEQ_W, MASK_PMSEQ_W, "dst", EXT_P_RV64},
  {"pmslt.w", MATCH_PMSLT_W, MASK_PMSLT_W, "dst", EXT_P_RV64},
  {"pmsltu.w", MATCH_PMSLTU_W, MASK_PMSLTU_W, "dst", EXT_P_RV64},
  {"psadd.w", MATCH_PSADD_W, MASK_PSADD_W, "dst", EXT_P_RV64},
  {"psaddu.w", MATCH_PSADDU_W, MASK_PSADDU_W, "dst", EXT_P_RV64},
  {"psa.wx", MATCH_PSA_WX, MASK_PSA_WX, "dst", EXT_P_RV64},
  {"psas.wx", MATCH_PSAS_WX, MASK_PSAS_WX, "dst", EXT_P_RV64},
  {"pssa.wx", MATCH_PSSA_WX, MASK_PSSA_WX, "dst", EXT_P_RV64},
  {"pssub.w", MATCH_PSSUB_W, MASK_PSSUB_W, "dst", EXT_P_RV64},
  {"pssubu.w", MATCH_PSSUBU_W, MASK_PSSUBU_W, "dst", EXT_P_RV64},
  {"psub.w", MATCH_PSUB_W, MASK_PSUB_W, "dst", EXT_P_RV64},
  {"psh1add.w", MATCH_PSH1ADD_W, MASK_PSH1ADD_W, "dst", EXT_P_RV64},
  {"pssh1sadd.w", MATCH_PSSH1SADD_W, MASK_PSSH1SADD_W, "dst", EXT_P_RV64},
  {"psll.ws", MATCH_PSLL_WS, MASK_PSLL_WS, "dst", EXT_P_RV64},
  {"psra.ws", MATCH_PSRA_WS, MASK_PSRA_WS, "dst", EXT_P_RV64},
  {"psrl.ws", MATCH_PSRL_WS, MASK_PSRL_WS, "dst", EXT_P_RV64},
  {"pssha.ws", MATCH_PSSHA_WS, MASK_PSSHA_WS, "dst", EXT_P_RV64},
  {"psshar.ws", MATCH_PSSHAR_WS, MASK_PSSHAR_WS, "dst", EXT_P_RV64},
  {"psshl.ws", MATCH_PSSHL_WS, MASK_PSSHL_WS, "dst", EXT_P_RV64},
  {"psshlr.ws", MATCH_PSSHLR_WS, MASK_PSSHLR_WS, "dst", EXT_P_RV64},
  {"shl", MATCH_SHL, MASK_SHL, "dst", EXT_P_RV64},
  {"shlr", MATCH_SHLR, MASK_SHLR, "dst", EXT_P_RV64},
  {"pnclipp.b", MATCH_PNCLIPP_B, MASK_PNCLIPP_B, "dst", EXT_P_RV64},
  {"pnclipp.h", MATCH_PNCLIPP_H, MASK_PNCLIPP_H, "dst", EXT_P_RV64},
  {"pnclipp.w", MATCH_PNCLIPP_W, MASK_PNCLIPP_W, "dst", EXT_P_RV64},
  {"pnclipup.b", MATCH_PNCLIPUP_B, MASK_PNCLIPUP_B, "dst", EXT_P_RV64},
  {"pnclipup.h", MATCH_PNCLIPUP_H, MASK_PNCLIPUP_H, "dst", EXT_P_RV64},
  {"pnclipup.w", MATCH_PNCLIPUP_W, MASK_PNCLIPUP_W, "dst", EXT_P_RV64},
  {"ppaireo.w", MATCH_PPAIREO_W, MASK_PPAIREO_W, "dst", EXT_P_RV64},
  {"ppairoe.w", MATCH_PPAIROE_W, MASK_PPAIROE_W, "dst", EXT_P_RV64},
  {"ppairo.w", MATCH_PPAIRO_W, MASK_PPAIRO_W, "dst", EXT_P_RV64},
  {"predsum.ws", MATCH_PREDSUM_WS, MASK_PREDSUM_WS, "dst", EXT_P_RV64},
  {"predsumu.ws", MATCH_PREDSUMU_WS, MASK_PREDSUMU_WS, "dst", EXT_P_RV64},
  {"pmul.w.h00", MATCH_PMUL_W_H00, MASK_PMUL_W_H00, "dst", EXT_P_RV64},
  {"pmul.w.h01", MATCH_PMUL_W_H01, MASK_PMUL_W_H01, "dst", EXT_P_RV64},
  {"pmul.w.h11", MATCH_PMUL_W_H11, MASK_PMUL_W_H11, "dst", EXT_P_RV64},
  {"pmulu.w.h00", MATCH_PMULU_W_H00, MASK_PMULU_W_H00, "dst", EXT_P_RV64},
  {"pmulu.w.h01", MATCH_PMULU_W_H01, MASK_PMULU_W_H01, "dst", EXT_P_RV64},
  {"pmulu.w.h11", MATCH_PMULU_W_H11, MASK_PMULU_W_H11, "dst", EXT_P_RV64},
  {"pmulsu.w.h00", MATCH_PMULSU_W_H00, MASK_PMULSU_W_H00, "dst", EXT_P_RV64},
  {"pmulsu.w.h11", MATCH_PMULSU_W_H11, MASK_PMULSU_W_H11, "dst", EXT_P_RV64},
  {"pmulh.w", MATCH_PMULH_W, MASK_PMULH_W, "dst", EXT_P_RV64},
  {"pmulhu.w", MATCH_PMULHU_W, MASK_PMULHU_W, "dst", EXT_P_RV64},
  {"pmulhsu.w", MATCH_PMULHSU_W, MASK_PMULHSU_W, "dst", EXT_P_RV64},
  {"pmulh.w.h0", MATCH_PMULH_W_H0, MASK_PMULH_W_H0, "dst", EXT_P_RV64},
  {"pmulh.w.h1", MATCH_PMULH_W_H1, MASK_PMULH_W_H1, "dst", EXT_P_RV64},
  {"pmulhsu.w.h0", MATCH_PMULHSU_W_H0, MASK_PMULHSU_W_H0, "dst", EXT_P_RV64},
  {"pmulhsu.w.h1", MATCH_PMULHSU_W_H1, MASK_PMULHSU_W_H1, "dst", EXT_P_RV64},
  {"pmulhr.w", MATCH_PMULHR_W, MASK_PMULHR_W, "dst", EXT_P_RV64},
  {"pmulhru.w", MATCH_PMULHRU_W, MASK_PMULHRU_W, "dst", EXT_P_RV64},
  {"pmulhrsu.w", MATCH_PMULHRSU_W, MASK_PMULHRSU_W, "dst", EXT_P_RV64},
  {"pmulq.w", MATCH_PMULQ_W, MASK_PMULQ_W, "dst", EXT_P_RV64},
  {"pmulqr.w", MATCH_PMULQR_W, MASK_PMULQR_W, "dst", EXT_P_RV64},
  {"pmacc.w.h00", MATCH_PMACC_W_H00, MASK_PMACC_W_H00, "dst", EXT_P_RV64},
  {"pmacc.w.h01", MATCH_PMACC_W_H01, MASK_PMACC_W_H01, "dst", EXT_P_RV64},
  {"pmacc.w.h11", MATCH_PMACC_W_H11, MASK_PMACC_W_H11, "dst", EXT_P_RV64},
  {"pmaccu.w.h00", MATCH_PMACCU_W_H00, MASK_PMACCU_W_H00, "dst", EXT_P_RV64},
  {"pmaccu.w.h01", MATCH_PMACCU_W_H01, MASK_PMACCU_W_H01, "dst", EXT_P_RV64},
  {"pmaccu.w.h11", MATCH_PMACCU_W_H11, MASK_PMACCU_W_H11, "dst", EXT_P_RV64},
  {"pmaccsu.w.h00", MATCH_PMACCSU_W_H00, MASK_PMACCSU_W_H00, "dst", EXT_P_RV64},
  {"pmaccsu.w.h11", MATCH_PMACCSU_W_H11, MASK_PMACCSU_W_H11, "dst", EXT_P_RV64},
  {"pmhacc.w", MATCH_PMHACC_W, MASK_PMHACC_W, "dst", EXT_P_RV64},
  {"pmhaccu.w", MATCH_PMHACCU_W, MASK_PMHACCU_W, "dst", EXT_P_RV64},
  {"pmhaccsu.w", MATCH_PMHACCSU_W, MASK_PMHACCSU_W, "dst", EXT_P_RV64},
  {"pmhacc.w.h0", MATCH_PMHACC_W_H0, MASK_PMHACC_W_H0, "dst", EXT_P_RV64},
  {"pmhacc.w.h1", MATCH_PMHACC_W_H1, MASK_PMHACC_W_H1, "dst", EXT_P_RV64},
  {"pmhaccsu.w.h0", MATCH_PMHACCSU_W_H0, MASK_PMHACCSU_W_H0, "dst", EXT_P_RV64},
  {"pmhaccsu.w.h1", MATCH_PMHACCSU_W_H1, MASK_PMHACCSU_W_H1, "dst", EXT_P_RV64},
  {"pmhracc.w", MATCH_PMHRACC_W, MASK_PMHRACC_W, "dst", EXT_P_RV64},
  {"pmhraccu.w", MATCH_PMHRACCU_W, MASK_PMHRACCU_W, "dst", EXT_P_RV64},
  {"pmhraccsu.w", MATCH_PMHRACCSU_W, MASK_PMHRACCSU_W, "dst", EXT_P_RV64},
  {"pmqacc.w.h00", MATCH_PMQACC_W_H00, MASK_PMQACC_W_H00, "dst", EXT_P_RV64},
  {"pmqacc.w.h01", MATCH_PMQACC_W_H01, MASK_PMQACC_W_H01, "dst", EXT_P_RV64},
  {"pmqacc.w.h11", MATCH_PMQACC_W_H11, MASK_PMQACC_W_H11, "dst", EXT_P_RV64},
  {"pmqracc.w.h00", MATCH_PMQRACC_W_H00, MASK_PMQRACC_W_H00, "dst", EXT_P_RV64},
  {"pmqracc.w.h01", MATCH_PMQRACC_W_H01, MASK_PMQRACC_W_H01, "dst", EXT_P_RV64},
  {"pmqracc.w.h11", MATCH_PMQRACC_W_H11, MASK_PMQRACC_W_H11, "dst", EXT_P_RV64},
  {"pmq2add.w", MATCH_PMQ2ADD_W, MASK_PMQ2ADD_W, "dst", EXT_P_RV64},
  {"pmq2adda.w", MATCH_PMQ2ADDA_W, MASK_PMQ2ADDA_W, "dst", EXT_P_RV64},
  {"pmqr2add.w", MATCH_PMQR2ADD_W, MASK_PMQR2ADD_W, "dst", EXT_P_RV64},
  {"pmqr2adda.w", MATCH_PMQR2ADDA_W, MASK_PMQR2ADDA_W, "dst", EXT_P_RV64},
  {"pm2add.w", MATCH_PM2ADD_W, MASK_PM2ADD_W, "dst", EXT_P_RV64},
  {"pm2add.wx", MATCH_PM2ADD_WX, MASK_PM2ADD_WX, "dst", EXT_P_RV64},
  {"pm2addu.w", MATCH_PM2ADDU_W, MASK_PM2ADDU_W, "dst", EXT_P_RV64},
  {"pm2addsu.w", MATCH_PM2ADDSU_W, MASK_PM2ADDSU_W, "dst", EXT_P_RV64},
  {"pm2adda.w", MATCH_PM2ADDA_W, MASK_PM2ADDA_W, "dst", EXT_P_RV64},
  {"pm2adda.wx", MATCH_PM2ADDA_WX, MASK_PM2ADDA_WX, "dst", EXT_P_RV64},
  {"pm2addau.w", MATCH_PM2ADDAU_W, MASK_PM2ADDAU_W, "dst", EXT_P_RV64},
  {"pm2addasu.w", MATCH_PM2ADDASU_W, MASK_PM2ADDASU_W, "dst", EXT_P_RV64},
  {"pm2sub.w", MATCH_PM2SUB_W, MASK_PM2SUB_W, "dst", EXT_P_RV64},
  {"pm2sub.wx", MATCH_PM2SUB_WX, MASK_PM2SUB_WX, "dst", EXT_P_RV64},
  {"pm2suba.w", MATCH_PM2SUBA_W, MASK_PM2SUBA_W, "dst", EXT_P_RV64},
  {"pm2suba.wx", MATCH_PM2SUBA_WX, MASK_PM2SUBA_WX, "dst", EXT_P_RV64},
  {"pm4add.h", MATCH_PM4ADD_H, MASK_PM4ADD_H, "dst", EXT_P_RV64},
  {"pm4addu.h", MATCH_PM4ADDU_H, MASK_PM4ADDU_H, "dst", EXT_P_RV64},
  {"pm4addsu.h", MATCH_PM4ADDSU_H, MASK_PM4ADDSU_H, "dst", EXT_P_RV64},
  {"pm4adda.h", MATCH_PM4ADDA_H, MASK_PM4ADDA_H, "dst", EXT_P_RV64},
  {"pm4addau.h", MATCH_PM4ADDAU_H, MASK_PM4ADDAU_H, "dst", EXT_P_RV64},
  {"pm4addasu.h", MATCH_PM4ADDASU_H, MASK_PM4ADDASU_H, "dst", EXT_P_RV64},
  {"psext.w.b", MATCH_PSEXT_W_B, MASK_PSEXT_W_B, "ds", EXT_P_RV64},
  {"psext.w.h", MATCH_PSEXT_W_H, MASK_PSEXT_W_H, "ds", EXT_P_RV64},
  {"zip16p", MATCH_ZIP16P, MASK_ZIP16P, "ds", EXT_P_RV64},
  {"zip16hp", MATCH_ZIP16HP, MASK_ZIP16HP, "ds", EXT_P_RV64},
  {"pslli.w", MATCH_PSLLI_W, MASK_PSLLI_W, "ds<", EXT_P_RV64},
  {"psrai.w", MATCH_PSRAI_W, MASK_PSRAI_W, "ds<", EXT_P_RV64},
  {"psrli.w", MATCH_PSRLI_W, MASK_PSRLI_W, "ds<", EXT_P_RV64},
  {"psrari.w", MATCH_PSRARI_W, MASK_PSRARI_W, "ds<", EXT_P_RV64},
  {"psati.w", MATCH_PSATI_W, MASK_PSATI_W, "ds<", EXT_P_RV64},
  {"pusati.w", MATCH_PUSATI_W, MASK_PUSATI_W, "ds<", EXT_P_RV64},
  {"psslai.w", MATCH_PSSLAI_W, MASK_PSSLAI_W, "ds<", EXT_P_RV64},
  {"pli.w", MATCH_PLI_W, MASK_PLI_W, "d$", EXT_P_RV64},
  {"plui.w", MATCH_PLUI_W, MASK_PLUI_W, "d%", EXT_P_RV64},

  // AMO instructions (4 variants: base/.rl/.aq/.aqrl)
  // ZAAMO
  {"amoadd_w", MATCH_AMOADD_W, MASK_AMOADD_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoadd_w_rl", MATCH_AMOADD_W | MASK_RL, MASK_AMOADD_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoadd_w_aq", MATCH_AMOADD_W | MASK_AQ, MASK_AMOADD_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoadd_w_aqrl", MATCH_AMOADD_W | MASK_AQRL, MASK_AMOADD_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoswap_w", MATCH_AMOSWAP_W, MASK_AMOSWAP_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoswap_w_rl", MATCH_AMOSWAP_W | MASK_RL, MASK_AMOSWAP_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoswap_w_aq", MATCH_AMOSWAP_W | MASK_AQ, MASK_AMOSWAP_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoswap_w_aqrl", MATCH_AMOSWAP_W | MASK_AQRL, MASK_AMOSWAP_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoand_w", MATCH_AMOAND_W, MASK_AMOAND_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoand_w_rl", MATCH_AMOAND_W | MASK_RL, MASK_AMOAND_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoand_w_aq", MATCH_AMOAND_W | MASK_AQ, MASK_AMOAND_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoand_w_aqrl", MATCH_AMOAND_W | MASK_AQRL, MASK_AMOAND_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoor_w", MATCH_AMOOR_W, MASK_AMOOR_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoor_w_rl", MATCH_AMOOR_W | MASK_RL, MASK_AMOOR_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoor_w_aq", MATCH_AMOOR_W | MASK_AQ, MASK_AMOOR_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoor_w_aqrl", MATCH_AMOOR_W | MASK_AQRL, MASK_AMOOR_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoxor_w", MATCH_AMOXOR_W, MASK_AMOXOR_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoxor_w_rl", MATCH_AMOXOR_W | MASK_RL, MASK_AMOXOR_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoxor_w_aq", MATCH_AMOXOR_W | MASK_AQ, MASK_AMOXOR_W | MASK_AQRL, "dt(", ZAAMO},
  {"amoxor_w_aqrl", MATCH_AMOXOR_W | MASK_AQRL, MASK_AMOXOR_W | MASK_AQRL, "dt(", ZAAMO},
  {"amomin_w", MATCH_AMOMIN_W, MASK_AMOMIN_W | MASK_AQRL, "dt(", ZAAMO},
  {"amomin_w_rl", MATCH_AMOMIN_W | MASK_RL, MASK_AMOMIN_W | MASK_AQRL, "dt(", ZAAMO},
  {"amomin_w_aq", MATCH_AMOMIN_W | MASK_AQ, MASK_AMOMIN_W | MASK_AQRL, "dt(", ZAAMO},
  {"amomin_w_aqrl", MATCH_AMOMIN_W | MASK_AQRL, MASK_AMOMIN_W | MASK_AQRL, "dt(", ZAAMO},
  {"amomax_w", MATCH_AMOMAX_W, MASK_AMOMAX_W | MASK_AQRL, "dt(", ZAAMO},
  {"amomax_w_rl", MATCH_AMOMAX_W | MASK_RL, MASK_AMOMAX_W | MASK_AQRL, "dt(", ZAAMO},
  {"amomax_w_aq", MATCH_AMOMAX_W | MASK_AQ, MASK_AMOMAX_W | MASK_AQRL, "dt(", ZAAMO},
  {"amomax_w_aqrl", MATCH_AMOMAX_W | MASK_AQRL, MASK_AMOMAX_W | MASK_AQRL, "dt(", ZAAMO},
  {"amominu_w", MATCH_AMOMINU_W, MASK_AMOMINU_W | MASK_AQRL, "dt(", ZAAMO},
  {"amominu_w_rl", MATCH_AMOMINU_W | MASK_RL, MASK_AMOMINU_W | MASK_AQRL, "dt(", ZAAMO},
  {"amominu_w_aq", MATCH_AMOMINU_W | MASK_AQ, MASK_AMOMINU_W | MASK_AQRL, "dt(", ZAAMO},
  {"amominu_w_aqrl", MATCH_AMOMINU_W | MASK_AQRL, MASK_AMOMINU_W | MASK_AQRL, "dt(", ZAAMO},
  {"amomaxu_w", MATCH_AMOMAXU_W, MASK_AMOMAXU_W | MASK_AQRL, "dt(", ZAAMO},
  {"amomaxu_w_rl", MATCH_AMOMAXU_W | MASK_RL, MASK_AMOMAXU_W | MASK_AQRL, "dt(", ZAAMO},
  {"amomaxu_w_aq", MATCH_AMOMAXU_W | MASK_AQ, MASK_AMOMAXU_W | MASK_AQRL, "dt(", ZAAMO},
  {"amomaxu_w_aqrl", MATCH_AMOMAXU_W | MASK_AQRL, MASK_AMOMAXU_W | MASK_AQRL, "dt(", ZAAMO},
  // ZAAMO RV64
  {"amoadd_d", MATCH_AMOADD_D, MASK_AMOADD_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoadd_d_rl", MATCH_AMOADD_D | MASK_RL, MASK_AMOADD_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoadd_d_aq", MATCH_AMOADD_D | MASK_AQ, MASK_AMOADD_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoadd_d_aqrl", MATCH_AMOADD_D | MASK_AQRL, MASK_AMOADD_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoswap_d", MATCH_AMOSWAP_D, MASK_AMOSWAP_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoswap_d_rl", MATCH_AMOSWAP_D | MASK_RL, MASK_AMOSWAP_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoswap_d_aq", MATCH_AMOSWAP_D | MASK_AQ, MASK_AMOSWAP_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoswap_d_aqrl", MATCH_AMOSWAP_D | MASK_AQRL, MASK_AMOSWAP_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoand_d", MATCH_AMOAND_D, MASK_AMOAND_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoand_d_rl", MATCH_AMOAND_D | MASK_RL, MASK_AMOAND_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoand_d_aq", MATCH_AMOAND_D | MASK_AQ, MASK_AMOAND_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoand_d_aqrl", MATCH_AMOAND_D | MASK_AQRL, MASK_AMOAND_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoor_d", MATCH_AMOOR_D, MASK_AMOOR_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoor_d_rl", MATCH_AMOOR_D | MASK_RL, MASK_AMOOR_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoor_d_aq", MATCH_AMOOR_D | MASK_AQ, MASK_AMOOR_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoor_d_aqrl", MATCH_AMOOR_D | MASK_AQRL, MASK_AMOOR_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoxor_d", MATCH_AMOXOR_D, MASK_AMOXOR_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoxor_d_rl", MATCH_AMOXOR_D | MASK_RL, MASK_AMOXOR_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoxor_d_aq", MATCH_AMOXOR_D | MASK_AQ, MASK_AMOXOR_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amoxor_d_aqrl", MATCH_AMOXOR_D | MASK_AQRL, MASK_AMOXOR_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amomin_d", MATCH_AMOMIN_D, MASK_AMOMIN_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amomin_d_rl", MATCH_AMOMIN_D | MASK_RL, MASK_AMOMIN_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amomin_d_aq", MATCH_AMOMIN_D | MASK_AQ, MASK_AMOMIN_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amomin_d_aqrl", MATCH_AMOMIN_D | MASK_AQRL, MASK_AMOMIN_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amomax_d", MATCH_AMOMAX_D, MASK_AMOMAX_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amomax_d_rl", MATCH_AMOMAX_D | MASK_RL, MASK_AMOMAX_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amomax_d_aq", MATCH_AMOMAX_D | MASK_AQ, MASK_AMOMAX_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amomax_d_aqrl", MATCH_AMOMAX_D | MASK_AQRL, MASK_AMOMAX_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amominu_d", MATCH_AMOMINU_D, MASK_AMOMINU_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amominu_d_rl", MATCH_AMOMINU_D | MASK_RL, MASK_AMOMINU_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amominu_d_aq", MATCH_AMOMINU_D | MASK_AQ, MASK_AMOMINU_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amominu_d_aqrl", MATCH_AMOMINU_D | MASK_AQRL, MASK_AMOMINU_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amomaxu_d", MATCH_AMOMAXU_D, MASK_AMOMAXU_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amomaxu_d_rl", MATCH_AMOMAXU_D | MASK_RL, MASK_AMOMAXU_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amomaxu_d_aq", MATCH_AMOMAXU_D | MASK_AQ, MASK_AMOMAXU_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  {"amomaxu_d_aqrl", MATCH_AMOMAXU_D | MASK_AQRL, MASK_AMOMAXU_D | MASK_AQRL, "dt(", ZAAMO_RV64},
  // ZALRSC
  {"lr_w", MATCH_LR_W, MASK_LR_W | MASK_AQRL, "d(", ZALRSC},
  {"lr_w_rl", MATCH_LR_W | MASK_RL, MASK_LR_W | MASK_AQRL, "d(", ZALRSC},
  {"lr_w_aq", MATCH_LR_W | MASK_AQ, MASK_LR_W | MASK_AQRL, "d(", ZALRSC},
  {"lr_w_aqrl", MATCH_LR_W | MASK_AQRL, MASK_LR_W | MASK_AQRL, "d(", ZALRSC},
  {"sc_w", MATCH_SC_W, MASK_SC_W | MASK_AQRL, "dt(", ZALRSC},
  {"sc_w_rl", MATCH_SC_W | MASK_RL, MASK_SC_W | MASK_AQRL, "dt(", ZALRSC},
  {"sc_w_aq", MATCH_SC_W | MASK_AQ, MASK_SC_W | MASK_AQRL, "dt(", ZALRSC},
  {"sc_w_aqrl", MATCH_SC_W | MASK_AQRL, MASK_SC_W | MASK_AQRL, "dt(", ZALRSC},
  // ZALRSC RV64
  {"lr_d", MATCH_LR_D, MASK_LR_D | MASK_AQRL, "d(", ZALRSC_RV64},
  {"lr_d_rl", MATCH_LR_D | MASK_RL, MASK_LR_D | MASK_AQRL, "d(", ZALRSC_RV64},
  {"lr_d_aq", MATCH_LR_D | MASK_AQ, MASK_LR_D | MASK_AQRL, "d(", ZALRSC_RV64},
  {"lr_d_aqrl", MATCH_LR_D | MASK_AQRL, MASK_LR_D | MASK_AQRL, "d(", ZALRSC_RV64},
  {"sc_d", MATCH_SC_D, MASK_SC_D | MASK_AQRL, "dt(", ZALRSC_RV64},
  {"sc_d_rl", MATCH_SC_D | MASK_RL, MASK_SC_D | MASK_AQRL, "dt(", ZALRSC_RV64},
  {"sc_d_aq", MATCH_SC_D | MASK_AQ, MASK_SC_D | MASK_AQRL, "dt(", ZALRSC_RV64},
  {"sc_d_aqrl", MATCH_SC_D | MASK_AQRL, MASK_SC_D | MASK_AQRL, "dt(", ZALRSC_RV64},
  // ZACAS
  {"amocas_w", MATCH_AMOCAS_W, MASK_AMOCAS_W | MASK_AQRL, "dt(", ZACAS},
  {"amocas_w_rl", MATCH_AMOCAS_W | MASK_RL, MASK_AMOCAS_W | MASK_AQRL, "dt(", ZACAS},
  {"amocas_w_aq", MATCH_AMOCAS_W | MASK_AQ, MASK_AMOCAS_W | MASK_AQRL, "dt(", ZACAS},
  {"amocas_w_aqrl", MATCH_AMOCAS_W | MASK_AQRL, MASK_AMOCAS_W | MASK_AQRL, "dt(", ZACAS},
  {"amocas_d", MATCH_AMOCAS_D, MASK_AMOCAS_D | MASK_AQRL, "dt(", ZACAS},
  {"amocas_d_rl", MATCH_AMOCAS_D | MASK_RL, MASK_AMOCAS_D | MASK_AQRL, "dt(", ZACAS},
  {"amocas_d_aq", MATCH_AMOCAS_D | MASK_AQ, MASK_AMOCAS_D | MASK_AQRL, "dt(", ZACAS},
  {"amocas_d_aqrl", MATCH_AMOCAS_D | MASK_AQRL, MASK_AMOCAS_D | MASK_AQRL, "dt(", ZACAS},
  {"amocas_q", MATCH_AMOCAS_Q, MASK_AMOCAS_Q | MASK_AQRL, "dt(", ZACAS_RV64},
  {"amocas_q_rl", MATCH_AMOCAS_Q | MASK_RL, MASK_AMOCAS_Q | MASK_AQRL, "dt(", ZACAS_RV64},
  {"amocas_q_aq", MATCH_AMOCAS_Q | MASK_AQ, MASK_AMOCAS_Q | MASK_AQRL, "dt(", ZACAS_RV64},
  {"amocas_q_aqrl", MATCH_AMOCAS_Q | MASK_AQRL, MASK_AMOCAS_Q | MASK_AQRL, "dt(", ZACAS_RV64},
  // ZABHA
  {"amoadd_b", MATCH_AMOADD_B, MASK_AMOADD_B | MASK_AQRL, "dt(", ZABHA},
  {"amoadd_b_rl", MATCH_AMOADD_B | MASK_RL, MASK_AMOADD_B | MASK_AQRL, "dt(", ZABHA},
  {"amoadd_b_aq", MATCH_AMOADD_B | MASK_AQ, MASK_AMOADD_B | MASK_AQRL, "dt(", ZABHA},
  {"amoadd_b_aqrl", MATCH_AMOADD_B | MASK_AQRL, MASK_AMOADD_B | MASK_AQRL, "dt(", ZABHA},
  {"amoswap_b", MATCH_AMOSWAP_B, MASK_AMOSWAP_B | MASK_AQRL, "dt(", ZABHA},
  {"amoswap_b_rl", MATCH_AMOSWAP_B | MASK_RL, MASK_AMOSWAP_B | MASK_AQRL, "dt(", ZABHA},
  {"amoswap_b_aq", MATCH_AMOSWAP_B | MASK_AQ, MASK_AMOSWAP_B | MASK_AQRL, "dt(", ZABHA},
  {"amoswap_b_aqrl", MATCH_AMOSWAP_B | MASK_AQRL, MASK_AMOSWAP_B | MASK_AQRL, "dt(", ZABHA},
  {"amoand_b", MATCH_AMOAND_B, MASK_AMOAND_B | MASK_AQRL, "dt(", ZABHA},
  {"amoand_b_rl", MATCH_AMOAND_B | MASK_RL, MASK_AMOAND_B | MASK_AQRL, "dt(", ZABHA},
  {"amoand_b_aq", MATCH_AMOAND_B | MASK_AQ, MASK_AMOAND_B | MASK_AQRL, "dt(", ZABHA},
  {"amoand_b_aqrl", MATCH_AMOAND_B | MASK_AQRL, MASK_AMOAND_B | MASK_AQRL, "dt(", ZABHA},
  {"amoor_b", MATCH_AMOOR_B, MASK_AMOOR_B | MASK_AQRL, "dt(", ZABHA},
  {"amoor_b_rl", MATCH_AMOOR_B | MASK_RL, MASK_AMOOR_B | MASK_AQRL, "dt(", ZABHA},
  {"amoor_b_aq", MATCH_AMOOR_B | MASK_AQ, MASK_AMOOR_B | MASK_AQRL, "dt(", ZABHA},
  {"amoor_b_aqrl", MATCH_AMOOR_B | MASK_AQRL, MASK_AMOOR_B | MASK_AQRL, "dt(", ZABHA},
  {"amoxor_b", MATCH_AMOXOR_B, MASK_AMOXOR_B | MASK_AQRL, "dt(", ZABHA},
  {"amoxor_b_rl", MATCH_AMOXOR_B | MASK_RL, MASK_AMOXOR_B | MASK_AQRL, "dt(", ZABHA},
  {"amoxor_b_aq", MATCH_AMOXOR_B | MASK_AQ, MASK_AMOXOR_B | MASK_AQRL, "dt(", ZABHA},
  {"amoxor_b_aqrl", MATCH_AMOXOR_B | MASK_AQRL, MASK_AMOXOR_B | MASK_AQRL, "dt(", ZABHA},
  {"amomin_b", MATCH_AMOMIN_B, MASK_AMOMIN_B | MASK_AQRL, "dt(", ZABHA},
  {"amomin_b_rl", MATCH_AMOMIN_B | MASK_RL, MASK_AMOMIN_B | MASK_AQRL, "dt(", ZABHA},
  {"amomin_b_aq", MATCH_AMOMIN_B | MASK_AQ, MASK_AMOMIN_B | MASK_AQRL, "dt(", ZABHA},
  {"amomin_b_aqrl", MATCH_AMOMIN_B | MASK_AQRL, MASK_AMOMIN_B | MASK_AQRL, "dt(", ZABHA},
  {"amomax_b", MATCH_AMOMAX_B, MASK_AMOMAX_B | MASK_AQRL, "dt(", ZABHA},
  {"amomax_b_rl", MATCH_AMOMAX_B | MASK_RL, MASK_AMOMAX_B | MASK_AQRL, "dt(", ZABHA},
  {"amomax_b_aq", MATCH_AMOMAX_B | MASK_AQ, MASK_AMOMAX_B | MASK_AQRL, "dt(", ZABHA},
  {"amomax_b_aqrl", MATCH_AMOMAX_B | MASK_AQRL, MASK_AMOMAX_B | MASK_AQRL, "dt(", ZABHA},
  {"amominu_b", MATCH_AMOMINU_B, MASK_AMOMINU_B | MASK_AQRL, "dt(", ZABHA},
  {"amominu_b_rl", MATCH_AMOMINU_B | MASK_RL, MASK_AMOMINU_B | MASK_AQRL, "dt(", ZABHA},
  {"amominu_b_aq", MATCH_AMOMINU_B | MASK_AQ, MASK_AMOMINU_B | MASK_AQRL, "dt(", ZABHA},
  {"amominu_b_aqrl", MATCH_AMOMINU_B | MASK_AQRL, MASK_AMOMINU_B | MASK_AQRL, "dt(", ZABHA},
  {"amomaxu_b", MATCH_AMOMAXU_B, MASK_AMOMAXU_B | MASK_AQRL, "dt(", ZABHA},
  {"amomaxu_b_rl", MATCH_AMOMAXU_B | MASK_RL, MASK_AMOMAXU_B | MASK_AQRL, "dt(", ZABHA},
  {"amomaxu_b_aq", MATCH_AMOMAXU_B | MASK_AQ, MASK_AMOMAXU_B | MASK_AQRL, "dt(", ZABHA},
  {"amomaxu_b_aqrl", MATCH_AMOMAXU_B | MASK_AQRL, MASK_AMOMAXU_B | MASK_AQRL, "dt(", ZABHA},
  {"amocas_b", MATCH_AMOCAS_B, MASK_AMOCAS_B | MASK_AQRL, "dt(", ZABHA},
  {"amocas_b_rl", MATCH_AMOCAS_B | MASK_RL, MASK_AMOCAS_B | MASK_AQRL, "dt(", ZABHA},
  {"amocas_b_aq", MATCH_AMOCAS_B | MASK_AQ, MASK_AMOCAS_B | MASK_AQRL, "dt(", ZABHA},
  {"amocas_b_aqrl", MATCH_AMOCAS_B | MASK_AQRL, MASK_AMOCAS_B | MASK_AQRL, "dt(", ZABHA},
  {"amoadd_h", MATCH_AMOADD_H, MASK_AMOADD_H | MASK_AQRL, "dt(", ZABHA},
  {"amoadd_h_rl", MATCH_AMOADD_H | MASK_RL, MASK_AMOADD_H | MASK_AQRL, "dt(", ZABHA},
  {"amoadd_h_aq", MATCH_AMOADD_H | MASK_AQ, MASK_AMOADD_H | MASK_AQRL, "dt(", ZABHA},
  {"amoadd_h_aqrl", MATCH_AMOADD_H | MASK_AQRL, MASK_AMOADD_H | MASK_AQRL, "dt(", ZABHA},
  {"amoswap_h", MATCH_AMOSWAP_H, MASK_AMOSWAP_H | MASK_AQRL, "dt(", ZABHA},
  {"amoswap_h_rl", MATCH_AMOSWAP_H | MASK_RL, MASK_AMOSWAP_H | MASK_AQRL, "dt(", ZABHA},
  {"amoswap_h_aq", MATCH_AMOSWAP_H | MASK_AQ, MASK_AMOSWAP_H | MASK_AQRL, "dt(", ZABHA},
  {"amoswap_h_aqrl", MATCH_AMOSWAP_H | MASK_AQRL, MASK_AMOSWAP_H | MASK_AQRL, "dt(", ZABHA},
  {"amoand_h", MATCH_AMOAND_H, MASK_AMOAND_H | MASK_AQRL, "dt(", ZABHA},
  {"amoand_h_rl", MATCH_AMOAND_H | MASK_RL, MASK_AMOAND_H | MASK_AQRL, "dt(", ZABHA},
  {"amoand_h_aq", MATCH_AMOAND_H | MASK_AQ, MASK_AMOAND_H | MASK_AQRL, "dt(", ZABHA},
  {"amoand_h_aqrl", MATCH_AMOAND_H | MASK_AQRL, MASK_AMOAND_H | MASK_AQRL, "dt(", ZABHA},
  {"amoor_h", MATCH_AMOOR_H, MASK_AMOOR_H | MASK_AQRL, "dt(", ZABHA},
  {"amoor_h_rl", MATCH_AMOOR_H | MASK_RL, MASK_AMOOR_H | MASK_AQRL, "dt(", ZABHA},
  {"amoor_h_aq", MATCH_AMOOR_H | MASK_AQ, MASK_AMOOR_H | MASK_AQRL, "dt(", ZABHA},
  {"amoor_h_aqrl", MATCH_AMOOR_H | MASK_AQRL, MASK_AMOOR_H | MASK_AQRL, "dt(", ZABHA},
  {"amoxor_h", MATCH_AMOXOR_H, MASK_AMOXOR_H | MASK_AQRL, "dt(", ZABHA},
  {"amoxor_h_rl", MATCH_AMOXOR_H | MASK_RL, MASK_AMOXOR_H | MASK_AQRL, "dt(", ZABHA},
  {"amoxor_h_aq", MATCH_AMOXOR_H | MASK_AQ, MASK_AMOXOR_H | MASK_AQRL, "dt(", ZABHA},
  {"amoxor_h_aqrl", MATCH_AMOXOR_H | MASK_AQRL, MASK_AMOXOR_H | MASK_AQRL, "dt(", ZABHA},
  {"amomin_h", MATCH_AMOMIN_H, MASK_AMOMIN_H | MASK_AQRL, "dt(", ZABHA},
  {"amomin_h_rl", MATCH_AMOMIN_H | MASK_RL, MASK_AMOMIN_H | MASK_AQRL, "dt(", ZABHA},
  {"amomin_h_aq", MATCH_AMOMIN_H | MASK_AQ, MASK_AMOMIN_H | MASK_AQRL, "dt(", ZABHA},
  {"amomin_h_aqrl", MATCH_AMOMIN_H | MASK_AQRL, MASK_AMOMIN_H | MASK_AQRL, "dt(", ZABHA},
  {"amomax_h", MATCH_AMOMAX_H, MASK_AMOMAX_H | MASK_AQRL, "dt(", ZABHA},
  {"amomax_h_rl", MATCH_AMOMAX_H | MASK_RL, MASK_AMOMAX_H | MASK_AQRL, "dt(", ZABHA},
  {"amomax_h_aq", MATCH_AMOMAX_H | MASK_AQ, MASK_AMOMAX_H | MASK_AQRL, "dt(", ZABHA},
  {"amomax_h_aqrl", MATCH_AMOMAX_H | MASK_AQRL, MASK_AMOMAX_H | MASK_AQRL, "dt(", ZABHA},
  {"amominu_h", MATCH_AMOMINU_H, MASK_AMOMINU_H | MASK_AQRL, "dt(", ZABHA},
  {"amominu_h_rl", MATCH_AMOMINU_H | MASK_RL, MASK_AMOMINU_H | MASK_AQRL, "dt(", ZABHA},
  {"amominu_h_aq", MATCH_AMOMINU_H | MASK_AQ, MASK_AMOMINU_H | MASK_AQRL, "dt(", ZABHA},
  {"amominu_h_aqrl", MATCH_AMOMINU_H | MASK_AQRL, MASK_AMOMINU_H | MASK_AQRL, "dt(", ZABHA},
  {"amomaxu_h", MATCH_AMOMAXU_H, MASK_AMOMAXU_H | MASK_AQRL, "dt(", ZABHA},
  {"amomaxu_h_rl", MATCH_AMOMAXU_H | MASK_RL, MASK_AMOMAXU_H | MASK_AQRL, "dt(", ZABHA},
  {"amomaxu_h_aq", MATCH_AMOMAXU_H | MASK_AQ, MASK_AMOMAXU_H | MASK_AQRL, "dt(", ZABHA},
  {"amomaxu_h_aqrl", MATCH_AMOMAXU_H | MASK_AQRL, MASK_AMOMAXU_H | MASK_AQRL, "dt(", ZABHA},
  {"amocas_h", MATCH_AMOCAS_H, MASK_AMOCAS_H | MASK_AQRL, "dt(", ZABHA},
  {"amocas_h_rl", MATCH_AMOCAS_H | MASK_RL, MASK_AMOCAS_H | MASK_AQRL, "dt(", ZABHA},
  {"amocas_h_aq", MATCH_AMOCAS_H | MASK_AQ, MASK_AMOCAS_H | MASK_AQRL, "dt(", ZABHA},
  {"amocas_h_aqrl", MATCH_AMOCAS_H | MASK_AQRL, MASK_AMOCAS_H | MASK_AQRL, "dt(", ZABHA},
  // ZICFISS AMO
  {"ssamoswap_w", MATCH_SSAMOSWAP_W, MASK_SSAMOSWAP_W | MASK_AQRL, "dt(", ZICFISS},
  {"ssamoswap_w_rl", MATCH_SSAMOSWAP_W | MASK_RL, MASK_SSAMOSWAP_W | MASK_AQRL, "dt(", ZICFISS},
  {"ssamoswap_w_aq", MATCH_SSAMOSWAP_W | MASK_AQ, MASK_SSAMOSWAP_W | MASK_AQRL, "dt(", ZICFISS},
  {"ssamoswap_w_aqrl", MATCH_SSAMOSWAP_W | MASK_AQRL, MASK_SSAMOSWAP_W | MASK_AQRL, "dt(", ZICFISS},
  {"ssamoswap_d", MATCH_SSAMOSWAP_D, MASK_SSAMOSWAP_D | MASK_AQRL, "dt(", ZICFISS_RV64},
  {"ssamoswap_d_rl", MATCH_SSAMOSWAP_D | MASK_RL, MASK_SSAMOSWAP_D | MASK_AQRL, "dt(", ZICFISS_RV64},
  {"ssamoswap_d_aq", MATCH_SSAMOSWAP_D | MASK_AQ, MASK_SSAMOSWAP_D | MASK_AQRL, "dt(", ZICFISS_RV64},
  {"ssamoswap_d_aqrl", MATCH_SSAMOSWAP_D | MASK_AQRL, MASK_SSAMOSWAP_D | MASK_AQRL, "dt(", ZICFISS_RV64},
  // ZIMOP: all mop.r/mop.rr variants as explicit rows.
  // Zicfiss sspush/sspopchk have higher priority (earlier in table)
  // and will correctly shadow the mop.r.28/mop.rr.7 overlapping encodings.
  {"mop_r_0", MATCH_MOP_R_0, MASK_MOP_R_0, "ds", ZIMOP},
  {"mop_r_1", MATCH_MOP_R_1, MASK_MOP_R_1, "ds", ZIMOP},
  {"mop_r_2", MATCH_MOP_R_2, MASK_MOP_R_2, "ds", ZIMOP},
  {"mop_r_3", MATCH_MOP_R_3, MASK_MOP_R_3, "ds", ZIMOP},
  {"mop_r_4", MATCH_MOP_R_4, MASK_MOP_R_4, "ds", ZIMOP},
  {"mop_r_5", MATCH_MOP_R_5, MASK_MOP_R_5, "ds", ZIMOP},
  {"mop_r_6", MATCH_MOP_R_6, MASK_MOP_R_6, "ds", ZIMOP},
  {"mop_r_7", MATCH_MOP_R_7, MASK_MOP_R_7, "ds", ZIMOP},
  {"mop_r_8", MATCH_MOP_R_8, MASK_MOP_R_8, "ds", ZIMOP},
  {"mop_r_9", MATCH_MOP_R_9, MASK_MOP_R_9, "ds", ZIMOP},
  {"mop_r_10", MATCH_MOP_R_10, MASK_MOP_R_10, "ds", ZIMOP},
  {"mop_r_11", MATCH_MOP_R_11, MASK_MOP_R_11, "ds", ZIMOP},
  {"mop_r_12", MATCH_MOP_R_12, MASK_MOP_R_12, "ds", ZIMOP},
  {"mop_r_13", MATCH_MOP_R_13, MASK_MOP_R_13, "ds", ZIMOP},
  {"mop_r_14", MATCH_MOP_R_14, MASK_MOP_R_14, "ds", ZIMOP},
  {"mop_r_15", MATCH_MOP_R_15, MASK_MOP_R_15, "ds", ZIMOP},
  {"mop_r_16", MATCH_MOP_R_16, MASK_MOP_R_16, "ds", ZIMOP},
  {"mop_r_17", MATCH_MOP_R_17, MASK_MOP_R_17, "ds", ZIMOP},
  {"mop_r_18", MATCH_MOP_R_18, MASK_MOP_R_18, "ds", ZIMOP},
  {"mop_r_19", MATCH_MOP_R_19, MASK_MOP_R_19, "ds", ZIMOP},
  {"mop_r_20", MATCH_MOP_R_20, MASK_MOP_R_20, "ds", ZIMOP},
  {"mop_r_21", MATCH_MOP_R_21, MASK_MOP_R_21, "ds", ZIMOP},
  {"mop_r_22", MATCH_MOP_R_22, MASK_MOP_R_22, "ds", ZIMOP},
  {"mop_r_23", MATCH_MOP_R_23, MASK_MOP_R_23, "ds", ZIMOP},
  {"mop_r_24", MATCH_MOP_R_24, MASK_MOP_R_24, "ds", ZIMOP},
  {"mop_r_25", MATCH_MOP_R_25, MASK_MOP_R_25, "ds", ZIMOP},
  {"mop_r_26", MATCH_MOP_R_26, MASK_MOP_R_26, "ds", ZIMOP},
  {"mop_r_27", MATCH_MOP_R_27, MASK_MOP_R_27, "ds", ZIMOP},
  {"mop_r_28", MATCH_MOP_R_28, MASK_MOP_R_28, "ds", ZIMOP},
  {"mop_r_29", MATCH_MOP_R_29, MASK_MOP_R_29, "ds", ZIMOP},
  {"mop_r_30", MATCH_MOP_R_30, MASK_MOP_R_30, "ds", ZIMOP},
  {"mop_r_31", MATCH_MOP_R_31, MASK_MOP_R_31, "ds", ZIMOP},
  {"mop_rr_0", MATCH_MOP_RR_0, MASK_MOP_RR_0, "dst", ZIMOP},
  {"mop_rr_1", MATCH_MOP_RR_1, MASK_MOP_RR_1, "dst", ZIMOP},
  {"mop_rr_2", MATCH_MOP_RR_2, MASK_MOP_RR_2, "dst", ZIMOP},
  {"mop_rr_3", MATCH_MOP_RR_3, MASK_MOP_RR_3, "dst", ZIMOP},
  {"mop_rr_4", MATCH_MOP_RR_4, MASK_MOP_RR_4, "dst", ZIMOP},
  {"mop_rr_5", MATCH_MOP_RR_5, MASK_MOP_RR_5, "dst", ZIMOP},
  {"mop_rr_6", MATCH_MOP_RR_6, MASK_MOP_RR_6, "dst", ZIMOP},
  {"mop_rr_7", MATCH_MOP_RR_7, MASK_MOP_RR_7, "dst", ZIMOP},

  // VECTOR instructions (has_any_vector)
{"vsetivli", MATCH_VSETIVLI, MASK_VSETIVLI, "dzW", VECTOR},
  {"vsetvli", MATCH_VSETVLI, MASK_VSETVLI, "dsW", VECTOR},
  {"vsetvl", MATCH_VSETVL, MASK_VSETVL, "dst", VECTOR},
  {"vlm.v", MATCH_VLM_V, MASK_VLM_V, "A(?k", VECTOR},
  {"vsm.v", MATCH_VSM_V, MASK_VSM_V, "G(?k", VECTOR},
  {"vs1r.v", MATCH_VS1R_V, MASK_VS1R_V | (0x7ul<<29), "G(", VECTOR},
  {"vs2r.v", MATCH_VS2R_V, MASK_VS2R_V | (0x7ul<<29), "G(", VECTOR},
  {"vs4r.v", MATCH_VS4R_V, MASK_VS4R_V | (0x7ul<<29), "G(", VECTOR},
  {"vs8r.v", MATCH_VS8R_V, MASK_VS8R_V | (0x7ul<<29), "G(", VECTOR},
  {"vadd_vv", MATCH_VADD_VV, MASK_VADD_VV, "ACB?k", VECTOR},
  {"vadd_vx", MATCH_VADD_VX, MASK_VADD_VX, "ACs?k", VECTOR},
  {"vadd_vi", MATCH_VADD_VI, MASK_VADD_VI, "AC5?k", VECTOR},
  {"vsub_vv", MATCH_VSUB_VV, MASK_VSUB_VV, "ACB?k", VECTOR},
  {"vsub_vx", MATCH_VSUB_VX, MASK_VSUB_VX, "ACs?k", VECTOR},
  {"vrsub_vx", MATCH_VRSUB_VX, MASK_VRSUB_VX, "ACs?k", VECTOR},
  {"vrsub_vi", MATCH_VRSUB_VI, MASK_VRSUB_VI, "AC5?k", VECTOR},
  {"vminu_vv", MATCH_VMINU_VV, MASK_VMINU_VV, "ACB?k", VECTOR},
  {"vminu_vx", MATCH_VMINU_VX, MASK_VMINU_VX, "ACs?k", VECTOR},
  {"vmin_vv", MATCH_VMIN_VV, MASK_VMIN_VV, "ACB?k", VECTOR},
  {"vmin_vx", MATCH_VMIN_VX, MASK_VMIN_VX, "ACs?k", VECTOR},
  {"vmaxu_vv", MATCH_VMAXU_VV, MASK_VMAXU_VV, "ACB?k", VECTOR},
  {"vmaxu_vx", MATCH_VMAXU_VX, MASK_VMAXU_VX, "ACs?k", VECTOR},
  {"vmax_vv", MATCH_VMAX_VV, MASK_VMAX_VV, "ACB?k", VECTOR},
  {"vmax_vx", MATCH_VMAX_VX, MASK_VMAX_VX, "ACs?k", VECTOR},
  {"vand_vv", MATCH_VAND_VV, MASK_VAND_VV, "ACB?k", VECTOR},
  {"vand_vx", MATCH_VAND_VX, MASK_VAND_VX, "ACs?k", VECTOR},
  {"vand_vi", MATCH_VAND_VI, MASK_VAND_VI, "AC5?k", VECTOR},
  {"vor_vv", MATCH_VOR_VV, MASK_VOR_VV, "ACB?k", VECTOR},
  {"vor_vx", MATCH_VOR_VX, MASK_VOR_VX, "ACs?k", VECTOR},
  {"vor_vi", MATCH_VOR_VI, MASK_VOR_VI, "AC5?k", VECTOR},
  {"vxor_vv", MATCH_VXOR_VV, MASK_VXOR_VV, "ACB?k", VECTOR},
  {"vxor_vx", MATCH_VXOR_VX, MASK_VXOR_VX, "ACs?k", VECTOR},
  {"vxor_vi", MATCH_VXOR_VI, MASK_VXOR_VI, "AC5?k", VECTOR},
  {"vrgather_vv", MATCH_VRGATHER_VV, MASK_VRGATHER_VV, "ACB?k", VECTOR},
  {"vrgather_vx", MATCH_VRGATHER_VX, MASK_VRGATHER_VX, "ACs?k", VECTOR},
  {"vrgather_vi", MATCH_VRGATHER_VI, MASK_VRGATHER_VI, "ACz?k", VECTOR},
  {"vrgatherei16_vv", MATCH_VRGATHEREI16_VV, MASK_VRGATHEREI16_VV, "ACB?k", VECTOR},
  {"vslideup_vx", MATCH_VSLIDEUP_VX, MASK_VSLIDEUP_VX, "ACs?k", VECTOR},
  {"vslideup_vi", MATCH_VSLIDEUP_VI, MASK_VSLIDEUP_VI, "ACz?k", VECTOR},
  {"vslidedown_vx", MATCH_VSLIDEDOWN_VX, MASK_VSLIDEDOWN_VX, "ACs?k", VECTOR},
  {"vslidedown_vi", MATCH_VSLIDEDOWN_VI, MASK_VSLIDEDOWN_VI, "ACz?k", VECTOR},
  {"vadc_vvm", MATCH_VADC_VVM, MASK_VADC_VVM|(1<<25), "ACBK", VECTOR},
  {"vadc_vxm", MATCH_VADC_VXM, MASK_VADC_VXM|(1<<25), "ACsK", VECTOR},
  {"vadc_vim", MATCH_VADC_VIM, MASK_VADC_VIM|(1<<25), "AC5K", VECTOR},
  {"vsbc_vvm", MATCH_VSBC_VVM, MASK_VSBC_VVM|(1<<25), "ACBK", VECTOR},
  {"vsbc_vxm", MATCH_VSBC_VXM, MASK_VSBC_VXM|(1<<25), "ACsK", VECTOR},
  {"vmadc_vvm", MATCH_VMADC_VVM, MASK_VMADC_VVM|(1<<25), "ACBK", VECTOR},
  {"vmadc_vxm", MATCH_VMADC_VXM, MASK_VMADC_VXM|(1<<25), "ACsK", VECTOR},
  {"vmadc_vim", MATCH_VMADC_VIM, MASK_VMADC_VIM|(1<<25), "AC5K", VECTOR},
  {"vmadc_vv", MATCH_VMADC_VV, MASK_VMADC_VV, "ACB?k", VECTOR},
  {"vmadc_vx", MATCH_VMADC_VX, MASK_VMADC_VX, "ACs?k", VECTOR},
  {"vmadc_vi", MATCH_VMADC_VI, MASK_VMADC_VI, "AC5?k", VECTOR},
  {"vmsbc_vvm", MATCH_VMSBC_VVM, MASK_VMSBC_VVM|(1<<25), "ACBK", VECTOR},
  {"vmsbc_vxm", MATCH_VMSBC_VXM, MASK_VMSBC_VXM|(1<<25), "ACsK", VECTOR},
  {"vmsbc_vv", MATCH_VMSBC_VV, MASK_VMSBC_VV, "ACB?k", VECTOR},
  {"vmsbc_vx", MATCH_VMSBC_VX, MASK_VMSBC_VX, "ACs?k", VECTOR},
  {"vmerge_vvm", MATCH_VMERGE_VVM, MASK_VMERGE_VVM|(1<<25), "ACBK", VECTOR},
  {"vmerge_vxm", MATCH_VMERGE_VXM, MASK_VMERGE_VXM|(1<<25), "ACsK", VECTOR},
  {"vmerge_vim", MATCH_VMERGE_VIM, MASK_VMERGE_VIM|(1<<25), "AC5K", VECTOR},
  {"vmv.v.i", MATCH_VMV_V_I, MASK_VMV_V_I, "A5", VECTOR},
  {"vmv.v.v", MATCH_VMV_V_V, MASK_VMV_V_V, "AB", VECTOR},
  {"vmv.v.x", MATCH_VMV_V_X, MASK_VMV_V_X, "As", VECTOR},
  {"vmseq_vv", MATCH_VMSEQ_VV, MASK_VMSEQ_VV, "ACB?k", VECTOR},
  {"vmseq_vx", MATCH_VMSEQ_VX, MASK_VMSEQ_VX, "ACs?k", VECTOR},
  {"vmseq_vi", MATCH_VMSEQ_VI, MASK_VMSEQ_VI, "AC5?k", VECTOR},
  {"vmsne_vv", MATCH_VMSNE_VV, MASK_VMSNE_VV, "ACB?k", VECTOR},
  {"vmsne_vx", MATCH_VMSNE_VX, MASK_VMSNE_VX, "ACs?k", VECTOR},
  {"vmsne_vi", MATCH_VMSNE_VI, MASK_VMSNE_VI, "AC5?k", VECTOR},
  {"vmsltu_vv", MATCH_VMSLTU_VV, MASK_VMSLTU_VV, "ACB?k", VECTOR},
  {"vmsltu_vx", MATCH_VMSLTU_VX, MASK_VMSLTU_VX, "ACs?k", VECTOR},
  {"vmslt_vv", MATCH_VMSLT_VV, MASK_VMSLT_VV, "ACB?k", VECTOR},
  {"vmslt_vx", MATCH_VMSLT_VX, MASK_VMSLT_VX, "ACs?k", VECTOR},
  {"vmsleu_vv", MATCH_VMSLEU_VV, MASK_VMSLEU_VV, "ACB?k", VECTOR},
  {"vmsleu_vx", MATCH_VMSLEU_VX, MASK_VMSLEU_VX, "ACs?k", VECTOR},
  {"vmsleu_vi", MATCH_VMSLEU_VI, MASK_VMSLEU_VI, "ACz?k", VECTOR},
  {"vmsle_vv", MATCH_VMSLE_VV, MASK_VMSLE_VV, "ACB?k", VECTOR},
  {"vmsle_vx", MATCH_VMSLE_VX, MASK_VMSLE_VX, "ACs?k", VECTOR},
  {"vmsle_vi", MATCH_VMSLE_VI, MASK_VMSLE_VI, "AC5?k", VECTOR},
  {"vmsgtu_vx", MATCH_VMSGTU_VX, MASK_VMSGTU_VX, "ACs?k", VECTOR},
  {"vmsgtu_vi", MATCH_VMSGTU_VI, MASK_VMSGTU_VI, "ACz?k", VECTOR},
  {"vmsgt_vx", MATCH_VMSGT_VX, MASK_VMSGT_VX, "ACs?k", VECTOR},
  {"vmsgt_vi", MATCH_VMSGT_VI, MASK_VMSGT_VI, "AC5?k", VECTOR},
  {"vsaddu_vv", MATCH_VSADDU_VV, MASK_VSADDU_VV, "ACB?k", VECTOR},
  {"vsaddu_vx", MATCH_VSADDU_VX, MASK_VSADDU_VX, "ACs?k", VECTOR},
  {"vsaddu_vi", MATCH_VSADDU_VI, MASK_VSADDU_VI, "ACz?k", VECTOR},
  {"vsadd_vv", MATCH_VSADD_VV, MASK_VSADD_VV, "ACB?k", VECTOR},
  {"vsadd_vx", MATCH_VSADD_VX, MASK_VSADD_VX, "ACs?k", VECTOR},
  {"vsadd_vi", MATCH_VSADD_VI, MASK_VSADD_VI, "AC5?k", VECTOR},
  {"vssubu_vv", MATCH_VSSUBU_VV, MASK_VSSUBU_VV, "ACB?k", VECTOR},
  {"vssubu_vx", MATCH_VSSUBU_VX, MASK_VSSUBU_VX, "ACs?k", VECTOR},
  {"vssub_vv", MATCH_VSSUB_VV, MASK_VSSUB_VV, "ACB?k", VECTOR},
  {"vssub_vx", MATCH_VSSUB_VX, MASK_VSSUB_VX, "ACs?k", VECTOR},
  {"vsll_vv", MATCH_VSLL_VV, MASK_VSLL_VV, "ACB?k", VECTOR},
  {"vsll_vx", MATCH_VSLL_VX, MASK_VSLL_VX, "ACs?k", VECTOR},
  {"vsll_vi", MATCH_VSLL_VI, MASK_VSLL_VI, "AC5?k", VECTOR},
  {"vmv1r.v", MATCH_VMV1R_V, MASK_VMV1R_V, "AC", VECTOR},
  {"vmv2r.v", MATCH_VMV2R_V, MASK_VMV2R_V, "AC", VECTOR},
  {"vmv4r.v", MATCH_VMV4R_V, MASK_VMV4R_V, "AC", VECTOR},
  {"vmv8r.v", MATCH_VMV8R_V, MASK_VMV8R_V, "AC", VECTOR},
  {"vsmul_vv", MATCH_VSMUL_VV, MASK_VSMUL_VV, "ACB?k", VECTOR},
  {"vsmul_vx", MATCH_VSMUL_VX, MASK_VSMUL_VX, "ACs?k", VECTOR},
  {"vsrl_vv", MATCH_VSRL_VV, MASK_VSRL_VV, "ACB?k", VECTOR},
  {"vsrl_vx", MATCH_VSRL_VX, MASK_VSRL_VX, "ACs?k", VECTOR},
  {"vsrl_vi", MATCH_VSRL_VI, MASK_VSRL_VI, "ACz?k", VECTOR},
  {"vsra_vv", MATCH_VSRA_VV, MASK_VSRA_VV, "ACB?k", VECTOR},
  {"vsra_vx", MATCH_VSRA_VX, MASK_VSRA_VX, "ACs?k", VECTOR},
  {"vsra_vi", MATCH_VSRA_VI, MASK_VSRA_VI, "ACz?k", VECTOR},
  {"vssrl_vv", MATCH_VSSRL_VV, MASK_VSSRL_VV, "ACB?k", VECTOR},
  {"vssrl_vx", MATCH_VSSRL_VX, MASK_VSSRL_VX, "ACs?k", VECTOR},
  {"vssrl_vi", MATCH_VSSRL_VI, MASK_VSSRL_VI, "ACz?k", VECTOR},
  {"vssra_vv", MATCH_VSSRA_VV, MASK_VSSRA_VV, "ACB?k", VECTOR},
  {"vssra_vx", MATCH_VSSRA_VX, MASK_VSSRA_VX, "ACs?k", VECTOR},
  {"vssra_vi", MATCH_VSSRA_VI, MASK_VSSRA_VI, "ACz?k", VECTOR},
  {"vnsrl_wv", MATCH_VNSRL_WV, MASK_VNSRL_WV, "ACB?k", VECTOR},
  {"vnsrl_wx", MATCH_VNSRL_WX, MASK_VNSRL_WX, "ACs?k", VECTOR},
  {"vnsrl_wi", MATCH_VNSRL_WI, MASK_VNSRL_WI, "ACz?k", VECTOR},
  {"vnsra_wv", MATCH_VNSRA_WV, MASK_VNSRA_WV, "ACB?k", VECTOR},
  {"vnsra_wx", MATCH_VNSRA_WX, MASK_VNSRA_WX, "ACs?k", VECTOR},
  {"vnsra_wi", MATCH_VNSRA_WI, MASK_VNSRA_WI, "ACz?k", VECTOR},
  {"vnclipu_wv", MATCH_VNCLIPU_WV, MASK_VNCLIPU_WV, "ACB?k", VECTOR},
  {"vnclipu_wx", MATCH_VNCLIPU_WX, MASK_VNCLIPU_WX, "ACs?k", VECTOR},
  {"vnclipu_wi", MATCH_VNCLIPU_WI, MASK_VNCLIPU_WI, "ACz?k", VECTOR},
  {"vnclip_wv", MATCH_VNCLIP_WV, MASK_VNCLIP_WV, "ACB?k", VECTOR},
  {"vnclip_wx", MATCH_VNCLIP_WX, MASK_VNCLIP_WX, "ACs?k", VECTOR},
  {"vnclip_wi", MATCH_VNCLIP_WI, MASK_VNCLIP_WI, "ACz?k", VECTOR},
  {"vwredsumu_vs", MATCH_VWREDSUMU_VS, MASK_VWREDSUMU_VS, "ACB?k", VECTOR},
  {"vwredsum_vs", MATCH_VWREDSUM_VS, MASK_VWREDSUM_VS, "ACB?k", VECTOR},
  {"vaaddu_vv", MATCH_VAADDU_VV, MASK_VAADDU_VV, "ACB?k", VECTOR},
  {"vaaddu_vx", MATCH_VAADDU_VX, MASK_VAADDU_VX, "ACs?k", VECTOR},
  {"vaadd_vv", MATCH_VAADD_VV, MASK_VAADD_VV, "ACB?k", VECTOR},
  {"vaadd_vx", MATCH_VAADD_VX, MASK_VAADD_VX, "ACs?k", VECTOR},
  {"vasubu_vv", MATCH_VASUBU_VV, MASK_VASUBU_VV, "ACB?k", VECTOR},
  {"vasubu_vx", MATCH_VASUBU_VX, MASK_VASUBU_VX, "ACs?k", VECTOR},
  {"vasub_vv", MATCH_VASUB_VV, MASK_VASUB_VV, "ACB?k", VECTOR},
  {"vasub_vx", MATCH_VASUB_VX, MASK_VASUB_VX, "ACs?k", VECTOR},
  {"vredsum_vs", MATCH_VREDSUM_VS, MASK_VREDSUM_VS, "ACB?k", VECTOR},
  {"vredand_vs", MATCH_VREDAND_VS, MASK_VREDAND_VS, "ACB?k", VECTOR},
  {"vredor_vs", MATCH_VREDOR_VS, MASK_VREDOR_VS, "ACB?k", VECTOR},
  {"vredxor_vs", MATCH_VREDXOR_VS, MASK_VREDXOR_VS, "ACB?k", VECTOR},
  {"vredminu_vs", MATCH_VREDMINU_VS, MASK_VREDMINU_VS, "ACB?k", VECTOR},
  {"vredmin_vs", MATCH_VREDMIN_VS, MASK_VREDMIN_VS, "ACB?k", VECTOR},
  {"vredmaxu_vs", MATCH_VREDMAXU_VS, MASK_VREDMAXU_VS, "ACB?k", VECTOR},
  {"vredmax_vs", MATCH_VREDMAX_VS, MASK_VREDMAX_VS, "ACB?k", VECTOR},
  {"vslide1up_vx", MATCH_VSLIDE1UP_VX, MASK_VSLIDE1UP_VX, "ACs?k", VECTOR},
  {"vslide1down_vx", MATCH_VSLIDE1DOWN_VX, MASK_VSLIDE1DOWN_VX, "ACs?k", VECTOR},
  {"vmv.x.s", MATCH_VMV_X_S, MASK_VMV_X_S, "dC", VECTOR},
  {"vcpop.m", MATCH_VCPOP_M, MASK_VCPOP_M, "dC?k", VECTOR},
  {"vfirst.m", MATCH_VFIRST_M, MASK_VFIRST_M, "dC?k", VECTOR},
  {"vmv.s.x", MATCH_VMV_S_X, MASK_VMV_S_X, "As", VECTOR},
  {"vzext_vf2", MATCH_VZEXT_VF2, MASK_VZEXT_VF2, "AC?k", VECTOR},
  {"vsext_vf2", MATCH_VSEXT_VF2, MASK_VSEXT_VF2, "AC?k", VECTOR},
  {"vzext_vf4", MATCH_VZEXT_VF4, MASK_VZEXT_VF4, "AC?k", VECTOR},
  {"vsext_vf4", MATCH_VSEXT_VF4, MASK_VSEXT_VF4, "AC?k", VECTOR},
  {"vzext_vf8", MATCH_VZEXT_VF8, MASK_VZEXT_VF8, "AC?k", VECTOR},
  {"vsext_vf8", MATCH_VSEXT_VF8, MASK_VSEXT_VF8, "AC?k", VECTOR},
  {"vmsbf_m", MATCH_VMSBF_M, MASK_VMSBF_M, "AC?k", VECTOR},
  {"vmsof_m", MATCH_VMSOF_M, MASK_VMSOF_M, "AC?k", VECTOR},
  {"vmsif_m", MATCH_VMSIF_M, MASK_VMSIF_M, "AC?k", VECTOR},
  {"viota_m", MATCH_VIOTA_M, MASK_VIOTA_M, "AC?k", VECTOR},
  {"vid.v", MATCH_VID_V, MASK_VID_V, "A?k", VECTOR},
  {"vid.v", MATCH_VID_V, MASK_VID_V, "A?k", VECTOR},
  {"vcompress.vm", MATCH_VCOMPRESS_VM, MASK_VCOMPRESS_VM, "ACB", VECTOR},
  {"vmandn_mm", MATCH_VMANDN_MM, MASK_VMANDN_MM, "ACB?k", VECTOR},
  {"vmand_mm", MATCH_VMAND_MM, MASK_VMAND_MM, "ACB?k", VECTOR},
  {"vmor_mm", MATCH_VMOR_MM, MASK_VMOR_MM, "ACB?k", VECTOR},
  {"vmxor_mm", MATCH_VMXOR_MM, MASK_VMXOR_MM, "ACB?k", VECTOR},
  {"vmorn_mm", MATCH_VMORN_MM, MASK_VMORN_MM, "ACB?k", VECTOR},
  {"vmnand_mm", MATCH_VMNAND_MM, MASK_VMNAND_MM, "ACB?k", VECTOR},
  {"vmnor_mm", MATCH_VMNOR_MM, MASK_VMNOR_MM, "ACB?k", VECTOR},
  {"vmxnor_mm", MATCH_VMXNOR_MM, MASK_VMXNOR_MM, "ACB?k", VECTOR},
  {"vdivu_vv", MATCH_VDIVU_VV, MASK_VDIVU_VV, "ACB?k", VECTOR},
  {"vdivu_vx", MATCH_VDIVU_VX, MASK_VDIVU_VX, "ACs?k", VECTOR},
  {"vdiv_vv", MATCH_VDIV_VV, MASK_VDIV_VV, "ACB?k", VECTOR},
  {"vdiv_vx", MATCH_VDIV_VX, MASK_VDIV_VX, "ACs?k", VECTOR},
  {"vremu_vv", MATCH_VREMU_VV, MASK_VREMU_VV, "ACB?k", VECTOR},
  {"vremu_vx", MATCH_VREMU_VX, MASK_VREMU_VX, "ACs?k", VECTOR},
  {"vrem_vv", MATCH_VREM_VV, MASK_VREM_VV, "ACB?k", VECTOR},
  {"vrem_vx", MATCH_VREM_VX, MASK_VREM_VX, "ACs?k", VECTOR},
  {"vmulhu_vv", MATCH_VMULHU_VV, MASK_VMULHU_VV, "ACB?k", VECTOR},
  {"vmulhu_vx", MATCH_VMULHU_VX, MASK_VMULHU_VX, "ACs?k", VECTOR},
  {"vmul_vv", MATCH_VMUL_VV, MASK_VMUL_VV, "ACB?k", VECTOR},
  {"vmul_vx", MATCH_VMUL_VX, MASK_VMUL_VX, "ACs?k", VECTOR},
  {"vmulhsu_vv", MATCH_VMULHSU_VV, MASK_VMULHSU_VV, "ACB?k", VECTOR},
  {"vmulhsu_vx", MATCH_VMULHSU_VX, MASK_VMULHSU_VX, "ACs?k", VECTOR},
  {"vmulh_vv", MATCH_VMULH_VV, MASK_VMULH_VV, "ACB?k", VECTOR},
  {"vmulh_vx", MATCH_VMULH_VX, MASK_VMULH_VX, "ACs?k", VECTOR},
  {"vmadd_vv", MATCH_VMADD_VV, MASK_VMADD_VV, "ABC?k", VECTOR},
  {"vmadd_vx", MATCH_VMADD_VX, MASK_VMADD_VX, "AsC?k", VECTOR},
  {"vnmsub_vv", MATCH_VNMSUB_VV, MASK_VNMSUB_VV, "ABC?k", VECTOR},
  {"vnmsub_vx", MATCH_VNMSUB_VX, MASK_VNMSUB_VX, "AsC?k", VECTOR},
  {"vmacc_vv", MATCH_VMACC_VV, MASK_VMACC_VV, "ABC?k", VECTOR},
  {"vmacc_vx", MATCH_VMACC_VX, MASK_VMACC_VX, "AsC?k", VECTOR},
  {"vnmsac_vv", MATCH_VNMSAC_VV, MASK_VNMSAC_VV, "ABC?k", VECTOR},
  {"vnmsac_vx", MATCH_VNMSAC_VX, MASK_VNMSAC_VX, "AsC?k", VECTOR},
  {"vwaddu_vv", MATCH_VWADDU_VV, MASK_VWADDU_VV, "ACB?k", VECTOR},
  {"vwaddu_vx", MATCH_VWADDU_VX, MASK_VWADDU_VX, "ACs?k", VECTOR},
  {"vwadd_vv", MATCH_VWADD_VV, MASK_VWADD_VV, "ACB?k", VECTOR},
  {"vwadd_vx", MATCH_VWADD_VX, MASK_VWADD_VX, "ACs?k", VECTOR},
  {"vwsubu_vv", MATCH_VWSUBU_VV, MASK_VWSUBU_VV, "ACB?k", VECTOR},
  {"vwsubu_vx", MATCH_VWSUBU_VX, MASK_VWSUBU_VX, "ACs?k", VECTOR},
  {"vwsub_vv", MATCH_VWSUB_VV, MASK_VWSUB_VV, "ACB?k", VECTOR},
  {"vwsub_vx", MATCH_VWSUB_VX, MASK_VWSUB_VX, "ACs?k", VECTOR},
  {"vwaddu_wv", MATCH_VWADDU_WV, MASK_VWADDU_WV, "ACB?k", VECTOR},
  {"vwaddu_wx", MATCH_VWADDU_WX, MASK_VWADDU_WX, "ACs?k", VECTOR},
  {"vwadd_wv", MATCH_VWADD_WV, MASK_VWADD_WV, "ACB?k", VECTOR},
  {"vwadd_wx", MATCH_VWADD_WX, MASK_VWADD_WX, "ACs?k", VECTOR},
  {"vwsubu_wv", MATCH_VWSUBU_WV, MASK_VWSUBU_WV, "ACB?k", VECTOR},
  {"vwsubu_wx", MATCH_VWSUBU_WX, MASK_VWSUBU_WX, "ACs?k", VECTOR},
  {"vwsub_wv", MATCH_VWSUB_WV, MASK_VWSUB_WV, "ACB?k", VECTOR},
  {"vwsub_wx", MATCH_VWSUB_WX, MASK_VWSUB_WX, "ACs?k", VECTOR},
  {"vwmulu_vv", MATCH_VWMULU_VV, MASK_VWMULU_VV, "ACB?k", VECTOR},
  {"vwmulu_vx", MATCH_VWMULU_VX, MASK_VWMULU_VX, "ACs?k", VECTOR},
  {"vwmulsu_vv", MATCH_VWMULSU_VV, MASK_VWMULSU_VV, "ACB?k", VECTOR},
  {"vwmulsu_vx", MATCH_VWMULSU_VX, MASK_VWMULSU_VX, "ACs?k", VECTOR},
  {"vwmul_vv", MATCH_VWMUL_VV, MASK_VWMUL_VV, "ACB?k", VECTOR},
  {"vwmul_vx", MATCH_VWMUL_VX, MASK_VWMUL_VX, "ACs?k", VECTOR},
  {"vwmaccu_vv", MATCH_VWMACCU_VV, MASK_VWMACCU_VV, "ABC?k", VECTOR},
  {"vwmaccu_vx", MATCH_VWMACCU_VX, MASK_VWMACCU_VX, "AsC?k", VECTOR},
  {"vwmacc_vv", MATCH_VWMACC_VV, MASK_VWMACC_VV, "ABC?k", VECTOR},
  {"vwmacc_vx", MATCH_VWMACC_VX, MASK_VWMACC_VX, "AsC?k", VECTOR},
  {"vwmaccus_vx", MATCH_VWMACCUS_VX, MASK_VWMACCUS_VX, "AsC?k", VECTOR},
  {"vwmaccsu_vv", MATCH_VWMACCSU_VV, MASK_VWMACCSU_VV, "ABC?k", VECTOR},
  {"vwmaccsu_vx", MATCH_VWMACCSU_VX, MASK_VWMACCSU_VX, "AsC?k", VECTOR},
  {"vqdot_vv", MATCH_VQDOT_VV, MASK_VQDOT_VV, "ACB?k", ZVQDOTQ},
  {"vqdot_vx", MATCH_VQDOT_VX, MASK_VQDOT_VX, "ACs?k", ZVQDOTQ},
  {"vqdotu_vv", MATCH_VQDOTU_VV, MASK_VQDOTU_VV, "ACB?k", ZVQDOTQ},
  {"vqdotu_vx", MATCH_VQDOTU_VX, MASK_VQDOTU_VX, "ACs?k", ZVQDOTQ},
  {"vqdotsu_vv", MATCH_VQDOTSU_VV, MASK_VQDOTSU_VV, "ACB?k", ZVQDOTQ},
  {"vqdotsu_vx", MATCH_VQDOTSU_VX, MASK_VQDOTSU_VX, "ACs?k", ZVQDOTQ},
  {"vqdotus_vx", MATCH_VQDOTUS_VX, MASK_VQDOTUS_VX, "ACs?k", ZVQDOTQ},
  {"vfadd_vv", MATCH_VFADD_VV, MASK_VFADD_VV, "ACB?k", VECTOR},
  {"vfadd_vf", MATCH_VFADD_VF, MASK_VFADD_VF, "ACS?k", VECTOR},
  {"vfredusum_vs", MATCH_VFREDUSUM_VS, MASK_VFREDUSUM_VS, "ACB?k", VECTOR},
  {"vfsub_vv", MATCH_VFSUB_VV, MASK_VFSUB_VV, "ACB?k", VECTOR},
  {"vfsub_vf", MATCH_VFSUB_VF, MASK_VFSUB_VF, "ACS?k", VECTOR},
  {"vfredosum_vs", MATCH_VFREDOSUM_VS, MASK_VFREDOSUM_VS, "ACB?k", VECTOR},
  {"vfmin_vv", MATCH_VFMIN_VV, MASK_VFMIN_VV, "ACB?k", VECTOR},
  {"vfmin_vf", MATCH_VFMIN_VF, MASK_VFMIN_VF, "ACS?k", VECTOR},
  {"vfredmin_vs", MATCH_VFREDMIN_VS, MASK_VFREDMIN_VS, "ACB?k", VECTOR},
  {"vfmax_vv", MATCH_VFMAX_VV, MASK_VFMAX_VV, "ACB?k", VECTOR},
  {"vfmax_vf", MATCH_VFMAX_VF, MASK_VFMAX_VF, "ACS?k", VECTOR},
  {"vfredmax_vs", MATCH_VFREDMAX_VS, MASK_VFREDMAX_VS, "ACB?k", VECTOR},
  {"vfsgnj_vv", MATCH_VFSGNJ_VV, MASK_VFSGNJ_VV, "ACB?k", VECTOR},
  {"vfsgnj_vf", MATCH_VFSGNJ_VF, MASK_VFSGNJ_VF, "ACS?k", VECTOR},
  {"vfsgnjn_vv", MATCH_VFSGNJN_VV, MASK_VFSGNJN_VV, "ACB?k", VECTOR},
  {"vfsgnjn_vf", MATCH_VFSGNJN_VF, MASK_VFSGNJN_VF, "ACS?k", VECTOR},
  {"vfsgnjx_vv", MATCH_VFSGNJX_VV, MASK_VFSGNJX_VV, "ACB?k", VECTOR},
  {"vfsgnjx_vf", MATCH_VFSGNJX_VF, MASK_VFSGNJX_VF, "ACS?k", VECTOR},
  {"vfmv.f.s", MATCH_VFMV_F_S, MASK_VFMV_F_S, "DC", VECTOR},
  {"vfmv.s.f", MATCH_VFMV_S_F, MASK_VFMV_S_F | MASK_VFMV_S_F, "AS", VECTOR},
  {"vfslide1up_vf", MATCH_VFSLIDE1UP_VF, MASK_VFSLIDE1UP_VF, "ACS?k", VECTOR},
  {"vfslide1down_vf", MATCH_VFSLIDE1DOWN_VF, MASK_VFSLIDE1DOWN_VF, "ACS?k", VECTOR},
  {"vfmerge.vfm", MATCH_VFMERGE_VFM, MASK_VFMERGE_VFM, "ACSK", VECTOR},
  {"vfmv.v.f", MATCH_VFMV_V_F, MASK_VFMV_V_F, "AS", VECTOR},
  {"vmfeq_vv", MATCH_VMFEQ_VV, MASK_VMFEQ_VV, "ACB?k", VECTOR},
  {"vmfeq_vf", MATCH_VMFEQ_VF, MASK_VMFEQ_VF, "ACS?k", VECTOR},
  {"vmfle_vv", MATCH_VMFLE_VV, MASK_VMFLE_VV, "ACB?k", VECTOR},
  {"vmfle_vf", MATCH_VMFLE_VF, MASK_VMFLE_VF, "ACS?k", VECTOR},
  {"vmflt_vv", MATCH_VMFLT_VV, MASK_VMFLT_VV, "ACB?k", VECTOR},
  {"vmflt_vf", MATCH_VMFLT_VF, MASK_VMFLT_VF, "ACS?k", VECTOR},
  {"vmfne_vv", MATCH_VMFNE_VV, MASK_VMFNE_VV, "ACB?k", VECTOR},
  {"vmfne_vf", MATCH_VMFNE_VF, MASK_VMFNE_VF, "ACS?k", VECTOR},
  {"vmfgt_vf", MATCH_VMFGT_VF, MASK_VMFGT_VF, "ACS?k", VECTOR},
  {"vmfge_vf", MATCH_VMFGE_VF, MASK_VMFGE_VF, "ACS?k", VECTOR},
  {"vfdiv_vv", MATCH_VFDIV_VV, MASK_VFDIV_VV, "ACB?k", VECTOR},
  {"vfdiv_vf", MATCH_VFDIV_VF, MASK_VFDIV_VF, "ACS?k", VECTOR},
  {"vfrdiv_vf", MATCH_VFRDIV_VF, MASK_VFRDIV_VF, "ACS?k", VECTOR},
  {"vfcvt_rtz_xu_f_v", MATCH_VFCVT_RTZ_XU_F_V, MASK_VFCVT_RTZ_XU_F_V, "AC?k", VECTOR},
  {"vfcvt_rtz_x_f_v", MATCH_VFCVT_RTZ_X_F_V, MASK_VFCVT_RTZ_X_F_V, "AC?k", VECTOR},
  {"vfcvt_xu_f_v", MATCH_VFCVT_XU_F_V, MASK_VFCVT_XU_F_V, "AC?k", VECTOR},
  {"vfcvt_x_f_v", MATCH_VFCVT_X_F_V, MASK_VFCVT_X_F_V, "AC?k", VECTOR},
  {"vfcvt_f_xu_v", MATCH_VFCVT_F_XU_V, MASK_VFCVT_F_XU_V, "AC?k", VECTOR},
  {"vfcvt_f_x_v", MATCH_VFCVT_F_X_V, MASK_VFCVT_F_X_V, "AC?k", VECTOR},
  {"vfwcvt_rtz_xu_f_v", MATCH_VFWCVT_RTZ_XU_F_V, MASK_VFWCVT_RTZ_XU_F_V, "AC?k", VECTOR},
  {"vfwcvt_rtz_x_f_v", MATCH_VFWCVT_RTZ_X_F_V, MASK_VFWCVT_RTZ_X_F_V, "AC?k", VECTOR},
  {"vfwcvt_xu_f_v", MATCH_VFWCVT_XU_F_V, MASK_VFWCVT_XU_F_V, "AC?k", VECTOR},
  {"vfwcvt_x_f_v", MATCH_VFWCVT_X_F_V, MASK_VFWCVT_X_F_V, "AC?k", VECTOR},
  {"vfwcvt_f_xu_v", MATCH_VFWCVT_F_XU_V, MASK_VFWCVT_F_XU_V, "AC?k", VECTOR},
  {"vfwcvt_f_x_v", MATCH_VFWCVT_F_X_V, MASK_VFWCVT_F_X_V, "AC?k", VECTOR},
  {"vfwcvt_f_f_v", MATCH_VFWCVT_F_F_V, MASK_VFWCVT_F_F_V, "AC?k", VECTOR},
  {"vfncvt_rtz_xu_f_w", MATCH_VFNCVT_RTZ_XU_F_W, MASK_VFNCVT_RTZ_XU_F_W, "AC?k", VECTOR},
  {"vfncvt_rtz_x_f_w", MATCH_VFNCVT_RTZ_X_F_W, MASK_VFNCVT_RTZ_X_F_W, "AC?k", VECTOR},
  {"vfncvt_xu_f_w", MATCH_VFNCVT_XU_F_W, MASK_VFNCVT_XU_F_W, "AC?k", VECTOR},
  {"vfncvt_x_f_w", MATCH_VFNCVT_X_F_W, MASK_VFNCVT_X_F_W, "AC?k", VECTOR},
  {"vfncvt_f_xu_w", MATCH_VFNCVT_F_XU_W, MASK_VFNCVT_F_XU_W, "AC?k", VECTOR},
  {"vfncvt_f_x_w", MATCH_VFNCVT_F_X_W, MASK_VFNCVT_F_X_W, "AC?k", VECTOR},
  {"vfncvt_f_f_w", MATCH_VFNCVT_F_F_W, MASK_VFNCVT_F_F_W, "AC?k", VECTOR},
  {"vfncvt_rod_f_f_w", MATCH_VFNCVT_ROD_F_F_W, MASK_VFNCVT_ROD_F_F_W, "AC?k", VECTOR},
  {"vfsqrt_v", MATCH_VFSQRT_V, MASK_VFSQRT_V, "AC?k", VECTOR},
  {"vfrsqrt7_v", MATCH_VFRSQRT7_V, MASK_VFRSQRT7_V, "AC?k", VECTOR},
  {"vfrec7_v", MATCH_VFREC7_V, MASK_VFREC7_V, "AC?k", VECTOR},
  {"vfclass_v", MATCH_VFCLASS_V, MASK_VFCLASS_V, "AC?k", VECTOR},
  {"vfmul_vv", MATCH_VFMUL_VV, MASK_VFMUL_VV, "ACB?k", VECTOR},
  {"vfmul_vf", MATCH_VFMUL_VF, MASK_VFMUL_VF, "ACS?k", VECTOR},
  {"vfrsub_vf", MATCH_VFRSUB_VF, MASK_VFRSUB_VF, "ACS?k", VECTOR},
  {"vfmadd_vv", MATCH_VFMADD_VV, MASK_VFMADD_VV, "ABC?k", VECTOR},
  {"vfmadd_vf", MATCH_VFMADD_VF, MASK_VFMADD_VF, "ASC?k", VECTOR},
  {"vfnmadd_vv", MATCH_VFNMADD_VV, MASK_VFNMADD_VV, "ABC?k", VECTOR},
  {"vfnmadd_vf", MATCH_VFNMADD_VF, MASK_VFNMADD_VF, "ASC?k", VECTOR},
  {"vfmsub_vv", MATCH_VFMSUB_VV, MASK_VFMSUB_VV, "ABC?k", VECTOR},
  {"vfmsub_vf", MATCH_VFMSUB_VF, MASK_VFMSUB_VF, "ASC?k", VECTOR},
  {"vfnmsub_vv", MATCH_VFNMSUB_VV, MASK_VFNMSUB_VV, "ABC?k", VECTOR},
  {"vfnmsub_vf", MATCH_VFNMSUB_VF, MASK_VFNMSUB_VF, "ASC?k", VECTOR},
  {"vfmacc_vv", MATCH_VFMACC_VV, MASK_VFMACC_VV, "ABC?k", VECTOR},
  {"vfmacc_vf", MATCH_VFMACC_VF, MASK_VFMACC_VF, "ASC?k", VECTOR},
  {"vfnmacc_vv", MATCH_VFNMACC_VV, MASK_VFNMACC_VV, "ABC?k", VECTOR},
  {"vfnmacc_vf", MATCH_VFNMACC_VF, MASK_VFNMACC_VF, "ASC?k", VECTOR},
  {"vfmsac_vv", MATCH_VFMSAC_VV, MASK_VFMSAC_VV, "ABC?k", VECTOR},
  {"vfmsac_vf", MATCH_VFMSAC_VF, MASK_VFMSAC_VF, "ASC?k", VECTOR},
  {"vfnmsac_vv", MATCH_VFNMSAC_VV, MASK_VFNMSAC_VV, "ABC?k", VECTOR},
  {"vfnmsac_vf", MATCH_VFNMSAC_VF, MASK_VFNMSAC_VF, "ASC?k", VECTOR},
  {"vfwadd_vv", MATCH_VFWADD_VV, MASK_VFWADD_VV, "ACB?k", VECTOR},
  {"vfwadd_vf", MATCH_VFWADD_VF, MASK_VFWADD_VF, "ACS?k", VECTOR},
  {"vfwredusum_vs", MATCH_VFWREDUSUM_VS, MASK_VFWREDUSUM_VS, "ACB?k", VECTOR},
  {"vfwsub_vv", MATCH_VFWSUB_VV, MASK_VFWSUB_VV, "ACB?k", VECTOR},
  {"vfwsub_vf", MATCH_VFWSUB_VF, MASK_VFWSUB_VF, "ACS?k", VECTOR},
  {"vfwredosum_vs", MATCH_VFWREDOSUM_VS, MASK_VFWREDOSUM_VS, "ACB?k", VECTOR},
  {"vfwadd_wv", MATCH_VFWADD_WV, MASK_VFWADD_WV, "ACB?k", VECTOR},
  {"vfwadd_wf", MATCH_VFWADD_WF, MASK_VFWADD_WF, "ACS?k", VECTOR},
  {"vfwsub_wv", MATCH_VFWSUB_WV, MASK_VFWSUB_WV, "ACB?k", VECTOR},
  {"vfwsub_wf", MATCH_VFWSUB_WF, MASK_VFWSUB_WF, "ACS?k", VECTOR},
  {"vfwmul_vv", MATCH_VFWMUL_VV, MASK_VFWMUL_VV, "ACB?k", VECTOR},
  {"vfwmul_vf", MATCH_VFWMUL_VF, MASK_VFWMUL_VF, "ACS?k", VECTOR},
  {"vfwmacc_vv", MATCH_VFWMACC_VV, MASK_VFWMACC_VV, "ABC?k", VECTOR},
  {"vfwmacc_vf", MATCH_VFWMACC_VF, MASK_VFWMACC_VF, "ASC?k", VECTOR},
  {"vfwnmacc_vv", MATCH_VFWNMACC_VV, MASK_VFWNMACC_VV, "ABC?k", VECTOR},
  {"vfwnmacc_vf", MATCH_VFWNMACC_VF, MASK_VFWNMACC_VF, "ASC?k", VECTOR},
  {"vfwmsac_vv", MATCH_VFWMSAC_VV, MASK_VFWMSAC_VV, "ABC?k", VECTOR},
  {"vfwmsac_vf", MATCH_VFWMSAC_VF, MASK_VFWMSAC_VF, "ASC?k", VECTOR},
  {"vfwnmsac_vv", MATCH_VFWNMSAC_VV, MASK_VFWNMSAC_VV, "ABC?k", VECTOR},
  {"vfwnmsac_vf", MATCH_VFWNMSAC_VF, MASK_VFWNMSAC_VF, "ASC?k", VECTOR},
  {"vfext_vf2", MATCH_VFEXT_VF2, MASK_VFEXT_VF2, "AC?k", ZVFOFP4MIN},
  {"vfncvt_f_f_q", MATCH_VFNCVT_F_F_Q, MASK_VFNCVT_F_F_Q, "AC?k", ZVFOFP8MIN},
  {"vfncvt_sat_f_f_q", MATCH_VFNCVT_SAT_F_F_Q, MASK_VFNCVT_SAT_F_F_Q, "AC?k", ZVFOFP8MIN},
  {"vfncvtbf16_sat_f_f_w", MATCH_VFNCVTBF16_SAT_F_F_W, MASK_VFNCVTBF16_SAT_F_F_W, "AC?k", ZVFOFP8MIN},
  {"vfncvtbf16_f_f_w", MATCH_VFNCVTBF16_F_F_W, MASK_VFNCVTBF16_F_F_W, "AC?k", ZVFBFMIN},
  {"vfwcvtbf16_f_f_v", MATCH_VFWCVTBF16_F_F_V, MASK_VFWCVTBF16_F_F_V, "AC?k", ZVFBFMIN},
  {"vfwmaccbf16_vv", MATCH_VFWMACCBF16_VV, MASK_VFWMACCBF16_VV, "ACB?k", ZVFBFWMA},
  {"vfwmaccbf16_vf", MATCH_VFWMACCBF16_VF, MASK_VFWMACCBF16_VF, "ACS?k", ZVFBFWMA},
  {"vabs_v", MATCH_VABS_V, MASK_VABS_V, "AC?k", ZVABD},
  {"vabd_vv", MATCH_VABD_VV, MASK_VABD_VV, "ACB?k", ZVABD},
  {"vabdu_vv", MATCH_VABDU_VV, MASK_VABDU_VV, "ACB?k", ZVABD},
  {"vwabda_vv", MATCH_VWABDA_VV, MASK_VWABDA_VV, "ABC?k", ZVABD},
  {"vwabdau_vv", MATCH_VWABDAU_VV, MASK_VWABDAU_VV, "ABC?k", ZVABD},
  {"vzip_vv", MATCH_VZIP_VV, MASK_VZIP_VV, "ACB?k", ZVZIP},
  {"vunzipe_v", MATCH_VUNZIPE_V, MASK_VUNZIPE_V, "AC?k", ZVZIP},
  {"vunzipo_v", MATCH_VUNZIPO_V, MASK_VUNZIPO_V, "AC?k", ZVZIP},
  {"vpaire_vv", MATCH_VPAIRE_VV, MASK_VPAIRE_VV, "ACB?k", ZVZIP},
  {"vpairo_vv", MATCH_VPAIRO_VV, MASK_VPAIRO_VV, "ACB?k", ZVZIP},
  {"vandn_vv", MATCH_VANDN_VV, MASK_VANDN_VV, "ACB?k", ZVBB},
  {"vandn_vx", MATCH_VANDN_VX, MASK_VANDN_VX, "ACs?k", ZVBB},
  {"vbrev_v", MATCH_VBREV_V, MASK_VBREV_V, "AC?k", ZVBB},
  {"vbrev8_v", MATCH_VBREV8_V, MASK_VBREV8_V, "AC?k", ZVBB},
  {"vrev8_v", MATCH_VREV8_V, MASK_VREV8_V, "AC?k", ZVBB},
  {"vclz_v", MATCH_VCLZ_V, MASK_VCLZ_V, "AC?k", ZVBB},
  {"vctz_v", MATCH_VCTZ_V, MASK_VCTZ_V, "AC?k", ZVBB},
  {"vcpop_v", MATCH_VCPOP_V, MASK_VCPOP_V, "AC?k", ZVBB},
  {"vrol_vv", MATCH_VROL_VV, MASK_VROL_VV, "ACB?k", ZVBB},
  {"vrol_vx", MATCH_VROL_VX, MASK_VROL_VX, "ACs?k", ZVBB},
  {"vror_vv", MATCH_VROR_VV, MASK_VROR_VV, "ACB?k", ZVBB},
  {"vror_vx", MATCH_VROR_VX, MASK_VROR_VX, "ACs?k", ZVBB},
  {"vror_vi", MATCH_VROR_VI, MASK_VROR_VI, "AC6?k", ZVBB},
  {"vwsll_vv", MATCH_VWSLL_VV, MASK_VWSLL_VV, "ACB?k", ZVBB},
  {"vwsll_vx", MATCH_VWSLL_VX, MASK_VWSLL_VX, "ACs?k", ZVBB},
  {"vwsll_vi", MATCH_VWSLL_VI, MASK_VWSLL_VI, "ACz?k", ZVBB},
  {"vclmul_vv", MATCH_VCLMUL_VV, MASK_VCLMUL_VV, "ACB?k", ZVBC},
  {"vclmul_vx", MATCH_VCLMUL_VX, MASK_VCLMUL_VX, "ACs?k", ZVBC},
  {"vclmulh_vv", MATCH_VCLMULH_VV, MASK_VCLMULH_VV, "ACB?k", ZVBC},
  {"vclmulh_vx", MATCH_VCLMULH_VX, MASK_VCLMULH_VX, "ACs?k", ZVBC},
  {"vgmul_vv", MATCH_VGMUL_VV, MASK_VGMUL_VV, "AC?k", ZVKG},
  {"vghsh_vv", MATCH_VGHSH_VV, MASK_VGHSH_VV, "ACB?k", ZVKG},
  {"vaesz_vs", MATCH_VAESZ_VS, MASK_VAESZ_VS, "AC?k", ZVKNED},
  {"vaeskf1_vi", MATCH_VAESKF1_VI, MASK_VAESKF1_VI, "ACz?k", ZVKNED},
  {"vaeskf2_vi", MATCH_VAESKF2_VI, MASK_VAESKF2_VI, "ACz?k", ZVKNED},
  {"vsha2ms_vv", MATCH_VSHA2MS_VV, MASK_VSHA2MS_VV, "ACB?k", ZVKNH},
  {"vsha2ch_vv", MATCH_VSHA2CH_VV, MASK_VSHA2CH_VV, "ACB?k", ZVKNH},
  {"vsha2cl_vv", MATCH_VSHA2CL_VV, MASK_VSHA2CL_VV, "ACB?k", ZVKNH},
  {"vsm4k_vi", MATCH_VSM4K_VI, MASK_VSM4K_VI, "ACz?k", ZVKSED},
  {"vsm4r_vv", MATCH_VSM4R_VV, MASK_VSM4R_VV, "AC?k", ZVKSED},
  {"vsm4r_vs", MATCH_VSM4R_VS, MASK_VSM4R_VS, "AC?k", ZVKSED},
  {"vsm3c_vi", MATCH_VSM3C_VI, MASK_VSM3C_VI, "ACz?k", ZVKSH},
  {"vsm3me_vv", MATCH_VSM3ME_VV, MASK_VSM3ME_VV, "ACB?k", ZVKSH},
  // vl1re8..vl8re64 whole-register loads
  {"vl1re8.v", MATCH_VL1RE8_V, MASK_VL1RE8_V | (0x7ul<<29), "A(?k", VECTOR},
  {"vl1re16.v", MATCH_VL1RE16_V, MASK_VL1RE16_V | (0x7ul<<29), "A(?k", VECTOR},
  {"vl1re32.v", MATCH_VL1RE32_V, MASK_VL1RE32_V | (0x7ul<<29), "A(?k", VECTOR},
  {"vl1re64.v", MATCH_VL1RE64_V, MASK_VL1RE64_V | (0x7ul<<29), "A(?k", VECTOR},
  {"vl2re8.v", MATCH_VL2RE8_V, MASK_VL2RE8_V | (0x7ul<<29), "A(?k", VECTOR},
  {"vl2re16.v", MATCH_VL2RE16_V, MASK_VL2RE16_V | (0x7ul<<29), "A(?k", VECTOR},
  {"vl2re32.v", MATCH_VL2RE32_V, MASK_VL2RE32_V | (0x7ul<<29), "A(?k", VECTOR},
  {"vl2re64.v", MATCH_VL2RE64_V, MASK_VL2RE64_V | (0x7ul<<29), "A(?k", VECTOR},
  {"vl4re8.v", MATCH_VL4RE8_V, MASK_VL4RE8_V | (0x7ul<<29), "A(?k", VECTOR},
  {"vl4re16.v", MATCH_VL4RE16_V, MASK_VL4RE16_V | (0x7ul<<29), "A(?k", VECTOR},
  {"vl4re32.v", MATCH_VL4RE32_V, MASK_VL4RE32_V | (0x7ul<<29), "A(?k", VECTOR},
  {"vl4re64.v", MATCH_VL4RE64_V, MASK_VL4RE64_V | (0x7ul<<29), "A(?k", VECTOR},
  {"vl8re8.v", MATCH_VL8RE8_V, MASK_VL8RE8_V | (0x7ul<<29), "A(?k", VECTOR},
  {"vl8re16.v", MATCH_VL8RE16_V, MASK_VL8RE16_V | (0x7ul<<29), "A(?k", VECTOR},
  {"vl8re32.v", MATCH_VL8RE32_V, MASK_VL8RE32_V | (0x7ul<<29), "A(?k", VECTOR},
  {"vl8re64.v", MATCH_VL8RE64_V, MASK_VL8RE64_V | (0x7ul<<29), "A(?k", VECTOR},

  // VECTOR segment load/store (9 types × 8 element widths × 8 nf values)
{"vle8.v", MATCH_VLE8_V, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vse8.v", MATCH_VSE8_V, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxei8.v", MATCH_VLUXEI8_V, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxei8.v", MATCH_VSUXEI8_V, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlse8.v", MATCH_VLSE8_V, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vsse8.v", MATCH_VSSE8_V, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxei8.v", MATCH_VLOXEI8_V, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxei8.v", MATCH_VSOXEI8_V, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vle8ff.v", MATCH_VLE8FF_V, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg2e8.v", MATCH_VLE8_V | SEG(2), MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg2e8.v", MATCH_VSE8_V | SEG(2), MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg2ei8.v", MATCH_VLUXEI8_V | SEG(2), MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg2ei8.v", MATCH_VSUXEI8_V | SEG(2), MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg2e8.v", MATCH_VLSE8_V | SEG(2), MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg2e8.v", MATCH_VSSE8_V | SEG(2), MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg2ei8.v", MATCH_VLOXEI8_V | SEG(2), MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg2ei8.v", MATCH_VSOXEI8_V | SEG(2), MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg2e8ff.v", MATCH_VLE8FF_V | SEG(2), MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg3e8.v", MATCH_VLE8_V | SEG(3), MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg3e8.v", MATCH_VSE8_V | SEG(3), MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg3ei8.v", MATCH_VLUXEI8_V | SEG(3), MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg3ei8.v", MATCH_VSUXEI8_V | SEG(3), MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg3e8.v", MATCH_VLSE8_V | SEG(3), MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg3e8.v", MATCH_VSSE8_V | SEG(3), MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg3ei8.v", MATCH_VLOXEI8_V | SEG(3), MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg3ei8.v", MATCH_VSOXEI8_V | SEG(3), MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg3e8ff.v", MATCH_VLE8FF_V | SEG(3), MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg4e8.v", MATCH_VLE8_V | SEG(4), MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg4e8.v", MATCH_VSE8_V | SEG(4), MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg4ei8.v", MATCH_VLUXEI8_V | SEG(4), MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg4ei8.v", MATCH_VSUXEI8_V | SEG(4), MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg4e8.v", MATCH_VLSE8_V | SEG(4), MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg4e8.v", MATCH_VSSE8_V | SEG(4), MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg4ei8.v", MATCH_VLOXEI8_V | SEG(4), MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg4ei8.v", MATCH_VSOXEI8_V | SEG(4), MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg4e8ff.v", MATCH_VLE8FF_V | SEG(4), MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg5e8.v", MATCH_VLE8_V | SEG(5), MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg5e8.v", MATCH_VSE8_V | SEG(5), MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg5ei8.v", MATCH_VLUXEI8_V | SEG(5), MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg5ei8.v", MATCH_VSUXEI8_V | SEG(5), MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg5e8.v", MATCH_VLSE8_V | SEG(5), MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg5e8.v", MATCH_VSSE8_V | SEG(5), MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg5ei8.v", MATCH_VLOXEI8_V | SEG(5), MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg5ei8.v", MATCH_VSOXEI8_V | SEG(5), MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg5e8ff.v", MATCH_VLE8FF_V | SEG(5), MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg6e8.v", MATCH_VLE8_V | SEG(6), MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg6e8.v", MATCH_VSE8_V | SEG(6), MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg6ei8.v", MATCH_VLUXEI8_V | SEG(6), MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg6ei8.v", MATCH_VSUXEI8_V | SEG(6), MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg6e8.v", MATCH_VLSE8_V | SEG(6), MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg6e8.v", MATCH_VSSE8_V | SEG(6), MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg6ei8.v", MATCH_VLOXEI8_V | SEG(6), MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg6ei8.v", MATCH_VSOXEI8_V | SEG(6), MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg6e8ff.v", MATCH_VLE8FF_V | SEG(6), MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg7e8.v", MATCH_VLE8_V | SEG(7), MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg7e8.v", MATCH_VSE8_V | SEG(7), MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg7ei8.v", MATCH_VLUXEI8_V | SEG(7), MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg7ei8.v", MATCH_VSUXEI8_V | SEG(7), MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg7e8.v", MATCH_VLSE8_V | SEG(7), MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg7e8.v", MATCH_VSSE8_V | SEG(7), MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg7ei8.v", MATCH_VLOXEI8_V | SEG(7), MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg7ei8.v", MATCH_VSOXEI8_V | SEG(7), MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg7e8ff.v", MATCH_VLE8FF_V | SEG(7), MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg8e8.v", MATCH_VLE8_V | SEG(8), MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg8e8.v", MATCH_VSE8_V | SEG(8), MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg8ei8.v", MATCH_VLUXEI8_V | SEG(8), MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg8ei8.v", MATCH_VSUXEI8_V | SEG(8), MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg8e8.v", MATCH_VLSE8_V | SEG(8), MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg8e8.v", MATCH_VSSE8_V | SEG(8), MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg8ei8.v", MATCH_VLOXEI8_V | SEG(8), MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg8ei8.v", MATCH_VSOXEI8_V | SEG(8), MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg8e8ff.v", MATCH_VLE8FF_V | SEG(8), MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vle16.v", MATCH_VLE8_V | EW16, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vse16.v", MATCH_VSE8_V | EW16, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxei16.v", MATCH_VLUXEI8_V | EW16, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxei16.v", MATCH_VSUXEI8_V | EW16, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlse16.v", MATCH_VLSE8_V | EW16, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vsse16.v", MATCH_VSSE8_V | EW16, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxei16.v", MATCH_VLOXEI8_V | EW16, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxei16.v", MATCH_VSOXEI8_V | EW16, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vle16ff.v", MATCH_VLE8FF_V | EW16, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg2e16.v", MATCH_VLE8_V | SEG(2) | EW16, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg2e16.v", MATCH_VSE8_V | SEG(2) | EW16, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg2ei16.v", MATCH_VLUXEI8_V | SEG(2) | EW16, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg2ei16.v", MATCH_VSUXEI8_V | SEG(2) | EW16, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg2e16.v", MATCH_VLSE8_V | SEG(2) | EW16, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg2e16.v", MATCH_VSSE8_V | SEG(2) | EW16, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg2ei16.v", MATCH_VLOXEI8_V | SEG(2) | EW16, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg2ei16.v", MATCH_VSOXEI8_V | SEG(2) | EW16, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg2e16ff.v", MATCH_VLE8FF_V | SEG(2) | EW16, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg3e16.v", MATCH_VLE8_V | SEG(3) | EW16, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg3e16.v", MATCH_VSE8_V | SEG(3) | EW16, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg3ei16.v", MATCH_VLUXEI8_V | SEG(3) | EW16, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg3ei16.v", MATCH_VSUXEI8_V | SEG(3) | EW16, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg3e16.v", MATCH_VLSE8_V | SEG(3) | EW16, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg3e16.v", MATCH_VSSE8_V | SEG(3) | EW16, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg3ei16.v", MATCH_VLOXEI8_V | SEG(3) | EW16, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg3ei16.v", MATCH_VSOXEI8_V | SEG(3) | EW16, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg3e16ff.v", MATCH_VLE8FF_V | SEG(3) | EW16, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg4e16.v", MATCH_VLE8_V | SEG(4) | EW16, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg4e16.v", MATCH_VSE8_V | SEG(4) | EW16, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg4ei16.v", MATCH_VLUXEI8_V | SEG(4) | EW16, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg4ei16.v", MATCH_VSUXEI8_V | SEG(4) | EW16, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg4e16.v", MATCH_VLSE8_V | SEG(4) | EW16, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg4e16.v", MATCH_VSSE8_V | SEG(4) | EW16, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg4ei16.v", MATCH_VLOXEI8_V | SEG(4) | EW16, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg4ei16.v", MATCH_VSOXEI8_V | SEG(4) | EW16, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg4e16ff.v", MATCH_VLE8FF_V | SEG(4) | EW16, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg5e16.v", MATCH_VLE8_V | SEG(5) | EW16, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg5e16.v", MATCH_VSE8_V | SEG(5) | EW16, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg5ei16.v", MATCH_VLUXEI8_V | SEG(5) | EW16, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg5ei16.v", MATCH_VSUXEI8_V | SEG(5) | EW16, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg5e16.v", MATCH_VLSE8_V | SEG(5) | EW16, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg5e16.v", MATCH_VSSE8_V | SEG(5) | EW16, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg5ei16.v", MATCH_VLOXEI8_V | SEG(5) | EW16, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg5ei16.v", MATCH_VSOXEI8_V | SEG(5) | EW16, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg5e16ff.v", MATCH_VLE8FF_V | SEG(5) | EW16, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg6e16.v", MATCH_VLE8_V | SEG(6) | EW16, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg6e16.v", MATCH_VSE8_V | SEG(6) | EW16, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg6ei16.v", MATCH_VLUXEI8_V | SEG(6) | EW16, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg6ei16.v", MATCH_VSUXEI8_V | SEG(6) | EW16, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg6e16.v", MATCH_VLSE8_V | SEG(6) | EW16, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg6e16.v", MATCH_VSSE8_V | SEG(6) | EW16, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg6ei16.v", MATCH_VLOXEI8_V | SEG(6) | EW16, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg6ei16.v", MATCH_VSOXEI8_V | SEG(6) | EW16, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg6e16ff.v", MATCH_VLE8FF_V | SEG(6) | EW16, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg7e16.v", MATCH_VLE8_V | SEG(7) | EW16, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg7e16.v", MATCH_VSE8_V | SEG(7) | EW16, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg7ei16.v", MATCH_VLUXEI8_V | SEG(7) | EW16, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg7ei16.v", MATCH_VSUXEI8_V | SEG(7) | EW16, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg7e16.v", MATCH_VLSE8_V | SEG(7) | EW16, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg7e16.v", MATCH_VSSE8_V | SEG(7) | EW16, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg7ei16.v", MATCH_VLOXEI8_V | SEG(7) | EW16, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg7ei16.v", MATCH_VSOXEI8_V | SEG(7) | EW16, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg7e16ff.v", MATCH_VLE8FF_V | SEG(7) | EW16, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg8e16.v", MATCH_VLE8_V | SEG(8) | EW16, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg8e16.v", MATCH_VSE8_V | SEG(8) | EW16, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg8ei16.v", MATCH_VLUXEI8_V | SEG(8) | EW16, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg8ei16.v", MATCH_VSUXEI8_V | SEG(8) | EW16, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg8e16.v", MATCH_VLSE8_V | SEG(8) | EW16, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg8e16.v", MATCH_VSSE8_V | SEG(8) | EW16, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg8ei16.v", MATCH_VLOXEI8_V | SEG(8) | EW16, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg8ei16.v", MATCH_VSOXEI8_V | SEG(8) | EW16, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg8e16ff.v", MATCH_VLE8FF_V | SEG(8) | EW16, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vle32.v", MATCH_VLE8_V | EW32, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vse32.v", MATCH_VSE8_V | EW32, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxei32.v", MATCH_VLUXEI8_V | EW32, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxei32.v", MATCH_VSUXEI8_V | EW32, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlse32.v", MATCH_VLSE8_V | EW32, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vsse32.v", MATCH_VSSE8_V | EW32, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxei32.v", MATCH_VLOXEI8_V | EW32, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxei32.v", MATCH_VSOXEI8_V | EW32, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vle32ff.v", MATCH_VLE8FF_V | EW32, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg2e32.v", MATCH_VLE8_V | SEG(2) | EW32, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg2e32.v", MATCH_VSE8_V | SEG(2) | EW32, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg2ei32.v", MATCH_VLUXEI8_V | SEG(2) | EW32, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg2ei32.v", MATCH_VSUXEI8_V | SEG(2) | EW32, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg2e32.v", MATCH_VLSE8_V | SEG(2) | EW32, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg2e32.v", MATCH_VSSE8_V | SEG(2) | EW32, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg2ei32.v", MATCH_VLOXEI8_V | SEG(2) | EW32, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg2ei32.v", MATCH_VSOXEI8_V | SEG(2) | EW32, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg2e32ff.v", MATCH_VLE8FF_V | SEG(2) | EW32, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg3e32.v", MATCH_VLE8_V | SEG(3) | EW32, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg3e32.v", MATCH_VSE8_V | SEG(3) | EW32, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg3ei32.v", MATCH_VLUXEI8_V | SEG(3) | EW32, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg3ei32.v", MATCH_VSUXEI8_V | SEG(3) | EW32, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg3e32.v", MATCH_VLSE8_V | SEG(3) | EW32, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg3e32.v", MATCH_VSSE8_V | SEG(3) | EW32, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg3ei32.v", MATCH_VLOXEI8_V | SEG(3) | EW32, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg3ei32.v", MATCH_VSOXEI8_V | SEG(3) | EW32, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg3e32ff.v", MATCH_VLE8FF_V | SEG(3) | EW32, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg4e32.v", MATCH_VLE8_V | SEG(4) | EW32, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg4e32.v", MATCH_VSE8_V | SEG(4) | EW32, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg4ei32.v", MATCH_VLUXEI8_V | SEG(4) | EW32, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg4ei32.v", MATCH_VSUXEI8_V | SEG(4) | EW32, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg4e32.v", MATCH_VLSE8_V | SEG(4) | EW32, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg4e32.v", MATCH_VSSE8_V | SEG(4) | EW32, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg4ei32.v", MATCH_VLOXEI8_V | SEG(4) | EW32, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg4ei32.v", MATCH_VSOXEI8_V | SEG(4) | EW32, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg4e32ff.v", MATCH_VLE8FF_V | SEG(4) | EW32, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg5e32.v", MATCH_VLE8_V | SEG(5) | EW32, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg5e32.v", MATCH_VSE8_V | SEG(5) | EW32, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg5ei32.v", MATCH_VLUXEI8_V | SEG(5) | EW32, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg5ei32.v", MATCH_VSUXEI8_V | SEG(5) | EW32, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg5e32.v", MATCH_VLSE8_V | SEG(5) | EW32, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg5e32.v", MATCH_VSSE8_V | SEG(5) | EW32, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg5ei32.v", MATCH_VLOXEI8_V | SEG(5) | EW32, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg5ei32.v", MATCH_VSOXEI8_V | SEG(5) | EW32, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg5e32ff.v", MATCH_VLE8FF_V | SEG(5) | EW32, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg6e32.v", MATCH_VLE8_V | SEG(6) | EW32, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg6e32.v", MATCH_VSE8_V | SEG(6) | EW32, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg6ei32.v", MATCH_VLUXEI8_V | SEG(6) | EW32, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg6ei32.v", MATCH_VSUXEI8_V | SEG(6) | EW32, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg6e32.v", MATCH_VLSE8_V | SEG(6) | EW32, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg6e32.v", MATCH_VSSE8_V | SEG(6) | EW32, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg6ei32.v", MATCH_VLOXEI8_V | SEG(6) | EW32, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg6ei32.v", MATCH_VSOXEI8_V | SEG(6) | EW32, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg6e32ff.v", MATCH_VLE8FF_V | SEG(6) | EW32, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg7e32.v", MATCH_VLE8_V | SEG(7) | EW32, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg7e32.v", MATCH_VSE8_V | SEG(7) | EW32, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg7ei32.v", MATCH_VLUXEI8_V | SEG(7) | EW32, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg7ei32.v", MATCH_VSUXEI8_V | SEG(7) | EW32, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg7e32.v", MATCH_VLSE8_V | SEG(7) | EW32, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg7e32.v", MATCH_VSSE8_V | SEG(7) | EW32, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg7ei32.v", MATCH_VLOXEI8_V | SEG(7) | EW32, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg7ei32.v", MATCH_VSOXEI8_V | SEG(7) | EW32, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg7e32ff.v", MATCH_VLE8FF_V | SEG(7) | EW32, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg8e32.v", MATCH_VLE8_V | SEG(8) | EW32, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg8e32.v", MATCH_VSE8_V | SEG(8) | EW32, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg8ei32.v", MATCH_VLUXEI8_V | SEG(8) | EW32, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg8ei32.v", MATCH_VSUXEI8_V | SEG(8) | EW32, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg8e32.v", MATCH_VLSE8_V | SEG(8) | EW32, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg8e32.v", MATCH_VSSE8_V | SEG(8) | EW32, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg8ei32.v", MATCH_VLOXEI8_V | SEG(8) | EW32, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg8ei32.v", MATCH_VSOXEI8_V | SEG(8) | EW32, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg8e32ff.v", MATCH_VLE8FF_V | SEG(8) | EW32, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vle64.v", MATCH_VLE8_V | EW64, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vse64.v", MATCH_VSE8_V | EW64, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxei64.v", MATCH_VLUXEI8_V | EW64, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxei64.v", MATCH_VSUXEI8_V | EW64, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlse64.v", MATCH_VLSE8_V | EW64, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vsse64.v", MATCH_VSSE8_V | EW64, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxei64.v", MATCH_VLOXEI8_V | EW64, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxei64.v", MATCH_VSOXEI8_V | EW64, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vle64ff.v", MATCH_VLE8FF_V | EW64, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg2e64.v", MATCH_VLE8_V | SEG(2) | EW64, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg2e64.v", MATCH_VSE8_V | SEG(2) | EW64, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg2ei64.v", MATCH_VLUXEI8_V | SEG(2) | EW64, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg2ei64.v", MATCH_VSUXEI8_V | SEG(2) | EW64, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg2e64.v", MATCH_VLSE8_V | SEG(2) | EW64, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg2e64.v", MATCH_VSSE8_V | SEG(2) | EW64, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg2ei64.v", MATCH_VLOXEI8_V | SEG(2) | EW64, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg2ei64.v", MATCH_VSOXEI8_V | SEG(2) | EW64, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg2e64ff.v", MATCH_VLE8FF_V | SEG(2) | EW64, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg3e64.v", MATCH_VLE8_V | SEG(3) | EW64, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg3e64.v", MATCH_VSE8_V | SEG(3) | EW64, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg3ei64.v", MATCH_VLUXEI8_V | SEG(3) | EW64, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg3ei64.v", MATCH_VSUXEI8_V | SEG(3) | EW64, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg3e64.v", MATCH_VLSE8_V | SEG(3) | EW64, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg3e64.v", MATCH_VSSE8_V | SEG(3) | EW64, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg3ei64.v", MATCH_VLOXEI8_V | SEG(3) | EW64, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg3ei64.v", MATCH_VSOXEI8_V | SEG(3) | EW64, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg3e64ff.v", MATCH_VLE8FF_V | SEG(3) | EW64, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg4e64.v", MATCH_VLE8_V | SEG(4) | EW64, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg4e64.v", MATCH_VSE8_V | SEG(4) | EW64, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg4ei64.v", MATCH_VLUXEI8_V | SEG(4) | EW64, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg4ei64.v", MATCH_VSUXEI8_V | SEG(4) | EW64, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg4e64.v", MATCH_VLSE8_V | SEG(4) | EW64, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg4e64.v", MATCH_VSSE8_V | SEG(4) | EW64, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg4ei64.v", MATCH_VLOXEI8_V | SEG(4) | EW64, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg4ei64.v", MATCH_VSOXEI8_V | SEG(4) | EW64, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg4e64ff.v", MATCH_VLE8FF_V | SEG(4) | EW64, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg5e64.v", MATCH_VLE8_V | SEG(5) | EW64, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg5e64.v", MATCH_VSE8_V | SEG(5) | EW64, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg5ei64.v", MATCH_VLUXEI8_V | SEG(5) | EW64, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg5ei64.v", MATCH_VSUXEI8_V | SEG(5) | EW64, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg5e64.v", MATCH_VLSE8_V | SEG(5) | EW64, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg5e64.v", MATCH_VSSE8_V | SEG(5) | EW64, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg5ei64.v", MATCH_VLOXEI8_V | SEG(5) | EW64, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg5ei64.v", MATCH_VSOXEI8_V | SEG(5) | EW64, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg5e64ff.v", MATCH_VLE8FF_V | SEG(5) | EW64, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg6e64.v", MATCH_VLE8_V | SEG(6) | EW64, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg6e64.v", MATCH_VSE8_V | SEG(6) | EW64, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg6ei64.v", MATCH_VLUXEI8_V | SEG(6) | EW64, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg6ei64.v", MATCH_VSUXEI8_V | SEG(6) | EW64, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg6e64.v", MATCH_VLSE8_V | SEG(6) | EW64, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg6e64.v", MATCH_VSSE8_V | SEG(6) | EW64, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg6ei64.v", MATCH_VLOXEI8_V | SEG(6) | EW64, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg6ei64.v", MATCH_VSOXEI8_V | SEG(6) | EW64, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg6e64ff.v", MATCH_VLE8FF_V | SEG(6) | EW64, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg7e64.v", MATCH_VLE8_V | SEG(7) | EW64, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg7e64.v", MATCH_VSE8_V | SEG(7) | EW64, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg7ei64.v", MATCH_VLUXEI8_V | SEG(7) | EW64, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg7ei64.v", MATCH_VSUXEI8_V | SEG(7) | EW64, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg7e64.v", MATCH_VLSE8_V | SEG(7) | EW64, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg7e64.v", MATCH_VSSE8_V | SEG(7) | EW64, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg7ei64.v", MATCH_VLOXEI8_V | SEG(7) | EW64, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg7ei64.v", MATCH_VSOXEI8_V | SEG(7) | EW64, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg7e64ff.v", MATCH_VLE8FF_V | SEG(7) | EW64, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg8e64.v", MATCH_VLE8_V | SEG(8) | EW64, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg8e64.v", MATCH_VSE8_V | SEG(8) | EW64, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg8ei64.v", MATCH_VLUXEI8_V | SEG(8) | EW64, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg8ei64.v", MATCH_VSUXEI8_V | SEG(8) | EW64, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg8e64.v", MATCH_VLSE8_V | SEG(8) | EW64, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg8e64.v", MATCH_VSSE8_V | SEG(8) | EW64, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg8ei64.v", MATCH_VLOXEI8_V | SEG(8) | EW64, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg8ei64.v", MATCH_VSOXEI8_V | SEG(8) | EW64, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg8e64ff.v", MATCH_VLE8FF_V | SEG(8) | EW64, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vle128.v", MATCH_VLE8_V | EW128, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vse128.v", MATCH_VSE8_V | EW128, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxei128.v", MATCH_VLUXEI8_V | EW128, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxei128.v", MATCH_VSUXEI8_V | EW128, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlse128.v", MATCH_VLSE8_V | EW128, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vsse128.v", MATCH_VSSE8_V | EW128, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxei128.v", MATCH_VLOXEI8_V | EW128, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxei128.v", MATCH_VSOXEI8_V | EW128, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vle128ff.v", MATCH_VLE8FF_V | EW128, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg2e128.v", MATCH_VLE8_V | SEG(2) | EW128, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg2e128.v", MATCH_VSE8_V | SEG(2) | EW128, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg2ei128.v", MATCH_VLUXEI8_V | SEG(2) | EW128, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg2ei128.v", MATCH_VSUXEI8_V | SEG(2) | EW128, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg2e128.v", MATCH_VLSE8_V | SEG(2) | EW128, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg2e128.v", MATCH_VSSE8_V | SEG(2) | EW128, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg2ei128.v", MATCH_VLOXEI8_V | SEG(2) | EW128, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg2ei128.v", MATCH_VSOXEI8_V | SEG(2) | EW128, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg2e128ff.v", MATCH_VLE8FF_V | SEG(2) | EW128, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg3e128.v", MATCH_VLE8_V | SEG(3) | EW128, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg3e128.v", MATCH_VSE8_V | SEG(3) | EW128, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg3ei128.v", MATCH_VLUXEI8_V | SEG(3) | EW128, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg3ei128.v", MATCH_VSUXEI8_V | SEG(3) | EW128, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg3e128.v", MATCH_VLSE8_V | SEG(3) | EW128, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg3e128.v", MATCH_VSSE8_V | SEG(3) | EW128, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg3ei128.v", MATCH_VLOXEI8_V | SEG(3) | EW128, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg3ei128.v", MATCH_VSOXEI8_V | SEG(3) | EW128, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg3e128ff.v", MATCH_VLE8FF_V | SEG(3) | EW128, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg4e128.v", MATCH_VLE8_V | SEG(4) | EW128, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg4e128.v", MATCH_VSE8_V | SEG(4) | EW128, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg4ei128.v", MATCH_VLUXEI8_V | SEG(4) | EW128, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg4ei128.v", MATCH_VSUXEI8_V | SEG(4) | EW128, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg4e128.v", MATCH_VLSE8_V | SEG(4) | EW128, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg4e128.v", MATCH_VSSE8_V | SEG(4) | EW128, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg4ei128.v", MATCH_VLOXEI8_V | SEG(4) | EW128, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg4ei128.v", MATCH_VSOXEI8_V | SEG(4) | EW128, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg4e128ff.v", MATCH_VLE8FF_V | SEG(4) | EW128, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg5e128.v", MATCH_VLE8_V | SEG(5) | EW128, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg5e128.v", MATCH_VSE8_V | SEG(5) | EW128, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg5ei128.v", MATCH_VLUXEI8_V | SEG(5) | EW128, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg5ei128.v", MATCH_VSUXEI8_V | SEG(5) | EW128, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg5e128.v", MATCH_VLSE8_V | SEG(5) | EW128, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg5e128.v", MATCH_VSSE8_V | SEG(5) | EW128, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg5ei128.v", MATCH_VLOXEI8_V | SEG(5) | EW128, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg5ei128.v", MATCH_VSOXEI8_V | SEG(5) | EW128, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg5e128ff.v", MATCH_VLE8FF_V | SEG(5) | EW128, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg6e128.v", MATCH_VLE8_V | SEG(6) | EW128, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg6e128.v", MATCH_VSE8_V | SEG(6) | EW128, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg6ei128.v", MATCH_VLUXEI8_V | SEG(6) | EW128, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg6ei128.v", MATCH_VSUXEI8_V | SEG(6) | EW128, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg6e128.v", MATCH_VLSE8_V | SEG(6) | EW128, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg6e128.v", MATCH_VSSE8_V | SEG(6) | EW128, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg6ei128.v", MATCH_VLOXEI8_V | SEG(6) | EW128, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg6ei128.v", MATCH_VSOXEI8_V | SEG(6) | EW128, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg6e128ff.v", MATCH_VLE8FF_V | SEG(6) | EW128, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg7e128.v", MATCH_VLE8_V | SEG(7) | EW128, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg7e128.v", MATCH_VSE8_V | SEG(7) | EW128, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg7ei128.v", MATCH_VLUXEI8_V | SEG(7) | EW128, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg7ei128.v", MATCH_VSUXEI8_V | SEG(7) | EW128, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg7e128.v", MATCH_VLSE8_V | SEG(7) | EW128, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg7e128.v", MATCH_VSSE8_V | SEG(7) | EW128, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg7ei128.v", MATCH_VLOXEI8_V | SEG(7) | EW128, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg7ei128.v", MATCH_VSOXEI8_V | SEG(7) | EW128, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg7e128ff.v", MATCH_VLE8FF_V | SEG(7) | EW128, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg8e128.v", MATCH_VLE8_V | SEG(8) | EW128, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg8e128.v", MATCH_VSE8_V | SEG(8) | EW128, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg8ei128.v", MATCH_VLUXEI8_V | SEG(8) | EW128, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg8ei128.v", MATCH_VSUXEI8_V | SEG(8) | EW128, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg8e128.v", MATCH_VLSE8_V | SEG(8) | EW128, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg8e128.v", MATCH_VSSE8_V | SEG(8) | EW128, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg8ei128.v", MATCH_VLOXEI8_V | SEG(8) | EW128, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg8ei128.v", MATCH_VSOXEI8_V | SEG(8) | EW128, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg8e128ff.v", MATCH_VLE8FF_V | SEG(8) | EW128, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vle256.v", MATCH_VLE8_V | EW256, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vse256.v", MATCH_VSE8_V | EW256, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxei256.v", MATCH_VLUXEI8_V | EW256, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxei256.v", MATCH_VSUXEI8_V | EW256, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlse256.v", MATCH_VLSE8_V | EW256, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vsse256.v", MATCH_VSSE8_V | EW256, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxei256.v", MATCH_VLOXEI8_V | EW256, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxei256.v", MATCH_VSOXEI8_V | EW256, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vle256ff.v", MATCH_VLE8FF_V | EW256, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg2e256.v", MATCH_VLE8_V | SEG(2) | EW256, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg2e256.v", MATCH_VSE8_V | SEG(2) | EW256, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg2ei256.v", MATCH_VLUXEI8_V | SEG(2) | EW256, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg2ei256.v", MATCH_VSUXEI8_V | SEG(2) | EW256, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg2e256.v", MATCH_VLSE8_V | SEG(2) | EW256, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg2e256.v", MATCH_VSSE8_V | SEG(2) | EW256, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg2ei256.v", MATCH_VLOXEI8_V | SEG(2) | EW256, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg2ei256.v", MATCH_VSOXEI8_V | SEG(2) | EW256, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg2e256ff.v", MATCH_VLE8FF_V | SEG(2) | EW256, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg3e256.v", MATCH_VLE8_V | SEG(3) | EW256, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg3e256.v", MATCH_VSE8_V | SEG(3) | EW256, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg3ei256.v", MATCH_VLUXEI8_V | SEG(3) | EW256, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg3ei256.v", MATCH_VSUXEI8_V | SEG(3) | EW256, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg3e256.v", MATCH_VLSE8_V | SEG(3) | EW256, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg3e256.v", MATCH_VSSE8_V | SEG(3) | EW256, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg3ei256.v", MATCH_VLOXEI8_V | SEG(3) | EW256, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg3ei256.v", MATCH_VSOXEI8_V | SEG(3) | EW256, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg3e256ff.v", MATCH_VLE8FF_V | SEG(3) | EW256, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg4e256.v", MATCH_VLE8_V | SEG(4) | EW256, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg4e256.v", MATCH_VSE8_V | SEG(4) | EW256, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg4ei256.v", MATCH_VLUXEI8_V | SEG(4) | EW256, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg4ei256.v", MATCH_VSUXEI8_V | SEG(4) | EW256, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg4e256.v", MATCH_VLSE8_V | SEG(4) | EW256, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg4e256.v", MATCH_VSSE8_V | SEG(4) | EW256, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg4ei256.v", MATCH_VLOXEI8_V | SEG(4) | EW256, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg4ei256.v", MATCH_VSOXEI8_V | SEG(4) | EW256, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg4e256ff.v", MATCH_VLE8FF_V | SEG(4) | EW256, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg5e256.v", MATCH_VLE8_V | SEG(5) | EW256, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg5e256.v", MATCH_VSE8_V | SEG(5) | EW256, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg5ei256.v", MATCH_VLUXEI8_V | SEG(5) | EW256, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg5ei256.v", MATCH_VSUXEI8_V | SEG(5) | EW256, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg5e256.v", MATCH_VLSE8_V | SEG(5) | EW256, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg5e256.v", MATCH_VSSE8_V | SEG(5) | EW256, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg5ei256.v", MATCH_VLOXEI8_V | SEG(5) | EW256, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg5ei256.v", MATCH_VSOXEI8_V | SEG(5) | EW256, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg5e256ff.v", MATCH_VLE8FF_V | SEG(5) | EW256, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg6e256.v", MATCH_VLE8_V | SEG(6) | EW256, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg6e256.v", MATCH_VSE8_V | SEG(6) | EW256, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg6ei256.v", MATCH_VLUXEI8_V | SEG(6) | EW256, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg6ei256.v", MATCH_VSUXEI8_V | SEG(6) | EW256, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg6e256.v", MATCH_VLSE8_V | SEG(6) | EW256, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg6e256.v", MATCH_VSSE8_V | SEG(6) | EW256, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg6ei256.v", MATCH_VLOXEI8_V | SEG(6) | EW256, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg6ei256.v", MATCH_VSOXEI8_V | SEG(6) | EW256, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg6e256ff.v", MATCH_VLE8FF_V | SEG(6) | EW256, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg7e256.v", MATCH_VLE8_V | SEG(7) | EW256, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg7e256.v", MATCH_VSE8_V | SEG(7) | EW256, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg7ei256.v", MATCH_VLUXEI8_V | SEG(7) | EW256, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg7ei256.v", MATCH_VSUXEI8_V | SEG(7) | EW256, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg7e256.v", MATCH_VLSE8_V | SEG(7) | EW256, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg7e256.v", MATCH_VSSE8_V | SEG(7) | EW256, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg7ei256.v", MATCH_VLOXEI8_V | SEG(7) | EW256, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg7ei256.v", MATCH_VSOXEI8_V | SEG(7) | EW256, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg7e256ff.v", MATCH_VLE8FF_V | SEG(7) | EW256, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg8e256.v", MATCH_VLE8_V | SEG(8) | EW256, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg8e256.v", MATCH_VSE8_V | SEG(8) | EW256, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg8ei256.v", MATCH_VLUXEI8_V | SEG(8) | EW256, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg8ei256.v", MATCH_VSUXEI8_V | SEG(8) | EW256, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg8e256.v", MATCH_VLSE8_V | SEG(8) | EW256, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg8e256.v", MATCH_VSSE8_V | SEG(8) | EW256, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg8ei256.v", MATCH_VLOXEI8_V | SEG(8) | EW256, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg8ei256.v", MATCH_VSOXEI8_V | SEG(8) | EW256, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg8e256ff.v", MATCH_VLE8FF_V | SEG(8) | EW256, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vle512.v", MATCH_VLE8_V | EW512, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vse512.v", MATCH_VSE8_V | EW512, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxei512.v", MATCH_VLUXEI8_V | EW512, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxei512.v", MATCH_VSUXEI8_V | EW512, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlse512.v", MATCH_VLSE8_V | EW512, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vsse512.v", MATCH_VSSE8_V | EW512, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxei512.v", MATCH_VLOXEI8_V | EW512, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxei512.v", MATCH_VSOXEI8_V | EW512, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vle512ff.v", MATCH_VLE8FF_V | EW512, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg2e512.v", MATCH_VLE8_V | SEG(2) | EW512, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg2e512.v", MATCH_VSE8_V | SEG(2) | EW512, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg2ei512.v", MATCH_VLUXEI8_V | SEG(2) | EW512, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg2ei512.v", MATCH_VSUXEI8_V | SEG(2) | EW512, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg2e512.v", MATCH_VLSE8_V | SEG(2) | EW512, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg2e512.v", MATCH_VSSE8_V | SEG(2) | EW512, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg2ei512.v", MATCH_VLOXEI8_V | SEG(2) | EW512, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg2ei512.v", MATCH_VSOXEI8_V | SEG(2) | EW512, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg2e512ff.v", MATCH_VLE8FF_V | SEG(2) | EW512, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg3e512.v", MATCH_VLE8_V | SEG(3) | EW512, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg3e512.v", MATCH_VSE8_V | SEG(3) | EW512, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg3ei512.v", MATCH_VLUXEI8_V | SEG(3) | EW512, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg3ei512.v", MATCH_VSUXEI8_V | SEG(3) | EW512, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg3e512.v", MATCH_VLSE8_V | SEG(3) | EW512, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg3e512.v", MATCH_VSSE8_V | SEG(3) | EW512, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg3ei512.v", MATCH_VLOXEI8_V | SEG(3) | EW512, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg3ei512.v", MATCH_VSOXEI8_V | SEG(3) | EW512, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg3e512ff.v", MATCH_VLE8FF_V | SEG(3) | EW512, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg4e512.v", MATCH_VLE8_V | SEG(4) | EW512, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg4e512.v", MATCH_VSE8_V | SEG(4) | EW512, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg4ei512.v", MATCH_VLUXEI8_V | SEG(4) | EW512, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg4ei512.v", MATCH_VSUXEI8_V | SEG(4) | EW512, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg4e512.v", MATCH_VLSE8_V | SEG(4) | EW512, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg4e512.v", MATCH_VSSE8_V | SEG(4) | EW512, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg4ei512.v", MATCH_VLOXEI8_V | SEG(4) | EW512, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg4ei512.v", MATCH_VSOXEI8_V | SEG(4) | EW512, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg4e512ff.v", MATCH_VLE8FF_V | SEG(4) | EW512, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg5e512.v", MATCH_VLE8_V | SEG(5) | EW512, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg5e512.v", MATCH_VSE8_V | SEG(5) | EW512, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg5ei512.v", MATCH_VLUXEI8_V | SEG(5) | EW512, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg5ei512.v", MATCH_VSUXEI8_V | SEG(5) | EW512, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg5e512.v", MATCH_VLSE8_V | SEG(5) | EW512, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg5e512.v", MATCH_VSSE8_V | SEG(5) | EW512, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg5ei512.v", MATCH_VLOXEI8_V | SEG(5) | EW512, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg5ei512.v", MATCH_VSOXEI8_V | SEG(5) | EW512, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg5e512ff.v", MATCH_VLE8FF_V | SEG(5) | EW512, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg6e512.v", MATCH_VLE8_V | SEG(6) | EW512, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg6e512.v", MATCH_VSE8_V | SEG(6) | EW512, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg6ei512.v", MATCH_VLUXEI8_V | SEG(6) | EW512, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg6ei512.v", MATCH_VSUXEI8_V | SEG(6) | EW512, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg6e512.v", MATCH_VLSE8_V | SEG(6) | EW512, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg6e512.v", MATCH_VSSE8_V | SEG(6) | EW512, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg6ei512.v", MATCH_VLOXEI8_V | SEG(6) | EW512, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg6ei512.v", MATCH_VSOXEI8_V | SEG(6) | EW512, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg6e512ff.v", MATCH_VLE8FF_V | SEG(6) | EW512, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg7e512.v", MATCH_VLE8_V | SEG(7) | EW512, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg7e512.v", MATCH_VSE8_V | SEG(7) | EW512, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg7ei512.v", MATCH_VLUXEI8_V | SEG(7) | EW512, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg7ei512.v", MATCH_VSUXEI8_V | SEG(7) | EW512, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg7e512.v", MATCH_VLSE8_V | SEG(7) | EW512, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg7e512.v", MATCH_VSSE8_V | SEG(7) | EW512, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg7ei512.v", MATCH_VLOXEI8_V | SEG(7) | EW512, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg7ei512.v", MATCH_VSOXEI8_V | SEG(7) | EW512, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg7e512ff.v", MATCH_VLE8FF_V | SEG(7) | EW512, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg8e512.v", MATCH_VLE8_V | SEG(8) | EW512, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg8e512.v", MATCH_VSE8_V | SEG(8) | EW512, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg8ei512.v", MATCH_VLUXEI8_V | SEG(8) | EW512, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg8ei512.v", MATCH_VSUXEI8_V | SEG(8) | EW512, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg8e512.v", MATCH_VLSE8_V | SEG(8) | EW512, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg8e512.v", MATCH_VSSE8_V | SEG(8) | EW512, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg8ei512.v", MATCH_VLOXEI8_V | SEG(8) | EW512, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg8ei512.v", MATCH_VSOXEI8_V | SEG(8) | EW512, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg8e512ff.v", MATCH_VLE8FF_V | SEG(8) | EW512, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vle1024.v", MATCH_VLE8_V | EW1024, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vse1024.v", MATCH_VSE8_V | EW1024, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxei1024.v", MATCH_VLUXEI8_V | EW1024, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxei1024.v", MATCH_VSUXEI8_V | EW1024, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlse1024.v", MATCH_VLSE8_V | EW1024, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vsse1024.v", MATCH_VSSE8_V | EW1024, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxei1024.v", MATCH_VLOXEI8_V | EW1024, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxei1024.v", MATCH_VSOXEI8_V | EW1024, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vle1024ff.v", MATCH_VLE8FF_V | EW1024, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg2e1024.v", MATCH_VLE8_V | SEG(2) | EW1024, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg2e1024.v", MATCH_VSE8_V | SEG(2) | EW1024, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg2ei1024.v", MATCH_VLUXEI8_V | SEG(2) | EW1024, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg2ei1024.v", MATCH_VSUXEI8_V | SEG(2) | EW1024, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg2e1024.v", MATCH_VLSE8_V | SEG(2) | EW1024, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg2e1024.v", MATCH_VSSE8_V | SEG(2) | EW1024, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg2ei1024.v", MATCH_VLOXEI8_V | SEG(2) | EW1024, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg2ei1024.v", MATCH_VSOXEI8_V | SEG(2) | EW1024, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg2e1024ff.v", MATCH_VLE8FF_V | SEG(2) | EW1024, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg3e1024.v", MATCH_VLE8_V | SEG(3) | EW1024, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg3e1024.v", MATCH_VSE8_V | SEG(3) | EW1024, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg3ei1024.v", MATCH_VLUXEI8_V | SEG(3) | EW1024, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg3ei1024.v", MATCH_VSUXEI8_V | SEG(3) | EW1024, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg3e1024.v", MATCH_VLSE8_V | SEG(3) | EW1024, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg3e1024.v", MATCH_VSSE8_V | SEG(3) | EW1024, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg3ei1024.v", MATCH_VLOXEI8_V | SEG(3) | EW1024, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg3ei1024.v", MATCH_VSOXEI8_V | SEG(3) | EW1024, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg3e1024ff.v", MATCH_VLE8FF_V | SEG(3) | EW1024, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg4e1024.v", MATCH_VLE8_V | SEG(4) | EW1024, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg4e1024.v", MATCH_VSE8_V | SEG(4) | EW1024, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg4ei1024.v", MATCH_VLUXEI8_V | SEG(4) | EW1024, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg4ei1024.v", MATCH_VSUXEI8_V | SEG(4) | EW1024, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg4e1024.v", MATCH_VLSE8_V | SEG(4) | EW1024, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg4e1024.v", MATCH_VSSE8_V | SEG(4) | EW1024, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg4ei1024.v", MATCH_VLOXEI8_V | SEG(4) | EW1024, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg4ei1024.v", MATCH_VSOXEI8_V | SEG(4) | EW1024, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg4e1024ff.v", MATCH_VLE8FF_V | SEG(4) | EW1024, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg5e1024.v", MATCH_VLE8_V | SEG(5) | EW1024, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg5e1024.v", MATCH_VSE8_V | SEG(5) | EW1024, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg5ei1024.v", MATCH_VLUXEI8_V | SEG(5) | EW1024, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg5ei1024.v", MATCH_VSUXEI8_V | SEG(5) | EW1024, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg5e1024.v", MATCH_VLSE8_V | SEG(5) | EW1024, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg5e1024.v", MATCH_VSSE8_V | SEG(5) | EW1024, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg5ei1024.v", MATCH_VLOXEI8_V | SEG(5) | EW1024, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg5ei1024.v", MATCH_VSOXEI8_V | SEG(5) | EW1024, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg5e1024ff.v", MATCH_VLE8FF_V | SEG(5) | EW1024, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg6e1024.v", MATCH_VLE8_V | SEG(6) | EW1024, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg6e1024.v", MATCH_VSE8_V | SEG(6) | EW1024, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg6ei1024.v", MATCH_VLUXEI8_V | SEG(6) | EW1024, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg6ei1024.v", MATCH_VSUXEI8_V | SEG(6) | EW1024, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg6e1024.v", MATCH_VLSE8_V | SEG(6) | EW1024, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg6e1024.v", MATCH_VSSE8_V | SEG(6) | EW1024, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg6ei1024.v", MATCH_VLOXEI8_V | SEG(6) | EW1024, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg6ei1024.v", MATCH_VSOXEI8_V | SEG(6) | EW1024, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg6e1024ff.v", MATCH_VLE8FF_V | SEG(6) | EW1024, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg7e1024.v", MATCH_VLE8_V | SEG(7) | EW1024, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg7e1024.v", MATCH_VSE8_V | SEG(7) | EW1024, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg7ei1024.v", MATCH_VLUXEI8_V | SEG(7) | EW1024, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg7ei1024.v", MATCH_VSUXEI8_V | SEG(7) | EW1024, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg7e1024.v", MATCH_VLSE8_V | SEG(7) | EW1024, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg7e1024.v", MATCH_VSSE8_V | SEG(7) | EW1024, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg7ei1024.v", MATCH_VLOXEI8_V | SEG(7) | EW1024, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg7ei1024.v", MATCH_VSOXEI8_V | SEG(7) | EW1024, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg7e1024ff.v", MATCH_VLE8FF_V | SEG(7) | EW1024, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},
  {"vlseg8e1024.v", MATCH_VLE8_V | SEG(8) | EW1024, MASK_VLE8_V | MASK_NF, "A(?k", VECTOR},
  {"vsseg8e1024.v", MATCH_VSE8_V | SEG(8) | EW1024, MASK_VSE8_V | MASK_NF, "G(?k", VECTOR},
  {"vluxseg8ei1024.v", MATCH_VLUXEI8_V | SEG(8) | EW1024, MASK_VLUXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsuxseg8ei1024.v", MATCH_VSUXEI8_V | SEG(8) | EW1024, MASK_VSUXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlsseg8e1024.v", MATCH_VLSE8_V | SEG(8) | EW1024, MASK_VLSE8_V | MASK_NF, "A(t?k", VECTOR},
  {"vssseg8e1024.v", MATCH_VSSE8_V | SEG(8) | EW1024, MASK_VSSE8_V | MASK_NF, "G(t?k", VECTOR},
  {"vloxseg8ei1024.v", MATCH_VLOXEI8_V | SEG(8) | EW1024, MASK_VLOXEI8_V | MASK_NF, "A(C?k", VECTOR},
  {"vsoxseg8ei1024.v", MATCH_VSOXEI8_V | SEG(8) | EW1024, MASK_VSOXEI8_V | MASK_NF, "G(C?k", VECTOR},
  {"vlseg8e1024ff.v", MATCH_VLE8FF_V | SEG(8) | EW1024, MASK_VLE8FF_V | MASK_NF, "A(?k", VECTOR},

  // zcmop_insns
  {"c.mop.1",  MATCH_C_MOP_1,  MASK_C_MOP_1,  "", ZCMOP_NO_ZICFISS},
  {"c.mop.3",  MATCH_C_MOP_3,  MASK_C_MOP_3,  "", ZCMOP},
  {"c.mop.5",  MATCH_C_MOP_5,  MASK_C_MOP_5,  "", ZCMOP_NO_ZICFISS},
  {"c.mop.7",  MATCH_C_MOP_7,  MASK_C_MOP_7,  "", ZCMOP},
  {"c.mop.9",  MATCH_C_MOP_9,  MASK_C_MOP_9,  "", ZCMOP},
  {"c.mop.11", MATCH_C_MOP_11, MASK_C_MOP_11, "", ZCMOP},
  {"c.mop.13", MATCH_C_MOP_13, MASK_C_MOP_13, "", ZCMOP},
  {"c.mop.15", MATCH_C_MOP_15, MASK_C_MOP_15, "", ZCMOP},
  // scalar crypto: aes64ks1i, aes32 variants
  {"aes64ks1i", MATCH_AES64KS1I, MASK_AES64KS1I, "ds+", ZKND_OR_ZKNE},
  {"aes32dsi",  MATCH_AES32DSI,  MASK_AES32DSI,  "dst-", ZKND_RV32},
  {"aes32dsmi", MATCH_AES32DSMI, MASK_AES32DSMI, "dst-", ZKND_RV32},
  {"aes32esi",  MATCH_AES32ESI,  MASK_AES32ESI,  "dst-", ZKNE_RV32},
  {"aes32esmi", MATCH_AES32ESMI, MASK_AES32ESMI, "dst-", ZKNE_RV32},
};

void disassembler_t::add_instructions(const isa_parser_t* isa, bool strict)
{
  // Flat table iteration (like binutils riscv_opcodes[])
  for (const auto& op : all_insns)
    if (insn_class_enabled(op.cls, isa, strict))
      add_insn(new disasm_insn_t(op.name, op.match, op.mask, parse_fmt(op.fmt)));

}



disassembler_t::disassembler_t(const isa_parser_t *isa, bool strict)
{
  // highest priority: instructions explicitly enabled
  add_instructions(isa, true);

  if (!strict) {
    // non-strict: register all instructions regardless of configured ISA
    add_instructions(isa, false);
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

