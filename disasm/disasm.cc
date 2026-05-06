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
  zcmop,              // EXT_ZCMOP
  zcmop_no_zicfiss,   // EXT_ZCMOP + !EXT_ZICFISS_strict (those encodings reused by Zicfiss)
  zmmul,            zmmul_rv64,
  zicbom,           zicboz,   zicond,
  zknd_or_zkne,     // EXT_ZKND || EXT_ZKNE (for aes64ks1i/aes64ks2)
  zknd_rv64,        zkne_rv64,
  zknd_rv32,        // EXT_ZKND + xlen==32 (for aes32dsi/dsmi)
  zkne_rv32,        // EXT_ZKNE + xlen==32 (for aes32esi/esmi)
  zknh,             zknh_rv64,   zknh_rv32,
  zksed,            zksh,
  zalasr,
  zaamo,            // EXT_ZAAMO
  zaamo_rv64,       // EXT_ZAAMO + rv64
  zacas,            // EXT_ZACAS (amocas.w/d, any xlen)
  zabha,            // EXT_ZABHA
  zimop,            // EXT_ZIMOP
  vector,            // isa->has_any_vector() || !strict
  zvqdotq,
  zvfofp4min,  zvfofp8min,
  zvfbfmin,    zvfbfwma,
  zvabd,       zvzip,
  zvbb,        zvbc,
  zvkg,        zvkned,
  zvknh,       // EXT_ZVKNHA || EXT_ZVKNHB
  zvksed,      zvksh,
  zicfiss,
  zicfiss_rv64,     // EXT_ZICFISS + rv64 (for ssamoswap.d)
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
    case ic::zcmp:              return ext(EXT_ZCMP);
    case ic::zcmt:              return ext(EXT_ZCMT);
    case ic::zcmop:             return ext(EXT_ZCMOP);
    case ic::zcmop_no_zicfiss:  return ext(EXT_ZCMOP) && !isa->extension_enabled(EXT_ZICFISS);
    case ic::zmmul:             return ext(EXT_ZMMUL);
    case ic::zmmul_rv64:      return ext(EXT_ZMMUL)   && xv(64);
    case ic::zicbom:          return ext(EXT_ZICBOM);
    case ic::zicboz:          return ext(EXT_ZICBOZ);
    case ic::zicond:          return ext(EXT_ZICOND);
    case ic::zknd_or_zkne:    return isa->extension_enabled(EXT_ZKND) || isa->extension_enabled(EXT_ZKNE) || !s;
    case ic::zknd_rv64:       return ext(EXT_ZKND)    && xv(64);
    case ic::zkne_rv64:       return ext(EXT_ZKNE)    && xv(64);
    case ic::zknd_rv32:       return ext(EXT_ZKND)    && xv(32);
    case ic::zkne_rv32:       return ext(EXT_ZKNE)    && xv(32);
    case ic::zaamo:           return ext(EXT_ZAAMO);
    case ic::zaamo_rv64:      return ext(EXT_ZAAMO)    && xv(64);
    case ic::zacas:           return ext(EXT_ZACAS);
    case ic::zabha:           return ext(EXT_ZABHA);
    case ic::zimop:           return ext(EXT_ZIMOP);
    case ic::zicfiss_rv64:    return ext(EXT_ZICFISS)  && xv(64);
    case ic::zknh:            return ext(EXT_ZKNH);
    case ic::zknh_rv64:       return ext(EXT_ZKNH)    && xv(64);
    case ic::zknh_rv32:       return ext(EXT_ZKNH)    && xv(32);
    case ic::zksed:           return ext(EXT_ZKSED);
    case ic::zksh:            return ext(EXT_ZKSH);
    case ic::zalasr:          return ext(EXT_ZALASR);
    case ic::vector:          return isa->has_any_vector() || !s;
    case ic::zvqdotq:         return ext(EXT_ZVQDOTQ);
    case ic::zvfofp4min:      return ext(EXT_ZVFOFP4MIN);
    case ic::zvfofp8min:      return ext(EXT_ZVFOFP8MIN);
    case ic::zvfbfmin:        return ext(EXT_ZVFBFMIN);
    case ic::zvfbfwma:        return ext(EXT_ZVFBFWMA);
    case ic::zvabd:           return ext(EXT_ZVABD);
    case ic::zvzip:           return ext(EXT_ZVZIP);
    case ic::zvbb:            return ext(EXT_ZVBB);
    case ic::zvbc:            return ext(EXT_ZVBC);
    case ic::zvkg:            return ext(EXT_ZVKG);
    case ic::zvkned:          return ext(EXT_ZVKNED);
    case ic::zvknh:           return isa->extension_enabled(EXT_ZVKNHA) || isa->extension_enabled(EXT_ZVKNHB) || !s;
    case ic::zvksed:          return ext(EXT_ZVKSED);
    case ic::zvksh:           return ext(EXT_ZVKSH);
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

// Register-field match constants: encode a specific register number into a field.
static constexpr uint32_t MATCH_RD_RA  = 1U << 7;   // rd = x1 (ra)
static constexpr uint32_t MATCH_RS1_RA = 1U << 15;  // rs1 = x1 (ra)

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
  {"unimp",   uint32_t(MATCH_CSRRW|(CSR_CYCLE<<20)), 0xffffffff,  "", always},
  {"c.unimp", 0,                           0xffff,                "", always},
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
  {"j",    MATCH_JAL,              MASK_JAL | MASK_RD,             "a", always},
  {"jal",  MATCH_JAL | MATCH_RD_RA,     MASK_JAL | MASK_RD,             "a", always},
  {"jal",  MATCH_JAL,             MASK_JAL,                       "da", always},
  {"ret",  MATCH_JALR | MATCH_RS1_RA,  MASK_JALR | MASK_RD | MASK_RS1 | MASK_IMM, "", always},
  {"jr",   MATCH_JALR,            MASK_JALR | MASK_RD | MASK_IMM, "s", always},
  {"jalr", MATCH_JALR | MATCH_RD_RA,   MASK_JALR | MASK_RD | MASK_IMM, "s", always},
  {"jalr", MATCH_JALR,            MASK_JALR,                        "dsj", always},
  // branch_insns
  {"beqz", MATCH_BEQ, MASK_BEQ | MASK_RS2, "sp", always},
  {"bnez", MATCH_BNE, MASK_BNE | MASK_RS2, "sp", always},
  {"bltz", MATCH_BLT, MASK_BLT | MASK_RS2, "sp", always},
  {"bgez", MATCH_BGE, MASK_BGE | MASK_RS2, "sp", always},
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
  {"nop",  MATCH_ADDI, MASK_ADDI | MASK_RD | MASK_RS1 | MASK_IMM, "", always},
  // li: addi rd, x0, imm  (mask_rs1 = 0xf8000 locks rs1=0)
  {"li",   MATCH_ADDI, MASK_ADDI | MASK_RS1, "dj", always},
  // mv: addi rd, rs1, 0  (mask_imm locks imm=0)
  {"mv",   MATCH_ADDI, MASK_ADDI | MASK_IMM, "ds", always},
  {"addi", MATCH_ADDI, MASK_ADDI, "dsj", always},
  {"slti", MATCH_SLTI, MASK_SLTI, "dsj", always},
  // seqz: sltiu rd, rs1, 1
  {"seqz", MATCH_SLTIU | (1u << 20), MASK_SLTIU | MASK_IMM, "ds", always},
  {"sltiu", MATCH_SLTIU, MASK_SLTIU, "dsj", always},
  // not: xori rd, rs1, -1  (imm=0xfff=-1)
  {"not",  MATCH_XORI | MASK_IMM, MASK_XORI | MASK_IMM, "ds", always},
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
  {"snez", MATCH_SLTU, MASK_SLTU | MASK_RS1, "dt", always},
  {"sltu", MATCH_SLTU, MASK_SLTU, "dst", always},
  {"xor",  MATCH_XOR,  MASK_XOR,  "dst", always},
  {"srl",  MATCH_SRL,  MASK_SRL,  "dst", always},
  {"sra",  MATCH_SRA,  MASK_SRA,  "dst", always},
  {"or",   MATCH_OR,   MASK_OR,   "dst", always},
  {"and",  MATCH_AND,  MASK_AND,  "dst", always},
  // rv64_int_insns
  // sext.w: addiw rd, rs1, 0
  {"sext.w", MATCH_ADDIW, MASK_ADDIW | MASK_IMM, "ds", rv64},
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
  {"csrr",  MATCH_CSRRS,  MASK_CSRRS  | MASK_RS1,    "dE", always},
  {"csrw",  MATCH_CSRRW,  MASK_CSRRW  | MASK_RD,      "Es", always},
  {"csrs",  MATCH_CSRRS,  MASK_CSRRS  | MASK_RD,      "Es", always},
  {"csrc",  MATCH_CSRRC,  MASK_CSRRC  | MASK_RD,      "Es", always},
  {"csrwi", MATCH_CSRRWI, MASK_CSRRWI | MASK_RD,      "Ez", always},
  {"csrsi", MATCH_CSRRSI, MASK_CSRRSI | MASK_RD,      "Ez", always},
  {"csrci", MATCH_CSRRCI, MASK_CSRRCI | MASK_RD,      "Ez", always},
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
  {"zext.w",  MATCH_ADD_UW, MASK_ADD_UW | MASK_RS2, "ds", zba_rv64},
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
  {"c.ebreak",   MATCH_C_ADD,  MASK_C_ADD | MASK_RD | MASK_CRS2,         "", zca},
  {"ret",        MATCH_C_JR  | 0x80u, MASK_C_JR | MASK_RD | MASK_CNZIMM6, "", zca},
  {"c.jr",       MATCH_C_JR,   MASK_C_JR  | MASK_CNZIMM6,                "e", zca},
  {"c.jalr",     MATCH_C_JALR, MASK_C_JALR | MASK_CNZIMM6,               "e", zca},
  {"c.nop",      MATCH_C_ADDI, MASK_C_ADDI | MASK_RD | MASK_CNZIMM6,      "", zca},
  {"c.addi16sp", MATCH_C_ADDI16SP, MASK_C_ADDI16SP | MASK_RD,        "Nx", zca},
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

  // AMO instructions (4 variants: base/.rl/.aq/.aqrl)
  // zaamo
  {"amoadd_w", MATCH_AMOADD_W, MASK_AMOADD_W | (3<<25), "dt(", zaamo},
  {"amoadd_w_rl", MATCH_AMOADD_W | (1<<25), MASK_AMOADD_W | (3<<25), "dt(", zaamo},
  {"amoadd_w_aq", MATCH_AMOADD_W | (2<<25), MASK_AMOADD_W | (3<<25), "dt(", zaamo},
  {"amoadd_w_aqrl", MATCH_AMOADD_W | (3<<25), MASK_AMOADD_W | (3<<25), "dt(", zaamo},
  {"amoswap_w", MATCH_AMOSWAP_W, MASK_AMOSWAP_W | (3<<25), "dt(", zaamo},
  {"amoswap_w_rl", MATCH_AMOSWAP_W | (1<<25), MASK_AMOSWAP_W | (3<<25), "dt(", zaamo},
  {"amoswap_w_aq", MATCH_AMOSWAP_W | (2<<25), MASK_AMOSWAP_W | (3<<25), "dt(", zaamo},
  {"amoswap_w_aqrl", MATCH_AMOSWAP_W | (3<<25), MASK_AMOSWAP_W | (3<<25), "dt(", zaamo},
  {"amoand_w", MATCH_AMOAND_W, MASK_AMOAND_W | (3<<25), "dt(", zaamo},
  {"amoand_w_rl", MATCH_AMOAND_W | (1<<25), MASK_AMOAND_W | (3<<25), "dt(", zaamo},
  {"amoand_w_aq", MATCH_AMOAND_W | (2<<25), MASK_AMOAND_W | (3<<25), "dt(", zaamo},
  {"amoand_w_aqrl", MATCH_AMOAND_W | (3<<25), MASK_AMOAND_W | (3<<25), "dt(", zaamo},
  {"amoor_w", MATCH_AMOOR_W, MASK_AMOOR_W | (3<<25), "dt(", zaamo},
  {"amoor_w_rl", MATCH_AMOOR_W | (1<<25), MASK_AMOOR_W | (3<<25), "dt(", zaamo},
  {"amoor_w_aq", MATCH_AMOOR_W | (2<<25), MASK_AMOOR_W | (3<<25), "dt(", zaamo},
  {"amoor_w_aqrl", MATCH_AMOOR_W | (3<<25), MASK_AMOOR_W | (3<<25), "dt(", zaamo},
  {"amoxor_w", MATCH_AMOXOR_W, MASK_AMOXOR_W | (3<<25), "dt(", zaamo},
  {"amoxor_w_rl", MATCH_AMOXOR_W | (1<<25), MASK_AMOXOR_W | (3<<25), "dt(", zaamo},
  {"amoxor_w_aq", MATCH_AMOXOR_W | (2<<25), MASK_AMOXOR_W | (3<<25), "dt(", zaamo},
  {"amoxor_w_aqrl", MATCH_AMOXOR_W | (3<<25), MASK_AMOXOR_W | (3<<25), "dt(", zaamo},
  {"amomin_w", MATCH_AMOMIN_W, MASK_AMOMIN_W | (3<<25), "dt(", zaamo},
  {"amomin_w_rl", MATCH_AMOMIN_W | (1<<25), MASK_AMOMIN_W | (3<<25), "dt(", zaamo},
  {"amomin_w_aq", MATCH_AMOMIN_W | (2<<25), MASK_AMOMIN_W | (3<<25), "dt(", zaamo},
  {"amomin_w_aqrl", MATCH_AMOMIN_W | (3<<25), MASK_AMOMIN_W | (3<<25), "dt(", zaamo},
  {"amomax_w", MATCH_AMOMAX_W, MASK_AMOMAX_W | (3<<25), "dt(", zaamo},
  {"amomax_w_rl", MATCH_AMOMAX_W | (1<<25), MASK_AMOMAX_W | (3<<25), "dt(", zaamo},
  {"amomax_w_aq", MATCH_AMOMAX_W | (2<<25), MASK_AMOMAX_W | (3<<25), "dt(", zaamo},
  {"amomax_w_aqrl", MATCH_AMOMAX_W | (3<<25), MASK_AMOMAX_W | (3<<25), "dt(", zaamo},
  {"amominu_w", MATCH_AMOMINU_W, MASK_AMOMINU_W | (3<<25), "dt(", zaamo},
  {"amominu_w_rl", MATCH_AMOMINU_W | (1<<25), MASK_AMOMINU_W | (3<<25), "dt(", zaamo},
  {"amominu_w_aq", MATCH_AMOMINU_W | (2<<25), MASK_AMOMINU_W | (3<<25), "dt(", zaamo},
  {"amominu_w_aqrl", MATCH_AMOMINU_W | (3<<25), MASK_AMOMINU_W | (3<<25), "dt(", zaamo},
  {"amomaxu_w", MATCH_AMOMAXU_W, MASK_AMOMAXU_W | (3<<25), "dt(", zaamo},
  {"amomaxu_w_rl", MATCH_AMOMAXU_W | (1<<25), MASK_AMOMAXU_W | (3<<25), "dt(", zaamo},
  {"amomaxu_w_aq", MATCH_AMOMAXU_W | (2<<25), MASK_AMOMAXU_W | (3<<25), "dt(", zaamo},
  {"amomaxu_w_aqrl", MATCH_AMOMAXU_W | (3<<25), MASK_AMOMAXU_W | (3<<25), "dt(", zaamo},
  // zaamo rv64
  {"amoadd_d", MATCH_AMOADD_D, MASK_AMOADD_D | (3<<25), "dt(", zaamo_rv64},
  {"amoadd_d_rl", MATCH_AMOADD_D | (1<<25), MASK_AMOADD_D | (3<<25), "dt(", zaamo_rv64},
  {"amoadd_d_aq", MATCH_AMOADD_D | (2<<25), MASK_AMOADD_D | (3<<25), "dt(", zaamo_rv64},
  {"amoadd_d_aqrl", MATCH_AMOADD_D | (3<<25), MASK_AMOADD_D | (3<<25), "dt(", zaamo_rv64},
  {"amoswap_d", MATCH_AMOSWAP_D, MASK_AMOSWAP_D | (3<<25), "dt(", zaamo_rv64},
  {"amoswap_d_rl", MATCH_AMOSWAP_D | (1<<25), MASK_AMOSWAP_D | (3<<25), "dt(", zaamo_rv64},
  {"amoswap_d_aq", MATCH_AMOSWAP_D | (2<<25), MASK_AMOSWAP_D | (3<<25), "dt(", zaamo_rv64},
  {"amoswap_d_aqrl", MATCH_AMOSWAP_D | (3<<25), MASK_AMOSWAP_D | (3<<25), "dt(", zaamo_rv64},
  {"amoand_d", MATCH_AMOAND_D, MASK_AMOAND_D | (3<<25), "dt(", zaamo_rv64},
  {"amoand_d_rl", MATCH_AMOAND_D | (1<<25), MASK_AMOAND_D | (3<<25), "dt(", zaamo_rv64},
  {"amoand_d_aq", MATCH_AMOAND_D | (2<<25), MASK_AMOAND_D | (3<<25), "dt(", zaamo_rv64},
  {"amoand_d_aqrl", MATCH_AMOAND_D | (3<<25), MASK_AMOAND_D | (3<<25), "dt(", zaamo_rv64},
  {"amoor_d", MATCH_AMOOR_D, MASK_AMOOR_D | (3<<25), "dt(", zaamo_rv64},
  {"amoor_d_rl", MATCH_AMOOR_D | (1<<25), MASK_AMOOR_D | (3<<25), "dt(", zaamo_rv64},
  {"amoor_d_aq", MATCH_AMOOR_D | (2<<25), MASK_AMOOR_D | (3<<25), "dt(", zaamo_rv64},
  {"amoor_d_aqrl", MATCH_AMOOR_D | (3<<25), MASK_AMOOR_D | (3<<25), "dt(", zaamo_rv64},
  {"amoxor_d", MATCH_AMOXOR_D, MASK_AMOXOR_D | (3<<25), "dt(", zaamo_rv64},
  {"amoxor_d_rl", MATCH_AMOXOR_D | (1<<25), MASK_AMOXOR_D | (3<<25), "dt(", zaamo_rv64},
  {"amoxor_d_aq", MATCH_AMOXOR_D | (2<<25), MASK_AMOXOR_D | (3<<25), "dt(", zaamo_rv64},
  {"amoxor_d_aqrl", MATCH_AMOXOR_D | (3<<25), MASK_AMOXOR_D | (3<<25), "dt(", zaamo_rv64},
  {"amomin_d", MATCH_AMOMIN_D, MASK_AMOMIN_D | (3<<25), "dt(", zaamo_rv64},
  {"amomin_d_rl", MATCH_AMOMIN_D | (1<<25), MASK_AMOMIN_D | (3<<25), "dt(", zaamo_rv64},
  {"amomin_d_aq", MATCH_AMOMIN_D | (2<<25), MASK_AMOMIN_D | (3<<25), "dt(", zaamo_rv64},
  {"amomin_d_aqrl", MATCH_AMOMIN_D | (3<<25), MASK_AMOMIN_D | (3<<25), "dt(", zaamo_rv64},
  {"amomax_d", MATCH_AMOMAX_D, MASK_AMOMAX_D | (3<<25), "dt(", zaamo_rv64},
  {"amomax_d_rl", MATCH_AMOMAX_D | (1<<25), MASK_AMOMAX_D | (3<<25), "dt(", zaamo_rv64},
  {"amomax_d_aq", MATCH_AMOMAX_D | (2<<25), MASK_AMOMAX_D | (3<<25), "dt(", zaamo_rv64},
  {"amomax_d_aqrl", MATCH_AMOMAX_D | (3<<25), MASK_AMOMAX_D | (3<<25), "dt(", zaamo_rv64},
  {"amominu_d", MATCH_AMOMINU_D, MASK_AMOMINU_D | (3<<25), "dt(", zaamo_rv64},
  {"amominu_d_rl", MATCH_AMOMINU_D | (1<<25), MASK_AMOMINU_D | (3<<25), "dt(", zaamo_rv64},
  {"amominu_d_aq", MATCH_AMOMINU_D | (2<<25), MASK_AMOMINU_D | (3<<25), "dt(", zaamo_rv64},
  {"amominu_d_aqrl", MATCH_AMOMINU_D | (3<<25), MASK_AMOMINU_D | (3<<25), "dt(", zaamo_rv64},
  {"amomaxu_d", MATCH_AMOMAXU_D, MASK_AMOMAXU_D | (3<<25), "dt(", zaamo_rv64},
  {"amomaxu_d_rl", MATCH_AMOMAXU_D | (1<<25), MASK_AMOMAXU_D | (3<<25), "dt(", zaamo_rv64},
  {"amomaxu_d_aq", MATCH_AMOMAXU_D | (2<<25), MASK_AMOMAXU_D | (3<<25), "dt(", zaamo_rv64},
  {"amomaxu_d_aqrl", MATCH_AMOMAXU_D | (3<<25), MASK_AMOMAXU_D | (3<<25), "dt(", zaamo_rv64},
  // zalrsc
  {"lr_w", MATCH_LR_W, MASK_LR_W | (3<<25), "d(", zalrsc},
  {"lr_w_rl", MATCH_LR_W | (1<<25), MASK_LR_W | (3<<25), "d(", zalrsc},
  {"lr_w_aq", MATCH_LR_W | (2<<25), MASK_LR_W | (3<<25), "d(", zalrsc},
  {"lr_w_aqrl", MATCH_LR_W | (3<<25), MASK_LR_W | (3<<25), "d(", zalrsc},
  {"sc_w", MATCH_SC_W, MASK_SC_W | (3<<25), "dt(", zalrsc},
  {"sc_w_rl", MATCH_SC_W | (1<<25), MASK_SC_W | (3<<25), "dt(", zalrsc},
  {"sc_w_aq", MATCH_SC_W | (2<<25), MASK_SC_W | (3<<25), "dt(", zalrsc},
  {"sc_w_aqrl", MATCH_SC_W | (3<<25), MASK_SC_W | (3<<25), "dt(", zalrsc},
  // zalrsc rv64
  {"lr_d", MATCH_LR_D, MASK_LR_D | (3<<25), "d(", zalrsc_rv64},
  {"lr_d_rl", MATCH_LR_D | (1<<25), MASK_LR_D | (3<<25), "d(", zalrsc_rv64},
  {"lr_d_aq", MATCH_LR_D | (2<<25), MASK_LR_D | (3<<25), "d(", zalrsc_rv64},
  {"lr_d_aqrl", MATCH_LR_D | (3<<25), MASK_LR_D | (3<<25), "d(", zalrsc_rv64},
  {"sc_d", MATCH_SC_D, MASK_SC_D | (3<<25), "dt(", zalrsc_rv64},
  {"sc_d_rl", MATCH_SC_D | (1<<25), MASK_SC_D | (3<<25), "dt(", zalrsc_rv64},
  {"sc_d_aq", MATCH_SC_D | (2<<25), MASK_SC_D | (3<<25), "dt(", zalrsc_rv64},
  {"sc_d_aqrl", MATCH_SC_D | (3<<25), MASK_SC_D | (3<<25), "dt(", zalrsc_rv64},
  // zacas
  {"amocas_w", MATCH_AMOCAS_W, MASK_AMOCAS_W | (3<<25), "dt(", zacas},
  {"amocas_w_rl", MATCH_AMOCAS_W | (1<<25), MASK_AMOCAS_W | (3<<25), "dt(", zacas},
  {"amocas_w_aq", MATCH_AMOCAS_W | (2<<25), MASK_AMOCAS_W | (3<<25), "dt(", zacas},
  {"amocas_w_aqrl", MATCH_AMOCAS_W | (3<<25), MASK_AMOCAS_W | (3<<25), "dt(", zacas},
  {"amocas_d", MATCH_AMOCAS_D, MASK_AMOCAS_D | (3<<25), "dt(", zacas},
  {"amocas_d_rl", MATCH_AMOCAS_D | (1<<25), MASK_AMOCAS_D | (3<<25), "dt(", zacas},
  {"amocas_d_aq", MATCH_AMOCAS_D | (2<<25), MASK_AMOCAS_D | (3<<25), "dt(", zacas},
  {"amocas_d_aqrl", MATCH_AMOCAS_D | (3<<25), MASK_AMOCAS_D | (3<<25), "dt(", zacas},
  {"amocas_q", MATCH_AMOCAS_Q, MASK_AMOCAS_Q | (3<<25), "dt(", zacas_rv64},
  {"amocas_q_rl", MATCH_AMOCAS_Q | (1<<25), MASK_AMOCAS_Q | (3<<25), "dt(", zacas_rv64},
  {"amocas_q_aq", MATCH_AMOCAS_Q | (2<<25), MASK_AMOCAS_Q | (3<<25), "dt(", zacas_rv64},
  {"amocas_q_aqrl", MATCH_AMOCAS_Q | (3<<25), MASK_AMOCAS_Q | (3<<25), "dt(", zacas_rv64},
  // zabha
  {"amoadd_b", MATCH_AMOADD_B, MASK_AMOADD_B | (3<<25), "dt(", zabha},
  {"amoadd_b_rl", MATCH_AMOADD_B | (1<<25), MASK_AMOADD_B | (3<<25), "dt(", zabha},
  {"amoadd_b_aq", MATCH_AMOADD_B | (2<<25), MASK_AMOADD_B | (3<<25), "dt(", zabha},
  {"amoadd_b_aqrl", MATCH_AMOADD_B | (3<<25), MASK_AMOADD_B | (3<<25), "dt(", zabha},
  {"amoswap_b", MATCH_AMOSWAP_B, MASK_AMOSWAP_B | (3<<25), "dt(", zabha},
  {"amoswap_b_rl", MATCH_AMOSWAP_B | (1<<25), MASK_AMOSWAP_B | (3<<25), "dt(", zabha},
  {"amoswap_b_aq", MATCH_AMOSWAP_B | (2<<25), MASK_AMOSWAP_B | (3<<25), "dt(", zabha},
  {"amoswap_b_aqrl", MATCH_AMOSWAP_B | (3<<25), MASK_AMOSWAP_B | (3<<25), "dt(", zabha},
  {"amoand_b", MATCH_AMOAND_B, MASK_AMOAND_B | (3<<25), "dt(", zabha},
  {"amoand_b_rl", MATCH_AMOAND_B | (1<<25), MASK_AMOAND_B | (3<<25), "dt(", zabha},
  {"amoand_b_aq", MATCH_AMOAND_B | (2<<25), MASK_AMOAND_B | (3<<25), "dt(", zabha},
  {"amoand_b_aqrl", MATCH_AMOAND_B | (3<<25), MASK_AMOAND_B | (3<<25), "dt(", zabha},
  {"amoor_b", MATCH_AMOOR_B, MASK_AMOOR_B | (3<<25), "dt(", zabha},
  {"amoor_b_rl", MATCH_AMOOR_B | (1<<25), MASK_AMOOR_B | (3<<25), "dt(", zabha},
  {"amoor_b_aq", MATCH_AMOOR_B | (2<<25), MASK_AMOOR_B | (3<<25), "dt(", zabha},
  {"amoor_b_aqrl", MATCH_AMOOR_B | (3<<25), MASK_AMOOR_B | (3<<25), "dt(", zabha},
  {"amoxor_b", MATCH_AMOXOR_B, MASK_AMOXOR_B | (3<<25), "dt(", zabha},
  {"amoxor_b_rl", MATCH_AMOXOR_B | (1<<25), MASK_AMOXOR_B | (3<<25), "dt(", zabha},
  {"amoxor_b_aq", MATCH_AMOXOR_B | (2<<25), MASK_AMOXOR_B | (3<<25), "dt(", zabha},
  {"amoxor_b_aqrl", MATCH_AMOXOR_B | (3<<25), MASK_AMOXOR_B | (3<<25), "dt(", zabha},
  {"amomin_b", MATCH_AMOMIN_B, MASK_AMOMIN_B | (3<<25), "dt(", zabha},
  {"amomin_b_rl", MATCH_AMOMIN_B | (1<<25), MASK_AMOMIN_B | (3<<25), "dt(", zabha},
  {"amomin_b_aq", MATCH_AMOMIN_B | (2<<25), MASK_AMOMIN_B | (3<<25), "dt(", zabha},
  {"amomin_b_aqrl", MATCH_AMOMIN_B | (3<<25), MASK_AMOMIN_B | (3<<25), "dt(", zabha},
  {"amomax_b", MATCH_AMOMAX_B, MASK_AMOMAX_B | (3<<25), "dt(", zabha},
  {"amomax_b_rl", MATCH_AMOMAX_B | (1<<25), MASK_AMOMAX_B | (3<<25), "dt(", zabha},
  {"amomax_b_aq", MATCH_AMOMAX_B | (2<<25), MASK_AMOMAX_B | (3<<25), "dt(", zabha},
  {"amomax_b_aqrl", MATCH_AMOMAX_B | (3<<25), MASK_AMOMAX_B | (3<<25), "dt(", zabha},
  {"amominu_b", MATCH_AMOMINU_B, MASK_AMOMINU_B | (3<<25), "dt(", zabha},
  {"amominu_b_rl", MATCH_AMOMINU_B | (1<<25), MASK_AMOMINU_B | (3<<25), "dt(", zabha},
  {"amominu_b_aq", MATCH_AMOMINU_B | (2<<25), MASK_AMOMINU_B | (3<<25), "dt(", zabha},
  {"amominu_b_aqrl", MATCH_AMOMINU_B | (3<<25), MASK_AMOMINU_B | (3<<25), "dt(", zabha},
  {"amomaxu_b", MATCH_AMOMAXU_B, MASK_AMOMAXU_B | (3<<25), "dt(", zabha},
  {"amomaxu_b_rl", MATCH_AMOMAXU_B | (1<<25), MASK_AMOMAXU_B | (3<<25), "dt(", zabha},
  {"amomaxu_b_aq", MATCH_AMOMAXU_B | (2<<25), MASK_AMOMAXU_B | (3<<25), "dt(", zabha},
  {"amomaxu_b_aqrl", MATCH_AMOMAXU_B | (3<<25), MASK_AMOMAXU_B | (3<<25), "dt(", zabha},
  {"amocas_b", MATCH_AMOCAS_B, MASK_AMOCAS_B | (3<<25), "dt(", zabha},
  {"amocas_b_rl", MATCH_AMOCAS_B | (1<<25), MASK_AMOCAS_B | (3<<25), "dt(", zabha},
  {"amocas_b_aq", MATCH_AMOCAS_B | (2<<25), MASK_AMOCAS_B | (3<<25), "dt(", zabha},
  {"amocas_b_aqrl", MATCH_AMOCAS_B | (3<<25), MASK_AMOCAS_B | (3<<25), "dt(", zabha},
  {"amoadd_h", MATCH_AMOADD_H, MASK_AMOADD_H | (3<<25), "dt(", zabha},
  {"amoadd_h_rl", MATCH_AMOADD_H | (1<<25), MASK_AMOADD_H | (3<<25), "dt(", zabha},
  {"amoadd_h_aq", MATCH_AMOADD_H | (2<<25), MASK_AMOADD_H | (3<<25), "dt(", zabha},
  {"amoadd_h_aqrl", MATCH_AMOADD_H | (3<<25), MASK_AMOADD_H | (3<<25), "dt(", zabha},
  {"amoswap_h", MATCH_AMOSWAP_H, MASK_AMOSWAP_H | (3<<25), "dt(", zabha},
  {"amoswap_h_rl", MATCH_AMOSWAP_H | (1<<25), MASK_AMOSWAP_H | (3<<25), "dt(", zabha},
  {"amoswap_h_aq", MATCH_AMOSWAP_H | (2<<25), MASK_AMOSWAP_H | (3<<25), "dt(", zabha},
  {"amoswap_h_aqrl", MATCH_AMOSWAP_H | (3<<25), MASK_AMOSWAP_H | (3<<25), "dt(", zabha},
  {"amoand_h", MATCH_AMOAND_H, MASK_AMOAND_H | (3<<25), "dt(", zabha},
  {"amoand_h_rl", MATCH_AMOAND_H | (1<<25), MASK_AMOAND_H | (3<<25), "dt(", zabha},
  {"amoand_h_aq", MATCH_AMOAND_H | (2<<25), MASK_AMOAND_H | (3<<25), "dt(", zabha},
  {"amoand_h_aqrl", MATCH_AMOAND_H | (3<<25), MASK_AMOAND_H | (3<<25), "dt(", zabha},
  {"amoor_h", MATCH_AMOOR_H, MASK_AMOOR_H | (3<<25), "dt(", zabha},
  {"amoor_h_rl", MATCH_AMOOR_H | (1<<25), MASK_AMOOR_H | (3<<25), "dt(", zabha},
  {"amoor_h_aq", MATCH_AMOOR_H | (2<<25), MASK_AMOOR_H | (3<<25), "dt(", zabha},
  {"amoor_h_aqrl", MATCH_AMOOR_H | (3<<25), MASK_AMOOR_H | (3<<25), "dt(", zabha},
  {"amoxor_h", MATCH_AMOXOR_H, MASK_AMOXOR_H | (3<<25), "dt(", zabha},
  {"amoxor_h_rl", MATCH_AMOXOR_H | (1<<25), MASK_AMOXOR_H | (3<<25), "dt(", zabha},
  {"amoxor_h_aq", MATCH_AMOXOR_H | (2<<25), MASK_AMOXOR_H | (3<<25), "dt(", zabha},
  {"amoxor_h_aqrl", MATCH_AMOXOR_H | (3<<25), MASK_AMOXOR_H | (3<<25), "dt(", zabha},
  {"amomin_h", MATCH_AMOMIN_H, MASK_AMOMIN_H | (3<<25), "dt(", zabha},
  {"amomin_h_rl", MATCH_AMOMIN_H | (1<<25), MASK_AMOMIN_H | (3<<25), "dt(", zabha},
  {"amomin_h_aq", MATCH_AMOMIN_H | (2<<25), MASK_AMOMIN_H | (3<<25), "dt(", zabha},
  {"amomin_h_aqrl", MATCH_AMOMIN_H | (3<<25), MASK_AMOMIN_H | (3<<25), "dt(", zabha},
  {"amomax_h", MATCH_AMOMAX_H, MASK_AMOMAX_H | (3<<25), "dt(", zabha},
  {"amomax_h_rl", MATCH_AMOMAX_H | (1<<25), MASK_AMOMAX_H | (3<<25), "dt(", zabha},
  {"amomax_h_aq", MATCH_AMOMAX_H | (2<<25), MASK_AMOMAX_H | (3<<25), "dt(", zabha},
  {"amomax_h_aqrl", MATCH_AMOMAX_H | (3<<25), MASK_AMOMAX_H | (3<<25), "dt(", zabha},
  {"amominu_h", MATCH_AMOMINU_H, MASK_AMOMINU_H | (3<<25), "dt(", zabha},
  {"amominu_h_rl", MATCH_AMOMINU_H | (1<<25), MASK_AMOMINU_H | (3<<25), "dt(", zabha},
  {"amominu_h_aq", MATCH_AMOMINU_H | (2<<25), MASK_AMOMINU_H | (3<<25), "dt(", zabha},
  {"amominu_h_aqrl", MATCH_AMOMINU_H | (3<<25), MASK_AMOMINU_H | (3<<25), "dt(", zabha},
  {"amomaxu_h", MATCH_AMOMAXU_H, MASK_AMOMAXU_H | (3<<25), "dt(", zabha},
  {"amomaxu_h_rl", MATCH_AMOMAXU_H | (1<<25), MASK_AMOMAXU_H | (3<<25), "dt(", zabha},
  {"amomaxu_h_aq", MATCH_AMOMAXU_H | (2<<25), MASK_AMOMAXU_H | (3<<25), "dt(", zabha},
  {"amomaxu_h_aqrl", MATCH_AMOMAXU_H | (3<<25), MASK_AMOMAXU_H | (3<<25), "dt(", zabha},
  {"amocas_h", MATCH_AMOCAS_H, MASK_AMOCAS_H | (3<<25), "dt(", zabha},
  {"amocas_h_rl", MATCH_AMOCAS_H | (1<<25), MASK_AMOCAS_H | (3<<25), "dt(", zabha},
  {"amocas_h_aq", MATCH_AMOCAS_H | (2<<25), MASK_AMOCAS_H | (3<<25), "dt(", zabha},
  {"amocas_h_aqrl", MATCH_AMOCAS_H | (3<<25), MASK_AMOCAS_H | (3<<25), "dt(", zabha},
  // zicfiss AMO
  {"ssamoswap_w", MATCH_SSAMOSWAP_W, MASK_SSAMOSWAP_W | (3<<25), "dt(", zicfiss},
  {"ssamoswap_w_rl", MATCH_SSAMOSWAP_W | (1<<25), MASK_SSAMOSWAP_W | (3<<25), "dt(", zicfiss},
  {"ssamoswap_w_aq", MATCH_SSAMOSWAP_W | (2<<25), MASK_SSAMOSWAP_W | (3<<25), "dt(", zicfiss},
  {"ssamoswap_w_aqrl", MATCH_SSAMOSWAP_W | (3<<25), MASK_SSAMOSWAP_W | (3<<25), "dt(", zicfiss},
  {"ssamoswap_d", MATCH_SSAMOSWAP_D, MASK_SSAMOSWAP_D | (3<<25), "dt(", zicfiss_rv64},
  {"ssamoswap_d_rl", MATCH_SSAMOSWAP_D | (1<<25), MASK_SSAMOSWAP_D | (3<<25), "dt(", zicfiss_rv64},
  {"ssamoswap_d_aq", MATCH_SSAMOSWAP_D | (2<<25), MASK_SSAMOSWAP_D | (3<<25), "dt(", zicfiss_rv64},
  {"ssamoswap_d_aqrl", MATCH_SSAMOSWAP_D | (3<<25), MASK_SSAMOSWAP_D | (3<<25), "dt(", zicfiss_rv64},
  // zimop: all mop.r/mop.rr variants as explicit rows.
  // Zicfiss sspush/sspopchk have higher priority (earlier in table)
  // and will correctly shadow the mop.r.28/mop.rr.7 overlapping encodings.
  {"mop_r_0", MATCH_MOP_R_0, MASK_MOP_R_0, "ds", zimop},
  {"mop_r_1", MATCH_MOP_R_1, MASK_MOP_R_1, "ds", zimop},
  {"mop_r_2", MATCH_MOP_R_2, MASK_MOP_R_2, "ds", zimop},
  {"mop_r_3", MATCH_MOP_R_3, MASK_MOP_R_3, "ds", zimop},
  {"mop_r_4", MATCH_MOP_R_4, MASK_MOP_R_4, "ds", zimop},
  {"mop_r_5", MATCH_MOP_R_5, MASK_MOP_R_5, "ds", zimop},
  {"mop_r_6", MATCH_MOP_R_6, MASK_MOP_R_6, "ds", zimop},
  {"mop_r_7", MATCH_MOP_R_7, MASK_MOP_R_7, "ds", zimop},
  {"mop_r_8", MATCH_MOP_R_8, MASK_MOP_R_8, "ds", zimop},
  {"mop_r_9", MATCH_MOP_R_9, MASK_MOP_R_9, "ds", zimop},
  {"mop_r_10", MATCH_MOP_R_10, MASK_MOP_R_10, "ds", zimop},
  {"mop_r_11", MATCH_MOP_R_11, MASK_MOP_R_11, "ds", zimop},
  {"mop_r_12", MATCH_MOP_R_12, MASK_MOP_R_12, "ds", zimop},
  {"mop_r_13", MATCH_MOP_R_13, MASK_MOP_R_13, "ds", zimop},
  {"mop_r_14", MATCH_MOP_R_14, MASK_MOP_R_14, "ds", zimop},
  {"mop_r_15", MATCH_MOP_R_15, MASK_MOP_R_15, "ds", zimop},
  {"mop_r_16", MATCH_MOP_R_16, MASK_MOP_R_16, "ds", zimop},
  {"mop_r_17", MATCH_MOP_R_17, MASK_MOP_R_17, "ds", zimop},
  {"mop_r_18", MATCH_MOP_R_18, MASK_MOP_R_18, "ds", zimop},
  {"mop_r_19", MATCH_MOP_R_19, MASK_MOP_R_19, "ds", zimop},
  {"mop_r_20", MATCH_MOP_R_20, MASK_MOP_R_20, "ds", zimop},
  {"mop_r_21", MATCH_MOP_R_21, MASK_MOP_R_21, "ds", zimop},
  {"mop_r_22", MATCH_MOP_R_22, MASK_MOP_R_22, "ds", zimop},
  {"mop_r_23", MATCH_MOP_R_23, MASK_MOP_R_23, "ds", zimop},
  {"mop_r_24", MATCH_MOP_R_24, MASK_MOP_R_24, "ds", zimop},
  {"mop_r_25", MATCH_MOP_R_25, MASK_MOP_R_25, "ds", zimop},
  {"mop_r_26", MATCH_MOP_R_26, MASK_MOP_R_26, "ds", zimop},
  {"mop_r_27", MATCH_MOP_R_27, MASK_MOP_R_27, "ds", zimop},
  {"mop_r_28", MATCH_MOP_R_28, MASK_MOP_R_28, "ds", zimop},
  {"mop_r_29", MATCH_MOP_R_29, MASK_MOP_R_29, "ds", zimop},
  {"mop_r_30", MATCH_MOP_R_30, MASK_MOP_R_30, "ds", zimop},
  {"mop_r_31", MATCH_MOP_R_31, MASK_MOP_R_31, "ds", zimop},
  {"mop_rr_0", MATCH_MOP_RR_0, MASK_MOP_RR_0, "dst", zimop},
  {"mop_rr_1", MATCH_MOP_RR_1, MASK_MOP_RR_1, "dst", zimop},
  {"mop_rr_2", MATCH_MOP_RR_2, MASK_MOP_RR_2, "dst", zimop},
  {"mop_rr_3", MATCH_MOP_RR_3, MASK_MOP_RR_3, "dst", zimop},
  {"mop_rr_4", MATCH_MOP_RR_4, MASK_MOP_RR_4, "dst", zimop},
  {"mop_rr_5", MATCH_MOP_RR_5, MASK_MOP_RR_5, "dst", zimop},
  {"mop_rr_6", MATCH_MOP_RR_6, MASK_MOP_RR_6, "dst", zimop},
  {"mop_rr_7", MATCH_MOP_RR_7, MASK_MOP_RR_7, "dst", zimop},

  // vector instructions (has_any_vector)
{"vsetivli", MATCH_VSETIVLI, MASK_VSETIVLI, "dzW", vector},
  {"vsetvli", MATCH_VSETVLI, MASK_VSETVLI, "dsW", vector},
  {"vsetvl", MATCH_VSETVL, MASK_VSETVL, "dst", vector},
  {"vlm.v", MATCH_VLM_V, MASK_VLM_V, "A(?k", vector},
  {"vsm.v", MATCH_VSM_V, MASK_VSM_V, "G(?k", vector},
  {"vs1r.v", MATCH_VS1R_V, MASK_VS1R_V | (0x7ul<<29), "G(", vector},
  {"vs2r.v", MATCH_VS2R_V, MASK_VS2R_V | (0x7ul<<29), "G(", vector},
  {"vs4r.v", MATCH_VS4R_V, MASK_VS4R_V | (0x7ul<<29), "G(", vector},
  {"vs8r.v", MATCH_VS8R_V, MASK_VS8R_V | (0x7ul<<29), "G(", vector},
  {"vadd_vv", MATCH_VADD_VV, MASK_VADD_VV, "ACB?k", vector},
  {"vadd_vx", MATCH_VADD_VX, MASK_VADD_VX, "ACs?k", vector},
  {"vadd_vi", MATCH_VADD_VI, MASK_VADD_VI, "AC5?k", vector},
  {"vsub_vv", MATCH_VSUB_VV, MASK_VSUB_VV, "ACB?k", vector},
  {"vsub_vx", MATCH_VSUB_VX, MASK_VSUB_VX, "ACs?k", vector},
  {"vrsub_vx", MATCH_VRSUB_VX, MASK_VRSUB_VX, "ACs?k", vector},
  {"vrsub_vi", MATCH_VRSUB_VI, MASK_VRSUB_VI, "AC5?k", vector},
  {"vminu_vv", MATCH_VMINU_VV, MASK_VMINU_VV, "ACB?k", vector},
  {"vminu_vx", MATCH_VMINU_VX, MASK_VMINU_VX, "ACs?k", vector},
  {"vmin_vv", MATCH_VMIN_VV, MASK_VMIN_VV, "ACB?k", vector},
  {"vmin_vx", MATCH_VMIN_VX, MASK_VMIN_VX, "ACs?k", vector},
  {"vmaxu_vv", MATCH_VMAXU_VV, MASK_VMAXU_VV, "ACB?k", vector},
  {"vmaxu_vx", MATCH_VMAXU_VX, MASK_VMAXU_VX, "ACs?k", vector},
  {"vmax_vv", MATCH_VMAX_VV, MASK_VMAX_VV, "ACB?k", vector},
  {"vmax_vx", MATCH_VMAX_VX, MASK_VMAX_VX, "ACs?k", vector},
  {"vand_vv", MATCH_VAND_VV, MASK_VAND_VV, "ACB?k", vector},
  {"vand_vx", MATCH_VAND_VX, MASK_VAND_VX, "ACs?k", vector},
  {"vand_vi", MATCH_VAND_VI, MASK_VAND_VI, "AC5?k", vector},
  {"vor_vv", MATCH_VOR_VV, MASK_VOR_VV, "ACB?k", vector},
  {"vor_vx", MATCH_VOR_VX, MASK_VOR_VX, "ACs?k", vector},
  {"vor_vi", MATCH_VOR_VI, MASK_VOR_VI, "AC5?k", vector},
  {"vxor_vv", MATCH_VXOR_VV, MASK_VXOR_VV, "ACB?k", vector},
  {"vxor_vx", MATCH_VXOR_VX, MASK_VXOR_VX, "ACs?k", vector},
  {"vxor_vi", MATCH_VXOR_VI, MASK_VXOR_VI, "AC5?k", vector},
  {"vrgather_vv", MATCH_VRGATHER_VV, MASK_VRGATHER_VV, "ACB?k", vector},
  {"vrgather_vx", MATCH_VRGATHER_VX, MASK_VRGATHER_VX, "ACs?k", vector},
  {"vrgather_vi", MATCH_VRGATHER_VI, MASK_VRGATHER_VI, "ACz?k", vector},
  {"vrgatherei16_vv", MATCH_VRGATHEREI16_VV, MASK_VRGATHEREI16_VV, "ACB?k", vector},
  {"vslideup_vx", MATCH_VSLIDEUP_VX, MASK_VSLIDEUP_VX, "ACs?k", vector},
  {"vslideup_vi", MATCH_VSLIDEUP_VI, MASK_VSLIDEUP_VI, "ACz?k", vector},
  {"vslidedown_vx", MATCH_VSLIDEDOWN_VX, MASK_VSLIDEDOWN_VX, "ACs?k", vector},
  {"vslidedown_vi", MATCH_VSLIDEDOWN_VI, MASK_VSLIDEDOWN_VI, "ACz?k", vector},
  {"vadc_vvm", MATCH_VADC_VVM, MASK_VADC_VVM|(1<<25), "ACBK", vector},
  {"vadc_vxm", MATCH_VADC_VXM, MASK_VADC_VXM|(1<<25), "ACsK", vector},
  {"vadc_vim", MATCH_VADC_VIM, MASK_VADC_VIM|(1<<25), "AC5K", vector},
  {"vsbc_vvm", MATCH_VSBC_VVM, MASK_VSBC_VVM|(1<<25), "ACBK", vector},
  {"vsbc_vxm", MATCH_VSBC_VXM, MASK_VSBC_VXM|(1<<25), "ACsK", vector},
  {"vmadc_vvm", MATCH_VMADC_VVM, MASK_VMADC_VVM|(1<<25), "ACBK", vector},
  {"vmadc_vxm", MATCH_VMADC_VXM, MASK_VMADC_VXM|(1<<25), "ACsK", vector},
  {"vmadc_vim", MATCH_VMADC_VIM, MASK_VMADC_VIM|(1<<25), "AC5K", vector},
  {"vmadc_vv", MATCH_VMADC_VV, MASK_VMADC_VV, "ACB?k", vector},
  {"vmadc_vx", MATCH_VMADC_VX, MASK_VMADC_VX, "ACs?k", vector},
  {"vmadc_vi", MATCH_VMADC_VI, MASK_VMADC_VI, "AC5?k", vector},
  {"vmsbc_vvm", MATCH_VMSBC_VVM, MASK_VMSBC_VVM|(1<<25), "ACBK", vector},
  {"vmsbc_vxm", MATCH_VMSBC_VXM, MASK_VMSBC_VXM|(1<<25), "ACsK", vector},
  {"vmsbc_vv", MATCH_VMSBC_VV, MASK_VMSBC_VV, "ACB?k", vector},
  {"vmsbc_vx", MATCH_VMSBC_VX, MASK_VMSBC_VX, "ACs?k", vector},
  {"vmerge_vvm", MATCH_VMERGE_VVM, MASK_VMERGE_VVM|(1<<25), "ACBK", vector},
  {"vmerge_vxm", MATCH_VMERGE_VXM, MASK_VMERGE_VXM|(1<<25), "ACsK", vector},
  {"vmerge_vim", MATCH_VMERGE_VIM, MASK_VMERGE_VIM|(1<<25), "AC5K", vector},
  {"vmv.v.i", MATCH_VMV_V_I, MASK_VMV_V_I, "A5", vector},
  {"vmv.v.v", MATCH_VMV_V_V, MASK_VMV_V_V, "AB", vector},
  {"vmv.v.x", MATCH_VMV_V_X, MASK_VMV_V_X, "As", vector},
  {"vmseq_vv", MATCH_VMSEQ_VV, MASK_VMSEQ_VV, "ACB?k", vector},
  {"vmseq_vx", MATCH_VMSEQ_VX, MASK_VMSEQ_VX, "ACs?k", vector},
  {"vmseq_vi", MATCH_VMSEQ_VI, MASK_VMSEQ_VI, "AC5?k", vector},
  {"vmsne_vv", MATCH_VMSNE_VV, MASK_VMSNE_VV, "ACB?k", vector},
  {"vmsne_vx", MATCH_VMSNE_VX, MASK_VMSNE_VX, "ACs?k", vector},
  {"vmsne_vi", MATCH_VMSNE_VI, MASK_VMSNE_VI, "AC5?k", vector},
  {"vmsltu_vv", MATCH_VMSLTU_VV, MASK_VMSLTU_VV, "ACB?k", vector},
  {"vmsltu_vx", MATCH_VMSLTU_VX, MASK_VMSLTU_VX, "ACs?k", vector},
  {"vmslt_vv", MATCH_VMSLT_VV, MASK_VMSLT_VV, "ACB?k", vector},
  {"vmslt_vx", MATCH_VMSLT_VX, MASK_VMSLT_VX, "ACs?k", vector},
  {"vmsleu_vv", MATCH_VMSLEU_VV, MASK_VMSLEU_VV, "ACB?k", vector},
  {"vmsleu_vx", MATCH_VMSLEU_VX, MASK_VMSLEU_VX, "ACs?k", vector},
  {"vmsleu_vi", MATCH_VMSLEU_VI, MASK_VMSLEU_VI, "ACz?k", vector},
  {"vmsle_vv", MATCH_VMSLE_VV, MASK_VMSLE_VV, "ACB?k", vector},
  {"vmsle_vx", MATCH_VMSLE_VX, MASK_VMSLE_VX, "ACs?k", vector},
  {"vmsle_vi", MATCH_VMSLE_VI, MASK_VMSLE_VI, "AC5?k", vector},
  {"vmsgtu_vx", MATCH_VMSGTU_VX, MASK_VMSGTU_VX, "ACs?k", vector},
  {"vmsgtu_vi", MATCH_VMSGTU_VI, MASK_VMSGTU_VI, "ACz?k", vector},
  {"vmsgt_vx", MATCH_VMSGT_VX, MASK_VMSGT_VX, "ACs?k", vector},
  {"vmsgt_vi", MATCH_VMSGT_VI, MASK_VMSGT_VI, "AC5?k", vector},
  {"vsaddu_vv", MATCH_VSADDU_VV, MASK_VSADDU_VV, "ACB?k", vector},
  {"vsaddu_vx", MATCH_VSADDU_VX, MASK_VSADDU_VX, "ACs?k", vector},
  {"vsaddu_vi", MATCH_VSADDU_VI, MASK_VSADDU_VI, "ACz?k", vector},
  {"vsadd_vv", MATCH_VSADD_VV, MASK_VSADD_VV, "ACB?k", vector},
  {"vsadd_vx", MATCH_VSADD_VX, MASK_VSADD_VX, "ACs?k", vector},
  {"vsadd_vi", MATCH_VSADD_VI, MASK_VSADD_VI, "AC5?k", vector},
  {"vssubu_vv", MATCH_VSSUBU_VV, MASK_VSSUBU_VV, "ACB?k", vector},
  {"vssubu_vx", MATCH_VSSUBU_VX, MASK_VSSUBU_VX, "ACs?k", vector},
  {"vssub_vv", MATCH_VSSUB_VV, MASK_VSSUB_VV, "ACB?k", vector},
  {"vssub_vx", MATCH_VSSUB_VX, MASK_VSSUB_VX, "ACs?k", vector},
  {"vsll_vv", MATCH_VSLL_VV, MASK_VSLL_VV, "ACB?k", vector},
  {"vsll_vx", MATCH_VSLL_VX, MASK_VSLL_VX, "ACs?k", vector},
  {"vsll_vi", MATCH_VSLL_VI, MASK_VSLL_VI, "AC5?k", vector},
  {"vmv1r.v", MATCH_VMV1R_V, MASK_VMV1R_V, "AC", vector},
  {"vmv2r.v", MATCH_VMV2R_V, MASK_VMV2R_V, "AC", vector},
  {"vmv4r.v", MATCH_VMV4R_V, MASK_VMV4R_V, "AC", vector},
  {"vmv8r.v", MATCH_VMV8R_V, MASK_VMV8R_V, "AC", vector},
  {"vsmul_vv", MATCH_VSMUL_VV, MASK_VSMUL_VV, "ACB?k", vector},
  {"vsmul_vx", MATCH_VSMUL_VX, MASK_VSMUL_VX, "ACs?k", vector},
  {"vsrl_vv", MATCH_VSRL_VV, MASK_VSRL_VV, "ACB?k", vector},
  {"vsrl_vx", MATCH_VSRL_VX, MASK_VSRL_VX, "ACs?k", vector},
  {"vsrl_vi", MATCH_VSRL_VI, MASK_VSRL_VI, "ACz?k", vector},
  {"vsra_vv", MATCH_VSRA_VV, MASK_VSRA_VV, "ACB?k", vector},
  {"vsra_vx", MATCH_VSRA_VX, MASK_VSRA_VX, "ACs?k", vector},
  {"vsra_vi", MATCH_VSRA_VI, MASK_VSRA_VI, "ACz?k", vector},
  {"vssrl_vv", MATCH_VSSRL_VV, MASK_VSSRL_VV, "ACB?k", vector},
  {"vssrl_vx", MATCH_VSSRL_VX, MASK_VSSRL_VX, "ACs?k", vector},
  {"vssrl_vi", MATCH_VSSRL_VI, MASK_VSSRL_VI, "ACz?k", vector},
  {"vssra_vv", MATCH_VSSRA_VV, MASK_VSSRA_VV, "ACB?k", vector},
  {"vssra_vx", MATCH_VSSRA_VX, MASK_VSSRA_VX, "ACs?k", vector},
  {"vssra_vi", MATCH_VSSRA_VI, MASK_VSSRA_VI, "ACz?k", vector},
  {"vnsrl_wv", MATCH_VNSRL_WV, MASK_VNSRL_WV, "ACB?k", vector},
  {"vnsrl_wx", MATCH_VNSRL_WX, MASK_VNSRL_WX, "ACs?k", vector},
  {"vnsrl_wi", MATCH_VNSRL_WI, MASK_VNSRL_WI, "ACz?k", vector},
  {"vnsra_wv", MATCH_VNSRA_WV, MASK_VNSRA_WV, "ACB?k", vector},
  {"vnsra_wx", MATCH_VNSRA_WX, MASK_VNSRA_WX, "ACs?k", vector},
  {"vnsra_wi", MATCH_VNSRA_WI, MASK_VNSRA_WI, "ACz?k", vector},
  {"vnclipu_wv", MATCH_VNCLIPU_WV, MASK_VNCLIPU_WV, "ACB?k", vector},
  {"vnclipu_wx", MATCH_VNCLIPU_WX, MASK_VNCLIPU_WX, "ACs?k", vector},
  {"vnclipu_wi", MATCH_VNCLIPU_WI, MASK_VNCLIPU_WI, "ACz?k", vector},
  {"vnclip_wv", MATCH_VNCLIP_WV, MASK_VNCLIP_WV, "ACB?k", vector},
  {"vnclip_wx", MATCH_VNCLIP_WX, MASK_VNCLIP_WX, "ACs?k", vector},
  {"vnclip_wi", MATCH_VNCLIP_WI, MASK_VNCLIP_WI, "ACz?k", vector},
  {"vwredsumu_vs", MATCH_VWREDSUMU_VS, MASK_VWREDSUMU_VS, "ACB?k", vector},
  {"vwredsum_vs", MATCH_VWREDSUM_VS, MASK_VWREDSUM_VS, "ACB?k", vector},
  {"vaaddu_vv", MATCH_VAADDU_VV, MASK_VAADDU_VV, "ACB?k", vector},
  {"vaaddu_vx", MATCH_VAADDU_VX, MASK_VAADDU_VX, "ACs?k", vector},
  {"vaadd_vv", MATCH_VAADD_VV, MASK_VAADD_VV, "ACB?k", vector},
  {"vaadd_vx", MATCH_VAADD_VX, MASK_VAADD_VX, "ACs?k", vector},
  {"vasubu_vv", MATCH_VASUBU_VV, MASK_VASUBU_VV, "ACB?k", vector},
  {"vasubu_vx", MATCH_VASUBU_VX, MASK_VASUBU_VX, "ACs?k", vector},
  {"vasub_vv", MATCH_VASUB_VV, MASK_VASUB_VV, "ACB?k", vector},
  {"vasub_vx", MATCH_VASUB_VX, MASK_VASUB_VX, "ACs?k", vector},
  {"vredsum_vs", MATCH_VREDSUM_VS, MASK_VREDSUM_VS, "ACB?k", vector},
  {"vredand_vs", MATCH_VREDAND_VS, MASK_VREDAND_VS, "ACB?k", vector},
  {"vredor_vs", MATCH_VREDOR_VS, MASK_VREDOR_VS, "ACB?k", vector},
  {"vredxor_vs", MATCH_VREDXOR_VS, MASK_VREDXOR_VS, "ACB?k", vector},
  {"vredminu_vs", MATCH_VREDMINU_VS, MASK_VREDMINU_VS, "ACB?k", vector},
  {"vredmin_vs", MATCH_VREDMIN_VS, MASK_VREDMIN_VS, "ACB?k", vector},
  {"vredmaxu_vs", MATCH_VREDMAXU_VS, MASK_VREDMAXU_VS, "ACB?k", vector},
  {"vredmax_vs", MATCH_VREDMAX_VS, MASK_VREDMAX_VS, "ACB?k", vector},
  {"vslide1up_vx", MATCH_VSLIDE1UP_VX, MASK_VSLIDE1UP_VX, "ACs?k", vector},
  {"vslide1down_vx", MATCH_VSLIDE1DOWN_VX, MASK_VSLIDE1DOWN_VX, "ACs?k", vector},
  {"vmv.x.s", MATCH_VMV_X_S, MASK_VMV_X_S, "dC", vector},
  {"vcpop.m", MATCH_VCPOP_M, MASK_VCPOP_M, "dC?k", vector},
  {"vfirst.m", MATCH_VFIRST_M, MASK_VFIRST_M, "dC?k", vector},
  {"vmv.s.x", MATCH_VMV_S_X, MASK_VMV_S_X, "As", vector},
  {"vzext_vf2", MATCH_VZEXT_VF2, MASK_VZEXT_VF2, "AC?k", vector},
  {"vsext_vf2", MATCH_VSEXT_VF2, MASK_VSEXT_VF2, "AC?k", vector},
  {"vzext_vf4", MATCH_VZEXT_VF4, MASK_VZEXT_VF4, "AC?k", vector},
  {"vsext_vf4", MATCH_VSEXT_VF4, MASK_VSEXT_VF4, "AC?k", vector},
  {"vzext_vf8", MATCH_VZEXT_VF8, MASK_VZEXT_VF8, "AC?k", vector},
  {"vsext_vf8", MATCH_VSEXT_VF8, MASK_VSEXT_VF8, "AC?k", vector},
  {"vmsbf_m", MATCH_VMSBF_M, MASK_VMSBF_M, "AC?k", vector},
  {"vmsof_m", MATCH_VMSOF_M, MASK_VMSOF_M, "AC?k", vector},
  {"vmsif_m", MATCH_VMSIF_M, MASK_VMSIF_M, "AC?k", vector},
  {"viota_m", MATCH_VIOTA_M, MASK_VIOTA_M, "AC?k", vector},
  {"vid.v", MATCH_VID_V, MASK_VID_V, "A?k", vector},
  {"vid.v", MATCH_VID_V, MASK_VID_V, "A?k", vector},
  {"vcompress.vm", MATCH_VCOMPRESS_VM, MASK_VCOMPRESS_VM, "ACB", vector},
  {"vmandn_mm", MATCH_VMANDN_MM, MASK_VMANDN_MM, "ACB?k", vector},
  {"vmand_mm", MATCH_VMAND_MM, MASK_VMAND_MM, "ACB?k", vector},
  {"vmor_mm", MATCH_VMOR_MM, MASK_VMOR_MM, "ACB?k", vector},
  {"vmxor_mm", MATCH_VMXOR_MM, MASK_VMXOR_MM, "ACB?k", vector},
  {"vmorn_mm", MATCH_VMORN_MM, MASK_VMORN_MM, "ACB?k", vector},
  {"vmnand_mm", MATCH_VMNAND_MM, MASK_VMNAND_MM, "ACB?k", vector},
  {"vmnor_mm", MATCH_VMNOR_MM, MASK_VMNOR_MM, "ACB?k", vector},
  {"vmxnor_mm", MATCH_VMXNOR_MM, MASK_VMXNOR_MM, "ACB?k", vector},
  {"vdivu_vv", MATCH_VDIVU_VV, MASK_VDIVU_VV, "ACB?k", vector},
  {"vdivu_vx", MATCH_VDIVU_VX, MASK_VDIVU_VX, "ACs?k", vector},
  {"vdiv_vv", MATCH_VDIV_VV, MASK_VDIV_VV, "ACB?k", vector},
  {"vdiv_vx", MATCH_VDIV_VX, MASK_VDIV_VX, "ACs?k", vector},
  {"vremu_vv", MATCH_VREMU_VV, MASK_VREMU_VV, "ACB?k", vector},
  {"vremu_vx", MATCH_VREMU_VX, MASK_VREMU_VX, "ACs?k", vector},
  {"vrem_vv", MATCH_VREM_VV, MASK_VREM_VV, "ACB?k", vector},
  {"vrem_vx", MATCH_VREM_VX, MASK_VREM_VX, "ACs?k", vector},
  {"vmulhu_vv", MATCH_VMULHU_VV, MASK_VMULHU_VV, "ACB?k", vector},
  {"vmulhu_vx", MATCH_VMULHU_VX, MASK_VMULHU_VX, "ACs?k", vector},
  {"vmul_vv", MATCH_VMUL_VV, MASK_VMUL_VV, "ACB?k", vector},
  {"vmul_vx", MATCH_VMUL_VX, MASK_VMUL_VX, "ACs?k", vector},
  {"vmulhsu_vv", MATCH_VMULHSU_VV, MASK_VMULHSU_VV, "ACB?k", vector},
  {"vmulhsu_vx", MATCH_VMULHSU_VX, MASK_VMULHSU_VX, "ACs?k", vector},
  {"vmulh_vv", MATCH_VMULH_VV, MASK_VMULH_VV, "ACB?k", vector},
  {"vmulh_vx", MATCH_VMULH_VX, MASK_VMULH_VX, "ACs?k", vector},
  {"vmadd_vv", MATCH_VMADD_VV, MASK_VMADD_VV, "ABC?k", vector},
  {"vmadd_vx", MATCH_VMADD_VX, MASK_VMADD_VX, "AsC?k", vector},
  {"vnmsub_vv", MATCH_VNMSUB_VV, MASK_VNMSUB_VV, "ABC?k", vector},
  {"vnmsub_vx", MATCH_VNMSUB_VX, MASK_VNMSUB_VX, "AsC?k", vector},
  {"vmacc_vv", MATCH_VMACC_VV, MASK_VMACC_VV, "ABC?k", vector},
  {"vmacc_vx", MATCH_VMACC_VX, MASK_VMACC_VX, "AsC?k", vector},
  {"vnmsac_vv", MATCH_VNMSAC_VV, MASK_VNMSAC_VV, "ABC?k", vector},
  {"vnmsac_vx", MATCH_VNMSAC_VX, MASK_VNMSAC_VX, "AsC?k", vector},
  {"vwaddu_vv", MATCH_VWADDU_VV, MASK_VWADDU_VV, "ACB?k", vector},
  {"vwaddu_vx", MATCH_VWADDU_VX, MASK_VWADDU_VX, "ACs?k", vector},
  {"vwadd_vv", MATCH_VWADD_VV, MASK_VWADD_VV, "ACB?k", vector},
  {"vwadd_vx", MATCH_VWADD_VX, MASK_VWADD_VX, "ACs?k", vector},
  {"vwsubu_vv", MATCH_VWSUBU_VV, MASK_VWSUBU_VV, "ACB?k", vector},
  {"vwsubu_vx", MATCH_VWSUBU_VX, MASK_VWSUBU_VX, "ACs?k", vector},
  {"vwsub_vv", MATCH_VWSUB_VV, MASK_VWSUB_VV, "ACB?k", vector},
  {"vwsub_vx", MATCH_VWSUB_VX, MASK_VWSUB_VX, "ACs?k", vector},
  {"vwaddu_wv", MATCH_VWADDU_WV, MASK_VWADDU_WV, "ACB?k", vector},
  {"vwaddu_wx", MATCH_VWADDU_WX, MASK_VWADDU_WX, "ACs?k", vector},
  {"vwadd_wv", MATCH_VWADD_WV, MASK_VWADD_WV, "ACB?k", vector},
  {"vwadd_wx", MATCH_VWADD_WX, MASK_VWADD_WX, "ACs?k", vector},
  {"vwsubu_wv", MATCH_VWSUBU_WV, MASK_VWSUBU_WV, "ACB?k", vector},
  {"vwsubu_wx", MATCH_VWSUBU_WX, MASK_VWSUBU_WX, "ACs?k", vector},
  {"vwsub_wv", MATCH_VWSUB_WV, MASK_VWSUB_WV, "ACB?k", vector},
  {"vwsub_wx", MATCH_VWSUB_WX, MASK_VWSUB_WX, "ACs?k", vector},
  {"vwmulu_vv", MATCH_VWMULU_VV, MASK_VWMULU_VV, "ACB?k", vector},
  {"vwmulu_vx", MATCH_VWMULU_VX, MASK_VWMULU_VX, "ACs?k", vector},
  {"vwmulsu_vv", MATCH_VWMULSU_VV, MASK_VWMULSU_VV, "ACB?k", vector},
  {"vwmulsu_vx", MATCH_VWMULSU_VX, MASK_VWMULSU_VX, "ACs?k", vector},
  {"vwmul_vv", MATCH_VWMUL_VV, MASK_VWMUL_VV, "ACB?k", vector},
  {"vwmul_vx", MATCH_VWMUL_VX, MASK_VWMUL_VX, "ACs?k", vector},
  {"vwmaccu_vv", MATCH_VWMACCU_VV, MASK_VWMACCU_VV, "ABC?k", vector},
  {"vwmaccu_vx", MATCH_VWMACCU_VX, MASK_VWMACCU_VX, "AsC?k", vector},
  {"vwmacc_vv", MATCH_VWMACC_VV, MASK_VWMACC_VV, "ABC?k", vector},
  {"vwmacc_vx", MATCH_VWMACC_VX, MASK_VWMACC_VX, "AsC?k", vector},
  {"vwmaccus_vx", MATCH_VWMACCUS_VX, MASK_VWMACCUS_VX, "AsC?k", vector},
  {"vwmaccsu_vv", MATCH_VWMACCSU_VV, MASK_VWMACCSU_VV, "ABC?k", vector},
  {"vwmaccsu_vx", MATCH_VWMACCSU_VX, MASK_VWMACCSU_VX, "AsC?k", vector},
  {"vqdot_vv", MATCH_VQDOT_VV, MASK_VQDOT_VV, "ACB?k", zvqdotq},
  {"vqdot_vx", MATCH_VQDOT_VX, MASK_VQDOT_VX, "ACs?k", zvqdotq},
  {"vqdotu_vv", MATCH_VQDOTU_VV, MASK_VQDOTU_VV, "ACB?k", zvqdotq},
  {"vqdotu_vx", MATCH_VQDOTU_VX, MASK_VQDOTU_VX, "ACs?k", zvqdotq},
  {"vqdotsu_vv", MATCH_VQDOTSU_VV, MASK_VQDOTSU_VV, "ACB?k", zvqdotq},
  {"vqdotsu_vx", MATCH_VQDOTSU_VX, MASK_VQDOTSU_VX, "ACs?k", zvqdotq},
  {"vqdotus_vx", MATCH_VQDOTUS_VX, MASK_VQDOTUS_VX, "ACs?k", zvqdotq},
  {"vfadd_vv", MATCH_VFADD_VV, MASK_VFADD_VV, "ACB?k", vector},
  {"vfadd_vf", MATCH_VFADD_VF, MASK_VFADD_VF, "ACS?k", vector},
  {"vfredusum_vs", MATCH_VFREDUSUM_VS, MASK_VFREDUSUM_VS, "ACB?k", vector},
  {"vfsub_vv", MATCH_VFSUB_VV, MASK_VFSUB_VV, "ACB?k", vector},
  {"vfsub_vf", MATCH_VFSUB_VF, MASK_VFSUB_VF, "ACS?k", vector},
  {"vfredosum_vs", MATCH_VFREDOSUM_VS, MASK_VFREDOSUM_VS, "ACB?k", vector},
  {"vfmin_vv", MATCH_VFMIN_VV, MASK_VFMIN_VV, "ACB?k", vector},
  {"vfmin_vf", MATCH_VFMIN_VF, MASK_VFMIN_VF, "ACS?k", vector},
  {"vfredmin_vs", MATCH_VFREDMIN_VS, MASK_VFREDMIN_VS, "ACB?k", vector},
  {"vfmax_vv", MATCH_VFMAX_VV, MASK_VFMAX_VV, "ACB?k", vector},
  {"vfmax_vf", MATCH_VFMAX_VF, MASK_VFMAX_VF, "ACS?k", vector},
  {"vfredmax_vs", MATCH_VFREDMAX_VS, MASK_VFREDMAX_VS, "ACB?k", vector},
  {"vfsgnj_vv", MATCH_VFSGNJ_VV, MASK_VFSGNJ_VV, "ACB?k", vector},
  {"vfsgnj_vf", MATCH_VFSGNJ_VF, MASK_VFSGNJ_VF, "ACS?k", vector},
  {"vfsgnjn_vv", MATCH_VFSGNJN_VV, MASK_VFSGNJN_VV, "ACB?k", vector},
  {"vfsgnjn_vf", MATCH_VFSGNJN_VF, MASK_VFSGNJN_VF, "ACS?k", vector},
  {"vfsgnjx_vv", MATCH_VFSGNJX_VV, MASK_VFSGNJX_VV, "ACB?k", vector},
  {"vfsgnjx_vf", MATCH_VFSGNJX_VF, MASK_VFSGNJX_VF, "ACS?k", vector},
  {"vfmv.f.s", MATCH_VFMV_F_S, MASK_VFMV_F_S, "DC", vector},
  {"vfmv.s.f", MATCH_VFMV_S_F, MASK_VFMV_S_F | MASK_VFMV_S_F, "AS", vector},
  {"vfslide1up_vf", MATCH_VFSLIDE1UP_VF, MASK_VFSLIDE1UP_VF, "ACS?k", vector},
  {"vfslide1down_vf", MATCH_VFSLIDE1DOWN_VF, MASK_VFSLIDE1DOWN_VF, "ACS?k", vector},
  {"vfmerge.vfm", MATCH_VFMERGE_VFM, MASK_VFMERGE_VFM, "ACSK", vector},
  {"vfmv.v.f", MATCH_VFMV_V_F, MASK_VFMV_V_F, "AS", vector},
  {"vmfeq_vv", MATCH_VMFEQ_VV, MASK_VMFEQ_VV, "ACB?k", vector},
  {"vmfeq_vf", MATCH_VMFEQ_VF, MASK_VMFEQ_VF, "ACS?k", vector},
  {"vmfle_vv", MATCH_VMFLE_VV, MASK_VMFLE_VV, "ACB?k", vector},
  {"vmfle_vf", MATCH_VMFLE_VF, MASK_VMFLE_VF, "ACS?k", vector},
  {"vmflt_vv", MATCH_VMFLT_VV, MASK_VMFLT_VV, "ACB?k", vector},
  {"vmflt_vf", MATCH_VMFLT_VF, MASK_VMFLT_VF, "ACS?k", vector},
  {"vmfne_vv", MATCH_VMFNE_VV, MASK_VMFNE_VV, "ACB?k", vector},
  {"vmfne_vf", MATCH_VMFNE_VF, MASK_VMFNE_VF, "ACS?k", vector},
  {"vmfgt_vf", MATCH_VMFGT_VF, MASK_VMFGT_VF, "ACS?k", vector},
  {"vmfge_vf", MATCH_VMFGE_VF, MASK_VMFGE_VF, "ACS?k", vector},
  {"vfdiv_vv", MATCH_VFDIV_VV, MASK_VFDIV_VV, "ACB?k", vector},
  {"vfdiv_vf", MATCH_VFDIV_VF, MASK_VFDIV_VF, "ACS?k", vector},
  {"vfrdiv_vf", MATCH_VFRDIV_VF, MASK_VFRDIV_VF, "ACS?k", vector},
  {"vfcvt_rtz_xu_f_v", MATCH_VFCVT_RTZ_XU_F_V, MASK_VFCVT_RTZ_XU_F_V, "AC?k", vector},
  {"vfcvt_rtz_x_f_v", MATCH_VFCVT_RTZ_X_F_V, MASK_VFCVT_RTZ_X_F_V, "AC?k", vector},
  {"vfcvt_xu_f_v", MATCH_VFCVT_XU_F_V, MASK_VFCVT_XU_F_V, "AC?k", vector},
  {"vfcvt_x_f_v", MATCH_VFCVT_X_F_V, MASK_VFCVT_X_F_V, "AC?k", vector},
  {"vfcvt_f_xu_v", MATCH_VFCVT_F_XU_V, MASK_VFCVT_F_XU_V, "AC?k", vector},
  {"vfcvt_f_x_v", MATCH_VFCVT_F_X_V, MASK_VFCVT_F_X_V, "AC?k", vector},
  {"vfwcvt_rtz_xu_f_v", MATCH_VFWCVT_RTZ_XU_F_V, MASK_VFWCVT_RTZ_XU_F_V, "AC?k", vector},
  {"vfwcvt_rtz_x_f_v", MATCH_VFWCVT_RTZ_X_F_V, MASK_VFWCVT_RTZ_X_F_V, "AC?k", vector},
  {"vfwcvt_xu_f_v", MATCH_VFWCVT_XU_F_V, MASK_VFWCVT_XU_F_V, "AC?k", vector},
  {"vfwcvt_x_f_v", MATCH_VFWCVT_X_F_V, MASK_VFWCVT_X_F_V, "AC?k", vector},
  {"vfwcvt_f_xu_v", MATCH_VFWCVT_F_XU_V, MASK_VFWCVT_F_XU_V, "AC?k", vector},
  {"vfwcvt_f_x_v", MATCH_VFWCVT_F_X_V, MASK_VFWCVT_F_X_V, "AC?k", vector},
  {"vfwcvt_f_f_v", MATCH_VFWCVT_F_F_V, MASK_VFWCVT_F_F_V, "AC?k", vector},
  {"vfncvt_rtz_xu_f_w", MATCH_VFNCVT_RTZ_XU_F_W, MASK_VFNCVT_RTZ_XU_F_W, "AC?k", vector},
  {"vfncvt_rtz_x_f_w", MATCH_VFNCVT_RTZ_X_F_W, MASK_VFNCVT_RTZ_X_F_W, "AC?k", vector},
  {"vfncvt_xu_f_w", MATCH_VFNCVT_XU_F_W, MASK_VFNCVT_XU_F_W, "AC?k", vector},
  {"vfncvt_x_f_w", MATCH_VFNCVT_X_F_W, MASK_VFNCVT_X_F_W, "AC?k", vector},
  {"vfncvt_f_xu_w", MATCH_VFNCVT_F_XU_W, MASK_VFNCVT_F_XU_W, "AC?k", vector},
  {"vfncvt_f_x_w", MATCH_VFNCVT_F_X_W, MASK_VFNCVT_F_X_W, "AC?k", vector},
  {"vfncvt_f_f_w", MATCH_VFNCVT_F_F_W, MASK_VFNCVT_F_F_W, "AC?k", vector},
  {"vfncvt_rod_f_f_w", MATCH_VFNCVT_ROD_F_F_W, MASK_VFNCVT_ROD_F_F_W, "AC?k", vector},
  {"vfsqrt_v", MATCH_VFSQRT_V, MASK_VFSQRT_V, "AC?k", vector},
  {"vfrsqrt7_v", MATCH_VFRSQRT7_V, MASK_VFRSQRT7_V, "AC?k", vector},
  {"vfrec7_v", MATCH_VFREC7_V, MASK_VFREC7_V, "AC?k", vector},
  {"vfclass_v", MATCH_VFCLASS_V, MASK_VFCLASS_V, "AC?k", vector},
  {"vfmul_vv", MATCH_VFMUL_VV, MASK_VFMUL_VV, "ACB?k", vector},
  {"vfmul_vf", MATCH_VFMUL_VF, MASK_VFMUL_VF, "ACS?k", vector},
  {"vfrsub_vf", MATCH_VFRSUB_VF, MASK_VFRSUB_VF, "ACS?k", vector},
  {"vfmadd_vv", MATCH_VFMADD_VV, MASK_VFMADD_VV, "ABC?k", vector},
  {"vfmadd_vf", MATCH_VFMADD_VF, MASK_VFMADD_VF, "ASC?k", vector},
  {"vfnmadd_vv", MATCH_VFNMADD_VV, MASK_VFNMADD_VV, "ABC?k", vector},
  {"vfnmadd_vf", MATCH_VFNMADD_VF, MASK_VFNMADD_VF, "ASC?k", vector},
  {"vfmsub_vv", MATCH_VFMSUB_VV, MASK_VFMSUB_VV, "ABC?k", vector},
  {"vfmsub_vf", MATCH_VFMSUB_VF, MASK_VFMSUB_VF, "ASC?k", vector},
  {"vfnmsub_vv", MATCH_VFNMSUB_VV, MASK_VFNMSUB_VV, "ABC?k", vector},
  {"vfnmsub_vf", MATCH_VFNMSUB_VF, MASK_VFNMSUB_VF, "ASC?k", vector},
  {"vfmacc_vv", MATCH_VFMACC_VV, MASK_VFMACC_VV, "ABC?k", vector},
  {"vfmacc_vf", MATCH_VFMACC_VF, MASK_VFMACC_VF, "ASC?k", vector},
  {"vfnmacc_vv", MATCH_VFNMACC_VV, MASK_VFNMACC_VV, "ABC?k", vector},
  {"vfnmacc_vf", MATCH_VFNMACC_VF, MASK_VFNMACC_VF, "ASC?k", vector},
  {"vfmsac_vv", MATCH_VFMSAC_VV, MASK_VFMSAC_VV, "ABC?k", vector},
  {"vfmsac_vf", MATCH_VFMSAC_VF, MASK_VFMSAC_VF, "ASC?k", vector},
  {"vfnmsac_vv", MATCH_VFNMSAC_VV, MASK_VFNMSAC_VV, "ABC?k", vector},
  {"vfnmsac_vf", MATCH_VFNMSAC_VF, MASK_VFNMSAC_VF, "ASC?k", vector},
  {"vfwadd_vv", MATCH_VFWADD_VV, MASK_VFWADD_VV, "ACB?k", vector},
  {"vfwadd_vf", MATCH_VFWADD_VF, MASK_VFWADD_VF, "ACS?k", vector},
  {"vfwredusum_vs", MATCH_VFWREDUSUM_VS, MASK_VFWREDUSUM_VS, "ACB?k", vector},
  {"vfwsub_vv", MATCH_VFWSUB_VV, MASK_VFWSUB_VV, "ACB?k", vector},
  {"vfwsub_vf", MATCH_VFWSUB_VF, MASK_VFWSUB_VF, "ACS?k", vector},
  {"vfwredosum_vs", MATCH_VFWREDOSUM_VS, MASK_VFWREDOSUM_VS, "ACB?k", vector},
  {"vfwadd_wv", MATCH_VFWADD_WV, MASK_VFWADD_WV, "ACB?k", vector},
  {"vfwadd_wf", MATCH_VFWADD_WF, MASK_VFWADD_WF, "ACS?k", vector},
  {"vfwsub_wv", MATCH_VFWSUB_WV, MASK_VFWSUB_WV, "ACB?k", vector},
  {"vfwsub_wf", MATCH_VFWSUB_WF, MASK_VFWSUB_WF, "ACS?k", vector},
  {"vfwmul_vv", MATCH_VFWMUL_VV, MASK_VFWMUL_VV, "ACB?k", vector},
  {"vfwmul_vf", MATCH_VFWMUL_VF, MASK_VFWMUL_VF, "ACS?k", vector},
  {"vfwmacc_vv", MATCH_VFWMACC_VV, MASK_VFWMACC_VV, "ABC?k", vector},
  {"vfwmacc_vf", MATCH_VFWMACC_VF, MASK_VFWMACC_VF, "ASC?k", vector},
  {"vfwnmacc_vv", MATCH_VFWNMACC_VV, MASK_VFWNMACC_VV, "ABC?k", vector},
  {"vfwnmacc_vf", MATCH_VFWNMACC_VF, MASK_VFWNMACC_VF, "ASC?k", vector},
  {"vfwmsac_vv", MATCH_VFWMSAC_VV, MASK_VFWMSAC_VV, "ABC?k", vector},
  {"vfwmsac_vf", MATCH_VFWMSAC_VF, MASK_VFWMSAC_VF, "ASC?k", vector},
  {"vfwnmsac_vv", MATCH_VFWNMSAC_VV, MASK_VFWNMSAC_VV, "ABC?k", vector},
  {"vfwnmsac_vf", MATCH_VFWNMSAC_VF, MASK_VFWNMSAC_VF, "ASC?k", vector},
  {"vfext_vf2", MATCH_VFEXT_VF2, MASK_VFEXT_VF2, "AC?k", zvfofp4min},
  {"vfncvt_f_f_q", MATCH_VFNCVT_F_F_Q, MASK_VFNCVT_F_F_Q, "AC?k", zvfofp8min},
  {"vfncvt_sat_f_f_q", MATCH_VFNCVT_SAT_F_F_Q, MASK_VFNCVT_SAT_F_F_Q, "AC?k", zvfofp8min},
  {"vfncvtbf16_sat_f_f_w", MATCH_VFNCVTBF16_SAT_F_F_W, MASK_VFNCVTBF16_SAT_F_F_W, "AC?k", zvfofp8min},
  {"vfncvtbf16_f_f_w", MATCH_VFNCVTBF16_F_F_W, MASK_VFNCVTBF16_F_F_W, "AC?k", zvfbfmin},
  {"vfwcvtbf16_f_f_v", MATCH_VFWCVTBF16_F_F_V, MASK_VFWCVTBF16_F_F_V, "AC?k", zvfbfmin},
  {"vfwmaccbf16_vv", MATCH_VFWMACCBF16_VV, MASK_VFWMACCBF16_VV, "ACB?k", zvfbfwma},
  {"vfwmaccbf16_vf", MATCH_VFWMACCBF16_VF, MASK_VFWMACCBF16_VF, "ACS?k", zvfbfwma},
  {"vabs_v", MATCH_VABS_V, MASK_VABS_V, "AC?k", zvabd},
  {"vabd_vv", MATCH_VABD_VV, MASK_VABD_VV, "ACB?k", zvabd},
  {"vabdu_vv", MATCH_VABDU_VV, MASK_VABDU_VV, "ACB?k", zvabd},
  {"vwabda_vv", MATCH_VWABDA_VV, MASK_VWABDA_VV, "ABC?k", zvabd},
  {"vwabdau_vv", MATCH_VWABDAU_VV, MASK_VWABDAU_VV, "ABC?k", zvabd},
  {"vzip_vv", MATCH_VZIP_VV, MASK_VZIP_VV, "ACB?k", zvzip},
  {"vunzipe_v", MATCH_VUNZIPE_V, MASK_VUNZIPE_V, "AC?k", zvzip},
  {"vunzipo_v", MATCH_VUNZIPO_V, MASK_VUNZIPO_V, "AC?k", zvzip},
  {"vpaire_vv", MATCH_VPAIRE_VV, MASK_VPAIRE_VV, "ACB?k", zvzip},
  {"vpairo_vv", MATCH_VPAIRO_VV, MASK_VPAIRO_VV, "ACB?k", zvzip},
  {"vandn_vv", MATCH_VANDN_VV, MASK_VANDN_VV, "ACB?k", zvbb},
  {"vandn_vx", MATCH_VANDN_VX, MASK_VANDN_VX, "ACs?k", zvbb},
  {"vbrev_v", MATCH_VBREV_V, MASK_VBREV_V, "AC?k", zvbb},
  {"vbrev8_v", MATCH_VBREV8_V, MASK_VBREV8_V, "AC?k", zvbb},
  {"vrev8_v", MATCH_VREV8_V, MASK_VREV8_V, "AC?k", zvbb},
  {"vclz_v", MATCH_VCLZ_V, MASK_VCLZ_V, "AC?k", zvbb},
  {"vctz_v", MATCH_VCTZ_V, MASK_VCTZ_V, "AC?k", zvbb},
  {"vcpop_v", MATCH_VCPOP_V, MASK_VCPOP_V, "AC?k", zvbb},
  {"vrol_vv", MATCH_VROL_VV, MASK_VROL_VV, "ACB?k", zvbb},
  {"vrol_vx", MATCH_VROL_VX, MASK_VROL_VX, "ACs?k", zvbb},
  {"vror_vv", MATCH_VROR_VV, MASK_VROR_VV, "ACB?k", zvbb},
  {"vror_vx", MATCH_VROR_VX, MASK_VROR_VX, "ACs?k", zvbb},
  {"vror_vi", MATCH_VROR_VI, MASK_VROR_VI, "AC6?k", zvbb},
  {"vwsll_vv", MATCH_VWSLL_VV, MASK_VWSLL_VV, "ACB?k", zvbb},
  {"vwsll_vx", MATCH_VWSLL_VX, MASK_VWSLL_VX, "ACs?k", zvbb},
  {"vwsll_vi", MATCH_VWSLL_VI, MASK_VWSLL_VI, "ACz?k", zvbb},
  {"vclmul_vv", MATCH_VCLMUL_VV, MASK_VCLMUL_VV, "ACB?k", zvbc},
  {"vclmul_vx", MATCH_VCLMUL_VX, MASK_VCLMUL_VX, "ACs?k", zvbc},
  {"vclmulh_vv", MATCH_VCLMULH_VV, MASK_VCLMULH_VV, "ACB?k", zvbc},
  {"vclmulh_vx", MATCH_VCLMULH_VX, MASK_VCLMULH_VX, "ACs?k", zvbc},
  {"vgmul_vv", MATCH_VGMUL_VV, MASK_VGMUL_VV, "AC?k", zvkg},
  {"vghsh_vv", MATCH_VGHSH_VV, MASK_VGHSH_VV, "ACB?k", zvkg},
  {"vaesz_vs", MATCH_VAESZ_VS, MASK_VAESZ_VS, "AC?k", zvkned},
  {"vaeskf1_vi", MATCH_VAESKF1_VI, MASK_VAESKF1_VI, "ACz?k", zvkned},
  {"vaeskf2_vi", MATCH_VAESKF2_VI, MASK_VAESKF2_VI, "ACz?k", zvkned},
  {"vsha2ms_vv", MATCH_VSHA2MS_VV, MASK_VSHA2MS_VV, "ACB?k", zvknh},
  {"vsha2ch_vv", MATCH_VSHA2CH_VV, MASK_VSHA2CH_VV, "ACB?k", zvknh},
  {"vsha2cl_vv", MATCH_VSHA2CL_VV, MASK_VSHA2CL_VV, "ACB?k", zvknh},
  {"vsm4k_vi", MATCH_VSM4K_VI, MASK_VSM4K_VI, "ACz?k", zvksed},
  {"vsm4r_vv", MATCH_VSM4R_VV, MASK_VSM4R_VV, "AC?k", zvksed},
  {"vsm4r_vs", MATCH_VSM4R_VS, MASK_VSM4R_VS, "AC?k", zvksed},
  {"vsm3c_vi", MATCH_VSM3C_VI, MASK_VSM3C_VI, "ACz?k", zvksh},
  {"vsm3me_vv", MATCH_VSM3ME_VV, MASK_VSM3ME_VV, "ACB?k", zvksh},
  // vl1re8..vl8re64 whole-register loads
  {"vl1re8.v", MATCH_VL1RE8_V, MASK_VL1RE8_V | (0x7ul<<29), "A(?k", vector},
  {"vl1re16.v", MATCH_VL1RE16_V, MASK_VL1RE16_V | (0x7ul<<29), "A(?k", vector},
  {"vl1re32.v", MATCH_VL1RE32_V, MASK_VL1RE32_V | (0x7ul<<29), "A(?k", vector},
  {"vl1re64.v", MATCH_VL1RE64_V, MASK_VL1RE64_V | (0x7ul<<29), "A(?k", vector},
  {"vl2re8.v", MATCH_VL2RE8_V, MASK_VL2RE8_V | (0x7ul<<29), "A(?k", vector},
  {"vl2re16.v", MATCH_VL2RE16_V, MASK_VL2RE16_V | (0x7ul<<29), "A(?k", vector},
  {"vl2re32.v", MATCH_VL2RE32_V, MASK_VL2RE32_V | (0x7ul<<29), "A(?k", vector},
  {"vl2re64.v", MATCH_VL2RE64_V, MASK_VL2RE64_V | (0x7ul<<29), "A(?k", vector},
  {"vl4re8.v", MATCH_VL4RE8_V, MASK_VL4RE8_V | (0x7ul<<29), "A(?k", vector},
  {"vl4re16.v", MATCH_VL4RE16_V, MASK_VL4RE16_V | (0x7ul<<29), "A(?k", vector},
  {"vl4re32.v", MATCH_VL4RE32_V, MASK_VL4RE32_V | (0x7ul<<29), "A(?k", vector},
  {"vl4re64.v", MATCH_VL4RE64_V, MASK_VL4RE64_V | (0x7ul<<29), "A(?k", vector},
  {"vl8re8.v", MATCH_VL8RE8_V, MASK_VL8RE8_V | (0x7ul<<29), "A(?k", vector},
  {"vl8re16.v", MATCH_VL8RE16_V, MASK_VL8RE16_V | (0x7ul<<29), "A(?k", vector},
  {"vl8re32.v", MATCH_VL8RE32_V, MASK_VL8RE32_V | (0x7ul<<29), "A(?k", vector},
  {"vl8re64.v", MATCH_VL8RE64_V, MASK_VL8RE64_V | (0x7ul<<29), "A(?k", vector},

  // vector segment load/store (9 types × 8 element widths × 8 nf values)
{"vle8.v", MATCH_VLE8_V, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vse8.v", MATCH_VSE8_V, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxei8.v", MATCH_VLUXEI8_V, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxei8.v", MATCH_VSUXEI8_V, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlse8.v", MATCH_VLSE8_V, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vsse8.v", MATCH_VSSE8_V, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxei8.v", MATCH_VLOXEI8_V, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxei8.v", MATCH_VSOXEI8_V, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vle8ff.v", MATCH_VLE8FF_V, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg2e8.v", MATCH_VLE8_V | 0x20000000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg2e8.v", MATCH_VSE8_V | 0x20000000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg2ei8.v", MATCH_VLUXEI8_V | 0x20000000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg2ei8.v", MATCH_VSUXEI8_V | 0x20000000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg2e8.v", MATCH_VLSE8_V | 0x20000000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg2e8.v", MATCH_VSSE8_V | 0x20000000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg2ei8.v", MATCH_VLOXEI8_V | 0x20000000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg2ei8.v", MATCH_VSOXEI8_V | 0x20000000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg2e8ff.v", MATCH_VLE8FF_V | 0x20000000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg3e8.v", MATCH_VLE8_V | 0x40000000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg3e8.v", MATCH_VSE8_V | 0x40000000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg3ei8.v", MATCH_VLUXEI8_V | 0x40000000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg3ei8.v", MATCH_VSUXEI8_V | 0x40000000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg3e8.v", MATCH_VLSE8_V | 0x40000000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg3e8.v", MATCH_VSSE8_V | 0x40000000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg3ei8.v", MATCH_VLOXEI8_V | 0x40000000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg3ei8.v", MATCH_VSOXEI8_V | 0x40000000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg3e8ff.v", MATCH_VLE8FF_V | 0x40000000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg4e8.v", MATCH_VLE8_V | 0x60000000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg4e8.v", MATCH_VSE8_V | 0x60000000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg4ei8.v", MATCH_VLUXEI8_V | 0x60000000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg4ei8.v", MATCH_VSUXEI8_V | 0x60000000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg4e8.v", MATCH_VLSE8_V | 0x60000000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg4e8.v", MATCH_VSSE8_V | 0x60000000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg4ei8.v", MATCH_VLOXEI8_V | 0x60000000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg4ei8.v", MATCH_VSOXEI8_V | 0x60000000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg4e8ff.v", MATCH_VLE8FF_V | 0x60000000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg5e8.v", MATCH_VLE8_V | 0x80000000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg5e8.v", MATCH_VSE8_V | 0x80000000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg5ei8.v", MATCH_VLUXEI8_V | 0x80000000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg5ei8.v", MATCH_VSUXEI8_V | 0x80000000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg5e8.v", MATCH_VLSE8_V | 0x80000000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg5e8.v", MATCH_VSSE8_V | 0x80000000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg5ei8.v", MATCH_VLOXEI8_V | 0x80000000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg5ei8.v", MATCH_VSOXEI8_V | 0x80000000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg5e8ff.v", MATCH_VLE8FF_V | 0x80000000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg6e8.v", MATCH_VLE8_V | 0xa0000000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg6e8.v", MATCH_VSE8_V | 0xa0000000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg6ei8.v", MATCH_VLUXEI8_V | 0xa0000000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg6ei8.v", MATCH_VSUXEI8_V | 0xa0000000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg6e8.v", MATCH_VLSE8_V | 0xa0000000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg6e8.v", MATCH_VSSE8_V | 0xa0000000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg6ei8.v", MATCH_VLOXEI8_V | 0xa0000000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg6ei8.v", MATCH_VSOXEI8_V | 0xa0000000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg6e8ff.v", MATCH_VLE8FF_V | 0xa0000000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg7e8.v", MATCH_VLE8_V | 0xc0000000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg7e8.v", MATCH_VSE8_V | 0xc0000000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg7ei8.v", MATCH_VLUXEI8_V | 0xc0000000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg7ei8.v", MATCH_VSUXEI8_V | 0xc0000000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg7e8.v", MATCH_VLSE8_V | 0xc0000000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg7e8.v", MATCH_VSSE8_V | 0xc0000000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg7ei8.v", MATCH_VLOXEI8_V | 0xc0000000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg7ei8.v", MATCH_VSOXEI8_V | 0xc0000000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg7e8ff.v", MATCH_VLE8FF_V | 0xc0000000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg8e8.v", MATCH_VLE8_V | 0xe0000000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg8e8.v", MATCH_VSE8_V | 0xe0000000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg8ei8.v", MATCH_VLUXEI8_V | 0xe0000000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg8ei8.v", MATCH_VSUXEI8_V | 0xe0000000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg8e8.v", MATCH_VLSE8_V | 0xe0000000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg8e8.v", MATCH_VSSE8_V | 0xe0000000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg8ei8.v", MATCH_VLOXEI8_V | 0xe0000000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg8ei8.v", MATCH_VSOXEI8_V | 0xe0000000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg8e8ff.v", MATCH_VLE8FF_V | 0xe0000000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vle16.v", MATCH_VLE8_V | 0x5000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vse16.v", MATCH_VSE8_V | 0x5000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxei16.v", MATCH_VLUXEI8_V | 0x5000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxei16.v", MATCH_VSUXEI8_V | 0x5000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlse16.v", MATCH_VLSE8_V | 0x5000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vsse16.v", MATCH_VSSE8_V | 0x5000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxei16.v", MATCH_VLOXEI8_V | 0x5000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxei16.v", MATCH_VSOXEI8_V | 0x5000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vle16ff.v", MATCH_VLE8FF_V | 0x5000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg2e16.v", MATCH_VLE8_V | 0x20000000u | 0x5000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg2e16.v", MATCH_VSE8_V | 0x20000000u | 0x5000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg2ei16.v", MATCH_VLUXEI8_V | 0x20000000u | 0x5000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg2ei16.v", MATCH_VSUXEI8_V | 0x20000000u | 0x5000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg2e16.v", MATCH_VLSE8_V | 0x20000000u | 0x5000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg2e16.v", MATCH_VSSE8_V | 0x20000000u | 0x5000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg2ei16.v", MATCH_VLOXEI8_V | 0x20000000u | 0x5000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg2ei16.v", MATCH_VSOXEI8_V | 0x20000000u | 0x5000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg2e16ff.v", MATCH_VLE8FF_V | 0x20000000u | 0x5000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg3e16.v", MATCH_VLE8_V | 0x40000000u | 0x5000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg3e16.v", MATCH_VSE8_V | 0x40000000u | 0x5000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg3ei16.v", MATCH_VLUXEI8_V | 0x40000000u | 0x5000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg3ei16.v", MATCH_VSUXEI8_V | 0x40000000u | 0x5000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg3e16.v", MATCH_VLSE8_V | 0x40000000u | 0x5000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg3e16.v", MATCH_VSSE8_V | 0x40000000u | 0x5000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg3ei16.v", MATCH_VLOXEI8_V | 0x40000000u | 0x5000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg3ei16.v", MATCH_VSOXEI8_V | 0x40000000u | 0x5000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg3e16ff.v", MATCH_VLE8FF_V | 0x40000000u | 0x5000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg4e16.v", MATCH_VLE8_V | 0x60000000u | 0x5000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg4e16.v", MATCH_VSE8_V | 0x60000000u | 0x5000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg4ei16.v", MATCH_VLUXEI8_V | 0x60000000u | 0x5000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg4ei16.v", MATCH_VSUXEI8_V | 0x60000000u | 0x5000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg4e16.v", MATCH_VLSE8_V | 0x60000000u | 0x5000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg4e16.v", MATCH_VSSE8_V | 0x60000000u | 0x5000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg4ei16.v", MATCH_VLOXEI8_V | 0x60000000u | 0x5000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg4ei16.v", MATCH_VSOXEI8_V | 0x60000000u | 0x5000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg4e16ff.v", MATCH_VLE8FF_V | 0x60000000u | 0x5000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg5e16.v", MATCH_VLE8_V | 0x80000000u | 0x5000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg5e16.v", MATCH_VSE8_V | 0x80000000u | 0x5000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg5ei16.v", MATCH_VLUXEI8_V | 0x80000000u | 0x5000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg5ei16.v", MATCH_VSUXEI8_V | 0x80000000u | 0x5000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg5e16.v", MATCH_VLSE8_V | 0x80000000u | 0x5000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg5e16.v", MATCH_VSSE8_V | 0x80000000u | 0x5000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg5ei16.v", MATCH_VLOXEI8_V | 0x80000000u | 0x5000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg5ei16.v", MATCH_VSOXEI8_V | 0x80000000u | 0x5000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg5e16ff.v", MATCH_VLE8FF_V | 0x80000000u | 0x5000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg6e16.v", MATCH_VLE8_V | 0xa0000000u | 0x5000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg6e16.v", MATCH_VSE8_V | 0xa0000000u | 0x5000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg6ei16.v", MATCH_VLUXEI8_V | 0xa0000000u | 0x5000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg6ei16.v", MATCH_VSUXEI8_V | 0xa0000000u | 0x5000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg6e16.v", MATCH_VLSE8_V | 0xa0000000u | 0x5000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg6e16.v", MATCH_VSSE8_V | 0xa0000000u | 0x5000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg6ei16.v", MATCH_VLOXEI8_V | 0xa0000000u | 0x5000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg6ei16.v", MATCH_VSOXEI8_V | 0xa0000000u | 0x5000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg6e16ff.v", MATCH_VLE8FF_V | 0xa0000000u | 0x5000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg7e16.v", MATCH_VLE8_V | 0xc0000000u | 0x5000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg7e16.v", MATCH_VSE8_V | 0xc0000000u | 0x5000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg7ei16.v", MATCH_VLUXEI8_V | 0xc0000000u | 0x5000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg7ei16.v", MATCH_VSUXEI8_V | 0xc0000000u | 0x5000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg7e16.v", MATCH_VLSE8_V | 0xc0000000u | 0x5000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg7e16.v", MATCH_VSSE8_V | 0xc0000000u | 0x5000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg7ei16.v", MATCH_VLOXEI8_V | 0xc0000000u | 0x5000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg7ei16.v", MATCH_VSOXEI8_V | 0xc0000000u | 0x5000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg7e16ff.v", MATCH_VLE8FF_V | 0xc0000000u | 0x5000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg8e16.v", MATCH_VLE8_V | 0xe0000000u | 0x5000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg8e16.v", MATCH_VSE8_V | 0xe0000000u | 0x5000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg8ei16.v", MATCH_VLUXEI8_V | 0xe0000000u | 0x5000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg8ei16.v", MATCH_VSUXEI8_V | 0xe0000000u | 0x5000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg8e16.v", MATCH_VLSE8_V | 0xe0000000u | 0x5000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg8e16.v", MATCH_VSSE8_V | 0xe0000000u | 0x5000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg8ei16.v", MATCH_VLOXEI8_V | 0xe0000000u | 0x5000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg8ei16.v", MATCH_VSOXEI8_V | 0xe0000000u | 0x5000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg8e16ff.v", MATCH_VLE8FF_V | 0xe0000000u | 0x5000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vle32.v", MATCH_VLE8_V | 0x6000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vse32.v", MATCH_VSE8_V | 0x6000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxei32.v", MATCH_VLUXEI8_V | 0x6000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxei32.v", MATCH_VSUXEI8_V | 0x6000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlse32.v", MATCH_VLSE8_V | 0x6000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vsse32.v", MATCH_VSSE8_V | 0x6000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxei32.v", MATCH_VLOXEI8_V | 0x6000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxei32.v", MATCH_VSOXEI8_V | 0x6000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vle32ff.v", MATCH_VLE8FF_V | 0x6000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg2e32.v", MATCH_VLE8_V | 0x20000000u | 0x6000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg2e32.v", MATCH_VSE8_V | 0x20000000u | 0x6000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg2ei32.v", MATCH_VLUXEI8_V | 0x20000000u | 0x6000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg2ei32.v", MATCH_VSUXEI8_V | 0x20000000u | 0x6000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg2e32.v", MATCH_VLSE8_V | 0x20000000u | 0x6000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg2e32.v", MATCH_VSSE8_V | 0x20000000u | 0x6000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg2ei32.v", MATCH_VLOXEI8_V | 0x20000000u | 0x6000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg2ei32.v", MATCH_VSOXEI8_V | 0x20000000u | 0x6000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg2e32ff.v", MATCH_VLE8FF_V | 0x20000000u | 0x6000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg3e32.v", MATCH_VLE8_V | 0x40000000u | 0x6000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg3e32.v", MATCH_VSE8_V | 0x40000000u | 0x6000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg3ei32.v", MATCH_VLUXEI8_V | 0x40000000u | 0x6000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg3ei32.v", MATCH_VSUXEI8_V | 0x40000000u | 0x6000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg3e32.v", MATCH_VLSE8_V | 0x40000000u | 0x6000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg3e32.v", MATCH_VSSE8_V | 0x40000000u | 0x6000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg3ei32.v", MATCH_VLOXEI8_V | 0x40000000u | 0x6000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg3ei32.v", MATCH_VSOXEI8_V | 0x40000000u | 0x6000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg3e32ff.v", MATCH_VLE8FF_V | 0x40000000u | 0x6000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg4e32.v", MATCH_VLE8_V | 0x60000000u | 0x6000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg4e32.v", MATCH_VSE8_V | 0x60000000u | 0x6000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg4ei32.v", MATCH_VLUXEI8_V | 0x60000000u | 0x6000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg4ei32.v", MATCH_VSUXEI8_V | 0x60000000u | 0x6000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg4e32.v", MATCH_VLSE8_V | 0x60000000u | 0x6000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg4e32.v", MATCH_VSSE8_V | 0x60000000u | 0x6000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg4ei32.v", MATCH_VLOXEI8_V | 0x60000000u | 0x6000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg4ei32.v", MATCH_VSOXEI8_V | 0x60000000u | 0x6000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg4e32ff.v", MATCH_VLE8FF_V | 0x60000000u | 0x6000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg5e32.v", MATCH_VLE8_V | 0x80000000u | 0x6000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg5e32.v", MATCH_VSE8_V | 0x80000000u | 0x6000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg5ei32.v", MATCH_VLUXEI8_V | 0x80000000u | 0x6000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg5ei32.v", MATCH_VSUXEI8_V | 0x80000000u | 0x6000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg5e32.v", MATCH_VLSE8_V | 0x80000000u | 0x6000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg5e32.v", MATCH_VSSE8_V | 0x80000000u | 0x6000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg5ei32.v", MATCH_VLOXEI8_V | 0x80000000u | 0x6000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg5ei32.v", MATCH_VSOXEI8_V | 0x80000000u | 0x6000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg5e32ff.v", MATCH_VLE8FF_V | 0x80000000u | 0x6000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg6e32.v", MATCH_VLE8_V | 0xa0000000u | 0x6000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg6e32.v", MATCH_VSE8_V | 0xa0000000u | 0x6000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg6ei32.v", MATCH_VLUXEI8_V | 0xa0000000u | 0x6000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg6ei32.v", MATCH_VSUXEI8_V | 0xa0000000u | 0x6000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg6e32.v", MATCH_VLSE8_V | 0xa0000000u | 0x6000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg6e32.v", MATCH_VSSE8_V | 0xa0000000u | 0x6000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg6ei32.v", MATCH_VLOXEI8_V | 0xa0000000u | 0x6000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg6ei32.v", MATCH_VSOXEI8_V | 0xa0000000u | 0x6000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg6e32ff.v", MATCH_VLE8FF_V | 0xa0000000u | 0x6000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg7e32.v", MATCH_VLE8_V | 0xc0000000u | 0x6000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg7e32.v", MATCH_VSE8_V | 0xc0000000u | 0x6000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg7ei32.v", MATCH_VLUXEI8_V | 0xc0000000u | 0x6000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg7ei32.v", MATCH_VSUXEI8_V | 0xc0000000u | 0x6000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg7e32.v", MATCH_VLSE8_V | 0xc0000000u | 0x6000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg7e32.v", MATCH_VSSE8_V | 0xc0000000u | 0x6000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg7ei32.v", MATCH_VLOXEI8_V | 0xc0000000u | 0x6000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg7ei32.v", MATCH_VSOXEI8_V | 0xc0000000u | 0x6000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg7e32ff.v", MATCH_VLE8FF_V | 0xc0000000u | 0x6000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg8e32.v", MATCH_VLE8_V | 0xe0000000u | 0x6000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg8e32.v", MATCH_VSE8_V | 0xe0000000u | 0x6000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg8ei32.v", MATCH_VLUXEI8_V | 0xe0000000u | 0x6000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg8ei32.v", MATCH_VSUXEI8_V | 0xe0000000u | 0x6000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg8e32.v", MATCH_VLSE8_V | 0xe0000000u | 0x6000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg8e32.v", MATCH_VSSE8_V | 0xe0000000u | 0x6000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg8ei32.v", MATCH_VLOXEI8_V | 0xe0000000u | 0x6000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg8ei32.v", MATCH_VSOXEI8_V | 0xe0000000u | 0x6000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg8e32ff.v", MATCH_VLE8FF_V | 0xe0000000u | 0x6000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vle64.v", MATCH_VLE8_V | 0x7000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vse64.v", MATCH_VSE8_V | 0x7000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxei64.v", MATCH_VLUXEI8_V | 0x7000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxei64.v", MATCH_VSUXEI8_V | 0x7000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlse64.v", MATCH_VLSE8_V | 0x7000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vsse64.v", MATCH_VSSE8_V | 0x7000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxei64.v", MATCH_VLOXEI8_V | 0x7000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxei64.v", MATCH_VSOXEI8_V | 0x7000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vle64ff.v", MATCH_VLE8FF_V | 0x7000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg2e64.v", MATCH_VLE8_V | 0x20000000u | 0x7000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg2e64.v", MATCH_VSE8_V | 0x20000000u | 0x7000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg2ei64.v", MATCH_VLUXEI8_V | 0x20000000u | 0x7000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg2ei64.v", MATCH_VSUXEI8_V | 0x20000000u | 0x7000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg2e64.v", MATCH_VLSE8_V | 0x20000000u | 0x7000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg2e64.v", MATCH_VSSE8_V | 0x20000000u | 0x7000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg2ei64.v", MATCH_VLOXEI8_V | 0x20000000u | 0x7000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg2ei64.v", MATCH_VSOXEI8_V | 0x20000000u | 0x7000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg2e64ff.v", MATCH_VLE8FF_V | 0x20000000u | 0x7000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg3e64.v", MATCH_VLE8_V | 0x40000000u | 0x7000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg3e64.v", MATCH_VSE8_V | 0x40000000u | 0x7000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg3ei64.v", MATCH_VLUXEI8_V | 0x40000000u | 0x7000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg3ei64.v", MATCH_VSUXEI8_V | 0x40000000u | 0x7000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg3e64.v", MATCH_VLSE8_V | 0x40000000u | 0x7000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg3e64.v", MATCH_VSSE8_V | 0x40000000u | 0x7000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg3ei64.v", MATCH_VLOXEI8_V | 0x40000000u | 0x7000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg3ei64.v", MATCH_VSOXEI8_V | 0x40000000u | 0x7000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg3e64ff.v", MATCH_VLE8FF_V | 0x40000000u | 0x7000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg4e64.v", MATCH_VLE8_V | 0x60000000u | 0x7000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg4e64.v", MATCH_VSE8_V | 0x60000000u | 0x7000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg4ei64.v", MATCH_VLUXEI8_V | 0x60000000u | 0x7000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg4ei64.v", MATCH_VSUXEI8_V | 0x60000000u | 0x7000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg4e64.v", MATCH_VLSE8_V | 0x60000000u | 0x7000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg4e64.v", MATCH_VSSE8_V | 0x60000000u | 0x7000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg4ei64.v", MATCH_VLOXEI8_V | 0x60000000u | 0x7000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg4ei64.v", MATCH_VSOXEI8_V | 0x60000000u | 0x7000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg4e64ff.v", MATCH_VLE8FF_V | 0x60000000u | 0x7000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg5e64.v", MATCH_VLE8_V | 0x80000000u | 0x7000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg5e64.v", MATCH_VSE8_V | 0x80000000u | 0x7000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg5ei64.v", MATCH_VLUXEI8_V | 0x80000000u | 0x7000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg5ei64.v", MATCH_VSUXEI8_V | 0x80000000u | 0x7000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg5e64.v", MATCH_VLSE8_V | 0x80000000u | 0x7000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg5e64.v", MATCH_VSSE8_V | 0x80000000u | 0x7000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg5ei64.v", MATCH_VLOXEI8_V | 0x80000000u | 0x7000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg5ei64.v", MATCH_VSOXEI8_V | 0x80000000u | 0x7000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg5e64ff.v", MATCH_VLE8FF_V | 0x80000000u | 0x7000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg6e64.v", MATCH_VLE8_V | 0xa0000000u | 0x7000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg6e64.v", MATCH_VSE8_V | 0xa0000000u | 0x7000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg6ei64.v", MATCH_VLUXEI8_V | 0xa0000000u | 0x7000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg6ei64.v", MATCH_VSUXEI8_V | 0xa0000000u | 0x7000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg6e64.v", MATCH_VLSE8_V | 0xa0000000u | 0x7000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg6e64.v", MATCH_VSSE8_V | 0xa0000000u | 0x7000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg6ei64.v", MATCH_VLOXEI8_V | 0xa0000000u | 0x7000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg6ei64.v", MATCH_VSOXEI8_V | 0xa0000000u | 0x7000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg6e64ff.v", MATCH_VLE8FF_V | 0xa0000000u | 0x7000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg7e64.v", MATCH_VLE8_V | 0xc0000000u | 0x7000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg7e64.v", MATCH_VSE8_V | 0xc0000000u | 0x7000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg7ei64.v", MATCH_VLUXEI8_V | 0xc0000000u | 0x7000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg7ei64.v", MATCH_VSUXEI8_V | 0xc0000000u | 0x7000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg7e64.v", MATCH_VLSE8_V | 0xc0000000u | 0x7000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg7e64.v", MATCH_VSSE8_V | 0xc0000000u | 0x7000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg7ei64.v", MATCH_VLOXEI8_V | 0xc0000000u | 0x7000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg7ei64.v", MATCH_VSOXEI8_V | 0xc0000000u | 0x7000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg7e64ff.v", MATCH_VLE8FF_V | 0xc0000000u | 0x7000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg8e64.v", MATCH_VLE8_V | 0xe0000000u | 0x7000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg8e64.v", MATCH_VSE8_V | 0xe0000000u | 0x7000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg8ei64.v", MATCH_VLUXEI8_V | 0xe0000000u | 0x7000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg8ei64.v", MATCH_VSUXEI8_V | 0xe0000000u | 0x7000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg8e64.v", MATCH_VLSE8_V | 0xe0000000u | 0x7000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg8e64.v", MATCH_VSSE8_V | 0xe0000000u | 0x7000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg8ei64.v", MATCH_VLOXEI8_V | 0xe0000000u | 0x7000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg8ei64.v", MATCH_VSOXEI8_V | 0xe0000000u | 0x7000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg8e64ff.v", MATCH_VLE8FF_V | 0xe0000000u | 0x7000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vle128.v", MATCH_VLE8_V | 0x10000000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vse128.v", MATCH_VSE8_V | 0x10000000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxei128.v", MATCH_VLUXEI8_V | 0x10000000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxei128.v", MATCH_VSUXEI8_V | 0x10000000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlse128.v", MATCH_VLSE8_V | 0x10000000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vsse128.v", MATCH_VSSE8_V | 0x10000000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxei128.v", MATCH_VLOXEI8_V | 0x10000000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxei128.v", MATCH_VSOXEI8_V | 0x10000000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vle128ff.v", MATCH_VLE8FF_V | 0x10000000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg2e128.v", MATCH_VLE8_V | 0x20000000u | 0x10000000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg2e128.v", MATCH_VSE8_V | 0x20000000u | 0x10000000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg2ei128.v", MATCH_VLUXEI8_V | 0x20000000u | 0x10000000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg2ei128.v", MATCH_VSUXEI8_V | 0x20000000u | 0x10000000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg2e128.v", MATCH_VLSE8_V | 0x20000000u | 0x10000000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg2e128.v", MATCH_VSSE8_V | 0x20000000u | 0x10000000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg2ei128.v", MATCH_VLOXEI8_V | 0x20000000u | 0x10000000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg2ei128.v", MATCH_VSOXEI8_V | 0x20000000u | 0x10000000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg2e128ff.v", MATCH_VLE8FF_V | 0x20000000u | 0x10000000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg3e128.v", MATCH_VLE8_V | 0x40000000u | 0x10000000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg3e128.v", MATCH_VSE8_V | 0x40000000u | 0x10000000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg3ei128.v", MATCH_VLUXEI8_V | 0x40000000u | 0x10000000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg3ei128.v", MATCH_VSUXEI8_V | 0x40000000u | 0x10000000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg3e128.v", MATCH_VLSE8_V | 0x40000000u | 0x10000000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg3e128.v", MATCH_VSSE8_V | 0x40000000u | 0x10000000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg3ei128.v", MATCH_VLOXEI8_V | 0x40000000u | 0x10000000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg3ei128.v", MATCH_VSOXEI8_V | 0x40000000u | 0x10000000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg3e128ff.v", MATCH_VLE8FF_V | 0x40000000u | 0x10000000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg4e128.v", MATCH_VLE8_V | 0x60000000u | 0x10000000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg4e128.v", MATCH_VSE8_V | 0x60000000u | 0x10000000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg4ei128.v", MATCH_VLUXEI8_V | 0x60000000u | 0x10000000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg4ei128.v", MATCH_VSUXEI8_V | 0x60000000u | 0x10000000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg4e128.v", MATCH_VLSE8_V | 0x60000000u | 0x10000000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg4e128.v", MATCH_VSSE8_V | 0x60000000u | 0x10000000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg4ei128.v", MATCH_VLOXEI8_V | 0x60000000u | 0x10000000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg4ei128.v", MATCH_VSOXEI8_V | 0x60000000u | 0x10000000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg4e128ff.v", MATCH_VLE8FF_V | 0x60000000u | 0x10000000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg5e128.v", MATCH_VLE8_V | 0x80000000u | 0x10000000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg5e128.v", MATCH_VSE8_V | 0x80000000u | 0x10000000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg5ei128.v", MATCH_VLUXEI8_V | 0x80000000u | 0x10000000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg5ei128.v", MATCH_VSUXEI8_V | 0x80000000u | 0x10000000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg5e128.v", MATCH_VLSE8_V | 0x80000000u | 0x10000000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg5e128.v", MATCH_VSSE8_V | 0x80000000u | 0x10000000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg5ei128.v", MATCH_VLOXEI8_V | 0x80000000u | 0x10000000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg5ei128.v", MATCH_VSOXEI8_V | 0x80000000u | 0x10000000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg5e128ff.v", MATCH_VLE8FF_V | 0x80000000u | 0x10000000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg6e128.v", MATCH_VLE8_V | 0xa0000000u | 0x10000000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg6e128.v", MATCH_VSE8_V | 0xa0000000u | 0x10000000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg6ei128.v", MATCH_VLUXEI8_V | 0xa0000000u | 0x10000000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg6ei128.v", MATCH_VSUXEI8_V | 0xa0000000u | 0x10000000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg6e128.v", MATCH_VLSE8_V | 0xa0000000u | 0x10000000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg6e128.v", MATCH_VSSE8_V | 0xa0000000u | 0x10000000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg6ei128.v", MATCH_VLOXEI8_V | 0xa0000000u | 0x10000000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg6ei128.v", MATCH_VSOXEI8_V | 0xa0000000u | 0x10000000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg6e128ff.v", MATCH_VLE8FF_V | 0xa0000000u | 0x10000000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg7e128.v", MATCH_VLE8_V | 0xc0000000u | 0x10000000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg7e128.v", MATCH_VSE8_V | 0xc0000000u | 0x10000000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg7ei128.v", MATCH_VLUXEI8_V | 0xc0000000u | 0x10000000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg7ei128.v", MATCH_VSUXEI8_V | 0xc0000000u | 0x10000000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg7e128.v", MATCH_VLSE8_V | 0xc0000000u | 0x10000000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg7e128.v", MATCH_VSSE8_V | 0xc0000000u | 0x10000000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg7ei128.v", MATCH_VLOXEI8_V | 0xc0000000u | 0x10000000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg7ei128.v", MATCH_VSOXEI8_V | 0xc0000000u | 0x10000000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg7e128ff.v", MATCH_VLE8FF_V | 0xc0000000u | 0x10000000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg8e128.v", MATCH_VLE8_V | 0xe0000000u | 0x10000000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg8e128.v", MATCH_VSE8_V | 0xe0000000u | 0x10000000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg8ei128.v", MATCH_VLUXEI8_V | 0xe0000000u | 0x10000000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg8ei128.v", MATCH_VSUXEI8_V | 0xe0000000u | 0x10000000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg8e128.v", MATCH_VLSE8_V | 0xe0000000u | 0x10000000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg8e128.v", MATCH_VSSE8_V | 0xe0000000u | 0x10000000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg8ei128.v", MATCH_VLOXEI8_V | 0xe0000000u | 0x10000000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg8ei128.v", MATCH_VSOXEI8_V | 0xe0000000u | 0x10000000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg8e128ff.v", MATCH_VLE8FF_V | 0xe0000000u | 0x10000000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vle256.v", MATCH_VLE8_V | 0x10005000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vse256.v", MATCH_VSE8_V | 0x10005000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxei256.v", MATCH_VLUXEI8_V | 0x10005000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxei256.v", MATCH_VSUXEI8_V | 0x10005000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlse256.v", MATCH_VLSE8_V | 0x10005000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vsse256.v", MATCH_VSSE8_V | 0x10005000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxei256.v", MATCH_VLOXEI8_V | 0x10005000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxei256.v", MATCH_VSOXEI8_V | 0x10005000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vle256ff.v", MATCH_VLE8FF_V | 0x10005000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg2e256.v", MATCH_VLE8_V | 0x20000000u | 0x10005000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg2e256.v", MATCH_VSE8_V | 0x20000000u | 0x10005000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg2ei256.v", MATCH_VLUXEI8_V | 0x20000000u | 0x10005000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg2ei256.v", MATCH_VSUXEI8_V | 0x20000000u | 0x10005000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg2e256.v", MATCH_VLSE8_V | 0x20000000u | 0x10005000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg2e256.v", MATCH_VSSE8_V | 0x20000000u | 0x10005000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg2ei256.v", MATCH_VLOXEI8_V | 0x20000000u | 0x10005000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg2ei256.v", MATCH_VSOXEI8_V | 0x20000000u | 0x10005000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg2e256ff.v", MATCH_VLE8FF_V | 0x20000000u | 0x10005000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg3e256.v", MATCH_VLE8_V | 0x40000000u | 0x10005000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg3e256.v", MATCH_VSE8_V | 0x40000000u | 0x10005000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg3ei256.v", MATCH_VLUXEI8_V | 0x40000000u | 0x10005000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg3ei256.v", MATCH_VSUXEI8_V | 0x40000000u | 0x10005000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg3e256.v", MATCH_VLSE8_V | 0x40000000u | 0x10005000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg3e256.v", MATCH_VSSE8_V | 0x40000000u | 0x10005000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg3ei256.v", MATCH_VLOXEI8_V | 0x40000000u | 0x10005000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg3ei256.v", MATCH_VSOXEI8_V | 0x40000000u | 0x10005000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg3e256ff.v", MATCH_VLE8FF_V | 0x40000000u | 0x10005000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg4e256.v", MATCH_VLE8_V | 0x60000000u | 0x10005000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg4e256.v", MATCH_VSE8_V | 0x60000000u | 0x10005000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg4ei256.v", MATCH_VLUXEI8_V | 0x60000000u | 0x10005000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg4ei256.v", MATCH_VSUXEI8_V | 0x60000000u | 0x10005000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg4e256.v", MATCH_VLSE8_V | 0x60000000u | 0x10005000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg4e256.v", MATCH_VSSE8_V | 0x60000000u | 0x10005000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg4ei256.v", MATCH_VLOXEI8_V | 0x60000000u | 0x10005000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg4ei256.v", MATCH_VSOXEI8_V | 0x60000000u | 0x10005000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg4e256ff.v", MATCH_VLE8FF_V | 0x60000000u | 0x10005000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg5e256.v", MATCH_VLE8_V | 0x80000000u | 0x10005000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg5e256.v", MATCH_VSE8_V | 0x80000000u | 0x10005000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg5ei256.v", MATCH_VLUXEI8_V | 0x80000000u | 0x10005000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg5ei256.v", MATCH_VSUXEI8_V | 0x80000000u | 0x10005000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg5e256.v", MATCH_VLSE8_V | 0x80000000u | 0x10005000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg5e256.v", MATCH_VSSE8_V | 0x80000000u | 0x10005000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg5ei256.v", MATCH_VLOXEI8_V | 0x80000000u | 0x10005000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg5ei256.v", MATCH_VSOXEI8_V | 0x80000000u | 0x10005000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg5e256ff.v", MATCH_VLE8FF_V | 0x80000000u | 0x10005000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg6e256.v", MATCH_VLE8_V | 0xa0000000u | 0x10005000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg6e256.v", MATCH_VSE8_V | 0xa0000000u | 0x10005000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg6ei256.v", MATCH_VLUXEI8_V | 0xa0000000u | 0x10005000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg6ei256.v", MATCH_VSUXEI8_V | 0xa0000000u | 0x10005000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg6e256.v", MATCH_VLSE8_V | 0xa0000000u | 0x10005000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg6e256.v", MATCH_VSSE8_V | 0xa0000000u | 0x10005000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg6ei256.v", MATCH_VLOXEI8_V | 0xa0000000u | 0x10005000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg6ei256.v", MATCH_VSOXEI8_V | 0xa0000000u | 0x10005000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg6e256ff.v", MATCH_VLE8FF_V | 0xa0000000u | 0x10005000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg7e256.v", MATCH_VLE8_V | 0xc0000000u | 0x10005000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg7e256.v", MATCH_VSE8_V | 0xc0000000u | 0x10005000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg7ei256.v", MATCH_VLUXEI8_V | 0xc0000000u | 0x10005000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg7ei256.v", MATCH_VSUXEI8_V | 0xc0000000u | 0x10005000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg7e256.v", MATCH_VLSE8_V | 0xc0000000u | 0x10005000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg7e256.v", MATCH_VSSE8_V | 0xc0000000u | 0x10005000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg7ei256.v", MATCH_VLOXEI8_V | 0xc0000000u | 0x10005000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg7ei256.v", MATCH_VSOXEI8_V | 0xc0000000u | 0x10005000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg7e256ff.v", MATCH_VLE8FF_V | 0xc0000000u | 0x10005000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg8e256.v", MATCH_VLE8_V | 0xe0000000u | 0x10005000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg8e256.v", MATCH_VSE8_V | 0xe0000000u | 0x10005000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg8ei256.v", MATCH_VLUXEI8_V | 0xe0000000u | 0x10005000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg8ei256.v", MATCH_VSUXEI8_V | 0xe0000000u | 0x10005000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg8e256.v", MATCH_VLSE8_V | 0xe0000000u | 0x10005000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg8e256.v", MATCH_VSSE8_V | 0xe0000000u | 0x10005000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg8ei256.v", MATCH_VLOXEI8_V | 0xe0000000u | 0x10005000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg8ei256.v", MATCH_VSOXEI8_V | 0xe0000000u | 0x10005000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg8e256ff.v", MATCH_VLE8FF_V | 0xe0000000u | 0x10005000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vle512.v", MATCH_VLE8_V | 0x10006000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vse512.v", MATCH_VSE8_V | 0x10006000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxei512.v", MATCH_VLUXEI8_V | 0x10006000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxei512.v", MATCH_VSUXEI8_V | 0x10006000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlse512.v", MATCH_VLSE8_V | 0x10006000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vsse512.v", MATCH_VSSE8_V | 0x10006000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxei512.v", MATCH_VLOXEI8_V | 0x10006000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxei512.v", MATCH_VSOXEI8_V | 0x10006000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vle512ff.v", MATCH_VLE8FF_V | 0x10006000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg2e512.v", MATCH_VLE8_V | 0x20000000u | 0x10006000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg2e512.v", MATCH_VSE8_V | 0x20000000u | 0x10006000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg2ei512.v", MATCH_VLUXEI8_V | 0x20000000u | 0x10006000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg2ei512.v", MATCH_VSUXEI8_V | 0x20000000u | 0x10006000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg2e512.v", MATCH_VLSE8_V | 0x20000000u | 0x10006000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg2e512.v", MATCH_VSSE8_V | 0x20000000u | 0x10006000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg2ei512.v", MATCH_VLOXEI8_V | 0x20000000u | 0x10006000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg2ei512.v", MATCH_VSOXEI8_V | 0x20000000u | 0x10006000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg2e512ff.v", MATCH_VLE8FF_V | 0x20000000u | 0x10006000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg3e512.v", MATCH_VLE8_V | 0x40000000u | 0x10006000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg3e512.v", MATCH_VSE8_V | 0x40000000u | 0x10006000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg3ei512.v", MATCH_VLUXEI8_V | 0x40000000u | 0x10006000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg3ei512.v", MATCH_VSUXEI8_V | 0x40000000u | 0x10006000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg3e512.v", MATCH_VLSE8_V | 0x40000000u | 0x10006000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg3e512.v", MATCH_VSSE8_V | 0x40000000u | 0x10006000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg3ei512.v", MATCH_VLOXEI8_V | 0x40000000u | 0x10006000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg3ei512.v", MATCH_VSOXEI8_V | 0x40000000u | 0x10006000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg3e512ff.v", MATCH_VLE8FF_V | 0x40000000u | 0x10006000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg4e512.v", MATCH_VLE8_V | 0x60000000u | 0x10006000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg4e512.v", MATCH_VSE8_V | 0x60000000u | 0x10006000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg4ei512.v", MATCH_VLUXEI8_V | 0x60000000u | 0x10006000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg4ei512.v", MATCH_VSUXEI8_V | 0x60000000u | 0x10006000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg4e512.v", MATCH_VLSE8_V | 0x60000000u | 0x10006000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg4e512.v", MATCH_VSSE8_V | 0x60000000u | 0x10006000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg4ei512.v", MATCH_VLOXEI8_V | 0x60000000u | 0x10006000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg4ei512.v", MATCH_VSOXEI8_V | 0x60000000u | 0x10006000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg4e512ff.v", MATCH_VLE8FF_V | 0x60000000u | 0x10006000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg5e512.v", MATCH_VLE8_V | 0x80000000u | 0x10006000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg5e512.v", MATCH_VSE8_V | 0x80000000u | 0x10006000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg5ei512.v", MATCH_VLUXEI8_V | 0x80000000u | 0x10006000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg5ei512.v", MATCH_VSUXEI8_V | 0x80000000u | 0x10006000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg5e512.v", MATCH_VLSE8_V | 0x80000000u | 0x10006000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg5e512.v", MATCH_VSSE8_V | 0x80000000u | 0x10006000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg5ei512.v", MATCH_VLOXEI8_V | 0x80000000u | 0x10006000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg5ei512.v", MATCH_VSOXEI8_V | 0x80000000u | 0x10006000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg5e512ff.v", MATCH_VLE8FF_V | 0x80000000u | 0x10006000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg6e512.v", MATCH_VLE8_V | 0xa0000000u | 0x10006000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg6e512.v", MATCH_VSE8_V | 0xa0000000u | 0x10006000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg6ei512.v", MATCH_VLUXEI8_V | 0xa0000000u | 0x10006000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg6ei512.v", MATCH_VSUXEI8_V | 0xa0000000u | 0x10006000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg6e512.v", MATCH_VLSE8_V | 0xa0000000u | 0x10006000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg6e512.v", MATCH_VSSE8_V | 0xa0000000u | 0x10006000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg6ei512.v", MATCH_VLOXEI8_V | 0xa0000000u | 0x10006000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg6ei512.v", MATCH_VSOXEI8_V | 0xa0000000u | 0x10006000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg6e512ff.v", MATCH_VLE8FF_V | 0xa0000000u | 0x10006000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg7e512.v", MATCH_VLE8_V | 0xc0000000u | 0x10006000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg7e512.v", MATCH_VSE8_V | 0xc0000000u | 0x10006000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg7ei512.v", MATCH_VLUXEI8_V | 0xc0000000u | 0x10006000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg7ei512.v", MATCH_VSUXEI8_V | 0xc0000000u | 0x10006000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg7e512.v", MATCH_VLSE8_V | 0xc0000000u | 0x10006000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg7e512.v", MATCH_VSSE8_V | 0xc0000000u | 0x10006000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg7ei512.v", MATCH_VLOXEI8_V | 0xc0000000u | 0x10006000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg7ei512.v", MATCH_VSOXEI8_V | 0xc0000000u | 0x10006000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg7e512ff.v", MATCH_VLE8FF_V | 0xc0000000u | 0x10006000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg8e512.v", MATCH_VLE8_V | 0xe0000000u | 0x10006000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg8e512.v", MATCH_VSE8_V | 0xe0000000u | 0x10006000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg8ei512.v", MATCH_VLUXEI8_V | 0xe0000000u | 0x10006000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg8ei512.v", MATCH_VSUXEI8_V | 0xe0000000u | 0x10006000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg8e512.v", MATCH_VLSE8_V | 0xe0000000u | 0x10006000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg8e512.v", MATCH_VSSE8_V | 0xe0000000u | 0x10006000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg8ei512.v", MATCH_VLOXEI8_V | 0xe0000000u | 0x10006000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg8ei512.v", MATCH_VSOXEI8_V | 0xe0000000u | 0x10006000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg8e512ff.v", MATCH_VLE8FF_V | 0xe0000000u | 0x10006000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vle1024.v", MATCH_VLE8_V | 0x10007000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vse1024.v", MATCH_VSE8_V | 0x10007000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxei1024.v", MATCH_VLUXEI8_V | 0x10007000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxei1024.v", MATCH_VSUXEI8_V | 0x10007000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlse1024.v", MATCH_VLSE8_V | 0x10007000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vsse1024.v", MATCH_VSSE8_V | 0x10007000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxei1024.v", MATCH_VLOXEI8_V | 0x10007000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxei1024.v", MATCH_VSOXEI8_V | 0x10007000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vle1024ff.v", MATCH_VLE8FF_V | 0x10007000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg2e1024.v", MATCH_VLE8_V | 0x20000000u | 0x10007000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg2e1024.v", MATCH_VSE8_V | 0x20000000u | 0x10007000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg2ei1024.v", MATCH_VLUXEI8_V | 0x20000000u | 0x10007000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg2ei1024.v", MATCH_VSUXEI8_V | 0x20000000u | 0x10007000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg2e1024.v", MATCH_VLSE8_V | 0x20000000u | 0x10007000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg2e1024.v", MATCH_VSSE8_V | 0x20000000u | 0x10007000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg2ei1024.v", MATCH_VLOXEI8_V | 0x20000000u | 0x10007000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg2ei1024.v", MATCH_VSOXEI8_V | 0x20000000u | 0x10007000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg2e1024ff.v", MATCH_VLE8FF_V | 0x20000000u | 0x10007000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg3e1024.v", MATCH_VLE8_V | 0x40000000u | 0x10007000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg3e1024.v", MATCH_VSE8_V | 0x40000000u | 0x10007000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg3ei1024.v", MATCH_VLUXEI8_V | 0x40000000u | 0x10007000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg3ei1024.v", MATCH_VSUXEI8_V | 0x40000000u | 0x10007000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg3e1024.v", MATCH_VLSE8_V | 0x40000000u | 0x10007000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg3e1024.v", MATCH_VSSE8_V | 0x40000000u | 0x10007000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg3ei1024.v", MATCH_VLOXEI8_V | 0x40000000u | 0x10007000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg3ei1024.v", MATCH_VSOXEI8_V | 0x40000000u | 0x10007000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg3e1024ff.v", MATCH_VLE8FF_V | 0x40000000u | 0x10007000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg4e1024.v", MATCH_VLE8_V | 0x60000000u | 0x10007000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg4e1024.v", MATCH_VSE8_V | 0x60000000u | 0x10007000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg4ei1024.v", MATCH_VLUXEI8_V | 0x60000000u | 0x10007000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg4ei1024.v", MATCH_VSUXEI8_V | 0x60000000u | 0x10007000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg4e1024.v", MATCH_VLSE8_V | 0x60000000u | 0x10007000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg4e1024.v", MATCH_VSSE8_V | 0x60000000u | 0x10007000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg4ei1024.v", MATCH_VLOXEI8_V | 0x60000000u | 0x10007000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg4ei1024.v", MATCH_VSOXEI8_V | 0x60000000u | 0x10007000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg4e1024ff.v", MATCH_VLE8FF_V | 0x60000000u | 0x10007000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg5e1024.v", MATCH_VLE8_V | 0x80000000u | 0x10007000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg5e1024.v", MATCH_VSE8_V | 0x80000000u | 0x10007000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg5ei1024.v", MATCH_VLUXEI8_V | 0x80000000u | 0x10007000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg5ei1024.v", MATCH_VSUXEI8_V | 0x80000000u | 0x10007000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg5e1024.v", MATCH_VLSE8_V | 0x80000000u | 0x10007000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg5e1024.v", MATCH_VSSE8_V | 0x80000000u | 0x10007000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg5ei1024.v", MATCH_VLOXEI8_V | 0x80000000u | 0x10007000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg5ei1024.v", MATCH_VSOXEI8_V | 0x80000000u | 0x10007000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg5e1024ff.v", MATCH_VLE8FF_V | 0x80000000u | 0x10007000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg6e1024.v", MATCH_VLE8_V | 0xa0000000u | 0x10007000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg6e1024.v", MATCH_VSE8_V | 0xa0000000u | 0x10007000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg6ei1024.v", MATCH_VLUXEI8_V | 0xa0000000u | 0x10007000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg6ei1024.v", MATCH_VSUXEI8_V | 0xa0000000u | 0x10007000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg6e1024.v", MATCH_VLSE8_V | 0xa0000000u | 0x10007000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg6e1024.v", MATCH_VSSE8_V | 0xa0000000u | 0x10007000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg6ei1024.v", MATCH_VLOXEI8_V | 0xa0000000u | 0x10007000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg6ei1024.v", MATCH_VSOXEI8_V | 0xa0000000u | 0x10007000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg6e1024ff.v", MATCH_VLE8FF_V | 0xa0000000u | 0x10007000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg7e1024.v", MATCH_VLE8_V | 0xc0000000u | 0x10007000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg7e1024.v", MATCH_VSE8_V | 0xc0000000u | 0x10007000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg7ei1024.v", MATCH_VLUXEI8_V | 0xc0000000u | 0x10007000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg7ei1024.v", MATCH_VSUXEI8_V | 0xc0000000u | 0x10007000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg7e1024.v", MATCH_VLSE8_V | 0xc0000000u | 0x10007000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg7e1024.v", MATCH_VSSE8_V | 0xc0000000u | 0x10007000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg7ei1024.v", MATCH_VLOXEI8_V | 0xc0000000u | 0x10007000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg7ei1024.v", MATCH_VSOXEI8_V | 0xc0000000u | 0x10007000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg7e1024ff.v", MATCH_VLE8FF_V | 0xc0000000u | 0x10007000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},
  {"vlseg8e1024.v", MATCH_VLE8_V | 0xe0000000u | 0x10007000u, MASK_VLE8_V | 0xe0000000u, "A(?k", vector},
  {"vsseg8e1024.v", MATCH_VSE8_V | 0xe0000000u | 0x10007000u, MASK_VSE8_V | 0xe0000000u, "G(?k", vector},
  {"vluxseg8ei1024.v", MATCH_VLUXEI8_V | 0xe0000000u | 0x10007000u, MASK_VLUXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsuxseg8ei1024.v", MATCH_VSUXEI8_V | 0xe0000000u | 0x10007000u, MASK_VSUXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlsseg8e1024.v", MATCH_VLSE8_V | 0xe0000000u | 0x10007000u, MASK_VLSE8_V | 0xe0000000u, "A(t?k", vector},
  {"vssseg8e1024.v", MATCH_VSSE8_V | 0xe0000000u | 0x10007000u, MASK_VSSE8_V | 0xe0000000u, "G(t?k", vector},
  {"vloxseg8ei1024.v", MATCH_VLOXEI8_V | 0xe0000000u | 0x10007000u, MASK_VLOXEI8_V | 0xe0000000u, "A(C?k", vector},
  {"vsoxseg8ei1024.v", MATCH_VSOXEI8_V | 0xe0000000u | 0x10007000u, MASK_VSOXEI8_V | 0xe0000000u, "G(C?k", vector},
  {"vlseg8e1024ff.v", MATCH_VLE8FF_V | 0xe0000000u | 0x10007000u, MASK_VLE8FF_V | 0xe0000000u, "A(?k", vector},

  // zcmop_insns
  {"c.mop.1",  MATCH_C_MOP_1,  MASK_C_MOP_1,  "", zcmop_no_zicfiss},
  {"c.mop.3",  MATCH_C_MOP_3,  MASK_C_MOP_3,  "", zcmop},
  {"c.mop.5",  MATCH_C_MOP_5,  MASK_C_MOP_5,  "", zcmop_no_zicfiss},
  {"c.mop.7",  MATCH_C_MOP_7,  MASK_C_MOP_7,  "", zcmop},
  {"c.mop.9",  MATCH_C_MOP_9,  MASK_C_MOP_9,  "", zcmop},
  {"c.mop.11", MATCH_C_MOP_11, MASK_C_MOP_11, "", zcmop},
  {"c.mop.13", MATCH_C_MOP_13, MASK_C_MOP_13, "", zcmop},
  {"c.mop.15", MATCH_C_MOP_15, MASK_C_MOP_15, "", zcmop},
  // scalar crypto: aes64ks1i, aes32 variants
  {"aes64ks1i", MATCH_AES64KS1I, MASK_AES64KS1I, "ds+", zknd_or_zkne},
  {"aes32dsi",  MATCH_AES32DSI,  MASK_AES32DSI,  "dst-", zknd_rv32},
  {"aes32dsmi", MATCH_AES32DSMI, MASK_AES32DSMI, "dst-", zknd_rv32},
  {"aes32esi",  MATCH_AES32ESI,  MASK_AES32ESI,  "dst-", zkne_rv32},
  {"aes32esmi", MATCH_AES32ESMI, MASK_AES32ESMI, "dst-", zkne_rv32},
};

#undef EXT1
#undef XV
#undef XVS
#undef EXT1_XV
#undef EXT1_XVS
#undef EXT2
#undef EXT2_XV

void disassembler_t::add_instructions(const isa_parser_t* isa, bool strict)
{
  // Flat table iteration (like binutils riscv_opcodes[])
  for (const auto& op : all_insns)
    if (insn_class_enabled(op.cls, isa, strict))
      add_insn(new disasm_insn_t(op.name, op.match, op.mask, parse_fmt(op.fmt)));

  // zext.h: xlen-dependent match, cannot be in static table
  if (ext_enabled(EXT_ZBB))
    add_insn(new disasm_insn_t("zext.h",
      (isa->get_max_xlen() == 32 ? MATCH_PACK : MATCH_PACKW),
      MASK_PACK | (0x1fUL << 20), {&xrd, &xrs1}));

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

