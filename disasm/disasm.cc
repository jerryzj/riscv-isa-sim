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
// For std::reverse:
#include <algorithm>

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
// Table-driven disassembly infrastructure (aligned with binutils riscv-opc.c)
// ---------------------------------------------------------------------------
// Predicate macros for the flat opcode table's 'enabled' field.
// nullptr means always enabled. Each macro is a C++ lambda.
#define EXT1(e)       [](const isa_parser_t *isa, bool s) -> bool { return isa->extension_enabled(e) || !s; }
#define XV(x)         [](const isa_parser_t *isa, bool s) -> bool { return isa->get_max_xlen() == (x) || !s; }
#define XVS(x)        [](const isa_parser_t *isa, bool  ) -> bool { return isa->get_max_xlen() == (x); }
#define EXT1_XV(e,x)  [](const isa_parser_t *isa, bool s) -> bool { \
    return (isa->extension_enabled(e) && isa->get_max_xlen() == (x)) || !s; }
#define EXT1_XVS(e,x) [](const isa_parser_t *isa, bool s) -> bool { \
    return (isa->extension_enabled(e) || !s) && isa->get_max_xlen() == (x); }
#define EXT2(e1,e2)   [](const isa_parser_t *isa, bool s) -> bool { \
    return isa->extension_enabled(e1) || isa->extension_enabled(e2) || !s; }
#define EXT2_XV(e1,e2,x) [](const isa_parser_t *isa, bool s) -> bool { \
    return ((isa->extension_enabled(e1) || isa->extension_enabled(e2)) && \
            isa->get_max_xlen() == (x)) || !s; }

struct disasm_opcode_t {
  const char *name;
  uint32_t match;
  uint32_t mask;
  const char *fmt;
  bool (*enabled)(const isa_parser_t*, bool); // nullptr = always enabled
};

static const arg_t *fmt_char_to_arg(char c)
{
  switch (c) {
    case 'd': return &xrd;        case 's': return &xrs1;
    case 't': return &xrs2;       case 'r': return &xrs3;
    case 'D': return &frd;        case 'S': return &frs1;
    case 'T': return &frs2;       case 'R': return &frs3;
    case 'A': return &vd;         case 'B': return &vs1;
    case 'C': return &vs2;        case 'G': return &vs3;
    case 'P': return &xrd_p;      case 'Q': return &xrs1_p;
    case 'U': return &xrs2_p;
    case 'j': return &imm;        case 'Z': return &shamt;
    case 'u': return &bigimm;     case 'z': return &zimm5;
    case '5': return &v_simm5;    case '6': return &v_zimm6;
    case 'L': return &fli_imm;    case '>': return &b_imm5;
    case '\'': return &shamtd;    case '<': return &shamtw;
    case ';': return &shamth;     case ':': return &shamtb;
    case '7': return &p_imm8;     case '$': return &p_imm10csl;
    case '%': return &p_imm10csr; case '&': return &p_imm10csrw;
    case '-': return &bs;         case '+': return &rcon;
    case 'o': return &load_address;
    case 'q': return &store_address;
    case '(': return &base_only_address;
    case 'E': return &csr;        case 'm': return &rm;
    case 'I': return &iorw;       case '0': return &x0;
    case 'k': return &vm;         case 'K': return &v0;
    case 'W': return &v_vtype;
    case 'p': return &branch_target;
    case 'a': return &jump_target;
    case 'e': return &rvc_rs1;    case 'f': return &rvc_rs2;
    case 'F': return &rvc_fp_rs2; case 'H': return &rvc_rs1s;
    case 'J': return &rvc_rs2s;   case '#': return &rvc_fp_rs2s;
    case 'N': return &rvc_sp;     case 'X': return &rvc_ra;
    case 'Y': return &rvc_t0;     case 'V': return &rvc_r1s;
    case 'O': return &rvc_r2s;
    case 'i': return &rvc_imm;
    case 'n': return &rvc_addi4spn_imm;
    case 'x': return &rvc_addi16sp_imm;
    case 'l': return &rvc_lwsp_imm;
    case 'h': return &rvc_shamt;
    case 'b': return &rvc_uimm;
    case '@': return &rvc_lwsp_address;
    case 'M': return &rvc_ldsp_address;
    case '_': return &rvc_swsp_address;
    case 'g': return &rvc_sdsp_address;
    case 'c': return &rvc_lw_address;
    case 'v': return &rvc_ld_address;
    case 'y': return &rvc_branch_target;
    case 'w': return &rvc_jump_target;
    case '1': return &rvcm_jt_index;
    case '!': return &rvcm_pushpop_rlist;
    case '2': return &rvcm_push_stack_adj_32;
    case '4': return &rvcm_push_stack_adj_64;
    case '3': return &rvcm_pop_stack_adj_32;
    case '8': return &rvcm_pop_stack_adj_64;
    case '*': return &rvb_b_address;
    case '/': return &rvb_h_address;
    default:  return nullptr;
  }
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

// Single flat opcode table (like binutils riscv_opcodes[]).
// Entry order determines disassembly priority (first = highest after reversal).
static const disasm_opcode_t all_insns[] = {
  // prefetch_insns
  {"prefetch_r", MATCH_PREFETCH_R, MASK_PREFETCH_R, "q", nullptr},
  {"prefetch_w", MATCH_PREFETCH_W, MASK_PREFETCH_W, "q", nullptr},
  {"prefetch_i", MATCH_PREFETCH_I, MASK_PREFETCH_I, "q", nullptr},
  {"pause",      MATCH_PAUSE,      MASK_PAUSE,      "", nullptr},
  // base_load_store_insns
  {"lb",  MATCH_LB,  MASK_LB,  "do", nullptr},
  {"lbu", MATCH_LBU, MASK_LBU, "do", nullptr},
  {"lh",  MATCH_LH,  MASK_LH,  "do", nullptr},
  {"lhu", MATCH_LHU, MASK_LHU, "do", nullptr},
  {"lw",  MATCH_LW,  MASK_LW,  "do", nullptr},
  {"sb",  MATCH_SB,  MASK_SB,  "tq", nullptr},
  {"sh",  MATCH_SH,  MASK_SH,  "tq", nullptr},
  {"sw",  MATCH_SW,  MASK_SW,  "tq", nullptr},
  // rv64_load_store_insns
  {"lwu", MATCH_LWU, MASK_LWU, "do", XV(64)},
  {"ld",  MATCH_LD,  MASK_LD,  "do", XV(64)},
  {"sd",  MATCH_SD,  MASK_SD,  "tq", XV(64)},
  // zalrsc_insns
  {"lr.w", MATCH_LR_W, MASK_LR_W, "d(", EXT1(EXT_ZALRSC)},
  // zalrsc64_insns
  {"lr.d", MATCH_LR_D, MASK_LR_D, "d(", EXT1_XV(EXT_ZALRSC,64)},
  // zacas64_insns
  // amocas.q handled by add_xamo_insn in add_instructions
  // zawrs_insns
  {"wrs_sto", MATCH_WRS_STO, MASK_WRS_STO, "", EXT1(EXT_ZAWRS)},
  {"wrs_nto", MATCH_WRS_NTO, MASK_WRS_NTO, "", EXT1(EXT_ZAWRS)},
  // zicfilp_insns
  {"lpad", MATCH_LPAD, MASK_LPAD, "u", EXT1(EXT_ZICFILP)},
  // jump_insns
  {"j",    MATCH_JAL,              MASK_JAL | 0xf80u,             "a", nullptr},
  {"jal",  MATCH_JAL | 0x80u,     MASK_JAL | 0xf80u,             "a", nullptr},
  {"jal",  MATCH_JAL,             MASK_JAL,                       "da", nullptr},
  {"ret",  MATCH_JALR | 0x8000u,  MASK_JALR | 0xf80u | 0xf8000u | 0xfff00000u, "", nullptr},
  {"jr",   MATCH_JALR,            MASK_JALR | 0xf80u | 0xfff00000u, "s", nullptr},
  {"jalr", MATCH_JALR | 0x80u,   MASK_JALR | 0xf80u | 0xfff00000u, "s", nullptr},
  {"jalr", MATCH_JALR,            MASK_JALR,                        "dsj", nullptr},
  // branch_insns
  {"beqz", MATCH_BEQ, MASK_BEQ | 0x1f00000u, "sp", nullptr},
  {"bnez", MATCH_BNE, MASK_BNE | 0x1f00000u, "sp", nullptr},
  {"bltz", MATCH_BLT, MASK_BLT | 0x1f00000u, "sp", nullptr},
  {"bgez", MATCH_BGE, MASK_BGE | 0x1f00000u, "sp", nullptr},
  {"beq",  MATCH_BEQ, MASK_BEQ,  "stp", nullptr},
  {"bne",  MATCH_BNE, MASK_BNE,  "stp", nullptr},
  {"blt",  MATCH_BLT, MASK_BLT,  "stp", nullptr},
  {"bge",  MATCH_BGE, MASK_BGE,  "stp", nullptr},
  {"bltu", MATCH_BLTU, MASK_BLTU, "stp", nullptr},
  {"bgeu", MATCH_BGEU, MASK_BGEU, "stp", nullptr},
  // utype_insns
  {"lui",   MATCH_LUI,   MASK_LUI,   "du", nullptr},
  {"auipc", MATCH_AUIPC, MASK_AUIPC, "du", nullptr},
  // base_int_insns
  // nop: addi x0,x0,0
  {"nop",  MATCH_ADDI, MASK_ADDI | 0xf80u | 0xf8000u | 0xfff00000u, "", nullptr},
  // li: addi rd, x0, imm  (mask_rs1 = 0xf8000 locks rs1=0)
  {"li",   MATCH_ADDI, MASK_ADDI | 0xf8000u, "dj", nullptr},
  // mv: addi rd, rs1, 0  (mask_imm locks imm=0)
  {"mv",   MATCH_ADDI, MASK_ADDI | 0xfff00000u, "ds", nullptr},
  {"addi", MATCH_ADDI, MASK_ADDI, "dsj", nullptr},
  {"slti", MATCH_SLTI, MASK_SLTI, "dsj", nullptr},
  // seqz: sltiu rd, rs1, 1
  {"seqz", MATCH_SLTIU | (1u << 20), MASK_SLTIU | 0xfff00000u, "ds", nullptr},
  {"sltiu", MATCH_SLTIU, MASK_SLTIU, "dsj", nullptr},
  // not: xori rd, rs1, -1  (imm=0xfff=-1)
  {"not",  MATCH_XORI | 0xfff00000u, MASK_XORI | 0xfff00000u, "ds", nullptr},
  {"xori", MATCH_XORI, MASK_XORI, "dsj", nullptr},
  {"slli", MATCH_SLLI, MASK_SLLI, "dsZ", nullptr},
  {"srli", MATCH_SRLI, MASK_SRLI, "dsZ", nullptr},
  {"srai", MATCH_SRAI, MASK_SRAI, "dsZ", nullptr},
  {"ori",  MATCH_ORI,  MASK_ORI,  "dsj", nullptr},
  {"andi", MATCH_ANDI, MASK_ANDI, "dsj", nullptr},
  {"add",  MATCH_ADD,  MASK_ADD,  "dst", nullptr},
  {"sub",  MATCH_SUB,  MASK_SUB,  "dst", nullptr},
  {"sll",  MATCH_SLL,  MASK_SLL,  "dst", nullptr},
  {"slt",  MATCH_SLT,  MASK_SLT,  "dst", nullptr},
  // snez: sltu rd, x0, rs2  (mask_rs1 locks rs1=0)
  {"snez", MATCH_SLTU, MASK_SLTU | 0xf8000u, "dt", nullptr},
  {"sltu", MATCH_SLTU, MASK_SLTU, "dst", nullptr},
  {"xor",  MATCH_XOR,  MASK_XOR,  "dst", nullptr},
  {"srl",  MATCH_SRL,  MASK_SRL,  "dst", nullptr},
  {"sra",  MATCH_SRA,  MASK_SRA,  "dst", nullptr},
  {"or",   MATCH_OR,   MASK_OR,   "dst", nullptr},
  {"and",  MATCH_AND,  MASK_AND,  "dst", nullptr},
  // rv64_int_insns
  // sext.w: addiw rd, rs1, 0
  {"sext.w", MATCH_ADDIW, MASK_ADDIW | 0xfff00000u, "ds", XV(64)},
  {"addiw",  MATCH_ADDIW, MASK_ADDIW, "dsj", XV(64)},
  {"slliw",  MATCH_SLLIW, MASK_SLLIW, "dsZ", XV(64)},
  {"srliw",  MATCH_SRLIW, MASK_SRLIW, "dsZ", XV(64)},
  {"sraiw",  MATCH_SRAIW, MASK_SRAIW, "dsZ", XV(64)},
  {"addw",   MATCH_ADDW,  MASK_ADDW,  "dst", XV(64)},
  {"subw",   MATCH_SUBW,  MASK_SUBW,  "dst", XV(64)},
  {"sllw",   MATCH_SLLW,  MASK_SLLW,  "dst", XV(64)},
  {"srlw",   MATCH_SRLW,  MASK_SRLW,  "dst", XV(64)},
  {"sraw",   MATCH_SRAW,  MASK_SRAW,  "dst", XV(64)},
  // system_insns
  {"ecall",   MATCH_ECALL,   MASK_ECALL,   "", nullptr},
  {"ebreak",  MATCH_EBREAK,  MASK_EBREAK,  "", nullptr},
  {"mret",    MATCH_MRET,    MASK_MRET,    "", nullptr},
  {"dret",    MATCH_DRET,    MASK_DRET,    "", nullptr},
  {"wfi",     MATCH_WFI,     MASK_WFI,     "", nullptr},
  {"fence",   MATCH_FENCE,   MASK_FENCE,   "I", nullptr},
  {"fence.i", MATCH_FENCE_I, MASK_FENCE_I, "", nullptr},
  // CSR pseudo-instructions (more specific masks first)
  {"csrr",  MATCH_CSRRS,  MASK_CSRRS  | 0xf8000u,    "dE", nullptr},
  {"csrw",  MATCH_CSRRW,  MASK_CSRRW  | 0xf80u,      "Es", nullptr},
  {"csrs",  MATCH_CSRRS,  MASK_CSRRS  | 0xf80u,      "Es", nullptr},
  {"csrc",  MATCH_CSRRC,  MASK_CSRRC  | 0xf80u,      "Es", nullptr},
  {"csrwi", MATCH_CSRRWI, MASK_CSRRWI | 0xf80u,      "Ez", nullptr},
  {"csrsi", MATCH_CSRRSI, MASK_CSRRSI | 0xf80u,      "Ez", nullptr},
  {"csrci", MATCH_CSRRCI, MASK_CSRRCI | 0xf80u,      "Ez", nullptr},
  {"csrrw",  MATCH_CSRRW,  MASK_CSRRW,  "dEs", nullptr},
  {"csrrs",  MATCH_CSRRS,  MASK_CSRRS,  "dEs", nullptr},
  {"csrrc",  MATCH_CSRRC,  MASK_CSRRC,  "dEs", nullptr},
  {"csrrwi", MATCH_CSRRWI, MASK_CSRRWI, "dEz", nullptr},
  {"csrrsi", MATCH_CSRRSI, MASK_CSRRSI, "dEz", nullptr},
  {"csrrci", MATCH_CSRRCI, MASK_CSRRCI, "dEz", nullptr},
  // s_ext_insns
  {"sret",       MATCH_SRET,       MASK_SRET,       "", EXT1('S')},
  {"sfence.vma", MATCH_SFENCE_VMA, MASK_SFENCE_VMA, "st", EXT1('S')},
  // m_ext_insns
  {"mul",    MATCH_MUL,    MASK_MUL,    "dst", EXT1('M')},
  {"mulh",   MATCH_MULH,   MASK_MULH,   "dst", EXT1('M')},
  {"mulhu",  MATCH_MULHU,  MASK_MULHU,  "dst", EXT1('M')},
  {"mulhsu", MATCH_MULHSU, MASK_MULHSU, "dst", EXT1('M')},
  {"div",    MATCH_DIV,    MASK_DIV,    "dst", EXT1('M')},
  {"divu",   MATCH_DIVU,   MASK_DIVU,   "dst", EXT1('M')},
  {"rem",    MATCH_REM,    MASK_REM,    "dst", EXT1('M')},
  {"remu",   MATCH_REMU,   MASK_REMU,   "dst", EXT1('M')},
  // m_ext64_insns
  {"mulw",  MATCH_MULW,  MASK_MULW,  "dst", EXT1_XV('M',64)},
  {"divw",  MATCH_DIVW,  MASK_DIVW,  "dst", EXT1_XV('M',64)},
  {"divuw", MATCH_DIVUW, MASK_DIVUW, "dst", EXT1_XV('M',64)},
  {"remw",  MATCH_REMW,  MASK_REMW,  "dst", EXT1_XV('M',64)},
  {"remuw", MATCH_REMUW, MASK_REMUW, "dst", EXT1_XV('M',64)},
  // zba_insns
  {"sh1add", MATCH_SH1ADD, MASK_SH1ADD, "dst", EXT1(EXT_ZBA)},
  {"sh2add", MATCH_SH2ADD, MASK_SH2ADD, "dst", EXT1(EXT_ZBA)},
  {"sh3add", MATCH_SH3ADD, MASK_SH3ADD, "dst", EXT1(EXT_ZBA)},
  // zba64_insns
  {"slli.uw", MATCH_SLLI_UW, MASK_SLLI_UW, "dsZ", EXT1_XV(EXT_ZBA,64)},
  // zext.w: add.uw rd, rs1, zero  (mask_rs2 locks rs2=0)
  {"zext.w",  MATCH_ADD_UW, MASK_ADD_UW | 0x1f00000u, "ds", EXT1_XV(EXT_ZBA,64)},
  {"add.uw",  MATCH_ADD_UW,  MASK_ADD_UW,  "dst", EXT1_XV(EXT_ZBA,64)},
  {"sh1add.uw", MATCH_SH1ADD_UW, MASK_SH1ADD_UW, "dst", EXT1_XV(EXT_ZBA,64)},
  {"sh2add.uw", MATCH_SH2ADD_UW, MASK_SH2ADD_UW, "dst", EXT1_XV(EXT_ZBA,64)},
  {"sh3add.uw", MATCH_SH3ADD_UW, MASK_SH3ADD_UW, "dst", EXT1_XV(EXT_ZBA,64)},
  // zbb_insns
  {"ror",    MATCH_ROR,    MASK_ROR,    "dst", EXT1(EXT_ZBB)},
  {"rol",    MATCH_ROL,    MASK_ROL,    "dst", EXT1(EXT_ZBB)},
  {"rori",   MATCH_RORI,   MASK_RORI,   "dsZ", EXT1(EXT_ZBB)},
  {"ctz",    MATCH_CTZ,    MASK_CTZ,    "ds", EXT1(EXT_ZBB)},
  {"clz",    MATCH_CLZ,    MASK_CLZ,    "ds", EXT1(EXT_ZBB)},
  {"cpop",   MATCH_CPOP,   MASK_CPOP,   "ds", EXT1(EXT_ZBB)},
  {"min",    MATCH_MIN,    MASK_MIN,    "dst", EXT1(EXT_ZBB)},
  {"minu",   MATCH_MINU,   MASK_MINU,   "dst", EXT1(EXT_ZBB)},
  {"max",    MATCH_MAX,    MASK_MAX,    "dst", EXT1(EXT_ZBB)},
  {"maxu",   MATCH_MAXU,   MASK_MAXU,   "dst", EXT1(EXT_ZBB)},
  {"andn",   MATCH_ANDN,   MASK_ANDN,   "dst", EXT1(EXT_ZBB)},
  {"orn",    MATCH_ORN,    MASK_ORN,    "dst", EXT1(EXT_ZBB)},
  {"xnor",   MATCH_XNOR,   MASK_XNOR,   "dst", EXT1(EXT_ZBB)},
  {"sext.b", MATCH_SEXT_B, MASK_SEXT_B, "ds", EXT1(EXT_ZBB)},
  {"sext.h", MATCH_SEXT_H, MASK_SEXT_H, "ds", EXT1(EXT_ZBB)},
  {"rev8",   MATCH_REV8,   MASK_REV8,   "ds", EXT1(EXT_ZBB)},
  {"orc.b",  MATCH_ORC_B,  MASK_ORC_B,  "ds", EXT1(EXT_ZBB)},
  // zbb64_insns
  {"rorw",  MATCH_RORW,  MASK_RORW,  "dst", EXT1_XV(EXT_ZBB,64)},
  {"rolw",  MATCH_ROLW,  MASK_ROLW,  "dst", EXT1_XV(EXT_ZBB,64)},
  {"roriw", MATCH_RORIW, MASK_RORIW, "dsZ", EXT1_XV(EXT_ZBB,64)},
  {"ctzw",  MATCH_CTZW,  MASK_CTZW,  "ds", EXT1_XV(EXT_ZBB,64)},
  {"clzw",  MATCH_CLZW,  MASK_CLZW,  "ds", EXT1_XV(EXT_ZBB,64)},
  {"cpopw", MATCH_CPOPW, MASK_CPOPW, "ds", EXT1_XV(EXT_ZBB,64)},
  // zbc_insns
  {"clmul",  MATCH_CLMUL,  MASK_CLMUL,  "dst", EXT1(EXT_ZBC)},
  {"clmulh", MATCH_CLMULH, MASK_CLMULH, "dst", EXT1(EXT_ZBC)},
  {"clmulr", MATCH_CLMULR, MASK_CLMULR, "dst", EXT1(EXT_ZBC)},
  // zbs_insns
  {"bclr",  MATCH_BCLR,  MASK_BCLR,  "dst", EXT1(EXT_ZBS)},
  {"binv",  MATCH_BINV,  MASK_BINV,  "dst", EXT1(EXT_ZBS)},
  {"bset",  MATCH_BSET,  MASK_BSET,  "dst", EXT1(EXT_ZBS)},
  {"bext",  MATCH_BEXT,  MASK_BEXT,  "dst", EXT1(EXT_ZBS)},
  {"bclri", MATCH_BCLRI, MASK_BCLRI, "dsZ", EXT1(EXT_ZBS)},
  {"binvi", MATCH_BINVI, MASK_BINVI, "dsZ", EXT1(EXT_ZBS)},
  {"bseti", MATCH_BSETI, MASK_BSETI, "dsZ", EXT1(EXT_ZBS)},
  {"bexti", MATCH_BEXTI, MASK_BEXTI, "dsZ", EXT1(EXT_ZBS)},
  // zbkb_insns
  {"brev8", MATCH_BREV8, MASK_BREV8, "ds", EXT1(EXT_ZBKB)},
  {"rev8",  MATCH_REV8,  MASK_REV8,  "ds", EXT1(EXT_ZBKB)},
  {"pack",  MATCH_PACK,  MASK_PACK,  "dst", EXT1(EXT_ZBKB)},
  {"packh", MATCH_PACKH, MASK_PACKH, "dst", EXT1(EXT_ZBKB)},
  // zbkb64_insns
  {"packw", MATCH_PACKW, MASK_PACKW, "dst", EXT1_XV(EXT_ZBKB,64)},
  // svinval_insns
  {"sfence.w.inval",  MATCH_SFENCE_W_INVAL,  MASK_SFENCE_W_INVAL,  "", EXT1(EXT_SVINVAL)},
  {"sfence.inval.ir", MATCH_SFENCE_INVAL_IR, MASK_SFENCE_INVAL_IR, "", EXT1(EXT_SVINVAL)},
  {"sinval.vma",      MATCH_SINVAL_VMA,      MASK_SINVAL_VMA,      "st", EXT1(EXT_SVINVAL)},
  {"hinval.vvma",     MATCH_HINVAL_VVMA,     MASK_HINVAL_VVMA,     "st", EXT1(EXT_SVINVAL)},
  {"hinval.gvma",     MATCH_HINVAL_GVMA,     MASK_HINVAL_GVMA,     "st", EXT1(EXT_SVINVAL)},
  // f_ext_insns
  {"flw",    MATCH_FLW,    MASK_FLW,    "Do", EXT1('F')},
  {"fsw",    MATCH_FSW,    MASK_FSW,    "Tq", EXT1('F')},
  {"fmv.w.x", MATCH_FMV_W_X, MASK_FMV_W_X, "Ds", EXT1('F')},
  {"fmv.x.w", MATCH_FMV_X_W, MASK_FMV_X_W, "dS", EXT1('F')},
  // f_or_zfinx_insns
  {"fadd.s",    MATCH_FADD_S,    MASK_FADD_S,    "DST", EXT2('F',EXT_ZFINX)},
  {"fsub.s",    MATCH_FSUB_S,    MASK_FSUB_S,    "DST", EXT2('F',EXT_ZFINX)},
  {"fmul.s",    MATCH_FMUL_S,    MASK_FMUL_S,    "DST", EXT2('F',EXT_ZFINX)},
  {"fdiv.s",    MATCH_FDIV_S,    MASK_FDIV_S,    "DST", EXT2('F',EXT_ZFINX)},
  {"fsqrt.s",   MATCH_FSQRT_S,   MASK_FSQRT_S,   "DS", EXT2('F',EXT_ZFINX)},
  {"fmin.s",    MATCH_FMIN_S,    MASK_FMIN_S,    "DST", EXT2('F',EXT_ZFINX)},
  {"fmax.s",    MATCH_FMAX_S,    MASK_FMAX_S,    "DST", EXT2('F',EXT_ZFINX)},
  {"fmadd.s",   MATCH_FMADD_S,   MASK_FMADD_S,   "DSTR", EXT2('F',EXT_ZFINX)},
  {"fmsub.s",   MATCH_FMSUB_S,   MASK_FMSUB_S,   "DSTR", EXT2('F',EXT_ZFINX)},
  {"fnmadd.s",  MATCH_FNMADD_S,  MASK_FNMADD_S,  "DSTR", EXT2('F',EXT_ZFINX)},
  {"fnmsub.s",  MATCH_FNMSUB_S,  MASK_FNMSUB_S,  "DSTR", EXT2('F',EXT_ZFINX)},
  {"fsgnj.s",   MATCH_FSGNJ_S,   MASK_FSGNJ_S,   "DST", EXT2('F',EXT_ZFINX)},
  {"fsgnjn.s",  MATCH_FSGNJN_S,  MASK_FSGNJN_S,  "DST", EXT2('F',EXT_ZFINX)},
  {"fsgnjx.s",  MATCH_FSGNJX_S,  MASK_FSGNJX_S,  "DST", EXT2('F',EXT_ZFINX)},
  {"fcvt.s.d",  MATCH_FCVT_S_D,  MASK_FCVT_S_D,  "DS", EXT2('F',EXT_ZFINX)},
  {"fcvt.s.q",  MATCH_FCVT_S_Q,  MASK_FCVT_S_Q,  "DS", EXT2('F',EXT_ZFINX)},
  {"fcvt.s.w",  MATCH_FCVT_S_W,  MASK_FCVT_S_W,  "Ds", EXT2('F',EXT_ZFINX)},
  {"fcvt.s.wu", MATCH_FCVT_S_WU, MASK_FCVT_S_WU, "Ds", EXT2('F',EXT_ZFINX)},
  {"fcvt.w.s",  MATCH_FCVT_W_S,  MASK_FCVT_W_S,  "dS", EXT2('F',EXT_ZFINX)},
  {"fcvt.wu.s", MATCH_FCVT_WU_S, MASK_FCVT_WU_S, "dS", EXT2('F',EXT_ZFINX)},
  {"fclass.s",  MATCH_FCLASS_S,  MASK_FCLASS_S,  "dS", EXT2('F',EXT_ZFINX)},
  {"feq.s",     MATCH_FEQ_S,     MASK_FEQ_S,     "dST", EXT2('F',EXT_ZFINX)},
  {"flt.s",     MATCH_FLT_S,     MASK_FLT_S,     "dST", EXT2('F',EXT_ZFINX)},
  {"fle.s",     MATCH_FLE_S,     MASK_FLE_S,     "dST", EXT2('F',EXT_ZFINX)},
  // f_or_zfinx64_insns
  {"fcvt.s.l",  MATCH_FCVT_S_L,  MASK_FCVT_S_L,  "Ds", EXT2_XV('F',EXT_ZFINX,64)},
  {"fcvt.s.lu", MATCH_FCVT_S_LU, MASK_FCVT_S_LU, "Ds", EXT2_XV('F',EXT_ZFINX,64)},
  {"fcvt.l.s",  MATCH_FCVT_L_S,  MASK_FCVT_L_S,  "dS", EXT2_XV('F',EXT_ZFINX,64)},
  {"fcvt.lu.s", MATCH_FCVT_LU_S, MASK_FCVT_LU_S, "dS", EXT2_XV('F',EXT_ZFINX,64)},
  // d_ext_insns
  {"fld", MATCH_FLD, MASK_FLD, "Do", EXT1('D')},
  {"fsd", MATCH_FSD, MASK_FSD, "Tq", EXT1('D')},
  // d_ext64_insns
  {"fmv.d.x", MATCH_FMV_D_X, MASK_FMV_D_X, "Ds", EXT1_XV('D',64)},
  {"fmv.x.d", MATCH_FMV_X_D, MASK_FMV_X_D, "dS", EXT1_XV('D',64)},
  // d_or_zdinx_insns
  {"fadd.d",    MATCH_FADD_D,    MASK_FADD_D,    "DST", EXT2('D',EXT_ZDINX)},
  {"fsub.d",    MATCH_FSUB_D,    MASK_FSUB_D,    "DST", EXT2('D',EXT_ZDINX)},
  {"fmul.d",    MATCH_FMUL_D,    MASK_FMUL_D,    "DST", EXT2('D',EXT_ZDINX)},
  {"fdiv.d",    MATCH_FDIV_D,    MASK_FDIV_D,    "DST", EXT2('D',EXT_ZDINX)},
  {"fsqrt.d",   MATCH_FSQRT_D,   MASK_FSQRT_D,   "DS", EXT2('D',EXT_ZDINX)},
  {"fmin.d",    MATCH_FMIN_D,    MASK_FMIN_D,    "DST", EXT2('D',EXT_ZDINX)},
  {"fmax.d",    MATCH_FMAX_D,    MASK_FMAX_D,    "DST", EXT2('D',EXT_ZDINX)},
  {"fmadd.d",   MATCH_FMADD_D,   MASK_FMADD_D,   "DSTR", EXT2('D',EXT_ZDINX)},
  {"fmsub.d",   MATCH_FMSUB_D,   MASK_FMSUB_D,   "DSTR", EXT2('D',EXT_ZDINX)},
  {"fnmadd.d",  MATCH_FNMADD_D,  MASK_FNMADD_D,  "DSTR", EXT2('D',EXT_ZDINX)},
  {"fnmsub.d",  MATCH_FNMSUB_D,  MASK_FNMSUB_D,  "DSTR", EXT2('D',EXT_ZDINX)},
  {"fsgnj.d",   MATCH_FSGNJ_D,   MASK_FSGNJ_D,   "DST", EXT2('D',EXT_ZDINX)},
  {"fsgnjn.d",  MATCH_FSGNJN_D,  MASK_FSGNJN_D,  "DST", EXT2('D',EXT_ZDINX)},
  {"fsgnjx.d",  MATCH_FSGNJX_D,  MASK_FSGNJX_D,  "DST", EXT2('D',EXT_ZDINX)},
  {"fcvt.d.s",  MATCH_FCVT_D_S,  MASK_FCVT_D_S,  "DS", EXT2('D',EXT_ZDINX)},
  {"fcvt.d.q",  MATCH_FCVT_D_Q,  MASK_FCVT_D_Q,  "DS", EXT2('D',EXT_ZDINX)},
  {"fcvt.d.w",  MATCH_FCVT_D_W,  MASK_FCVT_D_W,  "Ds", EXT2('D',EXT_ZDINX)},
  {"fcvt.d.wu", MATCH_FCVT_D_WU, MASK_FCVT_D_WU, "Ds", EXT2('D',EXT_ZDINX)},
  {"fcvt.w.d",  MATCH_FCVT_W_D,  MASK_FCVT_W_D,  "dS", EXT2('D',EXT_ZDINX)},
  {"fcvt.wu.d", MATCH_FCVT_WU_D, MASK_FCVT_WU_D, "dS", EXT2('D',EXT_ZDINX)},
  {"fclass.d",  MATCH_FCLASS_D,  MASK_FCLASS_D,  "dS", EXT2('D',EXT_ZDINX)},
  {"feq.d",     MATCH_FEQ_D,     MASK_FEQ_D,     "dST", EXT2('D',EXT_ZDINX)},
  {"flt.d",     MATCH_FLT_D,     MASK_FLT_D,     "dST", EXT2('D',EXT_ZDINX)},
  {"fle.d",     MATCH_FLE_D,     MASK_FLE_D,     "dST", EXT2('D',EXT_ZDINX)},
  // d_or_zdinx64_insns
  {"fcvt.d.l",  MATCH_FCVT_D_L,  MASK_FCVT_D_L,  "Ds", EXT2_XV('D',EXT_ZDINX,64)},
  {"fcvt.d.lu", MATCH_FCVT_D_LU, MASK_FCVT_D_LU, "Ds", EXT2_XV('D',EXT_ZDINX,64)},
  {"fcvt.l.d",  MATCH_FCVT_L_D,  MASK_FCVT_L_D,  "dS", EXT2_XV('D',EXT_ZDINX,64)},
  {"fcvt.lu.d", MATCH_FCVT_LU_D, MASK_FCVT_LU_D, "dS", EXT2_XV('D',EXT_ZDINX,64)},
  // zfa_insns
  {"fli.s",    MATCH_FLI_S,    MASK_FLI_S,    "dL", EXT1(EXT_ZFA)},
  {"fminm.s",  MATCH_FMINM_S,  MASK_FMINM_S,  "DST", EXT1(EXT_ZFA)},
  {"fmaxm.s",  MATCH_FMAXM_S,  MASK_FMAXM_S,  "DST", EXT1(EXT_ZFA)},
  {"fround.s",   MATCH_FROUND_S,   MASK_FROUND_S,   "DS", EXT1(EXT_ZFA)},
  {"froundnx.s", MATCH_FROUNDNX_S, MASK_FROUNDNX_S, "DS", EXT1(EXT_ZFA)},
  {"fleq.s",   MATCH_FLEQ_S,   MASK_FLEQ_S,   "dST", EXT1(EXT_ZFA)},
  {"fltq.s",   MATCH_FLTQ_S,   MASK_FLTQ_S,   "dST", EXT1(EXT_ZFA)},
  // zfa_zfh_insns
  {"fli.h",    MATCH_FLI_H,    MASK_FLI_H,    "dL", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && (isa->extension_enabled(EXT_ZFH) || isa->extension_enabled(EXT_ZVFH))) || !s; }},
  {"fminm.h",  MATCH_FMINM_H,  MASK_FMINM_H,  "DST", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && (isa->extension_enabled(EXT_ZFH) || isa->extension_enabled(EXT_ZVFH))) || !s; }},
  {"fmaxm.h",  MATCH_FMAXM_H,  MASK_FMAXM_H,  "DST", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && (isa->extension_enabled(EXT_ZFH) || isa->extension_enabled(EXT_ZVFH))) || !s; }},
  {"fround.h",   MATCH_FROUND_H,   MASK_FROUND_H,   "DS", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && (isa->extension_enabled(EXT_ZFH) || isa->extension_enabled(EXT_ZVFH))) || !s; }},
  {"froundnx.h", MATCH_FROUNDNX_H, MASK_FROUNDNX_H, "DS", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && (isa->extension_enabled(EXT_ZFH) || isa->extension_enabled(EXT_ZVFH))) || !s; }},
  {"fleq.h",   MATCH_FLEQ_H,   MASK_FLEQ_H,   "dST", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && (isa->extension_enabled(EXT_ZFH) || isa->extension_enabled(EXT_ZVFH))) || !s; }},
  {"fltq.h",   MATCH_FLTQ_H,   MASK_FLTQ_H,   "dST", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && (isa->extension_enabled(EXT_ZFH) || isa->extension_enabled(EXT_ZVFH))) || !s; }},
  // zfa_d_insns
  {"fli.d",      MATCH_FLI_D,      MASK_FLI_D,      "dL", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('D')) || !s; }},
  {"fminm.d",    MATCH_FMINM_D,    MASK_FMINM_D,    "DST", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('D')) || !s; }},
  {"fmaxm.d",    MATCH_FMAXM_D,    MASK_FMAXM_D,    "DST", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('D')) || !s; }},
  {"fround.d",   MATCH_FROUND_D,   MASK_FROUND_D,   "DS", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('D')) || !s; }},
  {"froundnx.d", MATCH_FROUNDNX_D, MASK_FROUNDNX_D, "DS", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('D')) || !s; }},
  {"fleq.d",     MATCH_FLEQ_D,     MASK_FLEQ_D,     "dST", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('D')) || !s; }},
  {"fltq.d",     MATCH_FLTQ_D,     MASK_FLTQ_D,     "dST", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('D')) || !s; }},
  {"fcvtmod.w.d",MATCH_FCVTMOD_W_D,MASK_FCVTMOD_W_D,"dSm", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('D')) || !s; }},
  // zfa_d32_insns
  {"fmvp.d.x", MATCH_FMVP_D_X, MASK_FMVP_D_X, "Dst", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) || !s) && isa->extension_enabled('D') && isa->get_max_xlen() == 32; }},
  {"fmvh.x.d", MATCH_FMVH_X_D, MASK_FMVH_X_D, "dS", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) || !s) && isa->extension_enabled('D') && isa->get_max_xlen() == 32; }},
  // zfa_q_insns
  {"fli.q",      MATCH_FLI_Q,      MASK_FLI_Q,      "dL", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('Q')) || !s; }},
  {"fminm.q",    MATCH_FMINM_Q,    MASK_FMINM_Q,    "DST", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('Q')) || !s; }},
  {"fmaxm.q",    MATCH_FMAXM_Q,    MASK_FMAXM_Q,    "DST", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('Q')) || !s; }},
  {"fround.q",   MATCH_FROUND_Q,   MASK_FROUND_Q,   "DS", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('Q')) || !s; }},
  {"froundnx.q", MATCH_FROUNDNX_Q, MASK_FROUNDNX_Q, "DS", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('Q')) || !s; }},
  {"fleq.q",     MATCH_FLEQ_Q,     MASK_FLEQ_Q,     "dST", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('Q')) || !s; }},
  {"fltq.q",     MATCH_FLTQ_Q,     MASK_FLTQ_Q,     "dST", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('Q')) || !s; }},
  // zfa_q64_insns
  {"fmvp.q.x", MATCH_FMVP_Q_X, MASK_FMVP_Q_X, "Dst", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('Q') && isa->get_max_xlen() == 64) || !s; }},
  {"fmvh.x.q", MATCH_FMVH_X_Q, MASK_FMVH_X_Q, "dS", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZFA) && isa->extension_enabled('Q') && isa->get_max_xlen() == 64) || !s; }},
  // zfh_insns
  {"fadd.h",    MATCH_FADD_H,    MASK_FADD_H,    "DST", EXT1(EXT_ZFH)},
  {"fsub.h",    MATCH_FSUB_H,    MASK_FSUB_H,    "DST", EXT1(EXT_ZFH)},
  {"fmul.h",    MATCH_FMUL_H,    MASK_FMUL_H,    "DST", EXT1(EXT_ZFH)},
  {"fdiv.h",    MATCH_FDIV_H,    MASK_FDIV_H,    "DST", EXT1(EXT_ZFH)},
  {"fsqrt.h",   MATCH_FSQRT_H,   MASK_FSQRT_H,   "DS", EXT1(EXT_ZFH)},
  {"fmin.h",    MATCH_FMIN_H,    MASK_FMIN_H,    "DST", EXT1(EXT_ZFH)},
  {"fmax.h",    MATCH_FMAX_H,    MASK_FMAX_H,    "DST", EXT1(EXT_ZFH)},
  {"fmadd.h",   MATCH_FMADD_H,   MASK_FMADD_H,   "DSTR", EXT1(EXT_ZFH)},
  {"fmsub.h",   MATCH_FMSUB_H,   MASK_FMSUB_H,   "DSTR", EXT1(EXT_ZFH)},
  {"fnmadd.h",  MATCH_FNMADD_H,  MASK_FNMADD_H,  "DSTR", EXT1(EXT_ZFH)},
  {"fnmsub.h",  MATCH_FNMSUB_H,  MASK_FNMSUB_H,  "DSTR", EXT1(EXT_ZFH)},
  {"fsgnj.h",   MATCH_FSGNJ_H,   MASK_FSGNJ_H,   "DST", EXT1(EXT_ZFH)},
  {"fsgnjn.h",  MATCH_FSGNJN_H,  MASK_FSGNJN_H,  "DST", EXT1(EXT_ZFH)},
  {"fsgnjx.h",  MATCH_FSGNJX_H,  MASK_FSGNJX_H,  "DST", EXT1(EXT_ZFH)},
  {"fcvt.h.l",  MATCH_FCVT_H_L,  MASK_FCVT_H_L,  "Ds", EXT1(EXT_ZFH)},
  {"fcvt.h.lu", MATCH_FCVT_H_LU, MASK_FCVT_H_LU, "Ds", EXT1(EXT_ZFH)},
  {"fcvt.h.w",  MATCH_FCVT_H_W,  MASK_FCVT_H_W,  "Ds", EXT1(EXT_ZFH)},
  {"fcvt.h.wu", MATCH_FCVT_H_WU, MASK_FCVT_H_WU, "Ds", EXT1(EXT_ZFH)},
  {"fcvt.l.h",  MATCH_FCVT_L_H,  MASK_FCVT_L_H,  "dS", EXT1(EXT_ZFH)},
  {"fcvt.lu.h", MATCH_FCVT_LU_H, MASK_FCVT_LU_H, "dS", EXT1(EXT_ZFH)},
  {"fcvt.w.h",  MATCH_FCVT_W_H,  MASK_FCVT_W_H,  "dS", EXT1(EXT_ZFH)},
  {"fcvt.wu.h", MATCH_FCVT_WU_H, MASK_FCVT_WU_H, "dS", EXT1(EXT_ZFH)},
  {"fclass.h",  MATCH_FCLASS_H,  MASK_FCLASS_H,  "dS", EXT1(EXT_ZFH)},
  {"feq.h",     MATCH_FEQ_H,     MASK_FEQ_H,     "dST", EXT1(EXT_ZFH)},
  {"flt.h",     MATCH_FLT_H,     MASK_FLT_H,     "dST", EXT1(EXT_ZFH)},
  {"fle.h",     MATCH_FLE_H,     MASK_FLE_H,     "dST", EXT1(EXT_ZFH)},
  // zhinx_insns
  {"fadd.h",    MATCH_FADD_H,    MASK_FADD_H,    "dst", EXT1(EXT_ZHINX)},
  {"fsub.h",    MATCH_FSUB_H,    MASK_FSUB_H,    "dst", EXT1(EXT_ZHINX)},
  {"fmul.h",    MATCH_FMUL_H,    MASK_FMUL_H,    "dst", EXT1(EXT_ZHINX)},
  {"fdiv.h",    MATCH_FDIV_H,    MASK_FDIV_H,    "dst", EXT1(EXT_ZHINX)},
  {"fsqrt.h",   MATCH_FSQRT_H,   MASK_FSQRT_H,   "ds", EXT1(EXT_ZHINX)},
  {"fmin.h",    MATCH_FMIN_H,    MASK_FMIN_H,    "dst", EXT1(EXT_ZHINX)},
  {"fmax.h",    MATCH_FMAX_H,    MASK_FMAX_H,    "dst", EXT1(EXT_ZHINX)},
  {"fmadd.h",   MATCH_FMADD_H,   MASK_FMADD_H,   "dstr", EXT1(EXT_ZHINX)},
  {"fmsub.h",   MATCH_FMSUB_H,   MASK_FMSUB_H,   "dstr", EXT1(EXT_ZHINX)},
  {"fnmadd.h",  MATCH_FNMADD_H,  MASK_FNMADD_H,  "dstr", EXT1(EXT_ZHINX)},
  {"fnmsub.h",  MATCH_FNMSUB_H,  MASK_FNMSUB_H,  "dstr", EXT1(EXT_ZHINX)},
  {"fsgnj.h",   MATCH_FSGNJ_H,   MASK_FSGNJ_H,   "dst", EXT1(EXT_ZHINX)},
  {"fsgnjn.h",  MATCH_FSGNJN_H,  MASK_FSGNJN_H,  "dst", EXT1(EXT_ZHINX)},
  {"fsgnjx.h",  MATCH_FSGNJX_H,  MASK_FSGNJX_H,  "dst", EXT1(EXT_ZHINX)},
  {"fcvt.h.l",  MATCH_FCVT_H_L,  MASK_FCVT_H_L,  "ds", EXT1(EXT_ZHINX)},
  {"fcvt.h.lu", MATCH_FCVT_H_LU, MASK_FCVT_H_LU, "ds", EXT1(EXT_ZHINX)},
  {"fcvt.h.w",  MATCH_FCVT_H_W,  MASK_FCVT_H_W,  "ds", EXT1(EXT_ZHINX)},
  {"fcvt.h.wu", MATCH_FCVT_H_WU, MASK_FCVT_H_WU, "ds", EXT1(EXT_ZHINX)},
  {"fcvt.l.h",  MATCH_FCVT_L_H,  MASK_FCVT_L_H,  "ds", EXT1(EXT_ZHINX)},
  {"fcvt.lu.h", MATCH_FCVT_LU_H, MASK_FCVT_LU_H, "ds", EXT1(EXT_ZHINX)},
  {"fcvt.w.h",  MATCH_FCVT_W_H,  MASK_FCVT_W_H,  "ds", EXT1(EXT_ZHINX)},
  {"fcvt.wu.h", MATCH_FCVT_WU_H, MASK_FCVT_WU_H, "ds", EXT1(EXT_ZHINX)},
  {"fclass.h",  MATCH_FCLASS_H,  MASK_FCLASS_H,  "ds", EXT1(EXT_ZHINX)},
  {"feq.h",     MATCH_FEQ_H,     MASK_FEQ_H,     "dst", EXT1(EXT_ZHINX)},
  {"flt.h",     MATCH_FLT_H,     MASK_FLT_H,     "dst", EXT1(EXT_ZHINX)},
  {"fle.h",     MATCH_FLE_H,     MASK_FLE_H,     "dst", EXT1(EXT_ZHINX)},
  // zfhmin_insns
  {"fcvt.h.s", MATCH_FCVT_H_S, MASK_FCVT_H_S, "DS", EXT1(EXT_ZFHMIN)},
  {"fcvt.h.d", MATCH_FCVT_H_D, MASK_FCVT_H_D, "DS", EXT1(EXT_ZFHMIN)},
  {"fcvt.h.q", MATCH_FCVT_H_Q, MASK_FCVT_H_Q, "DS", EXT1(EXT_ZFHMIN)},
  {"fcvt.s.h", MATCH_FCVT_S_H, MASK_FCVT_S_H, "DS", EXT1(EXT_ZFHMIN)},
  {"fcvt.d.h", MATCH_FCVT_D_H, MASK_FCVT_D_H, "DS", EXT1(EXT_ZFHMIN)},
  {"fcvt.q.h", MATCH_FCVT_Q_H, MASK_FCVT_Q_H, "DS", EXT1(EXT_ZFHMIN)},
  // zfh_move_insns
  {"flh",    MATCH_FLH,    MASK_FLH,    "Do", EXT1(EXT_INTERNAL_ZFH_MOVE)},
  {"fsh",    MATCH_FSH,    MASK_FSH,    "Tq", EXT1(EXT_INTERNAL_ZFH_MOVE)},
  {"fmv.h.x", MATCH_FMV_H_X, MASK_FMV_H_X, "Ds", EXT1(EXT_INTERNAL_ZFH_MOVE)},
  {"fmv.x.h", MATCH_FMV_X_H, MASK_FMV_X_H, "dS", EXT1(EXT_INTERNAL_ZFH_MOVE)},
  // zhinxmin_insns
  {"fcvt.h.s", MATCH_FCVT_H_S, MASK_FCVT_H_S, "ds", EXT1(EXT_ZHINXMIN)},
  {"fcvt.h.d", MATCH_FCVT_H_D, MASK_FCVT_H_D, "ds", EXT1(EXT_ZHINXMIN)},
  {"fcvt.s.h", MATCH_FCVT_S_H, MASK_FCVT_S_H, "ds", EXT1(EXT_ZHINXMIN)},
  {"fcvt.d.h", MATCH_FCVT_D_H, MASK_FCVT_D_H, "ds", EXT1(EXT_ZHINXMIN)},
  // zibi_insns
  {"beqi", MATCH_BEQI, MASK_BEQI, "s>p", EXT1(EXT_ZIBI)},
  {"bnei", MATCH_BNEI, MASK_BNEI, "s>p", EXT1(EXT_ZIBI)},
  // q_ext_insns
  {"flq", MATCH_FLQ, MASK_FLQ, "Do", EXT1('Q')},
  {"fsq", MATCH_FSQ, MASK_FSQ, "Tq", EXT1('Q')},
  {"fadd.q",    MATCH_FADD_Q,    MASK_FADD_Q,    "DST", EXT1('Q')},
  {"fsub.q",    MATCH_FSUB_Q,    MASK_FSUB_Q,    "DST", EXT1('Q')},
  {"fmul.q",    MATCH_FMUL_Q,    MASK_FMUL_Q,    "DST", EXT1('Q')},
  {"fdiv.q",    MATCH_FDIV_Q,    MASK_FDIV_Q,    "DST", EXT1('Q')},
  {"fsqrt.q",   MATCH_FSQRT_Q,   MASK_FSQRT_Q,   "DS", EXT1('Q')},
  {"fmin.q",    MATCH_FMIN_Q,    MASK_FMIN_Q,    "DST", EXT1('Q')},
  {"fmax.q",    MATCH_FMAX_Q,    MASK_FMAX_Q,    "DST", EXT1('Q')},
  {"fmadd.q",   MATCH_FMADD_Q,   MASK_FMADD_Q,   "DSTR", EXT1('Q')},
  {"fmsub.q",   MATCH_FMSUB_Q,   MASK_FMSUB_Q,   "DSTR", EXT1('Q')},
  {"fnmadd.q",  MATCH_FNMADD_Q,  MASK_FNMADD_Q,  "DSTR", EXT1('Q')},
  {"fnmsub.q",  MATCH_FNMSUB_Q,  MASK_FNMSUB_Q,  "DSTR", EXT1('Q')},
  {"fsgnj.q",   MATCH_FSGNJ_Q,   MASK_FSGNJ_Q,   "DST", EXT1('Q')},
  {"fsgnjn.q",  MATCH_FSGNJN_Q,  MASK_FSGNJN_Q,  "DST", EXT1('Q')},
  {"fsgnjx.q",  MATCH_FSGNJX_Q,  MASK_FSGNJX_Q,  "DST", EXT1('Q')},
  {"fcvt.q.s",  MATCH_FCVT_Q_S,  MASK_FCVT_Q_S,  "DS", EXT1('Q')},
  {"fcvt.q.d",  MATCH_FCVT_Q_D,  MASK_FCVT_Q_D,  "DS", EXT1('Q')},
  {"fcvt.q.l",  MATCH_FCVT_Q_L,  MASK_FCVT_Q_L,  "Ds", EXT1('Q')},
  {"fcvt.q.lu", MATCH_FCVT_Q_LU, MASK_FCVT_Q_LU, "Ds", EXT1('Q')},
  {"fcvt.q.w",  MATCH_FCVT_Q_W,  MASK_FCVT_Q_W,  "Ds", EXT1('Q')},
  {"fcvt.q.wu", MATCH_FCVT_Q_WU, MASK_FCVT_Q_WU, "Ds", EXT1('Q')},
  {"fcvt.l.q",  MATCH_FCVT_L_Q,  MASK_FCVT_L_Q,  "dS", EXT1('Q')},
  {"fcvt.lu.q", MATCH_FCVT_LU_Q, MASK_FCVT_LU_Q, "dS", EXT1('Q')},
  {"fcvt.w.q",  MATCH_FCVT_W_Q,  MASK_FCVT_W_Q,  "dS", EXT1('Q')},
  {"fcvt.wu.q", MATCH_FCVT_WU_Q, MASK_FCVT_WU_Q, "dS", EXT1('Q')},
  {"fclass.q",  MATCH_FCLASS_Q,  MASK_FCLASS_Q,  "dS", EXT1('Q')},
  {"feq.q",     MATCH_FEQ_Q,     MASK_FEQ_Q,     "dST", EXT1('Q')},
  {"flt.q",     MATCH_FLT_Q,     MASK_FLT_Q,     "dST", EXT1('Q')},
  {"fle.q",     MATCH_FLE_Q,     MASK_FLE_Q,     "dST", EXT1('Q')},
  // zfbfmin_insns
  {"fcvt.bf16.s", MATCH_FCVT_BF16_S, MASK_FCVT_BF16_S, "DS", EXT1(EXT_ZFBFMIN)},
  {"fcvt.s.bf16", MATCH_FCVT_S_BF16, MASK_FCVT_S_BF16, "DS", EXT1(EXT_ZFBFMIN)},
  // h_ext_insns
  {"hlv.b",   MATCH_HLV_B,   MASK_HLV_B,   "d(", EXT1('H')},
  {"hlv.bu",  MATCH_HLV_BU,  MASK_HLV_BU,  "d(", EXT1('H')},
  {"hlv.h",   MATCH_HLV_H,   MASK_HLV_H,   "d(", EXT1('H')},
  {"hlv.hu",  MATCH_HLV_HU,  MASK_HLV_HU,  "d(", EXT1('H')},
  {"hlv.w",   MATCH_HLV_W,   MASK_HLV_W,   "d(", EXT1('H')},
  {"hlv.wu",  MATCH_HLV_WU,  MASK_HLV_WU,  "d(", EXT1('H')},
  {"hlv.d",   MATCH_HLV_D,   MASK_HLV_D,   "d(", EXT1('H')},
  {"hlvx.hu", MATCH_HLVX_HU, MASK_HLVX_HU, "d(", EXT1('H')},
  {"hlvx.wu", MATCH_HLVX_WU, MASK_HLVX_WU, "d(", EXT1('H')},
  {"hsv.b",   MATCH_HSV_B,   MASK_HSV_B,   "t(", EXT1('H')},
  {"hsv.h",   MATCH_HSV_H,   MASK_HSV_H,   "t(", EXT1('H')},
  {"hsv.w",   MATCH_HSV_W,   MASK_HSV_W,   "t(", EXT1('H')},
  {"hsv.d",   MATCH_HSV_D,   MASK_HSV_D,   "t(", EXT1('H')},
  {"hfence.gvma", MATCH_HFENCE_GVMA, MASK_HFENCE_GVMA, "st", EXT1('H')},
  {"hfence.vvma", MATCH_HFENCE_VVMA, MASK_HFENCE_VVMA, "st", EXT1('H')},
  // zca_insns
  {"c.ebreak",   MATCH_C_ADD,  MASK_C_ADD | 0xf80u | 0x7cu,         "", EXT1(EXT_ZCA)},
  {"ret",        MATCH_C_JR  | 0x80u, MASK_C_JR | 0xf80u | 0x107cu, "", EXT1(EXT_ZCA)},
  {"c.jr",       MATCH_C_JR,   MASK_C_JR  | 0x107cu,                "e", EXT1(EXT_ZCA)},
  {"c.jalr",     MATCH_C_JALR, MASK_C_JALR | 0x107cu,               "e", EXT1(EXT_ZCA)},
  {"c.nop",      MATCH_C_ADDI, MASK_C_ADDI | 0xf80u | 0x107cu,      "", EXT1(EXT_ZCA)},
  {"c.addi16sp", MATCH_C_ADDI16SP, MASK_C_ADDI16SP | 0xf80u,        "Nx", EXT1(EXT_ZCA)},
  {"c.addi4spn", MATCH_C_ADDI4SPN, MASK_C_ADDI4SPN,                 "JNn", EXT1(EXT_ZCA)},
  {"c.li",       MATCH_C_LI,   MASK_C_LI,   "di", EXT1(EXT_ZCA)},
  {"c.lui",      MATCH_C_LUI,  MASK_C_LUI,  "db", EXT1(EXT_ZCA)},
  {"c.addi",     MATCH_C_ADDI, MASK_C_ADDI, "di", EXT1(EXT_ZCA)},
  {"c.slli",     MATCH_C_SLLI, MASK_C_SLLI, "eh", EXT1(EXT_ZCA)},
  {"c.srli",     MATCH_C_SRLI, MASK_C_SRLI, "Hh", EXT1(EXT_ZCA)},
  {"c.srai",     MATCH_C_SRAI, MASK_C_SRAI, "Hh", EXT1(EXT_ZCA)},
  {"c.andi",     MATCH_C_ANDI, MASK_C_ANDI, "Hi", EXT1(EXT_ZCA)},
  {"c.mv",       MATCH_C_MV,   MASK_C_MV,   "df", EXT1(EXT_ZCA)},
  {"c.add",      MATCH_C_ADD,  MASK_C_ADD,  "df", EXT1(EXT_ZCA)},
  {"c.sub",      MATCH_C_SUB,  MASK_C_SUB,  "HJ", EXT1(EXT_ZCA)},
  {"c.and",      MATCH_C_AND,  MASK_C_AND,  "HJ", EXT1(EXT_ZCA)},
  {"c.or",       MATCH_C_OR,   MASK_C_OR,   "HJ", EXT1(EXT_ZCA)},
  {"c.xor",      MATCH_C_XOR,  MASK_C_XOR,  "HJ", EXT1(EXT_ZCA)},
  {"c.lwsp",     MATCH_C_LWSP, MASK_C_LWSP, "d@", EXT1(EXT_ZCA)},
  {"c.swsp",     MATCH_C_SWSP, MASK_C_SWSP, "f_", EXT1(EXT_ZCA)},
  {"c.lw",       MATCH_C_LW,   MASK_C_LW,   "Jc", EXT1(EXT_ZCA)},
  {"c.sw",       MATCH_C_SW,   MASK_C_SW,   "Jc", EXT1(EXT_ZCA)},
  {"c.beqz",     MATCH_C_BEQZ, MASK_C_BEQZ, "Hy", EXT1(EXT_ZCA)},
  {"c.bnez",     MATCH_C_BNEZ, MASK_C_BNEZ, "Hy", EXT1(EXT_ZCA)},
  {"c.j",        MATCH_C_J,    MASK_C_J,    "w", EXT1(EXT_ZCA)},
  // zca32_insns
  {"c.jal", MATCH_C_JAL, MASK_C_JAL, "w", EXT1_XVS(EXT_ZCA,32)},
  // zca_not32_insns
  {"c.addiw", MATCH_C_ADDIW, MASK_C_ADDIW, "di", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZCA) || !s) && isa->get_max_xlen() != 32; }},
  // zca64_insns
  {"c.addw", MATCH_C_ADDW, MASK_C_ADDW, "HJ", EXT1_XV(EXT_ZCA,64)},
  {"c.subw", MATCH_C_SUBW, MASK_C_SUBW, "HJ", EXT1_XV(EXT_ZCA,64)},
  // zca_ld_insns
  {"c.ld",   MATCH_C_LD,   MASK_C_LD,   "Jv", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZCA) || !s) && (isa->get_max_xlen() == 64 || isa->extension_enabled(EXT_ZCLSD)); }},
  {"c.ldsp", MATCH_C_LDSP, MASK_C_LDSP, "dM", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZCA) || !s) && (isa->get_max_xlen() == 64 || isa->extension_enabled(EXT_ZCLSD)); }},
  {"c.sd",   MATCH_C_SD,   MASK_C_SD,   "Jv", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZCA) || !s) && (isa->get_max_xlen() == 64 || isa->extension_enabled(EXT_ZCLSD)); }},
  {"c.sdsp", MATCH_C_SDSP, MASK_C_SDSP, "fg", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZCA) || !s) && (isa->get_max_xlen() == 64 || isa->extension_enabled(EXT_ZCLSD)); }},
  // zcd_insns
  {"c.fld",   MATCH_C_FLD,   MASK_C_FLD,   "#v", EXT1(EXT_ZCD)},
  {"c.fldsp", MATCH_C_FLDSP, MASK_C_FLDSP, "DM", EXT1(EXT_ZCD)},
  {"c.fsd",   MATCH_C_FSD,   MASK_C_FSD,   "#v", EXT1(EXT_ZCD)},
  {"c.fsdsp", MATCH_C_FSDSP, MASK_C_FSDSP, "Fg", EXT1(EXT_ZCD)},
  // zcf_insns
  {"c.flw",   MATCH_C_FLW,   MASK_C_FLW,   "#c", EXT1(EXT_ZCF)},
  {"c.flwsp", MATCH_C_FLWSP, MASK_C_FLWSP, "D@", EXT1(EXT_ZCF)},
  {"c.fsw",   MATCH_C_FSW,   MASK_C_FSW,   "#c", EXT1(EXT_ZCF)},
  {"c.fswsp", MATCH_C_FSWSP, MASK_C_FSWSP, "F_", EXT1(EXT_ZCF)},
  // zcb_insns
  {"c.zext.b", MATCH_C_ZEXT_B, MASK_C_ZEXT_B, "H", EXT1(EXT_ZCB)},
  {"c.sext.b", MATCH_C_SEXT_B, MASK_C_SEXT_B, "H", EXT1(EXT_ZCB)},
  {"c.zext.h", MATCH_C_ZEXT_H, MASK_C_ZEXT_H, "H", EXT1(EXT_ZCB)},
  {"c.sext.h", MATCH_C_SEXT_H, MASK_C_SEXT_H, "H", EXT1(EXT_ZCB)},
  {"c.not",    MATCH_C_NOT,    MASK_C_NOT,    "H", EXT1(EXT_ZCB)},
  {"c.mul",    MATCH_C_MUL,    MASK_C_MUL,    "HJ", EXT1(EXT_ZCB)},
  {"c.lbu",    MATCH_C_LBU,    MASK_C_LBU,    "J*", EXT1(EXT_ZCB)},
  {"c.lhu",    MATCH_C_LHU,    MASK_C_LHU,    "J/", EXT1(EXT_ZCB)},
  {"c.lh",     MATCH_C_LH,     MASK_C_LH,     "J/", EXT1(EXT_ZCB)},
  {"c.sb",     MATCH_C_SB,     MASK_C_SB,     "J*", EXT1(EXT_ZCB)},
  {"c.sh",     MATCH_C_SH,     MASK_C_SH,     "J/", EXT1(EXT_ZCB)},
  // zcb64_insns
  {"c.zext.w", MATCH_C_ZEXT_W, MASK_C_ZEXT_W, "H", EXT1_XV(EXT_ZCB,64)},
  // zcmp32_insns
  {"cm.push",    MATCH_CM_PUSH,    MASK_CM_PUSH,    "!2", EXT1_XVS(EXT_ZCMP,32)},
  {"cm.pop",     MATCH_CM_POP,     MASK_CM_POP,     "!3", EXT1_XVS(EXT_ZCMP,32)},
  {"cm.popret",  MATCH_CM_POPRET,  MASK_CM_POPRET,  "!3", EXT1_XVS(EXT_ZCMP,32)},
  {"cm.popretz", MATCH_CM_POPRETZ, MASK_CM_POPRETZ, "!3", EXT1_XVS(EXT_ZCMP,32)},
  // zcmp64_insns
  {"cm.push",    MATCH_CM_PUSH,    MASK_CM_PUSH,    "!4", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZCMP) || !s) && isa->get_max_xlen() != 32; }},
  {"cm.pop",     MATCH_CM_POP,     MASK_CM_POP,     "!8", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZCMP) || !s) && isa->get_max_xlen() != 32; }},
  {"cm.popret",  MATCH_CM_POPRET,  MASK_CM_POPRET,  "!8", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZCMP) || !s) && isa->get_max_xlen() != 32; }},
  {"cm.popretz", MATCH_CM_POPRETZ, MASK_CM_POPRETZ, "!8", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZCMP) || !s) && isa->get_max_xlen() != 32; }},
  // zcmp_common_insns
  {"cm.mva01s", MATCH_CM_MVA01S, MASK_CM_MVA01S, "VO", EXT1(EXT_ZCMP)},
  {"cm.mvsa01", MATCH_CM_MVSA01, MASK_CM_MVSA01, "VO", EXT1(EXT_ZCMP)},
  // zcmt_insns
  {"cm.jt",   MATCH_CM_JALT, MASK_CM_JALT | 0x380u, "1", EXT1(EXT_ZCMT)},
  {"cm.jalt", MATCH_CM_JALT, MASK_CM_JALT,           "1", EXT1(EXT_ZCMT)},
  // zmmul_insns
  {"mul",    MATCH_MUL,    MASK_MUL,    "dst", EXT1(EXT_ZMMUL)},
  {"mulh",   MATCH_MULH,   MASK_MULH,   "dst", EXT1(EXT_ZMMUL)},
  {"mulhu",  MATCH_MULHU,  MASK_MULHU,  "dst", EXT1(EXT_ZMMUL)},
  {"mulhsu", MATCH_MULHSU, MASK_MULHSU, "dst", EXT1(EXT_ZMMUL)},
  // zmmul64_insns
  {"mulw",   MATCH_MULW,   MASK_MULW,   "dst", EXT1_XV(EXT_ZMMUL,64)},
  // zicbom_insns
  {"cbo.clean", MATCH_CBO_CLEAN, MASK_CBO_CLEAN, "(", EXT1(EXT_ZICBOM)},
  {"cbo.flush", MATCH_CBO_FLUSH, MASK_CBO_FLUSH, "(", EXT1(EXT_ZICBOM)},
  {"cbo.inval", MATCH_CBO_INVAL, MASK_CBO_INVAL, "(", EXT1(EXT_ZICBOM)},
  // zicboz_insns
  {"cbo.zero",  MATCH_CBO_ZERO,  MASK_CBO_ZERO,  "(", EXT1(EXT_ZICBOZ)},
  // zicond_insns
  {"czero.eqz", MATCH_CZERO_EQZ, MASK_CZERO_EQZ, "dst", EXT1(EXT_ZICOND)},
  {"czero.nez", MATCH_CZERO_NEZ, MASK_CZERO_NEZ, "dst", EXT1(EXT_ZICOND)},
  // zknd_zknde_insns
  // aes64ks1i is explicit (has rcon immediate)
  {"aes64ks2", MATCH_AES64KS2, MASK_AES64KS2, "dst", [](const isa_parser_t *isa, bool s) -> bool { return isa->extension_enabled(EXT_ZKND) || isa->extension_enabled(EXT_ZKNE) || !s; }},
  // zknd64_insns
  {"aes64ds",  MATCH_AES64DS,  MASK_AES64DS,  "dst", EXT1_XV(EXT_ZKND,64)},
  {"aes64dsm", MATCH_AES64DSM, MASK_AES64DSM, "dst", EXT1_XV(EXT_ZKND,64)},
  {"aes64im",  MATCH_AES64IM,  MASK_AES64IM,  "ds", EXT1_XV(EXT_ZKND,64)},
  // zkne64_insns
  {"aes64es",  MATCH_AES64ES,  MASK_AES64ES,  "dst", EXT1_XV(EXT_ZKNE,64)},
  {"aes64esm", MATCH_AES64ESM, MASK_AES64ESM, "dst", EXT1_XV(EXT_ZKNE,64)},
  // zknh_insns
  {"sha256sig0", MATCH_SHA256SIG0, MASK_SHA256SIG0, "ds", EXT1(EXT_ZKNH)},
  {"sha256sig1", MATCH_SHA256SIG1, MASK_SHA256SIG1, "ds", EXT1(EXT_ZKNH)},
  {"sha256sum0", MATCH_SHA256SUM0, MASK_SHA256SUM0, "ds", EXT1(EXT_ZKNH)},
  {"sha256sum1", MATCH_SHA256SUM1, MASK_SHA256SUM1, "ds", EXT1(EXT_ZKNH)},
  // zknh64_insns
  {"sha512sig0", MATCH_SHA512SIG0, MASK_SHA512SIG0, "ds", EXT1_XV(EXT_ZKNH,64)},
  {"sha512sig1", MATCH_SHA512SIG1, MASK_SHA512SIG1, "ds", EXT1_XV(EXT_ZKNH,64)},
  {"sha512sum0", MATCH_SHA512SUM0, MASK_SHA512SUM0, "ds", EXT1_XV(EXT_ZKNH,64)},
  {"sha512sum1", MATCH_SHA512SUM1, MASK_SHA512SUM1, "ds", EXT1_XV(EXT_ZKNH,64)},
  // zknh32_insns
  {"sha512sig0h", MATCH_SHA512SIG0H, MASK_SHA512SIG0H, "dst", EXT1_XV(EXT_ZKNH,32)},
  {"sha512sig0l", MATCH_SHA512SIG0L, MASK_SHA512SIG0L, "dst", EXT1_XV(EXT_ZKNH,32)},
  {"sha512sig1h", MATCH_SHA512SIG1H, MASK_SHA512SIG1H, "dst", EXT1_XV(EXT_ZKNH,32)},
  {"sha512sig1l", MATCH_SHA512SIG1L, MASK_SHA512SIG1L, "dst", EXT1_XV(EXT_ZKNH,32)},
  {"sha512sum0r", MATCH_SHA512SUM0R, MASK_SHA512SUM0R, "dst", EXT1_XV(EXT_ZKNH,32)},
  {"sha512sum1r", MATCH_SHA512SUM1R, MASK_SHA512SUM1R, "dst", EXT1_XV(EXT_ZKNH,32)},
  // zksed_insns
  {"sm4ed", MATCH_SM4ED, MASK_SM4ED, "dst-", EXT1(EXT_ZKSED)},
  {"sm4ks", MATCH_SM4KS, MASK_SM4KS, "dst-", EXT1(EXT_ZKSED)},
  // zksh_insns
  {"sm3p0", MATCH_SM3P0, MASK_SM3P0, "ds", EXT1(EXT_ZKSH)},
  {"sm3p1", MATCH_SM3P1, MASK_SM3P1, "ds", EXT1(EXT_ZKSH)},
  // zalasr_insns
  {"lb.aq",  MATCH_LB_AQ,  MASK_LB_AQ,  "d(", EXT1(EXT_ZALASR)},
  {"lh.aq",  MATCH_LH_AQ,  MASK_LH_AQ,  "d(", EXT1(EXT_ZALASR)},
  {"lw.aq",  MATCH_LW_AQ,  MASK_LW_AQ,  "d(", EXT1(EXT_ZALASR)},
  {"ld.aq",  MATCH_LD_AQ,  MASK_LD_AQ,  "d(", EXT1(EXT_ZALASR)},
  {"sb.rl",  MATCH_SB_RL,  MASK_SB_RL,  "t(", EXT1(EXT_ZALASR)},
  {"sh.rl",  MATCH_SH_RL,  MASK_SH_RL,  "t(", EXT1(EXT_ZALASR)},
  {"sw.rl",  MATCH_SW_RL,  MASK_SW_RL,  "t(", EXT1(EXT_ZALASR)},
  {"sd.rl",  MATCH_SD_RL,  MASK_SD_RL,  "t(", EXT1(EXT_ZALASR)},
  // zicfiss_insns
  {"sspush",   MATCH_SSPUSH_X1, MASK_SSPUSH_X1, "t", EXT1(EXT_ZICFISS)},
  {"sspush",   MATCH_SSPUSH_X5, MASK_SSPUSH_X5, "t", EXT1(EXT_ZICFISS)},
  {"sspopchk", MATCH_SSPOPCHK_X1, MASK_SSPOPCHK_X1, "s", EXT1(EXT_ZICFISS)},
  {"sspopchk", MATCH_SSPOPCHK_X5, MASK_SSPOPCHK_X5, "s", EXT1(EXT_ZICFISS)},
  {"ssrdp",    MATCH_SSRDP,    MASK_SSRDP,    "d", EXT1(EXT_ZICFISS)},
  // zicfiss_zca_insns
  {"c.sspush",   MATCH_C_SSPUSH_X1,   MASK_C_SSPUSH_X1,   "X", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZICFISS) && isa->extension_enabled(EXT_ZCA)) || !s; }},
  {"c.sspopchk", MATCH_C_SSPOPCHK_X5, MASK_C_SSPOPCHK_X5, "Y", [](const isa_parser_t *isa, bool s) -> bool { return (isa->extension_enabled(EXT_ZICFISS) && isa->extension_enabled(EXT_ZCA)) || !s; }},
  // P-extension
  {"aadd", MATCH_AADD, MASK_AADD, "dst", EXT1_XVS('P',32)},
  {"aaddu", MATCH_AADDU, MASK_AADDU, "dst", EXT1_XVS('P',32)},
  {"asub", MATCH_ASUB, MASK_ASUB, "dst", EXT1_XVS('P',32)},
  {"asubu", MATCH_ASUBU, MASK_ASUBU, "dst", EXT1_XVS('P',32)},
  {"mseq", MATCH_MSEQ, MASK_MSEQ, "dst", EXT1_XVS('P',32)},
  {"mslt", MATCH_MSLT, MASK_MSLT, "dst", EXT1_XVS('P',32)},
  {"msltu", MATCH_MSLTU, MASK_MSLTU, "dst", EXT1_XVS('P',32)},
  {"addd", MATCH_ADDD, MASK_ADDD, "PQU", EXT1('P')},
  {"subd", MATCH_SUBD, MASK_SUBD, "PQU", EXT1('P')},
  {"merge", MATCH_MERGE, MASK_MERGE, "dst", EXT1('P')},
  {"mvm", MATCH_MVM, MASK_MVM, "dst", EXT1('P')},
  {"mvmn", MATCH_MVMN, MASK_MVMN, "dst", EXT1('P')},
  {"nclip", MATCH_NCLIP, MASK_NCLIP, "dQt", EXT1('P')},
  {"nclipr", MATCH_NCLIPR, MASK_NCLIPR, "dQt", EXT1('P')},
  {"nclipu", MATCH_NCLIPU, MASK_NCLIPU, "dQt", EXT1('P')},
  {"nclipru", MATCH_NCLIPRU, MASK_NCLIPRU, "dQt", EXT1('P')},
  {"nsra", MATCH_NSRA, MASK_NSRA, "dQt", EXT1('P')},
  {"nsrar", MATCH_NSRAR, MASK_NSRAR, "dQt", EXT1('P')},
  {"nsrl", MATCH_NSRL, MASK_NSRL, "dQt", EXT1('P')},
  {"sadd", MATCH_SADD, MASK_SADD, "dst", EXT1_XVS('P',32)},
  {"saddu", MATCH_SADDU, MASK_SADDU, "dst", EXT1_XVS('P',32)},
  {"ssub", MATCH_SSUB, MASK_SSUB, "dst", EXT1_XVS('P',32)},
  {"ssubu", MATCH_SSUBU, MASK_SSUBU, "dst", EXT1_XVS('P',32)},
  {"ssh1sadd", MATCH_SSH1SADD, MASK_SSH1SADD, "dst", EXT1_XVS('P',32)},
  {"ssha", MATCH_SSHA, MASK_SSHA, "dst", EXT1_XVS('P',32)},
  {"sshar", MATCH_SSHAR, MASK_SSHAR, "dst", EXT1_XVS('P',32)},
  {"sshl", MATCH_SSHL, MASK_SSHL, "dst", EXT1_XVS('P',32)},
  {"sshlr", MATCH_SSHLR, MASK_SSHLR, "dst", EXT1_XVS('P',32)},
  {"sha", MATCH_SHA, MASK_SHA, "PQU", EXT1('P')},
  {"shar", MATCH_SHAR, MASK_SHAR, "PQU", EXT1('P')},
  {"slx", MATCH_SLX, MASK_SLX, "dst", EXT1('P')},
  {"srx", MATCH_SRX, MASK_SRX, "dst", EXT1('P')},
  {"wadd", MATCH_WADD, MASK_WADD, "Pst", EXT1('P')},
  {"wadda", MATCH_WADDA, MASK_WADDA, "Pst", EXT1('P')},
  {"waddu", MATCH_WADDU, MASK_WADDU, "Pst", EXT1('P')},
  {"waddau", MATCH_WADDAU, MASK_WADDAU, "Pst", EXT1('P')},
  {"wsub", MATCH_WSUB, MASK_WSUB, "Pst", EXT1('P')},
  {"wsuba", MATCH_WSUBA, MASK_WSUBA, "Pst", EXT1('P')},
  {"wsubu", MATCH_WSUBU, MASK_WSUBU, "Pst", EXT1('P')},
  {"wsubau", MATCH_WSUBAU, MASK_WSUBAU, "Pst", EXT1('P')},
  {"wsll", MATCH_WSLL, MASK_WSLL, "Pst", EXT1('P')},
  {"wsla", MATCH_WSLA, MASK_WSLA, "Pst", EXT1('P')},
  {"wmul", MATCH_WMUL, MASK_WMUL, "Pst", EXT1('P')},
  {"wmulu", MATCH_WMULU, MASK_WMULU, "Pst", EXT1('P')},
  {"wmulsu", MATCH_WMULSU, MASK_WMULSU, "Pst", EXT1('P')},
  {"wmacc", MATCH_WMACC, MASK_WMACC, "Pst", EXT1('P')},
  {"wmaccu", MATCH_WMACCU, MASK_WMACCU, "Pst", EXT1('P')},
  {"wmaccsu", MATCH_WMACCSU, MASK_WMACCSU, "Pst", EXT1('P')},
  {"macc.h00", MATCH_MACC_H00, MASK_MACC_H00, "dst", EXT1_XVS('P',32)},
  {"macc.h01", MATCH_MACC_H01, MASK_MACC_H01, "dst", EXT1_XVS('P',32)},
  {"macc.h11", MATCH_MACC_H11, MASK_MACC_H11, "dst", EXT1_XVS('P',32)},
  {"maccu.h00", MATCH_MACCU_H00, MASK_MACCU_H00, "dst", EXT1_XVS('P',32)},
  {"maccu.h01", MATCH_MACCU_H01, MASK_MACCU_H01, "dst", EXT1_XVS('P',32)},
  {"maccu.h11", MATCH_MACCU_H11, MASK_MACCU_H11, "dst", EXT1_XVS('P',32)},
  {"maccsu.h00", MATCH_MACCSU_H00, MASK_MACCSU_H00, "dst", EXT1_XVS('P',32)},
  {"maccsu.h11", MATCH_MACCSU_H11, MASK_MACCSU_H11, "dst", EXT1_XVS('P',32)},
  {"mul.h00", MATCH_MUL_H00, MASK_MUL_H00, "dst", EXT1_XVS('P',32)},
  {"mul.h01", MATCH_MUL_H01, MASK_MUL_H01, "dst", EXT1_XVS('P',32)},
  {"mul.h11", MATCH_MUL_H11, MASK_MUL_H11, "dst", EXT1_XVS('P',32)},
  {"mulu.h00", MATCH_MULU_H00, MASK_MULU_H00, "dst", EXT1_XVS('P',32)},
  {"mulu.h01", MATCH_MULU_H01, MASK_MULU_H01, "dst", EXT1_XVS('P',32)},
  {"mulu.h11", MATCH_MULU_H11, MASK_MULU_H11, "dst", EXT1_XVS('P',32)},
  {"mulsu.h00", MATCH_MULSU_H00, MASK_MULSU_H00, "dst", EXT1_XVS('P',32)},
  {"mulsu.h11", MATCH_MULSU_H11, MASK_MULSU_H11, "dst", EXT1_XVS('P',32)},
  {"mulh.h0", MATCH_MULH_H0, MASK_MULH_H0, "dst", EXT1_XVS('P',32)},
  {"mulh.h1", MATCH_MULH_H1, MASK_MULH_H1, "dst", EXT1_XVS('P',32)},
  {"mulhsu.h0", MATCH_MULHSU_H0, MASK_MULHSU_H0, "dst", EXT1_XVS('P',32)},
  {"mulhsu.h1", MATCH_MULHSU_H1, MASK_MULHSU_H1, "dst", EXT1_XVS('P',32)},
  {"mulhr", MATCH_MULHR, MASK_MULHR, "dst", EXT1_XVS('P',32)},
  {"mulhru", MATCH_MULHRU, MASK_MULHRU, "dst", EXT1_XVS('P',32)},
  {"mulhrsu", MATCH_MULHRSU, MASK_MULHRSU, "dst", EXT1_XVS('P',32)},
  {"mulq", MATCH_MULQ, MASK_MULQ, "dst", EXT1_XVS('P',32)},
  {"mulqr", MATCH_MULQR, MASK_MULQR, "dst", EXT1_XVS('P',32)},
  {"mhacc", MATCH_MHACC, MASK_MHACC, "dst", EXT1_XVS('P',32)},
  {"mhaccu", MATCH_MHACCU, MASK_MHACCU, "dst", EXT1_XVS('P',32)},
  {"mhaccsu", MATCH_MHACCSU, MASK_MHACCSU, "dst", EXT1_XVS('P',32)},
  {"mhacc.h0", MATCH_MHACC_H0, MASK_MHACC_H0, "dst", EXT1_XVS('P',32)},
  {"mhacc.h1", MATCH_MHACC_H1, MASK_MHACC_H1, "dst", EXT1_XVS('P',32)},
  {"mhaccsu.h0", MATCH_MHACCSU_H0, MASK_MHACCSU_H0, "dst", EXT1_XVS('P',32)},
  {"mhaccsu.h1", MATCH_MHACCSU_H1, MASK_MHACCSU_H1, "dst", EXT1_XVS('P',32)},
  {"mhracc", MATCH_MHRACC, MASK_MHRACC, "dst", EXT1_XVS('P',32)},
  {"mhraccu", MATCH_MHRACCU, MASK_MHRACCU, "dst", EXT1_XVS('P',32)},
  {"mhraccsu", MATCH_MHRACCSU, MASK_MHRACCSU, "dst", EXT1_XVS('P',32)},
  {"mqacc.h00", MATCH_MQACC_H00, MASK_MQACC_H00, "dst", EXT1('P')},
  {"mqacc.h01", MATCH_MQACC_H01, MASK_MQACC_H01, "dst", EXT1('P')},
  {"mqacc.h11", MATCH_MQACC_H11, MASK_MQACC_H11, "dst", EXT1('P')},
  {"mqracc.h00", MATCH_MQRACC_H00, MASK_MQRACC_H00, "dst", EXT1('P')},
  {"mqracc.h01", MATCH_MQRACC_H01, MASK_MQRACC_H01, "dst", EXT1('P')},
  {"mqracc.h11", MATCH_MQRACC_H11, MASK_MQRACC_H11, "dst", EXT1('P')},
  {"abs", MATCH_ABS, MASK_ABS, "ds", EXT1('P')},
  {"cls", MATCH_CLS, MASK_CLS, "ds", EXT1('P')},
  {"nclipi", MATCH_NCLIPI, MASK_NCLIPI, "ds'", EXT1('P')},
  {"nclipiu", MATCH_NCLIPIU, MASK_NCLIPIU, "ds'", EXT1('P')},
  {"nclipri", MATCH_NCLIPRI, MASK_NCLIPRI, "ds'", EXT1('P')},
  {"nclipriu", MATCH_NCLIPRIU, MASK_NCLIPRIU, "ds'", EXT1('P')},
  {"nsrai", MATCH_NSRAI, MASK_NSRAI, "ds'", EXT1('P')},
  {"nsrari", MATCH_NSRARI, MASK_NSRARI, "ds'", EXT1('P')},
  {"nsrli", MATCH_NSRLI, MASK_NSRLI, "ds'", EXT1('P')},
  {"sslai", MATCH_SSLAI, MASK_SSLAI, "dsZ", EXT1_XVS('P',32)},
  {"wslli", MATCH_WSLLI, MASK_WSLLI, "dsZ", EXT1('P')},
  {"wslai", MATCH_WSLAI, MASK_WSLAI, "dsZ", EXT1('P')},
  {"sati", MATCH_SATI, MASK_SATI, "dsZ", EXT1_XVS('P',64)},
  {"usati", MATCH_USATI, MASK_USATI, "dsZ", EXT1_XVS('P',64)},
  {"srari", MATCH_SRARI, MASK_SRARI, "dsZ", EXT1_XVS('P',64)},
  {"sati", MATCH_SATI_RV32, MASK_SATI_RV32, "dsZ", EXT1_XVS('P',64)},
  {"usati", MATCH_USATI_RV32, MASK_USATI_RV32, "dsZ", EXT1_XVS('P',64)},
  {"srari", MATCH_SRARI_RV32, MASK_SRARI_RV32, "dsZ", EXT1_XVS('P',64)},
  {"paadd.b", MATCH_PAADD_B, MASK_PAADD_B, "dst", EXT1('P')},
  {"paadd.h", MATCH_PAADD_H, MASK_PAADD_H, "dst", EXT1('P')},
  {"paadd.db", MATCH_PAADD_DB, MASK_PAADD_DB, "PQU", EXT1('P')},
  {"paadd.dh", MATCH_PAADD_DH, MASK_PAADD_DH, "PQU", EXT1('P')},
  {"paadd.dw", MATCH_PAADD_DW, MASK_PAADD_DW, "PQU", EXT1('P')},
  {"paaddu.b", MATCH_PAADDU_B, MASK_PAADDU_B, "dst", EXT1('P')},
  {"paaddu.h", MATCH_PAADDU_H, MASK_PAADDU_H, "dst", EXT1('P')},
  {"paaddu.db", MATCH_PAADDU_DB, MASK_PAADDU_DB, "PQU", EXT1('P')},
  {"paaddu.dh", MATCH_PAADDU_DH, MASK_PAADDU_DH, "PQU", EXT1('P')},
  {"paaddu.dw", MATCH_PAADDU_DW, MASK_PAADDU_DW, "PQU", EXT1('P')},
  {"paas.hx", MATCH_PAAS_HX, MASK_PAAS_HX, "dst", EXT1('P')},
  {"paas.dhx", MATCH_PAAS_DHX, MASK_PAAS_DHX, "PQU", EXT1('P')},
  {"pabd.b", MATCH_PABD_B, MASK_PABD_B, "dst", EXT1('P')},
  {"pabd.h", MATCH_PABD_H, MASK_PABD_H, "dst", EXT1('P')},
  {"pabd.db", MATCH_PABD_DB, MASK_PABD_DB, "PQU", EXT1('P')},
  {"pabd.dh", MATCH_PABD_DH, MASK_PABD_DH, "PQU", EXT1('P')},
  {"pabdu.b", MATCH_PABDU_B, MASK_PABDU_B, "dst", EXT1('P')},
  {"pabdu.h", MATCH_PABDU_H, MASK_PABDU_H, "dst", EXT1('P')},
  {"pabdu.db", MATCH_PABDU_DB, MASK_PABDU_DB, "PQU", EXT1('P')},
  {"pabdu.dh", MATCH_PABDU_DH, MASK_PABDU_DH, "PQU", EXT1('P')},
  {"pabdsumu.b", MATCH_PABDSUMU_B, MASK_PABDSUMU_B, "dst", EXT1('P')},
  {"pabdsumau.b", MATCH_PABDSUMAU_B, MASK_PABDSUMAU_B, "dst", EXT1('P')},
  {"padd.b", MATCH_PADD_B, MASK_PADD_B, "dst", EXT1('P')},
  {"padd.h", MATCH_PADD_H, MASK_PADD_H, "dst", EXT1('P')},
  {"padd.bs", MATCH_PADD_BS, MASK_PADD_BS, "dst", EXT1('P')},
  {"padd.hs", MATCH_PADD_HS, MASK_PADD_HS, "dst", EXT1('P')},
  {"padd.db", MATCH_PADD_DB, MASK_PADD_DB, "PQU", EXT1('P')},
  {"padd.dh", MATCH_PADD_DH, MASK_PADD_DH, "PQU", EXT1('P')},
  {"padd.dw", MATCH_PADD_DW, MASK_PADD_DW, "PQU", EXT1('P')},
  {"padd.dbs", MATCH_PADD_DBS, MASK_PADD_DBS, "PQt", EXT1('P')},
  {"padd.dhs", MATCH_PADD_DHS, MASK_PADD_DHS, "PQt", EXT1('P')},
  {"padd.dws", MATCH_PADD_DWS, MASK_PADD_DWS, "PQt", EXT1('P')},
  {"pasub.b", MATCH_PASUB_B, MASK_PASUB_B, "dst", EXT1('P')},
  {"pasub.h", MATCH_PASUB_H, MASK_PASUB_H, "dst", EXT1('P')},
  {"pasub.db", MATCH_PASUB_DB, MASK_PASUB_DB, "PQU", EXT1('P')},
  {"pasub.dh", MATCH_PASUB_DH, MASK_PASUB_DH, "PQU", EXT1('P')},
  {"pasub.dw", MATCH_PASUB_DW, MASK_PASUB_DW, "PQU", EXT1('P')},
  {"pasubu.b", MATCH_PASUBU_B, MASK_PASUBU_B, "dst", EXT1('P')},
  {"pasubu.h", MATCH_PASUBU_H, MASK_PASUBU_H, "dst", EXT1('P')},
  {"pasubu.db", MATCH_PASUBU_DB, MASK_PASUBU_DB, "PQU", EXT1('P')},
  {"pasubu.dh", MATCH_PASUBU_DH, MASK_PASUBU_DH, "PQU", EXT1('P')},
  {"pasubu.dw", MATCH_PASUBU_DW, MASK_PASUBU_DW, "PQU", EXT1('P')},
  {"pasa.hx", MATCH_PASA_HX, MASK_PASA_HX, "dst", EXT1('P')},
  {"pasa.dhx", MATCH_PASA_DHX, MASK_PASA_DHX, "PQU", EXT1('P')},
  {"pas.hx", MATCH_PAS_HX, MASK_PAS_HX, "dst", EXT1('P')},
  {"pas.dhx", MATCH_PAS_DHX, MASK_PAS_DHX, "PQU", EXT1('P')},
  {"psadd.b", MATCH_PSADD_B, MASK_PSADD_B, "dst", EXT1('P')},
  {"psadd.h", MATCH_PSADD_H, MASK_PSADD_H, "dst", EXT1('P')},
  {"psadd.db", MATCH_PSADD_DB, MASK_PSADD_DB, "PQU", EXT1('P')},
  {"psadd.dh", MATCH_PSADD_DH, MASK_PSADD_DH, "PQU", EXT1('P')},
  {"psadd.dw", MATCH_PSADD_DW, MASK_PSADD_DW, "PQU", EXT1('P')},
  {"psaddu.b", MATCH_PSADDU_B, MASK_PSADDU_B, "dst", EXT1('P')},
  {"psaddu.h", MATCH_PSADDU_H, MASK_PSADDU_H, "dst", EXT1('P')},
  {"psaddu.db", MATCH_PSADDU_DB, MASK_PSADDU_DB, "PQU", EXT1('P')},
  {"psaddu.dh", MATCH_PSADDU_DH, MASK_PSADDU_DH, "PQU", EXT1('P')},
  {"psaddu.dw", MATCH_PSADDU_DW, MASK_PSADDU_DW, "PQU", EXT1('P')},
  {"psub.b", MATCH_PSUB_B, MASK_PSUB_B, "dst", EXT1('P')},
  {"psub.h", MATCH_PSUB_H, MASK_PSUB_H, "dst", EXT1('P')},
  {"psub.db", MATCH_PSUB_DB, MASK_PSUB_DB, "PQU", EXT1('P')},
  {"psub.dh", MATCH_PSUB_DH, MASK_PSUB_DH, "PQU", EXT1('P')},
  {"psub.dw", MATCH_PSUB_DW, MASK_PSUB_DW, "PQU", EXT1('P')},
  {"pssub.b", MATCH_PSSUB_B, MASK_PSSUB_B, "dst", EXT1('P')},
  {"pssub.h", MATCH_PSSUB_H, MASK_PSSUB_H, "dst", EXT1('P')},
  {"pssub.db", MATCH_PSSUB_DB, MASK_PSSUB_DB, "PQU", EXT1('P')},
  {"pssub.dh", MATCH_PSSUB_DH, MASK_PSSUB_DH, "PQU", EXT1('P')},
  {"pssub.dw", MATCH_PSSUB_DW, MASK_PSSUB_DW, "PQU", EXT1('P')},
  {"pssubu.b", MATCH_PSSUBU_B, MASK_PSSUBU_B, "dst", EXT1('P')},
  {"pssubu.h", MATCH_PSSUBU_H, MASK_PSSUBU_H, "dst", EXT1('P')},
  {"pssubu.db", MATCH_PSSUBU_DB, MASK_PSSUBU_DB, "PQU", EXT1('P')},
  {"pssubu.dh", MATCH_PSSUBU_DH, MASK_PSSUBU_DH, "PQU", EXT1('P')},
  {"pssubu.dw", MATCH_PSSUBU_DW, MASK_PSSUBU_DW, "PQU", EXT1('P')},
  {"psa.hx", MATCH_PSA_HX, MASK_PSA_HX, "dst", EXT1('P')},
  {"psa.dhx", MATCH_PSA_DHX, MASK_PSA_DHX, "PQU", EXT1('P')},
  {"psas.hx", MATCH_PSAS_HX, MASK_PSAS_HX, "dst", EXT1('P')},
  {"psas.dhx", MATCH_PSAS_DHX, MASK_PSAS_DHX, "PQU", EXT1('P')},
  {"pssa.hx", MATCH_PSSA_HX, MASK_PSSA_HX, "dst", EXT1('P')},
  {"pssa.dhx", MATCH_PSSA_DHX, MASK_PSSA_DHX, "PQU", EXT1('P')},
  {"pmax.b", MATCH_PMAX_B, MASK_PMAX_B, "dst", EXT1('P')},
  {"pmax.h", MATCH_PMAX_H, MASK_PMAX_H, "dst", EXT1('P')},
  {"pmax.db", MATCH_PMAX_DB, MASK_PMAX_DB, "PQU", EXT1('P')},
  {"pmax.dh", MATCH_PMAX_DH, MASK_PMAX_DH, "PQU", EXT1('P')},
  {"pmax.dw", MATCH_PMAX_DW, MASK_PMAX_DW, "PQU", EXT1('P')},
  {"pmaxu.b", MATCH_PMAXU_B, MASK_PMAXU_B, "dst", EXT1('P')},
  {"pmaxu.h", MATCH_PMAXU_H, MASK_PMAXU_H, "dst", EXT1('P')},
  {"pmaxu.db", MATCH_PMAXU_DB, MASK_PMAXU_DB, "PQU", EXT1('P')},
  {"pmaxu.dh", MATCH_PMAXU_DH, MASK_PMAXU_DH, "PQU", EXT1('P')},
  {"pmaxu.dw", MATCH_PMAXU_DW, MASK_PMAXU_DW, "PQU", EXT1('P')},
  {"pmin.b", MATCH_PMIN_B, MASK_PMIN_B, "dst", EXT1('P')},
  {"pmin.h", MATCH_PMIN_H, MASK_PMIN_H, "dst", EXT1('P')},
  {"pmin.db", MATCH_PMIN_DB, MASK_PMIN_DB, "PQU", EXT1('P')},
  {"pmin.dh", MATCH_PMIN_DH, MASK_PMIN_DH, "PQU", EXT1('P')},
  {"pmin.dw", MATCH_PMIN_DW, MASK_PMIN_DW, "PQU", EXT1('P')},
  {"pminu.b", MATCH_PMINU_B, MASK_PMINU_B, "dst", EXT1('P')},
  {"pminu.h", MATCH_PMINU_H, MASK_PMINU_H, "dst", EXT1('P')},
  {"pminu.db", MATCH_PMINU_DB, MASK_PMINU_DB, "PQU", EXT1('P')},
  {"pminu.dh", MATCH_PMINU_DH, MASK_PMINU_DH, "PQU", EXT1('P')},
  {"pminu.dw", MATCH_PMINU_DW, MASK_PMINU_DW, "PQU", EXT1('P')},
  {"pmseq.b", MATCH_PMSEQ_B, MASK_PMSEQ_B, "dst", EXT1('P')},
  {"pmseq.h", MATCH_PMSEQ_H, MASK_PMSEQ_H, "dst", EXT1('P')},
  {"pmseq.db", MATCH_PMSEQ_DB, MASK_PMSEQ_DB, "PQU", EXT1('P')},
  {"pmseq.dh", MATCH_PMSEQ_DH, MASK_PMSEQ_DH, "PQU", EXT1('P')},
  {"pmseq.dw", MATCH_PMSEQ_DW, MASK_PMSEQ_DW, "PQU", EXT1('P')},
  {"pmslt.b", MATCH_PMSLT_B, MASK_PMSLT_B, "dst", EXT1('P')},
  {"pmslt.h", MATCH_PMSLT_H, MASK_PMSLT_H, "dst", EXT1('P')},
  {"pmslt.db", MATCH_PMSLT_DB, MASK_PMSLT_DB, "PQU", EXT1('P')},
  {"pmslt.dh", MATCH_PMSLT_DH, MASK_PMSLT_DH, "PQU", EXT1('P')},
  {"pmslt.dw", MATCH_PMSLT_DW, MASK_PMSLT_DW, "PQU", EXT1('P')},
  {"pmsltu.b", MATCH_PMSLTU_B, MASK_PMSLTU_B, "dst", EXT1('P')},
  {"pmsltu.h", MATCH_PMSLTU_H, MASK_PMSLTU_H, "dst", EXT1('P')},
  {"pmsltu.db", MATCH_PMSLTU_DB, MASK_PMSLTU_DB, "PQU", EXT1('P')},
  {"pmsltu.dh", MATCH_PMSLTU_DH, MASK_PMSLTU_DH, "PQU", EXT1('P')},
  {"pmsltu.dw", MATCH_PMSLTU_DW, MASK_PMSLTU_DW, "PQU", EXT1('P')},
  {"psll.bs", MATCH_PSLL_BS, MASK_PSLL_BS, "dst", EXT1('P')},
  {"psll.hs", MATCH_PSLL_HS, MASK_PSLL_HS, "dst", EXT1('P')},
  {"psll.dbs", MATCH_PSLL_DBS, MASK_PSLL_DBS, "PQt", EXT1('P')},
  {"psll.dhs", MATCH_PSLL_DHS, MASK_PSLL_DHS, "PQt", EXT1('P')},
  {"psll.dws", MATCH_PSLL_DWS, MASK_PSLL_DWS, "PQt", EXT1('P')},
  {"psra.bs", MATCH_PSRA_BS, MASK_PSRA_BS, "dst", EXT1('P')},
  {"psra.hs", MATCH_PSRA_HS, MASK_PSRA_HS, "dst", EXT1('P')},
  {"psra.dbs", MATCH_PSRA_DBS, MASK_PSRA_DBS, "PQt", EXT1('P')},
  {"psra.dhs", MATCH_PSRA_DHS, MASK_PSRA_DHS, "PQt", EXT1('P')},
  {"psra.dws", MATCH_PSRA_DWS, MASK_PSRA_DWS, "PQt", EXT1('P')},
  {"psrl.bs", MATCH_PSRL_BS, MASK_PSRL_BS, "dst", EXT1('P')},
  {"psrl.hs", MATCH_PSRL_HS, MASK_PSRL_HS, "dst", EXT1('P')},
  {"psrl.dbs", MATCH_PSRL_DBS, MASK_PSRL_DBS, "PQt", EXT1('P')},
  {"psrl.dhs", MATCH_PSRL_DHS, MASK_PSRL_DHS, "PQt", EXT1('P')},
  {"psrl.dws", MATCH_PSRL_DWS, MASK_PSRL_DWS, "PQt", EXT1('P')},
  {"pssha.hs", MATCH_PSSHA_HS, MASK_PSSHA_HS, "dst", EXT1('P')},
  {"pssha.dhs", MATCH_PSSHA_DHS, MASK_PSSHA_DHS, "PQt", EXT1('P')},
  {"pssha.dws", MATCH_PSSHA_DWS, MASK_PSSHA_DWS, "PQt", EXT1('P')},
  {"psshar.hs", MATCH_PSSHAR_HS, MASK_PSSHAR_HS, "dst", EXT1('P')},
  {"psshar.dhs", MATCH_PSSHAR_DHS, MASK_PSSHAR_DHS, "PQt", EXT1('P')},
  {"psshar.dws", MATCH_PSSHAR_DWS, MASK_PSSHAR_DWS, "PQt", EXT1('P')},
  {"psshl.hs", MATCH_PSSHL_HS, MASK_PSSHL_HS, "dst", EXT1('P')},
  {"psshl.dhs", MATCH_PSSHL_DHS, MASK_PSSHL_DHS, "PQt", EXT1('P')},
  {"psshl.dws", MATCH_PSSHL_DWS, MASK_PSSHL_DWS, "PQt", EXT1('P')},
  {"psshlr.hs", MATCH_PSSHLR_HS, MASK_PSSHLR_HS, "dst", EXT1('P')},
  {"psshlr.dhs", MATCH_PSSHLR_DHS, MASK_PSSHLR_DHS, "PQt", EXT1('P')},
  {"psshlr.dws", MATCH_PSSHLR_DWS, MASK_PSSHLR_DWS, "PQt", EXT1('P')},
  {"psh1add.h", MATCH_PSH1ADD_H, MASK_PSH1ADD_H, "dst", EXT1('P')},
  {"psh1add.dh", MATCH_PSH1ADD_DH, MASK_PSH1ADD_DH, "PQU", EXT1('P')},
  {"psh1add.dw", MATCH_PSH1ADD_DW, MASK_PSH1ADD_DW, "PQU", EXT1('P')},
  {"pssh1sadd.h", MATCH_PSSH1SADD_H, MASK_PSSH1SADD_H, "dst", EXT1('P')},
  {"pssh1sadd.dh", MATCH_PSSH1SADD_DH, MASK_PSSH1SADD_DH, "PQU", EXT1('P')},
  {"pssh1sadd.dw", MATCH_PSSH1SADD_DW, MASK_PSSH1SADD_DW, "PQU", EXT1('P')},
  {"pnclip.bs", MATCH_PNCLIP_BS, MASK_PNCLIP_BS, "dQt", EXT1('P')},
  {"pnclip.hs", MATCH_PNCLIP_HS, MASK_PNCLIP_HS, "dQt", EXT1('P')},
  {"pnclipr.bs", MATCH_PNCLIPR_BS, MASK_PNCLIPR_BS, "dQt", EXT1('P')},
  {"pnclipr.hs", MATCH_PNCLIPR_HS, MASK_PNCLIPR_HS, "dQt", EXT1('P')},
  {"pnclipu.bs", MATCH_PNCLIPU_BS, MASK_PNCLIPU_BS, "dQt", EXT1('P')},
  {"pnclipu.hs", MATCH_PNCLIPU_HS, MASK_PNCLIPU_HS, "dQt", EXT1('P')},
  {"pnclipru.bs", MATCH_PNCLIPRU_BS, MASK_PNCLIPRU_BS, "dQt", EXT1('P')},
  {"pnclipru.hs", MATCH_PNCLIPRU_HS, MASK_PNCLIPRU_HS, "dQt", EXT1('P')},
  {"pnsra.bs", MATCH_PNSRA_BS, MASK_PNSRA_BS, "dQt", EXT1('P')},
  {"pnsra.hs", MATCH_PNSRA_HS, MASK_PNSRA_HS, "dQt", EXT1('P')},
  {"pnsrar.bs", MATCH_PNSRAR_BS, MASK_PNSRAR_BS, "dQt", EXT1('P')},
  {"pnsrar.hs", MATCH_PNSRAR_HS, MASK_PNSRAR_HS, "dQt", EXT1('P')},
  {"pnsrl.bs", MATCH_PNSRL_BS, MASK_PNSRL_BS, "dQt", EXT1('P')},
  {"pnsrl.hs", MATCH_PNSRL_HS, MASK_PNSRL_HS, "dQt", EXT1('P')},
  {"pwsll.bs", MATCH_PWSLL_BS, MASK_PWSLL_BS, "Pst", EXT1('P')},
  {"pwsll.hs", MATCH_PWSLL_HS, MASK_PWSLL_HS, "Pst", EXT1('P')},
  {"pwsla.bs", MATCH_PWSLA_BS, MASK_PWSLA_BS, "Pst", EXT1('P')},
  {"pwsla.hs", MATCH_PWSLA_HS, MASK_PWSLA_HS, "Pst", EXT1('P')},
  {"ppaire.b", MATCH_PPAIRE_B, MASK_PPAIRE_B, "dst", EXT1('P')},
  {"ppaire.h", MATCH_PPAIRE_H, MASK_PPAIRE_H, "dst", EXT1('P')},
  {"ppaire.db", MATCH_PPAIRE_DB, MASK_PPAIRE_DB, "PQU", EXT1('P')},
  {"ppaire.dh", MATCH_PPAIRE_DH, MASK_PPAIRE_DH, "PQU", EXT1('P')},
  {"ppaireo.b", MATCH_PPAIREO_B, MASK_PPAIREO_B, "dst", EXT1('P')},
  {"ppaireo.h", MATCH_PPAIREO_H, MASK_PPAIREO_H, "dst", EXT1('P')},
  {"ppaireo.db", MATCH_PPAIREO_DB, MASK_PPAIREO_DB, "PQU", EXT1('P')},
  {"ppaireo.dh", MATCH_PPAIREO_DH, MASK_PPAIREO_DH, "PQU", EXT1('P')},
  {"ppairo.b", MATCH_PPAIRO_B, MASK_PPAIRO_B, "dst", EXT1('P')},
  {"ppairo.h", MATCH_PPAIRO_H, MASK_PPAIRO_H, "dst", EXT1('P')},
  {"ppairo.db", MATCH_PPAIRO_DB, MASK_PPAIRO_DB, "PQU", EXT1('P')},
  {"ppairo.dh", MATCH_PPAIRO_DH, MASK_PPAIRO_DH, "PQU", EXT1('P')},
  {"ppairoe.b", MATCH_PPAIROE_B, MASK_PPAIROE_B, "dst", EXT1('P')},
  {"ppairoe.h", MATCH_PPAIROE_H, MASK_PPAIROE_H, "dst", EXT1('P')},
  {"ppairoe.db", MATCH_PPAIROE_DB, MASK_PPAIROE_DB, "PQU", EXT1('P')},
  {"ppairoe.dh", MATCH_PPAIROE_DH, MASK_PPAIROE_DH, "PQU", EXT1('P')},
  {"predsum.bs", MATCH_PREDSUM_BS, MASK_PREDSUM_BS, "dst", EXT1('P')},
  {"predsum.hs", MATCH_PREDSUM_HS, MASK_PREDSUM_HS, "dst", EXT1('P')},
  {"predsum.dbs", MATCH_PREDSUM_DBS, MASK_PREDSUM_DBS, "dQt", EXT1('P')},
  {"predsum.dhs", MATCH_PREDSUM_DHS, MASK_PREDSUM_DHS, "dQt", EXT1('P')},
  {"predsumu.bs", MATCH_PREDSUMU_BS, MASK_PREDSUMU_BS, "dst", EXT1('P')},
  {"predsumu.hs", MATCH_PREDSUMU_HS, MASK_PREDSUMU_HS, "dst", EXT1('P')},
  {"predsumu.dbs", MATCH_PREDSUMU_DBS, MASK_PREDSUMU_DBS, "dQt", EXT1('P')},
  {"predsumu.dhs", MATCH_PREDSUMU_DHS, MASK_PREDSUMU_DHS, "dQt", EXT1('P')},
  {"psabs.b", MATCH_PSABS_B, MASK_PSABS_B, "ds", EXT1('P')},
  {"psabs.h", MATCH_PSABS_H, MASK_PSABS_H, "ds", EXT1('P')},
  {"psabs.db", MATCH_PSABS_DB, MASK_PSABS_DB, "PQ", EXT1('P')},
  {"psabs.dh", MATCH_PSABS_DH, MASK_PSABS_DH, "PQ", EXT1('P')},
  {"psext.h.b", MATCH_PSEXT_H_B, MASK_PSEXT_H_B, "ds", EXT1('P')},
  {"psext.dh.b", MATCH_PSEXT_DH_B, MASK_PSEXT_DH_B, "PQ", EXT1('P')},
  {"psext.dw.b", MATCH_PSEXT_DW_B, MASK_PSEXT_DW_B, "PQ", EXT1('P')},
  {"psext.dw.h", MATCH_PSEXT_DW_H, MASK_PSEXT_DW_H, "PQ", EXT1('P')},
  {"pslli.b", MATCH_PSLLI_B, MASK_PSLLI_B, "ds:", EXT1('P')},
  {"pslli.h", MATCH_PSLLI_H, MASK_PSLLI_H, "ds;", EXT1('P')},
  {"pslli.db", MATCH_PSLLI_DB, MASK_PSLLI_DB, "PQ:", EXT1('P')},
  {"pslli.dh", MATCH_PSLLI_DH, MASK_PSLLI_DH, "PQ;", EXT1('P')},
  {"pslli.dw", MATCH_PSLLI_DW, MASK_PSLLI_DW, "PQ<", EXT1('P')},
  {"psrai.b", MATCH_PSRAI_B, MASK_PSRAI_B, "ds:", EXT1('P')},
  {"psrai.h", MATCH_PSRAI_H, MASK_PSRAI_H, "ds;", EXT1('P')},
  {"psrai.db", MATCH_PSRAI_DB, MASK_PSRAI_DB, "PQ:", EXT1('P')},
  {"psrai.dh", MATCH_PSRAI_DH, MASK_PSRAI_DH, "PQ;", EXT1('P')},
  {"psrai.dw", MATCH_PSRAI_DW, MASK_PSRAI_DW, "PQ<", EXT1('P')},
  {"psrli.b", MATCH_PSRLI_B, MASK_PSRLI_B, "ds:", EXT1('P')},
  {"psrli.h", MATCH_PSRLI_H, MASK_PSRLI_H, "ds;", EXT1('P')},
  {"psrli.db", MATCH_PSRLI_DB, MASK_PSRLI_DB, "PQ:", EXT1('P')},
  {"psrli.dh", MATCH_PSRLI_DH, MASK_PSRLI_DH, "PQ;", EXT1('P')},
  {"psrli.dw", MATCH_PSRLI_DW, MASK_PSRLI_DW, "PQ<", EXT1('P')},
  {"psrari.h", MATCH_PSRARI_H, MASK_PSRARI_H, "ds;", EXT1('P')},
  {"psrari.dh", MATCH_PSRARI_DH, MASK_PSRARI_DH, "PQ;", EXT1('P')},
  {"psrari.dw", MATCH_PSRARI_DW, MASK_PSRARI_DW, "PQ<", EXT1('P')},
  {"psati.h", MATCH_PSATI_H, MASK_PSATI_H, "ds;", EXT1('P')},
  {"psati.dh", MATCH_PSATI_DH, MASK_PSATI_DH, "PQ;", EXT1('P')},
  {"psati.dw", MATCH_PSATI_DW, MASK_PSATI_DW, "PQ<", EXT1('P')},
  {"pusati.h", MATCH_PUSATI_H, MASK_PUSATI_H, "ds;", EXT1('P')},
  {"pusati.dh", MATCH_PUSATI_DH, MASK_PUSATI_DH, "PQ;", EXT1('P')},
  {"pusati.dw", MATCH_PUSATI_DW, MASK_PUSATI_DW, "PQ<", EXT1('P')},
  {"psslai.h", MATCH_PSSLAI_H, MASK_PSSLAI_H, "ds;", EXT1('P')},
  {"psslai.dh", MATCH_PSSLAI_DH, MASK_PSSLAI_DH, "PQ;", EXT1('P')},
  {"psslai.dw", MATCH_PSSLAI_DW, MASK_PSSLAI_DW, "PQ<", EXT1('P')},
  {"pnclipi.b", MATCH_PNCLIPI_B, MASK_PNCLIPI_B, "dQ;", EXT1('P')},
  {"pnclipi.h", MATCH_PNCLIPI_H, MASK_PNCLIPI_H, "dQ<", EXT1('P')},
  {"pnclipiu.b", MATCH_PNCLIPIU_B, MASK_PNCLIPIU_B, "dQ;", EXT1('P')},
  {"pnclipiu.h", MATCH_PNCLIPIU_H, MASK_PNCLIPIU_H, "dQ<", EXT1('P')},
  {"pnclipri.b", MATCH_PNCLIPRI_B, MASK_PNCLIPRI_B, "dQ;", EXT1('P')},
  {"pnclipri.h", MATCH_PNCLIPRI_H, MASK_PNCLIPRI_H, "dQ<", EXT1('P')},
  {"pnclipriu.b", MATCH_PNCLIPRIU_B, MASK_PNCLIPRIU_B, "dQ;", EXT1('P')},
  {"pnclipriu.h", MATCH_PNCLIPRIU_H, MASK_PNCLIPRIU_H, "dQ<", EXT1('P')},
  {"pnsrai.b", MATCH_PNSRAI_B, MASK_PNSRAI_B, "dQ;", EXT1('P')},
  {"pnsrai.h", MATCH_PNSRAI_H, MASK_PNSRAI_H, "dQ<", EXT1('P')},
  {"pnsrari.b", MATCH_PNSRARI_B, MASK_PNSRARI_B, "dQ;", EXT1('P')},
  {"pnsrari.h", MATCH_PNSRARI_H, MASK_PNSRARI_H, "dQ<", EXT1('P')},
  {"pnsrli.b", MATCH_PNSRLI_B, MASK_PNSRLI_B, "dQ;", EXT1('P')},
  {"pnsrli.h", MATCH_PNSRLI_H, MASK_PNSRLI_H, "dQ<", EXT1('P')},
  {"pwslli.b", MATCH_PWSLLI_B, MASK_PWSLLI_B, "Ps:", EXT1('P')},
  {"pwslli.h", MATCH_PWSLLI_H, MASK_PWSLLI_H, "Ps;", EXT1('P')},
  {"pwslai.b", MATCH_PWSLAI_B, MASK_PWSLAI_B, "Ps:", EXT1('P')},
  {"pwslai.h", MATCH_PWSLAI_H, MASK_PWSLAI_H, "Ps;", EXT1('P')},
  {"pli.b", MATCH_PLI_B, MASK_PLI_B, "d7", EXT1('P')},
  {"pli.h", MATCH_PLI_H, MASK_PLI_H, "d$", EXT1('P')},
  {"pli.db", MATCH_PLI_DB, MASK_PLI_DB, "P7", EXT1('P')},
  {"pli.dh", MATCH_PLI_DH, MASK_PLI_DH, "P$", EXT1('P')},
  {"plui.h", MATCH_PLUI_H, MASK_PLUI_H, "d%", EXT1('P')},
  {"plui.dh", MATCH_PLUI_DH, MASK_PLUI_DH, "P%", EXT1('P')},
  {"pmul.h.b00", MATCH_PMUL_H_B00, MASK_PMUL_H_B00, "dst", EXT1('P')},
  {"pmul.h.b01", MATCH_PMUL_H_B01, MASK_PMUL_H_B01, "dst", EXT1('P')},
  {"pmul.h.b11", MATCH_PMUL_H_B11, MASK_PMUL_H_B11, "dst", EXT1('P')},
  {"pmulu.h.b00", MATCH_PMULU_H_B00, MASK_PMULU_H_B00, "dst", EXT1('P')},
  {"pmulu.h.b01", MATCH_PMULU_H_B01, MASK_PMULU_H_B01, "dst", EXT1('P')},
  {"pmulu.h.b11", MATCH_PMULU_H_B11, MASK_PMULU_H_B11, "dst", EXT1('P')},
  {"pmulsu.h.b00", MATCH_PMULSU_H_B00, MASK_PMULSU_H_B00, "dst", EXT1('P')},
  {"pmulsu.h.b11", MATCH_PMULSU_H_B11, MASK_PMULSU_H_B11, "dst", EXT1('P')},
  {"pmulh.h", MATCH_PMULH_H, MASK_PMULH_H, "dst", EXT1('P')},
  {"pmulhu.h", MATCH_PMULHU_H, MASK_PMULHU_H, "dst", EXT1('P')},
  {"pmulhsu.h", MATCH_PMULHSU_H, MASK_PMULHSU_H, "dst", EXT1('P')},
  {"pmulh.h.b0", MATCH_PMULH_H_B0, MASK_PMULH_H_B0, "dst", EXT1('P')},
  {"pmulh.h.b1", MATCH_PMULH_H_B1, MASK_PMULH_H_B1, "dst", EXT1('P')},
  {"pmulhsu.h.b0", MATCH_PMULHSU_H_B0, MASK_PMULHSU_H_B0, "dst", EXT1('P')},
  {"pmulhsu.h.b1", MATCH_PMULHSU_H_B1, MASK_PMULHSU_H_B1, "dst", EXT1('P')},
  {"pmulhr.h", MATCH_PMULHR_H, MASK_PMULHR_H, "dst", EXT1('P')},
  {"pmulhru.h", MATCH_PMULHRU_H, MASK_PMULHRU_H, "dst", EXT1('P')},
  {"pmulhrsu.h", MATCH_PMULHRSU_H, MASK_PMULHRSU_H, "dst", EXT1('P')},
  {"pmulq.h", MATCH_PMULQ_H, MASK_PMULQ_H, "dst", EXT1('P')},
  {"pmulqr.h", MATCH_PMULQR_H, MASK_PMULQR_H, "dst", EXT1('P')},
  {"pmhacc.h", MATCH_PMHACC_H, MASK_PMHACC_H, "dst", EXT1('P')},
  {"pmhaccu.h", MATCH_PMHACCU_H, MASK_PMHACCU_H, "dst", EXT1('P')},
  {"pmhaccsu.h", MATCH_PMHACCSU_H, MASK_PMHACCSU_H, "dst", EXT1('P')},
  {"pmhacc.h.b0", MATCH_PMHACC_H_B0, MASK_PMHACC_H_B0, "dst", EXT1('P')},
  {"pmhacc.h.b1", MATCH_PMHACC_H_B1, MASK_PMHACC_H_B1, "dst", EXT1('P')},
  {"pmhaccsu.h.b0", MATCH_PMHACCSU_H_B0, MASK_PMHACCSU_H_B0, "dst", EXT1('P')},
  {"pmhaccsu.h.b1", MATCH_PMHACCSU_H_B1, MASK_PMHACCSU_H_B1, "dst", EXT1('P')},
  {"pmhracc.h", MATCH_PMHRACC_H, MASK_PMHRACC_H, "dst", EXT1('P')},
  {"pmhraccu.h", MATCH_PMHRACCU_H, MASK_PMHRACCU_H, "dst", EXT1('P')},
  {"pmhraccsu.h", MATCH_PMHRACCSU_H, MASK_PMHRACCSU_H, "dst", EXT1('P')},
  {"pmq2add.h", MATCH_PMQ2ADD_H, MASK_PMQ2ADD_H, "dst", EXT1('P')},
  {"pmq2adda.h", MATCH_PMQ2ADDA_H, MASK_PMQ2ADDA_H, "dst", EXT1('P')},
  {"pmqr2add.h", MATCH_PMQR2ADD_H, MASK_PMQR2ADD_H, "dst", EXT1('P')},
  {"pmqr2adda.h", MATCH_PMQR2ADDA_H, MASK_PMQR2ADDA_H, "dst", EXT1('P')},
  {"pwadd.b", MATCH_PWADD_B, MASK_PWADD_B, "Pst", EXT1('P')},
  {"pwadd.h", MATCH_PWADD_H, MASK_PWADD_H, "Pst", EXT1('P')},
  {"pwaddu.b", MATCH_PWADDU_B, MASK_PWADDU_B, "Pst", EXT1('P')},
  {"pwaddu.h", MATCH_PWADDU_H, MASK_PWADDU_H, "Pst", EXT1('P')},
  {"pwadda.b", MATCH_PWADDA_B, MASK_PWADDA_B, "Pst", EXT1('P')},
  {"pwadda.h", MATCH_PWADDA_H, MASK_PWADDA_H, "Pst", EXT1('P')},
  {"pwaddau.b", MATCH_PWADDAU_B, MASK_PWADDAU_B, "Pst", EXT1('P')},
  {"pwaddau.h", MATCH_PWADDAU_H, MASK_PWADDAU_H, "Pst", EXT1('P')},
  {"pwsub.b", MATCH_PWSUB_B, MASK_PWSUB_B, "Pst", EXT1('P')},
  {"pwsub.h", MATCH_PWSUB_H, MASK_PWSUB_H, "Pst", EXT1('P')},
  {"pwsubu.b", MATCH_PWSUBU_B, MASK_PWSUBU_B, "Pst", EXT1('P')},
  {"pwsubu.h", MATCH_PWSUBU_H, MASK_PWSUBU_H, "Pst", EXT1('P')},
  {"pwsuba.b", MATCH_PWSUBA_B, MASK_PWSUBA_B, "Pst", EXT1('P')},
  {"pwsuba.h", MATCH_PWSUBA_H, MASK_PWSUBA_H, "Pst", EXT1('P')},
  {"pwsubau.b", MATCH_PWSUBAU_B, MASK_PWSUBAU_B, "Pst", EXT1('P')},
  {"pwsubau.h", MATCH_PWSUBAU_H, MASK_PWSUBAU_H, "Pst", EXT1('P')},
  {"pwmul.b", MATCH_PWMUL_B, MASK_PWMUL_B, "Pst", EXT1('P')},
  {"pwmul.h", MATCH_PWMUL_H, MASK_PWMUL_H, "Pst", EXT1('P')},
  {"pwmulu.b", MATCH_PWMULU_B, MASK_PWMULU_B, "Pst", EXT1('P')},
  {"pwmulu.h", MATCH_PWMULU_H, MASK_PWMULU_H, "Pst", EXT1('P')},
  {"pwmulsu.b", MATCH_PWMULSU_B, MASK_PWMULSU_B, "Pst", EXT1('P')},
  {"pwmulsu.h", MATCH_PWMULSU_H, MASK_PWMULSU_H, "Pst", EXT1('P')},
  {"pwmacc.h", MATCH_PWMACC_H, MASK_PWMACC_H, "Pst", EXT1('P')},
  {"pwmaccu.h", MATCH_PWMACCU_H, MASK_PWMACCU_H, "Pst", EXT1('P')},
  {"pwmaccsu.h", MATCH_PWMACCSU_H, MASK_PWMACCSU_H, "Pst", EXT1('P')},
  {"pm2add.h", MATCH_PM2ADD_H, MASK_PM2ADD_H, "dst", EXT1('P')},
  {"pm2add.hx", MATCH_PM2ADD_HX, MASK_PM2ADD_HX, "dst", EXT1('P')},
  {"pm2addu.h", MATCH_PM2ADDU_H, MASK_PM2ADDU_H, "dst", EXT1('P')},
  {"pm2addsu.h", MATCH_PM2ADDSU_H, MASK_PM2ADDSU_H, "dst", EXT1('P')},
  {"pm2adda.h", MATCH_PM2ADDA_H, MASK_PM2ADDA_H, "dst", EXT1('P')},
  {"pm2adda.hx", MATCH_PM2ADDA_HX, MASK_PM2ADDA_HX, "dst", EXT1('P')},
  {"pm2addau.h", MATCH_PM2ADDAU_H, MASK_PM2ADDAU_H, "dst", EXT1('P')},
  {"pm2addasu.h", MATCH_PM2ADDASU_H, MASK_PM2ADDASU_H, "dst", EXT1('P')},
  {"pm2sub.h", MATCH_PM2SUB_H, MASK_PM2SUB_H, "dst", EXT1('P')},
  {"pm2sub.hx", MATCH_PM2SUB_HX, MASK_PM2SUB_HX, "dst", EXT1('P')},
  {"pm2suba.h", MATCH_PM2SUBA_H, MASK_PM2SUBA_H, "dst", EXT1('P')},
  {"pm2suba.hx", MATCH_PM2SUBA_HX, MASK_PM2SUBA_HX, "dst", EXT1('P')},
  {"pm2sadd.h", MATCH_PM2SADD_H, MASK_PM2SADD_H, "dst", EXT1('P')},
  {"pm2sadd.hx", MATCH_PM2SADD_HX, MASK_PM2SADD_HX, "dst", EXT1('P')},
  {"pm2wadd.h", MATCH_PM2WADD_H, MASK_PM2WADD_H, "Pst", EXT1('P')},
  {"pm2wadd.hx", MATCH_PM2WADD_HX, MASK_PM2WADD_HX, "Pst", EXT1('P')},
  {"pm2waddu.h", MATCH_PM2WADDU_H, MASK_PM2WADDU_H, "Pst", EXT1('P')},
  {"pm2waddsu.h", MATCH_PM2WADDSU_H, MASK_PM2WADDSU_H, "Pst", EXT1('P')},
  {"pm2wadda.h", MATCH_PM2WADDA_H, MASK_PM2WADDA_H, "Pst", EXT1('P')},
  {"pm2wadda.hx", MATCH_PM2WADDA_HX, MASK_PM2WADDA_HX, "Pst", EXT1('P')},
  {"pm2waddau.h", MATCH_PM2WADDAU_H, MASK_PM2WADDAU_H, "Pst", EXT1('P')},
  {"pm2waddasu.h", MATCH_PM2WADDASU_H, MASK_PM2WADDASU_H, "Pst", EXT1('P')},
  {"pm2wsub.h", MATCH_PM2WSUB_H, MASK_PM2WSUB_H, "Pst", EXT1('P')},
  {"pm2wsub.hx", MATCH_PM2WSUB_HX, MASK_PM2WSUB_HX, "Pst", EXT1('P')},
  {"pm2wsuba.h", MATCH_PM2WSUBA_H, MASK_PM2WSUBA_H, "Pst", EXT1('P')},
  {"pm2wsuba.hx", MATCH_PM2WSUBA_HX, MASK_PM2WSUBA_HX, "Pst", EXT1('P')},
  {"pm4add.b", MATCH_PM4ADD_B, MASK_PM4ADD_B, "dst", EXT1('P')},
  {"pm4addu.b", MATCH_PM4ADDU_B, MASK_PM4ADDU_B, "dst", EXT1('P')},
  {"pm4addsu.b", MATCH_PM4ADDSU_B, MASK_PM4ADDSU_B, "dst", EXT1('P')},
  {"pm4adda.b", MATCH_PM4ADDA_B, MASK_PM4ADDA_B, "dst", EXT1('P')},
  {"pm4addau.b", MATCH_PM4ADDAU_B, MASK_PM4ADDAU_B, "dst", EXT1('P')},
  {"pm4addasu.b", MATCH_PM4ADDASU_B, MASK_PM4ADDASU_B, "dst", EXT1('P')},
  {"zip8p", MATCH_ZIP8P, MASK_ZIP8P, "ds", EXT1('P')},
  {"zip8hp", MATCH_ZIP8HP, MASK_ZIP8HP, "ds", EXT1('P')},
  {"unzip8p", MATCH_UNZIP8P, MASK_UNZIP8P, "ds", EXT1('P')},
  {"unzip8hp", MATCH_UNZIP8HP, MASK_UNZIP8HP, "ds", EXT1('P')},
  {"unzip16p", MATCH_UNZIP16P, MASK_UNZIP16P, "ds", EXT1('P')},
  {"unzip16hp", MATCH_UNZIP16HP, MASK_UNZIP16HP, "ds", EXT1('P')},
  {"wzip8p", MATCH_WZIP8P, MASK_WZIP8P, "Ps", EXT1('P')},
  {"wzip16p", MATCH_WZIP16P, MASK_WZIP16P, "Ps", EXT1('P')},
  {"mqwacc", MATCH_MQWACC, MASK_MQWACC, "Pst", EXT1('P')},
  {"mqrwacc", MATCH_MQRWACC, MASK_MQRWACC, "Pst", EXT1('P')},
  {"pmqwacc.h", MATCH_PMQWACC_H, MASK_PMQWACC_H, "Pst", EXT1('P')},
  {"pmqrwacc.h", MATCH_PMQRWACC_H, MASK_PMQRWACC_H, "Pst", EXT1('P')},
  {"absw", MATCH_ABSW, MASK_ABSW, "ds", EXT1_XVS('P',64)},
  {"clsw", MATCH_CLSW, MASK_CLSW, "ds", EXT1_XVS('P',64)},
  {"macc.w00", MATCH_MACC_W00, MASK_MACC_W00, "dst", EXT1_XVS('P',64)},
  {"macc.w01", MATCH_MACC_W01, MASK_MACC_W01, "dst", EXT1_XVS('P',64)},
  {"macc.w11", MATCH_MACC_W11, MASK_MACC_W11, "dst", EXT1_XVS('P',64)},
  {"maccu.w00", MATCH_MACCU_W00, MASK_MACCU_W00, "dst", EXT1_XVS('P',64)},
  {"maccu.w01", MATCH_MACCU_W01, MASK_MACCU_W01, "dst", EXT1_XVS('P',64)},
  {"maccu.w11", MATCH_MACCU_W11, MASK_MACCU_W11, "dst", EXT1_XVS('P',64)},
  {"maccsu.w00", MATCH_MACCSU_W00, MASK_MACCSU_W00, "dst", EXT1_XVS('P',64)},
  {"maccsu.w11", MATCH_MACCSU_W11, MASK_MACCSU_W11, "dst", EXT1_XVS('P',64)},
  {"mul.w00", MATCH_MUL_W00, MASK_MUL_W00, "dst", EXT1_XVS('P',64)},
  {"mul.w01", MATCH_MUL_W01, MASK_MUL_W01, "dst", EXT1_XVS('P',64)},
  {"mul.w11", MATCH_MUL_W11, MASK_MUL_W11, "dst", EXT1_XVS('P',64)},
  {"mulu.w00", MATCH_MULU_W00, MASK_MULU_W00, "dst", EXT1_XVS('P',64)},
  {"mulu.w01", MATCH_MULU_W01, MASK_MULU_W01, "dst", EXT1_XVS('P',64)},
  {"mulu.w11", MATCH_MULU_W11, MASK_MULU_W11, "dst", EXT1_XVS('P',64)},
  {"mulsu.w00", MATCH_MULSU_W00, MASK_MULSU_W00, "dst", EXT1_XVS('P',64)},
  {"mulsu.w11", MATCH_MULSU_W11, MASK_MULSU_W11, "dst", EXT1_XVS('P',64)},
  {"mqacc.w00", MATCH_MQACC_W00, MASK_MQACC_W00, "dst", EXT1_XVS('P',64)},
  {"mqacc.w01", MATCH_MQACC_W01, MASK_MQACC_W01, "dst", EXT1_XVS('P',64)},
  {"mqacc.w11", MATCH_MQACC_W11, MASK_MQACC_W11, "dst", EXT1_XVS('P',64)},
  {"mqracc.w00", MATCH_MQRACC_W00, MASK_MQRACC_W00, "dst", EXT1_XVS('P',64)},
  {"mqracc.w01", MATCH_MQRACC_W01, MASK_MQRACC_W01, "dst", EXT1_XVS('P',64)},
  {"mqracc.w11", MATCH_MQRACC_W11, MASK_MQRACC_W11, "dst", EXT1_XVS('P',64)},
  {"paadd.w", MATCH_PAADD_W, MASK_PAADD_W, "dst", EXT1_XVS('P',64)},
  {"paaddu.w", MATCH_PAADDU_W, MASK_PAADDU_W, "dst", EXT1_XVS('P',64)},
  {"paas.wx", MATCH_PAAS_WX, MASK_PAAS_WX, "dst", EXT1_XVS('P',64)},
  {"padd.w", MATCH_PADD_W, MASK_PADD_W, "dst", EXT1_XVS('P',64)},
  {"padd.ws", MATCH_PADD_WS, MASK_PADD_WS, "dst", EXT1_XVS('P',64)},
  {"pasa.wx", MATCH_PASA_WX, MASK_PASA_WX, "dst", EXT1_XVS('P',64)},
  {"pasub.w", MATCH_PASUB_W, MASK_PASUB_W, "dst", EXT1_XVS('P',64)},
  {"pasubu.w", MATCH_PASUBU_W, MASK_PASUBU_W, "dst", EXT1_XVS('P',64)},
  {"pas.wx", MATCH_PAS_WX, MASK_PAS_WX, "dst", EXT1_XVS('P',64)},
  {"pmax.w", MATCH_PMAX_W, MASK_PMAX_W, "dst", EXT1_XVS('P',64)},
  {"pmaxu.w", MATCH_PMAXU_W, MASK_PMAXU_W, "dst", EXT1_XVS('P',64)},
  {"pmin.w", MATCH_PMIN_W, MASK_PMIN_W, "dst", EXT1_XVS('P',64)},
  {"pminu.w", MATCH_PMINU_W, MASK_PMINU_W, "dst", EXT1_XVS('P',64)},
  {"pmseq.w", MATCH_PMSEQ_W, MASK_PMSEQ_W, "dst", EXT1_XVS('P',64)},
  {"pmslt.w", MATCH_PMSLT_W, MASK_PMSLT_W, "dst", EXT1_XVS('P',64)},
  {"pmsltu.w", MATCH_PMSLTU_W, MASK_PMSLTU_W, "dst", EXT1_XVS('P',64)},
  {"psadd.w", MATCH_PSADD_W, MASK_PSADD_W, "dst", EXT1_XVS('P',64)},
  {"psaddu.w", MATCH_PSADDU_W, MASK_PSADDU_W, "dst", EXT1_XVS('P',64)},
  {"psa.wx", MATCH_PSA_WX, MASK_PSA_WX, "dst", EXT1_XVS('P',64)},
  {"psas.wx", MATCH_PSAS_WX, MASK_PSAS_WX, "dst", EXT1_XVS('P',64)},
  {"pssa.wx", MATCH_PSSA_WX, MASK_PSSA_WX, "dst", EXT1_XVS('P',64)},
  {"pssub.w", MATCH_PSSUB_W, MASK_PSSUB_W, "dst", EXT1_XVS('P',64)},
  {"pssubu.w", MATCH_PSSUBU_W, MASK_PSSUBU_W, "dst", EXT1_XVS('P',64)},
  {"psub.w", MATCH_PSUB_W, MASK_PSUB_W, "dst", EXT1_XVS('P',64)},
  {"psh1add.w", MATCH_PSH1ADD_W, MASK_PSH1ADD_W, "dst", EXT1_XVS('P',64)},
  {"pssh1sadd.w", MATCH_PSSH1SADD_W, MASK_PSSH1SADD_W, "dst", EXT1_XVS('P',64)},
  {"psll.ws", MATCH_PSLL_WS, MASK_PSLL_WS, "dst", EXT1_XVS('P',64)},
  {"psra.ws", MATCH_PSRA_WS, MASK_PSRA_WS, "dst", EXT1_XVS('P',64)},
  {"psrl.ws", MATCH_PSRL_WS, MASK_PSRL_WS, "dst", EXT1_XVS('P',64)},
  {"pssha.ws", MATCH_PSSHA_WS, MASK_PSSHA_WS, "dst", EXT1_XVS('P',64)},
  {"psshar.ws", MATCH_PSSHAR_WS, MASK_PSSHAR_WS, "dst", EXT1_XVS('P',64)},
  {"psshl.ws", MATCH_PSSHL_WS, MASK_PSSHL_WS, "dst", EXT1_XVS('P',64)},
  {"psshlr.ws", MATCH_PSSHLR_WS, MASK_PSSHLR_WS, "dst", EXT1_XVS('P',64)},
  {"shl", MATCH_SHL, MASK_SHL, "dst", EXT1_XVS('P',64)},
  {"shlr", MATCH_SHLR, MASK_SHLR, "dst", EXT1_XVS('P',64)},
  {"pnclipp.b", MATCH_PNCLIPP_B, MASK_PNCLIPP_B, "dst", EXT1_XVS('P',64)},
  {"pnclipp.h", MATCH_PNCLIPP_H, MASK_PNCLIPP_H, "dst", EXT1_XVS('P',64)},
  {"pnclipp.w", MATCH_PNCLIPP_W, MASK_PNCLIPP_W, "dst", EXT1_XVS('P',64)},
  {"pnclipup.b", MATCH_PNCLIPUP_B, MASK_PNCLIPUP_B, "dst", EXT1_XVS('P',64)},
  {"pnclipup.h", MATCH_PNCLIPUP_H, MASK_PNCLIPUP_H, "dst", EXT1_XVS('P',64)},
  {"pnclipup.w", MATCH_PNCLIPUP_W, MASK_PNCLIPUP_W, "dst", EXT1_XVS('P',64)},
  {"ppaireo.w", MATCH_PPAIREO_W, MASK_PPAIREO_W, "dst", EXT1_XVS('P',64)},
  {"ppairoe.w", MATCH_PPAIROE_W, MASK_PPAIROE_W, "dst", EXT1_XVS('P',64)},
  {"ppairo.w", MATCH_PPAIRO_W, MASK_PPAIRO_W, "dst", EXT1_XVS('P',64)},
  {"predsum.ws", MATCH_PREDSUM_WS, MASK_PREDSUM_WS, "dst", EXT1_XVS('P',64)},
  {"predsumu.ws", MATCH_PREDSUMU_WS, MASK_PREDSUMU_WS, "dst", EXT1_XVS('P',64)},
  {"pmul.w.h00", MATCH_PMUL_W_H00, MASK_PMUL_W_H00, "dst", EXT1_XVS('P',64)},
  {"pmul.w.h01", MATCH_PMUL_W_H01, MASK_PMUL_W_H01, "dst", EXT1_XVS('P',64)},
  {"pmul.w.h11", MATCH_PMUL_W_H11, MASK_PMUL_W_H11, "dst", EXT1_XVS('P',64)},
  {"pmulu.w.h00", MATCH_PMULU_W_H00, MASK_PMULU_W_H00, "dst", EXT1_XVS('P',64)},
  {"pmulu.w.h01", MATCH_PMULU_W_H01, MASK_PMULU_W_H01, "dst", EXT1_XVS('P',64)},
  {"pmulu.w.h11", MATCH_PMULU_W_H11, MASK_PMULU_W_H11, "dst", EXT1_XVS('P',64)},
  {"pmulsu.w.h00", MATCH_PMULSU_W_H00, MASK_PMULSU_W_H00, "dst", EXT1_XVS('P',64)},
  {"pmulsu.w.h11", MATCH_PMULSU_W_H11, MASK_PMULSU_W_H11, "dst", EXT1_XVS('P',64)},
  {"pmulh.w", MATCH_PMULH_W, MASK_PMULH_W, "dst", EXT1_XVS('P',64)},
  {"pmulhu.w", MATCH_PMULHU_W, MASK_PMULHU_W, "dst", EXT1_XVS('P',64)},
  {"pmulhsu.w", MATCH_PMULHSU_W, MASK_PMULHSU_W, "dst", EXT1_XVS('P',64)},
  {"pmulh.w.h0", MATCH_PMULH_W_H0, MASK_PMULH_W_H0, "dst", EXT1_XVS('P',64)},
  {"pmulh.w.h1", MATCH_PMULH_W_H1, MASK_PMULH_W_H1, "dst", EXT1_XVS('P',64)},
  {"pmulhsu.w.h0", MATCH_PMULHSU_W_H0, MASK_PMULHSU_W_H0, "dst", EXT1_XVS('P',64)},
  {"pmulhsu.w.h1", MATCH_PMULHSU_W_H1, MASK_PMULHSU_W_H1, "dst", EXT1_XVS('P',64)},
  {"pmulhr.w", MATCH_PMULHR_W, MASK_PMULHR_W, "dst", EXT1_XVS('P',64)},
  {"pmulhru.w", MATCH_PMULHRU_W, MASK_PMULHRU_W, "dst", EXT1_XVS('P',64)},
  {"pmulhrsu.w", MATCH_PMULHRSU_W, MASK_PMULHRSU_W, "dst", EXT1_XVS('P',64)},
  {"pmulq.w", MATCH_PMULQ_W, MASK_PMULQ_W, "dst", EXT1_XVS('P',64)},
  {"pmulqr.w", MATCH_PMULQR_W, MASK_PMULQR_W, "dst", EXT1_XVS('P',64)},
  {"pmacc.w.h00", MATCH_PMACC_W_H00, MASK_PMACC_W_H00, "dst", EXT1_XVS('P',64)},
  {"pmacc.w.h01", MATCH_PMACC_W_H01, MASK_PMACC_W_H01, "dst", EXT1_XVS('P',64)},
  {"pmacc.w.h11", MATCH_PMACC_W_H11, MASK_PMACC_W_H11, "dst", EXT1_XVS('P',64)},
  {"pmaccu.w.h00", MATCH_PMACCU_W_H00, MASK_PMACCU_W_H00, "dst", EXT1_XVS('P',64)},
  {"pmaccu.w.h01", MATCH_PMACCU_W_H01, MASK_PMACCU_W_H01, "dst", EXT1_XVS('P',64)},
  {"pmaccu.w.h11", MATCH_PMACCU_W_H11, MASK_PMACCU_W_H11, "dst", EXT1_XVS('P',64)},
  {"pmaccsu.w.h00", MATCH_PMACCSU_W_H00, MASK_PMACCSU_W_H00, "dst", EXT1_XVS('P',64)},
  {"pmaccsu.w.h11", MATCH_PMACCSU_W_H11, MASK_PMACCSU_W_H11, "dst", EXT1_XVS('P',64)},
  {"pmhacc.w", MATCH_PMHACC_W, MASK_PMHACC_W, "dst", EXT1_XVS('P',64)},
  {"pmhaccu.w", MATCH_PMHACCU_W, MASK_PMHACCU_W, "dst", EXT1_XVS('P',64)},
  {"pmhaccsu.w", MATCH_PMHACCSU_W, MASK_PMHACCSU_W, "dst", EXT1_XVS('P',64)},
  {"pmhacc.w.h0", MATCH_PMHACC_W_H0, MASK_PMHACC_W_H0, "dst", EXT1_XVS('P',64)},
  {"pmhacc.w.h1", MATCH_PMHACC_W_H1, MASK_PMHACC_W_H1, "dst", EXT1_XVS('P',64)},
  {"pmhaccsu.w.h0", MATCH_PMHACCSU_W_H0, MASK_PMHACCSU_W_H0, "dst", EXT1_XVS('P',64)},
  {"pmhaccsu.w.h1", MATCH_PMHACCSU_W_H1, MASK_PMHACCSU_W_H1, "dst", EXT1_XVS('P',64)},
  {"pmhracc.w", MATCH_PMHRACC_W, MASK_PMHRACC_W, "dst", EXT1_XVS('P',64)},
  {"pmhraccu.w", MATCH_PMHRACCU_W, MASK_PMHRACCU_W, "dst", EXT1_XVS('P',64)},
  {"pmhraccsu.w", MATCH_PMHRACCSU_W, MASK_PMHRACCSU_W, "dst", EXT1_XVS('P',64)},
  {"pmqacc.w.h00", MATCH_PMQACC_W_H00, MASK_PMQACC_W_H00, "dst", EXT1_XVS('P',64)},
  {"pmqacc.w.h01", MATCH_PMQACC_W_H01, MASK_PMQACC_W_H01, "dst", EXT1_XVS('P',64)},
  {"pmqacc.w.h11", MATCH_PMQACC_W_H11, MASK_PMQACC_W_H11, "dst", EXT1_XVS('P',64)},
  {"pmqracc.w.h00", MATCH_PMQRACC_W_H00, MASK_PMQRACC_W_H00, "dst", EXT1_XVS('P',64)},
  {"pmqracc.w.h01", MATCH_PMQRACC_W_H01, MASK_PMQRACC_W_H01, "dst", EXT1_XVS('P',64)},
  {"pmqracc.w.h11", MATCH_PMQRACC_W_H11, MASK_PMQRACC_W_H11, "dst", EXT1_XVS('P',64)},
  {"pmq2add.w", MATCH_PMQ2ADD_W, MASK_PMQ2ADD_W, "dst", EXT1_XVS('P',64)},
  {"pmq2adda.w", MATCH_PMQ2ADDA_W, MASK_PMQ2ADDA_W, "dst", EXT1_XVS('P',64)},
  {"pmqr2add.w", MATCH_PMQR2ADD_W, MASK_PMQR2ADD_W, "dst", EXT1_XVS('P',64)},
  {"pmqr2adda.w", MATCH_PMQR2ADDA_W, MASK_PMQR2ADDA_W, "dst", EXT1_XVS('P',64)},
  {"pm2add.w", MATCH_PM2ADD_W, MASK_PM2ADD_W, "dst", EXT1_XVS('P',64)},
  {"pm2add.wx", MATCH_PM2ADD_WX, MASK_PM2ADD_WX, "dst", EXT1_XVS('P',64)},
  {"pm2addu.w", MATCH_PM2ADDU_W, MASK_PM2ADDU_W, "dst", EXT1_XVS('P',64)},
  {"pm2addsu.w", MATCH_PM2ADDSU_W, MASK_PM2ADDSU_W, "dst", EXT1_XVS('P',64)},
  {"pm2adda.w", MATCH_PM2ADDA_W, MASK_PM2ADDA_W, "dst", EXT1_XVS('P',64)},
  {"pm2adda.wx", MATCH_PM2ADDA_WX, MASK_PM2ADDA_WX, "dst", EXT1_XVS('P',64)},
  {"pm2addau.w", MATCH_PM2ADDAU_W, MASK_PM2ADDAU_W, "dst", EXT1_XVS('P',64)},
  {"pm2addasu.w", MATCH_PM2ADDASU_W, MASK_PM2ADDASU_W, "dst", EXT1_XVS('P',64)},
  {"pm2sub.w", MATCH_PM2SUB_W, MASK_PM2SUB_W, "dst", EXT1_XVS('P',64)},
  {"pm2sub.wx", MATCH_PM2SUB_WX, MASK_PM2SUB_WX, "dst", EXT1_XVS('P',64)},
  {"pm2suba.w", MATCH_PM2SUBA_W, MASK_PM2SUBA_W, "dst", EXT1_XVS('P',64)},
  {"pm2suba.wx", MATCH_PM2SUBA_WX, MASK_PM2SUBA_WX, "dst", EXT1_XVS('P',64)},
  {"pm4add.h", MATCH_PM4ADD_H, MASK_PM4ADD_H, "dst", EXT1_XVS('P',64)},
  {"pm4addu.h", MATCH_PM4ADDU_H, MASK_PM4ADDU_H, "dst", EXT1_XVS('P',64)},
  {"pm4addsu.h", MATCH_PM4ADDSU_H, MASK_PM4ADDSU_H, "dst", EXT1_XVS('P',64)},
  {"pm4adda.h", MATCH_PM4ADDA_H, MASK_PM4ADDA_H, "dst", EXT1_XVS('P',64)},
  {"pm4addau.h", MATCH_PM4ADDAU_H, MASK_PM4ADDAU_H, "dst", EXT1_XVS('P',64)},
  {"pm4addasu.h", MATCH_PM4ADDASU_H, MASK_PM4ADDASU_H, "dst", EXT1_XVS('P',64)},
  {"psext.w.b", MATCH_PSEXT_W_B, MASK_PSEXT_W_B, "ds", EXT1_XVS('P',64)},
  {"psext.w.h", MATCH_PSEXT_W_H, MASK_PSEXT_W_H, "ds", EXT1_XVS('P',64)},
  {"zip16p", MATCH_ZIP16P, MASK_ZIP16P, "ds", EXT1_XVS('P',64)},
  {"zip16hp", MATCH_ZIP16HP, MASK_ZIP16HP, "ds", EXT1_XVS('P',64)},
  {"pslli.w", MATCH_PSLLI_W, MASK_PSLLI_W, "ds<", EXT1_XVS('P',64)},
  {"psrai.w", MATCH_PSRAI_W, MASK_PSRAI_W, "ds<", EXT1_XVS('P',64)},
  {"psrli.w", MATCH_PSRLI_W, MASK_PSRLI_W, "ds<", EXT1_XVS('P',64)},
  {"psrari.w", MATCH_PSRARI_W, MASK_PSRARI_W, "ds<", EXT1_XVS('P',64)},
  {"psati.w", MATCH_PSATI_W, MASK_PSATI_W, "ds<", EXT1_XVS('P',64)},
  {"pusati.w", MATCH_PUSATI_W, MASK_PUSATI_W, "ds<", EXT1_XVS('P',64)},
  {"psslai.w", MATCH_PSSLAI_W, MASK_PSSLAI_W, "ds<", EXT1_XVS('P',64)},
  {"pli.w", MATCH_PLI_W, MASK_PLI_W, "d$", EXT1_XVS('P',64)},
  {"plui.w", MATCH_PLUI_W, MASK_PLUI_W, "d%", EXT1_XVS('P',64)},
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

  #define DEFINE_RTYPE(code)  d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&xrd, &xrs1, &xrs2}));
  #define DEFINE_R1TYPE(code) d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&xrd, &xrs1}));

  if (ext_enabled(EXT_ZIMOP)) {
    #define DISASM_MOP_R(name, rs1, rd) \
      d->add_insn(new disasm_insn_t(#name, match_##name | (rs1 << 15) | (rd << 7), \
                                        0xFFFFFFFF, {&xrd, &xrs1}));

    #define DISASM_MOP_RR(name, rs1, rd, rs2) \
      d->add_insn(new disasm_insn_t(#name, match_##name | (rs1 << 15) | (rd << 7) | (rs2 << 20), \
                                        0xFFFFFFFF, {&xrd, &xrs1, &xrs2}));
    DEFINE_R1TYPE(mop_r_0);
    DEFINE_R1TYPE(mop_r_1);
    DEFINE_R1TYPE(mop_r_2);
    DEFINE_R1TYPE(mop_r_3);
    DEFINE_R1TYPE(mop_r_4);
    DEFINE_R1TYPE(mop_r_5);
    DEFINE_R1TYPE(mop_r_6);
    DEFINE_R1TYPE(mop_r_7);
    DEFINE_R1TYPE(mop_r_8);
    DEFINE_R1TYPE(mop_r_9);
    DEFINE_R1TYPE(mop_r_10);
    DEFINE_R1TYPE(mop_r_11);
    DEFINE_R1TYPE(mop_r_12);
    DEFINE_R1TYPE(mop_r_13);
    DEFINE_R1TYPE(mop_r_14);
    DEFINE_R1TYPE(mop_r_15);
    DEFINE_R1TYPE(mop_r_16);
    DEFINE_R1TYPE(mop_r_17);
    DEFINE_R1TYPE(mop_r_18);
    DEFINE_R1TYPE(mop_r_19);
    DEFINE_R1TYPE(mop_r_20);
    DEFINE_R1TYPE(mop_r_21);
    DEFINE_R1TYPE(mop_r_22);
    DEFINE_R1TYPE(mop_r_23);
    DEFINE_R1TYPE(mop_r_24);
    DEFINE_R1TYPE(mop_r_25);
    DEFINE_R1TYPE(mop_r_26);
    DEFINE_R1TYPE(mop_r_27);
    if (!ext_enabled_strict(EXT_ZICFISS)) {
      DEFINE_R1TYPE(mop_r_28);
    } else {
      // Add code points of mop_r_28 not used by Zicfiss
      for (unsigned rd_val = 0; rd_val <= 31; ++rd_val)
        for (unsigned rs1_val = 0; rs1_val <= 31; ++rs1_val)
          if ((rd_val != 0 && rs1_val !=0) || (rd_val == 0 && !(rs1_val == 1 || rs1_val == 5)))
            DISASM_MOP_R(mop_r_28, rs1_val, rd_val);
    }
    DEFINE_R1TYPE(mop_r_29);
    DEFINE_R1TYPE(mop_r_30);
    DEFINE_R1TYPE(mop_r_31);
    DEFINE_RTYPE(mop_rr_0);
    DEFINE_RTYPE(mop_rr_1);
    DEFINE_RTYPE(mop_rr_2);
    DEFINE_RTYPE(mop_rr_3);
    DEFINE_RTYPE(mop_rr_4);
    DEFINE_RTYPE(mop_rr_5);
    DEFINE_RTYPE(mop_rr_6);
    if (!ext_enabled_strict(EXT_ZICFISS)) {
      DEFINE_RTYPE(mop_rr_7);
    } else {
      // Add code points of mop_rr_7 not used by Zicfiss
      for (unsigned rd_val = 0; rd_val <= 31; ++rd_val)
        for (unsigned rs1_val = 0; rs1_val <= 31; ++rs1_val)
          for (unsigned rs2_val = 0; rs2_val <= 31; ++rs2_val)
            if ((rs2_val != 1 && rs2_val != 5) || rd_val != 0 || rs1_val != 0)
              DISASM_MOP_RR(mop_rr_7, rs1_val, rd_val, rs2_val);
    }
  }

  #undef DEFINE_RTYPE
  #undef DEFINE_R1TYPE
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
  #define DEFINE_RTYPE(code) d->add_insn(new disasm_insn_t(#code, match_##code, mask_##code, {&xrd, &xrs1, &xrs2}));
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
    DEFINE_RTYPE(vsetvl);

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
  #undef DEFINE_RTYPE
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
    if (op.enabled == nullptr || op.enabled(isa, strict))
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
