// See LICENSE for license details.

// Table-driven disassembler.  Every instruction is one row
//   {mnemonic, match, mask, operand format}
// where the operand format is a comma-separated list of operand names from
// operand_table() below (the operand format-string idea is borrowed from
// QEMU's disas/riscv.c).  Rows are added in priority order: when encodings
// overlap, the row added first wins, so pseudo-instructions go before the
// instruction they alias.

#include "disasm.h"
#include "decode_macros.h"
#include "platform.h"
#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#ifdef __GNUC__
# pragma GCC diagnostic ignored "-Wunused-variable"
#endif

// Indicates that the next arg (only) is optional.
// If the result of converting the next arg to a string is ""
// then it will not be printed.
static const arg_t* opt = nullptr;

namespace {

struct operand_t : public arg_t {
  std::string (*fn)(insn_t);
  operand_t(std::string (*fn)(insn_t)) : fn(fn) {}
  std::string to_string(insn_t insn) const override { return fn(insn); }
};

std::string hex(uint64_t v)
{
  std::stringstream s;
  s << std::hex << "0x" << v;
  return s.str();
}

std::string mem(int imm, uint64_t base)
{
  return std::to_string(imm) + '(' + xpr_name[base] + ')';
}

std::string pc_rel(int32_t target)
{
  return (target >= 0 ? "pc + " : "pc - ") + std::to_string(abs(target));
}

std::string csr_operand(insn_t insn)
{
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

std::string jump_target(insn_t insn)
{
  std::stringstream s;
  int32_t target = insn.uj_imm();
  char sign = target >= 0 ? '+' : '-';
  s << "pc " << sign << std::hex << " 0x" << abs(target);
  return s.str();
}

std::string fli_imm(insn_t insn)
{
  static const char* table[32] = {
    "-1.0", "min", "1.52587890625e-05", "3.0517578125e-05",
    "0.00390625", "0.0078125", "0.0625", "0.125",
    "0.25", "0.3125", "0.375", "0.4375",
    "0.5", "0.625", "0.75", "0.875",
    "1.0", "1.25", "1.5", "1.75",
    "2.0", "2.5", "3.0", "4.0",
    "8.0", "16.0", "128.0", "256.0",
    "32768.0", "65536.0", "inf", "nan"
  };
  return table[insn.rs1()];
}

std::string iorw(insn_t insn)
{
  std::string s;
  auto bits = insn.iorw();
  bool has_pre = false;
  static const char type[] = "wroi";
  for (int i = 7; i >= 4; --i) {
    if (bits & (1ul << i)) {
      s += type[i - 4];
      has_pre = true;
    }
  }

  s += (has_pre ? "," : "");
  for (int i = 3; i >= 0; --i) {
    if (bits & (1ul << i)) {
      s += type[i];
    }
  }

  return s;
}

std::string v_vtype(insn_t insn)
{
  std::stringstream s;
  int sew = insn.v_sew();
  int lmul = insn.v_lmul();
  auto vta = insn.v_vta() == 1 ? "ta" : "tu";
  auto vma = insn.v_vma() == 1 ? "ma" : "mu";
  // if bit 31 is set, this is vsetivli and there is a 10-bit vtype, else this is vsetvli and there is an 11-bit vtype
  int newType = (insn.bits() & 0x80000000) ? insn.v_zimm10() : insn.v_zimm11();
  // If the provided vtype has reserved bits, display the hex version of the vtype instead
  if ((newType >> 8) != 0) {
    s << "0x" << std::hex << newType;
  } else {
    s << "e" << sew;
    if (insn.v_frac_lmul()) {
      static const char* frac[] = {"", "f8", "f4", "f2"};
      s << ", m" << frac[lmul];
    } else {
      s << ", m" << (1 << lmul);
    }
    s << ", " << vta << ", " << vma;
  }

  return s.str();
}

std::string rvcm_pushpop_rlist(insn_t insn)
{
  int rlist = insn.rvc_rlist();
  switch (rlist) {
    case 0: case 1: case 2: case 3: return "unsupport rlist";
    case 4: return "{ra}";
    case 5: return "{ra, s0}";
    case 15: return "{ra, s0-s11}";
    default: return "{ra, s0-s" + std::to_string(rlist - 5) + '}';
  }
}

std::string msetmtypei_operand(insn_t insn)
{
  // eM[alt], wN: SEW, altfmt (bit 28), and TWIDEN = mtwiden ? 1 << (mtwiden - 1) : 0
  unsigned mtwiden = insn.rs1() & 3;
  return "e" + std::to_string(insn.v_sew()) + ((insn.bits() >> 28) & 1 ? "alt" : "") +
         ", w" + std::to_string(mtwiden ? 1 << (mtwiden - 1) : 0);
}

#define OPERAND(name, expr) \
  {name, operand_t([](UNUSED insn_t insn) -> std::string { return expr; })}

// std::less<> allows lookup by string_view without building a std::string
typedef std::map<std::string, operand_t, std::less<>> operand_table_t;

const operand_table_t& operand_table()
{
  static const operand_table_t table = {
    // integer registers; rdp/rs1p/rs2p are RV32 P-extension register pairs
    OPERAND("rd", xpr_name[insn.rd()]),
    OPERAND("rs1", xpr_name[insn.rs1()]),
    OPERAND("rs2", xpr_name[insn.rs2()]),
    OPERAND("rs3", xpr_name[insn.rs3()]),
    OPERAND("rdp", xpr_name[insn.rd_p()]),
    OPERAND("rs1p", xpr_name[insn.rs1_p()]),
    OPERAND("rs2p", xpr_name[insn.rs2_p()]),

    // memory operands
    OPERAND("imm(rs1)", mem(insn.i_imm(), insn.rs1())),
    OPERAND("simm(rs1)", mem(insn.s_imm(), insn.rs1())),
    OPERAND("(rs1)", std::string("(") + xpr_name[insn.rs1()] + ')'),
    OPERAND("(rs2)", std::string("(") + xpr_name[insn.rs2()] + ')'),

    // floating-point
    OPERAND("frd", fpr_name[insn.rd()]),
    OPERAND("frs1", fpr_name[insn.rs1()]),
    OPERAND("frs2", fpr_name[insn.rs2()]),
    OPERAND("frs3", fpr_name[insn.rs3()]),
    OPERAND("rm", frm_name(insn.rm())),
    OPERAND("fli_imm", fli_imm(insn)),

    // immediates and other fields
    OPERAND("csr", csr_operand(insn)),
    OPERAND("imm", std::to_string((int)insn.i_imm())),
    OPERAND("shamt", std::to_string((int)insn.shamt())),
    OPERAND("bigimm", hex((uint32_t)insn.u_imm() >> 12)),
    OPERAND("zimm5", std::to_string(insn.rs1())),
    OPERAND("branch_target", pc_rel(insn.sb_imm())),
    OPERAND("jump_target", jump_target(insn)),
    OPERAND("iorw", iorw(insn)),
    OPERAND("b_imm5", std::to_string((int)insn.b_imm5())),
    OPERAND("bs", std::to_string((int)insn.bs())),
    OPERAND("rcon", std::to_string((int)insn.rcon())),
    OPERAND("p_imm8", std::to_string((int)insn.p_imm8())),
    OPERAND("p_imm10csl", std::to_string((int)insn.p_imm10csl())),
    OPERAND("p_imm10csr", std::to_string((int)insn.p_imm10csr())),
    OPERAND("shamtb", std::to_string((int)insn.shamtb())),
    OPERAND("shamth", std::to_string((int)insn.shamth())),
    OPERAND("shamtw", std::to_string((int)insn.shamtw())),
    OPERAND("shamtd", std::to_string((int)insn.shamtd())),

    // compressed
    OPERAND("rvc_rs1", xpr_name[insn.rvc_rs1()]),
    OPERAND("rvc_rs2", xpr_name[insn.rvc_rs2()]),
    OPERAND("rvc_rs1s", xpr_name[insn.rvc_rs1s()]),
    OPERAND("rvc_rs2s", xpr_name[insn.rvc_rs2s()]),
    OPERAND("rvc_fp_rs2", fpr_name[insn.rvc_rs2()]),
    OPERAND("rvc_fp_rs2s", fpr_name[insn.rvc_rs2s()]),
    OPERAND("rvc_r1s", xpr_name[RVC_R1S]),
    OPERAND("rvc_r2s", xpr_name[RVC_R2S]),
    OPERAND("rvc_sp", xpr_name[X_SP]),
    OPERAND("rvc_ra", xpr_name[X_RA]),
    OPERAND("rvc_t0", xpr_name[X_T0]),
    OPERAND("rvc_imm", std::to_string((int)insn.rvc_imm())),
    OPERAND("rvc_addi4spn_imm", std::to_string((int)insn.rvc_addi4spn_imm())),
    OPERAND("rvc_addi16sp_imm", std::to_string((int)insn.rvc_addi16sp_imm())),
    OPERAND("rvc_shamt", std::to_string((int)(insn.rvc_imm() & 0x3f))),
    OPERAND("rvc_uimm", hex((uint32_t)insn.rvc_imm() << 12 >> 12)),
    OPERAND("rvc_lwsp_address", mem(insn.rvc_lwsp_imm(), X_SP)),
    OPERAND("rvc_ldsp_address", mem(insn.rvc_ldsp_imm(), X_SP)),
    OPERAND("rvc_swsp_address", mem(insn.rvc_swsp_imm(), X_SP)),
    OPERAND("rvc_sdsp_address", mem(insn.rvc_sdsp_imm(), X_SP)),
    OPERAND("rvc_lw_address", mem(insn.rvc_lw_imm(), insn.rvc_rs1s())),
    OPERAND("rvc_ld_address", mem(insn.rvc_ld_imm(), insn.rvc_rs1s())),
    OPERAND("rvb_b_address", mem(insn.rvc_lbimm(), insn.rvc_rs1s())),
    OPERAND("rvb_h_address", mem(insn.rvc_lhimm(), insn.rvc_rs1s())),
    OPERAND("rvc_branch_target", pc_rel(insn.rvc_b_imm())),
    OPERAND("rvc_jump_target", pc_rel(insn.rvc_j_imm())),
    OPERAND("rvcm_jt_index", std::to_string((uint32_t)insn.rvc_index())),
    OPERAND("rvcm_pushpop_rlist", rvcm_pushpop_rlist(insn)),
    OPERAND("rvcm_push_stack_adj_32", '-' + std::to_string(insn.zcmp_stack_adjustment(32))),
    OPERAND("rvcm_push_stack_adj_64", '-' + std::to_string(insn.zcmp_stack_adjustment(64))),
    OPERAND("rvcm_pop_stack_adj_32", std::to_string(insn.zcmp_stack_adjustment(32))),
    OPERAND("rvcm_pop_stack_adj_64", std::to_string(insn.zcmp_stack_adjustment(64))),

    // vector; "vm" is the optional ", v0.t" mask suffix
    OPERAND("vd", vr_name[insn.rd()]),
    OPERAND("vs1", vr_name[insn.rs1()]),
    OPERAND("vs2", vr_name[insn.rs2()]),
    OPERAND("vs3", vr_name[insn.rd()]),
    OPERAND("vm", insn.v_vm() ? "" : "v0.t"),
    OPERAND("v0", "v0"),
    OPERAND("v_simm5", std::to_string((int)insn.v_simm5())),
    OPERAND("v_zimm6", std::to_string(insn.v_zimm6())),
    OPERAND("v_vtype", v_vtype(insn)),
    OPERAND("bdota_vs2", vr_name[insn.rs2() & -8]),
    OPERAND("bdota_ci", std::to_string(8 * (insn.rs2() % 8))),

    // Zvt: matrix tile number in rd[4:1] (rd[4:2] for 3-bit forms, whose rd[1] is 0)
    OPERAND("mtd", "mt" + std::to_string(insn.rd() >> 1)),
    OPERAND("msetmtypei", msetmtypei_operand(insn)),
  };
  return table;
}

#undef OPERAND

std::vector<const arg_t*> parse_format(const char* fmt)
{
  std::vector<const arg_t*> args;
  for (std::string_view rest = fmt; !rest.empty();) {
    auto comma = rest.find(',');
    auto name = rest.substr(0, comma);
    rest = comma == rest.npos ? std::string_view() : rest.substr(comma + 1);

    auto it = operand_table().find(name);
    if (it == operand_table().end()) {
      fprintf(stderr, "disasm: unknown operand '%.*s' in format \"%s\"\n", (int)name.size(), name.data(), fmt);
      abort();
    }
    if (name == "vm")
      args.push_back(opt);
    args.push_back(&it->second);
  }
  return args;
}

struct insn_row_t {
  const char* name;
  uint32_t match;
  uint32_t mask;
  const char* fmt;
};

void add_row(disassembler_t* d, const insn_row_t& r)
{
  // Rows only use string-literal formats, so the pointer identifies the
  // format; thread_local keeps concurrent disassembler construction safe.
  static thread_local std::unordered_map<const char*, std::vector<const arg_t*>> cache;
  auto it = cache.find(r.fmt);
  if (it == cache.end())
    it = cache.emplace(r.fmt, parse_format(r.fmt)).first;
  d->add_insn(new disasm_insn_t(r.name, r.match, r.mask, it->second));
}

void add_unknown_insns(disassembler_t* d)
{
  // provide a default disassembly for all instructions as a fallback
  static const insn_row_t rows[] = {
    #define DECLARE_INSN(code, match, mask) {#code " (args unknown)", match, mask, ""},
    #include "encoding.h"
    #undef DECLARE_INSN
  };
  for (const auto& r : rows)
    add_row(d, r);
}

} // namespace

std::string disassembler_t::disassemble(insn_t insn) const
{
  const disasm_insn_t* disasm_insn = lookup(insn);
  return disasm_insn ? disasm_insn->to_string(insn) : "unknown";
}

// Row named after its encoding.h instruction ('_' is printed as '.').
#define INSN(code, fmt) {#code, match_##code, mask_##code, fmt}
// Same, with extra mask bits (reserved fields, fixed operands, ...).
#define INSN_X(code, extra, fmt) {#code, match_##code, mask_##code | (extra), fmt}
// Another mnemonic for (a subset of) an encoding, e.g. a pseudo-instruction.
#define ALIAS(name, code, extra, fmt) {name, match_##code, mask_##code | (extra), fmt}
// An AMO and its .rl/.aq/.aqrl variants.
#define AMO(code) \
  {#code,         match_##code,             mask_##code | mask_aqrl, "rd,rs2,(rs1)"}, \
  {#code ".rl",   match_##code | (1 << 25), mask_##code | mask_aqrl, "rd,rs2,(rs1)"}, \
  {#code ".aq",   match_##code | (2 << 25), mask_##code | mask_aqrl, "rd,rs2,(rs1)"}, \
  {#code ".aqrl", match_##code | (3 << 25), mask_##code | mask_aqrl, "rd,rs2,(rs1)"}

#define ext_enabled_strict(x) (isa->extension_enabled(x))
#define ext_enabled(x) (ext_enabled_strict(x) || !strict)
#define xlen_eq(x) (xlen_eq_strict(x) || !strict)
#define xlen_eq_strict(x) (isa->get_max_xlen() == (x))

void disassembler_t::add_instructions(const isa_parser_t* isa, bool strict)
{
  const uint32_t mask_rd = 0x1fUL << 7;
  const uint32_t match_rd_ra = 1UL << 7;
  const uint32_t mask_rs1 = 0x1fUL << 15;
  const uint32_t match_rs1_ra = 1UL << 15;
  const uint32_t mask_rs2 = 0x1fUL << 20;
  const uint32_t mask_imm = 0xfffUL << 20;
  const uint32_t imm_shift = 20;
  const uint32_t mask_rvc_rs2 = 0x1fUL << 2;
  const uint32_t mask_rvc_imm = mask_rvc_rs2 | 0x1000UL;
  const uint32_t mask_nf = 0x7Ul << 29;
  const uint32_t mask_vm = 0x1Ul << 25;
  const uint32_t mask_aqrl = 0x3Ul << 25;
  const uint32_t mask_vldst = 0x7Ul << 12 | 0x1UL << 28;
  // Shift amounts are XLEN wide; on RV32 (and for the *w shifts) the MSB is reserved.
  const uint32_t mask_shamt_msb = 0x1Ul << 25;
  const uint32_t shamt_msb = xlen_eq(64) ? 0 : mask_shamt_msb;
  const uint32_t rvc_shamt_msb = xlen_eq(64) ? 0 : 0x1Ul << 12;

  #define DECLARE_INSN(code, match, mask) \
   const uint32_t match_##code = match; \
   const uint32_t mask_##code = mask;
  #include "encoding.h"
  #undef DECLARE_INSN

  auto add = [this](std::initializer_list<insn_row_t> rows) {
    for (const auto& r : rows)
      add_row(this, r);
  };

  // Vector operand formats shared by most vector arithmetic instructions;
  // the m* forms are the multiply-add operand order.
  const char* const v = "vd,vs2,vm";
  const char* const vv = "vd,vs2,vs1,vm";
  const char* const vx = "vd,vs2,rs1,vm";
  const char* const vf = "vd,vs2,frs1,vm";
  const char* const vi = "vd,vs2,v_simm5,vm";
  const char* const viu = "vd,vs2,zimm5,vm";
  const char* const mvv = "vd,vs1,vs2,vm";
  const char* const mvx = "vd,rs1,vs2,vm";
  const char* const mvf = "vd,frs1,vs2,vm";

  add({
    {"unimp", match_csrrw|(CSR_CYCLE<<20), 0xffffffff, ""},
    {"c.unimp", 0, 0xffff, ""},

    // Following are HINTs, so they must precede their corresponding base-ISA
    // instructions.  We do not condition them on Zicbop/Zihintpause because,
    // definitionally, all implementations provide them.
    INSN(prefetch_r, "simm(rs1)"),
    INSN(prefetch_w, "simm(rs1)"),
    INSN(prefetch_i, "simm(rs1)"),
    INSN(pause, ""),

    INSN(lb, "rd,imm(rs1)"),
    INSN(lbu, "rd,imm(rs1)"),
    INSN(lh, "rd,imm(rs1)"),
    INSN(lhu, "rd,imm(rs1)"),
    INSN(lw, "rd,imm(rs1)"),

    INSN(sb, "rs2,simm(rs1)"),
    INSN(sh, "rs2,simm(rs1)"),
    INSN(sw, "rs2,simm(rs1)"),
  });

  if (xlen_eq(64)) add({
    INSN(lwu, "rd,imm(rs1)"),
    INSN(ld, "rd,imm(rs1)"),

    INSN(sd, "rs2,simm(rs1)"),
  });

  if (ext_enabled(EXT_ZAAMO)) {
    add({
      AMO(amoadd_w),
      AMO(amoswap_w),
      AMO(amoand_w),
      AMO(amoor_w),
      AMO(amoxor_w),
      AMO(amomin_w),
      AMO(amomax_w),
      AMO(amominu_w),
      AMO(amomaxu_w),
    });

    if (xlen_eq(64)) add({
      AMO(amoadd_d),
      AMO(amoswap_d),
      AMO(amoand_d),
      AMO(amoor_d),
      AMO(amoxor_d),
      AMO(amomin_d),
      AMO(amomax_d),
      AMO(amominu_d),
      AMO(amomaxu_d),
    });
  }

  if (ext_enabled(EXT_ZALRSC)) {
    add({
      INSN(lr_w, "rd,(rs1)"),
      AMO(sc_w),
    });

    if (xlen_eq(64)) add({
      INSN(lr_d, "rd,(rs1)"),
      AMO(sc_d),
    });
  }

  if (ext_enabled(EXT_ZACAS)) {
    add({
      AMO(amocas_w),
      AMO(amocas_d),
    });

    if (xlen_eq(64)) add({
      AMO(amocas_q),
    });
  }

  if (ext_enabled(EXT_ZABHA)) add({
    AMO(amoadd_b),
    AMO(amoswap_b),
    AMO(amoand_b),
    AMO(amoor_b),
    AMO(amoxor_b),
    AMO(amomin_b),
    AMO(amomax_b),
    AMO(amominu_b),
    AMO(amomaxu_b),
    AMO(amocas_b),
    AMO(amoadd_h),
    AMO(amoswap_h),
    AMO(amoand_h),
    AMO(amoor_h),
    AMO(amoxor_h),
    AMO(amomin_h),
    AMO(amomax_h),
    AMO(amominu_h),
    AMO(amomaxu_h),
    AMO(amocas_h),
  });

  if (ext_enabled(EXT_ZAWRS)) add({
    INSN(wrs_sto, ""),
    INSN(wrs_nto, ""),
  });

  if (ext_enabled(EXT_ZILX)) {
    // `lxb`/`lxbu` are assembler pseudoinstructions for `lxsb`/`lxsbu`; add
    // them first so they win when disassembling the shared encoding.
    add({
      ALIAS("lxb", lxsb, 0, "rd,(rs2),rs1"),
      ALIAS("lxbu", lxsbu, 0, "rd,(rs2),rs1"),

      // unscaled indexed loads
      INSN(lxh, "rd,(rs2),rs1"),
      INSN(lxw, "rd,(rs2),rs1"),
      INSN(lxhu, "rd,(rs2),rs1"),

      // scaled indexed loads
      INSN(lxsb, "rd,(rs2),rs1"),
      INSN(lxsh, "rd,(rs2),rs1"),
      INSN(lxsw, "rd,(rs2),rs1"),
      INSN(lxsbu, "rd,(rs2),rs1"),
      INSN(lxshu, "rd,(rs2),rs1"),
    });

    if (xlen_eq(64)) add({
      // unscaled indexed loads (RV64-only widths)
      INSN(lxd, "rd,(rs2),rs1"),
      INSN(lxwu, "rd,(rs2),rs1"),

      // scaled indexed loads (RV64-only widths)
      INSN(lxsd, "rd,(rs2),rs1"),
      INSN(lxswu, "rd,(rs2),rs1"),

      // scaled indexed loads with zero-extended 32-bit index (RV64-only)
      INSN(lxsuwb, "rd,(rs2),rs1"),
      INSN(lxsuwh, "rd,(rs2),rs1"),
      INSN(lxsuww, "rd,(rs2),rs1"),
      INSN(lxsuwd, "rd,(rs2),rs1"),
      INSN(lxsuwbu, "rd,(rs2),rs1"),
      INSN(lxsuwhu, "rd,(rs2),rs1"),
      INSN(lxsuwwu, "rd,(rs2),rs1"),
    });
  }

  if (ext_enabled(EXT_ZICFILP)) add({
    // lpad encodes as `auipc x0, label`, so it needs to be added before auipc
    // for higher disassembling priority
    INSN(lpad, "bigimm"),
  });

  add({
    {"j", match_jal, mask_jal | mask_rd, "jump_target"},
    {"jal", match_jal | match_rd_ra, mask_jal | mask_rd, "jump_target"},
    {"jal", match_jal, mask_jal, "rd,jump_target"},

    ALIAS("beqz", beq, mask_rs2, "rs1,branch_target"),
    ALIAS("bnez", bne, mask_rs2, "rs1,branch_target"),
    ALIAS("bltz", blt, mask_rs2, "rs1,branch_target"),
    ALIAS("bgez", bge, mask_rs2, "rs1,branch_target"),
    INSN(beq, "rs1,rs2,branch_target"),
    INSN(bne, "rs1,rs2,branch_target"),
    INSN(blt, "rs1,rs2,branch_target"),
    INSN(bge, "rs1,rs2,branch_target"),
    INSN(bltu, "rs1,rs2,branch_target"),
    INSN(bgeu, "rs1,rs2,branch_target"),

    INSN(lui, "rd,bigimm"),
    INSN(auipc, "rd,bigimm"),

    {"ret", match_jalr | match_rs1_ra, mask_jalr | mask_rd | mask_rs1 | mask_imm, ""},
    ALIAS("jr", jalr, mask_rd | mask_imm, "rs1"),
    {"jalr", match_jalr | match_rd_ra, mask_jalr | mask_rd | mask_imm, "rs1"},
    INSN(jalr, "rd,rs1,imm"),
  });

  add({
    {"nop", match_addi, mask_addi | mask_rd | mask_rs1 | mask_imm, ""},
    ALIAS("li", addi, mask_rs1, "rd,imm"),
    ALIAS("mv", addi, mask_imm, "rd,rs1"),
    INSN(addi, "rd,rs1,imm"),
    INSN(slti, "rd,rs1,imm"),
    {"seqz", match_sltiu | (1 << imm_shift), mask_sltiu | mask_imm, "rd,rs1"},
    INSN(sltiu, "rd,rs1,imm"),
    {"not", match_xori | mask_imm, mask_xori | mask_imm, "rd,rs1"},
    INSN(xori, "rd,rs1,imm"),

    INSN_X(slli, shamt_msb, "rd,rs1,shamt"),
    INSN_X(srli, shamt_msb, "rd,rs1,shamt"),
    INSN_X(srai, shamt_msb, "rd,rs1,shamt"),

    INSN(ori, "rd,rs1,imm"),
    INSN(andi, "rd,rs1,imm"),
  });

  if (xlen_eq(64)) add({
    ALIAS("sext.w", addiw, mask_imm, "rd,rs1"),
    INSN(addiw, "rd,rs1,imm"),

    INSN_X(slliw, mask_shamt_msb, "rd,rs1,shamt"),
    INSN_X(srliw, mask_shamt_msb, "rd,rs1,shamt"),
    INSN_X(sraiw, mask_shamt_msb, "rd,rs1,shamt"),

    INSN(addw, "rd,rs1,rs2"),
    INSN(subw, "rd,rs1,rs2"),
    INSN(sllw, "rd,rs1,rs2"),
    INSN(srlw, "rd,rs1,rs2"),
    INSN(sraw, "rd,rs1,rs2"),
  });

  add({
    INSN(add, "rd,rs1,rs2"),
    INSN(sub, "rd,rs1,rs2"),
    INSN(sll, "rd,rs1,rs2"),
    INSN(slt, "rd,rs1,rs2"),
    {"snez", match_sltu, mask_sltu | mask_rs1, "rd,rs2"},
    INSN(sltu, "rd,rs1,rs2"),
    INSN(xor, "rd,rs1,rs2"),
    INSN(srl, "rd,rs1,rs2"),
    INSN(sra, "rd,rs1,rs2"),
    INSN(or, "rd,rs1,rs2"),
    INSN(and, "rd,rs1,rs2"),

    INSN(ecall, ""),
    INSN(ebreak, ""),
    INSN(mret, ""),
    INSN(dret, ""),
    INSN(wfi, ""),
    {"fence", match_fence, mask_fence, "iorw"},
    INSN(fence_i, ""),

    {"csrr", match_csrrs, mask_csrrs | mask_rs1, "rd,csr"},
    {"csrw", match_csrrw, mask_csrrw | mask_rd, "csr,rs1"},
    {"csrs", match_csrrs, mask_csrrs | mask_rd, "csr,rs1"},
    {"csrc", match_csrrc, mask_csrrc | mask_rd, "csr,rs1"},
    {"csrwi", match_csrrwi, mask_csrrwi | mask_rd, "csr,zimm5"},
    {"csrsi", match_csrrsi, mask_csrrsi | mask_rd, "csr,zimm5"},
    {"csrci", match_csrrci, mask_csrrci | mask_rd, "csr,zimm5"},
    {"csrrw", match_csrrw, mask_csrrw, "rd,csr,rs1"},
    {"csrrs", match_csrrs, mask_csrrs, "rd,csr,rs1"},
    {"csrrc", match_csrrc, mask_csrrc, "rd,csr,rs1"},
    {"csrrwi", match_csrrwi, mask_csrrwi, "rd,csr,zimm5"},
    {"csrrsi", match_csrrsi, mask_csrrsi, "rd,csr,zimm5"},
    {"csrrci", match_csrrci, mask_csrrci, "rd,csr,zimm5"},
  });

  if (ext_enabled('S')) add({
    INSN(sret, ""),
    INSN(sfence_vma, "rs1,rs2"),
  });

  if (ext_enabled('M')) {
    add({
      INSN(mul, "rd,rs1,rs2"),
      INSN(mulh, "rd,rs1,rs2"),
      INSN(mulhu, "rd,rs1,rs2"),
      INSN(mulhsu, "rd,rs1,rs2"),
      INSN(div, "rd,rs1,rs2"),
      INSN(divu, "rd,rs1,rs2"),
      INSN(rem, "rd,rs1,rs2"),
      INSN(remu, "rd,rs1,rs2"),
    });

    if (xlen_eq(64)) add({
      INSN(mulw, "rd,rs1,rs2"),
      INSN(divw, "rd,rs1,rs2"),
      INSN(divuw, "rd,rs1,rs2"),
      INSN(remw, "rd,rs1,rs2"),
      INSN(remuw, "rd,rs1,rs2"),
    });
  }

  if (ext_enabled(EXT_ZBA)) {
    add({
      INSN(sh1add, "rd,rs1,rs2"),
      INSN(sh2add, "rd,rs1,rs2"),
      INSN(sh3add, "rd,rs1,rs2"),
    });
    if (xlen_eq(64)) add({
      INSN_X(slli_uw, shamt_msb, "rd,rs1,shamt"),
      {"zext.w", match_add_uw, mask_add_uw | mask_rs2, "rd,rs1"},
      INSN(add_uw, "rd,rs1,rs2"),
      INSN(sh1add_uw, "rd,rs1,rs2"),
      INSN(sh2add_uw, "rd,rs1,rs2"),
      INSN(sh3add_uw, "rd,rs1,rs2"),
    });
  }

  if (ext_enabled(EXT_ZBB)) {
    add({
      INSN(ror, "rd,rs1,rs2"),
      INSN(rol, "rd,rs1,rs2"),
      INSN_X(rori, shamt_msb, "rd,rs1,shamt"),
      INSN(ctz, "rd,rs1"),
      INSN(clz, "rd,rs1"),
      INSN(cpop, "rd,rs1"),
      INSN(min, "rd,rs1,rs2"),
      INSN(minu, "rd,rs1,rs2"),
      INSN(max, "rd,rs1,rs2"),
      INSN(maxu, "rd,rs1,rs2"),
      INSN(andn, "rd,rs1,rs2"),
      INSN(orn, "rd,rs1,rs2"),
      INSN(xnor, "rd,rs1,rs2"),
      INSN(sext_b, "rd,rs1"),
      INSN(sext_h, "rd,rs1"),
      INSN(rev8, "rd,rs1"),
      INSN(orc_b, "rd,rs1"),
      {"zext.h", (isa->get_max_xlen() == 32 ? match_pack : match_packw), mask_pack | mask_rs2, "rd,rs1"},
    });
    if (xlen_eq(64)) add({
      INSN(rorw, "rd,rs1,rs2"),
      INSN(rolw, "rd,rs1,rs2"),
      INSN_X(roriw, mask_shamt_msb, "rd,rs1,shamt"),
      INSN(ctzw, "rd,rs1"),
      INSN(clzw, "rd,rs1"),
      INSN(cpopw, "rd,rs1"),
    });
  }

  if (ext_enabled(EXT_ZBC)) add({
    INSN(clmul, "rd,rs1,rs2"),
    INSN(clmulh, "rd,rs1,rs2"),
    INSN(clmulr, "rd,rs1,rs2"),
  });

  if (ext_enabled(EXT_ZBS)) add({
    INSN(bclr, "rd,rs1,rs2"),
    INSN(binv, "rd,rs1,rs2"),
    INSN(bset, "rd,rs1,rs2"),
    INSN(bext, "rd,rs1,rs2"),
    INSN_X(bclri, shamt_msb, "rd,rs1,shamt"),
    INSN_X(binvi, shamt_msb, "rd,rs1,shamt"),
    INSN_X(bseti, shamt_msb, "rd,rs1,shamt"),
    INSN_X(bexti, shamt_msb, "rd,rs1,shamt"),
  });

  if (ext_enabled(EXT_ZBKB)) {
    add({
      INSN(brev8, "rd,rs1"),
      INSN(rev8, "rd,rs1"),
      INSN(pack, "rd,rs1,rs2"),
      INSN(packh, "rd,rs1,rs2"),
    });
    if (xlen_eq(64)) add({
      INSN(packw, "rd,rs1,rs2"),
    });
  }

  if (ext_enabled(EXT_SVINVAL)) add({
    INSN(sfence_w_inval, ""),
    INSN(sfence_inval_ir, ""),
    INSN(sinval_vma, "rs1,rs2"),
    INSN(hinval_vvma, "rs1,rs2"),
    INSN(hinval_gvma, "rs1,rs2"),
  });

  if (ext_enabled('F')) add({
    INSN(flw, "frd,imm(rs1)"),
    INSN(fsw, "frs2,simm(rs1)"),
    INSN(fmv_w_x, "frd,rs1"),
    INSN(fmv_x_w, "rd,frs1"),
  });

  if (ext_enabled('F') || ext_enabled(EXT_ZFINX)) {
    add({
      INSN(fadd_s, "frd,frs1,frs2"),
      INSN(fsub_s, "frd,frs1,frs2"),
      INSN(fmul_s, "frd,frs1,frs2"),
      INSN(fdiv_s, "frd,frs1,frs2"),
      INSN(fsqrt_s, "frd,frs1"),
      INSN(fmin_s, "frd,frs1,frs2"),
      INSN(fmax_s, "frd,frs1,frs2"),
      INSN(fmadd_s, "frd,frs1,frs2,frs3"),
      INSN(fmsub_s, "frd,frs1,frs2,frs3"),
      INSN(fnmadd_s, "frd,frs1,frs2,frs3"),
      INSN(fnmsub_s, "frd,frs1,frs2,frs3"),
      INSN(fsgnj_s, "frd,frs1,frs2"),
      INSN(fsgnjn_s, "frd,frs1,frs2"),
      INSN(fsgnjx_s, "frd,frs1,frs2"),
      INSN(fcvt_s_d, "frd,frs1"),
      INSN(fcvt_s_q, "frd,frs1"),
      INSN(fcvt_s_w, "frd,rs1"),
      INSN(fcvt_s_wu, "frd,rs1"),
      INSN(fcvt_s_wu, "frd,rs1"),
      INSN(fcvt_w_s, "rd,frs1"),
      INSN(fcvt_wu_s, "rd,frs1"),
      INSN(fclass_s, "rd,frs1"),
      INSN(feq_s, "rd,frs1,frs2"),
      INSN(flt_s, "rd,frs1,frs2"),
      INSN(fle_s, "rd,frs1,frs2"),
    });

    if (xlen_eq(64)) add({
      INSN(fcvt_s_l, "frd,rs1"),
      INSN(fcvt_s_lu, "frd,rs1"),
      INSN(fcvt_l_s, "rd,frs1"),
      INSN(fcvt_lu_s, "rd,frs1"),
    });
  }

  if (ext_enabled('D')) {
    add({
      INSN(fld, "frd,imm(rs1)"),
      INSN(fsd, "frs2,simm(rs1)"),
    });

    if (xlen_eq(64)) add({
      INSN(fmv_d_x, "frd,rs1"),
      INSN(fmv_x_d, "rd,frs1"),
    });
  }

  if (ext_enabled('D') || ext_enabled(EXT_ZDINX)) {
    add({
      INSN(fadd_d, "frd,frs1,frs2"),
      INSN(fsub_d, "frd,frs1,frs2"),
      INSN(fmul_d, "frd,frs1,frs2"),
      INSN(fdiv_d, "frd,frs1,frs2"),
      INSN(fsqrt_d, "frd,frs1"),
      INSN(fmin_d, "frd,frs1,frs2"),
      INSN(fmax_d, "frd,frs1,frs2"),
      INSN(fmadd_d, "frd,frs1,frs2,frs3"),
      INSN(fmsub_d, "frd,frs1,frs2,frs3"),
      INSN(fnmadd_d, "frd,frs1,frs2,frs3"),
      INSN(fnmsub_d, "frd,frs1,frs2,frs3"),
      INSN(fsgnj_d, "frd,frs1,frs2"),
      INSN(fsgnjn_d, "frd,frs1,frs2"),
      INSN(fsgnjx_d, "frd,frs1,frs2"),
      INSN(fcvt_d_s, "frd,frs1"),
      INSN(fcvt_d_q, "frd,frs1"),
      INSN(fcvt_d_w, "frd,rs1"),
      INSN(fcvt_d_wu, "frd,rs1"),
      INSN(fcvt_d_wu, "frd,rs1"),
      INSN(fcvt_w_d, "rd,frs1"),
      INSN(fcvt_wu_d, "rd,frs1"),
      INSN(fclass_d, "rd,frs1"),
      INSN(feq_d, "rd,frs1,frs2"),
      INSN(flt_d, "rd,frs1,frs2"),
      INSN(fle_d, "rd,frs1,frs2"),
    });

    if (xlen_eq(64)) add({
      INSN(fcvt_d_l, "frd,rs1"),
      INSN(fcvt_d_lu, "frd,rs1"),
      INSN(fcvt_l_d, "rd,frs1"),
      INSN(fcvt_lu_d, "rd,frs1"),
    });
  }

  if (ext_enabled(EXT_ZFA)) {
    add({
      INSN(fli_s, "frd,fli_imm"),
      INSN(fminm_s, "frd,frs1,frs2"),
      INSN(fmaxm_s, "frd,frs1,frs2"),
      INSN(fround_s, "frd,frs1"),
      INSN(froundnx_s, "frd,frs1"),
      INSN(fleq_s, "rd,frs1,frs2"),
      INSN(fltq_s, "rd,frs1,frs2"),
    });

    if (ext_enabled(EXT_ZFH) || ext_enabled(EXT_ZVFH)) add({
      INSN(fli_h, "frd,fli_imm"),
      INSN(fminm_h, "frd,frs1,frs2"),
      INSN(fmaxm_h, "frd,frs1,frs2"),
      INSN(fround_h, "frd,frs1"),
      INSN(froundnx_h, "frd,frs1"),
      INSN(fleq_h, "rd,frs1,frs2"),
      INSN(fltq_h, "rd,frs1,frs2"),
    });

    if (ext_enabled('D')) {
      add({
        INSN(fli_d, "frd,fli_imm"),
        INSN(fminm_d, "frd,frs1,frs2"),
        INSN(fmaxm_d, "frd,frs1,frs2"),
        INSN(fround_d, "frd,frs1"),
        INSN(froundnx_d, "frd,frs1"),
        INSN(fleq_d, "rd,frs1,frs2"),
        INSN(fltq_d, "rd,frs1,frs2"),
        INSN(fcvtmod_w_d, "rd,frs1,rm"),
      });

      if (xlen_eq(32)) add({
        INSN(fmvp_d_x, "frd,rs1,rs2"),
        INSN(fmvh_x_d, "rd,frs1"),
      });
    }

    if (ext_enabled('Q')) {
      add({
        INSN(fli_q, "frd,fli_imm"),
        INSN(fminm_q, "frd,frs1,frs2"),
        INSN(fmaxm_q, "frd,frs1,frs2"),
        INSN(fround_q, "frd,frs1"),
        INSN(froundnx_q, "frd,frs1"),
        INSN(fleq_q, "rd,frs1,frs2"),
        INSN(fltq_q, "rd,frs1,frs2"),
      });

      if (xlen_eq(64)) add({
        INSN(fmvp_q_x, "frd,rs1,rs2"),
        INSN(fmvh_x_q, "rd,frs1"),
      });
    }
  }

  if (ext_enabled(EXT_ZFH)) add({
    INSN(fadd_h, "frd,frs1,frs2"),
    INSN(fsub_h, "frd,frs1,frs2"),
    INSN(fmul_h, "frd,frs1,frs2"),
    INSN(fdiv_h, "frd,frs1,frs2"),
    INSN(fsqrt_h, "frd,frs1"),
    INSN(fmin_h, "frd,frs1,frs2"),
    INSN(fmax_h, "frd,frs1,frs2"),
    INSN(fmadd_h, "frd,frs1,frs2,frs3"),
    INSN(fmsub_h, "frd,frs1,frs2,frs3"),
    INSN(fnmadd_h, "frd,frs1,frs2,frs3"),
    INSN(fnmsub_h, "frd,frs1,frs2,frs3"),
    INSN(fsgnj_h, "frd,frs1,frs2"),
    INSN(fsgnjn_h, "frd,frs1,frs2"),
    INSN(fsgnjx_h, "frd,frs1,frs2"),
    INSN(fcvt_h_l, "frd,rs1"),
    INSN(fcvt_h_lu, "frd,rs1"),
    INSN(fcvt_h_w, "frd,rs1"),
    INSN(fcvt_h_wu, "frd,rs1"),
    INSN(fcvt_h_wu, "frd,rs1"),
    INSN(fcvt_l_h, "rd,frs1"),
    INSN(fcvt_lu_h, "rd,frs1"),
    INSN(fcvt_w_h, "rd,frs1"),
    INSN(fcvt_wu_h, "rd,frs1"),
    INSN(fclass_h, "rd,frs1"),
    INSN(feq_h, "rd,frs1,frs2"),
    INSN(flt_h, "rd,frs1,frs2"),
    INSN(fle_h, "rd,frs1,frs2"),
  });

  if (ext_enabled(EXT_ZHINX)) add({
    INSN(fadd_h, "rd,rs1,rs2"),
    INSN(fsub_h, "rd,rs1,rs2"),
    INSN(fmul_h, "rd,rs1,rs2"),
    INSN(fdiv_h, "rd,rs1,rs2"),
    INSN(fsqrt_h, "rd,rs1"),
    INSN(fmin_h, "rd,rs1,rs2"),
    INSN(fmax_h, "rd,rs1,rs2"),
    INSN(fmadd_h, "rd,rs1,rs2,rs3"),
    INSN(fmsub_h, "rd,rs1,rs2,rs3"),
    INSN(fnmadd_h, "rd,rs1,rs2,rs3"),
    INSN(fnmsub_h, "rd,rs1,rs2,rs3"),
    INSN(fsgnj_h, "rd,rs1,rs2"),
    INSN(fsgnjn_h, "rd,rs1,rs2"),
    INSN(fsgnjx_h, "rd,rs1,rs2"),
    INSN(fcvt_h_l, "rd,rs1"),
    INSN(fcvt_h_lu, "rd,rs1"),
    INSN(fcvt_h_w, "rd,rs1"),
    INSN(fcvt_h_wu, "rd,rs1"),
    INSN(fcvt_h_wu, "rd,rs1"),
    INSN(fcvt_l_h, "rd,rs1"),
    INSN(fcvt_lu_h, "rd,rs1"),
    INSN(fcvt_w_h, "rd,rs1"),
    INSN(fcvt_wu_h, "rd,rs1"),
    INSN(fclass_h, "rd,rs1"),
    INSN(feq_h, "rd,rs1,rs2"),
    INSN(flt_h, "rd,rs1,rs2"),
    INSN(fle_h, "rd,rs1,rs2"),
  });

  if (ext_enabled(EXT_ZFHMIN)) add({
    INSN(fcvt_h_s, "frd,frs1"),
    INSN(fcvt_h_d, "frd,frs1"),
    INSN(fcvt_h_q, "frd,frs1"),
    INSN(fcvt_s_h, "frd,frs1"),
    INSN(fcvt_d_h, "frd,frs1"),
    INSN(fcvt_q_h, "frd,frs1"),
  });

  if (ext_enabled(EXT_INTERNAL_ZFH_MOVE)) add({
    INSN(flh, "frd,imm(rs1)"),
    INSN(fsh, "frs2,simm(rs1)"),
    INSN(fmv_h_x, "frd,rs1"),
    INSN(fmv_x_h, "rd,frs1"),
  });

  if (ext_enabled(EXT_ZHINXMIN)) add({
    INSN(fcvt_h_s, "rd,rs1"),
    INSN(fcvt_h_d, "rd,rs1"),
    // INSN(fcvt_h_q, "rd,rs1"),
    INSN(fcvt_s_h, "rd,rs1"),
    INSN(fcvt_d_h, "rd,rs1"),
    // INSN(fcvt_q_h, "rd,rs1"),
  });

  if (ext_enabled(EXT_ZIBI)) add({
     INSN(beqi, "rs1,b_imm5,branch_target"),
     INSN(bnei, "rs1,b_imm5,branch_target"),
  });

  if (ext_enabled('Q')) add({
    INSN(flq, "frd,imm(rs1)"),
    INSN(fsq, "frs2,simm(rs1)"),
    INSN(fadd_q, "frd,frs1,frs2"),
    INSN(fsub_q, "frd,frs1,frs2"),
    INSN(fmul_q, "frd,frs1,frs2"),
    INSN(fdiv_q, "frd,frs1,frs2"),
    INSN(fsqrt_q, "frd,frs1"),
    INSN(fmin_q, "frd,frs1,frs2"),
    INSN(fmax_q, "frd,frs1,frs2"),
    INSN(fmadd_q, "frd,frs1,frs2,frs3"),
    INSN(fmsub_q, "frd,frs1,frs2,frs3"),
    INSN(fnmadd_q, "frd,frs1,frs2,frs3"),
    INSN(fnmsub_q, "frd,frs1,frs2,frs3"),
    INSN(fsgnj_q, "frd,frs1,frs2"),
    INSN(fsgnjn_q, "frd,frs1,frs2"),
    INSN(fsgnjx_q, "frd,frs1,frs2"),
    INSN(fcvt_q_s, "frd,frs1"),
    INSN(fcvt_q_d, "frd,frs1"),
    INSN(fcvt_q_l, "frd,rs1"),
    INSN(fcvt_q_lu, "frd,rs1"),
    INSN(fcvt_q_w, "frd,rs1"),
    INSN(fcvt_q_wu, "frd,rs1"),
    INSN(fcvt_q_wu, "frd,rs1"),
    INSN(fcvt_l_q, "rd,frs1"),
    INSN(fcvt_lu_q, "rd,frs1"),
    INSN(fcvt_w_q, "rd,frs1"),
    INSN(fcvt_wu_q, "rd,frs1"),
    INSN(fclass_q, "rd,frs1"),
    INSN(feq_q, "rd,frs1,frs2"),
    INSN(flt_q, "rd,frs1,frs2"),
    INSN(fle_q, "rd,frs1,frs2"),
  });

  if (ext_enabled(EXT_ZFBFMIN)) add({
    INSN(fcvt_bf16_s, "frd,frs1"),
    INSN(fcvt_s_bf16, "frd,frs1"),
  });

  // ext-h
  if (ext_enabled('H')) add({
    INSN(hlv_b, "rd,(rs1)"),
    INSN(hlv_bu, "rd,(rs1)"),
    INSN(hlv_h, "rd,(rs1)"),
    INSN(hlv_hu, "rd,(rs1)"),
    INSN(hlv_w, "rd,(rs1)"),
    INSN(hlv_wu, "rd,(rs1)"),
    INSN(hlv_d, "rd,(rs1)"),

    INSN(hlvx_hu, "rd,(rs1)"),
    INSN(hlvx_wu, "rd,(rs1)"),

    INSN(hsv_b, "rs2,(rs1)"),
    INSN(hsv_h, "rs2,(rs1)"),
    INSN(hsv_w, "rs2,(rs1)"),
    INSN(hsv_d, "rs2,(rs1)"),

    INSN(hfence_gvma, "rs1,rs2"),
    INSN(hfence_vvma, "rs1,rs2"),
  });

  // ext-c
  if (ext_enabled(EXT_ZCA)) {
    add({
      ALIAS("c.ebreak", c_add, mask_rd | mask_rvc_rs2, ""),
      {"c.ret", match_c_jr | match_rd_ra, mask_c_jr | mask_rd | mask_rvc_imm, ""},
      INSN_X(c_jr, mask_rvc_imm, "rvc_rs1"),
      INSN_X(c_jalr, mask_rvc_imm, "rvc_rs1"),
      ALIAS("c.nop", c_addi, mask_rd | mask_rvc_imm, ""),
      INSN_X(c_addi16sp, mask_rd, "rvc_sp,rvc_addi16sp_imm"),
      INSN(c_addi4spn, "rvc_rs2s,rvc_sp,rvc_addi4spn_imm"),
      INSN(c_li, "rd,rvc_imm"),
      INSN(c_lui, "rd,rvc_uimm"),
      INSN(c_addi, "rd,rvc_imm"),
      // On RV32 the shift amount is 5 bits, so bit 12 is reserved.
      INSN_X(c_slli, rvc_shamt_msb, "rvc_rs1,rvc_shamt"),
      INSN_X(c_srli, rvc_shamt_msb, "rvc_rs1s,rvc_shamt"),
      INSN_X(c_srai, rvc_shamt_msb, "rvc_rs1s,rvc_shamt"),
      INSN(c_andi, "rvc_rs1s,rvc_imm"),
      INSN(c_mv, "rd,rvc_rs2"),
      INSN(c_add, "rd,rvc_rs2"),
      INSN(c_sub, "rvc_rs1s,rvc_rs2s"),
      INSN(c_and, "rvc_rs1s,rvc_rs2s"),
      INSN(c_or, "rvc_rs1s,rvc_rs2s"),
      INSN(c_xor, "rvc_rs1s,rvc_rs2s"),
      INSN(c_lwsp, "rd,rvc_lwsp_address"),
      INSN(c_swsp, "rvc_rs2,rvc_swsp_address"),
      INSN(c_lw, "rvc_rs2s,rvc_lw_address"),
      INSN(c_sw, "rvc_rs2s,rvc_lw_address"),
      INSN(c_beqz, "rvc_rs1s,rvc_branch_target"),
      INSN(c_bnez, "rvc_rs1s,rvc_branch_target"),
      INSN(c_j, "rvc_jump_target"),
    });
    if (xlen_eq_strict(32))
      add({INSN(c_jal, "rvc_jump_target")});
    else
      add({INSN(c_addiw, "rd,rvc_imm")});

    if (xlen_eq(64)) add({
      INSN(c_addw, "rvc_rs1s,rvc_rs2s"),
      INSN(c_subw, "rvc_rs1s,rvc_rs2s"),
    });

    if (xlen_eq_strict(64) || ext_enabled_strict(EXT_ZCLSD)) add({
      INSN(c_ld, "rvc_rs2s,rvc_ld_address"),
      INSN(c_ldsp, "rd,rvc_ldsp_address"),
      INSN(c_sd, "rvc_rs2s,rvc_ld_address"),
      INSN(c_sdsp, "rvc_rs2,rvc_sdsp_address"),
    });
  }

  if (ext_enabled(EXT_ZCD)) add({
    INSN(c_fld, "rvc_fp_rs2s,rvc_ld_address"),
    INSN(c_fldsp, "frd,rvc_ldsp_address"),
    INSN(c_fsd, "rvc_fp_rs2s,rvc_ld_address"),
    INSN(c_fsdsp, "rvc_fp_rs2,rvc_sdsp_address"),
  });

  if (ext_enabled(EXT_ZCF)) add({
    INSN(c_flw, "rvc_fp_rs2s,rvc_lw_address"),
    INSN(c_flwsp, "frd,rvc_lwsp_address"),
    INSN(c_fsw, "rvc_fp_rs2s,rvc_lw_address"),
    INSN(c_fswsp, "rvc_fp_rs2,rvc_swsp_address"),
  });

  if (ext_enabled(EXT_ZCB)) {
    add({
      INSN(c_zext_b, "rvc_rs1s"),
      INSN(c_sext_b, "rvc_rs1s"),
      INSN(c_zext_h, "rvc_rs1s"),
      INSN(c_sext_h, "rvc_rs1s"),
    });
    if (xlen_eq(64)) add({
      INSN(c_zext_w, "rvc_rs1s"),
    });
    add({
      INSN(c_not, "rvc_rs1s"),
      INSN(c_mul, "rvc_rs1s,rvc_rs2s"),
      INSN(c_lbu, "rvc_rs2s,rvb_b_address"),
      INSN(c_lhu, "rvc_rs2s,rvb_h_address"),
      INSN(c_lh, "rvc_rs2s,rvb_h_address"),
      INSN(c_sb, "rvc_rs2s,rvb_b_address"),
      INSN(c_sh, "rvc_rs2s,rvb_h_address"),
    });
  }

  if (ext_enabled(EXT_ZCMP)) {
    if (xlen_eq_strict(32)) {
      add({
        INSN(cm_push, "rvcm_pushpop_rlist,rvcm_push_stack_adj_32"),
        INSN(cm_pop, "rvcm_pushpop_rlist,rvcm_pop_stack_adj_32"),
        INSN(cm_popret, "rvcm_pushpop_rlist,rvcm_pop_stack_adj_32"),
        INSN(cm_popretz, "rvcm_pushpop_rlist,rvcm_pop_stack_adj_32"),
      });
    } else {
      add({
        INSN(cm_push, "rvcm_pushpop_rlist,rvcm_push_stack_adj_64"),
        INSN(cm_pop, "rvcm_pushpop_rlist,rvcm_pop_stack_adj_64"),
        INSN(cm_popret, "rvcm_pushpop_rlist,rvcm_pop_stack_adj_64"),
        INSN(cm_popretz, "rvcm_pushpop_rlist,rvcm_pop_stack_adj_64"),
      });
    }

    add({
      INSN(cm_mva01s, "rvc_r1s,rvc_r2s"),
      INSN(cm_mvsa01, "rvc_r1s,rvc_r2s"),
    });
  }

  if (ext_enabled(EXT_ZCMT)) add({
    ALIAS("cm.jt", cm_jalt, 0x380, "rvcm_jt_index"),
    INSN(cm_jalt, "rvcm_jt_index"),
  });

  // Zvt goes before the vector loads/stores: vtle*/vtse* reuse the reserved
  // mew=1 encodings that the vle*/vse* generator below also produces.
  if (ext_enabled(EXT_ZVTBASE)) add({
    INSN(msettn, "rd,rs1"),
    INSN(msettm, "rd,rs1"),
    INSN(msettk, "rd,rs1"),
    INSN(msetmtype, "rs1,rs2"),
    INSN(msetmtypei, "msetmtypei"),
    INSN(vtle8, "rs2,(rs1)"),
    INSN(vtle16, "rs2,(rs1)"),
    INSN(vtle32, "rs2,(rs1)"),
    INSN(vtle64, "rs2,(rs1)"),
    INSN(vtse8, "rs2,(rs1)"),
    INSN(vtse16, "rs2,(rs1)"),
    INSN(vtse32, "rs2,(rs1)"),
    INSN(vtse64, "rs2,(rs1)"),
    INSN(vtmv_v_t, "vd,rs1"),
    INSN(vtmv_t_v, "rs1,vs2"),
    INSN(vtzero, "mtd"),
    INSN(vtdiscard, ""),
  });

  if (ext_enabled(EXT_ZVTFMM) || ext_enabled(EXT_ZVTDMM) || ext_enabled(EXT_ZVTFP16FMM) ||
      ext_enabled(EXT_ZVTBF16FMM) || ext_enabled(EXT_ZVTOFP8FMM)) add({
    INSN(vtfmm_tvv, "mtd,vs2,vs1"),
    INSN(vtfmm_alt_tvv, "mtd,vs2,vs1"),
  });

  if (ext_enabled(EXT_ZVTI8I32MM)) add({
    INSN(vtmmu_tvv, "mtd,vs2,vs1"),
    INSN(vtmms_tvv, "mtd,vs2,vs1"),
  });

  if (isa->has_any_vector() || !strict) {
    add({
      INSN(vsetivli, "rd,zimm5,v_vtype"),
      INSN(vsetvli, "rd,rs1,v_vtype"),
      INSN(vsetvl, "rd,rs1,rs2"),
      INSN(vlm_v, "vd,(rs1),vm"),
      INSN(vsm_v, "vs3,(rs1),vm"),
    });

    // Unit-stride, strided, indexed and fault-only-first loads/stores for
    // every element width and segment count, generated from the 8-bit,
    // nf=1 encodings.
    const struct { uint32_t match, mask; const char *name, *fmt; } vldst[] = {
      {match_vle8_v,    mask_vle8_v,    "vl%se%d.v",    "vd,(rs1),vm"},
      {match_vse8_v,    mask_vse8_v,    "vs%se%d.v",    "vs3,(rs1),vm"},
      {match_vluxei8_v, mask_vluxei8_v, "vlux%sei%d.v", "vd,(rs1),vs2,vm"},
      {match_vsuxei8_v, mask_vsuxei8_v, "vsux%sei%d.v", "vs3,(rs1),vs2,vm"},
      {match_vlse8_v,   mask_vlse8_v,   "vls%se%d.v",   "vd,(rs1),rs2,vm"},
      {match_vsse8_v,   mask_vsse8_v,   "vss%se%d.v",   "vs3,(rs1),rs2,vm"},
      {match_vloxei8_v, mask_vloxei8_v, "vlox%sei%d.v", "vd,(rs1),vs2,vm"},
      {match_vsoxei8_v, mask_vsoxei8_v, "vsox%sei%d.v", "vs3,(rs1),vs2,vm"},
      {match_vle8ff_v,  mask_vle8ff_v,  "vl%se%dff.v",  "vd,(rs1),vm"},
    };
    const uint32_t elt_map[] = {0x00000000, 0x00005000, 0x00006000, 0x00007000,
                                0x10000000, 0x10005000, 0x10006000, 0x10007000};
    char name[128];
    for (unsigned elt = 0; elt <= 7; ++elt) {
      for (unsigned nf = 0; nf <= 7; ++nf) {
        const auto seg = nf ? "seg" + std::to_string(nf + 1) : "";
        for (const auto& t : vldst) {
          snprintf(name, sizeof(name), t.name, seg.c_str(), 8 << elt);
          add_row(this, {name, ((t.match | (nf << 29)) & ~mask_vldst) | elt_map[elt], t.mask | mask_nf, t.fmt});
        }
      }

      // whole-register loads
      for (unsigned nf : {7, 3, 1, 0}) {
        snprintf(name, sizeof(name), "vl%dre%d.v", nf + 1, 8 << elt);
        add_row(this, {name, match_vl1re8_v | (nf << 29) | elt_map[elt], mask_vl1re8_v | mask_nf, "vd,(rs1),vm"});
      }
    }

    add({
      {"vs1r.v", match_vs1r_v | (0 << 29), mask_vs1r_v | mask_nf, "vs3,(rs1)"},
      {"vs2r.v", match_vs1r_v | (1 << 29), mask_vs1r_v | mask_nf, "vs3,(rs1)"},
      {"vs4r.v", match_vs1r_v | (3 << 29), mask_vs1r_v | mask_nf, "vs3,(rs1)"},
      {"vs8r.v", match_vs1r_v | (7 << 29), mask_vs1r_v | mask_nf, "vs3,(rs1)"},
    });

    //OPFVV/OPFVF
    //0b00_0000
    add({
      INSN(vadd_vv, vv),
      INSN(vadd_vx, vx),
      INSN(vadd_vi, vi),
      INSN(vsub_vv, vv),
      INSN(vsub_vx, vx),
      INSN(vrsub_vx, vx),
      INSN(vrsub_vi, vi),
      INSN(vminu_vv, vv),
      INSN(vminu_vx, vx),
      INSN(vmin_vv, vv),
      INSN(vmin_vx, vx),
      INSN(vmaxu_vv, vv),
      INSN(vmaxu_vx, vx),
      INSN(vmax_vv, vv),
      INSN(vmax_vx, vx),
      INSN(vand_vv, vv),
      INSN(vand_vx, vx),
      INSN(vand_vi, vi),
      INSN(vor_vv, vv),
      INSN(vor_vx, vx),
      INSN(vor_vi, vi),
      INSN(vxor_vv, vv),
      INSN(vxor_vx, vx),
      INSN(vxor_vi, vi),
      INSN(vrgather_vv, vv),
      INSN(vrgather_vx, vx),
      INSN(vrgather_vi, viu),
      INSN(vrgatherei16_vv, vv),
      INSN(vslideup_vx, vx),
      INSN(vslideup_vi, viu),
      INSN(vslidedown_vx, vx),
      INSN(vslidedown_vi, viu),

      //0b01_0000
      INSN_X(vadc_vvm, mask_vm, "vd,vs2,vs1,v0"),
      INSN_X(vadc_vxm, mask_vm, "vd,vs2,rs1,v0"),
      INSN_X(vadc_vim, mask_vm, "vd,vs2,v_simm5,v0"),
      INSN_X(vsbc_vvm, mask_vm, "vd,vs2,vs1,v0"),
      INSN_X(vsbc_vxm, mask_vm, "vd,vs2,rs1,v0"),
      INSN_X(vmadc_vvm, mask_vm, "vd,vs2,vs1,v0"),
      INSN_X(vmadc_vxm, mask_vm, "vd,vs2,rs1,v0"),
      INSN_X(vmadc_vim, mask_vm, "vd,vs2,v_simm5,v0"),
      INSN(vmadc_vv, vv),
      INSN(vmadc_vx, vx),
      INSN(vmadc_vi, vi),
      INSN_X(vmsbc_vvm, mask_vm, "vd,vs2,vs1,v0"),
      INSN_X(vmsbc_vxm, mask_vm, "vd,vs2,rs1,v0"),
      INSN(vmsbc_vv, vv),
      INSN(vmsbc_vx, vx),
      INSN_X(vmerge_vvm, mask_vm, "vd,vs2,vs1,v0"),
      INSN_X(vmerge_vxm, mask_vm, "vd,vs2,rs1,v0"),
      INSN_X(vmerge_vim, mask_vm, "vd,vs2,v_simm5,v0"),
      INSN(vmv_v_i, "vd,v_simm5"),
      INSN(vmv_v_v, "vd,vs1"),
      INSN(vmv_v_x, "vd,rs1"),
      INSN(vmseq_vv, vv),
      INSN(vmseq_vx, vx),
      INSN(vmseq_vi, vi),
      INSN(vmsne_vv, vv),
      INSN(vmsne_vx, vx),
      INSN(vmsne_vi, vi),
      INSN(vmsltu_vv, vv),
      INSN(vmsltu_vx, vx),
      INSN(vmslt_vv, vv),
      INSN(vmslt_vx, vx),
      INSN(vmsleu_vv, vv),
      INSN(vmsleu_vx, vx),
      INSN(vmsleu_vi, viu),
      INSN(vmsle_vv, vv),
      INSN(vmsle_vx, vx),
      INSN(vmsle_vi, vi),
      INSN(vmsgtu_vx, vx),
      INSN(vmsgtu_vi, viu),
      INSN(vmsgt_vx, vx),
      INSN(vmsgt_vi, vi),

      //0b10_0000
      INSN(vsaddu_vv, vv),
      INSN(vsaddu_vx, vx),
      INSN(vsaddu_vi, viu),
      INSN(vsadd_vv, vv),
      INSN(vsadd_vx, vx),
      INSN(vsadd_vi, vi),
      INSN(vssubu_vv, vv),
      INSN(vssubu_vx, vx),
      INSN(vssub_vv, vv),
      INSN(vssub_vx, vx),
      INSN(vsll_vv, vv),
      INSN(vsll_vx, vx),
      INSN(vsll_vi, vi),
      INSN(vmv1r_v, "vd,vs2"),
      INSN(vmv2r_v, "vd,vs2"),
      INSN(vmv4r_v, "vd,vs2"),
      INSN(vmv8r_v, "vd,vs2"),
      INSN(vsmul_vv, vv),
      INSN(vsmul_vx, vx),
      INSN(vsrl_vv, vv),
      INSN(vsrl_vx, vx),
      INSN(vsrl_vi, viu),
      INSN(vsra_vv, vv),
      INSN(vsra_vx, vx),
      INSN(vsra_vi, viu),
      INSN(vssrl_vv, vv),
      INSN(vssrl_vx, vx),
      INSN(vssrl_vi, viu),
      INSN(vssra_vv, vv),
      INSN(vssra_vx, vx),
      INSN(vssra_vi, viu),
      INSN(vnsrl_wv, vv),
      INSN(vnsrl_wx, vx),
      INSN(vnsrl_wi, viu),
      INSN(vnsra_wv, vv),
      INSN(vnsra_wx, vx),
      INSN(vnsra_wi, viu),
      INSN(vnclipu_wv, vv),
      INSN(vnclipu_wx, vx),
      INSN(vnclipu_wi, viu),
      INSN(vnclip_wv, vv),
      INSN(vnclip_wx, vx),
      INSN(vnclip_wi, viu),

      //0b11_0000
      INSN(vwredsumu_vs, vv),
      INSN(vwredsum_vs, vv),

      //OPMVV/OPMVX
      //0b00_0000
      INSN(vaaddu_vv, vv),
      INSN(vaaddu_vx, vx),
      INSN(vaadd_vv, vv),
      INSN(vaadd_vx, vx),
      INSN(vasubu_vv, vv),
      INSN(vasubu_vx, vx),
      INSN(vasub_vv, vv),
      INSN(vasub_vx, vx),

      INSN(vredsum_vs, vv),
      INSN(vredand_vs, vv),
      INSN(vredor_vs, vv),
      INSN(vredxor_vs, vv),
      INSN(vredminu_vs, vv),
      INSN(vredmin_vs, vv),
      INSN(vredmaxu_vs, vv),
      INSN(vredmax_vs, vv),
      INSN(vslide1up_vx, vx),
      INSN(vslide1down_vx, vx),

      //0b01_0000
      //VWXUNARY0
      INSN(vmv_x_s, "rd,vs2"),
      INSN(vcpop_m, "rd,vs2,vm"),
      INSN(vfirst_m, "rd,vs2,vm"),

      //VRXUNARY0
      INSN(vmv_s_x, "vd,rs1"),

      //VXUNARY0
      INSN(vzext_vf2, v),
      INSN(vsext_vf2, v),
      INSN(vzext_vf4, v),
      INSN(vsext_vf4, v),
      INSN(vzext_vf8, v),
      INSN(vsext_vf8, v),

      //VMUNARY0
      INSN(vmsbf_m, v),
      INSN(vmsof_m, v),
      INSN(vmsif_m, v),
      INSN(viota_m, v),
      INSN(vid_v, "vd,vm"),

      INSN(vid_v, "vd,vm"),

      INSN(vcompress_vm, "vd,vs2,vs1"),

      INSN(vmandn_mm, vv),
      INSN(vmand_mm, vv),
      INSN(vmor_mm, vv),
      INSN(vmxor_mm, vv),
      INSN(vmorn_mm, vv),
      INSN(vmnand_mm, vv),
      INSN(vmnor_mm, vv),
      INSN(vmxnor_mm, vv),

      //0b10_0000
      INSN(vdivu_vv, vv),
      INSN(vdivu_vx, vx),
      INSN(vdiv_vv, vv),
      INSN(vdiv_vx, vx),
      INSN(vremu_vv, vv),
      INSN(vremu_vx, vx),
      INSN(vrem_vv, vv),
      INSN(vrem_vx, vx),
      INSN(vmulhu_vv, vv),
      INSN(vmulhu_vx, vx),
      INSN(vmul_vv, vv),
      INSN(vmul_vx, vx),
      INSN(vmulhsu_vv, vv),
      INSN(vmulhsu_vx, vx),
      INSN(vmulh_vv, vv),
      INSN(vmulh_vx, vx),
      INSN(vmadd_vv, mvv),
      INSN(vmadd_vx, mvx),
      INSN(vnmsub_vv, mvv),
      INSN(vnmsub_vx, mvx),
      INSN(vmacc_vv, mvv),
      INSN(vmacc_vx, mvx),
      INSN(vnmsac_vv, mvv),
      INSN(vnmsac_vx, mvx),

      //0b11_0000
      INSN(vwaddu_vv, vv),
      INSN(vwaddu_vx, vx),
      INSN(vwadd_vv, vv),
      INSN(vwadd_vx, vx),
      INSN(vwsubu_vv, vv),
      INSN(vwsubu_vx, vx),
      INSN(vwsub_vv, vv),
      INSN(vwsub_vx, vx),
      INSN(vwaddu_wv, vv),
      INSN(vwaddu_wx, vx),
      INSN(vwadd_wv, vv),
      INSN(vwadd_wx, vx),
      INSN(vwsubu_wv, vv),
      INSN(vwsubu_wx, vx),
      INSN(vwsub_wv, vv),
      INSN(vwsub_wx, vx),
      INSN(vwmulu_vv, vv),
      INSN(vwmulu_vx, vx),
      INSN(vwmulsu_vv, vv),
      INSN(vwmulsu_vx, vx),
      INSN(vwmul_vv, vv),
      INSN(vwmul_vx, vx),
      INSN(vwmaccu_vv, mvv),
      INSN(vwmaccu_vx, mvx),
      INSN(vwmacc_vv, mvv),
      INSN(vwmacc_vx, mvx),
      INSN(vwmaccus_vx, mvx),
      INSN(vwmaccsu_vv, mvv),
      INSN(vwmaccsu_vx, mvx),
    });

    if (ext_enabled(EXT_ZVDOT4A)) add({
      INSN(vdot4a_vv, vv),
      INSN(vdot4a_vx, vx),
      INSN(vdot4au_vv, vv),
      INSN(vdot4au_vx, vx),
      INSN(vdot4asu_vv, vv),
      INSN(vdot4asu_vx, vx),
      INSN(vdot4aus_vx, vx),
    });

    if (ext_enabled(EXT_ZVQWBDOTA8I) || ext_enabled(EXT_ZVQWBDOTA16I)) add({
      INSN(vqwbdotau_vv, "vd,bdota_vs2,vs1,bdota_ci,vm"),
      INSN(vqwbdotas_vv, "vd,bdota_vs2,vs1,bdota_ci,vm"),
    });

    if (ext_enabled(EXT_ZVFQWBDOTA8F)) add({
      INSN(vfqwbdota_vv, "vd,bdota_vs2,vs1,bdota_ci,vm"),
      INSN(vfqwbdota_alt_vv, "vd,bdota_vs2,vs1,bdota_ci,vm"),
    });

    if (ext_enabled(EXT_ZVFWBDOTA16BF)) add({
      INSN(vfwbdota_vv, "vd,bdota_vs2,vs1,bdota_ci,vm"),
    });

    if (ext_enabled(EXT_ZVFBDOTA32F)) add({
      INSN(vfbdota_vv, "vd,bdota_vs2,vs1,bdota_ci,vm"),
    });

    if (ext_enabled(EXT_ZVQWDOTA8I) || ext_enabled(EXT_ZVQWDOTA16I)) add({
      INSN(vqwdotau_vv, vv),
      INSN(vqwdotas_vv, vv),
    });

    if (ext_enabled(EXT_ZVFQWDOTA8F)) add({
      INSN(vfqwdota_vv, vv),
      INSN(vfqwdota_alt_vv, vv),
    });

    if (ext_enabled(EXT_ZVFWDOTA16BF)) add({
      INSN(vfwdota_vv, vv),
    });

    //OPFVV/OPFVF
    //0b00_0000
    add({
      INSN(vfadd_vv, vv),
      INSN(vfadd_vf, vf),
      INSN(vfredusum_vs, vv),
      INSN(vfsub_vv, vv),
      INSN(vfsub_vf, vf),
      INSN(vfredosum_vs, vv),
      INSN(vfmin_vv, vv),
      INSN(vfmin_vf, vf),
      INSN(vfredmin_vs, vv),
      INSN(vfmax_vv, vv),
      INSN(vfmax_vf, vf),
      INSN(vfredmax_vs, vv),
      INSN(vfsgnj_vv, vv),
      INSN(vfsgnj_vf, vf),
      INSN(vfsgnjn_vv, vv),
      INSN(vfsgnjn_vf, vf),
      INSN(vfsgnjx_vv, vv),
      INSN(vfsgnjx_vf, vf),
      INSN(vfmv_f_s, "frd,vs2"),
      INSN_X(vfmv_s_f, mask_vfmv_s_f, "vd,frs1"),
      INSN(vfslide1up_vf, vf),
      INSN(vfslide1down_vf, vf),

      //0b01_0000
      INSN(vfmerge_vfm, "vd,vs2,frs1,v0"),
      INSN(vfmv_v_f, "vd,frs1"),
      INSN(vmfeq_vv, vv),
      INSN(vmfeq_vf, vf),
      INSN(vmfle_vv, vv),
      INSN(vmfle_vf, vf),
      INSN(vmflt_vv, vv),
      INSN(vmflt_vf, vf),
      INSN(vmfne_vv, vv),
      INSN(vmfne_vf, vf),
      INSN(vmfgt_vf, vf),
      INSN(vmfge_vf, vf),

      //0b10_0000
      INSN(vfdiv_vv, vv),
      INSN(vfdiv_vf, vf),
      INSN(vfrdiv_vf, vf),

      //vfunary0
      INSN(vfcvt_rtz_xu_f_v, v),
      INSN(vfcvt_rtz_x_f_v, v),
      INSN(vfcvt_xu_f_v, v),
      INSN(vfcvt_x_f_v, v),
      INSN(vfcvt_f_xu_v, v),
      INSN(vfcvt_f_x_v, v),
      INSN(vfwcvt_rtz_xu_f_v, v),
      INSN(vfwcvt_rtz_x_f_v, v),
      INSN(vfwcvt_xu_f_v, v),
      INSN(vfwcvt_x_f_v, v),
      INSN(vfwcvt_f_xu_v, v),
      INSN(vfwcvt_f_x_v, v),
      INSN(vfwcvt_f_f_v, v),

      INSN(vfncvt_rtz_xu_f_w, v),
      INSN(vfncvt_rtz_x_f_w, v),
      INSN(vfncvt_xu_f_w, v),
      INSN(vfncvt_x_f_w, v),
      INSN(vfncvt_f_xu_w, v),
      INSN(vfncvt_f_x_w, v),
      INSN(vfncvt_f_f_w, v),
      INSN(vfncvt_rod_f_f_w, v),

      //vfunary1
      INSN(vfsqrt_v, v),
      INSN(vfrsqrt7_v, v),
      INSN(vfrec7_v, v),
      INSN(vfclass_v, v),

      INSN(vfmul_vv, vv),
      INSN(vfmul_vf, vf),
      INSN(vfrsub_vf, vf),
      INSN(vfmadd_vv, mvv),
      INSN(vfmadd_vf, mvf),
      INSN(vfnmadd_vv, mvv),
      INSN(vfnmadd_vf, mvf),
      INSN(vfmsub_vv, mvv),
      INSN(vfmsub_vf, mvf),
      INSN(vfnmsub_vv, mvv),
      INSN(vfnmsub_vf, mvf),
      INSN(vfmacc_vv, mvv),
      INSN(vfmacc_vf, mvf),
      INSN(vfnmacc_vv, mvv),
      INSN(vfnmacc_vf, mvf),
      INSN(vfmsac_vv, mvv),
      INSN(vfmsac_vf, mvf),
      INSN(vfnmsac_vv, mvv),
      INSN(vfnmsac_vf, mvf),

      //0b11_0000
      INSN(vfwadd_vv, vv),
      INSN(vfwadd_vf, vf),
      INSN(vfwredusum_vs, vv),
      INSN(vfwsub_vv, vv),
      INSN(vfwsub_vf, vf),
      INSN(vfwredosum_vs, vv),
      INSN(vfwadd_wv, vv),
      INSN(vfwadd_wf, vf),
      INSN(vfwsub_wv, vv),
      INSN(vfwsub_wf, vf),
      INSN(vfwmul_vv, vv),
      INSN(vfwmul_vf, vf),
      INSN(vfwmacc_vv, mvv),
      INSN(vfwmacc_vf, mvf),
      INSN(vfwnmacc_vv, mvv),
      INSN(vfwnmacc_vf, mvf),
      INSN(vfwmsac_vv, mvv),
      INSN(vfwmsac_vf, mvf),
      INSN(vfwnmsac_vv, mvv),
      INSN(vfwnmsac_vf, mvf),
    });
  }

  if (ext_enabled(EXT_ZVFOFP4MIN)) add({
    INSN(vfext_vf2, v),
  });

  if (ext_enabled(EXT_ZVFOFP8MIN)) add({
    INSN(vfncvt_f_f_q, v),
    INSN(vfncvt_sat_f_f_q, v),
    INSN(vfncvtbf16_sat_f_f_w, v),
  });

  if (ext_enabled(EXT_ZVFBFMIN)) add({
    INSN(vfncvtbf16_f_f_w, v),
    INSN(vfwcvtbf16_f_f_v, v),
  });

  if (ext_enabled(EXT_ZVFBFWMA)) add({
    INSN(vfwmaccbf16_vv, vv),
    INSN(vfwmaccbf16_vf, vf),
  });

  if (ext_enabled(EXT_ZMMUL)) {
    add({
      INSN(mul, "rd,rs1,rs2"),
      INSN(mulh, "rd,rs1,rs2"),
      INSN(mulhu, "rd,rs1,rs2"),
      INSN(mulhsu, "rd,rs1,rs2"),
    });

    if (xlen_eq(64)) add({
      INSN(mulw, "rd,rs1,rs2"),
    });
  }

  if (ext_enabled(EXT_ZICBOM)) add({
    INSN(cbo_clean, "(rs1)"),
    INSN(cbo_flush, "(rs1)"),
    INSN(cbo_inval, "(rs1)"),
  });

  if (ext_enabled(EXT_ZICBOZ)) add({
    INSN(cbo_zero, "(rs1)"),
  });

  if (ext_enabled(EXT_ZICOND)) add({
    INSN(czero_eqz, "rd,rs1,rs2"),
    INSN(czero_nez, "rd,rs1,rs2"),
  });

  if (ext_enabled(EXT_ZIMOP)) {
    add({
      INSN(mop_r_0, "rd,rs1"),
      INSN(mop_r_1, "rd,rs1"),
      INSN(mop_r_2, "rd,rs1"),
      INSN(mop_r_3, "rd,rs1"),
      INSN(mop_r_4, "rd,rs1"),
      INSN(mop_r_5, "rd,rs1"),
      INSN(mop_r_6, "rd,rs1"),
      INSN(mop_r_7, "rd,rs1"),
      INSN(mop_r_8, "rd,rs1"),
      INSN(mop_r_9, "rd,rs1"),
      INSN(mop_r_10, "rd,rs1"),
      INSN(mop_r_11, "rd,rs1"),
      INSN(mop_r_12, "rd,rs1"),
      INSN(mop_r_13, "rd,rs1"),
      INSN(mop_r_14, "rd,rs1"),
      INSN(mop_r_15, "rd,rs1"),
      INSN(mop_r_16, "rd,rs1"),
      INSN(mop_r_17, "rd,rs1"),
      INSN(mop_r_18, "rd,rs1"),
      INSN(mop_r_19, "rd,rs1"),
      INSN(mop_r_20, "rd,rs1"),
      INSN(mop_r_21, "rd,rs1"),
      INSN(mop_r_22, "rd,rs1"),
      INSN(mop_r_23, "rd,rs1"),
      INSN(mop_r_24, "rd,rs1"),
      INSN(mop_r_25, "rd,rs1"),
      INSN(mop_r_26, "rd,rs1"),
      INSN(mop_r_27, "rd,rs1"),
    });
    if (!ext_enabled_strict(EXT_ZICFISS)) {
      add({INSN(mop_r_28, "rd,rs1")});
    } else {
      // Add code points of mop_r_28 not used by Zicfiss
      const auto r1 = parse_format("rd,rs1");
      for (unsigned rd_val = 0; rd_val <= 31; ++rd_val)
        for (unsigned rs1_val = 0; rs1_val <= 31; ++rs1_val)
          if ((rd_val != 0 && rs1_val !=0) || (rd_val == 0 && !(rs1_val == 1 || rs1_val == 5)))
            add_insn(new disasm_insn_t("mop.r.28", match_mop_r_28 | (rs1_val << 15) | (rd_val << 7), 0xffffffff, r1));
    }
    add({
      INSN(mop_r_29, "rd,rs1"),
      INSN(mop_r_30, "rd,rs1"),
      INSN(mop_r_31, "rd,rs1"),
      INSN(mop_rr_0, "rd,rs1,rs2"),
      INSN(mop_rr_1, "rd,rs1,rs2"),
      INSN(mop_rr_2, "rd,rs1,rs2"),
      INSN(mop_rr_3, "rd,rs1,rs2"),
      INSN(mop_rr_4, "rd,rs1,rs2"),
      INSN(mop_rr_5, "rd,rs1,rs2"),
      INSN(mop_rr_6, "rd,rs1,rs2"),
    });
    if (!ext_enabled_strict(EXT_ZICFISS)) {
      add({INSN(mop_rr_7, "rd,rs1,rs2")});
    } else {
      // Add code points of mop_rr_7 not used by Zicfiss
      const auto rr = parse_format("rd,rs1,rs2");
      for (unsigned rd_val = 0; rd_val <= 31; ++rd_val)
        for (unsigned rs1_val = 0; rs1_val <= 31; ++rs1_val)
          for (unsigned rs2_val = 0; rs2_val <= 31; ++rs2_val)
            if ((rs2_val != 1 && rs2_val != 5) || rd_val != 0 || rs1_val != 0)
              add_insn(new disasm_insn_t("mop.rr.7", match_mop_rr_7 | (rs1_val << 15) | (rd_val << 7) | (rs2_val << 20), 0xffffffff, rr));
    }
  }

  if (ext_enabled(EXT_ZCMOP)) {
    // c.mop.1 and c.mop.5 are c.sspush/c.sspopchk under Zicfiss
    if (!ext_enabled_strict(EXT_ZICFISS))
      add({INSN(c_mop_1, "")});
    add({INSN(c_mop_3, "")});
    if (!ext_enabled_strict(EXT_ZICFISS))
      add({INSN(c_mop_5, "")});
    add({
      INSN(c_mop_7, ""),
      INSN(c_mop_9, ""),
      INSN(c_mop_11, ""),
      INSN(c_mop_13, ""),
      INSN(c_mop_15, ""),
    });
  }

  if (ext_enabled(EXT_ZKND) || ext_enabled(EXT_ZKNE)) add({
    INSN(aes64ks1i, "rd,rs1,rcon"),
    INSN(aes64ks2, "rd,rs1,rs2"),
  });

  if (ext_enabled(EXT_ZKND)) {
    if (xlen_eq(64)) add({
      INSN(aes64ds, "rd,rs1,rs2"),
      INSN(aes64dsm, "rd,rs1,rs2"),
      INSN(aes64im, "rd,rs1"),
    });

    if (xlen_eq(32)) add({
      INSN(aes32dsi, "rd,rs1,rs2,bs"),
      INSN(aes32dsmi, "rd,rs1,rs2,bs"),
    });
  }

  if (ext_enabled(EXT_ZKNE)) {
    if (xlen_eq(64)) add({
      INSN(aes64es, "rd,rs1,rs2"),
      INSN(aes64esm, "rd,rs1,rs2"),
    });

    if (xlen_eq(32)) add({
      INSN(aes32esi, "rd,rs1,rs2,bs"),
      INSN(aes32esmi, "rd,rs1,rs2,bs"),
    });
  }

  if (ext_enabled(EXT_ZKNH)) {
    add({
      INSN(sha256sig0, "rd,rs1"),
      INSN(sha256sig1, "rd,rs1"),
      INSN(sha256sum0, "rd,rs1"),
      INSN(sha256sum1, "rd,rs1"),
    });

    if (xlen_eq(64)) add({
      INSN(sha512sig0, "rd,rs1"),
      INSN(sha512sig1, "rd,rs1"),
      INSN(sha512sum0, "rd,rs1"),
      INSN(sha512sum1, "rd,rs1"),
    });

    if (xlen_eq(32)) add({
      INSN(sha512sig0h, "rd,rs1,rs2"),
      INSN(sha512sig0l, "rd,rs1,rs2"),
      INSN(sha512sig1h, "rd,rs1,rs2"),
      INSN(sha512sig1l, "rd,rs1,rs2"),
      INSN(sha512sum0r, "rd,rs1,rs2"),
      INSN(sha512sum1r, "rd,rs1,rs2"),
    });
  }

  if (ext_enabled(EXT_ZKSED)) add({
    INSN(sm4ed, "rd,rs1,rs2,bs"),
    INSN(sm4ks, "rd,rs1,rs2,bs"),
  });

  if (ext_enabled(EXT_ZKSH)) add({
    INSN(sm3p0, "rd,rs1"),
    INSN(sm3p1, "rd,rs1"),
  });

  if (ext_enabled(EXT_ZVABD)) add({
    INSN(vabd_vv, vv),
    INSN(vabd_vx, vx),
    INSN(vabdu_vv, vv),
    INSN(vabdu_vx, vx),
    INSN(vwabda_vv, vv),
    INSN(vwabda_vx, vx),
    INSN(vwabdau_vv, vv),
    INSN(vwabdau_vx, vx),
  });

  if (ext_enabled(EXT_ZVZIP)) add({
    INSN(vzip_vv, vv),
    INSN(vunzipe_v, v),
    INSN(vunzipo_v, v),
    INSN(vpaire_vv, vv),
    INSN(vpairo_vv, vv),
  });

  if (ext_enabled(EXT_ZVBB)) {
    add({
      INSN(vandn_vv, vv),
      INSN(vandn_vx, vx),
      INSN(vbrev_v, v),
      INSN(vbrev8_v, v),
      INSN(vrev8_v, v),
      INSN(vclz_v, v),
      INSN(vctz_v, v),
      INSN(vcpop_v, v),
      INSN(vrol_vv, vv),
      INSN(vrol_vx, vx),
      INSN(vror_vv, vv),
      INSN(vror_vx, vx),
      INSN(vror_vi, "vd,vs2,v_zimm6,vm"),
      INSN(vwsll_vv, vv),
      INSN(vwsll_vx, vx),
      INSN(vwsll_vi, viu),
    });
  }

  if (ext_enabled(EXT_ZVBC)) add({
    INSN(vclmul_vv, vv),
    INSN(vclmul_vx, vx),
    INSN(vclmulh_vv, vv),
    INSN(vclmulh_vx, vx),
  });

  if (ext_enabled(EXT_ZVKG)) add({
    // Despite its suffix, the vgmul.vv instruction
    // is really ".v", with the form "vgmul.vv vd, vs2".
    INSN(vgmul_vv, v),
    INSN(vghsh_vv, vv),
  });

  if (ext_enabled(EXT_ZVKNED)) add({
    // Despite their suffixes, the vaes*.{vv,vs} instructions
    // are really ".v", with the form "<op>.{vv,vs} vd, vs2".
    INSN(vaesdm_vv, v),
    INSN(vaesdm_vs, v),
    INSN(vaesdf_vv, v),
    INSN(vaesdf_vs, v),
    INSN(vaesem_vv, v),
    INSN(vaesem_vs, v),
    INSN(vaesef_vv, v),
    INSN(vaesef_vs, v),

    INSN(vaesz_vs, v),
    INSN(vaeskf1_vi, viu),
    INSN(vaeskf2_vi, viu),
  });

  if (ext_enabled(EXT_ZVKNHA) || ext_enabled(EXT_ZVKNHB)) add({
    INSN(vsha2ms_vv, vv),
    INSN(vsha2ch_vv, vv),
    INSN(vsha2cl_vv, vv),
  });

  if (ext_enabled(EXT_ZVKSED)) add({
    INSN(vsm4k_vi, viu),
    // Despite their suffixes, the vsm4r.{vv,vs} instructions
    // are really ".v", with the form "vsm4r.{vv,vs} vd, vs2".
    INSN(vsm4r_vv, v),
    INSN(vsm4r_vs, v),
  });

  if (ext_enabled(EXT_ZVKSH)) add({
    INSN(vsm3c_vi, viu),
    INSN(vsm3me_vv, vv),
  });

  if (ext_enabled(EXT_ZALASR)) add({
    INSN(lb_aq, "rd,(rs1)"),
    INSN(lh_aq, "rd,(rs1)"),
    INSN(lw_aq, "rd,(rs1)"),
    INSN(ld_aq, "rd,(rs1)"),
    INSN(sb_rl, "rs2,(rs1)"),
    INSN(sh_rl, "rs2,(rs1)"),
    INSN(sw_rl, "rs2,(rs1)"),
    INSN(sd_rl, "rs2,(rs1)"),
  });

  if (ext_enabled(EXT_ZICFISS)) {
    add({
      ALIAS("sspush", sspush_x1, 0, "rs2"),
      ALIAS("sspush", sspush_x5, 0, "rs2"),
      ALIAS("sspopchk", sspopchk_x1, 0, "rs1"),
      ALIAS("sspopchk", sspopchk_x5, 0, "rs1"),
      INSN(ssrdp, "rd"),
      AMO(ssamoswap_w),
    });

    if (xlen_eq(64)) add({
      AMO(ssamoswap_d),
    });

    if (ext_enabled(EXT_ZCA)) add({
      ALIAS("c.sspush", c_sspush_x1, 0, "rvc_ra"),
      ALIAS("c.sspopchk", c_sspopchk_x5, 0, "rvc_t0"),
    });
  }

  // P-extension (Packed SIMD) instructions
  if (ext_enabled('P')) {
    // R-type instructions (rd, rs1, rs2) - RV32 only (share opcode with RV64 packed-word)
    if (xlen_eq(32)) add({
      INSN(aadd, "rd,rs1,rs2"),
      INSN(aaddu, "rd,rs1,rs2"),
      INSN(asub, "rd,rs1,rs2"),
      INSN(asubu, "rd,rs1,rs2"),
      INSN(mseq, "rd,rs1,rs2"),
      INSN(mslt, "rd,rs1,rs2"),
      INSN(msltu, "rd,rs1,rs2"),
    });
    // RV32/RV64 common instructions
    add({
      INSN(addd, "rdp,rs1p,rs2p"),
      INSN(subd, "rdp,rs1p,rs2p"),
      INSN(merge, "rd,rs1,rs2"),
      INSN(mvm, "rd,rs1,rs2"),
      INSN(mvmn, "rd,rs1,rs2"),
      // Type 2: rs1p - Narrowing instructions (rd normal, rs1p is pair, rs2 normal/scalar)
      INSN(nclip, "rd,rs1p,rs2"),
      INSN(nclipr, "rd,rs1p,rs2"),
      INSN(nclipu, "rd,rs1p,rs2"),
      INSN(nclipru, "rd,rs1p,rs2"),
      INSN(nsra, "rd,rs1p,rs2"),
      INSN(nsrar, "rd,rs1p,rs2"),
      INSN(nsrl, "rd,rs1p,rs2"),
    });
    // RV32-only instructions (share opcode with RV64 packed-word)
    if (xlen_eq(32)) add({
      INSN(sadd, "rd,rs1,rs2"),
      INSN(saddu, "rd,rs1,rs2"),
      INSN(ssub, "rd,rs1,rs2"),
      INSN(ssubu, "rd,rs1,rs2"),
      INSN(ssh1sadd, "rd,rs1,rs2"),
      INSN(ssha, "rd,rs1,rs2"),
      INSN(sshar, "rd,rs1,rs2"),
      INSN(sshl, "rd,rs1,rs2"),
      INSN(sshlr, "rd,rs1,rs2"),
    });
    add({
      INSN(sha, "rdp,rs1p,rs2p"),
      INSN(shar, "rdp,rs1p,rs2p"),
      INSN(slx, "rd,rs1,rs2"),
      INSN(srx, "rd,rs1,rs2"),
      // Type 1: rdp - Widening instructions (rdp is pair, rs1/rs2 normal)
      INSN(wadd, "rdp,rs1,rs2"),
      INSN(wadda, "rdp,rs1,rs2"),
      INSN(waddu, "rdp,rs1,rs2"),
      INSN(waddau, "rdp,rs1,rs2"),
      INSN(wsub, "rdp,rs1,rs2"),
      INSN(wsuba, "rdp,rs1,rs2"),
      INSN(wsubu, "rdp,rs1,rs2"),
      INSN(wsubau, "rdp,rs1,rs2"),
      INSN(wsll, "rdp,rs1,rs2"),
      INSN(wsla, "rdp,rs1,rs2"),
      INSN(wmul, "rdp,rs1,rs2"),
      INSN(wmulu, "rdp,rs1,rs2"),
      INSN(wmulsu, "rdp,rs1,rs2"),
      INSN(wmacc, "rdp,rs1,rs2"),
      INSN(wmaccu, "rdp,rs1,rs2"),
      INSN(wmaccsu, "rdp,rs1,rs2"),
    });

    // R-type mac/mul instructions with element selection (RV32 only - share opcode with RV64 packed-word)
    if (xlen_eq(32)) add({
      INSN(macc_h00, "rd,rs1,rs2"),
      INSN(macc_h01, "rd,rs1,rs2"),
      INSN(macc_h11, "rd,rs1,rs2"),
      INSN(maccu_h00, "rd,rs1,rs2"),
      INSN(maccu_h01, "rd,rs1,rs2"),
      INSN(maccu_h11, "rd,rs1,rs2"),
      INSN(maccsu_h00, "rd,rs1,rs2"),
      INSN(maccsu_h11, "rd,rs1,rs2"),
      INSN(mul_h00, "rd,rs1,rs2"),
      INSN(mul_h01, "rd,rs1,rs2"),
      INSN(mul_h11, "rd,rs1,rs2"),
      INSN(mulu_h00, "rd,rs1,rs2"),
      INSN(mulu_h01, "rd,rs1,rs2"),
      INSN(mulu_h11, "rd,rs1,rs2"),
      INSN(mulsu_h00, "rd,rs1,rs2"),
      INSN(mulsu_h11, "rd,rs1,rs2"),
      INSN(mulh_h0, "rd,rs1,rs2"),
      INSN(mulh_h1, "rd,rs1,rs2"),
      INSN(mulhsu_h0, "rd,rs1,rs2"),
      INSN(mulhsu_h1, "rd,rs1,rs2"),
      INSN(mulhr, "rd,rs1,rs2"),
      INSN(mulhru, "rd,rs1,rs2"),
      INSN(mulhrsu, "rd,rs1,rs2"),
      INSN(mulq, "rd,rs1,rs2"),
      INSN(mulqr, "rd,rs1,rs2"),
      INSN(mhacc, "rd,rs1,rs2"),
      INSN(mhaccu, "rd,rs1,rs2"),
      INSN(mhaccsu, "rd,rs1,rs2"),
      INSN(mhacc_h0, "rd,rs1,rs2"),
      INSN(mhacc_h1, "rd,rs1,rs2"),
      INSN(mhaccsu_h0, "rd,rs1,rs2"),
      INSN(mhaccsu_h1, "rd,rs1,rs2"),
      INSN(mhracc, "rd,rs1,rs2"),
      INSN(mhraccu, "rd,rs1,rs2"),
      INSN(mhraccsu, "rd,rs1,rs2"),
    });
    add({
      INSN(mqacc_h00, "rd,rs1,rs2"),
      INSN(mqacc_h01, "rd,rs1,rs2"),
      INSN(mqacc_h11, "rd,rs1,rs2"),
      INSN(mqracc_h00, "rd,rs1,rs2"),
      INSN(mqracc_h01, "rd,rs1,rs2"),
      INSN(mqracc_h11, "rd,rs1,rs2"),

      // R1-type instructions (rd, rs1) - unary ops
      INSN(abs, "rd,rs1"),
      INSN(cls, "rd,rs1"),

      // I-type shift instructions (rd, rs1, shamt)
      INSN(nclipi, "rd,rs1,shamtd"),
      INSN(nclipiu, "rd,rs1,shamtd"),
      INSN(nclipri, "rd,rs1,shamtd"),
      INSN(nclipriu, "rd,rs1,shamtd"),
      INSN(nsrai, "rd,rs1,shamtd"),
      INSN(nsrari, "rd,rs1,shamtd"),
      INSN(nsrli, "rd,rs1,shamtd"),
    });
    // sslai shares opcode with psslai_w on RV64
    if (xlen_eq(32)) add({
      INSN(sslai, "rd,rs1,shamt"),
    });
    add({
      INSN(wslli, "rd,rs1,shamt"),
      INSN(wslai, "rd,rs1,shamt"),
    });
    if (xlen_eq(64)) {
      add({
        INSN(sati, "rd,rs1,shamt"),
        INSN(usati, "rd,rs1,shamt"),
        INSN(srari, "rd,rs1,shamt"),
      });
    } else {
      add({
        ALIAS("sati", sati_rv32, 0, "rd,rs1,shamt"),
        ALIAS("usati", usati_rv32, 0, "rd,rs1,shamt"),
        ALIAS("srari", srari_rv32, 0, "rd,rs1,shamt"),
      });
    }

    // Packed R-type instructions (rd, rs1, rs2) - RV32/RV64 common
    add({
      INSN(paadd_b, "rd,rs1,rs2"),
      INSN(paadd_h, "rd,rs1,rs2"),
      // Type 4: rdp + rs1p + rs2p - Doubleword pair-to-pair ops
      INSN(paadd_db, "rdp,rs1p,rs2p"),
      INSN(paadd_dh, "rdp,rs1p,rs2p"),
      INSN(paadd_dw, "rdp,rs1p,rs2p"),
      INSN(paaddu_b, "rd,rs1,rs2"),
      INSN(paaddu_h, "rd,rs1,rs2"),
      INSN(paaddu_db, "rdp,rs1p,rs2p"),
      INSN(paaddu_dh, "rdp,rs1p,rs2p"),
      INSN(paaddu_dw, "rdp,rs1p,rs2p"),
      INSN(paas_hx, "rd,rs1,rs2"),
      INSN(paas_dhx, "rdp,rs1p,rs2p"),
      INSN(pabd_b, "rd,rs1,rs2"),
      INSN(pabd_h, "rd,rs1,rs2"),
      INSN(pabd_db, "rdp,rs1p,rs2p"),
      INSN(pabd_dh, "rdp,rs1p,rs2p"),
      INSN(pabdu_b, "rd,rs1,rs2"),
      INSN(pabdu_h, "rd,rs1,rs2"),
      INSN(pabdu_db, "rdp,rs1p,rs2p"),
      INSN(pabdu_dh, "rdp,rs1p,rs2p"),
      INSN(pabdsumu_b, "rd,rs1,rs2"),
      INSN(pabdsumau_b, "rd,rs1,rs2"),
      INSN(padd_b, "rd,rs1,rs2"),
      INSN(padd_h, "rd,rs1,rs2"),
      INSN(padd_bs, "rd,rs1,rs2"),
      INSN(padd_hs, "rd,rs1,rs2"),
      INSN(padd_db, "rdp,rs1p,rs2p"),
      INSN(padd_dh, "rdp,rs1p,rs2p"),
      INSN(padd_dw, "rdp,rs1p,rs2p"),
      // Type 3: rdp + rs1p - Doubleword with scalar rs2
      INSN(padd_dbs, "rdp,rs1p,rs2"),
      INSN(padd_dhs, "rdp,rs1p,rs2"),
      INSN(padd_dws, "rdp,rs1p,rs2"),
      INSN(pasub_b, "rd,rs1,rs2"),
      INSN(pasub_h, "rd,rs1,rs2"),
      INSN(pasub_db, "rdp,rs1p,rs2p"),
      INSN(pasub_dh, "rdp,rs1p,rs2p"),
      INSN(pasub_dw, "rdp,rs1p,rs2p"),
      INSN(pasubu_b, "rd,rs1,rs2"),
      INSN(pasubu_h, "rd,rs1,rs2"),
      INSN(pasubu_db, "rdp,rs1p,rs2p"),
      INSN(pasubu_dh, "rdp,rs1p,rs2p"),
      INSN(pasubu_dw, "rdp,rs1p,rs2p"),
      INSN(pasa_hx, "rd,rs1,rs2"),
      INSN(pasa_dhx, "rdp,rs1p,rs2p"),
      INSN(pas_hx, "rd,rs1,rs2"),
      INSN(pas_dhx, "rdp,rs1p,rs2p"),
      INSN(psadd_b, "rd,rs1,rs2"),
      INSN(psadd_h, "rd,rs1,rs2"),
      INSN(psadd_db, "rdp,rs1p,rs2p"),
      INSN(psadd_dh, "rdp,rs1p,rs2p"),
      INSN(psadd_dw, "rdp,rs1p,rs2p"),
      INSN(psaddu_b, "rd,rs1,rs2"),
      INSN(psaddu_h, "rd,rs1,rs2"),
      INSN(psaddu_db, "rdp,rs1p,rs2p"),
      INSN(psaddu_dh, "rdp,rs1p,rs2p"),
      INSN(psaddu_dw, "rdp,rs1p,rs2p"),
      INSN(psub_b, "rd,rs1,rs2"),
      INSN(psub_h, "rd,rs1,rs2"),
      INSN(psub_db, "rdp,rs1p,rs2p"),
      INSN(psub_dh, "rdp,rs1p,rs2p"),
      INSN(psub_dw, "rdp,rs1p,rs2p"),
      INSN(pssub_b, "rd,rs1,rs2"),
      INSN(pssub_h, "rd,rs1,rs2"),
      INSN(pssub_db, "rdp,rs1p,rs2p"),
      INSN(pssub_dh, "rdp,rs1p,rs2p"),
      INSN(pssub_dw, "rdp,rs1p,rs2p"),
      INSN(pssubu_b, "rd,rs1,rs2"),
      INSN(pssubu_h, "rd,rs1,rs2"),
      INSN(pssubu_db, "rdp,rs1p,rs2p"),
      INSN(pssubu_dh, "rdp,rs1p,rs2p"),
      INSN(pssubu_dw, "rdp,rs1p,rs2p"),
      INSN(psa_hx, "rd,rs1,rs2"),
      INSN(psa_dhx, "rdp,rs1p,rs2p"),
      INSN(psas_hx, "rd,rs1,rs2"),
      INSN(psas_dhx, "rdp,rs1p,rs2p"),
      INSN(pssa_hx, "rd,rs1,rs2"),
      INSN(pssa_dhx, "rdp,rs1p,rs2p"),
      INSN(pmax_b, "rd,rs1,rs2"),
      INSN(pmax_h, "rd,rs1,rs2"),
      INSN(pmax_db, "rdp,rs1p,rs2p"),
      INSN(pmax_dh, "rdp,rs1p,rs2p"),
      INSN(pmax_dw, "rdp,rs1p,rs2p"),
      INSN(pmaxu_b, "rd,rs1,rs2"),
      INSN(pmaxu_h, "rd,rs1,rs2"),
      INSN(pmaxu_db, "rdp,rs1p,rs2p"),
      INSN(pmaxu_dh, "rdp,rs1p,rs2p"),
      INSN(pmaxu_dw, "rdp,rs1p,rs2p"),
      INSN(pmin_b, "rd,rs1,rs2"),
      INSN(pmin_h, "rd,rs1,rs2"),
      INSN(pmin_db, "rdp,rs1p,rs2p"),
      INSN(pmin_dh, "rdp,rs1p,rs2p"),
      INSN(pmin_dw, "rdp,rs1p,rs2p"),
      INSN(pminu_b, "rd,rs1,rs2"),
      INSN(pminu_h, "rd,rs1,rs2"),
      INSN(pminu_db, "rdp,rs1p,rs2p"),
      INSN(pminu_dh, "rdp,rs1p,rs2p"),
      INSN(pminu_dw, "rdp,rs1p,rs2p"),
      INSN(pmseq_b, "rd,rs1,rs2"),
      INSN(pmseq_h, "rd,rs1,rs2"),
      INSN(pmseq_db, "rdp,rs1p,rs2p"),
      INSN(pmseq_dh, "rdp,rs1p,rs2p"),
      INSN(pmseq_dw, "rdp,rs1p,rs2p"),
      INSN(pmslt_b, "rd,rs1,rs2"),
      INSN(pmslt_h, "rd,rs1,rs2"),
      INSN(pmslt_db, "rdp,rs1p,rs2p"),
      INSN(pmslt_dh, "rdp,rs1p,rs2p"),
      INSN(pmslt_dw, "rdp,rs1p,rs2p"),
      INSN(pmsltu_b, "rd,rs1,rs2"),
      INSN(pmsltu_h, "rd,rs1,rs2"),
      INSN(pmsltu_db, "rdp,rs1p,rs2p"),
      INSN(pmsltu_dh, "rdp,rs1p,rs2p"),
      INSN(pmsltu_dw, "rdp,rs1p,rs2p"),
      INSN(psll_bs, "rd,rs1,rs2"),
      INSN(psll_hs, "rd,rs1,rs2"),
      // Type 3: rdp + rs1p - Doubleword shift with scalar rs2
      INSN(psll_dbs, "rdp,rs1p,rs2"),
      INSN(psll_dhs, "rdp,rs1p,rs2"),
      INSN(psll_dws, "rdp,rs1p,rs2"),
      INSN(psra_bs, "rd,rs1,rs2"),
      INSN(psra_hs, "rd,rs1,rs2"),
      INSN(psra_dbs, "rdp,rs1p,rs2"),
      INSN(psra_dhs, "rdp,rs1p,rs2"),
      INSN(psra_dws, "rdp,rs1p,rs2"),
      INSN(psrl_bs, "rd,rs1,rs2"),
      INSN(psrl_hs, "rd,rs1,rs2"),
      INSN(psrl_dbs, "rdp,rs1p,rs2"),
      INSN(psrl_dhs, "rdp,rs1p,rs2"),
      INSN(psrl_dws, "rdp,rs1p,rs2"),
      INSN(pssha_hs, "rd,rs1,rs2"),
      INSN(pssha_dhs, "rdp,rs1p,rs2"),
      INSN(pssha_dws, "rdp,rs1p,rs2"),
      INSN(psshar_hs, "rd,rs1,rs2"),
      INSN(psshar_dhs, "rdp,rs1p,rs2"),
      INSN(psshar_dws, "rdp,rs1p,rs2"),
      INSN(psshl_hs, "rd,rs1,rs2"),
      INSN(psshl_dhs, "rdp,rs1p,rs2"),
      INSN(psshl_dws, "rdp,rs1p,rs2"),
      INSN(psshlr_hs, "rd,rs1,rs2"),
      INSN(psshlr_dhs, "rdp,rs1p,rs2"),
      INSN(psshlr_dws, "rdp,rs1p,rs2"),
      INSN(psh1add_h, "rd,rs1,rs2"),
      INSN(psh1add_dh, "rdp,rs1p,rs2p"),
      INSN(psh1add_dw, "rdp,rs1p,rs2p"),
      INSN(pssh1sadd_h, "rd,rs1,rs2"),
      INSN(pssh1sadd_dh, "rdp,rs1p,rs2p"),
      INSN(pssh1sadd_dw, "rdp,rs1p,rs2p"),
      // Type 2: rs1p - Narrowing with scalar rs2
      INSN(pnclip_bs, "rd,rs1p,rs2"),
      INSN(pnclip_hs, "rd,rs1p,rs2"),
      INSN(pnclipr_bs, "rd,rs1p,rs2"),
      INSN(pnclipr_hs, "rd,rs1p,rs2"),
      INSN(pnclipu_bs, "rd,rs1p,rs2"),
      INSN(pnclipu_hs, "rd,rs1p,rs2"),
      INSN(pnclipru_bs, "rd,rs1p,rs2"),
      INSN(pnclipru_hs, "rd,rs1p,rs2"),
      INSN(pnsra_bs, "rd,rs1p,rs2"),
      INSN(pnsra_hs, "rd,rs1p,rs2"),
      INSN(pnsrar_bs, "rd,rs1p,rs2"),
      INSN(pnsrar_hs, "rd,rs1p,rs2"),
      INSN(pnsrl_bs, "rd,rs1p,rs2"),
      INSN(pnsrl_hs, "rd,rs1p,rs2"),
      // Type 1: rdp - Widening with scalar rs2
      INSN(pwsll_bs, "rdp,rs1,rs2"),
      INSN(pwsll_hs, "rdp,rs1,rs2"),
      INSN(pwsla_bs, "rdp,rs1,rs2"),
      INSN(pwsla_hs, "rdp,rs1,rs2"),
      INSN(ppaire_b, "rd,rs1,rs2"),
      INSN(ppaire_h, "rd,rs1,rs2"),
      INSN(ppaire_db, "rdp,rs1p,rs2p"),
      INSN(ppaire_dh, "rdp,rs1p,rs2p"),
      INSN(ppaireo_b, "rd,rs1,rs2"),
      INSN(ppaireo_h, "rd,rs1,rs2"),
      INSN(ppaireo_db, "rdp,rs1p,rs2p"),
      INSN(ppaireo_dh, "rdp,rs1p,rs2p"),
      INSN(ppairo_b, "rd,rs1,rs2"),
      INSN(ppairo_h, "rd,rs1,rs2"),
      INSN(ppairo_db, "rdp,rs1p,rs2p"),
      INSN(ppairo_dh, "rdp,rs1p,rs2p"),
      INSN(ppairoe_b, "rd,rs1,rs2"),
      INSN(ppairoe_h, "rd,rs1,rs2"),
      INSN(ppairoe_db, "rdp,rs1p,rs2p"),
      INSN(ppairoe_dh, "rdp,rs1p,rs2p"),
      INSN(predsum_bs, "rd,rs1,rs2"),
      INSN(predsum_hs, "rd,rs1,rs2"),
      // Type 2: rs1p - Reduction sum (rd normal, rs1p is pair)
      INSN(predsum_dbs, "rd,rs1p,rs2"),
      INSN(predsum_dhs, "rd,rs1p,rs2"),
      INSN(predsumu_bs, "rd,rs1,rs2"),
      INSN(predsumu_hs, "rd,rs1,rs2"),
      INSN(predsumu_dbs, "rd,rs1p,rs2"),
      INSN(predsumu_dhs, "rd,rs1p,rs2"),

      // Packed R1-type instructions (rd, rs1) - unary
      INSN(psabs_b, "rd,rs1"),
      INSN(psabs_h, "rd,rs1"),
      // Type 3: rdp + rs1p - Doubleword unary ops
      INSN(psabs_db, "rdp,rs1p"),
      INSN(psabs_dh, "rdp,rs1p"),
      INSN(psext_h_b, "rd,rs1"),
      INSN(psext_dh_b, "rdp,rs1p"),
      INSN(psext_dw_b, "rdp,rs1p"),
      INSN(psext_dw_h, "rdp,rs1p"),

      // Packed I-type with shamt
      INSN(pslli_b, "rd,rs1,shamtb"),
      INSN(pslli_h, "rd,rs1,shamth"),
      // Type 3: rdp + rs1p - Doubleword immediate shift
      INSN(pslli_db, "rdp,rs1p,shamtb"),
      INSN(pslli_dh, "rdp,rs1p,shamth"),
      INSN(pslli_dw, "rdp,rs1p,shamtw"),
      INSN(psrai_b, "rd,rs1,shamtb"),
      INSN(psrai_h, "rd,rs1,shamth"),
      INSN(psrai_db, "rdp,rs1p,shamtb"),
      INSN(psrai_dh, "rdp,rs1p,shamth"),
      INSN(psrai_dw, "rdp,rs1p,shamtw"),
      INSN(psrli_b, "rd,rs1,shamtb"),
      INSN(psrli_h, "rd,rs1,shamth"),
      INSN(psrli_db, "rdp,rs1p,shamtb"),
      INSN(psrli_dh, "rdp,rs1p,shamth"),
      INSN(psrli_dw, "rdp,rs1p,shamtw"),
      INSN(psrari_h, "rd,rs1,shamth"),
      INSN(psrari_dh, "rdp,rs1p,shamth"),
      INSN(psrari_dw, "rdp,rs1p,shamtw"),
      INSN(psati_h, "rd,rs1,shamth"),
      INSN(psati_dh, "rdp,rs1p,shamth"),
      INSN(psati_dw, "rdp,rs1p,shamtw"),
      INSN(pusati_h, "rd,rs1,shamth"),
      INSN(pusati_dh, "rdp,rs1p,shamth"),
      INSN(pusati_dw, "rdp,rs1p,shamtw"),
      INSN(psslai_h, "rd,rs1,shamth"),
      INSN(psslai_dh, "rdp,rs1p,shamth"),
      INSN(psslai_dw, "rdp,rs1p,shamtw"),
      // Type 2: rs1p - Narrowing immediate (rd normal, rs1p is pair)
      INSN(pnclipi_b, "rd,rs1p,shamth"),
      INSN(pnclipi_h, "rd,rs1p,shamtw"),
      INSN(pnclipiu_b, "rd,rs1p,shamth"),
      INSN(pnclipiu_h, "rd,rs1p,shamtw"),
      INSN(pnclipri_b, "rd,rs1p,shamth"),
      INSN(pnclipri_h, "rd,rs1p,shamtw"),
      INSN(pnclipriu_b, "rd,rs1p,shamth"),
      INSN(pnclipriu_h, "rd,rs1p,shamtw"),
      INSN(pnsrai_b, "rd,rs1p,shamth"),
      INSN(pnsrai_h, "rd,rs1p,shamtw"),
      INSN(pnsrari_b, "rd,rs1p,shamth"),
      INSN(pnsrari_h, "rd,rs1p,shamtw"),
      INSN(pnsrli_b, "rd,rs1p,shamth"),
      INSN(pnsrli_h, "rd,rs1p,shamtw"),
      // Type 1: rdp - Widening immediate (rdp is pair, rs1 normal)
      INSN(pwslli_b, "rdp,rs1,shamtb"),
      INSN(pwslli_h, "rdp,rs1,shamth"),
      INSN(pwslai_b, "rdp,rs1,shamtb"),
      INSN(pwslai_h, "rdp,rs1,shamth"),

      // Packed load-immediate instructions (rd, imm) - Type 1: rdp for _db, _dh
      INSN(pli_b, "rd,p_imm8"),
      INSN(pli_h, "rd,p_imm10csl"),
      INSN(pli_db, "rdp,p_imm8"),
      INSN(pli_dh, "rdp,p_imm10csl"),
      INSN(plui_h, "rd,p_imm10csr"),
      INSN(plui_dh, "rdp,p_imm10csr"),

      // Packed multiply/mac instructions
      INSN(pmul_h_b00, "rd,rs1,rs2"),
      INSN(pmul_h_b01, "rd,rs1,rs2"),
      INSN(pmul_h_b11, "rd,rs1,rs2"),
      INSN(pmulu_h_b00, "rd,rs1,rs2"),
      INSN(pmulu_h_b01, "rd,rs1,rs2"),
      INSN(pmulu_h_b11, "rd,rs1,rs2"),
      INSN(pmulsu_h_b00, "rd,rs1,rs2"),
      INSN(pmulsu_h_b11, "rd,rs1,rs2"),
      INSN(pmulh_h, "rd,rs1,rs2"),
      INSN(pmulhu_h, "rd,rs1,rs2"),
      INSN(pmulhsu_h, "rd,rs1,rs2"),
      INSN(pmulh_h_b0, "rd,rs1,rs2"),
      INSN(pmulh_h_b1, "rd,rs1,rs2"),
      INSN(pmulhsu_h_b0, "rd,rs1,rs2"),
      INSN(pmulhsu_h_b1, "rd,rs1,rs2"),
      INSN(pmulhr_h, "rd,rs1,rs2"),
      INSN(pmulhru_h, "rd,rs1,rs2"),
      INSN(pmulhrsu_h, "rd,rs1,rs2"),
      INSN(pmulq_h, "rd,rs1,rs2"),
      INSN(pmulqr_h, "rd,rs1,rs2"),
      INSN(pmhacc_h, "rd,rs1,rs2"),
      INSN(pmhaccu_h, "rd,rs1,rs2"),
      INSN(pmhaccsu_h, "rd,rs1,rs2"),
      INSN(pmhacc_h_b0, "rd,rs1,rs2"),
      INSN(pmhacc_h_b1, "rd,rs1,rs2"),
      INSN(pmhaccsu_h_b0, "rd,rs1,rs2"),
      INSN(pmhaccsu_h_b1, "rd,rs1,rs2"),
      INSN(pmhracc_h, "rd,rs1,rs2"),
      INSN(pmhraccu_h, "rd,rs1,rs2"),
      INSN(pmhraccsu_h, "rd,rs1,rs2"),
      INSN(pmq2add_h, "rd,rs1,rs2"),
      INSN(pmq2adda_h, "rd,rs1,rs2"),
      INSN(pmqr2add_h, "rd,rs1,rs2"),
      INSN(pmqr2adda_h, "rd,rs1,rs2"),

      // Packed widening instructions - Type 1: rdp (pair result, normal sources)
      INSN(pwadd_b, "rdp,rs1,rs2"),
      INSN(pwadd_h, "rdp,rs1,rs2"),
      INSN(pwaddu_b, "rdp,rs1,rs2"),
      INSN(pwaddu_h, "rdp,rs1,rs2"),
      INSN(pwadda_b, "rdp,rs1,rs2"),
      INSN(pwadda_h, "rdp,rs1,rs2"),
      INSN(pwaddau_b, "rdp,rs1,rs2"),
      INSN(pwaddau_h, "rdp,rs1,rs2"),
      INSN(pwsub_b, "rdp,rs1,rs2"),
      INSN(pwsub_h, "rdp,rs1,rs2"),
      INSN(pwsubu_b, "rdp,rs1,rs2"),
      INSN(pwsubu_h, "rdp,rs1,rs2"),
      INSN(pwsuba_b, "rdp,rs1,rs2"),
      INSN(pwsuba_h, "rdp,rs1,rs2"),
      INSN(pwsubau_b, "rdp,rs1,rs2"),
      INSN(pwsubau_h, "rdp,rs1,rs2"),
      INSN(pwmul_b, "rdp,rs1,rs2"),
      INSN(pwmul_h, "rdp,rs1,rs2"),
      INSN(pwmulu_b, "rdp,rs1,rs2"),
      INSN(pwmulu_h, "rdp,rs1,rs2"),
      INSN(pwmulsu_b, "rdp,rs1,rs2"),
      INSN(pwmulsu_h, "rdp,rs1,rs2"),
      INSN(pwmacc_h, "rdp,rs1,rs2"),
      INSN(pwmaccu_h, "rdp,rs1,rs2"),
      INSN(pwmaccsu_h, "rdp,rs1,rs2"),

      // Packed multi-add instructions
      INSN(pm2add_h, "rd,rs1,rs2"),
      INSN(pm2add_hx, "rd,rs1,rs2"),
      INSN(pm2addu_h, "rd,rs1,rs2"),
      INSN(pm2addsu_h, "rd,rs1,rs2"),
      INSN(pm2adda_h, "rd,rs1,rs2"),
      INSN(pm2adda_hx, "rd,rs1,rs2"),
      INSN(pm2addau_h, "rd,rs1,rs2"),
      INSN(pm2addasu_h, "rd,rs1,rs2"),
      INSN(pm2sub_h, "rd,rs1,rs2"),
      INSN(pm2sub_hx, "rd,rs1,rs2"),
      INSN(pm2suba_h, "rd,rs1,rs2"),
      INSN(pm2suba_hx, "rd,rs1,rs2"),
      INSN(pm2sadd_h, "rd,rs1,rs2"),
      INSN(pm2sadd_hx, "rd,rs1,rs2"),
      // pm2wadd produces widened result - Type 1: rdp
      INSN(pm2wadd_h, "rdp,rs1,rs2"),
      INSN(pm2wadd_hx, "rdp,rs1,rs2"),
      INSN(pm2waddu_h, "rdp,rs1,rs2"),
      INSN(pm2waddsu_h, "rdp,rs1,rs2"),
      INSN(pm2wadda_h, "rdp,rs1,rs2"),
      INSN(pm2wadda_hx, "rdp,rs1,rs2"),
      INSN(pm2waddau_h, "rdp,rs1,rs2"),
      INSN(pm2waddasu_h, "rdp,rs1,rs2"),
      INSN(pm2wsub_h, "rdp,rs1,rs2"),
      INSN(pm2wsub_hx, "rdp,rs1,rs2"),
      INSN(pm2wsuba_h, "rdp,rs1,rs2"),
      INSN(pm2wsuba_hx, "rdp,rs1,rs2"),
      INSN(pm4add_b, "rd,rs1,rs2"),
      INSN(pm4addu_b, "rd,rs1,rs2"),
      INSN(pm4addsu_b, "rd,rs1,rs2"),
      INSN(pm4adda_b, "rd,rs1,rs2"),
      INSN(pm4addau_b, "rd,rs1,rs2"),
      INSN(pm4addasu_b, "rd,rs1,rs2"),

      // Zip/Unzip instructions
      INSN(zip8p, "rd,rs1"),
      INSN(zip8hp, "rd,rs1"),
      INSN(unzip8p, "rd,rs1"),
      INSN(unzip8hp, "rd,rs1"),
      INSN(unzip16p, "rd,rs1"),
      INSN(unzip16hp, "rd,rs1"),
      // Type 1: rdp - Widening zip (pair result)
      INSN(wzip8p, "rdp,rs1"),
      INSN(wzip16p, "rdp,rs1"),

      // mqwacc instructions - Type 1: rdp (widened 64-bit result)
      INSN(mqwacc, "rdp,rs1,rs2"),
      INSN(mqrwacc, "rdp,rs1,rs2"),
      INSN(pmqwacc_h, "rdp,rs1,rs2"),
      INSN(pmqrwacc_h, "rdp,rs1,rs2"),
    });

    // RV64 P-extension instructions (word-sized operations)
    // These share opcodes with RV32 scalar instructions
    if (xlen_eq(64)) add({
      // R1-type unary instructions
      INSN(absw, "rd,rs1"),
      INSN(clsw, "rd,rs1"),

      // R-type scalar MAC/MUL instructions (word-sized)
      INSN(macc_w00, "rd,rs1,rs2"),
      INSN(macc_w01, "rd,rs1,rs2"),
      INSN(macc_w11, "rd,rs1,rs2"),
      INSN(maccu_w00, "rd,rs1,rs2"),
      INSN(maccu_w01, "rd,rs1,rs2"),
      INSN(maccu_w11, "rd,rs1,rs2"),
      INSN(maccsu_w00, "rd,rs1,rs2"),
      INSN(maccsu_w11, "rd,rs1,rs2"),
      INSN(mul_w00, "rd,rs1,rs2"),
      INSN(mul_w01, "rd,rs1,rs2"),
      INSN(mul_w11, "rd,rs1,rs2"),
      INSN(mulu_w00, "rd,rs1,rs2"),
      INSN(mulu_w01, "rd,rs1,rs2"),
      INSN(mulu_w11, "rd,rs1,rs2"),
      INSN(mulsu_w00, "rd,rs1,rs2"),
      INSN(mulsu_w11, "rd,rs1,rs2"),
      INSN(mqacc_w00, "rd,rs1,rs2"),
      INSN(mqacc_w01, "rd,rs1,rs2"),
      INSN(mqacc_w11, "rd,rs1,rs2"),
      INSN(mqracc_w00, "rd,rs1,rs2"),
      INSN(mqracc_w01, "rd,rs1,rs2"),
      INSN(mqracc_w11, "rd,rs1,rs2"),

      // R-type packed word-sized instructions (share opcode with RV32 scalar)
      INSN(paadd_w, "rd,rs1,rs2"),
      INSN(paaddu_w, "rd,rs1,rs2"),
      INSN(paas_wx, "rd,rs1,rs2"),
      INSN(padd_w, "rd,rs1,rs2"),
      INSN(padd_ws, "rd,rs1,rs2"),
      INSN(pasa_wx, "rd,rs1,rs2"),
      INSN(pasub_w, "rd,rs1,rs2"),
      INSN(pasubu_w, "rd,rs1,rs2"),
      INSN(pas_wx, "rd,rs1,rs2"),
      INSN(pmax_w, "rd,rs1,rs2"),
      INSN(pmaxu_w, "rd,rs1,rs2"),
      INSN(pmin_w, "rd,rs1,rs2"),
      INSN(pminu_w, "rd,rs1,rs2"),
      INSN(pmseq_w, "rd,rs1,rs2"),
      INSN(pmslt_w, "rd,rs1,rs2"),
      INSN(pmsltu_w, "rd,rs1,rs2"),
      INSN(psadd_w, "rd,rs1,rs2"),
      INSN(psaddu_w, "rd,rs1,rs2"),
      INSN(psa_wx, "rd,rs1,rs2"),
      INSN(psas_wx, "rd,rs1,rs2"),
      INSN(pssa_wx, "rd,rs1,rs2"),
      INSN(pssub_w, "rd,rs1,rs2"),
      INSN(pssubu_w, "rd,rs1,rs2"),
      INSN(psub_w, "rd,rs1,rs2"),
      INSN(psh1add_w, "rd,rs1,rs2"),
      INSN(pssh1sadd_w, "rd,rs1,rs2"),
      INSN(psll_ws, "rd,rs1,rs2"),
      INSN(psra_ws, "rd,rs1,rs2"),
      INSN(psrl_ws, "rd,rs1,rs2"),
      INSN(pssha_ws, "rd,rs1,rs2"),
      INSN(psshar_ws, "rd,rs1,rs2"),
      INSN(psshl_ws, "rd,rs1,rs2"),
      INSN(psshlr_ws, "rd,rs1,rs2"),
      INSN(shl, "rd,rs1,rs2"),
      INSN(shlr, "rd,rs1,rs2"),
      INSN(pnclipp_b, "rd,rs1,rs2"),
      INSN(pnclipp_h, "rd,rs1,rs2"),
      INSN(pnclipp_w, "rd,rs1,rs2"),
      INSN(pnclipup_b, "rd,rs1,rs2"),
      INSN(pnclipup_h, "rd,rs1,rs2"),
      INSN(pnclipup_w, "rd,rs1,rs2"),
      INSN(ppaireo_w, "rd,rs1,rs2"),
      INSN(ppairoe_w, "rd,rs1,rs2"),
      INSN(ppairo_w, "rd,rs1,rs2"),
      INSN(predsum_ws, "rd,rs1,rs2"),
      INSN(predsumu_ws, "rd,rs1,rs2"),

      // Packed multiply/mac word-sized instructions (share opcode with RV32 scalar)
      INSN(pmul_w_h00, "rd,rs1,rs2"),
      INSN(pmul_w_h01, "rd,rs1,rs2"),
      INSN(pmul_w_h11, "rd,rs1,rs2"),
      INSN(pmulu_w_h00, "rd,rs1,rs2"),
      INSN(pmulu_w_h01, "rd,rs1,rs2"),
      INSN(pmulu_w_h11, "rd,rs1,rs2"),
      INSN(pmulsu_w_h00, "rd,rs1,rs2"),
      INSN(pmulsu_w_h11, "rd,rs1,rs2"),
      INSN(pmulh_w, "rd,rs1,rs2"),
      INSN(pmulhu_w, "rd,rs1,rs2"),
      INSN(pmulhsu_w, "rd,rs1,rs2"),
      INSN(pmulh_w_h0, "rd,rs1,rs2"),
      INSN(pmulh_w_h1, "rd,rs1,rs2"),
      INSN(pmulhsu_w_h0, "rd,rs1,rs2"),
      INSN(pmulhsu_w_h1, "rd,rs1,rs2"),
      INSN(pmulhr_w, "rd,rs1,rs2"),
      INSN(pmulhru_w, "rd,rs1,rs2"),
      INSN(pmulhrsu_w, "rd,rs1,rs2"),
      INSN(pmulq_w, "rd,rs1,rs2"),
      INSN(pmulqr_w, "rd,rs1,rs2"),
      INSN(pmacc_w_h00, "rd,rs1,rs2"),
      INSN(pmacc_w_h01, "rd,rs1,rs2"),
      INSN(pmacc_w_h11, "rd,rs1,rs2"),
      INSN(pmaccu_w_h00, "rd,rs1,rs2"),
      INSN(pmaccu_w_h01, "rd,rs1,rs2"),
      INSN(pmaccu_w_h11, "rd,rs1,rs2"),
      INSN(pmaccsu_w_h00, "rd,rs1,rs2"),
      INSN(pmaccsu_w_h11, "rd,rs1,rs2"),
      INSN(pmhacc_w, "rd,rs1,rs2"),
      INSN(pmhaccu_w, "rd,rs1,rs2"),
      INSN(pmhaccsu_w, "rd,rs1,rs2"),
      INSN(pmhacc_w_h0, "rd,rs1,rs2"),
      INSN(pmhacc_w_h1, "rd,rs1,rs2"),
      INSN(pmhaccsu_w_h0, "rd,rs1,rs2"),
      INSN(pmhaccsu_w_h1, "rd,rs1,rs2"),
      INSN(pmhracc_w, "rd,rs1,rs2"),
      INSN(pmhraccu_w, "rd,rs1,rs2"),
      INSN(pmhraccsu_w, "rd,rs1,rs2"),
      INSN(pmqacc_w_h00, "rd,rs1,rs2"),
      INSN(pmqacc_w_h01, "rd,rs1,rs2"),
      INSN(pmqacc_w_h11, "rd,rs1,rs2"),
      INSN(pmqracc_w_h00, "rd,rs1,rs2"),
      INSN(pmqracc_w_h01, "rd,rs1,rs2"),
      INSN(pmqracc_w_h11, "rd,rs1,rs2"),
      INSN(pmq2add_w, "rd,rs1,rs2"),
      INSN(pmq2adda_w, "rd,rs1,rs2"),
      INSN(pmqr2add_w, "rd,rs1,rs2"),
      INSN(pmqr2adda_w, "rd,rs1,rs2"),

      // Packed multi-add word-sized instructions
      INSN(pm2add_w, "rd,rs1,rs2"),
      INSN(pm2add_wx, "rd,rs1,rs2"),
      INSN(pm2addu_w, "rd,rs1,rs2"),
      INSN(pm2addsu_w, "rd,rs1,rs2"),
      INSN(pm2adda_w, "rd,rs1,rs2"),
      INSN(pm2adda_wx, "rd,rs1,rs2"),
      INSN(pm2addau_w, "rd,rs1,rs2"),
      INSN(pm2addasu_w, "rd,rs1,rs2"),
      INSN(pm2sub_w, "rd,rs1,rs2"),
      INSN(pm2sub_wx, "rd,rs1,rs2"),
      INSN(pm2suba_w, "rd,rs1,rs2"),
      INSN(pm2suba_wx, "rd,rs1,rs2"),
      INSN(pm4add_h, "rd,rs1,rs2"),
      INSN(pm4addu_h, "rd,rs1,rs2"),
      INSN(pm4addsu_h, "rd,rs1,rs2"),
      INSN(pm4adda_h, "rd,rs1,rs2"),
      INSN(pm4addau_h, "rd,rs1,rs2"),
      INSN(pm4addasu_h, "rd,rs1,rs2"),

      // R1-type packed word-sized unary instructions
      INSN(psext_w_b, "rd,rs1"),
      INSN(psext_w_h, "rd,rs1"),
      INSN(zip16p, "rd,rs1"),
      INSN(zip16hp, "rd,rs1"),

      // Packed I-type with shamt (word-sized) - share opcode with RV32 scalar
      INSN(pslli_w, "rd,rs1,shamtw"),
      INSN(psrai_w, "rd,rs1,shamtw"),
      INSN(psrli_w, "rd,rs1,shamtw"),
      INSN(psrari_w, "rd,rs1,shamtw"),
      INSN(psati_w, "rd,rs1,shamtw"),
      INSN(pusati_w, "rd,rs1,shamtw"),
      INSN(psslai_w, "rd,rs1,shamtw"),

      // Packed load-immediate word-sized instructions
      INSN(pli_w, "rd,p_imm10csl"),
      INSN(plui_w, "rd,p_imm10csr"),
    });
  }
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

  built = true;
}

const disasm_insn_t* disassembler_t::lookup(insn_t insn) const
{
  const disasm_insn_t* best = nullptr;
  int64_t best_prio = INT64_MAX;
  for (size_t level = 0; level < LEVELS; level++) {
    // Entries whose mask covers the whole major opcode beat RVC-quadrant-only
    // entries, which beat the rest, regardless of priority (e.g. c.sspush
    // beats the reserved c.lui encoding it reuses).
    if (best && (key_masks[level] & 0x7f) != 0x7f)
      return best;

    auto it = index[level].find(insn.bits() & key_masks[level]);
    if (it == index[level].end())
      continue;
    for (const auto& e : it->second) {
      if (e.prio >= best_prio)
        break;
      if (*e.insn == insn) {
        best = e.insn;
        best_prio = e.prio;
        break;
      }
    }
  }
  return best;
}

void NOINLINE disassembler_t::add_insn(disasm_insn_t* insn)
{
  size_t level = 0;
  while ((insn->get_mask() & key_masks[level]) != key_masks[level])
    level++; // terminates: the last key is 0
  auto& list = index[level][insn->get_match() & key_masks[level]];

  if (built) {
    list.insert(list.begin(), {--top_prio, insn});
    return;
  }

  // A built-in entry with the same encoding as an earlier one can never win.
  for (const auto& e : list) {
    if (e.insn->get_match() == insn->get_match() && e.insn->get_mask() == insn->get_mask()) {
      delete insn;
      return;
    }
  }
  list.push_back({next_prio++, insn});
}

disassembler_t::~disassembler_t()
{
  for (const auto& level : index)
    for (const auto& [key, list] : level)
      for (const auto& e : list)
        delete e.insn;
}
