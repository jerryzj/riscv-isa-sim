// See LICENSE for license details.

#if !defined(NAME) || !defined(OPCODE)
#error "Compile insn_template.cc with -DNAME=<insn> and -DOPCODE=<match>"
#endif

#include "insn_template.h"
#include "insn_macros.h"

#define INSN_CONCAT2(a, b) a##b
#define INSN_CONCAT(a, b) INSN_CONCAT2(a, b)
#define INSN_FN(prefix) INSN_CONCAT(prefix, NAME)

#define INSN_XSTR(x) #x
#define INSN_HEADER(n) INSN_XSTR(insns/n.h)

#define DECODE_MACRO_USAGE_LOGGED 0

#define PROLOGUE \
  reg_t npc = sext_xlen(pc + insn_length(OPCODE)); \
  if (!p->extension_enabled(EXT_ZCA)) assume(insn_length(OPCODE) % 4 == 0)

#define EPILOGUE \
  trace_opcode(p, OPCODE, insn); \
  return npc

reg_t INSN_FN(fast_rv32i_)(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 32
  PROLOGUE;
  #include INSN_HEADER(NAME)
  EPILOGUE;
  #undef xlen
}

reg_t INSN_FN(fast_rv64i_)(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 64
  PROLOGUE;
  #include INSN_HEADER(NAME)
  EPILOGUE;
  #undef xlen
}

#undef DECODE_MACRO_USAGE_LOGGED
#define DECODE_MACRO_USAGE_LOGGED 1

reg_t INSN_FN(logged_rv32i_)(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 32
  PROLOGUE;
  #include INSN_HEADER(NAME)
  EPILOGUE;
  #undef xlen
}

reg_t INSN_FN(logged_rv64i_)(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 64
  PROLOGUE;
  #include INSN_HEADER(NAME)
  EPILOGUE;
  #undef xlen
}

#undef CHECK_REG
#define CHECK_REG(reg) require((reg) < 16)

#undef DECODE_MACRO_USAGE_LOGGED
#define DECODE_MACRO_USAGE_LOGGED 0

reg_t INSN_FN(fast_rv32e_)(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 32
  PROLOGUE;
  #include INSN_HEADER(NAME)
  EPILOGUE;
  #undef xlen
}

reg_t INSN_FN(fast_rv64e_)(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 64
  PROLOGUE;
  #include INSN_HEADER(NAME)
  EPILOGUE;
  #undef xlen
}

#undef DECODE_MACRO_USAGE_LOGGED
#define DECODE_MACRO_USAGE_LOGGED 1

reg_t INSN_FN(logged_rv32e_)(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 32
  PROLOGUE;
  #include INSN_HEADER(NAME)
  EPILOGUE;
  #undef xlen
}

reg_t INSN_FN(logged_rv64e_)(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 64
  PROLOGUE;
  #include INSN_HEADER(NAME)
  EPILOGUE;
  #undef xlen
}
