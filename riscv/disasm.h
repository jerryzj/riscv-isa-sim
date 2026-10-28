// See LICENSE for license details.

#ifndef _RISCV_DISASM_H
#define _RISCV_DISASM_H

#include "common.h"
#include "decode.h"
#include "isa_parser.h"
#include <string>
#include <sstream>
#include <algorithm>
#include <vector>
#include <unordered_map>

extern const char* xpr_name[NXPR];
extern const char* fpr_name[NFPR];
extern const char* vr_name[NVPR];
extern const char* csr_name(int which);
extern const char* frm_name(int which);

class arg_t
{
 public:
  virtual std::string to_string(insn_t val) const = 0;
  virtual ~arg_t() {}
};

class disasm_insn_t
{
 public:
  NOINLINE disasm_insn_t(const char* name_, uint32_t match, uint32_t mask,
                         const std::vector<const arg_t*>& args)
    : match(match), mask(mask), args(args)
  {
    name = name_;
    std::replace(name.begin(), name.end(), '_', '.');
  }

  bool operator == (insn_t insn) const
  {
    return (insn.bits() & mask) == match;
  }

  const char* get_name() const
  {
    return name.c_str();
  }

  std::string to_string(insn_t insn) const
  {
    std::string s(name);

    if (args.size())
    {
      bool next_arg_optional  = false;
      s += std::string(std::max(1, 8 - int(name.size())), ' ');
      for (size_t i = 0; i < args.size(); i++) {
        if (args[i] == nullptr) {
          next_arg_optional = true;
          continue;
        }
        std::string argString = args[i]->to_string(insn);
        if (next_arg_optional) {
          next_arg_optional = false;
          if (argString.empty()) continue;
        }
        if (i != 0) s += ", ";
        s += argString;
      }
    }
    return s;
  }

  uint32_t get_match() const { return match; }
  uint32_t get_mask() const { return mask; }

 private:
  uint32_t match;
  uint32_t mask;
  std::vector<const arg_t*> args;
  std::string name;
};

class disassembler_t
{
 public:
  disassembler_t(const isa_parser_t *isa, bool strict = false);
  ~disassembler_t();

  std::string disassemble(insn_t insn) const;
  const disasm_insn_t* lookup(insn_t insn) const;

  void add_insn(disasm_insn_t* insn);

 private:
  // Each instruction is indexed under the first of these keys that its mask
  // covers (opcode+funct3+funct6, opcode+funct3, opcode, RVC quadrant+funct3,
  // anything); lookup() probes every level and the highest priority wins.
  static constexpr uint32_t key_masks[] = {0xfc00707f, 0x707f, 0x7f, 0xe003, 0};
  static constexpr size_t LEVELS = sizeof(key_masks) / sizeof(key_masks[0]);

  struct entry_t {
    int64_t prio; // lower wins
    const disasm_insn_t* insn;
  };
  // each list is sorted by priority
  std::unordered_map<uint32_t, std::vector<entry_t>> index[LEVELS];
  int64_t next_prio = 0; // built-in instructions: first added wins
  int64_t top_prio = 0;  // added after construction: beat everything, latest first
  bool built = false;

  void add_instructions(const isa_parser_t* isa, bool strict);
};

#endif
