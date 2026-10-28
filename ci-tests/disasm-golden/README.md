# Disassembler golden comparison

Checks that a disassembler change does not change its output, and measures
its speed, by comparing a base revision against the working tree or another
revision.

    ./configure && make            # any configured build dir (for config.h)
    ci-tests/disasm-golden/compare.sh <base-rev> <build-dir> [<new-rev>]

- `dump.cc` prints the disassembly of every `encoding.h` instruction with
  random and hand-picked operand fields (so pseudo-instructions such as
  `ret`, `seqz` and `li` are hit), every 16-bit word and 200k random 32-bit
  words, under 19 ISA strings in strict and non-strict mode, plus
  instructions added after construction (as extensions do) that override
  built-in ones (8.7M lines).
  The output is deterministic; the script requires it to be byte-identical.
- `bench.cc` reports disassembler construction time and `lookup()` /
  `disassemble()` time per instruction (rv64gcv_zba_zbb_zbs_zfh).

- `cross-check.py` cross-checks one instruction list against
  `llvm-mc --disassemble` or binutils `objdump`, and `cross-sweep.py` runs
  it for every list the reference supports (see below).

Both sides are compiled by the script from their own sources
(`git archive` for the base revision).

## Results

Each row is `compare.sh <previous> <build> <commit>` (gcc, -O2).  Golden is
the sha256 of the 8.7M-line dump (each row's base is the previous row's
golden); "kinds" is the number of distinct `base -> new` mnemonic changes.
Lookup and disassemble are per instruction, non-strict / strict.

| commit | golden | kinds | construct | lookup | disassemble |
|---|---|---|---|---|---|
| e8edbee7 upstream | `dd025a62…` | | 0.89 / 0.22 ms | 112 / 49 ns | 212 / 96 ns |
| 9dad410a table-driven rewrite | identical | 0 | 0.75 / 0.20 ms | 117 / 50 ns | 213 / 98 ns |
| 9f8f10a6 multi-level lookup index | identical | 0 | 0.96 / 0.33 ms | 21 / 32 ns | 118 / 79 ns |
| a97120e8 Zvt | `09e6ad21…` | 57 | | | |
| ac413de8 mnret | `99ff0440…` | 2 | | | |
| 2b1afc0c P gating and operands | `fc252b59…` | 281 | | | |
| 0a277fb9 Zbb/Zbkb/Zbkx/Zkn | `9a0d54ab…` | 13 | | | |
| 675336e2 lr/Zalasr | `31fe7589…` | 16 | | | |
| 5a64dc3a H | `7a5f3519…` | 3 | | | |
| 35400f0d vector .vi, vfwmaccbf16 | `468c6f24…` | 6 | | | |
| 3e53ea51 FP conversion gating | `d01f24fb…` | 12 | | | |
| 8a3d609a P immediates | `29227442…` | 13 | | | |

For each commit that changes the output, the changed lines touch only the
intended instructions:

- a97120e8 (Zvt): the 21 Zvt instructions change from `(args unknown)` /
  `unknown` to their mnemonic, and the reserved mew=1 vector loads/stores
  that Zvt reuses (`vle1024.v`, `vlseg<n>e1024[ff].v`, `vl<n>re1024.v`,
  `vse1024.v`, `vsseg<n>e1024.v`) become `vtle*` / `vtse*`.
- ac413de8 (mnret): `mnret (args unknown)` / `unknown` become `mnret`.
- 2b1afc0c (P): only P instructions.  In the strict P configurations,
  instructions whose implementation requires the other XLEN become
  `unknown` (RV32-only pair/widening/narrowing ops on RV64; `sha`, `shar`,
  `zip*p`, `unzip*p` on RV32) and RV64 shows `pmqacc.w.h*` /
  `pmqracc.w.h*` instead of `mqacc.h*` / `mqracc.h*`; `rev`, `rev16` and
  `rev.rv32` (shown as `rev`) are decoded; 27 instructions keep their
  mnemonic and change operands (pairs, `rs2`, shift-amount widths).
- 0a277fb9 (B/K): `xperm4`, `xperm8`, `zip`, `unzip`, `rev8.rv32` (shown as
  `rev8`) are decoded; on RV32 the RV64 `rev8` encoding, `aes64ks1i` and
  `aes64ks2` become `unknown`.
- 675336e2 (lr/Zalasr): `lr.w`/`lr.d` gain `.aq`/`.rl`/`.aqrl`, Zalasr
  loads/stores with both bits set become `<op>.aqrl`; on RV32 `ld.aq` and
  `sd.rl` become `unknown`.
- 5a64dc3a (H): on RV32 `hlv.wu`, `hlv.d`, `hsv.d` become `unknown`.
- 35400f0d (V): `vsaddu.vi`, `vmsleu.vi`, `vmsgtu.vi`, `vsll.vi` change
  their immediate, `vfwmaccbf16.vv/.vf` their operand order.
- 3e53ea51 (FP): `fcvt.{h,q}.l[u]` / `fcvt.l[u].{h,q}` become `unknown` on
  RV32 and `fcvt.{s,d}.q`, `fcvt.h.q`, `fcvt.q.h` without Q.
- 8a3d609a (P): the immediates of `pli.*`, `plui.*`, `sati` and `psati.*`.

## Cross-check against llvm-mc and binutils

`cross-sweep.py --all [--ref binutils --objdump <objdump>] <build>` encodes
every instruction of each spike instruction list 8 times with random
operands (RV64 and RV32) and compares spike with the reference
(`llvm-mc --disassemble -M no-aliases`, LLVM 23.1.1; binutils 2.45.1
`objdump -M arch=<isa>,no-aliases`), ignoring spike's own conventions
(`pc + N` branch targets, `jalr rd, rs1, imm`, omitted rounding mode,
`beqz`-style aliases, decimal `fli` constants).  Instructions that differ:

| list (RV64 / RV32) | llvm upstream | llvm now | binutils upstream | binutils now |
|---|---|---|---|---|
| a (lr aq/rl) | 2 / 1 | 0 / 0 | 2 / 1 | 0 / 0 |
| d, q, zfh (gating) | 51 / 50 | 48 / 39 | 3 / 11 | 0 / 0 |
| h | 0 / 3 | 0 / 0 | 0 / 3 | 0 / 0 |
| zalasr | 8 / 8 | 0 / 0 | 8 / 8 | 0 / 0 |
| b | 2 / 6 | 0 / 0 | 2 / 11 | 0 / 5 |
| k | 0 / 2 | 0 / 0 | 0 / 2 | 0 / 0 |
| v_alu_int | 7 / 7 | 3 / 3 | 4 / 4 | 0 / 0 |
| zvfbfwma | 2 / 2 | 0 / 0 | 2 / 2 | 0 / 0 |
| p | 268 / 38 | 0 / 3 | 268 / 41 | 2 / 4 |
| all lists | 561 | 200 | 421 | 60 |

llvm covers 46 lists (2996 instruction x XLEN checks), binutils 50 (3026,
including zvbdota, zvdota, zvfofp4min and zvfofp8min, which llvm lacks;
all of them match).  Neither supports Zilx, Zvdot4a or Zvt.

The remaining differences are not disassembler bugs:

- reserved encodings that a reference rejects and spike prints anyway:
  rounding modes 5 and 6 (llvm), non-zero reserved `fence` fields,
  `cm.push`/`cm.pop*` rlist < 4 and `cm.mvsa01` with equal registers,
  odd registers in RV32 `amocas.d`, misaligned `vl<n>re`/`vs<n>r`/`vmv<n>r`
  register groups, EEW=64 indexed loads/stores on RV32, `vsetvli` with a
  reserved SEW;
- reserved encodings that binutils accepts and spike rejects: RV32 shifts
  with shamt >= 32 (`slli`, `c.slli`, `bclri`, `rori`, ...) and the RV64-only
  `absw` on RV32;
- `lpad`, which llvm prints as `auipc zero` with `-M no-aliases`;
- Zvabd and Zvzip: binutils has no support; llvm's Zvabd draft uses other
  encodings than spike's encoding.h (`vabd.vv` funct6 0x11 vs 0x15);
- P: llvm prints the field instead of the saturation width for
  `psati.dh`/`psati.dw` only (binutils and spike's `P_SAT(field + 1)` agree
  on the width), binutils decodes the `pli.h`/`pli.w`/`pli.dh` immediate
  with a bit layout that disagrees with llvm and spike's implementation
  (its values fall outside the 10-bit range), and `ppaire.h` on RV32 is
  decoded by both only as Zbkb `pack`.
