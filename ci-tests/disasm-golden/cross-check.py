#!/usr/bin/env python3
"""Cross-check spike's disassembly of one instruction list against llvm-mc
or binutils objdump.

  usage: cross-check.py [--ref llvm|binutils] [--objdump PATH] \\
             <build-dir> <riscv.mk.in list> <spike-isa> <xlen> [<llvm-mattr>]
  e.g.   cross-check.py build riscv_insn_ext_p rv64imafd_p 64 +experimental-p
         cross-check.py --ref binutils build riscv_insn_ext_p rv64imafd_p 64

Every instruction in the riscv.mk.in list is encoded 8 times with random
operand fields and disassembled by spike (strict mode, working tree) and by
the reference: `llvm-mc --disassemble -M no-aliases`, or
`objdump -b binary -M arch=<spike-isa>,no-aliases`.  Lines are compared
after canonicalizing whitespace and numbers; spike "unknown" and an invalid
encoding in the reference count as equal.  Differences that only come from
spike's long-standing output conventions (see spike_style) are counted
separately as "style".
"""
import os, re, subprocess, sys, tempfile

args = sys.argv[1:]
ref, objdump = 'llvm', 'riscv64-unknown-elf-objdump'
while args and args[0].startswith('--'):
    opt = args.pop(0)
    if opt == '--ref': ref = args.pop(0)
    elif opt == '--objdump': objdump = args.pop(0)
    else: sys.exit('unknown option ' + opt)
build, insn_list, isa, xlen = args[:4]
mattr = args[4] if len(args) > 4 else ''
here = os.path.dirname(os.path.abspath(__file__))
src = subprocess.run(['git', '-C', here, 'rev-parse', '--show-toplevel'], capture_output=True, text=True).stdout.strip()

mk = open(os.path.join(src, 'riscv/riscv.mk.in')).read()
body = re.search(r'^%s\s*=\s*\\\n((?:[ \t]+\w+[ \t]*\\?\n)+)' % insn_list, mk, re.M).group(1)
names = body.replace('\\', ' ').split()

# built in the build dir and reused until a source changes
gen = os.path.join(build, 'cross-gen')
srcs = [os.path.join(here, 'cross-gen.cc')] + \
       [os.path.join(src, 'disasm', f) for f in ('disasm.cc', 'isa_parser.cc', 'regnames.cc')] + \
       [os.path.join(src, 'riscv', f) for f in ('disasm.h', 'encoding.h', 'decode.h')]
if not os.path.exists(gen) or max(map(os.path.getmtime, srcs)) > os.path.getmtime(gen):
    flags = ['-std=c++2a', '-O1', '-iquote', build, '-I' + src] + \
            sum((['-iquote', os.path.join(src, d)] for d in ('riscv', 'disasm', 'fesvr', 'softfloat')), [])
    subprocess.run(['g++'] + flags + srcs[:4] + ['-o', gen], check=True)

rows = [l.split('\t') for l in subprocess.run([gen, isa], input='\n'.join(names), capture_output=True,
                                             text=True, check=True).stdout.splitlines()]
# 16-bit (compressed) words are printed with 4 hex digits
words = [bytes.fromhex(w)[::-1] for w, _, _ in rows]
addrs = [sum(map(len, words[:i])) for i in range(len(words))]

def run_llvm():
    inp = ''.join(' '.join('0x%02x' % b for b in w) + '\n' for w in words)
    r = subprocess.run(['llvm-mc', '--disassemble', '-triple=riscv' + xlen, '-mattr=' + mattr, '-M', 'no-aliases'],
                       input=inp, capture_output=True, text=True)
    bad = {int(m.group(1)) for m in re.finditer(r'<stdin>:(\d+):\d+: warning: invalid', r.stderr)}
    out = iter(l.strip() for l in r.stdout.splitlines() if l.strip() and not l.strip().startswith('.text'))
    return ['INVALID' if i in bad else next(out) for i in range(1, len(words) + 1)]

def run_binutils():
    with tempfile.NamedTemporaryFile(suffix='.bin') as f:
        f.write(b''.join(words)); f.flush()
        r = subprocess.run([objdump, '-D', '-b', 'binary', '-m', 'riscv:rv' + xlen,
                            '-M', 'arch=%s,no-aliases' % isa, f.name], capture_output=True, text=True, check=True)
    by_addr = {}
    for l in r.stdout.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\t[0-9a-f]+\s*\t(.*)$', l)
        if m:   # drop objdump's "# <address>" comments
            by_addr[int(m.group(1), 16)] = 'INVALID' if m.group(2).startswith('.insn') else m.group(2).split(' #')[0]
    return [by_addr[a] for a in addrs]

refout = run_llvm() if ref == 'llvm' else run_binutils()

def canon(s):
    s = re.sub(r'\s+', ' ', s).strip()
    s = re.sub(r' ?, ?', ',', s)
    return re.sub(r'\b0x[0-9a-f]+\b(?![.p])', lambda m: str(int(m.group(0), 16)), s)   # hex ints -> decimal

def spike_style(spike, other, addr):
    """True if spike and the reference only differ by spike output conventions."""
    def target(m):   # pc-relative "pc + 8": llvm prints the offset, binutils the address
        off = int(m.group(2), 0) * (-1 if m.group(1) == '-' else 1)
        return str(off if ref == 'llvm' else (addr + off) % (1 << int(xlen)))
    s = re.sub(r'pc ([+-]) ?(0x[0-9a-f]+|\d+)', target, spike)
    s = canon(s)
    s = re.sub(r'^(jalr \w+),(\w+),(-?\d+)$', r'\1,\3(\2)', s)                 # jalr rd, rs1, imm
    s = re.sub(r'^b(eq|ne|lt|ge)z (\w+),', r'b\1 \2,zero,', s)                 # beqz etc. (no-aliases)
    o = re.sub(r',(rne|rtz|rdn|rup|rmm|dyn|unknown)$', '', other)               # spike omits the rounding mode
    o = re.sub(r'(?<=,)(-?0x[0-9a-f.]+p[+-]\d+)$', lambda m: repr(float.fromhex(m.group(1))), o)  # fli: hex float
    s = re.sub(r'(?<=,)(-?[0-9.]+e-\d+)$', lambda m: repr(float(m.group(1))), s)
    return s == o

diffs = {}; style = 0
for (w, name, spike), other, addr in zip(rows, refout, addrs):
    other = canon(other)
    if canon(spike) == other or (other == 'INVALID' and spike.strip() == 'unknown'):
        continue
    if spike_style(spike, other, addr):
        style += 1
    else:
        diffs.setdefault(name, []).append((w, re.sub(r'\s+', ' ', spike).strip(), other))

print('%s on %s vs %s: %d instructions, %d words, %d style-only, %d differ in %d instructions'
      % (insn_list, isa, 'llvm-mc riscv%s %s' % (xlen, mattr) if ref == 'llvm' else 'objdump',
         len(names), len(rows), style, sum(map(len, diffs.values())), len(diffs)))
for name, d in sorted(diffs.items()):
    w, s, l = d[0]
    print('  %-14s %-8s  spike: %-32s %s: %s' % (name, w, s, ref, l))
