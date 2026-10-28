#!/usr/bin/env python3
"""Run cross-check.py for every spike instruction list the reference supports.

  usage: cross-sweep.py [--all] [--ref llvm|binutils] [--objdump PATH] <build-dir> [<list suffix>...]
  e.g.   cross-sweep.py build p zalasr

With list names, prints every difference of those lists.  Otherwise prints
the summary of the lists that still differ (of every list with --all).
"""
import re, subprocess, sys
import os
C = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cross-check.py')
args = sys.argv[1:]
show_all = '--all' in args
args = [a for a in args if a != '--all']
refopts = []
while args and args[0] in ('--ref', '--objdump'):
    refopts += args[:2]; args = args[2:]
B = args[0]
G = '+m,+a,+f,+d,+c'
V = G + ',+v'
L = [('i','gc',G),('a','gc_zacas_zabha',G+',+zacas,+zabha'),('c','gc',G),('m','gc',G),('f','gc',G),('d','gc',G),
     ('q','imafdqc',G+',+q'),('zfh','gc_zfh',G+',+zfh'),('f_zfa','gc_zfa',G+',+zfa'),('d_zfa','gc_zfa',G+',+zfa'),
     ('q_zfa','imafdqc_zfa',G+',+q,+zfa'),('zfh_zfa','gc_zfh_zfa',G+',+zfh,+zfa'),('h','gch',G+',+h'),
     ('zcb','gc_zcb_zba_zbb',G+',+zcb,+zba,+zbb'),('zcmp','imafd_zca_zcb_zcmp','+m,+a,+f,+d,+zca,+zcb,+zcmp'),
     ('zcmt','imafd_zca_zcb_zcmt','+m,+a,+f,+d,+zca,+zcb,+zcmt'),('cmo','gc_zicbom_zicboz',G+',+zicbom,+zicboz,+zicbop'),
     ('zicond','gc_zicond',G+',+zicond'),('zfbfmin','gc_zfbfmin',G+',+zfbfmin'),('zacas','gc_zacas',G+',+zacas'),
     ('zabha','gc_zabha_zacas',G+',+zabha,+zacas'),('zawrs','gc_zawrs',G+',+zawrs'),('zalasr','gc_zalasr',G+',+zalasr'),
     ('zimop','gc_zimop',G+',+zimop'),('zcmop','gc_zcmop',G+',+zcmop'),('zicfilp','gc_zicfilp',G+',+experimental-zicfilp'),
     ('zicfiss','gc_zicfiss_zimop_zcmop',G+',+experimental-zicfiss,+zimop,+zcmop'),('zibi','gc_zibi',G+',+experimental-zibi'),
     ('b','gc_zba_zbb_zbc_zbs_zbkb_zbkc_zbkx',G+',+zba,+zbb,+zbc,+zbs,+zbkb,+zbkc,+zbkx'),
     ('k','gc_zknd_zkne_zknh_zksed_zksh_zbkb',G+',+zknd,+zkne,+zknh,+zksed,+zksh,+zbkb'),
     ('v_alu_int','gcv',V),('v_alu_fp','gcv',V),('v_ldst','gcv',V),('v_ctrl','gcv',V),
     ('zvbb','gcv_zvbb',V+',+zvbb'),('zvbc','gcv_zvbc',V+',+zvbc'),('zvkg','gcv_zvkg',V+',+zvkg'),
     ('zvkned','gcv_zvkned',V+',+zvkned'),('zvknh','gcv_zvknhb',V+',+zvknhb'),('zvksed','gcv_zvksed',V+',+zvksed'),
     ('zvksh','gcv_zvksh',V+',+zvksh'),('zvfbfmin','gcv_zvfbfmin',V+',+zvfbfmin'),('zvfbfwma','gcv_zvfbfwma',V+',+zvfbfwma'),
     ('zvabd','gcv_zvabd',V+',+experimental-zvabd'),('zvzip','gcv_zvzip',V+',+experimental-zvzip'),
     ('p','imafd_p','+m,+a,+f,+d,+experimental-p'),
     # binutils only (no llvm-mc support)
     ('zvbdota','gcv_zvqwbdota8i_zvqwbdota16i_zvfqwbdota8f_zvfwbdota16bf_zvfbdota32f',None),
     ('zvdota','gcv_zvqwdota8i_zvqwdota16i_zvfqwdota8f_zvfwdota16bf',None),
     ('zvfofp4min','gcv_zvfofp4min',None),('zvfofp8min','gcv_zvfofp8min',None)]
binutils = 'binutils' in refopts
only = args[1:]
for n, isa, m in L:
    if only and n not in only: continue
    if m is None and not binutils: continue
    for x in ('64', '32'):
        r = subprocess.run([C] + refopts + [B, 'riscv_insn_ext_' + n, 'rv' + x + isa, x, m or ''], capture_output=True, text=True)
        out = (r.stdout or r.stderr).splitlines()
        head = out[0] if out else r.stderr[-300:]
        if only or show_all or ' 0 differ' not in head:
            print(re.sub(r' vs (llvm-mc riscv\S+ \S*|objdump)', '', head))
            if only: print('\n'.join(out[1:]))
