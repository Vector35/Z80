#!/usr/bin/env python

import re
import sys
import binaryninja

arch = None
def disasm_binja(data, addr):
    global arch
    if not arch:
        arch = binaryninja.Architecture['Z80']
    toksAndLen = arch.get_instruction_text(data, addr)
    if not toksAndLen or toksAndLen[1]==0:
        return ''
    toks = toksAndLen[0]
    strs = map(lambda x: x.text, toks)
    return ''.join(strs)

def is_num(x):
    return bool(re.match(r'^[A-Fa-f0-9]+$', x))

def tok_vals(x):
    result = set()
    if x.startswith('$'):
        x = x[1:]
    if x.startswith('0x'):
        x = x[2:]
    if re.match(r'^[A-Fa-f0-9]+$', x):
        result.add(int(x, 16))
    if re.match(r'^[0-9]+$', x):
        result.add(int(x, 10))
    return result

def is_token_equal(a, b):
    a_vals = tok_vals(a)
    if a_vals:
        b_vals = tok_vals(b)
        if b_vals:
            return bool(a_vals.intersection(b_vals))

    return a == b

def is_disasm_equal(a, b):
    toks_a = re.split(' |,', a)
    toks_b = re.split(' |,', b)

    if len(toks_a) != len(toks_b):
        return False

    return all(is_token_equal(ta, tb) for (ta,tb) in zip(toks_a, toks_b))

if __name__ == '__main__':
    ADDR = 0
    with open('./disasm65536.txt') as fp:
        for line in fp.readlines():
            # eg: "00 0B 00 00: NOP"
            (b0,b1,b2,b3,expected) = re.match(r'^(..) (..) (..) (..): (.*)\n$', line).group(1,2,3,4,5)
            data = b''.join([int(x,16).to_bytes(1,'big') for x in [b0,b1,b2,b3]])

            distxt = disasm_binja(data, ADDR)

            #print(f'{ADDR:04X}: {data.hex()} {a}')
            print(f'{data.hex()} {distxt}')

            if not is_disasm_equal(distxt, expected):
                print(f'expected {expected}')
                sys.exit(-1)
