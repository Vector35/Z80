#!/usr/bin/env python

import re

from binaryninja.log import log_info
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType

from z80dis.z80 import *

class Z80(Architecture):
    name = 'Z80'

    address_size = 2
    default_int_size = 1
    instr_alignment = 1
    max_instr_length = 4

    # register related stuff
    regs = {
        # main registers
        'AF': RegisterInfo('AF', 2),
        'BC': RegisterInfo('BC', 2),
        'DE': RegisterInfo('DE', 2),
        'HL': RegisterInfo('HL', 2),

        # alternate registers
        'AF_': RegisterInfo('AF_', 2),
        'BC_': RegisterInfo('BC_', 2),
        'DE_': RegisterInfo('DE_', 2),
        'HL_': RegisterInfo('HL_', 2),

        # main registers (sub)
        'A': RegisterInfo('AF', 1, 1),
        'B': RegisterInfo('BC', 1, 1),
        'C': RegisterInfo('BC', 1, 0),
        'D': RegisterInfo('DE', 1, 1),
        'E': RegisterInfo('DE', 1, 0),
        'H': RegisterInfo('HL', 1, 1),
        'L': RegisterInfo('HL', 1, 0),
        'Flags': RegisterInfo('AF', 0),

        # alternate registers (sub)
        'A_': RegisterInfo('AF_', 1, 1),
        'B_': RegisterInfo('BC_', 1, 1),
        'C_': RegisterInfo('BC_', 1, 0),
        'D_': RegisterInfo('DE_', 1, 1),
        'E_': RegisterInfo('DE_', 1, 0),
        'H_': RegisterInfo('HL_', 1, 1),
        'L_': RegisterInfo('HL_', 1, 0),
        'Flags_': RegisterInfo('AF_', 0),

        # index registers
        'IX': RegisterInfo('IX', 2),
        'IY': RegisterInfo('IY', 2),
        'SP': RegisterInfo('SP', 2),

        # other registers
        'I': RegisterInfo('I', 1),
        'R': RegisterInfo('R', 1),

        # program counter
        'PC': RegisterInfo('PC', 2),

        # status
        'status': RegisterInfo('status', 1)
    }

    stack_pointer = "SP"

    # internal
    cond_strs = ['C', 'NC', 'Z', 'NZ', 'M', 'P', 'PE', 'PO']
    reg8_strs = list('ABDHCELIR') + ['A\'', 'B\'', 'C\'', 'D\'', 'E\'', 'H\'', 'L\'', 'Flags', 'Flags\'', 'IXh', 'IXl', 'IYh', 'IYl']
    reg16_strs = ['AF', 'BC', 'DE', 'HL', 'AF', 'AF\'', 'BC\'', 'DE\'', 'HL\'', 'IX', 'IY', 'SP', 'PC']
    reg_strs = reg8_strs + reg16_strs

#------------------------------------------------------------------------------
# CFG building
#------------------------------------------------------------------------------

    def get_instruction_info(self, data, addr):
        decoded = decode(data, addr)

        # on error, return nothing
        if decoded.status == DECODE_STATUS.ERROR or decoded.len == 0:
            return None

        # on non-branching, return length
        result = InstructionInfo()
        result.length = decoded.len
        if decoded.typ != INSTRTYPE.JUMP_CALL_RETURN:
            return result

        # jp has several variations
        if decoded.op == OP.JP:
            (oper0type, oper0val) = decoded.operands[0]

            # jp pe,0xDEAD
            if oper0type == OPER_TYPE.CON:
                assert decoded.operands[1][0] == OPER_TYPE.ADDR
                result.add_branch(BranchType.TrueBranch, decoded.operands[1][1])
                result.add_branch(BranchType.FalseBranch, addr + decoded.len)
            # jp (hl); jp (ix); jp (iy)
            elif oper0type in [OPER_TYPE.REG_HL_DEREF, OPER_TYPE.MEM_DISPL_IX, OPER_TYPE.MEM_DISPL_IY]:
                result.add_branch(BranchType.IndirectBranch)
            # jp 0xDEAD
            elif oper0type == OPER_TYPE.ADDR:
                result.add_branch(BranchType.UnconditionalBranch, oper0val)
            else:
                raise Exception('handling JP')
       
        # jr can be conditional
        elif decoded.op == OP.JR:
            (oper0type, oper0val) = decoded.operands[0]

            # jr c,0xdf07
            if oper0type == OPER_TYPE.CON:
                assert decoded.operands[1][0] == OPER_TYPE.ADDR
                result.add_branch(BranchType.TrueBranch, decoded.operands[1][1])
                result.add_branch(BranchType.FalseBranch, addr + decoded.len)
            # jr 0xdf07
            elif oper0type == OPER_TYPE.ADDR:
                result.add_branch(BranchType.UnconditionalBranch, oper0val)
            else:
                raise Exception('handling JR')

        # djnz is implicitly conditional
        elif decoded.op == OP.DJNZ:
            (oper0type, oper0val) = decoded.operands[0]
            assert oper0type == OPR_TYPE.ADDR
            result.add_branch(BranchType.TrueBranch, oper0val)
            result.add_branch(BranchType.FalseBranch, addr + decoded.len)
        
        # call can be conditional
        elif decoded.op == OP.CALL:
            (oper0type, oper0val) = decoded.operands[0]
            # call c,0xdf07
            if oper0type == OPER_TYPE.CON:
                assert decoded.operands[1][0] == OPER_TYPE.ADDR
                result.add_branch(BranchType.CallDestination, decoded.operands[1][1])
            # call 0xdf07
            elif oper0type == OPER_TYPE.ADDR:
                result.add_branch(BranchType.UnconditionalBranch, oper0val)
            else:
                raise Exception('handling JR')

        # ret can be conditional
        elif decoded.op == OP.RET:
            assert len(decoded.operands) == 0 or decoded.operands[0][1] == OPER_TYPE.COND
            # ret
            if len(decoded.operands) == 0:
                result.add_branch(BranchType.FunctionReturn)
            # ret nz
            else:
                # conditional returns dont' end block
                pass

        # ret from interrupts
        elif decoded.op == OP.RETI or decoded.op == OP.RETN:
            result.add_branch(BranchType.FunctionReturn)

        return result

#------------------------------------------------------------------------------
# STRING building, disassembly
#------------------------------------------------------------------------------

# from api/python/function.py:
#
#		TextToken                  Text that doesn't fit into the other tokens
#		InstructionToken           The instruction mnemonic
#		OperandSeparatorToken      The comma or whatever else separates tokens
#		RegisterToken              Registers
#		IntegerToken               Integers
#		PossibleAddressToken       Integers that are likely addresses
#		BeginMemoryOperandToken    The start of memory operand
#		EndMemoryOperandToken      The end of a memory operand
#		FloatingPointToken         Floating point number

    def get_instruction_text(self, data, addr):
        decoded = decode(data, addr)
        if decoded.status != DECODE_STATUS.OK or decoded.len == 0:
            return None

        CC_TO_STR = {
            CC.ALWAYS:"1", CC.NOT_N:"nn", CC.N:"n", CC.NOT_Z:"nz", CC.Z:"z",
            CC.NOT_C:"nc", CC.C:"c", CC.NOT_P:"po", CC.P:"pe", CC.NOT_S:"p", CC.S:"m",
            CC.NOT_H:"nh", CC.H:"h"
        }

        REG_TO_STR = {
            OPER_TYPE.REG_A:"a", OPER_TYPE.REG_F:"f", OPER_TYPE.REG_B:"b", OPER_TYPE.REG_C:"c",
            OPER_TYPE.REG_D:"d", OPER_TYPE.REG_E:"e", OPER_TYPE.REG_H:"h", OPER_TYPE.REG_L:"l",
            OPER_TYPE.REG_C_DEREF:"(c)", OPER_TYPE.REG_AF:"af", OPER_TYPE.REG_BC:"bc",
            OPER_TYPE.REG_DE:"de", OPER_TYPE.REG_HL:"hl", OPER_TYPE.REG_BC_DEREF:"(bc)",
            OPER_TYPE.REG_DE_DEREF:"(de)", OPER_TYPE.REG_HL_DEREF:"(hl)", OPER_TYPE.REG_A_:"a'",
            OPER_TYPE.REG_F_:"f'", OPER_TYPE.REG_B_:"b'", OPER_TYPE.REG_C_:"c'",
            OPER_TYPE.REG_D_:"d'", OPER_TYPE.REG_E_:"e'", OPER_TYPE.REG_H_:"h'",
            OPER_TYPE.REG_L_:"l'", OPER_TYPE.REG_AF_:"af'", OPER_TYPE.REG_BC_:"bc'",
            OPER_TYPE.REG_DE_:"de'", OPER_TYPE.REG_HL_:"hl'", OPER_TYPE.REG_I:"i",
            OPER_TYPE.REG_R:"r", OPER_TYPE.REG_IX:"ix", OPER_TYPE.REG_IXH:"ixh",
            OPER_TYPE.REG_IXL:"ixl", OPER_TYPE.REG_IY:"iy", OPER_TYPE.REG_IYH:"iyh",
            OPER_TYPE.REG_IYL:"iyl", OPER_TYPE.REG_SP:"sp", OPER_TYPE.REG_PC:"pc",
            OPER_TYPE.REG_SP_DEREF:"(sp)"
        }

        result = []

        # opcode
        result.append(InstructionTextToken( \
            InstructionTextTokenType.InstructionToken, decoded.op.name.lower()))

        # space for operand
        if decoded.operands:
            result.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))

        for i, operand in enumerate(decoded.operands):
            (operType, operVal) = operand

            if operType == OPER_TYPE.ADDR:
                if operVal < 0:
                    operVal = operVal & 0xFFFF
                txt = '0x%04x' % operVal
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.PossibleAddressToken, txt, operVal))
        
            elif operType == OPER_TYPE.ADDR_DEREF:
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.BeginMemoryOperandToken, '('))
                txt = '0x%04x' % operVal
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.PossibleAddressToken, txt, operVal))
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.EndMemoryOperandToken, ')'))
        
            elif operType in [OPER_TYPE.MEM_DISPL_IX, OPER_TYPE.MEM_DISPL_IY]:
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.BeginMemoryOperandToken, '('))

                txt = 'ix' if operType == OPER_TYPE.MEM_DISPL_IX else 'iy'
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.RegisterToken, txt))

                if operVal == 0:
                    # omit displacement of 0
                    pass
                elif operVal >= 16:
                    # (iy+0x28)
                    result.append(InstructionTextToken( \
                        InstructionTextTokenType.TextToken, '+'))
                    result.append(InstructionTextToken( \
                        InstructionTextTokenType.IntegerToken, '0x%X' % operVal, operVal))
                elif operVal > 0:
                    result.append(InstructionTextToken( \
                        InstructionTextTokenType.TextToken, '+'))
                    result.append(InstructionTextToken( \
                        InstructionTextTokenType.IntegerToken, '%d' % operVal, operVal))
                elif operVal <= -16:
                    # adc a,(ix-0x55)
                    result.append(InstructionTextToken( \
                        InstructionTextTokenType.TextToken, '-'))
                    result.append(InstructionTextToken( \
                        InstructionTextTokenType.IntegerToken, '0x%X' % (-operVal), operVal))
                else:
                    result.append(InstructionTextToken( \
                        InstructionTextTokenType.IntegerToken, '%d' % operVal, operVal))

                result.append(InstructionTextToken( \
                    InstructionTextTokenType.EndMemoryOperandToken, ')'))
        
            elif operType == OPER_TYPE.ADDR:
                txt = '0x%04X' % operVal
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.PossibleAddressToken, txt, operVal)  )              
        
            elif operType == OPER_TYPE.IMM:
                if operVal == 0:
                    txt = '0'
                elif operVal >= 16:
                    txt = '0x%x' % operVal
                else:
                    txt = '%d' % operVal

                result.append(InstructionTextToken( \
                    InstructionTextTokenType.IntegerToken, txt, operVal))
        
            elif operType == OPER_TYPE.CON:
                txt = CC_TO_STR[operVal]
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.TextToken, txt))

            else:
                # must be register
                assert operType in REG_TO_STR
                txt = REG_TO_STR[operType]
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.RegisterToken, txt))

            # if this isn't the last operand, add comma
            if i < len(decoded.operands)-1:
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.OperandSeparatorToken, ','))

        # crazy undoc shit
        if decoded.metaLoad != OPER_TYPE.NONE:
            extras = []

            extras.append(InstructionTextToken( \
                InstructionTextTokenType.InstructionToken, 'ld'))
            extras.append(InstructionTextToken( \
                InstructionTextTokenType.TextToken, ' '))
            extras.append(InstructionTextToken( \
                InstructionTextTokenType.RegisterToken, REG_TO_STR[decoded.metaLoad]))
            extras.append(InstructionTextToken( \
                InstructionTextTokenType.OperandSeparatorToken, ','))

            result = extras + result

        return result, decoded.len

#------------------------------------------------------------------------------
# LIFTING
#------------------------------------------------------------------------------
    def get_instruction_low_level_il(self, data, addr, il):
        decoded = decode(data, addr)
        if decoded.status != DECODE_STATUS.OK or decoded.len == 0:
            return None        

        if decoded.op == OP.CALL:
            if decoded.operands[0] == OPER_TYPE.ADDR:
                il.append(il.call(il.const_pointer(2, decoded.operands[1])))
            else:
                # TODO: handle the conditional
                il.append(il.nop())

        elif decoded.op == OP.RET:
            il.append(il.ret(il.pop(2)))

        else:
            #il.append(il.unimplemented())
            il.append(il.nop())

        return decoded.len

