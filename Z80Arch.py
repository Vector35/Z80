#!/usr/bin/env python

import re

from binaryninja.log import log_info
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType

from z80dis.z80 import *

CC_TO_STR = {
    CC.ALWAYS:"1", CC.NOT_N:"nn", CC.N:"n", CC.NOT_Z:"nz", CC.Z:"z",
    CC.NOT_C:"nc", CC.C:"c", CC.NOT_P:"po", CC.P:"pe", CC.NOT_S:"p", CC.S:"m",
    CC.NOT_H:"nh", CC.H:"h"
}

REG_TO_STR = {
    OPER_TYPE.REG_A:"A", OPER_TYPE.REG_F:"F",
    OPER_TYPE.REG_B:"B", OPER_TYPE.REG_C:"C",
    OPER_TYPE.REG_D:"D", OPER_TYPE.REG_E:"E",
    OPER_TYPE.REG_H:"H", OPER_TYPE.REG_L:"L",
    OPER_TYPE.REG_AF:"AF",
    OPER_TYPE.REG_BC:"BC",
    OPER_TYPE.REG_DE:"DE",
    OPER_TYPE.REG_HL:"HL",

    OPER_TYPE.REG_A_:"A'", OPER_TYPE.REG_F_:"F'",
    OPER_TYPE.REG_B_:"B'", OPER_TYPE.REG_C_:"C'",
    OPER_TYPE.REG_D_:"D'", OPER_TYPE.REG_E_:"E'",
    OPER_TYPE.REG_H_:"H'", OPER_TYPE.REG_L_:"L'",
    OPER_TYPE.REG_AF_:"AF'",
    OPER_TYPE.REG_BC_:"BC'",
    OPER_TYPE.REG_DE_:"DE'",
    OPER_TYPE.REG_HL_:"HL'",

    OPER_TYPE.REG_I:"I", OPER_TYPE.REG_R:"R",
    OPER_TYPE.REG_IXH:"IXH", OPER_TYPE.REG_IXL:"IXL",
    OPER_TYPE.REG_IYH:"IYH", OPER_TYPE.REG_IYL:"IYL",
    OPER_TYPE.REG_IY:"IY",
    OPER_TYPE.REG_IX:"IX",
    OPER_TYPE.REG_SP:"SP",
    OPER_TYPE.REG_PC:"PC"
}

REG_TO_SIZE = {
    OPER_TYPE.REG_A:1, OPER_TYPE.REG_F:1,
    OPER_TYPE.REG_B:1, OPER_TYPE.REG_C:1,
    OPER_TYPE.REG_D:1, OPER_TYPE.REG_E:1,
    OPER_TYPE.REG_H:1, OPER_TYPE.REG_L:1,
    OPER_TYPE.REG_AF:2,
    OPER_TYPE.REG_BC:2,
    OPER_TYPE.REG_DE:2,
    OPER_TYPE.REG_HL:2,

    OPER_TYPE.REG_A_:1, OPER_TYPE.REG_F_:1,
    OPER_TYPE.REG_B_:1, OPER_TYPE.REG_C_:1,
    OPER_TYPE.REG_D_:1, OPER_TYPE.REG_E_:1,
    OPER_TYPE.REG_H_:1, OPER_TYPE.REG_L_:1,
    OPER_TYPE.REG_AF_:2,
    OPER_TYPE.REG_BC_:2,
    OPER_TYPE.REG_DE_:2,
    OPER_TYPE.REG_HL_:2,

    OPER_TYPE.REG_I:1, OPER_TYPE.REG_R:1,
    OPER_TYPE.REG_IXH:1, OPER_TYPE.REG_IXL:1,
    OPER_TYPE.REG_IYH:1, OPER_TYPE.REG_IYL:1,
    OPER_TYPE.REG_IY:2,
    OPER_TYPE.REG_IX:2,
    OPER_TYPE.REG_SP:2,
    OPER_TYPE.REG_PC:2
}

OPER_TYPE_DEREF_TO_REG = {
    OPER_TYPE.REG_C_DEREF:'C',
    OPER_TYPE.REG_BC_DEREF:'BC',
    OPER_TYPE.REG_DE_DEREF:'DE',
    OPER_TYPE.REG_HL_DEREF:'HL',
    OPER_TYPE.REG_SP_DEREF:'SP'
}

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
            assert oper0type == OPER_TYPE.ADDR
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
            if decoded.operands and decoded.operands[0][1] == OPER_TYPE.CON:
                # conditional returns dont' end block
                pass
            else:
                result.add_branch(BranchType.FunctionReturn)

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

                txt = 'IX' if operType == OPER_TYPE.MEM_DISPL_IX else 'IY'
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

            elif operType in [OPER_TYPE.REG_C_DEREF, OPER_TYPE.REG_BC_DEREF, OPER_TYPE.REG_DE_DEREF, \
                OPER_TYPE.REG_HL_DEREF, OPER_TYPE.REG_SP_DEREF]:

                result.append(InstructionTextToken( \
                    InstructionTextTokenType.BeginMemoryOperandToken, '('))
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.RegisterToken, OPER_TYPE_DEREF_TO_REG[operType]))
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.EndMemoryOperandToken, ')'))

            else:
                # must be register
                if not operType in REG_TO_STR:
                    print('AAAAAAA')
                    print(operType)
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

    def operand_to_il(self, operType, operVal, il):
        if operType == OPER_TYPE.ADDR:
#            if operVal < 0:
#                operVal = operVal & 0xFFFF
#            txt = '0x%04x' % operVal
#            result.append(InstructionTextToken( \
#                InstructionTextTokenType.PossibleAddressToken, txt, operVal))
            return il.unimplemented()

        elif operType == OPER_TYPE.ADDR_DEREF:
#            result.append(InstructionTextToken( \
#                InstructionTextTokenType.BeginMemoryOperandToken, '('))
#            txt = '0x%04x' % operVal
#            result.append(InstructionTextToken( \
#                InstructionTextTokenType.PossibleAddressToken, txt, operVal))
#            result.append(InstructionTextToken( \
#                InstructionTextTokenType.EndMemoryOperandToken, ')'))
            return il.unimplemented()

        elif operType in [OPER_TYPE.MEM_DISPL_IX, OPER_TYPE.MEM_DISPL_IY]:
#            result.append(InstructionTextToken( \
#                InstructionTextTokenType.BeginMemoryOperandToken, '('))
#
#            txt = 'ix' if operType == OPER_TYPE.MEM_DISPL_IX else 'iy'
#            result.append(InstructionTextToken( \
#                InstructionTextTokenType.RegisterToken, txt))

#            if operVal == 0:
#                # omit displacement of 0
#                pass
#            elif operVal >= 16:
#                # (iy+0x28)
#                result.append(InstructionTextToken( \
#                    InstructionTextTokenType.TextToken, '+'))
#                result.append(InstructionTextToken( \
#                    InstructionTextTokenType.IntegerToken, '0x%X' % operVal, operVal))
#            elif operVal > 0:
#                result.append(InstructionTextToken( \
#                    InstructionTextTokenType.TextToken, '+'))
#                result.append(InstructionTextToken( \
#                    InstructionTextTokenType.IntegerToken, '%d' % operVal, operVal))
#            elif operVal <= -16:
#                # adc a,(ix-0x55)
#                result.append(InstructionTextToken( \
#                    InstructionTextTokenType.TextToken, '-'))
#                result.append(InstructionTextToken( \
#                    InstructionTextTokenType.IntegerToken, '0x%X' % (-operVal), operVal))
#            else:
#                result.append(InstructionTextToken( \
#                    InstructionTextTokenType.IntegerToken, '%d' % operVal, operVal))
#
#            result.append(InstructionTextToken( \
#                InstructionTextTokenType.EndMemoryOperandToken, ')'))
            return il.unimplemented()

        elif operType == OPER_TYPE.IMM:
            return il.const(4, operVal)

        elif operType in [OPER_TYPE.REG_C_DEREF, OPER_TYPE.REG_BC_DEREF, OPER_TYPE.REG_DE_DEREF,
            OPER_TYPE.REG_HL_DEREF, OPER_TYPE.REG_SP_DEREF]:
#
#            lookup = {
#                OPER_TYPE.REG_C_DEREF: 'C', OPER_TYPE.REG_BC_DEREF: 'BC',
#                OPER_TYPE.REG_DE_DEREF: 'DE', OPER_TYPE.REG_HL_DEREF: 'HL',
#                OPER_TYPE.REG_SP_DEREF: 'SP'
#            }:
            return il.unimplemented()

        elif operType == OPER_TYPE.CON:
#            txt = CC_TO_STR[operVal]
#            result.append(InstructionTextToken( \
#                InstructionTextTokenType.TextToken, txt))
            return il.unimplemented()

        else:
            assert operType in REG_TO_STR
            return il.reg(REG_TO_SIZE[operType], REG_TO_STR[operType])

    def get_instruction_low_level_il(self, data, addr, il):
        def is_reg(operand):
            return operand not in [OPER_TYPE.ADDR, OPER_TYPE.ADDR_DEREF, \
                OPER_TYPE.MEM_DISPL_IX, OPER_TYPE.MEM_DISPL_IY, OPER_TYPE.IMM, \
                OPER_TYPE.CON]

        decoded = decode(data, addr)
        if decoded.status != DECODE_STATUS.OK or decoded.len == 0:
            return None

        if decoded.op == OP.CALL:
            if decoded.operands[0][0] == OPER_TYPE.ADDR:
                il.append(il.call(il.const_pointer(2, decoded.operands[0][1])))
            else:
                # TODO: handle the conditional
                il.append(il.nop())

        elif decoded.op == OP.LD:
            assert len(decoded.operands) == 2
            (ta,va) = decoded.operands[0]
            (tb,vb) = decoded.operands[1]

            if is_reg(ta) and tb == OPER_TYPE.IMM:
                il.append(il.set_reg(REG_TO_SIZE[ta], REG_TO_STR[ta], self.operand_to_il(tb,vb,il)))
            else:
                il.append(il.unimplemented())

        elif decoded.op == OP.RET:
            il.append(il.ret(il.pop(2)))

        else:
            il.append(il.unimplemented())
            #il.append(il.nop()) # these get optimized away during lifted il -> llil

        return decoded.len

