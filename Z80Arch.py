#!/usr/bin/env python

import re

from binaryninja.log import log_info
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType, FlagRole, LowLevelILFlagCondition

from z80dis.z80 import *

CC_TO_STR = {
    CC.ALWAYS:'1', CC.NOT_N:'nn', CC.N:'n', CC.NOT_Z:'nz', CC.Z:'z',
    CC.NOT_C:'nc', CC.C:'c', CC.NOT_P:'po', CC.P:'pe', CC.NOT_S:'p', CC.S:'m',
    CC.NOT_H:'nh', CC.H:'h'
}

REG_TO_SIZE = {
    REG.A:1, REG.F:1,
    REG.B:1, REG.C:1,
    REG.D:1, REG.E:1,
    REG.H:1, REG.L:1,
    REG.AF:2,
    REG.BC:2,
    REG.DE:2,
    REG.HL:2,

    REG.A_:1, REG.F_:1,
    REG.B_:1, REG.C_:1,
    REG.D_:1, REG.E_:1,
    REG.H_:1, REG.L_:1,
    REG.AF_:2,
    REG.BC_:2,
    REG.DE_:2,
    REG.HL_:2,

    REG.I:1, REG.R:1,
    REG.IXH:1, REG.IXL:1,
    REG.IYH:1, REG.IYL:1,
    REG.IY:2,
    REG.IX:2,
    REG.SP:2,
    REG.PC:2
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
        "AF'": RegisterInfo("AF'", 2),
        "BC'": RegisterInfo("BC'", 2),
        "DE'": RegisterInfo("DE'", 2),
        "HL'": RegisterInfo("HL'", 2),

        # main registers (sub)
        "A": RegisterInfo("AF", 1, 1),
        "F": RegisterInfo("AF", 1, 0),
        "B": RegisterInfo("BC", 1, 1),
        "C": RegisterInfo("BC", 1, 0),
        "D": RegisterInfo("DE", 1, 1),
        "E": RegisterInfo("DE", 1, 0),
        "H": RegisterInfo("HL", 1, 1),
        "L": RegisterInfo("HL", 1, 0),
        "Flags": RegisterInfo("AF", 0),

        # alternate registers (sub)
        "A'": RegisterInfo("AF'", 1, 1),
        "F'": RegisterInfo("AF'", 1, 0),
        "B'": RegisterInfo("BC'", 1, 1),
        "C'": RegisterInfo("BC'", 1, 0),
        "D'": RegisterInfo("DE'", 1, 1),
        "E'": RegisterInfo("DE'", 1, 0),
        "H'": RegisterInfo("HL'", 1, 1),
        "L'": RegisterInfo("HL'", 1, 0),
        "Flags'": RegisterInfo("AF'", 0),

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
# FLAG fun
#------------------------------------------------------------------------------

    flags = ['s', 'z', 'h', 'pv', 'n', 'c']

    # remember, class None is default/integer
    semantic_flag_classes = ['class_bitstuff']

    # flag write types and their mappings
    flag_write_types = ['dummy', '*', 'c', 'z', 'cszpv', 'not_c']
    flags_written_by_flag_write_type = {
        'dummy': [],
        '*': ['s', 'z', 'h', 'pv', 'n', 'c'],
        'c': ['c'],
        'z': ['z'],
        'not_c': ['s', 'z', 'h', 'pv', 'n'] # eg: z80's DEC
    }
    semantic_class_for_flag_write_type = {
        # by default, everything is type None (integer)
#        '*': 'class_integer',
#        'c': 'class_integer',
#        'z': 'class_integer',
#        'cszpv': 'class_integer',
#        'not_c': 'class_integer'
    }

    # groups and their mappings
    semantic_flag_groups = ['group_e', 'group_ne', 'group_lt']
    flags_required_for_semantic_flag_group = {
        'group_lt': ['c'],
        'group_e': ['z'],
        'group_ne': ['z']
    }
    flag_conditions_for_semantic_flag_group = {
        #'group_e': {None: LowLevelILFlagCondition.LLFC_E},
        #'group_ne': {None: LowLevelILFlagCondition.LLFC_NE}
    }

    # roles
    flag_roles = {
        's': FlagRole.NegativeSignFlagRole,
        'z': FlagRole.ZeroFlagRole,
        'h': FlagRole.HalfCarryFlagRole,
        'pv': FlagRole.OverflowFlagRole, # actually overflow or parity: TODO: implement later
        'n': FlagRole.SpecialFlagRole, # set if last instruction was a subtraction (incl. CP)
        'c': FlagRole.CarryFlagRole
    }

    # MAP (condition x class) -> flags
    def get_flags_required_for_flag_condition(self, cond, sem_class):
        #LogDebug('incoming cond: %s, incoming sem_class: %s' % (str(cond), str(sem_class)))

        if sem_class == None:
            lookup = {
                # Z, zero flag for == and !=
                LowLevelILFlagCondition.LLFC_E: ['z'],
                LowLevelILFlagCondition.LLFC_NE: ['z'],
                # S, sign flag is in NEG and POS
                LowLevelILFlagCondition.LLFC_NEG: ['s'],
                # Z, zero flag for == and !=
                LowLevelILFlagCondition.LLFC_E: ['z'],
                LowLevelILFlagCondition.LLFC_NE: ['z'],
                # H, half carry for ???
                # P, parity for ???
                # s> s>= s< s<= done by sub and overflow test
                #if cond == LowLevelILFlagCondition.LLFC_SGT:
                #if cond == LowLevelILFlagCondition.LLFC_SGE:
                #if cond == LowLevelILFlagCondition.LLFC_SLT:
                #if cond == LowLevelILFlagCondition.LLFC_SLE:

                # C, for these
                LowLevelILFlagCondition.LLFC_UGE: ['c'],
                LowLevelILFlagCondition.LLFC_ULT: ['c']
            }

            if cond in lookup:
                return lookup[cond]

        return []

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
            (oper_type, oper_val) = decoded.operands[0]

            # jp pe,0xDEAD
            if oper_type == OPER_TYPE.COND:
                assert decoded.operands[1][0] == OPER_TYPE.ADDR
                result.add_branch(BranchType.TrueBranch, decoded.operands[1][1])
                result.add_branch(BranchType.FalseBranch, addr + decoded.len)
            # jp (hl); jp (ix); jp (iy)
            elif oper_type in [OPER_TYPE.REG_DEREF, OPER_TYPE.MEM_DISPL_IX, OPER_TYPE.MEM_DISPL_IY]:
                result.add_branch(BranchType.IndirectBranch)
            # jp 0xDEAD
            elif oper_type == OPER_TYPE.ADDR:
                result.add_branch(BranchType.UnconditionalBranch, oper_val)
            else:
                raise Exception('handling JP')

        # jr can be conditional
        elif decoded.op == OP.JR:
            (oper_type, oper_val) = decoded.operands[0]

            # jr c,0xdf07
            if oper_type == OPER_TYPE.COND:
                assert decoded.operands[1][0] == OPER_TYPE.ADDR
                result.add_branch(BranchType.TrueBranch, decoded.operands[1][1])
                result.add_branch(BranchType.FalseBranch, addr + decoded.len)
            # jr 0xdf07
            elif oper_type == OPER_TYPE.ADDR:
                result.add_branch(BranchType.UnconditionalBranch, oper_val)
            else:
                raise Exception('handling JR')

        # djnz is implicitly conditional
        elif decoded.op == OP.DJNZ:
            (oper_type, oper_val) = decoded.operands[0]
            assert oper_type == OPER_TYPE.ADDR
            result.add_branch(BranchType.TrueBranch, oper_val)
            result.add_branch(BranchType.FalseBranch, addr + decoded.len)

        # call can be conditional
        elif decoded.op == OP.CALL:
            (oper_type, oper_val) = decoded.operands[0]
            # call c,0xdf07
            if oper_type == OPER_TYPE.COND:
                assert decoded.operands[1][0] == OPER_TYPE.ADDR
                result.add_branch(BranchType.CallDestination, decoded.operands[1][1])
            # call 0xdf07
            elif oper_type == OPER_TYPE.ADDR:
                result.add_branch(BranchType.CallDestination, oper_val)
            else:
                raise Exception('handling CALL')

        # ret can be conditional
        elif decoded.op == OP.RET:
            if decoded.operands and decoded.operands[0][0] == OPER_TYPE.COND:
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

    def reg2str(self, r):
        reg_name = r.name
        return reg_name if reg_name[-1] != '_' else reg_name[:-1]+"'"

# from api/python/function.py:
#
#        TextToken                  Text that doesn't fit into the other tokens
#        InstructionToken           The instruction mnemonic
#        OperandSeparatorToken      The comma or whatever else separates tokens
#        RegisterToken              Registers
#        IntegerToken               Integers
#        PossibleAddressToken       Integers that are likely addresses
#        BeginMemoryOperandToken    The start of memory operand
#        EndMemoryOperandToken      The end of a memory operand
#        FloatingPointToken         Floating point number
    def get_instruction_text(self, data, addr):
        decoded = decode(data, addr)
        if decoded.status != DECODE_STATUS.OK or decoded.len == 0:
            return None

        result = []

        # opcode
        result.append(InstructionTextToken( \
            InstructionTextTokenType.InstructionToken, decoded.op.name))

        # space for operand
        if decoded.operands:
            result.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))

        # operands
        for i, operand in enumerate(decoded.operands):
            (oper_type, oper_val) = operand

            if oper_type == OPER_TYPE.REG:
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.RegisterToken, self.reg2str(oper_val)))

            elif oper_type == OPER_TYPE.REG_DEREF:
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.BeginMemoryOperandToken, '('))
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.RegisterToken, self.reg2str(oper_val)))
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.EndMemoryOperandToken, ')'))

            elif oper_type == OPER_TYPE.ADDR:
                if oper_val < 0:
                    oper_val = oper_val & 0xFFFF
                txt = '0x%04x' % oper_val
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.PossibleAddressToken, txt, oper_val))

            elif oper_type == OPER_TYPE.ADDR_DEREF:
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.BeginMemoryOperandToken, '('))
                txt = '0x%04x' % oper_val
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.PossibleAddressToken, txt, oper_val))
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.EndMemoryOperandToken, ')'))

            elif oper_type in [OPER_TYPE.MEM_DISPL_IX, OPER_TYPE.MEM_DISPL_IY]:
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.BeginMemoryOperandToken, '('))

                txt = 'IX' if oper_type == OPER_TYPE.MEM_DISPL_IX else 'IY'
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.RegisterToken, txt))

                if oper_val == 0:
                    # omit displacement of 0
                    pass
                elif oper_val >= 16:
                    # (iy+0x28)
                    result.append(InstructionTextToken( \
                        InstructionTextTokenType.TextToken, '+'))
                    result.append(InstructionTextToken( \
                        InstructionTextTokenType.IntegerToken, '0x%X' % oper_val, oper_val))
                elif oper_val > 0:
                    result.append(InstructionTextToken( \
                        InstructionTextTokenType.TextToken, '+'))
                    result.append(InstructionTextToken( \
                        InstructionTextTokenType.IntegerToken, '%d' % oper_val, oper_val))
                elif oper_val <= -16:
                    # adc a,(ix-0x55)
                    result.append(InstructionTextToken( \
                        InstructionTextTokenType.TextToken, '-'))
                    result.append(InstructionTextToken( \
                        InstructionTextTokenType.IntegerToken, '0x%X' % (-oper_val), oper_val))
                else:
                    result.append(InstructionTextToken( \
                        InstructionTextTokenType.IntegerToken, '%d' % oper_val, oper_val))

                result.append(InstructionTextToken( \
                    InstructionTextTokenType.EndMemoryOperandToken, ')'))

            elif oper_type == OPER_TYPE.IMM:
                if oper_val == 0:
                    txt = '0'
                elif oper_val >= 16:
                    txt = '0x%x' % oper_val
                else:
                    txt = '%d' % oper_val

                result.append(InstructionTextToken( \
                    InstructionTextTokenType.IntegerToken, txt, oper_val))

            elif oper_type == OPER_TYPE.COND:
                txt = CC_TO_STR[oper_val]
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.TextToken, txt))

            elif oper_type in [OPER_TYPE.REG_C_DEREF, OPER_TYPE.REG_BC_DEREF, OPER_TYPE.REG_DE_DEREF, \
                OPER_TYPE.REG_HL_DEREF, OPER_TYPE.REG_SP_DEREF]:

                result.append(InstructionTextToken( \
                    InstructionTextTokenType.BeginMemoryOperandToken, '('))
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.RegisterToken, self.reg2str(oper_val)))
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.EndMemoryOperandToken, ')'))

            else:
                raise Exception('unknown operand type: ' + str(oper_type))

            # if this isn't the last operand, add comma
            if i < len(decoded.operands)-1:
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.OperandSeparatorToken, ','))

        # crazy undoc shit
        if decoded.metaLoad:
            extras = []
            (oper_type, oper_val) = decoded.metaLoad
            assert oper_type == OPER_TYPE.REG
            extras.append(InstructionTextToken( \
                InstructionTextTokenType.InstructionToken, 'ld'))
            extras.append(InstructionTextToken( \
                InstructionTextTokenType.TextToken, ' '))
            extras.append(InstructionTextToken( \
                InstructionTextTokenType.RegisterToken, self.reg2str(oper_val)))
            extras.append(InstructionTextToken( \
                InstructionTextTokenType.OperandSeparatorToken, ','))

            result = extras + result

        return result, decoded.len

#------------------------------------------------------------------------------
# LIFTING
#------------------------------------------------------------------------------
    def operand_to_il(self, oper_type, oper_val, il, size_hint=0, ignore_load=False):
        if oper_type == OPER_TYPE.REG:
            return il.reg(REG_TO_SIZE[oper_val], reg2str(oper_val))

        elif oper_type == OPER_TYPE.REG_DEREF:
            tmp = operand_to_il(OPER_TYPE.REG, oper_val, il, size_hint)
            if ignore_load:
                return tmp
            else:
                return il.load(size_hint, tmp)

        elif oper_type == OPER_TYPE.ADDR:
            return il.const_pointer(2, oper_val)

        elif oper_type == OPER_TYPE.ADDR_DEREF:
            tmp = il.const_pointer(2, oper_val)
            if ignore_load:
                return tmp
            else:
                return il.load(size_hint, tmp)

        elif oper_type in [OPER_TYPE.MEM_DISPL_IX, OPER_TYPE.MEM_DISPL_IY]:
            reg_name = 'IX' if oper_type == OPER_TYPE.MEM_DISPL_IX else 'IY'
            tmp = il.add(2, il.reg(2, reg_name), il.const(1, oper_val))
            if ignore_load:
                return tmp
            else:
                return il.load(size_hint, tmp)

        elif oper_type == OPER_TYPE.IMM:
            return il.const(size_hint, oper_val)

        elif oper_type == OPER_TYPE.COND:
            return il.unimplemented()

        else:
            raise Exception("unknown operand type: " + str(oper_type))

    def get_instruction_low_level_il(self, data, addr, il):
        decoded = decode(data, addr)
        if decoded.status != DECODE_STATUS.OK or decoded.len == 0:
            return None

        expr = None

        if decoded.op == OP.NOP:
            expr = il.nop()

        elif decoded.op == OP.PUSH:
            if decoded.operands:
                (oper_type, oper_val) = decoded.operands[0]
                if oper_type == OPER_TYPE.REG:
                    size = REG_TO_SIZE[oper_val]
                    subexpr = self.operand_to_il(oper_type, oper_val, il, size)
                    expr = il.push(size, subexpr)

        elif decoded.op == OP.LD:
            (oper_type, oper_val) = decoded.operands[0]
            (operb_type, operb_val) = decoded.operands[1]

            if oper_type == OPER_TYPE.REG:
                size = REG_TO_SIZE[oper_val]
                subexpr = None

                if operb_type == OPER_TYPE.IMM:
                    if size == 2 and operb_val != 0:
                        subexpr = il.const_pointer(2, operb_val)
                    else:
                        subexpr = il.const(size, operb_val)

                    expr = il.set_reg(size, reg2str(oper_val), subexpr)

            elif oper_type == OPER_TYPE.ADDR_DEREF:
                if operb_type == OPER_TYPE.REG:
                    size = REG_TO_SIZE[operb_val]
                    src = self.operand_to_il(operb_type, operb_val, il, size)
                    dst = self.operand_to_il(oper_type, oper_val, il, size, True)
                    il.append(il.store(size, dst, src))

        if not expr:
            expr = il.unimplemented()

        il.append(expr)

        return decoded.len

