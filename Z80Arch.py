#!/usr/bin/env python

import re

from binaryninja.log import log_info
from binaryninja.lowlevelil import LowLevelILLabel, LowLevelILInstruction, ILRegister, LLIL_TEMP, LLIL_GET_TEMP_REG_INDEX, LowLevelILExpr
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType, FlagRole, LowLevelILFlagCondition, LowLevelILOperation

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

    # S - sign, set if the 2-complement value is negative (copy of msb)
    # Z - zero, set if value is zero
    # H - half carry, from bit 3 to 4
    # PV - parity when even number of bits set, overflow if 2-complement result doesn't fit in reg
    # N - subtract, set if last operation was subtraction
    # C - set if the result did not fit in register
    flags = ['s', 'z', 'h', 'pv', 'n', 'c']

#   SpecialFlagRole = 0,
#   ZeroFlagRole = 1,
#   PositiveSignFlagRole = 2,
#   NegativeSignFlagRole = 3,
#   CarryFlagRole = 4,
#   OverflowFlagRole = 5,
#   HalfCarryFlagRole = 6,
#   EvenParityFlagRole = 7,
#   OddParityFlagRole = 8,
#   OrderedFlagRole = 9,
#   UnorderedFlagRole = 10
    flag_roles = {
        's': FlagRole.NegativeSignFlagRole,
        'z': FlagRole.ZeroFlagRole,
        'h': FlagRole.HalfCarryFlagRole,
        'pv': FlagRole.SpecialFlagRole, # even parity or overflow, depending on instruction
        'n': FlagRole.SpecialFlagRole,
        'c': FlagRole.CarryFlagRole
    }

#        LLFC_E                  ==         Equal
#        LLFC_NE                 !=         Not equal
#        LLFC_SLT                s<         Signed less than
#        LLFC_ULT                u<         Unsigned less than
#        LLFC_SLE                s<=        Signed less than or equal
#        LLFC_ULE                u<=        Unsigned less than or equal
#        LLFC_SGE                s>=        Signed greater than or equal
#        LLFC_UGE                u>=        Unsigned greater than or equal
#        LLFC_SGT                s>         Signed greater than
#        LLFC_UGT                u>         Unsigned greater than
#        LLFC_NEG                -          Negative
#        LLFC_POS                +          Positive
#        LLFC_O                  overflow   Overflow
#        LLFC_NO                 !overflow  No overflow
    flags_required_for_flag_condition = {
        # S, sign flag is in NEG and POS
        #LowLevelILFlagCondition.LLFC_NEG: ['s'],
        #LowLevelILFlagCondition.LLFC_POS: ['s'],
        # Z, zero flag for == and !=
        #LowLevelILFlagCondition.LLFC_E: ['z'],
        #LowLevelILFlagCondition.LLFC_NE: ['z'],
        # H, half carry for ???
        # P, parity for ???
        # V, overflow for these, since they subtract, maybe?
        #LowLevelILFlagCondition.LLFC_SGT: ['v'],
        #LowLevelILFlagCondition.LLFC_SGE: ['v'],
        #LowLevelILFlagCondition.LLFC_SLT: ['v'],
        #LowLevelILFlagCondition.LLFC_SLE: ['v'],
        # N, for these, because it looks like NEGative :P
        #LowLevelILFlagCondition.LLFC_NEG: ['n'],
        # C, for these
        #LowLevelILFlagCondition.LLFC_UGE: ['c'],
        #LowLevelILFlagCondition.LLFC_ULT: ['c'],
    }

    # user defined id's for flag writing groups
    # eg: '*' writes all flags
    # eg: 'cvs' writes carry, overflow, sign
    # these are given to some instruction IL objects as the optional flags='*' argument
    flag_write_types = ['dummy', '*', 'c', 'z', 'cszpv', 'npv']

    flags_written_by_flag_write_type = {
        'dummy': [],
        '*': ['s', 'z', 'h', 'pv', 'n', 'c'],
        'c': ['c'],
        'z': ['z'],
        'cszpv': ['c','s','z','pv'],
        'npv': ['n','pv'] # eg: sbc
    }

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

    def cond_to_antecedent(self, cond, il):
        if cond == CC.ALWAYS:
            return il.const(1,1)

        # {'n', 'nn'} == {'negative', 'not negative'}
        if cond == CC.N:
            return il.flag('n')
        if cond == CC.NOT_N:
            return il.xor_expr(1, il.flag('n'), il.const(1,1))

        # {'z', 'nz'} == {'zero', 'not zero'}
        if cond == CC.Z:
            return il.flag('z')
        if cond == CC.NOT_Z:
            return il.xor_expr(1, il.flag('z'), il.const(1,1))

        # {'c', 'nc'} == {'carry', 'not carry'}
        if cond == CC.C:
            return il.flag('c')
        if cond == CC.NOT_C:
            return il.xor_expr(1, il.flag('c'), il.const(1,1))

        # {'pe', 'po'} == {'parity even', 'parity odd'} == {'overflow', 'no overflow'}
        if cond == CC.P:
            return il.flag('pv')
        if cond == CC.NOT_P:
            return il.xor_expr(1, il.flag('pv'), il.const(1,1))

        # {'m', 'p'} == {'minus', 'plus'} == {'sign flag set', 'sign flag clear'}
        if cond == CC.S:
            return il.flag('s')
        if cond == CC.NOT_S:
            return il.xor_expr(1, il.flag('s'), il.const(1,1))

        if cond == CC.H:
            return il.flag('h')
        if cond == CC.NOT_H:
            return il.xor_expr(1, il.flag('h'), il.const(1,1))

        raise Exception('unknown cond: ' + str(cond))

    def goto_or_jump(self, target_type, target_val, il):
        if target_type == OPER_TYPE.ADDR:
            tmp = il.get_label_for_address(Architecture['Z80'], target_val)
            if tmp:
                return il.goto(tmp)
            else:
                return il.jump(il.const_pointer(2, target_val))
        else:
            tmp = self.operand_to_il(target_type, target_val, il, 2)
            return il.jump(tmp)

    def append_conditional_instr(self, cond, instr, il):
        if cond == CC.ALWAYS:
            il.append(instr)
        else:
            ant = self.cond_to_antecedent(cond, il)
            t = LowLevelILLabel()
            f = LowLevelILLabel()
            il.append(il.if_expr(ant, t, f))
            il.mark_label(t)
            il.append(instr)
            il.mark_label(f)

    def append_conditional_jump(self, cond, target_type, target_val, il):
        # case: condition always
        if cond == CC.ALWAYS:
            il.append(goto_or_jump(target_type, target_val, il))
            return

        # case: condition and label available
        if target_type == OPER_TYPE.ADDR:
            t = il.get_label_for_address(Architecture['Z80'], target_val)
            if t:
                # if label exists, we can make it the true half of an if and
                # generate compact code
                f = LowLevelILLabel()
                ant = self.cond_to_antecedent(cond, il)
                il.append(il.if_expr(ant, t, f))
                il.mark_label(f)
                return

        # case: conditional and address available
        tmp = append(self.goto_or_jump(target_type, target_val, il))
        append_conditional_instr(cond, tmp, il)

    def operand_to_il(self, oper_type, oper_val, il, size_hint=0, peel_load=False):
        if oper_type == OPER_TYPE.REG:
            return il.reg(REG_TO_SIZE[oper_val], self.reg2str(oper_val))

        elif oper_type == OPER_TYPE.REG_DEREF:
            return il.load(size_hint, \
                self.operand_to_il(OPER_TYPE.REG, oper_val, il))

        elif oper_type == OPER_TYPE.ADDR:
            return il.const_pointer(2, oper_val)

        elif oper_type == OPER_TYPE.ADDR_DEREF:
            tmp = il.const_pointer(2, oper_val)
            if peel_load:
                return tmp
            else:
                return il.load(size_hint, tmp)

        elif oper_type in [OPER_TYPE.MEM_DISPL_IX, OPER_TYPE.MEM_DISPL_IY]:
            reg_name = 'IX' if oper_type == OPER_TYPE.MEM_DISPL_IX else 'IY'
            tmp = il.add(2, il.reg(2, reg_name), il.const(1, oper_val))
            if peel_load:
                return tmp
            else:
                return il.load(size_hint, tmp)

        elif oper_type == OPER_TYPE.IMM:
            return il.const(size_hint, oper_val)

        elif oper_type == OPER_TYPE.COND:
#            txt = CC_TO_STR[oper_val]
#            result.append(InstructionTextToken( \
#                InstructionTextTokenType.TextToken, txt))
            return il.unimplemented()

        else:
            raise Exception("unknown operand type: " + str(oper_type))

    def expressionify(self, size, foo, il, temps_are_conds=False):
        if isinstance(foo, LowLevelILExpr):
            return foo

        if isinstance(foo, ILRegister):
            if temps_are_conds and LLIL_TEMP(foo.index):
                # can't use il.reg() 'cause it will do lookup in architecture flags
                return il.expr(LowLevelILOperation.LLIL_FLAG, foo.index)
                #return il.reg(size, 'cond:%d' % LLIL_GET_TEMP_REG_INDEX(foo.index))

            # promote it to an LLIL_REG (read register)
            return il.reg(size, foo)

        elif isinstance(foo, ILFlag):
            return il.flag(foo)

        else:
            raise Exception('expressionify() doesn\'t know how to handle il: %s\n%s\n' % (foo, type(foo)))

    def gen_carry_out_expr(self, size, op, operands, il):
        # strategy: input check
        if op == LowLevelILOperation.LLIL_ADD:
            # on `s = a + b` carry out is `a > (255-b)`
            return il.compare_unsigned_greater_than(1,
                # a
                self.expressionify(size, operands[0], il),
                # 255 - b
                il.sub(1,
                    il.const(1, 255),
                    self.expressionify(size, operands[1], il)
                )
            )

        elif op == LowLevelILOperation.LLIL_ADC:
            # on `s = a + b` carry out is:
            # `a > (255-b)` when no carry in
            # `a >= (255-b)` when carry in
            #
            # equivalently:
            # ((a > 255-b) && !c) | ((a >= 255-b) && c)

            a = self.expressionify(size, operands[0], il)
            b = self.expressionify(size, operands[1], il)
            c = self.expressionify(size, operands[2], il)

            return il.or_expr(1,
                il.and_expr(1,
                    # a > (255-b)
                    il.compare_unsigned_greater_than(1, a, il.sub(1, il.const(1, 255), b)),
                    # !c
                    il.xor_expr(1, c, il.const(1,1))
                ),

                il.and_expr(1,
                    # a >= (255-b)
                    il.compare_unsigned_greater_equal(1, a, il.sub(1, il.const(1, 255), b)),
                    # c
                    c
                ),
            )

        else:
            raise Exception('gen_carry_out_expr(): %s' % op)


    def get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il):
        #print('get_flag_write_low_level_il(op=%s, flag=%s) (LLIL_RLC is: %d)' %
        #    (LowLevelILOperation(op).name, flag, LowLevelILOperation.LLIL_RLC))

        if flag == 'c':
            if op == LowLevelILOperation.LLIL_ADD:
                return self.gen_carry_out_expr(size, op, operands, il)

            if op == LowLevelILOperation.LLIL_ADC:
                return self.gen_carry_out_expr(size, op, operands, il)

            if op == LowLevelILOperation.LLIL_SUB or op == LowLevelILOperation.LLIL_SBB:

                if op == LowLevelILOperation.LLIL_SUB:
                    r = il.test_bit(1,
                            il.sub(size,
                                self.expressionify(size, operands[0], il),
                                self.expressionify(size, operands[1], il)
                            ),
                        il.const(1, 0x80)
                    )
                else:
                    r = il.test_bit(1,
                            il.sub_borrow(size,
                                self.expressionify(size, operands[0], il),
                                self.expressionify(size, operands[1], il),
                                self.expressionify(size, operands[2], il, True)
                            ),
                        il.const(1, 0x80)
                    )

                a_not = il.xor_expr(1,
                    il.test_bit(1, self.expressionify(size, operands[0], il), il.const(1, 0x80)),
                    il.const(1, 1)
                )

                b = il.test_bit(1, self.expressionify(size, operands[1], il), il.const(1, 0x80))

                return il.or_expr(1,
                    il.or_expr(1,
                        il.and_expr(1, a_not, b),
                        il.and_expr(1, b, r)
                    ),
                    il.and_expr(1, r, a_not)
                )

            # LLIL SBB from Z80's SBC


            # we use LLIL RLC to mean "rotate thru carry" from Z80's RL, RLA
            if op == LowLevelILOperation.LLIL_RLC:
                # op[0] is value to be rotated
                # op[1] is amount of rotation (always 1)
                # op[2] is carry input
                return il.test_bit(1, il.reg(size, operands[0]), il.const(1,0x80))

            # we use LLIL ROL to mean "rotate, copy MSB to carry" from Z80's RLC, RLCA
            elif op == LowLevelILOperation.LLIL_ROL:
                return il.test_bit(1, il.reg(size, operands[0]), il.const(1,0x80))


        elif flag == 'n':
            if op in [  LowLevelILOperation.LLIL_SBB,   # from z80 SBC
                        LowLevelILOperation.LLIL_SUB]:   # from z80 SUB, CP
                return il.const(1,1)
            else:
                return il.const(1,0)

        # TODO: copy expression then test output
        #elif flag == 's':
            #tmp = self.op_to_llil(op, operands, il)
            #return il.test_bit(1, tmp, il.const(1,0x80))

        # LLIL SBB from Z80's SBC
        elif flag == 'pv':
            if op == LowLevelILOperation.LLIL_ADD:
                operands = list(map(lambda x: self.expressionify(size, x, il), operands))
                r = il.test_bit(1,
                    il.add(size, operands[0], operands[1]),
                    il.const(1, 0x80)
                )

                r_not = il.xor_expr(1, r, il.const(1, 1))

                a = il.test_bit(1, self.expressionify(size, operands[0], il), il.const(1, 0x80))
                a_not = il.xor_expr(1, a, il.const(1, 1))

                b = il.test_bit(1, self.expressionify(size, operands[1], il), il.const(1, 0x80))
                b_not = il.xor_expr(1, b, il.const(1, 1))

                return il.or_expr(1,
                    il.or_expr(1,
                        il.and_expr(1, a, b),
                        il.and_expr(1, r_not, a_not)
                    ),
                    il.and_expr(1, b_not, r)
                )

            if op == LowLevelILOperation.LLIL_SUB or op == LowLevelILOperation.LLIL_SBB:

                if op == LowLevelILOperation.LLIL_SUB:
                    r = il.test_bit(1,
                            il.sub(size,
                                self.expressionify(size, operands[0], il),
                                self.expressionify(size, operands[1], il)
                            ),
                        il.const(1, 0x80)
                    )
                else:
                    r = il.test_bit(1,
                            il.sub_borrow(size,
                                self.expressionify(size, operands[0], il),
                                self.expressionify(size, operands[1], il),
                                self.expressionify(size, operands[2], il, True)
                            ),
                        il.const(1, 0x80)
                    )

                r_not = il.xor_expr(1, r, il.const(1, 1))

                a = il.test_bit(1, self.expressionify(size, operands[0], il), il.const(1, 0x80))
                a_not = il.xor_expr(1, a, il.const(1, 1))

                b = il.test_bit(1, self.expressionify(size, operands[1], il), il.const(1, 0x80))
                b_not = il.xor_expr(1, b, il.const(1, 1))

                return il.or_expr(1,
                    il.and_expr(1, il.and_expr(1, a, b_not), r_not),
                    il.and_expr(1, il.and_expr(1, a_not, b), r)
                )

            else:
                return il.const(1,1)

        return Architecture.get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il)

    def get_instruction_low_level_il(self, data, addr, il):
        decoded = decode(data, addr)
        if decoded.status != DECODE_STATUS.OK or decoded.len == 0:
            return None

        (oper_type, oper_val) = decoded.operands[0] if decoded.operands else (None, None)
        (operb_type, operb_val) = decoded.operands[1] if decoded.operands[1:] else (None, None)

        if decoded.op in [OP.ADD, OP.ADC]:
            assert len(decoded.operands) == 2
            if oper_type == OPER_TYPE.REG:
                size = REG_TO_SIZE[oper_val]
                rhs = self.operand_to_il(operb_type, operb_val, il, size)
                lhs = self.operand_to_il(oper_type, oper_val, il)
                if decoded.op == OP.ADD:
                    tmp = il.add(size, lhs, rhs, flags='*')
                else:
                    tmp = il.add_carry(size, lhs, rhs, il.flag("c"), flags='c')
                tmp = il.set_reg(size, self.reg2str(oper_val), tmp)
                il.append(tmp)
            else:
                il.append(il.unimplemented())

        elif decoded.op == OP.AND:
            tmp = il.reg(1, 'A')
            tmp = il.and_expr(1, self.operand_to_il(oper_type, oper_val, il, 1), tmp, flags='z')
            tmp = il.set_reg(1, 'A', tmp)
            il.append(tmp)

        elif decoded.op == OP.CALL:
            if oper_type == OPER_TYPE.ADDR:
                il.append(il.call(il.const_pointer(2, oper_val)))
            else:
                # TODO: handle the conditional
                il.append(il.unimplemented())

        elif decoded.op == OP.CP:
            # sub, but do not write to register
            lhs = il.reg(1, 'A')
            rhs = self.operand_to_il(oper_type, oper_val, il, 1)
            sub = il.sub(1, lhs, rhs, flags='cszpv')
            il.append(sub)

        elif decoded.op == OP.DJNZ:
            # decrement B
            tmp = il.reg(1, 'B')
            tmp = il.add(1, tmp, il.const(1,-1))
            il.append(tmp)
            # if nonzero, jump! (the "go" is built into il.if_expr)
            t = il.get_label_for_address(Architecture['Z80'], oper_val)
            f = LowLevelILLabel()
            tmp = il.compare_not_equal(1, il.reg(1, 'B'), il.const(1, 0))
            il.append(il.if_expr(tmp, t, f))
            il.mark_label(f)

        elif decoded.op == OP.INC:
            size = REG_TO_SIZE[oper_val] if oper_type == OPER_TYPE.REG else 1
            tmp = il.add(size, self.operand_to_il(oper_type, oper_val, il), il.const(1, 1))
            tmp = il.set_reg(size, self.reg2str(oper_val), tmp)
            il.append(tmp)

        elif decoded.op in [OP.JP, OP.JR]:
            if oper_type == OPER_TYPE.COND:
                self.append_conditional_jump(oper_val, operb_type, operb_val, il)
            else:
                il.append(self.goto_or_jump(oper_type, oper_val, il))

        elif decoded.op == OP.LD:
            assert len(decoded.operands) == 2

            if oper_type == OPER_TYPE.REG:
                size = REG_TO_SIZE[oper_val]
                rhs = self.operand_to_il(operb_type, operb_val, il, size)
                set_reg = il.set_reg(size, self.reg2str(oper_val), rhs)
                il.append(set_reg)
            else:
                il.append(il.unimplemented())

        elif decoded.op == OP.OR:
            tmp = il.reg(1, 'A')
            tmp = il.or_expr(1, self.operand_to_il(oper_type, oper_val, il, 1), tmp, flags='z')
            tmp = il.set_reg(1, 'A', tmp)
            il.append(tmp)

        elif decoded.op == OP.POP:
            if oper_type == OPER_TYPE.REG:
                size = REG_TO_SIZE[oper_val]
                tmp = il.pop(size)
                tmp = il.set_reg(size, self.reg2str(oper_val), tmp)
                il.append(tmp)
            else:
                il.append(il.unimplemented())

        elif decoded.op == OP.PUSH:
            if oper_type == OPER_TYPE.REG:
                il.append(il.push( \
                    REG_TO_SIZE[oper_val], \
                    self.operand_to_il(oper_type, oper_val, il)))
            else:
                print('PUSH a: ' + str(oper_type))
                il.append(il.unimplemented())

        elif decoded.op in [OP.RL, OP.RLA]:
            # rotate THROUGH carry: b0=c, c=b8
            # z80 'RL' -> llil 'RLC'
            if decoded.op == OP.RLA:
                src = il.reg(1, 'A')
            else:
                src = self.operand_to_il(oper_type, oper_val, il)

            rot = il.rotate_left_carry(1, src, il.const(1, 1), il.flag('c'), flags='c')

            if decoded.op == OP.RLA:
                il.append(il.set_reg(1, 'A', rot))
            elif oper_type == OPER_TYPE.REG:
                il.append(il.set_reg(1, self.reg2str(oper_val), rot))
            else:
                tmp = self.operand_to_il(oper_type, oper_val, il, 1, peel_load=True)
                il.append(il.store(1, tmp2, tmp))

        elif decoded.op in [OP.RLC, OP.RLCA]:
            # rotate and COPY to carry: b0=c, c=b8
            # z80 'RL' -> llil 'ROL'
            if decoded.op == OP.RLCA:
                src = il.reg(1, 'A')
            else:
                src = self.operand_to_il(oper_type, oper_val, il)

            rot = il.rotate_left(1, src, il.const(1, 1), flags='c')

            if decoded.op == OP.RLCA:
                il.append(il.set_reg(1, 'A', rot))
            elif oper_type == OPER_TYPE.REG:
                il.append(il.set_reg(1, self.reg2str(oper_val), rot))
            else:
                tmp = self.operand_to_il(oper_type, oper_val, il, 1, peel_load=True)
                il.append(il.store(1, tmp2, tmp))

        elif decoded.op == OP.RET:
            tmp = il.ret(il.pop(2))
            if decoded.operands:
                self.append_conditional_instr(decoded.operands[0][1], tmp, il)
            else:
                il.append(tmp)

        elif decoded.op == OP.SUB:
            tmp = self.operand_to_il(oper_type, oper_val, il, 1)
            tmp = il.sub(1, il.reg(1, 'A'), tmp, flags='c')
            tmp = il.set_reg(1, 'A', tmp)
            il.append(tmp)

        elif decoded.op == OP.SBC:
            size = REG_TO_SIZE[oper_val]
            lhs = self.operand_to_il(oper_type, oper_val, il, size)
            rhs = self.operand_to_il(operb_type, operb_val, il, size)
            flag = il.flag('c')
            tmp = il.sub_borrow(size, lhs, rhs, flag, flags='*')
            tmp = il.set_reg(1, 'A', tmp)
            il.append(tmp)

        elif decoded.op == OP.XOR:
            tmp = il.reg(1, 'A')
            tmp = il.xor_expr(1, self.operand_to_il(oper_type, oper_val, il, 1), tmp, flags='z')
            tmp = il.set_reg(1, 'A', tmp)
            il.append(tmp)

        else:
            il.append(il.unimplemented())
            #il.append(il.nop()) # these get optimized away during lifted il -> llil

        return decoded.len

