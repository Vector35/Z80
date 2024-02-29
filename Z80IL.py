#!/usr/bin/env python
#
# separate module for lifting, two main exports:
# gen_flag_il()
# gen_instr_il()

# Binja includes
from binaryninja.log import log_info
from binaryninja.architecture import Architecture
from binaryninja.enums import LowLevelILOperation, LowLevelILFlagCondition
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.lowlevelil import LowLevelILLabel, ILRegister, ILFlag, LLIL_TEMP, LLIL_GET_TEMP_REG_INDEX

# decode/disassemble
from z80dis.z80 import *

#------------------------------------------------------------------------------
# LOOKUP TABLES
#------------------------------------------------------------------------------

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

CC_UN_NOT = {
    CC.NOT_N:CC.N, CC.NOT_Z:CC.Z, CC.NOT_C:CC.C,
    CC.NOT_P:CC.P, CC.NOT_S:CC.S, CC.NOT_H:CC.H
}

#------------------------------------------------------------------------------
# HELPERS
#------------------------------------------------------------------------------

def jcc_to_flag_cond(cond, il):
    if cond == CC.ALWAYS:
        return il.const(1,1)

    # {'n', 'nn'} == {'negative', 'not negative'}
    if cond == CC.N:
        return il.flag('n')
    if cond == CC.NOT_N:
        return il.not_expr(0, il.flag('n'))

    # {'z', 'nz'} == {'zero', 'not zero'}
    if cond == CC.Z:
        return il.flag_condition(LowLevelILFlagCondition.LLFC_E)
    if cond == CC.NOT_Z:
        return il.flag_condition(LowLevelILFlagCondition.LLFC_NE)

    # {'c', 'nc'} == {'carry', 'not carry'}
    if cond == CC.C:
        return il.flag('c')
    if cond == CC.NOT_C:
        return il.not_expr(0, il.flag('c'))

    # {'pe', 'po'} == {'parity even', 'parity odd'} == {'overflow', 'no overflow'}
    if cond == CC.P:
        return il.flag('pv')
        #return il.flag_condition(LowLevelILFlagCondition.LLFC_SLE)
    if cond == CC.NOT_P:
        return il.not_expr(0, il.flag('pv'))
        #return il.flag_condition(LowLevelILFlagCondition.LLFC_SGT)

    # {'m', 'p'} == {'minus', 'plus'} == {'sign flag set', 'sign flag clear'}
    if cond == CC.S:
        return il.flag('s')
    if cond == CC.NOT_S:
        return il.not_expr(0, il.flag('s'))

    if cond == CC.H:
        return il.flag('h')
    if cond == CC.NOT_H:
        return il.not_expr(0, il.flag('h'))

    raise Exception('unknown cond: ' + str(cond))

def goto_or_jump(target_type, target_val, il):
    if target_type == OPER_TYPE.ADDR:
        tmp = il.get_label_for_address(Architecture['Z80'], target_val)
        if tmp:
            return il.goto(tmp)
        else:
            return il.jump(il.const_pointer(2, target_val))
    else:
        tmp = operand_to_il(target_type, target_val, il, 2)
        return il.jump(tmp)

def append_conditional_instr(cond, instr, il):
    if cond == CC.ALWAYS:
        il.append(instr)
    else:
        t = LowLevelILLabel()
        f = LowLevelILLabel()
        #if cond in CC_UN_NOT:
        #    ant = jcc_to_flag_cond(CC_UN_NOT[cond], il)
        #    il.append(il.if_expr(ant, f, t))
        #else:
        ant = jcc_to_flag_cond(cond, il)
        il.append(il.if_expr(ant, t, f))
        il.mark_label(t)
        il.append(instr)
        il.mark_label(f)

def append_conditional_jump(cond, target_type, target_val, addr_fallthru, il):
    # case: condition always
    if cond == CC.ALWAYS:
        il.append(goto_or_jump(target_type, target_val, il))
        return

    # case: condition and label available
    if target_type == OPER_TYPE.ADDR:
        t = il.get_label_for_address(Architecture['Z80'], target_val)
        f = il.get_label_for_address(Architecture['Z80'], addr_fallthru)
        if t and f:
            #if cond in CC_UN_NOT:
            #    ant = jcc_to_flag_cond(CC_UN_NOT[cond], il)
            #    il.append(il.if_expr(ant, f, t))
            #else:
            ant = jcc_to_flag_cond(cond, il)
            il.append(il.if_expr(ant, t, f))
            return

    # case: conditional and address available
    tmp = goto_or_jump(target_type, target_val, il)
    append_conditional_instr(cond, tmp, il)

def operand_to_il(oper_type, oper_val, il, size_hint=0, peel_load=False):
    if oper_type == OPER_TYPE.REG:
        return il.reg(REG_TO_SIZE[oper_val], reg2str(oper_val))

    elif oper_type == OPER_TYPE.REG_DEREF:
        tmp = operand_to_il(OPER_TYPE.REG, oper_val, il, size_hint)
        if peel_load:
            return tmp
        else:
            return il.load(size_hint, tmp)

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
        return il.unimplemented()

    else:
        raise Exception("unknown operand type: " + str(oper_type))

def exchange(lhs_reg, rhs_reg, il):
    # temp0 = lhs
    il.append(il.expr(LowLevelILOperation.LLIL_SET_REG,
        LLIL_TEMP(0),
        il.reg(2, lhs_reg),
        size = 2
    ))

    # lhs = rhs
    il.append(il.set_reg(2,
        lhs_reg,
        il.reg(2, rhs_reg)
    ))

    # rhs = temp0
    il.append(il.set_reg(2,
        rhs_reg,
        il.expr(LowLevelILOperation.LLIL_REG, LLIL_TEMP(0), 2)
    ))

def expressionify(size, foo, il, temps_are_conds=False):
    """ turns the "reg or constant"  operands to get_flag_write_low_level_il()
        into lifted expressions """
    if isinstance(foo, ILRegister):
        # LowLevelILExpr is different than ILRegister
        if temps_are_conds and LLIL_TEMP(foo.index):
            # can't use il.reg() 'cause it will do lookup in architecture flags
            return il.expr(LowLevelILOperation.LLIL_FLAG, foo.index)
            #return il.reg(size, 'cond:%d' % LLIL_GET_TEMP_REG_INDEX(foo))

        # promote it to an LLIL_REG (read register)
        return il.reg(size, foo)

    elif isinstance(foo, ILFlag):
        return il.flag(foo)

    elif isinstance(foo, int):
        return il.const(size, foo)

    else:
        raise Exception('expressionify() doesn\'t know how to handle il: %s\n%s\n' % (foo, type(foo)))

#------------------------------------------------------------------------------
# FLAG LIFTING
#------------------------------------------------------------------------------
#        il.append(il.set_flag('z', il.xor_expr(1, il.test_bit(1, operand, mask), il.const(1, 1))))
#        il.append(il.set_flag('n', il.const(0, 0)))
#        il.append(il.set_flag('h', il.const(0, 0)))

def gen_flag_il(op, size, write_type, flag, operands, il):
    if flag == 'c':
        if op == LowLevelILOperation.LLIL_SBB:
            return il.compare_signed_greater_than(size,
                il.add(size,
                    expressionify(size, operands[1], il),
                    expressionify(1, operands[2], il, True)
                ),
                expressionify(size, operands[0], il)
            )

        if op == LowLevelILOperation.LLIL_OR:
            return il.const(1, 0)
        if op == LowLevelILOperation.LLIL_ASR:
            return il.test_bit(1, expressionify(size, operands[0], il), il.const(1, 1))
        if op == LowLevelILOperation.LLIL_RLC:
            return il.test_bit(1, il.reg(size, operands[0]), il.const(1, 0x80))
        if op == LowLevelILOperation.LLIL_ROL:
            return il.test_bit(1, il.reg(size, operands[0]), il.const(1, 0x80))
        if op == LowLevelILOperation.LLIL_RRC:
            return il.test_bit(1, il.reg(size, operands[0]), il.const(1, 1))
        if op == LowLevelILOperation.LLIL_ROR:
            return il.test_bit(1, il.reg(size, operands[0]), il.const(1, 1))
        if op == LowLevelILOperation.LLIL_XOR:
            return il.const(1, 0)

    if flag == 'h':
        if op == LowLevelILOperation.LLIL_XOR:
            return il.const(1, 0)
        if op == LowLevelILOperation.LLIL_OR:
            return il.const(1, 0)
        if op == LowLevelILOperation.LLIL_ADD:
            # we've overflowed bottom nybble if it's lower after an add
            original_bottom_nybble = il.and_expr(size, expressionify(size, operands[0], il), il.const(size, 0x0F))
            result = il.add(size, expressionify(size, operands[0], il), expressionify(size, operands[1], il))
            result_bottom_nybble = il.and_expr(size, result, il.const(size, 0x0F))
            return il.compare_unsigned_less_than(size, result_bottom_nybble, original_bottom_nybble)
        if op == LowLevelILOperation.LLIL_ADC:
            # we've overflowed bottom nybble if it's lower after an adc
            original_bottom_nybble = il.and_expr(size, expressionify(size, operands[0], il), il.const(size, 0x0F))
            result = il.add_carry(size, expressionify(size, operands[0], il), expressionify(size, operands[1], il), il.flag("c"))
            result_bottom_nybble = il.and_expr(size, result, il.const(size, 0x0F))
            return il.compare_unsigned_less_than(size, result_bottom_nybble, original_bottom_nybble)
        if op == LowLevelILOperation.LLIL_SUB:
            # we've overflowed bottom nybble if it's higher after a sub
            original_bottom_nybble = il.and_expr(size, expressionify(size, operands[0], il), il.const(size, 0x0F))
            result = il.sub(size, expressionify(size, operands[0], il), expressionify(size, operands[1], il))
            result_bottom_nybble = il.and_expr(size, result, il.const(size, 0x0F))
            return il.compare_unsigned_greater_than(size, result_bottom_nybble, original_bottom_nybble)
        if op == LowLevelILOperation.LLIL_SBB:
            # we've overflowed bottom nybble if it's higher after a sbc
            original_bottom_nybble = il.and_expr(size, expressionify(size, operands[0], il), il.const(size, 0x0F))
            result = il.sub_borrow(size, expressionify(size, operands[0], il), expressionify(size, operands[1], il), il.flag("c"))
            result_bottom_nybble = il.and_expr(size, result, il.const(size, 0x0F))
            return il.compare_unsigned_greater_than(size, result_bottom_nybble, original_bottom_nybble)
        if op == LowLevelILOperation.LLIL_NEG:
            # if bottom nybble != 0 then we've had to borrow and therefore h needs to be set
            bottom_nybble = il.and_expr(size, expressionify(size, operands[0], il), il.const(size, 0x0F))
            return il.compare_not_equal(size, bottom_nybble, il.const(size, 0x00))

    if flag == 'n':
        if op == LowLevelILOperation.LLIL_XOR:
            return il.const(1, 0)
        if op == LowLevelILOperation.LLIL_OR:
            return il.const(1, 0)
        if op in [LowLevelILOperation.LLIL_ADD, LowLevelILOperation.LLIL_ADC]:
            return il.const(1, 0)
        if op in [LowLevelILOperation.LLIL_SUB, LowLevelILOperation.LLIL_SBB, LowLevelILOperation.LLIL_NEG]:
            return il.const(1, 1)

    if flag == 'pv':
        if op == LowLevelILOperation.LLIL_SBB:
            a = expressionify(size, operands[0], il)
            b = expressionify(size, operands[1], il)
            c = il.flag('c')

            zero = il.const(1, 0)
            result = il.sub(size, il.sub(size, a, b), c)
            subtrahend = il.add(size, b, c)

            return il.or_expr(0,
                il.and_expr(0,
                    # a>0 && (b+c)<0
                    il.and_expr(0,
                        il.compare_signed_greater_than(size, a, zero),
                        il.compare_signed_less_than(size, subtrahend, zero)
                    ),
                    # (a-(b+c))<0
                    il.compare_signed_less_than(size, result, zero)
                ),
                il.and_expr(0,
                    # a<0 && (b+c>0
                    il.and_expr(0,
                        il.compare_signed_less_than(size, a, zero),
                        il.compare_signed_greater_than(size, subtrahend, zero)
                    ),
                    # (a-(b+c))>0
                    il.compare_signed_greater_than(size, result, zero)
                )
            )


        if op == LowLevelILOperation.LLIL_XOR:
            assert size == 1
            result = il.xor_expr(size, expressionify(size, operands[0], il), expressionify(size, operands[1], il))
            # combine top4 and bottom4 bits
            top4 = il.logical_shift_right(size, result, il.const(1, 4))
            bot4 = il.and_expr(size, result, il.const(1, 0x0F))
            parity4 = il.xor_expr(size, top4, bot4)
            # combine top2 and bottom2 bits
            top2 = il.logical_shift_right(size, parity4, il.const(1, 2))
            bot2 = il.and_expr(size, parity4, il.const(1, 0x03))
            parity2 = il.xor_expr(size, top2, bot2)
            # combine top1 and bottom1 bits
            top1 = il.logical_shift_right(size, parity2, il.const(1, 1))
            bot1 = il.and_expr(size, parity2, il.const(1, 0x01))
            parity1 = il.xor_expr(size, top1, bot1)

            return il.compare_equal(size, parity1, il.const(size, 0))
        if op == LowLevelILOperation.LLIL_OR:
            assert size == 1
            result = il.or_expr(size, expressionify(size, operands[0], il), expressionify(size, operands[1], il))
            # combine top4 and bottom4 bits
            top4 = il.logical_shift_right(size, result, il.const(1, 4))
            bot4 = il.and_expr(size, result, il.const(1, 0x0F))
            parity4 = il.xor_expr(size, top4, bot4)
            # combine top2 and bottom2 bits
            top2 = il.logical_shift_right(size, parity4, il.const(1, 2))
            bot2 = il.and_expr(size, parity4, il.const(1, 0x03))
            parity2 = il.xor_expr(size, top2, bot2)
            # combine top1 and bottom1 bits
            top1 = il.logical_shift_right(size, parity2, il.const(1, 1))
            bot1 = il.and_expr(size, parity2, il.const(1, 0x01))
            parity1 = il.xor_expr(size, top1, bot1)

            return il.compare_equal(size, parity1, il.const(size, 0))

    if flag == 's':
        if op == LowLevelILOperation.LLIL_SBB:
            return il.compare_signed_less_than(size,
                il.sub(size,
                    il.sub(size,
                        expressionify(size, operands[0], il),
                        expressionify(size, operands[1], il),
                    ),
                    il.flag('c')
                ),
                il.const(1, 0)
            )

    if flag == 'z':
        if op == LowLevelILOperation.LLIL_XOR:
            return il.compare_equal(size,
                il.xor_expr(size,
                    expressionify(size, operands[0], il),
                    expressionify(size, operands[1], il),
                ),
                il.const(1, 0)
            )

    return None

#------------------------------------------------------------------------------
# INSTRUCTION LIFTING
#------------------------------------------------------------------------------

def gen_instr_il(addr, decoded, il):
    (oper_type, oper_val) = decoded.operands[0] if decoded.operands else (None, None)
    (operb_type, operb_val) = decoded.operands[1] if decoded.operands[1:] else (None, None)

    if decoded.op in [OP.ADD, OP.ADC]:
        assert len(decoded.operands) == 2
        if oper_type == OPER_TYPE.REG:
            size = REG_TO_SIZE[oper_val]
            rhs = operand_to_il(operb_type, operb_val, il, size)
            lhs = operand_to_il(oper_type, oper_val, il)
            if decoded.op == OP.ADD:
                tmp = il.add(size, lhs, rhs, flags='*')
            else:
                tmp = il.add_carry(size, lhs, rhs, il.flag("c"), flags='*')
            tmp = il.set_reg(size, reg2str(oper_val), tmp)
            il.append(tmp)
        else:
            # this shouldn't ever be hit as all the opcodes have lhs = register
            il.append(il.unimplemented())

    elif decoded.op == OP.AND:
        tmp = il.reg(1, 'A')
        tmp = il.and_expr(1, operand_to_il(oper_type, oper_val, il, 1), tmp, flags='z')
        tmp = il.set_reg(1, 'A', tmp)
        il.append(tmp)

    elif decoded.op == OP.BIT:
        assert oper_type == OPER_TYPE.IMM
        assert oper_val >= 0 and oper_val <= 7
        mask = il.const(1, 1<<oper_val)
        operand = operand_to_il(operb_type, operb_val, il, 1)
        il.append(il.and_expr(1, operand, mask, flags='z'))
        il.append(il.set_flag('h', il.const(1, 1)))
        il.append(il.set_flag('n', il.const(1, 0)))

    elif decoded.op == OP.CALL:
        if oper_type == OPER_TYPE.ADDR:
            il.append(il.call(il.const_pointer(2, oper_val)))
        else:
            tmp = il.call(il.const_pointer(2, operb_val))
            append_conditional_instr(oper_val, tmp, il)

    elif decoded.op == OP.CCF:
        il.append(il.set_flag('c', il.not_expr(0, il.flag('c'))))

    elif decoded.op == OP.CP:
        # sub, but do not write to register
        lhs = il.reg(1, 'A')
        rhs = operand_to_il(oper_type, oper_val, il, 1)
        sub = il.sub(1, lhs, rhs, flags='*')
        il.append(sub)

    elif decoded.op == OP.CPL:
        tmp = il.reg(1, 'A')
        tmp = il.xor_expr(1, il.const(1, 0xFF), tmp, flags='*')
        tmp = il.set_reg(1, 'A', tmp)
        il.append(tmp)

    elif decoded.op == OP.DAA:
        # correct BCD after arithmetic
        # based on page 17-18 http://www.z80.info/zip/z80-documented.pdf
        # and pseudocode from https://stackoverflow.com/questions/8119577/z80-daa-instruction/57837042#57837042

        # first step, find diff
        # initialise to 0
        diff = LLIL_TEMP(0)
        il.append(il.set_reg(1, diff, il.const(1, 0)))

        # lower carry
        # if lower nybble > 9 OR H flag set then we diff by 0x06
        label_add_6 = LowLevelILLabel()
        label_dont_add_6 = LowLevelILLabel()
        lower_nybble = il.xor_expr(1, il.const(1, 0x0F), il.reg(1, 'A'))
        cond_gt_9 = il.compare_unsigned_greater_than(1, lower_nybble, il.const(1, 0x09))
        cond_hf_set = il.flag('h')
        cond = il.or_expr(1, cond_gt_9, cond_hf_set)

        il.append(il.if_expr(cond, label_add_6, label_dont_add_6))
        il.mark_label(label_add_6)
        il.append(il.set_reg(1, diff, il.add(1, il.reg(1, diff), il.const(1, 0x06))))
        il.mark_label(label_dont_add_6)

        # upper carry
        # if byte > 0x99 or C flag set then we diff by 0x60
        label_add_60 = LowLevelILLabel()
        label_dont_add_60 = LowLevelILLabel()
        cond_gt_99 = il.compare_unsigned_greater_than(1, il.reg(1, 'A'), il.const(1, 0x99))
        cond_cf_set = il.flag('c')
        cond = il.or_expr(1, cond_gt_99, cond_cf_set)

        il.append(il.if_expr(cond, label_add_60, label_dont_add_60))
        il.mark_label(label_add_60)
        il.append(il.set_reg(1, diff, il.add(1, il.reg(1, diff), il.const(1, 0x60))))
        # set C flag here now as this is also the condition
        # we never reset it but we do set it if we make a high nybble adjustment
        il.append(il.set_flag('c', il.const(1, 1)))
        il.mark_label(label_dont_add_60)

        # set h flag
        # ideally the flag should evaluate to an expression that looks good in an if statement in HLIL
        # i suspect these flags never get queried
        # TODO implement h flag

        # apply adjustment
        label_neg_diff = LowLevelILLabel()
        label_add_diff = LowLevelILLabel()

        il.append(il.if_expr(il.flag('n'), label_neg_diff, label_add_diff))
        il.mark_label(label_neg_diff)
        il.append(il.set_reg(1, diff, il.neg_expr(1, il.reg(1, diff))))
        il.mark_label(label_add_diff)
        il.append(il.set_reg(1, 'A', il.add(1, il.reg(1, 'A'), il.reg(1, diff), 'z')))

        # TODO s and pv flags

    elif decoded.op == OP.DJNZ:
        # decrement B
        tmp = il.reg(1, 'B')
        tmp = il.add(1, tmp, il.const(1,-1))
        tmp = il.set_reg(1, 'B', tmp)
        il.append(tmp)
        # if nonzero, jump! (the "go" is built into il.if_expr)
        t = il.get_label_for_address(Architecture['Z80'], oper_val)
        if not t:
            il.append(il.unimplemented())
            return
        f = il.get_label_for_address(Architecture['Z80'], addr + decoded.len)
        if not f:
            il.append(il.unimplemented())
            return
        tmp = il.compare_not_equal(1, il.reg(1, 'B'), il.const(1, 0))
        il.append(il.if_expr(tmp, t, f))

    elif decoded.op == OP.EX:
        if oper_val == REG.AF:
            # special case, EX AF, AF'
            # build lhs from flags & A
            lhs = il.or_expr(2,
                il.or_expr(1,
                    il.or_expr(1,
                        il.shift_left(1, il.flag('s'), il.const(1, 7)),
                        il.shift_left(1, il.flag('z'), il.const(1, 6))
                    ),
                    il.or_expr(1,
                        il.or_expr(1,
                            il.shift_left(1, il.flag('h'), il.const(1, 4)),
                            il.shift_left(1, il.flag('pv'), il.const(1, 2))
                        ),
                        il.or_expr(1,
                            il.shift_left(1, il.flag('n'), il.const(1, 1)),
                            il.flag('c')
                        )
                    )
                ),
                il.shift_left(2,
                    il.reg(1, 'A'),
                    il.const(1, 8)
                )
            )
            # temp0 = lhs
            il.append(il.expr(LowLevelILOperation.LLIL_SET_REG,
                LLIL_TEMP(0),
                lhs,
                size = 2
            ))

            # lhs = rhs
            rhs = il.reg(2, "AF'")

            # copy across AF' and do flags at the end
            # we only care if A gets set, F doesn't matter
            il.append(il.set_reg(2,
                'AF',
                rhs
            ))

            # rhs = temp0
            il.append(il.set_reg(2,
                "AF'",
                il.expr(LowLevelILOperation.LLIL_REG, LLIL_TEMP(0), 2)
            ))

            # do flags last
            il.append(il.set_flag('c', il.test_bit(2, il.reg(1, 'F'), il.const(1, 1))))
            il.append(il.set_flag('h', il.test_bit(2, il.reg(1, 'F'), il.const(1, 1<<4))))
            il.append(il.set_flag('n', il.test_bit(2, il.reg(1, 'F'), il.const(1, 1<<1))))
            il.append(il.set_flag('pv', il.test_bit(2, il.reg(1, 'F'), il.const(1, 1<<2))))
            il.append(il.set_flag('s', il.test_bit(2, il.reg(1, 'F'), il.const(1, 1<<7))))
            il.append(il.set_flag('z', il.test_bit(2, il.reg(1, 'F'), il.const(1, 1<<6))))

        else:
            # every other EX is the same
            # temp0 = lhs
            il.append(il.expr(LowLevelILOperation.LLIL_SET_REG,
                LLIL_TEMP(0),
                operand_to_il(oper_type, oper_val, il, 2),
                size = 2
            ))

            # lhs = rhs
            rhs = operand_to_il(operb_type, operb_val, il, 2)

            if oper_type == OPER_TYPE.REG:
                il.append(il.set_reg(2,
                    reg2str(oper_val),
                    rhs
                ))
            else:
                il.append(il.store(2,
                    operand_to_il(oper_type, oper_val, il, 2, peel_load=True),
                    rhs
                ))

            # rhs = temp0
            il.append(il.set_reg(2,
                reg2str(operb_val),
                il.expr(LowLevelILOperation.LLIL_REG, LLIL_TEMP(0), 2)
            ))

    elif decoded.op == OP.EXX:
        exchange('BC', "BC'", il)
        exchange('DE', "DE'", il)
        exchange('HL', "HL'", il)

    elif decoded.op == OP.IN:
        temp0 = LLIL_TEMP(0)
        il.append(il.intrinsic([ILRegister(il.arch, temp0)], "in", [operand_to_il(operb_type, operb_val, il, 1)]))
        il.append(il.set_reg(1, reg2str(oper_val), il.reg(1, temp0)))

    elif decoded.op == OP.INC:
        # inc reg can be 1-byte or 2-byte
        if oper_type == OPER_TYPE.REG:
            size = REG_TO_SIZE[oper_val]
            tmp = il.add(size, operand_to_il(oper_type, oper_val, il), il.const(1, 1))
            tmp = il.set_reg(size, reg2str(oper_val), tmp)
        else:
            tmp = il.add(1, operand_to_il(oper_type, oper_val, il), il.const(1, 1))
            tmp = il.store(1, operand_to_il(oper_type, oper_val, il, 1, peel_load=True), tmp)

        il.append(tmp)

    elif decoded.op in [OP.JP, OP.JR]:
        if oper_type == OPER_TYPE.COND:
            append_conditional_jump(oper_val, operb_type, operb_val, addr + decoded.len, il)
        else:
            il.append(goto_or_jump(oper_type, oper_val, il))

    elif decoded.op == OP.LD:
        assert len(decoded.operands) == 2

        if oper_type == OPER_TYPE.REG:
            size = REG_TO_SIZE[oper_val]
            # for two-byte nonzero loads, guess that it's an address
            if size == 2 and operb_type == OPER_TYPE.IMM and operb_val != 0:
                operb_type = OPER_TYPE.ADDR
            rhs = operand_to_il(operb_type, operb_val, il, size)
            set_reg = il.set_reg(size, reg2str(oper_val), rhs)
            il.append(set_reg)
        else:
            assert operb_type in [OPER_TYPE.REG, OPER_TYPE.IMM]

            if operb_type == OPER_TYPE.REG:
                # 1 or 2 byte stores are possible here:
                # ld (0xcdab),bc
                # ld (ix-0x55),a
                size = REG_TO_SIZE[operb_val]
            elif operb_type == OPER_TYPE.IMM:
                # only 1 byte stores are possible
                # eg: ld (ix-0x55),0xcd
                size = 1

            src = operand_to_il(operb_type, operb_val, il, size)
            dst = operand_to_il(oper_type, oper_val, il, size, peel_load=True)
            il.append(il.store(size, dst, src))

    elif decoded.op in [OP.LDI, OP.LDIR]:
        if decoded.op == OP.LDIR:
            t = LowLevelILLabel()
            f = il.get_label_for_address(Architecture['Z80'], addr + decoded.len)
            il.mark_label(t)

        il.append(il.store(1, il.reg(2, 'DE'), il.load(1, il.reg(2, 'HL'))))
        il.append(il.set_reg(2, 'DE', il.add(2, il.reg(2, 'DE'), il.const(2,1))))
        il.append(il.set_reg(2, 'HL', il.add(2, il.reg(2, 'HL'), il.const(2,1))))
        il.append(il.set_reg(2, 'BC', il.sub(2, il.reg(2, 'BC'), il.const(2,1))))

        if decoded.op == OP.LDIR:
            do_mark = False
            if not f:
                do_mark = True
                f = LowLevelILLabel()

            il.append(il.if_expr(il.compare_not_equal(2, il.reg(2, 'BC'), il.const(2, 0)), t, f))

            if do_mark:
                il.mark_label(f)

    elif decoded.op == OP.NEG:
        tmp = il.reg(1, 'A')
        tmp = il.sub(1, il.const(1, 0), tmp, flags='*')
        tmp = il.set_reg(1, 'A', tmp)
        il.append(tmp)

    elif decoded.op == OP.NOP:
        il.append(il.nop())

    elif decoded.op == OP.OR:
        tmp = il.reg(1, 'A')
        tmp = il.or_expr(1, operand_to_il(oper_type, oper_val, il, 1), tmp, flags='*')
        tmp = il.set_reg(1, 'A', tmp)
        il.append(tmp)

    elif decoded.op == OP.OUT:
        il.append(il.intrinsic([], "out", [operand_to_il(oper_type, oper_val, il, 1), operand_to_il(operb_type, operb_val, il, 1)]))

    elif decoded.op == OP.POP:
        # possible operands are: af bc de hl ix iy
        if oper_val == REG.AF:
            flags = il.pop(1)
            tmp = il.pop(1)
            tmp = il.set_reg(1, 'A', tmp)
            il.append(tmp)
            il.append(il.set_flag('c', il.test_bit(1, flags, il.const(1, 1))))
            il.append(il.set_flag('h', il.test_bit(1, flags, il.const(1, 1<<4))))
            il.append(il.set_flag('n', il.test_bit(1, flags, il.const(1, 1<<1))))
            il.append(il.set_flag('pv', il.test_bit(1, flags, il.const(1, 1<<2))))
            il.append(il.set_flag('s', il.test_bit(1, flags, il.const(1, 1<<7))))
            il.append(il.set_flag('z', il.test_bit(1, flags, il.const(1, 1<<6))))
        else:
            # normal load
            size = REG_TO_SIZE[oper_val]
            tmp = il.pop(size)
            tmp = il.set_reg(size, reg2str(oper_val), tmp)
            il.append(tmp)

    elif decoded.op == OP.PUSH:
        # possible operands are: af bc de hl ix iy

        # when pushing AF, actually push the flags
        if oper_val == REG.AF:
            # lo byte F first
            il.append(il.push(2,
                il.or_expr(2,
                    il.or_expr(1,
                        il.or_expr(1,
                            il.shift_left(1, il.flag('s'), il.const(1, 7)),
                            il.shift_left(1, il.flag('z'), il.const(1, 6))
                        ),
                        il.or_expr(1,
                            il.or_expr(1,
                                il.shift_left(1, il.flag('h'), il.const(1, 4)),
                                il.shift_left(1, il.flag('pv'), il.const(1, 2))
                            ),
                            il.or_expr(1,
                                il.shift_left(1, il.flag('n'), il.const(1, 1)),
                                il.flag('c')
                            )
                        )
                    ),
                    il.shift_left(2,
                        il.reg(1, 'A'),
                        il.const(1, 8)
                    )
                )
            ))
        else:
            il.append(il.push( \
                REG_TO_SIZE[oper_val], \
                operand_to_il(oper_type, oper_val, il)))

    elif decoded.op in [OP.RL, OP.RLA]:
        # rotate THROUGH carry: b0=c, c=b8
        # z80 'RL' -> llil 'RLC'
        if decoded.op == OP.RLA:
            src = il.reg(1, 'A')
        else:
            src = operand_to_il(oper_type, oper_val, il)

        rot = il.rotate_left_carry(1, src, il.const(1, 1), il.flag('c'), flags='c')

        if decoded.op == OP.RLA:
            il.append(il.set_reg(1, 'A', rot))
        elif oper_type == OPER_TYPE.REG:
            il.append(il.set_reg(1, reg2str(oper_val), rot))
        else:
            tmp2 = operand_to_il(oper_type, oper_val, il, 1, peel_load=True)
            il.append(il.store(1, tmp2, rot))

    elif decoded.op in [OP.RLC, OP.RLCA]:
        # rotate and COPY to carry: b0=c, c=b8
        # z80 'RL' -> llil 'ROL'
        if decoded.op == OP.RLCA:
            src = il.reg(1, 'A')
        else:
            src = operand_to_il(oper_type, oper_val, il)

        rot = il.rotate_left(1, src, il.const(1, 1), flags='c')

        if decoded.op == OP.RLCA:
            il.append(il.set_reg(1, 'A', rot))
        elif oper_type == OPER_TYPE.REG:
            il.append(il.set_reg(1, reg2str(oper_val), rot))
        else:
            tmp2 = operand_to_il(oper_type, oper_val, il, 1, peel_load=True)
            il.append(il.store(1, tmp2, rot))

    elif decoded.op == OP.RET:
        tmp = il.ret(il.pop(2))
        if decoded.operands:
            append_conditional_instr(decoded.operands[0][1], tmp, il)
        else:
            il.append(tmp)

    elif decoded.op in [OP.RR, OP.RRA]:
        # rotate THROUGH carry: b7=c, c=b0
        # z80 'RR' -> llil 'RRC'
        if decoded.op == OP.RRA:
            src = il.reg(1, 'A')
        else:
            src = operand_to_il(oper_type, oper_val, il, 1)

        rot = il.rotate_right_carry(1, src, il.const(1, 1), il.flag('c'), flags='c')

        if decoded.op == OP.RRA:
            il.append(il.set_reg(1, 'A', rot))
        elif oper_type == OPER_TYPE.REG:
            il.append(il.set_reg(1, reg2str(oper_val), rot))
        else:
            tmp2 = operand_to_il(oper_type, oper_val, il, 1, peel_load=True)
            il.append(il.store(1, tmp2, rot))

    elif decoded.op in [OP.RRC, OP.RRCA]:
        # rotate and COPY to carry: b0=c, c=b8
        # z80 'RR' -> llil 'ROR'
        if decoded.op == OP.RRCA:
            src = il.reg(1, 'A')
        else:
            src = operand_to_il(oper_type, oper_val, il, 1)

        rot = il.rotate_right(1, src, il.const(1, 1), flags='c')

        if decoded.op == OP.RRCA:
            il.append(il.set_reg(1, 'A', rot))
        elif oper_type == OPER_TYPE.REG:
            il.append(il.set_reg(1, reg2str(oper_val), rot))
        else:
            tmp2 = operand_to_il(oper_type, oper_val, il, 1, peel_load=True)
            il.append(il.store(1, tmp2, rot))

    elif decoded.op == OP.RST:
        # this is like call but we zero extend
        il.append(il.call(il.const_pointer(2, oper_val)))

    elif decoded.op == OP.RES:
        assert oper_type == OPER_TYPE.IMM
        assert oper_val >= 0 and oper_val <= 7
        mask = il.const(1, (1<<oper_val) ^ 0xFF)
        operand = operand_to_il(operb_type, operb_val, il, 1)
        result = il.and_expr(1, operand, mask)

        if operb_type == OPER_TYPE.REG:
            tmp = il.set_reg(1, reg2str(operb_val), result)
        else:
            tmp = il.store(1, operand_to_il(operb_type, operb_val, il, 1, peel_load=True), result)

        il.append(tmp)

    elif decoded.op == OP.SET:
        assert oper_type == OPER_TYPE.IMM
        assert oper_val >= 0 and oper_val <= 7
        mask = il.const(1, 1<<oper_val)
        operand = operand_to_il(operb_type, operb_val, il, 1)
        result = il.or_expr(1, operand, mask)

        if operb_type == OPER_TYPE.REG:
            tmp = il.set_reg(1, reg2str(operb_val), result)
        else:
            tmp = il.store(1, operand_to_il(operb_type, operb_val, il, 1, peel_load=True), result)

        il.append(tmp)

    elif decoded.op == OP.SRA:
        tmp = operand_to_il(oper_type, oper_val, il, 1)
        tmp = il.arith_shift_right(1, tmp, il.const(1, 1), flags='c')

        if oper_type == OPER_TYPE.REG:
            tmp = il.set_reg(1, reg2str(oper_val), tmp)
        else:
            tmp = il.store(1,
                operand_to_il(oper_type, oper_val, il, 1, peel_load=True),
                tmp
            )

        il.append(tmp)

    elif decoded.op == OP.SUB:
        tmp = operand_to_il(oper_type, oper_val, il, 1)
        tmp = il.sub(1, il.reg(1, 'A'), tmp, flags='*')
        tmp = il.set_reg(1, 'A', tmp)
        il.append(tmp)

    elif decoded.op == OP.DEC:
        if oper_type == OPER_TYPE.REG:
            size = REG_TO_SIZE[oper_val]
            reg = operand_to_il(oper_type, oper_val, il, size)
            fwt = 'not_c' if size == 1 else None
            tmp = il.sub(size, reg, il.const(1, 1), flags=fwt)
            tmp = il.set_reg(size, reg2str(oper_val), tmp)
            il.append(tmp)
        else:
            mem = operand_to_il(oper_type, oper_val, il, 1)
            tmp = il.sub(1, mem, il.const(1, 1), flags='not_c')
            tmp = il.store(1, mem, tmp)
            il.append(tmp)

    elif decoded.op == OP.SBC:
        size = REG_TO_SIZE[oper_val]
        lhs = operand_to_il(oper_type, oper_val, il, size)
        rhs = operand_to_il(operb_type, operb_val, il, size)
        tmp = il.sub_borrow(size, lhs, rhs, il.flag('c'), flags='*')
        tmp = il.set_reg(1, 'A', tmp)
        il.append(tmp)

    elif decoded.op == OP.XOR:
        tmp = il.reg(1, 'A')
        tmp = il.xor_expr(1, operand_to_il(oper_type, oper_val, il, 1), tmp, flags='*')
        tmp = il.set_reg(1, 'A', tmp)
        il.append(tmp)

    else:
        il.append(il.unimplemented())
        #il.append(il.nop()) # these get optimized away during lifted il -> llil

