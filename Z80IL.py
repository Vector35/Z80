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
from binaryninja.lowlevelil import LowLevelILLabel, ILRegister, ILFlag, LLIL_TEMP, LLIL_GET_TEMP_REG_INDEX, LowLevelILExpr

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

def expressionify(size, foo, il, temps_are_conds=False):
    """ turns the "reg or constant"  operands to get_flag_write_low_level_il()
        into lifted expressions """
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
        if op == LowLevelILOperation.LLIL_POP:
            return il.set_flag('c', il.test_bit(1, il.reg(1, 'F'), il.const(1, 1)))
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
        if op == LowLevelILOperation.LLIL_POP:
            return il.set_flag('h', il.test_bit(1, il.reg(1, 'F'), il.const(1, 1<<4)))
        if op == LowLevelILOperation.LLIL_XOR:
            return il.const(1, 0)

    if flag == 'n':
        if op == LowLevelILOperation.LLIL_POP:
            return il.set_flag('n', il.test_bit(1, il.reg(1, 'F'), il.const(1, 1<<1)))
        if op == LowLevelILOperation.LLIL_XOR:
            return il.const(1, 0)

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

        if op == LowLevelILOperation.LLIL_POP:
            return il.set_flag('pv', il.test_bit(1, il.reg(1, 'F'), il.const(1, 1<<2)))

        if op == LowLevelILOperation.LLIL_XOR:
            # TODO: implement real parity
            return il.const(1, 0)

    if flag == 's':
        if op == LowLevelILOperation.LLIL_POP:
            return il.set_flag('s', il.test_bit(1, il.reg(1, 'F'), il.const(1, 1<<7)))

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
        il.append(il.and_expr(1, operand, mask, flags='*'))

    elif decoded.op == OP.CALL:
        if oper_type == OPER_TYPE.ADDR:
            il.append(il.call(il.const_pointer(2, oper_val)))
        else:
            # TODO: handle the conditional
            il.append(il.unimplemented())

    elif decoded.op == OP.CCF:
        il.append(il.set_flag('c', il.not_expr(0, il.flag('c'))))

    elif decoded.op == OP.CP:
        # sub, but do not write to register
        lhs = il.reg(1, 'A')
        rhs = operand_to_il(oper_type, oper_val, il, 1)
        sub = il.sub(1, lhs, rhs, flags='*')
        il.append(sub)

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
        # temp0 = lhs
        il.append(il.expr(LowLevelILOperation.LLIL_SET_REG,
            LLIL_TEMP(0),
            operand_to_il(oper_type, oper_val, il, 2).index,
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

    elif decoded.op == OP.NOP:
        il.append(il.nop())

    elif decoded.op == OP.OR:
        tmp = il.reg(1, 'A')
        tmp = il.or_expr(1, operand_to_il(oper_type, oper_val, il, 1), tmp, flags='*')
        tmp = il.set_reg(1, 'A', tmp)
        il.append(tmp)

    elif decoded.op == OP.POP:
        # possible operands are: af bc de hl ix iy
        flag_write_type = '*' if oper_val == REG.AF else None

        size = REG_TO_SIZE[oper_val]
        tmp = il.pop(size)
        tmp = il.set_reg(size, reg2str(oper_val), tmp, flag_write_type)
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
            tmp = operand_to_il(oper_type, oper_val, il, 1, peel_load=True)
            il.append(il.store(1, tmp2, tmp))

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
            tmp = operand_to_il(oper_type, oper_val, il, 1, peel_load=True)
            il.append(il.store(1, tmp2, tmp))

    elif decoded.op == OP.RET:
        tmp = il.ret(il.pop(2))
        if decoded.operands:
            append_conditional_instr(decoded.operands[0][1], tmp, il)
        else:
            il.append(tmp)

    elif decoded.op in [OP.RR, OP.RRA]:
        # rotate THROUGH carry: b7=c, c=b0
        # z80 'RL' -> llil 'RRC'
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

