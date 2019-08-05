#!/usr/bin/env python

from binaryninja.log import log_info
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo

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

Z80.register()
