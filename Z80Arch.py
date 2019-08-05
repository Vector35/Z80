#!/usr/bin/env python

import re

from binaryninja.log import log_info
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType

import skwrapper

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

	def get_instruction_info(self, data, addr):
		(instrTxt, instrLen) = skwrapper.disasm(data, addr)
		if instrLen == 0:
			return None
		result = InstructionInfo()
		result.length = instrLen
		return result 

	def get_instruction_text(self, data, addr):
		(instrTxt, instrLen) = skwrapper.disasm(data, addr)
		if instrLen == 0:
			return None

		result = []
		atoms = [t for t in re.split(r'([, ()\+])', instrTxt) if t] # delimeters kept if in capture group
		result.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, atoms[0]))
		if atoms[1:]:
			result.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))

		#
		for atom in atoms[1:]:
			if not atom or atom == ' ':
				continue
			# PROBLEM: cond 'C' conflicts with register C
			# eg: "RET C" is it "RET <reg>" or "REG <cc>" ?
			# eg: "CALL C" is it "CALL <reg>" or "CALL C,$0000" ?
			elif atom == 'C' and atoms[0] in ['CALL','RET']:
				# flag, condition code
				result.append(InstructionTextToken(InstructionTextTokenType.TextToken, atom))
			elif atom in self.reg16_strs or atom in self.reg8_strs:
				result.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, atom))
			elif atom in self.cond_strs:
				result.append(InstructionTextToken(InstructionTextTokenType.TextToken, atom))
			elif atom[0] == '#':
				result.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, atom, int(atom[1:],16)))
			elif atom[0] == '$':
				if len(atom)==5:
					result.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, atom, int(atom[1:],16)))
				else:
					result.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, atom, int(atom[1:],16)))
			elif atom.isdigit():
				result.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, atom, int(atom)))
			elif atom == '(':
				result.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, atom))
			elif atom == ')':
				result.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, atom))
			elif atom == '+':
				result.append(InstructionTextToken(InstructionTextTokenType.TextToken, atom))
			elif atom == ',':
				result.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, atom))
			else:
				raise Exception('unfamiliar token: %s from instruction %s' % (tok, instrTxt))

		return result, instrLen

	def get_instruction_low_level_il(self, data, addr, il):
		return None

Z80.register()
