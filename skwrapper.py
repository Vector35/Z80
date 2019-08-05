#!/usr/bin/env python

from skoolkit import disassembler

# skoolkit wants a 64k "snapshot" of memory, in the form of a bytes or list object
# we provide a fake snapshot that can position a few bytes to any area within the 64k mem
class CustomSnapshot():
	def __init__(self, data, addr):
		self.data = data
		self.base = addr

	def check_idx(self, idx):
		if idx < self.base or (idx - self.base) > len(self.data):
			raise IndexError

	def __getitem__(self, key):
		#print('__getitem__(%s)' % repr(key))

		if type(key) == int:
			self.check_idx(key)
			result = self.data[key-self.base]
		elif type(key) == slice:
			self.check_idx(key.start)
			self.check_idx(key.stop)
			result = self.data[key.start-self.base : key.stop-self.base]
		else:
			raise TypeError
			
		return result

disObj = None

def disasm(data, addr):
	#print('addr: %d, data: %s' % (addr, str(data)))
	global disObj

	if not disObj:
		disObj = disassembler.Disassembler(data, asm_hex=True)
	
	disObj.snapshot = CustomSnapshot(data, addr)

	decoder, template = disObj.ops[data[0]]

	try:
		if template is None:
			instrTxt, instrLen = decoder(disObj, addr, None)
		else:
			instrTxt, instrLen = decoder(disObj, template, addr, None)
	except IndexError:
		instrTxt, instrLen = '<error>', 0

	if instrTxt.startswith('DEFB'):
		instrTxt, instrLen = '<error>', 0

	return(instrTxt, instrLen)

if __name__ == '__main__':
	import sys
	import struct

	if not sys.argv[1:]:
		print(disasm(b'\xfd\x21\x00\x01', 0x8D)[0])
		sys.exit(0)

	addr = 0x38

	# just disassemble random junk and print it
	if sys.argv[1] == 'random':
		import random
		while 1:
			data = list(map(lambda x: random.randint(0,255), range(4)))
			print('%02X %02X %02X %02X: %s' % (data[0], data[1], data[2], data[3], disasm(data, addr)[0]))

	# 16-bit test
	elif sys.argv[1] == 'test16':
		for k in range(65536):
			data = list(struct.pack('>I', k << 16))
			print('%02X %02X 00 00: %s' % (data[0], data[1], disasm(data, addr)[0]))

	# 32-bit test
	elif sys.argv[1] == 'test32':
		for k in range(2**32):
			data = list(struct.pack('<I', k))
			print('%02X %02X %02X %02X: %s' % (data[0], data[1], data[2], data[3], disasm(data, addr)[0]))

	# bytes on command line
	else:
		data = list(map(lambda x: int(x,16), sys.argv[1:]))
		(instrTxt, instrLen) = disasm(data, addr)
		for k in range(instrLen):
			print('%02X ' % data[k], end='')
		print(': ' + instrTxt)
		sys.exit(0)




