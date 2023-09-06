#!/usr/bin/env python

from struct import unpack

from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.types import Symbol
from binaryninja.enums import SegmentFlag, SymbolType

class ColecoView(BinaryView):
	name = 'Coleco'
	long_name = 'ColecoVision ROM'

	@classmethod
	def is_valid_cartridge_header(self, data):
		# data is a string
		if len(data) < 12: return False
		(cart, local_spr_tbl, _, _, _, start_game) = unpack('<HHHHHH', data)
		if not cart in [0xAA55, 0x55AA]: return False
		if (start_game & 0xF000) != 0x8000: return False
		return True

	# return {None, 'cartridge', 'system'}
	@classmethod
	def get_rom_type(self, data):
		# data is a binaryninja.binaryview.BinaryView
		if len(data.read(0,0xc000)) == 0xc000:
			if self.is_valid_cartridge_header(data.read(0x8000, 12)):
				if data.read(0, 16) == '\x31\xb9\x73\xc3\x6e\x00\xff\xff\xc3\x0c\x80\xff\xff\xff\xff\xc3':
					print('detected ColecoVision system image')
					return 'system'

		if self.is_valid_cartridge_header(data.read(0, 12)):
			print('detected ColecoVision cartridge ROM')
			return 'cartridge'

		return None

	@classmethod
	def is_valid_for_data(self, data):
		return self.get_rom_type(data) in ['cartridge', 'system']

	def __init__(self, data):
		# data is a binaryninja.binaryview.BinaryView
		BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
		self.data = data
		self.romType = self.get_rom_type(data)

	def init(self):
		self.arch = Architecture['Z80']
		self.platform = Architecture['Z80'].standalone_platform

		# ram
		self.add_auto_segment(0x6000, 0x2000, 0, 0, SegmentFlag.SegmentReadable|SegmentFlag.SegmentWritable)
		# bios and cartridge ROM are in their natural place for system images
		if self.romType == 'system':
			self.add_auto_segment(0x0, 0x2000, 0, 0x2000, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
			self.add_auto_segment(0x8000, 0x4000, 0x8000, 0x4000, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
		#
		elif self.romType == 'cartridge':
			self.add_auto_segment(0x0, 0x2000, 0, 0, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
			self.add_auto_segment(0x8000, 0x4000, 0, 0x4000, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)

		# os symbols
		syms_os = { 0x1F61:'PLAY_SONGS', 0x1F64:'ACTIVATE', 0x1F67:'PUTOBJ', 0x1F6A:'REFLECT_VERTICAL',
			0x1F6D:'REFLECT_HORIZONTAL', 0x1F70:'ROTATE_90', 0x1F73:'ENLARGE',
			0x1F76:'CONTROLLER_SCAN', 0x1F79:'DECODER', 0x1F7C:'GAME_OPT',
			0x1F7F:'LOAD_ASCII', 0x1F82:'FILL_VRAM', 0x1F85:'MODE_1',
			0x1F88:'UPDATE_SPINNER', 0x1F8B:'INIT_TABLEP', 0x1F8E:'GET_VRAMP',
			0x1F91:'PUT_VRAMP', 0x1F94:'INIT_SPR_ORDERP', 0x1F97:'WR_SPR_NM_TBLP',
			0x1F9A:'INIT_TIMERP', 0x1F9D:'FREE_SIGNALP', 0x1FA0:'REQUEST_SIGNALP',
			0x1FA3:'TEST_SIGNALP', 0x1FA6:'WRITE_REGISTERP', 0x1FA9:'WRITE_VRAMP',
			0x1FAC:'READ_VRAMP', 0x1FAF:'INIT_WRITERP', 0x1FB2:'SOUND_INITP',
			0x1FB5:'PLAY_ITP', 0x1FB8:'INIT_TABLE', 0x1FBB:'GET_VRAM',
			0x1FBE:'PUT_VRAM', 0x1FC1:'INIT_SPR_ORDER', 0x1FC4:'WR_SPR_NM_TBL',
			0x1FC7:'INIT_TIMER', 0x1FCA:'FREE_SIGNAL', 0x1FCD:'REQUEST_SIGNAL',
			0x1FD0:'TEST_SIGNAL', 0x1FD3:'TIME_MGR', 0x1FD6:'TURN_OFF_SOUND',
			0x1FD9:'WRITE_REGISTER', 0x1FDC:'READ_REGISTER', 0x1FDF:'WRITE_VRAM',
			0x1FE2:'READ_VRAM', 0x1FE5:'INIT_WRITER', 0x1FE8:'WRITER',
			0x1FEB:'POLLER', 0x1FEE:'SOUND_INIT', 0x1FF1:'PLAY_IT',
			0x1FF4:'SOUND_MAN', 0x1FF7:'ACTIVATE', 0x1FFA:'PUTOBJ',
			0x1FFD:'RAND_GEN'}

		for addr,name in syms_os.items():
			self.define_auto_symbol(Symbol(SymbolType.ImportedFunctionSymbol, addr, name))
			#self.add_function(addr)

		# cartridge header
		syms_cart_data = {
			0x8000:'CARTRIDGE',
			0x8002:'LOCAL_SPR_TBL',
			0x8004:'SPRITE_ORDER',
			0x8006:'WORK_BUFFER',
			0x8008:'CONTROLLER_MAP',
			0x800A:'START_GAME',
			0x8024:'GAME_NAME'
		}

		for addr,name in syms_cart_data.items():
			t = self.parse_type_string('uint16_t %s' % name)[0]
			#self.undefine_auto_symbol(Symbol(SymbolType.DataSymbol, addr, name))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, addr, name))
			self.define_data_var(addr, t)

		syms_cart_code = {
			0x800C:'RST_8H_RAM',
			0x800F:'RST_10H_RAM',
			0x8012:'HDR_18H_RAM',
			0x8015:'RST_20H_RAM',
			0x8018:'RST_28H_RAM',
			0x801B:'RST_30H_RAM',
			0x801E:'IRQ_INT_VECTOR',
			0x8021:'NMI_INT_VECT',
		}

		for addr,name in syms_cart_code.items():
			#self.undefine_auto_symbol(Symbol(SymbolType.DataSymbol, addr, name))
			self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, addr, name))
			self.add_function(addr)

		# 1 byte symbols in RAM
		syms_ram1 = { 0x702A:'SAVE_CTRL', 0x73B9:'STACK', 0x73C2:'TEST_SIG_NUM', 0x73C5:'VDP_STATUS_BYTE',
			0x73C6:'DEFER_WRITES', 0x73C7:'MUX_SPRITES', 0x73CA:'QUEUE_SIZE', 0x73CB:'QUEUE_HEAD',
			0x73CC:'QUEUE_TAIL', 0x73EB:'SPIN_SW0_CT', 0x73EC:'SPIN_SW1_CT', 0x73ED:'RESERVED',
			0x73EE:'S0_C0', 0x73EF:'S0_C1', 0x73F0:'S1_C0', 0x73F1:'S1_C1'}

		for addr,name in syms_ram1.items():
			t = self.parse_type_string('uint8_t %s' % name)[0]
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, addr, name))
			self.define_data_var(addr, t)

		# 2 byte symbols in RAM
		syms_ram2 = { 0x73CD:'HEAD_ADDRESS', 0x73C8:'RAND_NUM', 0x73CF:'TAIL_ADDRESS', 0x73D1:'BUFFER',
			0x73D3:'TIMER_TABLE_BASE', 0x73D5:'NEXT_TIMER_DATA_BYTE', 0x73D7:'DBNCE_BUFF',
			0x73BA:'PARAM_AREA', 0x73C0:'TIMER_LENGTH', 0x73C3:'VDP_MODE_WORD', 0x73F2:'VRAM_ADDR_TABLE',
			0x73F2:'SPRITENAMETBL', 0x73F4:'SPRITEGENTBL', 0x73F6:'PATTERNNAMETBL', 0x73F8:'PATTERNGENTBL',
			0x73FA:'COLORTABLE', 0x73FC:'SAVE_TEMP', 0x73FE:'SAVED_COUNT', 0x7020:'PTR_LST_OF_SND_ADDRS',
			0x7022:'PTR_TO_S_ON_0', 0x7024:'PTR_TO_S_ON_1', 0x7026:'PTR_TO_S_ON_2', 0x7028:'PTR_TO_S_ON_3'}

		for addr,name in syms_ram2.items():
			t = self.parse_type_string('uint16_t %s' % name)[0]
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, addr, name))
			self.define_data_var(addr, t)

		# controller data area
		p_cda = 0
		if self.romType == 'cartridge':
			p_cda = unpack('<H', self.data[8:8+2])[0]
		elif self.romType == 'system':
			p_cda = unpack('<H', self.data[0x8008:0x8008+2])[0]

		syms_cda = ['P1_ENABLE', 'P2_ENABLE',
			'LEFT_BUTTON_P1', 'JOYSTICK_P1', 'SPINNER_COUNT_P1', 'RIGHT_BUTTON_P1', 'KEYBOARD_P1',
			'LEFT_BUTTON_P2', 'JOYSTICK_P2', 'SPINNER_COUNT_P2', 'RIGHT_BUTTON_P2', 'KEYBOARD_P2'
		]
		for (offs,name) in enumerate(syms_cda):
			t = self.parse_type_string('uint8_t %s' % name)[0]
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, p_cda+offs, name))
			self.define_data_var(p_cda+offs, t)

		# entrypoint is that start_game header member
		self.add_entry_point(unpack('<H', self.data[0xA:0xA+2])[0])
		return True

	def perform_is_executable(self):
		return True

	def perform_get_entry_point(self):
		return 0

	def perform_get_address_size(self):
	    return 2
