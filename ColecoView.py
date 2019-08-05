#!/usr/bin/env python

from struct import unpack

from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag

class ColecoView(BinaryView):
	name = 'Coleco'
	long_name = 'ColecoVision ROM'

	@classmethod
	def is_valid_for_data(self, data):
		header = data.read(0,0x24)
		return header[0:2] in [b"\xAA\x55", b"\x55\xAA"]

	def __init__(self, data):
		# data is a binaryninja.binaryview.BinaryView
		BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
		self.platform = Architecture['Z80'].standalone_platform
		self.data = data
	
	def init(self):
		#self.add_auto_segment(0x8000, 0x4000, 0, 0x4000, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)		
		self.add_auto_segment(0x8000, 0x4000, 0, 0x4000, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)		
		self.add_entry_point(unpack('<H', self.data[0xA:0xA+2])[0])
		return True

	def perform_is_executable(self):
		return True

	def perform_get_entry_point(self):
		return unpack('<H', self.data[0xA:0xA+2])[0]

