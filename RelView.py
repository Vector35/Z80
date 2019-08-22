#!/usr/bin/env python

import re
from struct import pack

from binaryninja.types import Symbol
from binaryninja.binaryview import BinaryView
from binaryninja.log import log_info, log_debug
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag, SymbolType, SectionSemantics

class RelView(BinaryView):
    name = '.rel object'
    long_name = 'sdcc z80 .rel object'

    @classmethod
    def is_valid_for_data(self, binaryView):
        sample = binaryView.read(0, 128)
        return sample.startswith(b'XL2\x0a') and b'\x0aO -mz80\x0a' in sample

    def __init__(self, binaryView):
        # data is a binaryninja.binaryview.BinaryView
        BinaryView.__init__(self, parent_view=binaryView, file_metadata=binaryView.file)

    def init(self):
        self.arch = Architecture['Z80']
        self.platform = Architecture['Z80'].standalone_platform

        syms = []
        have_code = False

        for line in self.parent_view.read(0, len(self.parent_view)).split(b'\x0a'):
            line = line.decode('utf-8')

            # AREA line -> create a section
            match = re.match(r'A _CODE size (.*) flags (.*) addr (.*)', line)
            if match:
                (size, flags, addr) = (int(x, 16) for x in match.group(1, 2, 3))
                assert flags == 0
                assert addr == 0
                log_info('adding _CODE [%X, %X)' % (addr, addr+size))

                self.add_auto_segment(addr, size, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable)
                
                #self.add_user_section('_CODE', addr, size, SectionSemantics.ReadOnlyCodeSectionSemantics)
                have_code = True
                continue

            # WRITE line -> write bytes to section
            match = re.match(r'^T (.. ..) (.*)', line)
            if match:
                (addr, data) = match.group(1, 2)
                # eg: "04 00" -> 0x0004
                addr = int(addr[3:5] + addr[0:2], 16)
                # eg: "AA BB CC DD" -> b'\xAA\xBB\xCC\xDD'
                data = b''.join([pack('B', int(x, 16)) for x in data.split(' ')])
                log_info('writing to %X: %s' % (addr, match.group(2)))
                self.write(addr, data) 
                continue 

            # SYMBOL line -> store
            match = re.match(r'^S (.+) Def(.*)', line)
            if match:
                (name, addr) = match.group(1, 2)
                if not name in ['.__.ABS.', '.  .ABS']:
                    addr = int(addr, 16)
                    log_info('saving symbol %s @ %X' % (name, addr))
                    syms.append((name, addr))
                    continue
        
        assert have_code
        for (name, addr) in syms:
            log_info('applying symbol %s @ %X' % (name, addr))
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, addr, name))
            self.add_function(addr)

        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0
