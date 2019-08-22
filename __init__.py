import binaryninja

from .Z80Arch import Z80
Z80.register()

from .ColecoView import ColecoView
ColecoView.register()

from .RelView import RelView
RelView.register()

# built-in view
EM_Z80 = 220
binaryninja.BinaryViewType['ELF'].register_arch(EM_Z80, binaryninja.enums.Endianness.LittleEndian, binaryninja.Architecture['Z80'])


