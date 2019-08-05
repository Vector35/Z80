#!/usr/bin/env python

from binaryninja.log import log_info
from binaryninja.architecture import Architecture

class Z80(Architecture):
  	name = 'Z80'

print("Hello, world!")
log_info("Hello, world!")

Z80.register()
