# Z80 Architecture Plugin (v1.1)
Author: **Vector 35 Inc**
_Sample Z80 architecture plugin written to accompany the <a href='https://binary.ninja/2020/01/08/guide-to-architecture-plugins-part1.html'>introductory blog post</a>._
## Description:
<p>This Z80 architecture plugin was originally written as an example architecture to introduce how to easily add support to Binary Ninja for any new architecture given an existing disassembly library. It originally used the <a href='https://skoolkit.ca/'>SchoolKit</a> python library as a disassembler, but later was updated to work with a <a href='https://github.com/lwerdna/z80dis'>dedicated library</a>.</p><p>This repository has several checkpoints from the <a href='https://binary.ninja/2020/01/08/guide-to-architecture-plugins-part1.html'>blog post</a> that are associated with specific comments.</p>


## Installation Instructions

### Windows

The built-in Python 2.7 currently included in Windows builds can't easily have additional dependencies installed. We recommend installing a 64-bit version of python, using the native pip functionality to install the z80dis module (and skoolkit if using the previous checkpoints).

### Linux

pip install z80dis;pip3 install z80dis

### Darwin

pip install z80dis;pip3 install z80dis
## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * 776
"


## Required Dependencies

The following dependencies are required for this plugin:

 * pip - z80dis


## License

This plugin is released under a MIT license.
## Metadata Version

2
