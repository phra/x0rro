#|/usr/bin/env python3

import sys
import lief

shellcode = [ 0x90 ] * 0x1000 # Assembly code

if len(sys.argv) < 2:
    print('Usage: python3 {} <FILE> [section_name]'.format(sys.argv[0]))
    sys.exit(-1)

filename = sys.argv[1]

app = lief.parse(filename)

section_name = sys.argv[2] if len(sys.argv) == 2 else '__shellcode'

print('adding {} section to __TEXT segment'.format(section_name))
section = lief.MachO.Section(section_name, shellcode)
section.alignment = 2
section += lief.MachO.SECTION_FLAGS.SOME_INSTRUCTIONS
section += lief.MachO.SECTION_FLAGS.PURE_INSTRUCTIONS
section = app.add_section(section)

app.write(filename)
