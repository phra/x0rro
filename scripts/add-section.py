#|/usr/bin/env python3

import sys
import lief

shellcode = [ 0x90 ] * 0x1000 # Assembly code

if len(sys.argv) < 2:
    print('Usage: python3 {} <FILE> [section_name]'.format(sys.argv[0]))
    sys.exit(-1)

filename = sys.argv[1]

app = lief.parse(filename)

section_name = sys.argv[2] if len(sys.argv) == 3 else '__shellcode'

print('adding {} section'.format(section_name))

if isinstance(app, lief.MachO.Binary):
  section = lief.MachO.Section(section_name, shellcode)
  section.alignment = 2
  section += lief.MachO.SECTION_FLAGS.SOME_INSTRUCTIONS
  section += lief.MachO.SECTION_FLAGS.PURE_INSTRUCTIONS
  section = app.add_section(section)
elif isinstance(app, lief.ELF.Binary):
  section = lief.ELF.Section(section_name, lief.ELF.SECTION_TYPES.DYNSYM)
  section.alignment = 2
  section.content = shellcode
  section += lief.ELF.SECTION_FLAGS.EXECINSTR
  section += lief.ELF.SECTION_FLAGS.WRITE
  section += lief.ELF.SECTION_FLAGS.ALLOC
  section = app.add(section)
elif isinstance(app, lief.PE.Binary):
  section = lief.PE.Section(shellcode, section_name, lief.PE.SECTION_CHARACTERISTICS.ALIGN_2BYTES | lief.PE.SECTION_CHARACTERISTICS.MEM_READ | lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)
  section = app.add_section(section)

else:
  raise Exception('Format not supported')

app.write(filename)
