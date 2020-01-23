#|/usr/bin/env python3

import sys
import lief

shellcode = [ 0x90 ] * 0x1000 # Assembly code

if len(sys.argv) < 2:
    print('Usage: python3 {} <FILE>'.format(sys.argv[0]))
    sys.exit(-1)

filename = sys.argv[1]

app = lief.parse(filename)

if app.is_pie:
    print('Binary is PIE, disabling it')
    app.header.remove(lief.MachO.HEADER_FLAGS.PIE)

for segment in app.segments:
  print('making {} rwx'.format(segment.name))
  segment.max_protection = 7
  segment.init_protection = 7

print('adding __shellcode section to __TEXT segment')
section = lief.MachO.Section("__shellcode", shellcode)
section.alignment = 2
section += lief.MachO.SECTION_FLAGS.SOME_INSTRUCTIONS
section += lief.MachO.SECTION_FLAGS.PURE_INSTRUCTIONS
section = app.add_section(section)

app.write(filename)
