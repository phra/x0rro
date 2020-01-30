#|/usr/bin/env python3

import sys
import lief

if len(sys.argv) < 2:
    print('Usage: python3 {} <FILE> [segments..]'.format(sys.argv[0]))
    sys.exit(-1)

def make_segment_rwx(segment):
  if not 'PAGEZERO' in segment.name:
    print('making {} rwx'.format(segment.name))
    segment.max_protection = 7
    #segment.init_protection = 7

def make_section_rwx(section):
  print('making {} rwx'.format(section.name))
  section += lief.ELF.SECTION_FLAGS.EXECINSTR
  section += lief.ELF.SECTION_FLAGS.WRITE
  section += lief.ELF.SECTION_FLAGS.ALLOC

def make_pe_section_rwx(section):
  print('making {} rwx'.format(section.name))
  section.characteristics = section.characteristics | lief.PE.SECTION_CHARACTERISTICS.MEM_READ | lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE

filename = sys.argv[1]

app = lief.parse(filename)

if isinstance(app, lief.MachO.Binary):
  if len(sys.argv) == 2:
    for segment in app.segments:
      make_segment_rwx(segment)
  else:
    for i in range(2, len(sys.argv)):
      for segment in app.segments:
        if sys.argv[i] in segment.name:
          make_segment_rwx(segment)
elif isinstance(app, lief.ELF.Binary):
  if len(sys.argv) == 2:
    for segment in app.segments:
      for section in segment.sections:
        make_section_rwx(section)
  else:
    for i in range(2, len(sys.argv)):
      for segment in app.segments:
        for section in segment.sections:
          if sys.argv[i] in section.name:
            make_section_rwx(section)
elif isinstance(app, lief.PE.Binary):
  if len(sys.argv) == 2:
    for section in app.sections:
      make_pe_section_rwx(section)
  else:
    for i in range(2, len(sys.argv)):
      for section in app.sections:
        if sys.argv[i] in section.name:
          make_pe_section_rwx(section)
else:
  raise Exception('Format not supported')

app.write(filename)
