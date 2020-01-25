#|/usr/bin/env python3

import sys
import lief

if len(sys.argv) < 2:
  print('Usage: python3 {} <FILE>'.format(sys.argv[0]))
  sys.exit(-1)

filename = sys.argv[1]

app = lief.parse(filename)

if app.is_pie:
  print('Binary is PIE, disabling it')
  if isinstance(app, lief.MachO.Binary):
    app.header.remove(lief.MachO.HEADER_FLAGS.PIE)
  else:
    raise Exception('Format not supported')
else:
  print('Binary is not PIE')

app.write(filename)
