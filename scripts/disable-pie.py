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
    app.header.remove(lief.MachO.HEADER_FLAGS.PIE)

app.write(filename)
