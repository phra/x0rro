#|/usr/bin/env python3

import sys
import lief

if len(sys.argv) < 2:
    print('Usage: python3 {} <FILE> <entrypoint>'.format(sys.argv[0]))
    sys.exit(-1)

filename = sys.argv[1]

app = lief.parse(filename)

print("current entrypoint is: " + hex(app.entrypoint))

if len(sys.argv) == 3:
    if isinstance(app, lief.MachO.Binary):
        __TEXT = app.get_segment("__TEXT")
        app.main_command.entrypoint = int(sys.argv[2], 16) - __TEXT.virtual_address
    elif isinstance(app, lief.ELF.Binary):
        app.header.entrypoint = int(sys.argv[2], 16)
    print("new entrypoint is: " + hex(app.entrypoint))
    app.write(filename)
