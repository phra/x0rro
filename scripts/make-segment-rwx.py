#|/usr/bin/env python3

import sys
import lief

def make_segment_rwx(segment):
    print('making {} rwx'.format(segment.name))
    segment.max_protection = 7
    segment.init_protection = 7

if len(sys.argv) < 2:
    print('Usage: python3 {} <FILE> [segments..]'.format(sys.argv[0]))
    sys.exit(-1)

filename = sys.argv[1]

app = lief.parse(filename)

if len(sys.argv) == 2:
  for segment in app.segments:
    make_segment_rwx(segment)
else:
  for i in range(2, len(sys.argv) - 1):
    for segment in app.segments:
      if sys.argv[i] in segment.name:
        make_segment_rwx(segment)

app.write(filename)
