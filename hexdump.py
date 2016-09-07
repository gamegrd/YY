#!/usr/bin/env python
# -*- coding: latin-1 -*-
"""
Dump binary data to the following text format:

0000000000: 00 00 00 5B 68 65 78 64  75 6D 70 5D 00 00 00 00  ...[hexdump]....
0000000010: 00 11 22 33 44 55 66 77  88 99 AA BB CC DD EE FF  .."3DUfw........

It is similar to the one used by:
Scapy
00 00 00 5B 68 65 78 64 75 6D 70 5D 00 00 00 00  ...[hexdump]....
00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF  .."3DUfw........

Far Manager
000000000: 00 00 00 5B 68 65 78 64 ¦ 75 6D 70 5D 00 00 00 00     [hexdump]
000000010: 00 11 22 33 44 55 66 77 ¦ 88 99 AA BB CC DD EE FF   ?"3DUfwˆ™ª»ÌÝîÿ

"""

__version__ = '0.3'
__author__  = 'anatoly techtonik <techtonik@gmail.com>'
__license__ = 'Public Domain'

__history__ = \
"""
0.3 (2013-04-29)
 * fully Python 3 compatible

0.2 (2013-04-28)
 * restore() to recover binary data from a hex dump in
   native, Far Manager and Scapy text formats (others
   might work as well)
 * restore() is Python 3 compatible

0.1 (2013-04-28)
 * working hexdump() function for Python 2
"""

import binascii  # binascii is required for Python 3
import sys

# --- constants
PY3K = sys.version_info >= (3, 0)

# --- helpers
def int2byte(i):
  '''convert int [0..255] to binary byte'''
  if PY3K:
    return i.to_bytes(1, 'little')
  else:
    return chr(i)

def chunks(seq, size): 
  '''Cut sequence into chunks of given size. If `seq` length is 
     not divisible by `size` without reminder, last chunk will 
     have length less than size. 

     >>> list( chunks([1,2,3,4,5,6,7], 3) ) 
     [[1, 2, 3], [4, 5, 6], [7]] 
  ''' 
  d, m = divmod(len(seq), size)
  for i in range(d):
    yield seq[i*size:(i+1)*size]
  if m: 
    yield seq[d*size:] 

# --- stuff
def hexdump(data):
  '''
  Print binary data in the hex dump text format:

  0000000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

    [x] data argument as a binary string
    [ ] data argument as an iterable
  '''
  if PY3K and type(data) == str:
    raise TypeError('Abstract unicode data (expected bytes)')

  line = ''
  for addr, d in enumerate(chunks(data, 16)):
    # 0000000000:
    line = '%010X: ' % (addr*16)
    # 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 
    dump = binascii.hexlify(d).decode('ascii').upper()
    dump = ' '.join(chunks(dump, 2))

    line += dump[:8*3]
    if len(d) > 8:  # insert separator if needed
      line += ' ' + dump[8*3:]
    # ................
    # calculate indentation, which may be different for the last line
    pad = 2
    if len(d) < 16:
      pad += 3*(16 - len(d))
    if len(d) <= 8:
      pad += 1
    line += ' '*pad

    for byte in d:
      # printable ASCII range 0x20 to 0x7E
      if not PY3K:
        byte = ord(byte)
      if 0x20 <= byte <= 0x7E:
        line += chr(byte)
      else:
        line += '.'

    line +='\r\n'
    print(line),

def restore(dump):
  '''
  Restore binary data from a hex dump.
    [x] dump argument as a string
    [ ] dump argument as a line iterator

  Supported formats:
    [x] hexdump.hexdump
    [x] Scapy
    [x] Far Manager
  '''
  minhexwidth = 2*16    # minimal width of the hex part - 00000... style
  bytehexwidth = 3*16-1 # min width for a bytewise dump - 00 00 ... style

  result = bytes() if PY3K else ''
  if type(dump) == str:
    text = dump.strip()  # ignore surrounding empty lines
    for line in text.split('\n'):
      # strip address part
      addrend = line.find(':')
      if 0 < addrend < minhexwidth:  # : is not in ascii part
        line = line[addrend+1:]
      line = line.lstrip()
      # check dump type
      if line[2] == ' ':  # 00 00 00 ...  type of dump
        # check separator
        sepstart = (2+1)*7+2  # ('00'+' ')*7+'00'
        sep = line[sepstart:sepstart+3]
        if sep[:2] == '  ' and sep[2:] != ' ':  # ...00 00  00 00...
          hexdata = line[:bytehexwidth+1]
        elif sep[2:] == ' ':  # ...00 00 | 00 00...  - Far Manager
          hexdata = line[:sepstart] + line[sepstart+3:bytehexwidth+2]
        else:                 # ...00 00 00 00... - Scapy, no separator
          hexdata = line[:bytehexwidth]

        # remove spaces and convert
        if PY3K:
          result += bytes.fromhex(hexdata)
        else:
          result += hexdata.replace(' ', '').decode('hex')
      else:
        raise TypeError('Unknown hexdump format')
  return result


if __name__ == '__main__':
  hexdump(b'zzzz'*12)
  hexdump(b'o'*17)
  hexdump(b'p'*24)
  hexdump(b'q'*26)
  hexdump(b'line\nfeed\r\ntest')
  hexdump(b'\x00\x00\x00\x5B\x68\x65\x78\x64\x75\x6D\x70\x5D\x00\x00\x00\x00'
          b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF')
  print('---')
  bin = open('hexfile.bin', 'rb').read()
  hexdump(bin)
  bindata = restore(
'''
0000000000: 00 00 00 5B 68 65 78 64  75 6D 70 5D 00 00 00 00  ...[hexdump]....
0000000010: 00 11 22 33 44 55 66 77  88 99 AA BB CC DD EE FF  .."3DUfw........
''')
  if bin == bindata:
    print('restore check passed')
  else:
    raise
  far = \
'''
000000000: 00 00 00 5B 68 65 78 64 ¦ 75 6D 70 5D 00 00 00 00     [hexdump]
000000010: 00 11 22 33 44 55 66 77 ¦ 88 99 AA BB CC DD EE FF   ?"3DUfwˆ™ª»ÌÝîÿ
'''
  if bin == restore(far):
    print('restore far format check passed')
  else:
    raise
  scapy = '''\
00 00 00 5B 68 65 78 64 75 6D 70 5D 00 00 00 00  ...[hexdump]....
00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF  .."3DUfw........
'''
  if bin == restore(scapy):
    print('restore scapy format check passed')
  else:
    raise
