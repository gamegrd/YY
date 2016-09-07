import binascii
import hexdump

class RC4:
   def __init__(self, key = ""):
       if key:
           self._rc4_init(key)

   def _rc4_init(self, key):
       (self.x,self.y) = (0,0)
       key_len = len(key)
       if key_len > 256 or key_len < 1:
           raise IndexError, 'Invalid key length' + key_len
       self.state_array = [i for i in xrange(0,256)] #self.stat_array = range(0,256)
       for i in xrange(0,256):
           self.x = ((ord(key[i%key_len]) & 0xff) + self.state_array[i] + self.x) & 0xff
           self.state_array[i], self.state_array[self.x] = self.state_array[self.x], self.state_array[i]
       self.x = 0

   def update(self, input):
       self.out = []
       for i in xrange(0,len(input)):
           self.x = (self.x + 1) & 0xff
           self.y = (self.state_array[self.x] + self.y) & 0xff
           self.state_array[self.x], self.state_array[self.y] = self.state_array[self.y], self.state_array[self.x]
           self.out.append(chr((ord(input[i]) ^ self.state_array[(self.state_array[self.x] + self.state_array[self.y]) & 0xff])))
       return "".join(self.out)

if __name__ == '__main__':
    key = 'F091172542D066E5F848E4BEAD43ACE1'
    data = 'F91C884344E7D3D1BA8DAEBF6E55A0ED4A60313D34555048F22441102DCB352602FE8F1478773FBF58FBE6D1E6F56DFB87E1F5B55901F24738444BE32191977F9CDFCEAD18DCDE65021F3303CBC3EC0545C939AA02016E04315FEAF90F07C7BF4841A0C886279EAAC9F4AD78576A74'

    key = binascii.unhexlify(key)
    data = binascii.unhexlify(data)
    rc4 = RC4(key)
    hexdump.hexdump(rc4.update(data))
    rc4 = RC4(key)
    hexdump.hexdump(rc4.update(data[:32]))
    hexdump.hexdump(rc4.update(data[32:]))

    rc4 = M2Crypto.RC4.RC4(key)
    hexdump.hexdump(rc4.update(data[:32]))
    hexdump.hexdump(rc4.update(data[32:]))
