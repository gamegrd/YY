import ExchangeKey_pb2
import hexdump
import binascii
import rsa

h = ExchangeKey_pb2.ExchangeKey()

(pub_key, pri_key) = rsa.newkeys(512, 3)
h.cmd = 0x1
req = ExchangeKey_pb2.ExchangeKeyReq()

h.req.f1 = chr(0x01) + chr(0x00) + chr(0x01)
rsa_key = rsa.transform.int2bytes(pub_key.n)
reversed(rsa_key)
h.req.rsa_key = chr(0x00) + rsa_key

buffer = h.SerializeToString()
hexdump.hexdump(buffer)
print len(buffer)

#buffer = '08021A4A08001240DC066DC88D7836B85C5B771CB4AFE4BC46185FC2017417FB29E1EEA3A0B3E0A46B44929A2338F825D85F025305D9A4D5622447A037ECA9FC4E55ACD14952F7F9188080042078'
#h.ParseFromString(binascii.unhexlify(buffer))
#print h.ack
