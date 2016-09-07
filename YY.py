#!/usr/bin/env python
import tornado.ioloop
import tornado.iostream
import tornado.netutil
import tornado.web
import hexdump
import time
from hashlib import md5
import socket
import rsa
import YYProto_pb2
import struct
import hashlib
from  rc4 import *
from urlparse import urlparse
from ctypes import *
import os
import tempfile
import datetime
import random


YY_CLIENT_WAITING = -1
YY_CLIENT_CONNECTING = 1
YY_CLIENT_CONNECTED = 2
YY_CLIENT_HANDSHAKING = 3
YY_CLIENT_LOGINING = 4
YY_CLIENT_LOGINED = 5
YY_CLIENT_ERROR = 6

YYGenkey = cdll.LoadLibrary("./YYGenkey.so")

YY_Server_list = [
"120.132.152.74",
"120.132.152.78",
"120.132.152.72",
"120.132.152.78",
"183.136.136.66",
"183.136.136.67",
"113.106.100.76",
"113.106.100.80",
"113.106.100.81",
"183.61.2.102",
"113.106.100.77",
"120.132.152.73",
]
    
def gen_key(challenge):
    if len(challenge) != 0x40:
        return None

    key_buffer = create_string_buffer(0x100)
    challenge_buffer = create_string_buffer(0x40)
    c_str = c_char_p(challenge)

    rv = YYGenkey.generateKey(c_str, 0x40, key_buffer, 0x100)
    if rv == 1:
        m = md5()
        m.update(key_buffer)
        return m.digest()
    else:
        return None

def gen_imei(string):
    m = md5()
    m.update(string)
    imei = ''
    for c in m.hexdigest()[:14]:
        if ord(c) >= ord('0') and ord(c) <= ord('9'):
            imei += c
        else:
            imei += chr( ord(c) - ord('a') + ord('2') )
    imei += '0'
    return imei

class _DecodeError(Exception):
    def __init__(self):
        pass

def DecodeVarint(buffer, pos, mask = (1 << 32) - 1):
    result = 0
    shift = 0
    while 1:
        b = ord(buffer[pos])
        result |= ((b & 0x7f) << shift)
        pos += 1
        if not (b & 0x80):
            result &= mask
            return (result, pos)
        shift += 7
        if shift >= 64:
            raise _DecodeError('Too many bytes when decoding varint.')


def ReadTag(buffer, pos):
  start = pos
  while ord(buffer[pos]) & 0x80:
    pos += 1
  pos += 1
  return (buffer[start:pos], pos)


class YYclient(object):
    def __init__(self, username, password):
        self.username = username
        self.password = hashlib.sha1(password).hexdigest()
        self.rc4_e = None
        self.rc4_d = None
        #self.rsa = rsa #rsa.newkeys(512, 3)
        self.state = YY_CLIENT_WAITING
        self.recv_buffer = ''
        self.challenge = ''
        self.imei = gen_imei(username + ':-P')
        self.last_active = None
        self.score = 0
        self.sigin_time = 0
        self.uptime = '0'
        self.login_retry = 3

    def on_connected(self):
        self.state = YY_CLIENT_HANDSHAKING

        proto = YYProto_pb2.YYProto()
        (pub_key, pri_key) = rsa.newkeys(512, 3)

        self.rsa_pub_key = pub_key
        self.rsa_pri_key = pri_key

        proto.cmd = 0x1
        proto.key_req.f1 = chr(0x01) + chr(0x00) + chr(0x01)
        rsa_key = rsa.transform.int2bytes(pub_key.n)
        reversed(rsa_key)
        proto.key_req.rsa_key = chr(0x00) + rsa_key

        buffer = proto.SerializeToString()
        #hexdump.hexdump(buffer)
        self.stream.write(struct.pack('I', len(buffer)) + buffer)

    def on_handshake_respone(self, recv_buffer):
        proto = YYProto_pb2.YYProto()
        proto.ParseFromString(recv_buffer[4:])
        #hexdump.hexdump(proto.key_ack.rsa_key)
        try:
            rc4_key = rsa.decrypt(proto.key_ack.rsa_key, self.rsa_pri_key)
        except:

            print 'decode key error username %s' % (self.username)
            self.state = YY_CLIENT_WAITING
            self.stream.close()
            return
        self.rc4_e = RC4(rc4_key)
        self.rc4_d = RC4(rc4_key)
        #print 'rc4_key'
        #hexdump.hexdump(rc4_key)
        self.login_request()

    def login_request(self):
        proto = YYProto_pb2.YYProto()
        proto.cmd = 0x7
        proto.login_req.username = self.username
        proto.login_req.password = self.password
        proto.login_req.imei = self.imei
        proto.login_req.yymand = 'yyman,w'
        proto.login_req.proxy_proto = 'proxy_proto_4_0'
        proto.login_req.f12 = 0
        proto.login_req.version = '1.7.403021'
        proto.login_req.f15 = 1
        proto.login_req.f16 = 1

        buffer = proto.SerializeToString()
        self.send_request(buffer)
        self.state = YY_CLIENT_LOGINING

    def on_receive_heartbeatReq(self, data):
        if len(data) > 0x10:
            challenge = data[6:]
            key = gen_key(challenge)
            self.heartbeatAct(key)
        else:
            self.heartbeatAct()

        self.uptime = datetime.timedelta(seconds = int((time.time() - self.sigin_time)))
    
    def on_loginAct(self, data):
        self.sigin_time = time.time()
        recv_buffer = data
        #hexdump.hexdump(data)
        print 'recv_loginack %s' % (self.username)
        self.state = YY_CLIENT_LOGINED

    def heartbeatAct(self, data=None):
        proto = YYProto_pb2.HeartBeatAct()
        print 'send heartbeat %s' % (self.username)
        proto.cmd = 0x06
        if data:
            proto.f7.key = data
            buffer = proto.SerializeToString()
        else:
            buffer = proto.SerializeToString()
            buffer += struct.pack('BB', 0x3A, 0x00)

        #ioloop.add_timeout(time.time() + self.heartbeat_interval / 1000, self.heartbeatAct)
        self.send_request(buffer)

    def on_receive_data(self, data):

        self.last_active = time.time()

        if self.state == YY_CLIENT_HANDSHAKING:
            if len(data) < 0x40:
                self.stream.close()
                self.state = YY_CLIENT_WAITING
                return
            else:
                self.on_handshake_respone(data)
            return

        data =  self.rc4_d.update(data)
        self.recv_buffer += data
        if len(self.recv_buffer) < 4:
            return

        recv_buffer = self.recv_buffer
        if self.state == YY_CLIENT_LOGINING:
            pktlen = struct.unpack('H',recv_buffer[:2])[0]
            #print pktlen, len(recv_buffer)
            #hexdump.hexdump(recv_buffer)
            if pktlen < 0x10: #login failed
                self.stream.close()
                if self.login_retry > 0:
                    self.login_retry -= 1
                    self.state = YY_CLIENT_WAITING
                else:
                    self.state = YY_CLIENT_ERROR
                return

            if pktlen > 0x800:
                hexdump.hexdump(recv_buffer)
                print 'oh shit\n'
                self.stream.close()
                return
            if len(recv_buffer) >= pktlen + 4:
                data = recv_buffer[4:4 + pktlen]
                self.on_loginAct(data)
                recv_buffer = recv_buffer[4 + pktlen:]
                if len(recv_buffer) < 4:
                    self.recv_buffer = recv_buffer
                    return
            else:
                return

        if self.state == YY_CLIENT_LOGINED:
            pktlen = struct.unpack('I', recv_buffer[:4])[0]
            while (len(recv_buffer) - 4) >= pktlen:
                data = recv_buffer[4:4 + pktlen]
                tag, pos = ReadTag(data, 0)
                tag = ord(tag[:1])
                if (tag & 0x7) == 0:
                    cmd, _ = DecodeVarint(data[pos:], 0)
                    print 'CMD:%02X' % ( cmd )
                    #hexdump.hexdump(data)
                    if cmd == 0x05:
                        self.on_receive_heartbeatReq(data)

                recv_buffer = recv_buffer[pktlen + 4:]
                if len(recv_buffer) < 4:
                    break
                else:
                    pktlen = struct.unpack('I', recv_buffer[:4])[0]
            self.recv_buffer = recv_buffer


    def send_request(self, buffer):
        buffer = struct.pack('I', len(buffer)) + buffer
        #hexdump.hexdump(buffer)
        buffer = self.rc4_e.update(buffer)
        self.stream.write(buffer)

    def login(self, host, port):
        self.state = YY_CLIENT_CONNECTING
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        print ((host, port))
        stream = tornado.iostream.IOStream(s);
        self.stream = stream
        stream.connect((host, port), self.on_connected)
        self.stream.read_until_close(self.on_close, self.on_receive_data)

    def on_close(self, data):
        self.stream.close()

    def free(self):
        if not self.stream.closed():
            self.stream.close()

class YYclientManager(object):
    def __init__(self, login_interval = 1, config = None):
        self.clients = {}
        self.banned_clients = []
        self.login_interval = login_interval

        if config:
            self.add_user_by_config(config)

    def add_user(self, username, password):
        YY = YYclient(username, password)
        self.clients[username] = YY

    def add_user_by_config(self, config):
        if os.path.exists(config):
            for line in open(config):
                line = line.strip()
                if line == '':
                    continue
                (username, password) = line.split('----')
                print username, password
                YY = YYclient(username, password)
                self.clients[username] = YY
    
    def add_user_by_stream(self, stream):
        for line in stream.split():
                line = line.strip()
                if line == '':
                    continue
                (username, password) = line.split('----')
                print username, password
                YY = YYclient(username, password)
                self.clients[username] = YY

    def do_login(self):
        users = self.clients.keys()
        users.sort()
        for user in users:
            yy = self.clients[user]
            if yy.state == YY_CLIENT_WAITING:
                #yy.login('183.61.2.102', 805)
                #yy.login('proxy.mobile.yy.com', random.randint(801, 806))
                ip = random.choice(YY_Server_list)
                yy.login(ip, random.randint(800, 806))
                break

    def check_client_state(self):
        now = time.time()
        users = self.clients.keys()
        users.sort()
        print 'check client state'
        for user in users:
            yy = self.clients[user]
            if yy.last_active and (now  > yy.last_active  +  10 * 60): #10 min
                yy.state = YY_CLIENT_WAITING
                continue

            if yy.state == YY_CLIENT_ERROR:
                print 'banned? %s\n' % (yy.username)
                del self.clients[user]
                self.banned_clients.append(yy)
                continue

    def free(self):
        for client in self.clients.values():
            client.free()

        self.clients = {}
        for client in self.banned_clients:
            client.free()
        self.banned_clients = []

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        global client_manager
        yyclients = sorted(client_manager.clients.values(), key = lambda x:x.state, reverse=True)
        count = 0
        for c in yyclients:
            if c.state == YY_CLIENT_LOGINED:
                count += 1
        self.render("index.html", YYclients = yyclients, banned_YYclients = client_manager.banned_clients, sigin_users = count, 
                uptime = datetime.timedelta(seconds=int((time.time() - start_time))))

class UploadFileHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("upload.html")

    def post(self):
        if self.request.files:
            temp = tempfile.TemporaryFile()
            file_dict_list = self.request.files['file']
            for file_dict in file_dict_list:
                filename = file_dict["filename"]
                temp.write(file_dict["body"])
                client_manager.add_user_by_stream(file_dict["body"])
                #print file_dict["body"]
            temp.close()
        self.redirect('/', permanent=True)

class SettingsHandler(tornado.web.RequestHandler):
    def post(self):
        global login_timer
        disconnect = self.get_argument('disconnect', default='False')
        if disconnect != 'False':
            client_manager.free()
            self.redirect('/', permanent=True)
            return

        interval = self.get_argument('login_interval', default='1')
        try:
            interval = int(interval)
        except:
            interval = 1

        login_timer.stop()
        login_timer = tornado.ioloop.PeriodicCallback(client_manager.do_login, interval * 1000, ioloop) #3 secondes
        login_timer.start()

        self.redirect('/', permanent=True)

application = tornado.web.Application([
        (r"/", MainHandler),
        (r"/account/?", UploadFileHandler),
        (r"/settings/?", SettingsHandler),
        ])

client_manager = YYclientManager()
application.listen(8888)
start_time = time.time()
ioloop = tornado.ioloop.IOLoop.instance()
login_timer = tornado.ioloop.PeriodicCallback(client_manager.do_login, 1 * 1000, ioloop) #3 secondes
check_client_state = tornado.ioloop.PeriodicCallback(client_manager.check_client_state, 5 * 60 * 1000, ioloop) #five minites

check_client_state.start()
login_timer.start()
ioloop.start()
