#!/usr/bin/env python
import tornado.ioloop
import tornado.iostream
import tornado.netutil
import hexdump
import socket


class ServerOnline(object):
    def on_connected(self):
        print '%s:%d OK' % (self.host, self.port)

    def connect(self, host, port):

        self.host = host
        self.port = port

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        stream = tornado.iostream.IOStream(s);
        self.target_stream = stream
        stream.connect((self.host, port), self.on_connected)


for line in open('server.list'):
    line = line.strip()
    ServerOnline().connect(line, 800)

tornado.ioloop.IOLoop.instance().start()
