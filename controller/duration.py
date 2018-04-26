#!/usr/bin/env python
import struct
import socket

from core import eBPFCoreApplication, set_event_handler, FLOOD
from core.packets import *

def int2ip(ipnum):
    o1 = int(ipnum / 16777216) % 256
    o2 = int(ipnum / 65536) % 256
    o3 = int(ipnum / 256) % 256
    o4 = int(ipnum) % 256
    return '{}.{}.{}.{}'.format(o4, o3, o2,o1)

class DurationApplication(eBPFCoreApplication):
    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
	self.begin = {}
        self.mac_to_port = {}

        with open('../examples/duration.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(elf=f.read()))

    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
	#print "Entrei no notify"
        tsec, tnsec, addr1, addr2, tp = struct.unpack('IIIII', pkt.data)
	if addr1 != addr2:
	        if tp == 0:
			if addr1+addr2 not in self.begin:			
				self.begin[addr1+addr2] = tsec
			else:
				if self.begin[addr1+addr2] == 0:
					self.begin[addr1+addr2] = tsec

			print "A flow from {} to {} started at {}.\n".format(int2ip(addr1), int2ip(addr2), tsec)
		elif tp == 1:
			if self.begin[addr1+addr2] != 0: 
				print "A flow from {} to {} lasted {} seconds.\n".format(int2ip(addr1), int2ip(addr2), tsec - self.begin[addr1+addr2])
				self.begin[addr1+addr2] = 0
		else:
			print "A flow from {} to {} reseted at {}.\n".format(int2ip(addr1), int2ip(addr2), tsec)


if __name__ == '__main__':
    DurationApplication().run()
