#!/usr/bin/env python
import struct
import sys

from core import eBPFCoreApplication, set_event_handler
from core.packets import *

import time
import matplotlib
import threading

from matplotlib import pyplot as plt
import numpy as np


def Int2IP(ipnum):
    o1 = int(ipnum / 16777216) % 256
    o2 = int(ipnum / 65536) % 256
    o3 = int(ipnum / 256) % 256
    o4 = int(ipnum) % 256
    return '%(o4)s.%(o3)s.%(o2)s.%(o1)s' % locals()


class CountMinApplication(eBPFCoreApplication):
    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        with open('../examples/cmin.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(elf=f.read()))
            if len(sys.argv) < 2:
                max_value = 1
            else:
                max_value = int(sys.argv[1])
            print("Changing max value to {} packets per second".format(max_value))
            key = "".join(map(chr,[0,0,0,0]))
            connection.send(TableEntryInsertRequest(table_name="max", key=key, value=struct.pack('I', max_value)))
            print("Finished")

    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
        # print '\n[{}] Received notify event {}, data length {}'.format(connection.dpid, pkt.id, len(pkt.data))
        if len(pkt.data) == 8:
            addr1, addr2 = struct.unpack_from('II', pkt.data, 0)
            print "Addr1: " + Int2IP(addr1)
            print "Addr2: " + Int2IP(addr2)
        elif len(pkt.data) == 4:
            num = struct.unpack_from('I', pkt.data, 0)[0]
            print "Number: " + str(num)
        else:
            print pkt.data.encode('hex')


if __name__ == '__main__':
    CountMinApplication().run()
