#!/usr/bin/env python
import struct

from core import eBPFCoreApplication, set_event_handler
from core.packets import *

import sys
import time
import threading

from matplotlib import pyplot as plt

COUNTT_NAME = 'counters'
FTIMET_NAME = 'first_time'

# (time interval, in sec) (maximum packets per second)

# Parameters check
if len(sys.argv) < 2:
    #default parameters
    time_int = 10
    max_pkts = 05

elif len(sys.argv) == 3 :
    time_int = int(sys.argv[1])
    max_pkts = int(sys.argv[2])

# Local table
ftime_table = {}
count_table = {}

class QueryThread(threading.Thread):
    def __init__(self, event, connection):
        threading.Thread.__init__(self)
        self.stopped = event
        self.connection = connection

    def run(self):
       global gtime
       while not self.stopped.wait(time_int):
            print("Collecting data from switches")
            self.connection.send(TableListRequest(table_name=FTIMET_NAME))
            self.connection.send(TableListRequest(table_name=COUNTT_NAME))

class HeavyHitterIdApplication(eBPFCoreApplication):

    def HexTo2IPAddr(self, hex_value):
        addr1 = ""
        addr2 = ""
        for i in range(0, 7, 2):
            addr1 += str(int(hex_value[i:i+2], 16)) + "."
            addr2 += str(int(hex_value[i+8:i+10], 16)) + "."
        return addr1[0:-1], addr2[0:-1]

    def check_hh(self):
       curr_time = int(time.time())
       for pair_addr, num in count_table.items():
           addr1, addr2 = self.HexTo2IPAddr(pair_addr)
           diff_time = curr_time - ftime_table[pair_addr][0]
           if (num/diff_time) > max_pkts:
               print("Flow between " + addr1 + " and " + addr2 + \
                     " is above the threshold defined (" + \
                     str(num/diff_time) + " > " + str(max_pkts) + ")")
           else:
               print("Ok (" + str(num) + "pkts in " + str(diff_time) + " s)")

    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        with open('../examples/flowcount.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(elf=f.read()))

        self.queryThreadStopEvent = threading.Event()
        self.queryThread = QueryThread(self.queryThreadStopEvent, connection)
        self.queryThread.daemon = True
        self.queryThread.start()

    @set_event_handler(Header.TABLE_LIST_REPLY)
    def table_list_reply(self, connection, pkt):
        
        if pkt.HasField('items') and pkt.HasField('entry'):
            item_size = pkt.entry.key_size + pkt.entry.value_size

            if pkt.entry.table_name == COUNTT_NAME:
                fmt = "{}sI".format(pkt.entry.key_size) # pair ip_addr + counter
                for i in range(pkt.n_items):
                    paddr, npkts = struct.unpack_from(fmt, pkt.items, i * item_size)
                    count_table[paddr.encode('hex')] = npkts
                    # print paddr.encode('hex') + " - #pkts: " + str(npkts)
                self.check_hh()

            elif pkt.entry.table_name == FTIMET_NAME:
                fmt = "{}sII".format(pkt.entry.key_size) # pair ip_addr + sec + nsec
                for i in range(pkt.n_items):
                    paddr, tsec, tnsec = struct.unpack_from(fmt, pkt.items, i * item_size)
                    ftime_table[paddr.encode('hex')] = [tsec, tnsec]               
                    # print paddr.encode('hex') + " - #time: " + str(tsec) + " s " + str(tnsec)


if __name__ == '__main__':
    HeavyHitterIdApplication().run()
