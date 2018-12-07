#!/usr/bin/env python
import struct

from core import eBPFCoreApplication, set_event_handler
from core.packets import *

import sys
import time
import threading

COUNTT_NAME = 'counters'
FTIMET_NAME = 'first_time'
LTIMET_NAME = 'last_time'

# (time interval, in ms) (maximum packets per second) (maximum byte rate in Gbps)

# Parameters check
if len(sys.argv) == 1:
    #default parameters
    time_int = 0.5 # 500 ms
    max_pkts = 50
    capacity = (10**9) >> 9 # 1 Gbps => 1.25e8 bytes / 64 (for table)
    active_int = 1 # 1000 ms

elif len(sys.argv) == 5:
    time_int = float(sys.argv[1]) / 1000
    max_pkts = int(sys.argv[2])
    capacity = (float(sys.argv[3]) * (10**9)) / (8 * 64)
    active_int = float(sys.argv[4]) / 1000

else:
    print("Wrong parameters. Should be: ")
    print("./heavyhitter.py time_int max_pkts capacity active_int")
    exit(1)

# Local table
ftime_table = {}
count_table = {}

class QueryThread(threading.Thread):
    def __init__(self, event, connection):
        threading.Thread.__init__(self)
        self.stopped = event
        self.connection = connection

    def run(self):
       while not self.stopped.wait(time_int):
            # print("Collecting data from switches")
            self.connection.send(TableListRequest(table_name=FTIMET_NAME))
            self.connection.send(TableListRequest(table_name=COUNTT_NAME))
            self.connection.send(TableListRequest(table_name=LTIMET_NAME))

class HeavyHitterIdApplication(eBPFCoreApplication):

    def HexTo2IPAddr(self, hex_value):
        addr1 = ""
        addr2 = ""
        for i in range(0, 7, 2):
            addr1 += str(int(hex_value[i:i+2], 16)) + "."
            addr2 += str(int(hex_value[i+8:i+10], 16)) + "."
        return addr1[0:-1], addr2[0:-1]

    def check_hh(self):
       if len(count_table) == 0:
           return 0
       curr_time  = time.time()
       fair_slice = capacity / len(count_table) 
       for pair_addr, counter in count_table.items():
           npkts  = counter[0]
           nbytes = counter[1]
           addr1, addr2 = self.HexTo2IPAddr(pair_addr)
           diff_time    = curr_time - ftime_table[pair_addr]#[0]
           if (npkts/diff_time) > max_pkts:
               print("(!) Flow between " + addr1 + " and " + addr2 + \
                     " is above the threshold defined (" + \
                     str(npkts/diff_time) + " > " + str(max_pkts) + ")")
           # else:
           #    print("Ok (" + str(npkts) + "pkts in " + str(diff_time) + " s)")
           if (nbytes/diff_time) > fair_slice:
               print("(!) Flow between " + addr1 + " and " + addr2 + \
                     " is consuming more resources than it should (" + \
                     str(nbytes/diff_time) + " > " + str(fair_slice) + ")")
           # else:
           #    print("Flow is normal: " + str(nbytes/diff_time) + " < " + str(fair_slice))
              
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
                fmt = "{}sII".format(pkt.entry.key_size) # pair ip_addr + counters
                for i in range(pkt.n_items):
                    paddr, npkts, nbytes = struct.unpack_from(fmt, pkt.items, i * item_size)
                    count_table[paddr.encode('hex')] = [npkts, nbytes]
                    # print paddr.encode('hex') + " - #pkts: " + str(npkts)
                self.check_hh()

            elif pkt.entry.table_name == FTIMET_NAME:
                fmt = "{}sII".format(pkt.entry.key_size) # pair ip_addr + sec + nsec
                for i in range(pkt.n_items):
                    paddr, tsec, tnsec = struct.unpack_from(fmt, pkt.items, i * item_size)
                    ftime_table[paddr.encode('hex')] = float(tsec) + float(tnsec)/(10**9) # [tsec, tnsec]
                    # print paddr.encode('hex') + " - #time: " + str(tsec) + " s " + str(tnsec)

            elif pkt.entry.table_name == LTIMET_NAME:
                fmt = "{}sII".format(pkt.entry.key_size) # pair ip_addr + sec + nsec
                ctime = time.time()
                for i in range(pkt.n_items):
                    paddr, tsec, tnsec = struct.unpack_from(fmt, pkt.items, i * item_size)
                    ltime = float(tsec) + float(tnsec)/(10**9) # [tsec, tnsec]
                    if (ctime - ltime) > active_int:
                        # delete entries
                        addr1, addr2 = self.HexTo2IPAddr(paddr.encode('hex'))
                        print("deleting entries for {}:{}".format(addr1, addr2))
                        connection.send(TableEntryDeleteRequest(table_name=LTIMET_NAME, key=paddr))
                        connection.send(TableEntryDeleteRequest(table_name=FTIMET_NAME, key=paddr))
                        connection.send(TableEntryDeleteRequest(table_name=COUNTT_NAME, key=paddr))
#                    else:
#                        print("missing time: {}-{}".format(ctime-ltime, active_int))
                    # print paddr.encode('hex') + " - #time: " + str(tsec) + " s " + str(tnsec)


if __name__ == '__main__':
    print("Running HH Controller")
    HeavyHitterIdApplication().run()

