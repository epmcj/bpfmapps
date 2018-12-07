#!/usr/bin/env python
import struct

from core import eBPFCoreApplication, set_event_handler
from core.packets import *

import time
import matplotlib
import threading
import sys
from matplotlib import pyplot as plt

# default values
READ_INTERVAL = 0.5 # s
T_ACTIVE      = 0.5 # s
AF_TABLE      = "activeflows"
FILE          = "../examples/af_v2.o"

i = 1
while i < len(sys.argv):
    if sys.argv[i] == "-ri":
        i += 1
        READ_INTERVAL = float(sys.argv[i])
        i += 1
    elif sys.argv[i] == "-ta":
        i += 1
        T_ACTIVE = float(sys.argv[i])
        i += 1
    else:
        print("Unknown parameter: " + sys.argv[i])
        exit(1)

plt.ion()
plt.draw()
plt.show()

class QueryThread(threading.Thread):
    def __init__(self, event, connection):
        threading.Thread.__init__(self)
        self.stopped = event
        self.connection = connection

    def run(self):
        while not self.stopped.wait(READ_INTERVAL):
            self.connection.send(TableListRequest(table_name="activeflows"))


class ActiveFlowsApplication(eBPFCoreApplication):
    def HexTo2IPAddr(self, hex_value):
        addr1 = ""
        addr2 = ""
        for i in range(0, 7, 2):
            addr1 += str(int(hex_value[i:i+2], 16)) + "."
            addr2 += str(int(hex_value[i+8:i+10], 16)) + "."
        return addr1[0:-1], addr2[0:-1]

    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        with open(FILE, "rb") as f:
            print("Installing the eBPF ELF ("+ FILE +")")
            connection.send(InstallRequest(elf=f.read()))
            print("eBPF ELF file sent")
            
        fname = time.strftime("%d-%m-%Y-%H:%M:%S.txt", time.gmtime())
        self.ltime = 0
        self.data  = [[], []]
        self.out   = open(fname, "w+")
        self.nonZero = False

        self.queryThreadStopEvent = threading.Event()
        self.queryThread = QueryThread(self.queryThreadStopEvent, connection)
        self.queryThread.daemon = True
        self.queryThread.start()

    #esse metodo que vai responder quando pedir pra listar as conexoes ativas, 
    @set_event_handler(Header.TABLE_LIST_REPLY)
    def table_list_reply(self, connection, pkt):
        if pkt.HasField("items") and pkt.HasField("entry"):
            item_size = pkt.entry.key_size + pkt.entry.value_size
            deleted = 0
            if pkt.entry.table_name == AF_TABLE:
                fmt = "{}sII".format(pkt.entry.key_size) # (ip_addr + s + ns)
                for i in range(pkt.n_items):
                    pair, ts, tns = struct.unpack_from(fmt, pkt.items, 
                                                       i * item_size)
                    if time.time() - (float(ts) + float(tns)/10**9) > T_ACTIVE:
                        deleted += 1
                        self.queryThread.connection.send(\
                            TableEntryDeleteRequest(table_name=AF_TABLE, 
                                                    key=pair))
            self.ltime += READ_INTERVAL
            self.data[0].append(self.ltime)
            self.data[1].append(pkt.n_items - deleted)
            
            if pkt.n_items > 0:
                self.nonZero = True
            # avoid writing zeros at the end of simulation
            if (pkt.n_items != 0 or not self.nonZero):
                self.out.write("%.2f,%d\n" % (self.ltime, pkt.n_items))
            
            plt.clf()
            plt.plot(self.data[0], self.data[1])
            plt.ylabel("Number of Active Flows")
            plt.xlabel("Time (s)")
            plt.tight_layout()
            plt.draw()
            plt.pause(0.01)
        print("{} active flows (deleted {}).").format(pkt.n_items, deleted)
        

if __name__ == "__main__":
#    data  = [[], []]
#    ltime = 0
    ActiveFlowsApplication().run()
