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
READ_INTERVAL   = 0.5 # s
TABLE_NUM_PCKTS = "numpckts"

FILE1 = "../examples/count_pkts.o"
# FILE2 = "../examples/count_pkts.o"

# input reading
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
            # requests the number of packets and clear the table
            self.table_name = TABLE_NUM_PCKTS        
            self.connection.send(TableListRequest(table_name=self.table_name))
            self.connection.send(TableEntryInsertRequest(table_name=self.table_name, 
                                 key=struct.pack("Q", 0), 
                                 value=struct.pack("Q", 0)))


class CountPcktsApp(eBPFCoreApplication):
    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        with open(FILE1, "rb") as f:
            print("Installing the eBPF ELF ("+ FILE1 +")")
            connection.send(InstallRequest(elf=f.read()))
            print("eBPF ELF file sent")
            
        fname = time.strftime("%d-%m-%Y-%H:%M:%S.txt", time.gmtime())
        self.ltime = 0
        self.data  = [[], []]
        # self.out   = open(fname, "w+")
        # self.nonZero = False

        self.queryThreadStopEvent = threading.Event()
        self.queryThread = QueryThread(self.queryThreadStopEvent, connection)
        self.queryThread.daemon = True
        self.queryThread.start()

    #esse metodo que vai responder quando pedir pra listar as conexoes ativas, 
    @set_event_handler(Header.TABLE_LIST_REPLY)
    def table_list_reply(self, connection, pkt):
        self.table_name = TABLE_NUM_PCKTS
        refTime = time.time()
        if pkt.HasField("items") and pkt.HasField("entry"):
            item_size = pkt.entry.key_size + pkt.entry.value_size
            if pkt.entry.table_name == self.table_name:
                num_pckts = struct.unpack_from("Q", pkt.items)
            self.ltime += READ_INTERVAL
            self.data[0].append(self.ltime)
            self.data[1].append(num_pckts)
            print("{}: {}".format(refTime, num_pckts))
            
            # if pkt.n_items > 0:
            #     self.nonZero = True
            # avoid writing zeros at the end of simulation
            # if (pkt.n_items != 0 or not self.nonZero):
                # self.out.write("{},{},{}\n".format(self.ltime, self.data[1][-1], refTime))
            
            plt.clf()
            plt.plot(self.data[0], self.data[1])
            plt.ylabel("Number of Packets")
            plt.xlabel("Time (s)")
            plt.tight_layout()
            plt.draw()
            plt.pause(0.01)
        

if __name__ == "__main__":
#    data  = [[], []]
#    ltime = 0
    CountPcktsApp().run()
