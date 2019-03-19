#!/usr/bin/env python
import struct

from core import eBPFCoreApplication, set_event_handler
from core.packets import *

import time
import matplotlib
import threading
import sys
from matplotlib import pyplot as plt

class CallOnInputThread(threading.Thread):
    def __init__(self, fn):
        threading.Thread.__init__(self)
        self.fn = fn
        
    def run(self):
        while True:
            cmd = raw_input(">> ")
            if cmd == "c":
                self.fn()

class QueryThread(threading.Thread):
    def __init__(self, event, connection, table):
        threading.Thread.__init__(self)
        self.stopped    = event
        self.connection = connection
        self.table_name = table

    def run(self):
        while not self.stopped.wait(READ_INTERVAL):
            # requests the number of packets and clear the table
            self.connection.send(TableListRequest(table_name=self.table_name))

class CountPcktsApp(eBPFCoreApplication):
    def install_next_program(self):
        elfName = self.programs[self.nextMode]
        with open(elfName, "rb") as f:
            print("Installing the eBPF ELF ("+ elfName +")")
            self.connection.send(InstallRequest(elf=f.read()))
            print("eBPF ELF file sent")
        # update nextMode for the next program installation
        self.queryThread.table_name = self.tables[self.nextMode]
        self.nextMode = (self.nextMode + 1) % 2 # nextMode is global
        
    def set_tables(self, tables):
        self.tables = tables
        
    def set_programs(self, programs):
        self.programs = programs
        
    def set_init_program(self, index):
        if index > len(self.programs):
            print("index {} of {} programs".format(index, len(self.programs)))
            exit(1)
        self.nextMode = index

    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        self.connection = connection # saving to change the program later
            
        fname = time.strftime("%d-%m-%Y-%H:%M:%S.txt", time.gmtime())
        self.ltime = 0
        self.data  = [[], []]
        # self.out   = open(fname, "w+")
        # self.nonZero = False

        self.queryThreadStopEvent = threading.Event()
        self.queryThread = QueryThread(self.queryThreadStopEvent, connection, "")
        self.queryThread.daemon = True
        self.queryThread.start()        

        self.install_next_program()
 
    @set_event_handler(Header.TABLE_LIST_REPLY)
    def table_list_reply(self, connection, pkt):
        refTime = time.time()
        if pkt.HasField("items") and pkt.HasField("entry"):
            item_size = pkt.entry.key_size + pkt.entry.value_size
            if pkt.entry.table_name == self.tables[0]:
                # table with a counter for all packets
                num_pckts = struct.unpack_from("Q", pkt.items)
                print("{}: {}".format(refTime, num_pckts))
            else:
                # table with counters for some IP protocol packets
                # print("items: ", len(pkt.items))
                fmt = "{}Q".format(pkt.n_items)
                pckts = struct.unpack_from(fmt, pkt.items)
                print("{}: {}".format(refTime, pckts))
            
            # self.ltime += READ_INTERVAL
            # self.data[0].append(self.ltime)
            # self.data[1].append(num_pckts)
        
            # if pkt.n_items > 0:
            #     self.nonZero = True
            # avoid writing zeros at the end of simulation
            # if (pkt.n_items != 0 or not self.nonZero):
                # self.out.write("{},{},{}\n".format(self.ltime, self.data[1][-1], refTime))
            
            # plt.clf()
            # plt.plot(self.data[0], self.data[1])
            # plt.ylabel("Number of Packets")
            # plt.xlabel("Time (s)")
            # plt.tight_layout()
            # plt.draw()
            # plt.pause(0.01)
        

if __name__ == "__main__":
    # default values
    READ_INTERVAL   = 0.5 # s

    FILES    = ["../examples/count_pkts.o", "../examples/count_subpkts.o"]
    TABLES   = ["numpckts", "numppp"]
    nextMode = 0

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

    # plt.ion()
    # plt.draw()
    # plt.show()

    app = CountPcktsApp()
    app.set_programs(FILES)
    app.set_init_program(nextMode)
    app.set_tables(TABLES)
    
    ct = CallOnInputThread(app.install_next_program)
    ct.daemon = True
    ct.start()
    
    app.run()
