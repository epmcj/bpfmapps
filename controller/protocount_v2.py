#!/usr/bin/env python
import struct

from core import eBPFCoreApplication, set_event_handler
from core.packets import *

import sys
import csv
import time
import matplotlib
import threading

from matplotlib import pyplot as plt

if len(sys.argv) == 1:
    READ_INTERVAL = 1 # s
    print("Default option: Reading data every second.")
else:
    READ_INTERVAL = float(sys.argv[1]) # s
PC_TABLE = "counters"

# table for ip protocols identification
csvFile = open("../protocol-numbers.csv")
reader  = csv.DictReader(csvFile)
pname   = [str(i) for i in range(256)]
for row in reader:
    try:
        pname[int(row["Decimal"])] = row["Keyword"]
    except:
        False

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
            self.connection.send(TableListRequest(table_name=PC_TABLE))


class ProtoCountApplication(eBPFCoreApplication):

    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        with open("../examples/protocount.o", "rb") as f:
            print("Installing the eBPF ELF (protocount.o)")
            connection.send(InstallRequest(elf=f.read()))
            print("eBPF ELF file sent")
        self.queryThreadStopEvent = threading.Event()
        self.queryThread = QueryThread(self.queryThreadStopEvent, connection)
        self.queryThread.daemon = True
        self.queryThread.start()

    @set_event_handler(Header.TABLE_LIST_REPLY)
    def table_list_reply(self, connection, pkt):
        x_labels  = [ ]
        data      = [ ]        
        item_size = pkt.entry.value_size
        # getting data
        for i in range(pkt.n_items):
            npkts, nbytes = struct.unpack_from("IQ", pkt.items, i * item_size)
            if npkts > 0:
                x_labels.append(pname[i])
                data.append(npkts)
        if len(x_labels) > 0:
            x = range(len(x_labels))
            # updating plot
    #        plt.cla()
            plt.clf()
            plt.bar(x, data, align="center")
            plt.ylabel("Number of Packets")
            plt.xlabel("Protocol")
            plt.xticks(x, x_labels, rotation=70)
            plt.draw()
            plt.pause(0.01)

if __name__ == "__main__":
    ProtoCountApplication().run()
