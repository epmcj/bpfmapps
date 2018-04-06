#!/usr/bin/env python
import struct

from core import eBPFCoreApplication, set_event_handler
from core.packets import *

import csv
import time
import matplotlib
import threading

from matplotlib import pyplot as plt

PROTO_TABLE_NAME = 'counters'
MAX_TO_SHOW      = 30 # max is 256

# table for ip protocols identification
csvFile = open('../protocol-numbers.csv')
reader  = csv.DictReader(csvFile)
pname   = [str(i) for i in range(256)]
for row in reader:
    try:
        pname[int(row['Decimal'])] = row['Keyword']
    except:
        False

plt.ion()
plt.title('Protocol Packet Count')
plt.xlabel('time (s)')
plt.draw()
plt.show()

class QueryThread(threading.Thread):
    def __init__(self, event, connection):
        threading.Thread.__init__(self)
        self.stopped = event
        self.connection = connection

    def run(self):
        while not self.stopped.wait(10):
            self.connection.send(TableListRequest(table_name=PROTO_TABLE_NAME))


class ProtoCountApplication(eBPFCoreApplication):

    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        with open('../examples/protocount.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(elf=f.read()))

        self.queryThreadStopEvent = threading.Event()
        self.queryThread = QueryThread(self.queryThreadStopEvent, connection)
        self.queryThread.daemon = True
        self.queryThread.start()

    @set_event_handler(Header.TABLE_LIST_REPLY)
    def table_list_reply(self, connection, pkt):
        plt.cla()
        plt.clf()

        num_elms = min(256, MAX_TO_SHOW) # pkt.n_items
        x        = range(num_elms)
        x_labels = pname[0:num_elms]
        data = [ ]
        
        item_size = pkt.entry.value_size

        for i in range(pkt.n_items):
            npackets, nbytes = struct.unpack_from('IQ', pkt.items, i * item_size)
            if i < num_elms:
                data.append(npackets)

        plt.bar(x, data, align='center')
        plt.xticks(x, x_labels, rotation=70)

        print 'new'
        plt.draw()
        plt.pause(0.01)

if __name__ == '__main__':
    ProtoCountApplication().run()
