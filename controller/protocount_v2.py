#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct

from core import eBPFCoreApplication, set_event_handler
from core.packets import *

import sys
import csv
import time
import matplotlib
import threading
from matplotlib import pyplot as plt

reload(sys)
sys.setdefaultencoding('utf-8')

if len(sys.argv) == 1:
    READ_INTERVAL = 1 # s
    print("Default option: Reading data every second.")
else:
    READ_INTERVAL = float(sys.argv[1]) # s
    print("Interval = {}".format(READ_INTERVAL))
# file path for figure
if len(sys.argv) == 3:
    FNAME = sys.argv[2]
else:
    FNAME  = ""
# file path for log
logName = time.strftime("pc%d-%m-%Y-%H:%M:%S.txt", time.gmtime())
    
PC_TABLE = 'counters'

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
plt.draw()
plt.show()

def autolabel(ax, rects, vals, fsize):
    """
    Attach a text label above each bar displaying its height
    """
    for i in range(len(rects)):
        rect = rects[i]
        val  = vals[i]
#    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width()/2., 1.0*height,
                '%d' % int(val), fontsize=fsize,
                ha='center', va='bottom')

def plot_bar_chart(x, xlabels, data, xlabel, ylabel, title, FNAME=""):    
    fsize = 30
    # updating plot
    plt.clf()
    plt.title(title)
    plt.ylabel(ylabel, fontsize=fsize)
    plt.xlabel(xlabel, fontsize=fsize)
    rects = plt.bar(x, data, align='center')
    ax = plt.gca()
    autolabel(ax, rects, data, fsize)
    plt.xticks(x, xlabels, rotation=70)
    
    for label in (ax.get_xticklabels() + ax.get_yticklabels()):
        label.set_fontsize(fsize)
    
    fig = plt.gcf()
    fig.set_size_inches(15, 12)
    
    plt.tight_layout()
    if FNAME is not "":
        plt.savefig(sys.argv[2], facecolor="w", transparent=True)
    plt.draw()
    plt.pause(0.01)

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
        with open('../examples/protocount.o', 'rb') as f:
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
        logFile   = open(logName, "w+")
        # getting data
        for i in range(pkt.n_items):
            npkts, nbytes = struct.unpack_from('IQ', pkt.items, i * item_size)
            if npkts > 0:
                x_labels.append(pname[i])
                data.append(npkts)        
        x = range(len(x_labels))
        # logging data (rewrite file at each reply)
        for value in data:
            logFile.write("%d\n" % (value)) #change to add protocol number !!!!
        logFile.close()        
        data = [val/10**3 for val in data]
        title = ''
#        ylabel = 'Number of Packets (in thousands)'
#        xlabel = 'Protocol'
        ylabel = 'Número de Pacotes (em milhares)'
        xlabel = 'Protocolo'
        plot_bar_chart(x, x_labels, data, xlabel, ylabel, title, FNAME)

if __name__ == '__main__':
    ProtoCountApplication().run()
