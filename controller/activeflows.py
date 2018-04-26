#!/usr/bin/env python
import struct

from core import eBPFCoreApplication, set_event_handler
from core.packets import *

import time
import matplotlib
import threading
import sys

ACTIVE_FLOWS = "activeflows"

class QueryThread(threading.Thread):
    def __init__(self, event, connection):
        threading.Thread.__init__(self)
        self.stopped = event
        self.connection = connection

    def run(self):
        while not self.stopped.wait(5):
            self.connection.send(TableListRequest(table_name='activeflows'))


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
        with open('../examples/activeflows.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(elf=f.read()))

        self.queryThreadStopEvent = threading.Event()
        self.queryThread = QueryThread(self.queryThreadStopEvent, connection)
        self.queryThread.daemon = True
        self.queryThread.start()

    #esse metodo que vai responder quando pedir pra listar as conexoes ativas, 
    @set_event_handler(Header.TABLE_LIST_REPLY)
    def table_list_reply(self, connection, pkt):
        #interval = float(sys.argv[1])
	interval = 5
        if pkt.HasField('items') and pkt.HasField('entry'):
            item_size = pkt.entry.key_size + pkt.entry.value_size

            if pkt.entry.table_name == ACTIVE_FLOWS:
                fmt = "{}sII".format(pkt.entry.key_size) # triple ip_addr + sec + nsec
                for i in range(pkt.n_items):
                    paddr, tsec, tnsec = struct.unpack_from(fmt, pkt.items, i * item_size)
                    addr1, addr2 = self.HexTo2IPAddr(paddr.encode('hex'))
		    if time.time() - (float(tsec) + float(tnsec)/10**9) < 5:
		    	print("Flow from {} to {} is active!".format(addr1, addr2))
		    else:
			self.queryThread.connection.send(TableEntryDeleteRequest(table_name=ACTIVE_FLOWS, key=paddr))
		
		print("There are {} active flows in total.").format(pkt.n_items)
	

	
	

if __name__ == '__main__':
    ActiveFlowsApplication().run()
