'''
-- Programming Assignment

Professor: Marcos Vieira
'''

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
''' Add your imports here ... '''
import csv


log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ[ 'HOME' ]  

''' Add your global variables here ... '''


class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")

    def _handle_ConnectionUp (self, event):    
        ''' Add your logic here ... '''
        pFile = open(policyFile)
        policies = csv.DictReader(pFile)
        for entry in policies:
            # blocking msgs from mac_0 to mac_1
            msg = of.ofp_flow_mod()
            msg.match.dl_src = EthAddr(entry['mac_0'])
            msg.match.dl_dst = EthAddr(entry['mac_1'])
            msg.command = of.OFPFC_ADD
            msg.idle_timeout = of.OFP_FLOW_PERMANENT
            msg.hard_timeout = of.OFP_FLOW_PERMANENT
            msg.priority = int(entry['id'])
            msg.out_port = of.OFPP_NONE
	    event.connection.send(msg)
            # blocking msgs from mac_1 to mac_0
            msg = of.ofp_flow_mod()
            msg.match.dl_src = EthAddr(entry['mac_1'])
            msg.match.dl_dst = EthAddr(entry['mac_0'])
            msg.command = of.OFPFC_ADD
            msg.idle_timeout = of.OFP_FLOW_PERMANENT
            msg.hard_timeout = of.OFP_FLOW_PERMANENT
            msg.priority = int(entry['id'])
            msg.out_port = of.OFPP_NONE
	    event.connection.send(msg)
        pFile.close()
        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
