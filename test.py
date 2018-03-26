'''
-- Programming Assignment
Professor: Marcos Vieira
'''

import urllib
import urllib2
import hashlib
import random
import email
import email.message
import email.encoders
import StringIO
import sys

""""""""""""""""""""
""""""""""""""""""""

from mininet.net import Mininet                                                           
from mininet.node import Controller                                                                    
from mininet.topo import SingleSwitchTopo   
from mininet.log import setLogLevel
import os


class POXBridge( Controller ):                                                                         
  "Custom Controller class to invoke POX"                                     
  def start( self ):                                                                                 
    "Start POX learning switch"                                                                    
    self.pox = '%s/pox/pox.py' % os.environ[ 'HOME' ]  
    self.cmd( self.pox, 'forwarding.l2_learning misc.firewall &' )                                               
  def stop( self ):                                                                                  
    "Stop POX"                                                                                     
    self.cmd( 'kill %' + self.pox )                      
          
def output():
  outputString = ''
  
  
  print "a. Firing up Mininet"
  net = Mininet( topo=SingleSwitchTopo( 8 ), controller=POXBridge, autoSetMacs=True )                                  
  net.start()   

  h3 = net.get('h3')
  h4 = net.get('h4')
  h6 = net.get('h6')
  
  print "b. Starting Test"
  # Start pings
  outputString += h3.cmd('ping', '-c3', h6.IP())
  outputString += h4.cmd('ping', '-c3', h6.IP())

  print outputString
    
  print "c. Stopping Mininet"
  net.stop()
    
  return outputString.strip()

output()