#!/usr/bin/env python
"""
This tool sends out DHCP discovery packets without a 802.1q VLAN header,
 as well as with all possible VLAN headers added (1-4095), to detect
 what alternative VLANs are available that have active DHCP servers 
 operating when connected to switch ports that are not assigned a 
 default VLAN or otherwise allow 802.1q tags to be passed along.
"""
__author__ = "Tim Ehrhart"
__copyright__ = "Copyright 2017"
__license__ = "GPL"
__version__ = "1.0.2"
__maintainer__ = "Tim Ehrhart"
__email__ = "tehrhart@gmail.com"
__status__ = "Development"

from scapy.all import *
packets = []

def main():
	if len(sys.argv)<2:
		print "%s version %s by %s (%s)" % (sys.argv[0], __version__, 
			__author__, __email__)
		print "Usage: "
		print "\t%s <interface> [delay]" % (sys.argv[0])
		sys.exit(1)
		
	else:
		tap_interface = sys.argv[1]
		conf.checkIPaddr = False
		fam,hw = get_if_raw_hwaddr(conf.iface)
		if sys.argv == 3:
			interval=(sys.argv[2]/1)
		else:
			interval=0.002
		
		
		for i in xrange(4095):
			sendTaggedRequest(i, hw)

		ans, unans = srp(packets, iface=tap_interface, timeout=3,
			inter=interval)

		print "\nVLAN\tMAC Address\t\tDHCP Server IP"
		for p in ans:
			if Dot1Q in p[1]:
				print "%d\t%s\t%s" % (p[1][Ether][Dot1Q].vlan, 
					p[1][Ether].src, p[1][IP].src)
			else:
				print "(none)\t%s\t%s" % (p[1][Ether].src, 
					p[1][IP].src)	


def sendTaggedRequest(vlanInt, hw):
		
		if vlanInt == 0:
			dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])
		else:
			dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff")/Dot1Q(vlan=vlanInt)/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])
		global packets
		packets.append(dhcp_discover)
						
if __name__ == '__main__':
	main()
