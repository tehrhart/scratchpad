#!/usr/bin/env python3
"""
VLAN DHCP Discovery Tool (Modernized)
February, 2026

Description:
  This tool performs a VLAN hopping discovery audit.
  It injects DHCP Discover packets tagged with VLAN IDs (0-4095)
  to identify which VLANs have active DHCP servers reachable from
  the current switch port.

  It utilizes a multi-threaded approach (Sender + Sniffer) to ensure
  asynchronous replies are captured effectively.
"""

import sys
import time
import random
import threading
import argparse
import struct
import logging
from scapy.all import (
    Ether, IP, UDP, BOOTP, DHCP, Dot1Q,
    get_if_hwaddr, sendp, sniff, conf
)

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Global list to store discovered results to avoid duplicates in output
found_vlans = set()
stop_sniffer = threading.Event()

def get_mac_bytes(mac_str):
    """Converts string MAC (e.g., 'aa:bb:cc...') to raw bytes for BOOTP chaddr."""
    return bytes.fromhex(mac_str.replace(':', ''))

def packet_callback(pkt, target_xid):
    """
    Callback function for the sniffer thread.
    Filters for DHCP Offers matching our transaction ID.
    """
    if DHCP in pkt:
        # Check if it is a DHCP Offer (MessageType 2)
        # Options is a list of tuples, e.g., [('message-type', 2), ('server_id', '...')]
        dhcp_opts = pkt[DHCP].options
        msg_type = next((opt[1] for opt in dhcp_opts if opt[0] == 'message-type'), None)
        
        if msg_type == 2:  # 2 = Offer
            # verify transaction ID matches our scanner
            if pkt[BOOTP].xid == target_xid:
                vlan_id = 0
                if Dot1Q in pkt:
                    vlan_id = pkt[Dot1Q].vlan
                
                # Deduplication logic
                if vlan_id not in found_vlans:
                    found_vlans.add(vlan_id)
                    
                    server_ip = pkt[IP].src
                    offered_ip = pkt[BOOTP].yiaddr
                    mac_src = pkt[Ether].src
                    
                    print(f"\n[+] SUCCESS: Found DHCP Server on VLAN {vlan_id}")
                    print(f"    |-- Server IP: {server_ip}")
                    print(f"    |-- Offered IP: {offered_ip}")
                    print(f"    |-- Server MAC: {mac_src}")

def sniffer_thread(interface, target_xid):
    """Background thread to listen for DHCP Offers."""
    logger.info(f"Sniffer started on {interface}. Waiting for offers...")
    # filter: UDP source port 67 (server) to dest port 68 (client)
    sniff(
        iface=interface,
        filter="udp and src port 67",
        prn=lambda x: packet_callback(x, target_xid),
        store=0,
        stop_filter=lambda x: stop_sniffer.is_set()
    )

def main():
    parser = argparse.ArgumentParser(description="VLAN DHCP Discovery Tool")
    parser.add_argument("interface", help="Network interface to use (e.g., eth0)")
    parser.add_argument("--delay", type=float, default=0.005, help="Delay between packets in seconds (default: 0.005)")
    parser.add_argument("--timeout", type=int, default=5, help="Seconds to wait after sending for final replies (default: 5)")
    parser.add_argument("--range", default="0-4095", help="VLAN range to scan (e.g., 10-20 or 0-4095)")
    
    args = parser.parse_args()

    # validate interface
    try:
        my_mac = get_if_hwaddr(args.interface)
        logger.info(f"Using Interface: {args.interface} ({my_mac})")
    except Exception as e:
        logger.error(f"Could not get MAC address for interface {args.interface}: {e}")
        sys.exit(1)

    # Generate a unique Transaction ID for this run
    # This ensures we don't pick up random DHCP noise from the network
    target_xid = random.randint(1, 0xFFFFFFFF)
    
    # Parse VLAN range
    try:
        if '-' in args.range:
            start_v, end_v = map(int, args.range.split('-'))
            vlan_list = range(start_v, end_v + 1)
        else:
            vlan_list = [int(args.range)]
    except ValueError:
        logger.error("Invalid range format. Use start-end (e.g., 10-100)")
        sys.exit(1)

    # 1. Start Sniffer Thread
    t = threading.Thread(target=sniffer_thread, args=(args.interface, target_xid))
    t.daemon = True
    t.start()
    
    # Give sniffer a moment to initialize
    time.sleep(1)

    # 2. Start Sending
    logger.info(f"Starting scan on {len(vlan_list)} VLANs with xid {hex(target_xid)}...")
    
    raw_mac = get_mac_bytes(my_mac)
    
    try:
        count = 0
        total = len(vlan_list)
        
        for vlan in vlan_list:
            # Construct DHCP Discover
            # Ether -> (Dot1Q) -> IP -> UDP -> BOOTP -> DHCP
            
            # Base Layer 2
            if vlan == 0:
                eth = Ether(src=my_mac, dst="ff:ff:ff:ff:ff:ff")
            else:
                eth = Ether(src=my_mac, dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=vlan)

            # Layer 3/4/7
            # Note: BOOTP flags=0x8000 requests broadcast reply (helps if we don't have IP yet)
            pkt = eth / \
                  IP(src="0.0.0.0", dst="255.255.255.255") / \
                  UDP(sport=68, dport=67) / \
                  BOOTP(chaddr=raw_mac, xid=target_xid, flags=0x8000) / \
                  DHCP(options=[("message-type", "discover"), "end"])
            
            sendp(pkt, iface=args.interface, verbose=0)
            
            count += 1
            if count % 100 == 0:
                sys.stdout.write(f"\rProgress: {count}/{total} packets sent...")
                sys.stdout.flush()
                
            time.sleep(args.delay)
            
    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user.")
    
    print(f"\nScanning complete. Waiting {args.timeout} seconds for late replies...")
    time.sleep(args.timeout)
    
    # Stop sniffer
    stop_sniffer.set()
    # Sending a dummy packet might be needed to unblock sniff() on some platforms,
    # but the daemon thread will die anyway when main exits.
    
    print("\n--- Scan Finished ---")
    if not found_vlans:
        print("No DHCP servers found on scanned VLANs.")
    else:
        print(f"Total VLANs with DHCP found: {len(found_vlans)}")

if __name__ == "__main__":
    # Ensure Scapy doesn't try to resolve DNS or verify checksums excessively
    conf.checkIPaddr = False
    main()
