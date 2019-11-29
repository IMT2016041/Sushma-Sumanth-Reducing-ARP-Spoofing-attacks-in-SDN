# Sushma-Sumanth-Reducing-ARP-Spoofing-attacks-in-SDN


Place the flowrules.py in ~/pox/pox/forwarding

* Run the POX controller using 
~/pox/pox.py log.level --DEBUG proto.dhcpd --network=10.1.1.0/24 --ip=10.1.1.1 forwarding.flowrules
* Run the topology using
  python demo.py


Project about mitigating ARP_SPOOFING ATTACKS

We have different set of conditions to check for REPLY and REQUEST packets. 

(The conditions have been taken from the paper)

1) ARP request packets: ARP request packet will be
considered spoofed, if it satisfies one of the following
conditions
• Source MAC address of ethernet header and source
MAC address of ARP header are not the same.
• Destination IP address in the ARP header is not present
in the known hosts list of the DHCP server.
• The MAC address binding present in the known hosts
list for the Source IP of the ARP header doesn’t match
with the source MAC address of the ARP header.

2) ARP reply packets: the ARP reply packet will be
considered spoofed, if it satisfies one of the following
conditions
• Source MAC address of ethernet header and source
MAC address of ARP header are not the same.
• Destination MAC address of ethernet header and
destination MAC address of ARP header are not the
same.
• The MAC address binding present in the known hosts
list for the Source IP of the ARP header doesn’t match
with the Source MAC address of the ARP header.
• The MAC address binding present in the known hosts
list, for the Destination IP of the ARP header doesn’t
match with the Destination MAC address of the ARP
header.
• Destination MAC address of the ethernet header has a
value of (FF:FF:FF:FF:FF:FF).
