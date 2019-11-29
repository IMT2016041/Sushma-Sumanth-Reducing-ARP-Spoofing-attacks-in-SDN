

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import pox.lib.packet as pkt
import time
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr


hosts = {}

log = core.getLogger()

_flood_delay = 0

def _handle_dhcp_lease(event):
  print "DHCP Packet \n"
  print "DHCP packet IP "+str(event.ip)+", MAC: "+str(event.host_mac)
  # Add this IP and MAC to the hosts dictionary
  if event.ip != None and event.host_mac != None :
  	hosts[str(event.ip)] = str(event.host_mac)
	print "****************  Host "+str(event.ip)+" added! with MAC: "+str(event.host_mac)+"*****************\n"


class LearningSwitch (object):
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Table to store MAC->PORT number
    self.macToPort = {}


    # listening for incoming packets
    connection.addListeners(self)


    self.hold_down_expired = _flood_delay == 0

    #adding entries for ARP traffic
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(dl_type = pkt.ethernet.ARP_TYPE);
    msg.idle_timeout = of.OFP_FLOW_PERMANENT;
    msg.hard_timeout = of.OFP_FLOW_PERMANENT;
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    self.connection.send(msg)
	
    # Add entries to intercept the DHCP traffic
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(nw_proto = 17, tp_src = 67 , tp_dst = 68 );
    msg.idle_timeout = of.OFP_FLOW_PERMANENT;
    msg.hard_timeout = of.OFP_FLOW_PERMANENT;
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    print "Installed flow entries\n"

    # Register a handler for DHCP lease packets
    core.DHCPD.addListenerByName('DHCPLease',_handle_dhcp_lease)

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """

    packet = event.parsed

    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass

      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    def handle_spoof(mac=None):
        print "---------------------Spoofing Detected !  Host Mac: "+str(mac)+" ------------------------\n"
        actions = []
        actions.append(of.ofp_action_output(port = of.OFPP_NONE)) # Drop
        msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=60, # Drop packets for 60 seconds
                                hard_timeout=60, # Drop packets for 60 seconds
                                buffer_id=event.ofp.buffer_id,
                                actions=actions,
                                match=of.ofp_match.from_packet(packet,
                                                               event.port))
        event.connection.send(msg.pack())
        print "Installed an entry to drop all the packets from the port"

	
    if packet.type == packet.ARP_TYPE:
		
		print "Its ARP\n"

		if packet.payload.opcode == pkt.arp.REQUEST :
			print "REQ packet..............."
			src_mac_eth = packet.src
			dst_mac_eth = packet.dst
			src_ip_arp = packet.payload.protosrc
			src_mac_arp = packet.payload.hwsrc 
			dst_ip_arp = packet.payload.protodst

			print "Source MAC : "+str(src_mac_arp)+"\n";
			print "Dest MAC : "+str(dst_mac_eth)+"\n";
			print "Source IP : "+str(src_ip_arp)+"\n";
			print "Source DST : "+str(dst_ip_arp)+"\n";
			

			
			if src_mac_eth != src_mac_arp :

				handle_spoof(src_mac_eth)
				return
			else:

				# Check if the source ip and src MAC are matched and stored earlier
				print "Table MAC : "+hosts[str(src_ip_arp)]+" and mac "+str(src_mac_arp)+"\n";
				if EthAddr(hosts[str(src_ip_arp)]) != src_mac_arp:
					print "Spoofing detected: IP and MAC not matched\n"
				        handle_spoof(src_mac_eth)
					print "Dropping\n"
					return
				else:

					print "Valid ARP\n";

					if dst_ip_arp not in hosts.keys():
						# Spoofing detected
						print "Spoofing detected: Dest host ip not in table\n"
						#drop()
				                handle_spoof(src_mac_eth)
						return
					else:
						if str(dst_mac_eth) == "ff:ff:ff:ff:ff:ff":
							# Now flood the packets to all the other ports
							print "Flooding the packets\n"
						else:
							# ARP Request should be broadcast. Some are unicast sometimes.
							print "Unicast ARP packet detected\n"


		if packet.payload.opcode == pkt.arp.REPLY :
			print "Reply packet..............."
			src_mac_eth = packet.src
			dst_mac_eth = packet.dst
			src_ip_arp = packet.payload.protosrc
			src_mac_arp = packet.payload.hwsrc 
			dst_ip_arp = packet.payload.protodst
			dst_mac_arp= packet.payload.hwdst

			print "Source MAC : "+str(src_mac_arp)+"\n";
			print "Dest MAC : "+str(dst_mac_eth)+"\n";
			print "Source IP : "+str(src_ip_arp)+"\n";
			print "Source DST : "+str(dst_ip_arp)+"\n";
			

			
			if src_mac_eth != src_mac_arp :

				handle_spoof(src_mac_eth)
				return
			
			elif dst_mac_eth!= dst_mac_arp:

				handle_spoof(src_mac_eth)
				return

			else:

				# Check if the source ip and src MAC are matched and stored earlier
				print "Table MAC : "+hosts[str(src_ip_arp)]+" and mac "+str(src_mac_arp)+"\n";
				if EthAddr(hosts[str(src_ip_arp)]) != src_mac_arp:
					print "Spoofing detected: IP and MAC not matched\n"
				        handle_spoof(src_mac_eth)
					print "Dropping\n"
					return

				

				elif dst_ip_arp not in hosts.keys():
					# Spoofing detected
					print "Spoofing detected: Dest host ip not in table\n"
					#drop()
			                handle_spoof(src_mac_eth)
					return


				else:
					if EthAddr(hosts[str(dst_ip_arp)]) != dst_mac_arp:
						print "Spoofing detected: IP and MAC not matched\n"
						handle_spoof(src_mac_eth)
						print "Dropping\n"
						return
					else:
						if str(dst_mac_eth) == "ff:ff:ff:ff:ff:ff":
							# Now flood the packets to all the other ports
							print "Flooding the packets\n"
						else:
							# ARP Request should be broadcast. Some are unicast sometimes.
							print "Unicast ARP packet detected\n"






    self.macToPort[packet.src] = event.port 

    if not self.transparent: 
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() 
        return

    if packet.dst.is_multicast:
      flood() 
    else:
      if packet.dst not in self.macToPort: 
        flood("Port for %s unknown -- flooding" % (packet.dst,))
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: 
          
          log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return
        
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp 
        self.connection.send(msg)
 

class l2_learning (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent):
    core.openflow.addListeners(self)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection, self.transparent)


def launch (transparent=False, hold_down=_flood_delay):
  """
  Starts an L2 learning switch.
  """
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  core.registerNew(l2_learning, str_to_bool(transparent))	
