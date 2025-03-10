# #This is PA2, SDN
# #By Brigham Inkley

# from pox.core import core
# import pox.openflow.libopenflow_01 as of
# from pox.lib.addresses import IPAddr, EthAddr
# from pox.lib.packet import ethernet, arp

# log = core.getLogger()

# # Virtual IP and backend servers
# VIRTUAL_IP = IPAddr("10.0.0.10")
# SERVERS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]
# MACS = {IPAddr("10.0.0.5"): EthAddr("00:00:00:00:00:05"),
#         IPAddr("10.0.0.6"): EthAddr("00:00:00:00:00:06")}
# server_index = 0  # Tracks which server to assign next

# class LoadBalancer (object):
#     def __init__(self, connection):
#         self.connection = connection
#         connection.addListeners(self)

#     def _handle_PacketIn(self, event):
#         try:
#             global server_index
#             packet = event.parsed

#             if packet.type == packet.ARP_TYPE and packet.payload.protodst == VIRTUAL_IP:
#                 log.info("Intercepted ARP request for virtual IP")
#                 server_ip = SERVERS[server_index]
#                 server_mac = MACS[server_ip]

#                 # Create and send ARP reply
#                 arp_reply = arp()
#                 arp_reply.hwsrc = server_mac
#                 arp_reply.hwdst = packet.payload.protosrc
#                 arp_reply.opcode = arp.REPLY
#                 arp_reply.protosrc = VIRTUAL_IP
#                 arp_reply.protodst = packet.payload.protosrc

#                 ethernet_reply = ethernet()
#                 ethernet_reply.src = server_mac
#                 ethernet_reply.dst = packet.src
#                 ethernet_reply.type = ethernet.ARP_TYPE
#                 ethernet_reply.payload = arp_reply

#                 msg = of.ofp_packet_out()
#                 msg.data = ethernet_reply.pack()
#                 msg.actions.append(of.ofp_action_output(port=event.port))
#                 self.connection.send(msg)

#                 # Rotate server for round-robin balancing
#                 server_index = (server_index + 1) % len(SERVERS)

#                 self.install_flow(event.port, server_ip, server_mac, packet)
#         except Exception as e:
#             log.error(f"Error handling PacketIn event: {e}")
        

#     def install_flow(self, client_port, server_ip, server_mac, packet):
#         log.info("Installing client-to-server flow:")
#         log.info(f"  Match: in_port={client_port}, dl_type=0x0800, nw_dst={VIRTUAL_IP}")
#         log.info(f"  Actions: set_dst(mac)={server_mac}, set_dst(ip)={server_ip}, output={self.connection.ports[server_ip]}")

#         msg_client_to_server = of.ofp_flow_mod()
#         msg_client_to_server.match.dl_type = 0x0800  
#         msg_client_to_server.match.nw_dst = VIRTUAL_IP  
#         msg_client_to_server.match.in_port = client_port 

#         msg_client_to_server.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
#         msg_client_to_server.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))

#         msg_client_to_server.actions.append(of.ofp_action_output(port=self.connection.ports[server_ip]))
#         self.connection.send(msg_client_to_server)

#         log.info("Installing server-to-client flow:")
#         log.info(f"  Match: in_port={self.connection.ports[server_ip]}, dl_type=0x0800, nw_src={server_ip}, nw_dst={packet.payload.protosrc}")
#         log.info(f"  Actions: set_src(ip)={VIRTUAL_IP}, set_src(mac)={server_mac}, output={client_port}")

#         msg_server_to_client = of.ofp_flow_mod()
#         msg_server_to_client.match.dl_type = 0x0800  
#         msg_server_to_client.match.nw_src = server_ip  
#         msg_server_to_client.match.nw_dst = packet.payload.protosrc

#         msg_server_to_client.match.in_port = self.connection.ports[server_ip] 

#         msg_server_to_client.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
#         msg_server_to_client.actions.append(of.ofp_action_dl_addr.set_src(server_mac))

#         msg_server_to_client.actions.append(of.ofp_action_output(port=client_port))
#         self.connection.send(msg_server_to_client)

# def launch():
#     def start_switch(event):
#         log.info("Initializing Load Balancer")
#         LoadBalancer(event.connection)

#     core.openflow.addListenerByName("ConnectionUp", start_switch)

from pox.core import core
from pox.openflow import libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
import time

log = core.getLogger()

# Virtual IP address
VIRTUAL_IP = "10.0.0.1"
VIRTUAL_MAC = EthAddr("00:00:00:00:00:01")

# A mapping of virtual IP to real IPs (example)
REAL_IPS = {
    "10.0.0.2": EthAddr("00:00:00:00:00:02"),
    "10.0.0.3": EthAddr("00:00:00:00:00:03"),
}

# This dictionary will hold information about virtual IP and mapping rules
arp_cache = {}

def _handle_ConnectionUp(event):
    """
    Handles a new connection to the switch and sets up flow rules.
    """
    log.info("Switch %s has connected.", event.dpid)

    # Install flow rules for packets coming into port 1 and port 2
    msg = of.ofp_flow_mod()
    msg.match.in_port = 1
    msg.match.dl_type = 0x0800  # Match IPv4 packets
    msg.actions.append(of.ofp_action_output(port=2))  # Forward to port 2
    event.connection.send(msg)

    msg = of.ofp_flow_mod()
    msg.match.in_port = 2
    msg.match.dl_type = 0x0800  # Match IPv4 packets
    msg.actions.append(of.ofp_action_output(port=1))  # Forward to port 1
    event.connection.send(msg)

    log.info("Initial flow rules installed for port 1 and port 2.")

    # Install ARP interception rule to respond to ARP requests for the virtual IP
    msg = of.ofp_flow_mod()
    msg.match.dl_type = 0x0806  # ARP packets
    msg.match.nw_proto = 0x01  # ARP request
    msg.match.nw_dst = IPAddr(VIRTUAL_IP)  # Match ARP requests to the virtual IP
    msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))  # Send to controller
    event.connection.send(msg)

    log.info("ARP interception rule installed for virtual IP: %s", VIRTUAL_IP)

def _handle_ArpRequest(event, arp_req):
    """
    Handles ARP requests and responds with the virtual MAC address.
    """
    # Check if the ARP request is for the virtual IP
    if arp_req.dst_ip == IPAddr(VIRTUAL_IP):
        log.info("Intercepted ARP request for virtual IP: %s", VIRTUAL_IP)
        # Respond with a crafted ARP reply
        arp_reply = of.ofp_packet_in()
        arp_reply.match = arp_req.match
        arp_reply.actions.append(of.ofp_action_nw_addr(VIRTUAL_IP))  # Send virtual IP
        arp_reply.actions.append(of.ofp_action_dl_addr(VIRTUAL_MAC))  # Send virtual MAC
        event.connection.send(arp_reply)
        log.info("Sent ARP reply with virtual MAC address: %s", VIRTUAL_MAC)

def _handle_PacketIn(event):
    """
    Handles incoming packets and installs the flow rules for forwarding them.
    """
    packet = event.parsed  # Get the parsed packet

    # If it's an ARP packet, process it
    if packet.type == packet.ARP_TYPE:
        arp_request = packet.payload
        _handle_ArpRequest(event, arp_request)

    # If it's an IP packet, do IP forwarding based on flow rules
    elif packet.type == packet.IP_TYPE:
        ip_packet = packet.payload
        if ip_packet.dstip in REAL_IPS:
            real_mac = REAL_IPS[str(ip_packet.dstip)]
            log.info("Forwarding IP packet to real MAC: %s", real_mac)
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet)
            msg.actions.append(of.ofp_action_dl_addr(real_mac))
            event.connection.send(msg)

def launch():
    """
    Launch the POX controller application.
    """
    log.info("Starting Load Balancer POX Application.")
    
    # Add listeners for OpenFlow events
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)

    log.info("Load Balancer POX Application is running.")