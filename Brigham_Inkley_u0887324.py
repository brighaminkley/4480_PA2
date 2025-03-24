# PA2 - SDN Load Balancer
# By Brigham Inkley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp

log = core.getLogger()

# Virtual IP and Backend Servers
VIRTUAL_IP = IPAddr("10.0.0.10")
VIRTUAL_MAC = EthAddr("00:00:00:00:00:10")  # Virtual MAC for outbound packets
SERVERS = [
    {"ip": IPAddr("10.0.0.5"), "mac": EthAddr("00:00:00:00:00:05")},
    {"ip": IPAddr("10.0.0.6"), "mac": EthAddr("00:00:00:00:00:06")},
]
server_index = 0  # Round-robin counter

SERVER_PORTS = {
    IPAddr("10.0.0.5"): 5,  # Port for h5
    IPAddr("10.0.0.6"): 6   # Port for h6
}

CLIENT_TO_SERVER = {}  # Stores mappings of clients to backend servers


class VirtualIPLoadBalancer:
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("Load Balancer initialized.")

    def _handle_PacketIn(self, event):
        """Handles incoming packets and determines how to process them."""
        global server_index
        packet = event.parsed

        if not packet:
            log.warning("Received empty packet. Ignoring.")
            return

        if packet.type == ethernet.ARP_TYPE:
            self._handle_arp(event, packet)
        elif packet.type == ethernet.IP_TYPE:
            self._handle_ip(event, packet)
        else:
            log.warning(f"Unhandled packet type: {packet.type}")

    def _handle_arp(self, event, packet):
        """Handles ARP requests for the Virtual IP and backend servers."""
        global server_index
        arp_pkt = packet.next
        src_ip = arp_pkt.protosrc
        dst_ip = arp_pkt.protodst

        # Handle ARP Requests for Virtual IP
        if arp_pkt.opcode == arp.REQUEST and dst_ip == VIRTUAL_IP:
            log.info(f"Received ARP request for {VIRTUAL_IP}. Assigning backend server.")

            # Select the next server in round-robin order
            server = SERVERS[server_index]
            server_index = (server_index + 1) % len(SERVERS)

            CLIENT_TO_SERVER[src_ip] = server

            # Construct ARP reply
            arp_reply = arp()
            arp_reply.hwsrc = server["mac"]
            arp_reply.hwdst = packet.src
            arp_reply.opcode = arp.REPLY
            arp_reply.protosrc = VIRTUAL_IP
            arp_reply.protodst = src_ip

            # Create Ethernet frame
            ethernet_reply = ethernet()
            ethernet_reply.type = ethernet.ARP_TYPE
            ethernet_reply.src = server["mac"]
            ethernet_reply.dst = packet.src
            ethernet_reply.payload = arp_reply

            # Send ARP response
            msg = of.ofp_packet_out()
            msg.data = ethernet_reply.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))
            self.connection.send(msg)
            log.info(f"Sent ARP reply with MAC {server['mac']} for {VIRTUAL_IP}.")

            self._install_flow_rules(event.port, packet.src, src_ip, server["ip"], server["mac"])

    def _handle_ip(self, event, packet):
        """Handles all IP packets (ICMP, TCP, UDP) and directs them correctly."""
        ip_packet = packet.next
        client_ip = ip_packet.srcip
        dst_ip = ip_packet.dstip

        log.info(f"Received IP packet from {client_ip} to {dst_ip}")

        # If the destination is the Virtual IP, forward it to a backend server
        if dst_ip == VIRTUAL_IP:
            if client_ip not in CLIENT_TO_SERVER:
                # Assign a backend server (round-robin)
                server = SERVERS[server_index]
                server_index = (server_index + 1) % len(SERVERS)
                CLIENT_TO_SERVER[client_ip] = server
            else:
                server = CLIENT_TO_SERVER[client_ip]

            server_ip = server["ip"]
            server_mac = server["mac"]
            server_port = SERVER_PORTS[server_ip]

            log.info(f"Redirecting {client_ip} -> {VIRTUAL_IP} traffic to backend {server_ip}.")

            # If the packet has a buffer ID, use it for direct forwarding
            if event.ofp.buffer_id != -1:
                log.info(f"Using buffer to forward {client_ip} -> {server_ip}.")
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                msg.in_port = event.port
                msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
                msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
                msg.actions.append(of.ofp_action_output(port=server_port))
                self.connection.send(msg)
            else:
                log.warning(f"No buffer for {client_ip} -> {server_ip}, sending manually.")
                msg = of.ofp_packet_out()
                msg.data = packet.pack()
                msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
                msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
                msg.actions.append(of.ofp_action_output(port=server_port))
                self.connection.send(msg)

            log.info(f"Manually forwarded first IP packet {client_ip} -> {server_ip}.")

            # Install Flow Rules for future packets
            self._install_flow_rules(event.port, packet.src, client_ip, server_ip, server_mac)

    def _install_flow_rules(self, client_port, client_mac, client_ip, server_ip, server_mac):
        """Installs OpenFlow rules for client-server communication."""
        server_port = SERVER_PORTS[server_ip]

        # Client-to-Server Flow
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        match.dl_type = 0x0800
        match.nw_dst = VIRTUAL_IP
        match.in_port = client_port
        msg.match = match

        msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        msg.actions.append(of.ofp_action_output(port=server_port))
        self.connection.send(msg)
        log.info(f"Installed flow: {client_ip} -> {server_ip} via {VIRTUAL_IP} on port {server_port}.")

        # Server-to-Client Flow
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        match.dl_type = 0x0800  # IPv4
        match.nw_src = server_ip
        match.nw_dst = client_ip
        match.in_port = server_port
        msg.match = match

        msg.actions.append(of.ofp_action_dl_addr.set_src(VIRTUAL_MAC))
        msg.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(client_mac))
        msg.actions.append(of.ofp_action_output(port=client_port))
        self.connection.send(msg)
        log.info(f"Installed return flow: {server_ip} -> {client_ip} via {VIRTUAL_IP}.")

def launch():
    def start_switch(event):
        log.info(f"Switch connected: {event.connection.dpid}")
        VirtualIPLoadBalancer(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)

# from pox.core import core
# import pox.openflow.libopenflow_01 as of
# from pox.lib.addresses import IPAddr, EthAddr
# from pox.lib.packet import ethernet, arp, icmp, ipv4

# log = core.getLogger()

# # Virtual IP and Backend Servers
# VIRTUAL_IP = IPAddr("10.0.0.10")
# VIRTUAL_MAC = EthAddr("00:00:00:00:00:10")  # Virtual MAC for outbound packets
# SERVERS = [
#     {"ip": IPAddr("10.0.0.5"), "mac": EthAddr("00:00:00:00:00:05")},
#     {"ip": IPAddr("10.0.0.6"), "mac": EthAddr("00:00:00:00:00:06")},
# ]
# server_index = 0  # Round-robin counter

# SERVER_PORTS = {
#     IPAddr("10.0.0.5"): 5,  # Port for h5
#     IPAddr("10.0.0.6"): 6   # Port for h6
# }

# CLIENT_TO_SERVER = {}  # Stores mappings of clients to backend servers

# class VirtualIPLoadBalancer:
#     def __init__(self, connection):
#         self.connection = connection
#         connection.addListeners(self)
#         log.info("4:12 Load Balancer initialized.")

#     def _handle_PacketIn(self, event):
#         global server_index
#         packet = event.parsed

#         if not packet:
#             log.warning("Received empty packet. Ignoring.")
#             return

#         if packet.type == ethernet.ARP_TYPE:
#             self._handle_arp(event, packet)
#         elif packet.type == ethernet.IP_TYPE and isinstance(packet.next, icmp):
#             self._handle_icmp(event, packet)

#     def _handle_arp(self, event, packet):
#         """Handles ARP requests for the Virtual IP and backend servers."""
#         global server_index

#         arp_pkt = packet.next
#         src_ip = arp_pkt.protosrc
#         dst_ip = arp_pkt.protodst

#         # Handle ARP Requests for Virtual IP
#         if arp_pkt.opcode == arp.REQUEST and dst_ip == VIRTUAL_IP:
#             log.info(f"Received ARP request for {VIRTUAL_IP}. Assigning backend server.")

#             # Select the next server in round-robin order
#             server = SERVERS[server_index]
#             server_index = (server_index + 1) % len(SERVERS)

#             CLIENT_TO_SERVER[src_ip] = server

#             # Construct ARP reply
#             arp_reply = arp()
#             arp_reply.hwsrc = server["mac"]
#             arp_reply.hwdst = packet.src
#             arp_reply.opcode = arp.REPLY
#             arp_reply.protosrc = VIRTUAL_IP
#             arp_reply.protodst = src_ip

#             # Create Ethernet frame
#             ethernet_reply = ethernet()
#             ethernet_reply.type = ethernet.ARP_TYPE
#             ethernet_reply.src = server["mac"]
#             ethernet_reply.dst = packet.src
#             ethernet_reply.payload = arp_reply

#             # Send ARP response
#             msg = of.ofp_packet_out()
#             msg.data = ethernet_reply.pack()
#             msg.actions.append(of.ofp_action_output(port=event.port))
#             self.connection.send(msg)
#             log.info(f"Sent ARP reply with MAC {server['mac']} for {VIRTUAL_IP}.")

#             self._install_flow_rules(event.port, packet.src, src_ip, server["ip"], server["mac"])

#         # Handle ARP Requests from Backend Servers (Servers Asking for Client MAC)
#         elif arp_pkt.opcode == arp.REQUEST and src_ip in [server["ip"] for server in SERVERS]:
#             log.info(f"Backend server {src_ip} is requesting MAC for {dst_ip}.")

#             if dst_ip in CLIENT_TO_SERVER:
#                 client_mac = CLIENT_TO_SERVER[dst_ip]["mac"]
                
#                 # Construct ARP reply
#                 arp_reply = arp()
#                 arp_reply.hwsrc = client_mac
#                 arp_reply.hwdst = packet.src
#                 arp_reply.opcode = arp.REPLY
#                 arp_reply.protosrc = dst_ip
#                 arp_reply.protodst = src_ip

#                 # Create Ethernet frame
#                 ethernet_reply = ethernet()
#                 ethernet_reply.type = ethernet.ARP_TYPE
#                 ethernet_reply.src = client_mac
#                 ethernet_reply.dst = packet.src
#                 ethernet_reply.payload = arp_reply

#                 # Send ARP response
#                 msg = of.ofp_packet_out()
#                 msg.data = ethernet_reply.pack()
#                 msg.actions.append(of.ofp_action_output(port=event.port))
#                 self.connection.send(msg)
#                 log.info(f"Sent ARP reply to server {src_ip} with MAC {client_mac} for {dst_ip}.")
#             else:
#                 log.warning(f"No known client MAC for {dst_ip}. Dropping ARP request.")

#     def _handle_icmp(self, event, packet):
#         """Handles ICMP echo requests by forwarding the first one manually and installing flow rules."""
#         ip_packet = packet.next
#         client_ip = ip_packet.srcip

#         if client_ip not in CLIENT_TO_SERVER:
#             log.warning(f"No backend server mapped for {client_ip}. Dropping ICMP packet.")
#             return

#         server = CLIENT_TO_SERVER[client_ip]
#         server_ip = server["ip"]
#         server_mac = server["mac"]
#         server_port = SERVER_PORTS[server_ip]

#         # Manually forward the first ICMP packet **using event.buffer_id**  
#         if event.ofp.buffer_id != -1:
#             log.info(f"Forwarding buffered first ICMP request {client_ip} -> {server_ip}.")
#             msg = of.ofp_packet_out()
#             msg.buffer_id = event.ofp.buffer_id
#             msg.in_port = event.port
#             msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
#             msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
#             msg.actions.append(of.ofp_action_output(port=server_port))
#             self.connection.send(msg)
#         else:
#             log.warning(f"No buffer ID for {client_ip} -> {server_ip}, sending manually.")
#             msg = of.ofp_packet_out()
#             msg.data = packet.pack()
#             msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
#             msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
#             msg.actions.append(of.ofp_action_output(port=server_port))
#             self.connection.send(msg)

#         log.info(f"Manually forwarded first ICMP request {client_ip} -> {server_ip}.")

#         # **Now install flow rules for future packets**
#         self._install_flow_rules(event.port, packet.src, client_ip, server_ip, server_mac)


#     def _install_flow_rules(self, client_port, client_mac, client_ip, server_ip, server_mac):
#         """Installs OpenFlow rules for client-server communication."""
#         server_port = SERVER_PORTS[server_ip]

#         # Client-to-Server Flow
#         msg = of.ofp_flow_mod()
#         match = of.ofp_match()
#         match.dl_type = 0x0800
#         match.nw_dst = VIRTUAL_IP
#         match.in_port = client_port
#         msg.match = match

#         msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
#         msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
#         msg.actions.append(of.ofp_action_output(port=server_port))
#         self.connection.send(msg)
#         log.info(f"Installed flow: {client_ip} -> {server_ip} via {VIRTUAL_IP} on port {server_port}.")

#         # Server-to-Client Flow
#         msg = of.ofp_flow_mod()
#         match = of.ofp_match()
#         match.dl_type = 0x0800  # IPv4
#         match.nw_src = server_ip
#         match.nw_dst = client_ip
#         match.in_port = server_port
#         msg.match = match

#         msg.actions.append(of.ofp_action_dl_addr.set_src(VIRTUAL_MAC))
#         msg.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
#         msg.actions.append(of.ofp_action_dl_addr.set_dst(client_mac))
#         msg.actions.append(of.ofp_action_output(port=client_port))
#         self.connection.send(msg)
#         log.info(f"Installed flow: {server_ip} -> {client_ip} via {VIRTUAL_IP} on port {client_port}.")

# def launch():
#     def start_switch(event):
#         log.info(f"Switch connected: {event.connection.dpid}")
#         VirtualIPLoadBalancer(event.connection)

#     core.openflow.addListenerByName("ConnectionUp", start_switch)