# PA2 - SDN Load Balancer
# By Brigham Inkley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.arp import arp, ethernet

VIRTUAL_IP = "10.0.0.10"
SERVER1_IP = "10.0.0.5"
SERVER2_IP = "10.0.0.6"
SERVER1_MAC = "00:00:00:00:00:05"
SERVER2_MAC = "00:00:00:00:00:06"

use_server1 = True  # Start with server 1


def launch():
    def _handle_ConnectionUp(event):
        global use_server1

        for m in event.connection.features.ports:
            if m.port_no < of.OFPP_MAX:
                print(m.port_no, m.name)

        # Initial flow rules (if any) can be added here


    def _handle_PacketIn(event):
        packet = event.parsed
        if packet.type == ethernet.ARP_TYPE:
            handle_arp(packet, event.port, event.connection)
        elif packet.type == 0x0800: # Only handle IPv4 packets
            core.getLogger().info(
                f"Received IPv4 packet: type={packet.type}, src={packet.src}, dst={packet.dst}, in_port={event.port}")
            # Handle IPv4 traffic here if needed in the future
        else:
            core.getLogger().info(f"Ignoring packet type: {packet.type}")
            return


    def handle_arp(packet, port, event_connection):
        global use_server1
        a = packet.payload
        if a.opcode == arp.REQUEST:  # Check if it's an ARP request
            if a.protodst == IPAddr(VIRTUAL_IP):  # ARP request for virtual IP
                target_mac = SERVER1_MAC if use_server1 else SERVER2_MAC
                target_ip = SERVER1_IP if use_server1 else SERVER2_IP

                r = arp()
                r.hwtype = a.hwtype
                r.prototype = a.prototype
                r.hwlen = a.hwlen
                r.protolen = a.protolen
                r.opcode = arp.REPLY  # It's a reply
                r.hwdst = packet.src
                r.hwsrc = EthAddr(target_mac)
                r.protodst = a.protosrc  # Corrected protodst
                r.protosrc = IPAddr(VIRTUAL_IP)

                # Log ARP reply details
                core.getLogger().info(
                    f"Sending ARP reply: hwdst={r.hwdst}, hwsrc={r.hwsrc}, protodst={r.protodst}, protosrc={r.protosrc}")

                # Send ARP reply
                e = ethernet(type=ethernet.ARP_TYPE, src=EthAddr(target_mac), dst=packet.src, payload=r)
                event_connection.send(e.pack())

                # Install flow rules
                install_flow_rules(event_connection, port, target_ip)

                # Toggle server selection
                use_server1 = not use_server1
        # You might want to add an 'elif' or 'else' here to handle other ARP packets, if needed


    def install_flow_rules(event_connection, port, target_ip):
        target_mac = SERVER1_MAC if target_ip == SERVER1_IP else SERVER2_MAC
        core.getLogger().info(
            f"Installing simplified flow rules for target_ip={target_ip}, target_mac={target_mac}, port={port}")
        # Flow for client to server (e.g., h1 to h5)
        if port == 1:  # Assuming h1 is on port 1
            match_client_to_server = of.ofp_match()
            match_client_to_server.in_port = 1
            match_client_to_server.dl_dst = EthAddr("00:00:00:00:00:05")  # h5's MAC
            action_client_to_server = of.ofp_action_output(port=5)  # h5's port
            flow_mod_client_to_server = of.ofp_flow_mod()
            flow_mod_client_to_server.match = match_client_to_server
            flow_mod_client_to_server.actions.append(action_client_to_server)
            event_connection.send(flow_mod_client_to_server)
            core.getLogger().info("Installed simplified rule: h1 to h5")
        # Flow for server to client (e.g., h5 to h1)
        elif port == 5:  # Assuming h5 is on port 5
            match_server_to_client = of.ofp_match()
            match_server_to_client.in_port = 5
            match_server_to_client.dl_dst = EthAddr("00:00:00:00:00:01")  # h1's MAC
            action_server_to_client = of.ofp_action_output(port=1)  # h1's port
            flow_mod_server_to_client = of.ofp_flow_mod()
            flow_mod_server_to_client.match = match_server_to_client
            flow_mod_server_to_client.actions.append(action_server_to_client)
            event_connection.send(flow_mod_server_to_client)
            core.getLogger().info("Installed simplified rule: h5 to h1")
        # Add similar blocks for other ports as needed


    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)


launch()

# from pox.core import core
# import pox.openflow.libopenflow_01 as of
# from pox.lib.addresses import IPAddr, EthAddr
# from pox.lib.packet import ethernet, arp

# log = core.getLogger()

# # Virtual IP and backend servers
# VIRTUAL_IP = IPAddr("10.0.0.10")
# SERVERS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]
# MACS = {
#     IPAddr("10.0.0.5"): EthAddr("00:00:00:00:00:05"),
#     IPAddr("10.0.0.6"): EthAddr("00:00:00:00:00:06")
# }
# SERVER_PORTS = {
#     IPAddr("10.0.0.5"): 5,  # Port for h5
#     IPAddr("10.0.0.6"): 6   # Port for h6
# }
# server_index = 0  # Tracks which server to assign next


# class LoadBalancer(object):
#     def __init__(self, connection):
#         self.connection = connection
#         connection.addListeners(self)
#         log.info("11:20 Load balancer initialized.")

#         msg = of.ofp_flow_mod()
#         msg.match = of.ofp_match(dl_type=0x0806)  # ARP
#         msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))  # Flood ARP packets
#         self.connection.send(msg)

#         log.info("Installed ARP flow rule: Flood ARP requests.")

#     def _handle_PacketIn(self, event):
#         log.info("PacketIn: Packet received")
#         pass
#         # global server_index
#         # packet = event.parsed
#         # ETH_TYPE_IPV6 = 0x86DD

#         # if packet.type == ETH_TYPE_IPV6:  # Ignore IPv6 packets
#         #     return

#         # if not packet:
#         #     log.warning("Ignoring empty packet.")
#         #     return

#         # log.info(f"PacketIn received: {packet}")
#         # log.info(f"Packet type: {packet.type}")

#         # # Handle ARP requests (client -> load balancer for virtual IP)
#         # if packet.type == ethernet.ARP_TYPE and packet.payload.opcode == arp.REQUEST:
#         #     log.info("Intercepted ARP request")

#         #     client_ip = packet.payload.protosrc
#         #     client_mac = packet.src
#         #     client_port = event.port

#         #     if packet.payload.protodst == VIRTUAL_IP:
#         #         server_ip = SERVERS[server_index]
#         #         server_mac = MACS[server_ip]
#         #         server_port = SERVER_PORTS[server_ip]
#         #         server_index = (server_index + 1) % len(SERVERS)

#         #         log.info(f"Assigning server {server_ip} to client {client_ip} on port {client_port}")

#         #         VIRTUAL_MAC = EthAddr("00:00:00:00:00:10")

#         #         # Send ARP reply (pretend virtual IP has virtual MAC)
#         #         arp_reply = arp()
#         #         arp_reply.hwsrc = VIRTUAL_MAC
#         #         arp_reply.hwdst = client_mac
#         #         arp_reply.opcode = arp.REPLY
#         #         arp_reply.protosrc = VIRTUAL_IP
#         #         arp_reply.protodst = client_ip

#         #         ethernet_reply = ethernet()
#         #         ethernet_reply.type = ethernet.ARP_TYPE
#         #         ethernet_reply.dst = client_mac
#         #         ethernet_reply.src = VIRTUAL_MAC
#         #         ethernet_reply.payload = arp_reply

#         #         msg = of.ofp_packet_out()
#         #         msg.data = ethernet_reply.pack()
#         #         msg.actions.append(of.ofp_action_output(port=client_port))
#         #         self.connection.send(msg)

#         #         log.info(f"Sent ARP reply with MAC {VIRTUAL_MAC} for virtual IP {VIRTUAL_IP}")

#         #         # Install flows for both directions (client -> server and server -> client)
#         #         self.install_flow_rules(client_port, client_mac, client_ip, server_ip, server_mac, server_port)

#         # # Handle ICMP (ping) packets
#         # elif packet.type == ethernet.IP_TYPE and packet.payload.protocol == packet.payload.ICMP_PROTOCOL:
#         #     log.info("Processing ICMP ping request")

#         #     client_ip = packet.payload.srcip
#         #     client_port = event.port

#         #     server_ip = SERVERS[server_index]
#         #     server_mac = MACS[server_ip]
#         #     server_port = SERVER_PORTS[server_ip]
#         #     server_index = (server_index + 1) % len(SERVERS)

#         #     log.info(f"Forwarding ICMP request to {server_ip} ({server_mac}) on port {server_port}")

#         #     # Forward ICMP request to the selected server
#         #     actions = [
#         #         of.ofp_action_dl_addr.set_dst(server_mac),
#         #         of.ofp_action_nw_addr.set_dst(server_ip),
#         #         of.ofp_action_output(port=server_port)
#         #     ]

#         #     match = of.ofp_match()
#         #     match.dl_type = 0x0800  # IP
#         #     match.nw_proto = 1      # ICMP protocol
#         #     match.nw_src = client_ip
#         #     match.nw_dst = VIRTUAL_IP

#         #     msg = of.ofp_flow_mod()
#         #     msg.match = match
#         #     msg.actions = actions
#         #     self.connection.send(msg)

#         #     log.info(f"Installed ICMP forward flow: {client_ip} -> {server_ip}")

#         #     # Reverse flow for ICMP reply (server -> client)
#         #     actions = [
#         #         of.ofp_action_dl_addr.set_src(server_mac),
#         #         of.ofp_action_nw_addr.set_src(VIRTUAL_IP),
#         #         of.ofp_action_dl_addr.set_dst(packet.src),
#         #         of.ofp_action_output(port=client_port)
#         #     ]

#         #     match = of.ofp_match()
#         #     match.dl_type = 0x0800
#         #     match.nw_proto = 1
#         #     match.nw_src = server_ip
#         #     match.nw_dst = client_ip

#         #     msg = of.ofp_flow_mod()
#         #     msg.match = match
#         #     msg.actions = actions
#         #     self.connection.send(msg)

#         #     log.info(f"Installed reverse ICMP flow: {server_ip} -> {client_ip}")

#         # else:
#         #     log.warning(f"Unhandled packet type: {packet.type}")


#     def install_flow_rules(self, client_port, client_mac, client_ip, server_ip, server_mac, server_port):
#         """
#         Install flow rules for client-to-server and server-to-client communication.
#         """

#         # Client-to-server flow
#         match = of.ofp_match()
#         match.in_port = client_port
#         match.dl_type = 0x0800  # IP
#         match.nw_dst = VIRTUAL_IP

#         actions = [
#             of.ofp_action_dl_addr.set_dst(server_mac),
#             of.ofp_action_nw_addr.set_dst(server_ip),
#             of.ofp_action_output(port=server_port)
#         ]

#         msg = of.ofp_flow_mod()
#         msg.match = match
#         msg.actions = actions
#         self.connection.send(msg)
#         log.info(f"Fixed client-to-server flow: {client_ip} -> {server_ip}.")

#         # Server-to-client flow
#         match = of.ofp_match()
#         match.in_port = server_port
#         match.dl_type = 0x0800  # IP
#         match.nw_src = server_ip
#         match.nw_dst = client_ip

#         actions = [
#             of.ofp_action_dl_addr.set_src(server_mac),  # Server's MAC as source
#             of.ofp_action_nw_addr.set_src(VIRTUAL_IP),  # Rewrite source IP to virtual IP
#             of.ofp_action_dl_addr.set_dst(client_mac),  # Client's MAC as destination
#             of.ofp_action_output(port=client_port)      # Send packet to client
#         ]

#         msg = of.ofp_flow_mod()
#         msg.match = match
#         msg.actions = actions
#         self.connection.send(msg)

#         log.info(f"Installed server-to-client flow: {server_ip} -> {client_ip} via {VIRTUAL_IP}")



# def launch():
#     def start_switch(event):
#         log.info(f"Switch connected: {event.connection.dpid}")
#         LoadBalancer(event.connection)

#     core.openflow.addListenerByName("ConnectionUp", start_switch)