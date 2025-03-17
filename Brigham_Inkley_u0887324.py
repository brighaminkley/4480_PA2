# PA2 - SDN Load Balancer
# By Brigham Inkley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet, arp

log = core.getLogger()

# Virtual IP and backend servers
VIRTUAL_IP = IPAddr("10.0.0.10")
VIRTUAL_MAC = EthAddr("00:00:00:00:00:10")  # Define virtual MAC as a constant
SERVERS = [
    {"ip": IPAddr("10.0.0.5"), "mac": EthAddr("00:00:00:00:00:05")},
    {"ip": IPAddr("10.0.0.6"), "mac": EthAddr("00:00:00:00:00:06")},
]
server_index = 0  # Round-robin counter

SERVER_PORTS = {
    IPAddr("10.0.0.5"): 5,  # Port for h5
    IPAddr("10.0.0.6"): 6   # Port for h6
}

class VirtualIPLoadBalancer:
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("11:01 Load Balancer initialized.")

    def _handle_PacketIn(self, event):
        global server_index
        packet = event.parsed

        if not packet:
            log.warning("Received empty packet. Ignoring.")
            return

        if packet.type != ethernet.ARP_TYPE:
            log.warning(f"Received non-ARP packet of type {packet.type}. Ignoring.")
            return

        # Handle ARP Requests for Virtual IP
        if packet.payload.opcode == arp.REQUEST:
            if packet.payload.protodst == VIRTUAL_IP:
                log.info(f"Received ARP request for {VIRTUAL_IP}. Assigning a backend server.")

                # Select the next server
                server = SERVERS[server_index]
                server_index = (server_index + 1) % len(SERVERS)

                # Construct ARP reply
                arp_reply = arp()
                arp_reply.hwsrc = server["mac"]
                arp_reply.hwdst = packet.src
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = VIRTUAL_IP
                arp_reply.protodst = packet.payload.protosrc

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

                # Install flow rules to forward traffic
                self._install_flow_rules(event.port, packet.src, packet.payload.protosrc, server["ip"], server["mac"])

            # Handle ARP Requests from Backend Servers (Servers Asking for Client MAC)
            elif packet.payload.protosrc in [server["ip"] for server in SERVERS]:  # If a backend server sent it
                server_ip = packet.payload.protosrc
                client_ip = packet.payload.protodst
                log.info(f"Backend server {server_ip} is requesting MAC for {client_ip}.")

                # Construct ARP reply
                arp_reply = arp()
                arp_reply.hwsrc = packet.src  # Use the client's MAC from the ARP request
                arp_reply.hwdst = packet.src  # Destination MAC is the server's MAC
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = client_ip
                arp_reply.protodst = server_ip

                # Create Ethernet frame
                ethernet_reply = ethernet()
                ethernet_reply.type = ethernet.ARP_TYPE
                ethernet_reply.src = packet.src  # Use the client's MAC
                ethernet_reply.dst = packet.src  # Destination MAC is the server's MAC
                ethernet_reply.payload = arp_reply

                # Send ARP response
                msg = of.ofp_packet_out()
                msg.data = ethernet_reply.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                self.connection.send(msg)
                log.info(f"Sent ARP reply to server {server_ip} with MAC for {client_ip}.")

            # Handle ARP Requests between h1 and h5
            elif packet.payload.protodst in [server["ip"] for server in SERVERS]:  # If a client is asking for a server's MAC
                server_ip = packet.payload.protodst
                client_ip = packet.payload.protosrc
                log.info(f"Client {client_ip} is requesting MAC for server {server_ip}.")

                # Find the server's MAC address
                server = next(server for server in SERVERS if server["ip"] == server_ip)

                # Construct ARP reply
                arp_reply = arp()
                arp_reply.hwsrc = server["mac"]
                arp_reply.hwdst = packet.src
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = server_ip
                arp_reply.protodst = client_ip

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
                log.info(f"Sent ARP reply with MAC {server['mac']} for {server_ip}.")

    def _install_flow_rules(self, client_port, client_mac, client_ip, server_ip, server_mac):
        """
        Installs OpenFlow rules for load balancing:
        1. Client-to-Server flow
        2. Server-to-Client flow
        """
        server_port = SERVER_PORTS[server_ip]

        # Client-to-Server Flow
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        match.dl_type = 0x0800  # IPv4
        match.nw_proto = 1       # ICMP
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
        match.nw_proto = 1       # ICMP
        match.nw_src = server_ip
        match.nw_dst = client_ip
        match.in_port = server_port

        msg.match = match  # Assign the match object to the msg
        msg.actions.append(of.ofp_action_dl_addr.set_src(VIRTUAL_MAC))
        msg.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(client_mac))
        msg.actions.append(of.ofp_action_output(port=client_port))
        self.connection.send(msg)
        log.info(f"Installed reverse flow: {server_ip} -> {client_ip} via {VIRTUAL_IP} on port {client_port}.")

def launch():
    def start_switch(event):
        log.info(f"Switch connected: {event.connection.dpid}")
        VirtualIPLoadBalancer(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)


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