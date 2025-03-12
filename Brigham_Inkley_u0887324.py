# PA2 - SDN Load Balancer
# By Brigham Inkley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet, arp

log = core.getLogger()

# Virtual IP and backend servers
VIRTUAL_IP = IPAddr("10.0.0.10")
SERVERS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]
MACS = {
    IPAddr("10.0.0.5"): EthAddr("00:00:00:00:00:05"),
    IPAddr("10.0.0.6"): EthAddr("00:00:00:00:00:06")
}
SERVER_PORTS = {
    IPAddr("10.0.0.5"): 5,  # Port for h5
    IPAddr("10.0.0.6"): 6   # Port for h6
}
server_index = 0  # Tracks which server to assign next


class LoadBalancer(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("6:23 Load balancer initialized.")

    def _handle_PacketIn(self, event):
        packet = event.parsed

        ETH_TYPE_IPV6 = 0x86DD

        if packet.type == ETH_TYPE_IPV6:  # Ignore IPv6 packets
            return

        if not packet:
            log.warning("Ignoring empty packet.")
            return

        # Log packet details for debugging
        log.info(f"PacketIn received: {packet}")
        log.info(f"Packet type: {packet.type}")

        # Handle ARP requests (clients asking for VIP or servers asking for client MAC)
        if packet.type == ethernet.ARP_TYPE and packet.payload.opcode == arp.REQUEST:
            log.info("Intercepted ARP request")

            client_ip = packet.payload.protosrc
            client_mac = packet.src
            client_port = event.port

            # Client requesting the virtual IP (10.0.0.10)
            if packet.payload.protodst == VIRTUAL_IP:
                global server_index
                server_ip = SERVERS[server_index]
                server_mac = MACS[server_ip]
                server_port = SERVER_PORTS[server_ip]
                server_index = (server_index + 1) % len(SERVERS)

                log.info(f"Assigning server {server_ip} to client {client_ip} on port {client_port}")

                # Send ARP reply (server MAC -> client MAC)
                arp_reply = arp()
                arp_reply.hwsrc = server_mac
                arp_reply.hwdst = client_mac
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = VIRTUAL_IP
                arp_reply.protodst = client_ip

                ethernet_reply = ethernet()
                ethernet_reply.type = ethernet.ARP_TYPE
                ethernet_reply.dst = client_mac
                ethernet_reply.src = server_mac
                ethernet_reply.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = ethernet_reply.pack()
                msg.actions.append(of.ofp_action_output(port=client_port))
                self.connection.send(msg)
                log.info(f"Sent ARP reply with MAC {server_mac} for virtual IP {VIRTUAL_IP}")

                # Install client-to-server and server-to-client flows
                self.install_flow_rules(client_port, client_mac, client_ip, server_ip, server_mac, server_port)

            # Server requesting a client's MAC address (to reply to pings)
            elif packet.payload.protosrc in SERVERS:
                server_ip = packet.payload.protosrc
                client_ip = packet.payload.protodst

                log.info(f"Server {server_ip} is requesting MAC for client {client_ip}")

                # Send ARP reply (client MAC -> server MAC)
                arp_reply = arp()
                arp_reply.hwsrc = client_mac
                arp_reply.hwdst = packet.src
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = client_ip
                arp_reply.protodst = server_ip

                ethernet_reply = ethernet()
                ethernet_reply.type = ethernet.ARP_TYPE
                ethernet_reply.dst = packet.src
                ethernet_reply.src = client_mac
                ethernet_reply.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = ethernet_reply.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                self.connection.send(msg)
                log.info(f"Replied to server {server_ip}'s ARP request for client {client_ip}")

        # Handle IP packets (ICMP pings)
        elif packet.type == ethernet.IP_TYPE:
            src_ip = packet.payload.srcip
            dst_ip = packet.payload.dstip

            log.info(f"Handling IP packet from {src_ip} to {dst_ip}")

            # Allow ICMP packets (pings) through while installing flows
            if packet.payload.protocol == packet.payload.ICMP_PROTOCOL:
                log.info("Processing ICMP ping request")

                if packet.payload.protocol == packet.payload.ICMP_PROTOCOL:
                    log.info("Processing ICMP ping request")

                    # Allow the current ping to pass through (first packet)
                    msg = of.ofp_packet_out()
                    msg.data = event.ofp
                    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                    self.connection.send(msg)
                    log.info("Flooded ICMP packet to let the ping through")

                    # Install flow to handle future ICMP traffic
                    match = of.ofp_match()
                    match.dl_type = 0x0800  # IP
                    match.nw_proto = 1       # ICMP protocol
                    match.nw_src = packet.payload.srcip
                    match.nw_dst = packet.payload.dstip

                    if packet.payload.protocol == packet.payload.ICMP_PROTOCOL:
                        log.info("Processing ICMP ping request")

                        # Forward ICMP request to the selected server
                        actions = [
                            of.ofp_action_dl_addr.set_dst(server_mac),  # Send to server MAC
                            of.ofp_action_nw_addr.set_dst(server_ip),   # Send to server IP
                            of.ofp_action_output(port=server_port)      # Forward to correct port
                        ]

                        msg = of.ofp_flow_mod()
                        match = of.ofp_match()
                        match.dl_type = 0x0800  # IP
                        match.nw_proto = 1      # ICMP protocol
                        match.nw_src = packet.payload.srcip
                        match.nw_dst = VIRTUAL_IP  # The VIP
                        msg.match = match
                        msg.actions = actions
                        self.connection.send(msg)

                        log.info(f"✅ Installed ICMP forwarding rule: {packet.payload.srcip} -> {server_ip}")

                    flow_mod = of.ofp_flow_mod()
                    flow_mod.match = match
                    flow_mod.actions = actions
                    self.connection.send(flow_mod)
                    log.info(f"Installed ICMP flow: {packet.payload.srcip} -> {packet.payload.dstip}")

            else:
                log.warning("Dropping unmatched non-ICMP IP packet")

        else:
            log.warning(f"Unhandled packet type: {packet.type}")

    def install_flow_rules(self, client_port, client_mac, client_ip, server_ip, server_mac, server_port):
        """
        Install flow rules for client-to-server and server-to-client communication.
        """

        # Client-to-server flow
        match = of.ofp_match()
        match.in_port = client_port
        match.dl_type = 0x0800  # IP
        match.nw_dst = VIRTUAL_IP  # 🔴 This is the problem

        actions = [
            of.ofp_action_dl_addr.set_dst(server_mac),  
            of.ofp_action_nw_addr.set_dst(server_ip),   
            of.ofp_action_output(port=server_port) 
        ]

        msg = of.ofp_flow_mod()
        msg.match = match
        msg.actions = actions
        self.connection.send(msg)
        log.info(f"Fixed client-to-server flow: {client_ip} -> {server_ip}.")

        # Server-to-client flow
        match = of.ofp_match()
        match.in_port = server_port
        match.dl_type = 0x0800  
        match.nw_src = server_ip 
        match.nw_dst = client_ip

        actions = [
            of.ofp_action_dl_addr.set_src(server_mac),
            of.ofp_action_nw_addr.set_src(VIRTUAL_IP),  
            of.ofp_action_dl_addr.set_dst(client_mac), 
            of.ofp_action_output(port=client_port)
        ]

        msg = of.ofp_flow_mod()
        msg.match = match
        msg.actions = actions
        self.connection.send(msg)
        log.info(f"Installed server-to-client ICMP flow: {server_ip} -> {client_ip} via {VIRTUAL_IP}")


def launch():
    def start_switch(event):
        log.info(f"Switch connected: {event.connection.dpid}")
        LoadBalancer(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)