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
server_index = 0  # Round-robin tracking for servers
installed_flows = set()  # Track installed flows

class LoadBalancer(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("Load balancer initialized.")

        # Install base rules
        self.install_arp_rule()
        self.install_icmp_flood_rule()
        # self.add_default_drop_rule()

        # Dump flows to check if rules are installed
        log.info("Dumping flow table after initialization:")
        self.dump_flows()

    def dump_flows(self):
        log.info("Requesting flow table...")
        msg = of.ofp_stats_request()
        msg.type = of.OFPST_FLOW
        self.connection.send(msg)
    
    def _handle_FlowStatsReceived(self, event):
        for flow in event.stats:
            log.info(f"Flow: {flow.match} -> actions: {flow.actions}")

    def add_default_drop_rule(self):
        # Low-priority rule to drop unmatched traffic
        msg = of.ofp_flow_mod()
        msg.priority = 0
        self.connection.send(msg)
        log.info("Installed default drop rule.")

    def install_arp_rule(self):
        # High-priority rule to allow ARP requests/replies
        msg = of.ofp_flow_mod()
        msg.priority = 100
        match = of.ofp_match()
        match.dl_type = 0x0806  # ARP
        msg.match = match
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)
        log.info("Installed ARP rule to allow ARP traffic.")

    def install_icmp_flood_rule(self):
        # Rule to flood ICMP traffic (ping) initially
        msg = of.ofp_flow_mod()
        msg.priority = 50
        match = of.ofp_match()
        match.dl_type = 0x0800  # IP
        match.nw_proto = 1  # ICMP
        msg.match = match
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)
        log.info("Installed ICMP flood rule to handle initial ping traffic.")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        log.info(f"PacketIn received: {packet}")

        if not packet:
            log.warning("Received empty packet.")
            return

        if packet.type == ethernet.ARP_TYPE and packet.payload.opcode == arp.REQUEST:
            log.info("Handling ARP request.")
            self.handle_arp_request(packet, event)
        elif packet.type == ethernet.IP_TYPE and packet.payload.protocol == 1:  # ICMP
            log.info(f"Handling ICMP packet from {packet.payload.srcip} to {packet.payload.dstip}")
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            self.connection.send(msg)
        else:
            log.warning(f"Unhandled packet type: {packet.type}")

    def handle_arp_request(self, packet, event):
        global server_index

        arp_payload = packet.payload

        if arp_payload.protodst == VIRTUAL_IP:  # Client requests virtual IP
            server_ip = SERVERS[server_index]
            server_mac = MACS[server_ip]
            server_port = SERVER_PORTS[server_ip]
            server_index = (server_index + 1) % len(SERVERS)

            # Send ARP reply
            arp_reply = arp()
            arp_reply.hwsrc = server_mac
            arp_reply.hwdst = packet.src
            arp_reply.opcode = arp.REPLY
            arp_reply.protosrc = VIRTUAL_IP
            arp_reply.protodst = arp_payload.protosrc

            ethernet_reply = ethernet()
            ethernet_reply.type = ethernet.ARP_TYPE
            ethernet_reply.dst = packet.src
            ethernet_reply.src = server_mac
            ethernet_reply.payload = arp_reply

            msg = of.ofp_packet_out()
            msg.data = ethernet_reply.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))
            self.connection.send(msg)
            log.info(f"Sent ARP reply with MAC {server_mac} for virtual IP {VIRTUAL_IP}.")

            # Install flow rules
            self.install_flow_rules(event.port, packet.src, server_ip, server_mac, server_port, IPAddr(arp_payload.protosrc))

            # Forward pending packets after flow installation
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=server_port))
            self.connection.send(msg)
            log.info(f"Forwarded pending packet from client {arp_payload.protosrc} to server {server_ip}")

        elif arp_payload.protosrc in SERVERS:  # Server requests client MAC
            client_ip = arp_payload.protodst
            client_mac = packet.src
            client_port = event.port

            arp_reply = arp()
            arp_reply.hwsrc = client_mac
            arp_reply.hwdst = packet.src
            arp_reply.opcode = arp.REPLY
            arp_reply.protosrc = client_ip
            arp_reply.protodst = arp_payload.protosrc

            ethernet_reply = ethernet()
            ethernet_reply.type = ethernet.ARP_TYPE
            ethernet_reply.dst = packet.src
            ethernet_reply.src = client_mac
            ethernet_reply.payload = arp_reply

            msg = of.ofp_packet_out()
            msg.data = ethernet_reply.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))
            self.connection.send(msg)
            log.info(f"Replied to server {arp_payload.protosrc}'s ARP request for client IP {client_ip}")

            # Forward pending packets from the server to client
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=client_port))
            self.connection.send(msg)
            log.info(f"Forwarded pending packet from server {arp_payload.protosrc} to client {client_ip}")

    def install_flow_rules(self, client_port, client_mac, server_ip, server_mac, server_port, client_ip):
        global installed_flows

        if (client_port, server_ip) in installed_flows:
            log.info(f"Flow from client port {client_port} to server {server_ip} already installed. Skipping.")
            return

        # Client to server flow
        match = of.ofp_match()
        match.in_port = client_port
        match.dl_type = 0x0800
        match.nw_dst = VIRTUAL_IP

        msg = of.ofp_flow_mod()
        msg.match = match
        msg.idle_timeout = 30
        msg.hard_timeout = 60
        msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        msg.actions.append(of.ofp_action_output(port=server_port))
        self.connection.send(msg)
        log.info(f"Installed client-to-server flow: client port {client_port} -> server {server_ip}.")

        # Server to client flow
        match = of.ofp_match()
        match.in_port = server_port
        match.dl_type = 0x0800
        match.nw_src = server_ip
        match.nw_dst = client_ip

        msg = of.ofp_flow_mod()
        msg.match = match
        msg.idle_timeout = 30
        msg.hard_timeout = 60
        msg.actions.append(of.ofp_action_dl_addr.set_src(server_mac))
        msg.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(client_mac))
        msg.actions.append(of.ofp_action_output(port=client_port))
        self.connection.send(msg)
        log.info(f"Installed server-to-client flow: server {server_ip} -> client IP {client_ip}.")

        installed_flows.add((client_port, server_ip))

def launch():
    def start_switch(event):
        log.info(f"Switch connected: {event.connection.dpid}")
        LoadBalancer(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)