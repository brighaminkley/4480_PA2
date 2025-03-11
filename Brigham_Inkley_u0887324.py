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
        log.info("5:25 Load balancer initialized.")

    def _handle_PacketIn(self, event):
        packet = event.parsed

        # Handle ARP Requests
        if packet.type == ethernet.ARP_TYPE and packet.payload.opcode == arp.REQUEST:
            log.info("Intercepted ARP request for virtual IP.")

            if packet.payload.protodst == VIRTUAL_IP:
                global server_index
                server_ip = SERVERS[server_index]
                server_mac = MACS[server_ip]
                server_port = SERVER_PORTS[server_ip]
                server_index = (server_index + 1) % len(SERVERS)

                log.info(f"Assigning {server_ip} to client {packet.payload.protosrc}")

                # Send ARP reply
                arp_reply = arp()
                arp_reply.hwsrc = server_mac
                arp_reply.hwdst = packet.src
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = VIRTUAL_IP
                arp_reply.protodst = packet.payload.protosrc

                ethernet_reply = ethernet()
                ethernet_reply.type = ethernet.ARP_TYPE
                ethernet_reply.dst = packet.src
                ethernet_reply.src = server_mac
                ethernet_reply.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = ethernet_reply.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                self.connection.send(msg)
                log.info(f"Sent ARP reply with MAC {server_mac} for virtual IP {VIRTUAL_IP}")

                # Install client-to-server flow
                self.install_flow_rules(event.port, packet.src, server_ip, server_mac, server_port)

    def install_flow_rules(self, client_port, client_mac, server_ip, server_mac, server_port):
        """
        Install flow rules to handle traffic between clients and servers.
        """

        # Client-to-server flow
        match = of.ofp_match()
        match.in_port = client_port
        match.dl_type = 0x0800  # IP
        match.nw_dst = VIRTUAL_IP

        actions = []
        actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        actions.append(of.ofp_action_output(port=server_port))

        msg = of.ofp_flow_mod()
        msg.match = match
        msg.actions = actions
        self.connection.send(msg)
        log.info(f"Installed client-to-server flow: client port {client_port} -> server {server_ip}.")

        # Server-to-client flow
        match = of.ofp_match()
        match.in_port = server_port
        match.dl_type = 0x0800  # IP
        match.nw_src = server_ip
        match.nw_dst = client_mac  # Fix: Use actual client IP here

        actions = []
        actions.append(of.ofp_action_dl_addr.set_src(server_mac))
        actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
        actions.append(of.ofp_action_dl_addr.set_dst(client_mac))
        actions.append(of.ofp_action_output(port=client_port))

        msg = of.ofp_flow_mod()
        msg.match = match
        msg.actions = actions
        self.connection.send(msg)
        log.info(f"Installed server-to-client flow: server {server_ip} -> client {client_mac}.")

def launch():
    def start_switch(event):
        log.info(f"Switch connected: {event.connection.dpid}")
        LoadBalancer(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)