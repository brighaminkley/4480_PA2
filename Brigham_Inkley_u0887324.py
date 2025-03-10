#This is PA2, SDN
#By Brigham Inkley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
import random

log = core.getLogger()

# Virtual IP and backend servers
VIRTUAL_IP = IPAddr("10.0.0.10")
SERVERS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]
MACS = {IPAddr("10.0.0.5"): EthAddr("00:00:00:00:00:05"),
        IPAddr("10.0.0.6"): EthAddr("00:00:00:00:00:06")}
server_index = 0  # Tracks which server to assign next

class LoadBalancer (object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        global server_index
        packet = event.parsed

        if packet.type == packet.ARP_TYPE and packet.payload.protodst == VIRTUAL_IP:
            log.info("Intercepted ARP request for virtual IP")
            server_ip = SERVERS[server_index]
            server_mac = MACS[server_ip]

            # Send an ARP reply with the assigned server's MAC
            arp_reply = packet.ARP()
            arp_reply.hwsrc = server_mac
            arp_reply.hwdst = packet.src
            arp_reply.opcode = packet.ARP_REPLY
            arp_reply.protosrc = VIRTUAL_IP
            arp_reply.protodst = packet.payload.protosrc

            ethernet = packet.ETHERNET()
            ethernet.src = server_mac
            ethernet.dst = packet.src
            ethernet.payload = arp_reply

            msg = of.ofp_packet_out()
            msg.data = ethernet.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))
            self.connection.send(msg)

            # Round-robin selection
            server_index = (server_index + 1) % len(SERVERS)

            # Install flow rules to forward ICMP traffic
            self.install_flow(event.port, server_ip, server_mac)

    def install_flow(self, client_port, server_ip, server_mac):
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800  # IP packets
        msg.match.nw_dst = VIRTUAL_IP
        msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        msg.actions.append(of.ofp_action_output(port=self.connection.ports[server_ip]))
        self.connection.send(msg)

def launch():
    def start_switch(event):
        log.info("Initializing Load Balancer")
        LoadBalancer(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
