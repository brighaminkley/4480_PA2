#This is PA2, SDN
#By Brigham Inkley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet, arp
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
        
            #Create a new ARP reply
            arp_reply = arp()
            arp_reply.hwsrc = server_mac
            arp_reply.hwdst = packet.src
            arp_reply.opcode = arp.REPLY
            arp_reply.protosrc = VIRTUAL_IP
            arp_reply.protodst = packet.payload.protosrc
        
            #Wrap it in an Ethernet frame
            ethernet_reply = ethernet()
            ethernet_reply.src = server_mac
            ethernet_reply.dst = packet.src
            ethernet_reply.type = ethernet.ARP_TYPE
            ethernet_reply.payload = arp_reply
        
            #Send ARP reply
            msg = of.ofp_packet_out()
            msg.data = ethernet_reply.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))
            self.connection.send(msg)
        
            #Rotate server for round-robin balancing
            server_index = (server_index + 1) % len(SERVERS)

            # Install flow rules to forward ICMP traffic
            self.install_flow(event.port, server_ip, server_mac)

    def install_flow(self, client_port, server_ip, server_mac):
        # Flow for traffic from client to server (virtual IP to real IP)
        msg_client_to_server = of.ofp_flow_mod()
        msg_client_to_server.match.dl_type = 0x0800  # IP packets [cite: 32, 33, 34]
        msg_client_to_server.match.nw_dst = VIRTUAL_IP  # Match packets destined for virtual IP [cite: 32, 33, 34]
        msg_client_to_server.match.in_port = client_port  # Match the client's port [cite: 32, 33, 34]
        msg_client_to_server.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        msg_client_to_server.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        
        # Forward the packet to the server [cite: 32, 33, 34]
        msg_client_to_server.actions.append(of.ofp_action_output(port=self.connection.ports[server_ip]))
        self.connection.send(msg_client_to_server)

        # Flow for traffic from server to client (real IP to virtual IP)
        msg_server_to_client = of.ofp_flow_mod()
        msg_server_to_client.match.dl_type = 0x0800  # IP packets [cite: 35]
        msg_server_to_client.match.nw_src = server_ip  # Match packets coming from the server [cite: 35]
        msg_server_to_client.match.nw_dst = IPAddr(packet.payload.protodst) #packet.payload.protodst  # Match packets destined for the client [cite: 35]
        msg_server_to_client.match.in_port = self.connection.ports[server_ip]  # Match the server's port [cite: 35]
        msg_server_to_client.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
        msg_server_to_client.actions.append(of.ofp_action_dl_addr.set_src(server_mac))
            
        # Forward the packet to the client
        msg_server_to_client.actions.append(of.ofp_action_output(port=client_port))
        self.connection.send(msg_server_to_client)

def launch():
    def start_switch(event):
        log.info("Initializing Load Balancer")
        LoadBalancer(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
