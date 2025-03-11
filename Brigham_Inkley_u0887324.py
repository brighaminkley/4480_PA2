# This is PA2, SDN
# By Brigham Inkley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet, arp  # Make sure you import the arp module correctly

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
        try:
            global server_index
            packet = event.parsed

            # Check if the packet is an ARP request for the virtual IP
            if packet.type == packet.ARP_TYPE and packet.payload.protodst == VIRTUAL_IP:
                log.info("Intercepted ARP request for virtual IP")
                
                # Round-robin to choose which server to respond with
                server_ip = SERVERS[server_index]
                server_mac = MACS[server_ip]

                # Create ARP reply
                arp_reply = arp.arp()  # Create the ARP object explicitly using arp.arp()
                arp_reply.hwsrc = server_mac
                arp_reply.hwdst = packet.payload.protosrc  # Source MAC address of the ARP request
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = VIRTUAL_IP
                arp_reply.protodst = packet.payload.protosrc  # Source IP address of the ARP request

                # Wrap the ARP reply in an Ethernet frame
                ethernet_reply = ethernet.ethernet()  # Create an Ethernet frame explicitly using ethernet.ethernet()
                ethernet_reply.src = server_mac
                ethernet_reply.dst = packet.src
                ethernet_reply.type = ethernet.ARP_TYPE
                ethernet_reply.payload = arp_reply

                # Send ARP reply
                msg = of.ofp_packet_out()
                msg.data = ethernet_reply.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                self.connection.send(msg)

                # Rotate server for round-robin balancing
                server_index = (server_index + 1) % len(SERVERS)

                # Install client-to-server and server-to-client flows
                self.install_flow(event.port, server_ip, server_mac, packet)
        
        except Exception as e:
            log.error(f"Error handling PacketIn event: {e}")
        

    def install_flow(self, client_port, server_ip, server_mac, packet):
        # Install client-to-server flow
        log.info("Installing client-to-server flow:")
        log.info(f"  Match: in_port={client_port}, dl_type=0x0800, nw_dst={VIRTUAL_IP}")
        log.info(f"  Actions: set_dst(mac)={server_mac}, set_dst(ip)={server_ip}, output={self.connection.ports[server_ip]}")

        msg_client_to_server = of.ofp_flow_mod()
        msg_client_to_server.match.dl_type = 0x0800  # Match IPv4 traffic
        msg_client_to_server.match.nw_dst = VIRTUAL_IP  # Match the virtual IP
        msg_client_to_server.match.in_port = client_port  # Match client port

        msg_client_to_server.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        msg_client_to_server.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        msg_client_to_server.actions.append(of.ofp_action_output(port=self.connection.ports[server_ip]))
        self.connection.send(msg_client_to_server)

        # Install server-to-client flow
        log.info("Installing server-to-client flow:")
        log.info(f"  Match: in_port={self.connection.ports[server_ip]}, dl_type=0x0800, nw_src={server_ip}, nw_dst={packet.payload.protosrc}")
        log.info(f"  Actions: set_src(ip)={VIRTUAL_IP}, set_src(mac)={server_mac}, output={client_port}")

        msg_server_to_client = of.ofp_flow_mod()
        msg_server_to_client.match.dl_type = 0x0800  # Match IPv4 traffic
        msg_server_to_client.match.nw_src = server_ip  # Match the server's IP
        msg_server_to_client.match.nw_dst = packet.payload.protosrc  # Match the client's IP
        msg_server_to_client.match.in_port = self.connection.ports[server_ip]  # Match server port

        msg_server_to_client.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
        msg_server_to_client.actions.append(of.ofp_action_dl_addr.set_src(server_mac))
        msg_server_to_client.actions.append(of.ofp_action_output(port=client_port))
        self.connection.send(msg_server_to_client)

def launch():
    def start_switch(event):
        log.info("Initializing Load Balancer")
        LoadBalancer(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)