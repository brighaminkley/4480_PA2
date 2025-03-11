# This is PA2, SDN
# By Brigham Inkley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet, arp

log = core.getLogger()

# Virtual IP and backend servers
VIRTUAL_IP = IPAddr("10.0.0.10")
SERVERS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]
MACS = {IPAddr("10.0.0.5"): EthAddr("00:00:00:00:00:05"),
        IPAddr("10.0.0.6"): EthAddr("00:00:00:00:00:06")}
server_index = 0  # Tracks which server to assign next

class LoadBalancer(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        try:
            global server_index
            packet = event.parsed

            log.info(f"Packet type: {packet.type}")
            log.info(f"Packet details: {packet}")

            # Check if the packet is an ARP request for the virtual IP
            if packet.type == ethernet.ARP_TYPE and packet.payload.protodst == VIRTUAL_IP:
                log.info("Intercepted ARP request for virtual IP")

                # Round-robin to choose which server to respond with
                log.info("THIS is line 33")
                server_ip = SERVERS[server_index]
                server_mac = MACS[server_ip]

                # Create ARP reply (use arp() to create an ARP packet)
                log.info("Right before arp() creation")
                arp_reply = arp()  # Create ARP packet using arp() constructor
                arp_reply.hwsrc = server_mac  # Set the source MAC address of the server
                arp_reply.hwdst = packet.src  # Set the destination MAC address (from the ARP request)
                arp_reply.opcode = arp.REPLY  # Set ARP reply opcode
                arp_reply.protosrc = VIRTUAL_IP  # Set the source IP address (virtual IP)
                arp_reply.protodst = packet.payload.protosrc  # Set the destination IP address (requester's IP)

                # Create the Ethernet frame and set its payload as the ARP reply
                ethernet_reply = ethernet()  # Create an Ethernet frame
                ethernet_reply.type = ethernet.ARP_TYPE  # Set Ethernet type to ARP
                ethernet_reply.dst = packet.src  # Set destination MAC address (from ARP request)
                ethernet_reply.src = server_mac  # Set source MAC address of the server
                ethernet_reply.payload = arp_reply  # Attach the ARP reply as the payload

                # Send ARP reply to the switch
                msg = of.ofp_packet_out()
                msg.data = ethernet_reply.pack()  # Pack the Ethernet frame with ARP payload
                msg.actions.append(of.ofp_action_output(port=event.port))  # Output the packet to the correct port
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