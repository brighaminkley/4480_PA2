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
client_macs = {}  # Dictionary to store client MAC addresses


class LoadBalancer(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        try:
            global server_index
            packet = event.parsed

            # Handle ARP Requests
            if packet.type == ethernet.ARP_TYPE and packet.payload.opcode == arp.REQUEST:
                log.info("TAKE 1: Intercepted ARP request for virtual IP")

                server_ip = IPAddr(SERVERS[server_index])
                server_mac = MACS[server_ip]

                # Store client MAC address
                client_macs[packet.payload.protosrc] = packet.src

                # Create ARP reply
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

                #Send ARP reply
                msg = of.ofp_packet_out()
                msg.data = ethernet_reply.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                self.connection.send(msg)

                #Rotate server for round-robin balancing
                server_index = (server_index + 1) % len(SERVERS)

                #Install flow rules
                self.install_flow(event.port, server_ip, server_mac, packet)

        except Exception as e:
            log.error(f"Error handling PacketIn event: {e}")

    def install_flow(self, client_port, server_ip, server_mac, packet):
        try:
            log.info(f"SERVER_PORTS dictionary: {SERVER_PORTS}")
            log.info(f"Trying to access SERVER_PORTS[{server_ip}]")
            server_port = SERVER_PORTS.get(IPAddr(server_ip), None)
            if server_port is None:
                log.error(f"Error: server_ip {server_ip} not found in SERVER_PORTS!")
                return

            client_mac = client_macs.get(packet.payload.protosrc)
            if client_mac is None:
                log.error(f"Error: Client MAC address not found for {packet.payload.protosrc}!")
                return

            #Install client-to-server flow
            log.info("Installing client-to-server flow:")
            log.info(f"  Match: in_port={client_port}, dl_type=0x0800, nw_dst={VIRTUAL_IP}")
            log.info(
                f"  Actions: set_dst(mac)={server_mac}, set_dst(ip)={server_ip}, output={server_port}")

            msg_client_to_server = of.ofp_flow_mod()
            msg_client_to_server.match.dl_type = 0x0800
            msg_client_to_server.match.nw_dst = VIRTUAL_IP
            msg_client_to_server.match.in_port = client_port
            msg_client_to_server.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
            msg_client_to_server.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
            msg_client_to_server.actions.append(of.ofp_action_output(port=server_port))  # ✅ Use mapped port
            self.connection.send(msg_client_to_server)

            #Install server-to-client flow
            log.info("Installing server-to-client flow:")
            log.info(
                f"  Match: in_port={server_port}, dl_type=0x0800, nw_src={server_ip}, nw_dst={packet.payload.protosrc}")
            log.info(
                f"  Actions: set_src(ip)={VIRTUAL_IP}, set_src(mac)={server_mac}, set_dst(mac)={client_mac}, output={client_port}")

            msg_server_to_client = of.ofp_flow_mod()
            msg_server_to_client.match.dl_type = 0x0800
            msg_server_to_client.match.nw_src = server_ip
            msg_server_to_client.match.nw_dst = packet.payload.protosrc
            msg_server_to_client.match.in_port = server_port
            msg_server_to_client.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
            msg_server_to_client.actions.append(of.ofp_action_dl_addr.set_src(server_mac))
            #Add this line to set the destination MAC
            msg_server_to_client.actions.append(of.ofp_action_dl_addr.set_dst(client_mac))
            msg_server_to_client.actions.append(of.ofp_action_output(port=client_port))
            self.connection.send(msg_server_to_client)

        except Exception as e:
            log.error(f"Error installing flow: {e}")


def launch():
    def start_switch(event):
        log.info("Initializing Load Balancer")
        LoadBalancer(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)