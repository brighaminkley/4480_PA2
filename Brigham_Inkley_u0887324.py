# PA2 - SDN Load Balancer
# By Brigham Inkley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet, arp, ipv4, icmp

log = core.getLogger()

# Configuration
VIRTUAL_IP = IPAddr("10.0.0.10")
VIRTUAL_MAC = EthAddr("00:00:00:00:00:10")
SERVERS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]
CLIENTS = [IPAddr(f"10.0.0.{i}") for i in range(1,5)]  # h1-h4
MACS = {
    IPAddr("10.0.0.5"): EthAddr("00:00:00:00:00:05"),
    IPAddr("10.0.0.6"): EthAddr("00:00:00:00:00:06")
}
CLIENT_MACS = {
    IPAddr(f"10.0.0.{i}"): EthAddr(f"00:00:00:00:00:0{i}")
    for i in range(1,5)  # h1-h4
}
SERVER_PORTS = {
    IPAddr("10.0.0.5"): 5,  # Port for h5
    IPAddr("10.0.0.6"): 6    # Port for h6
}
server_index = 0  # Round-robin counter

class LoadBalancer(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("10:38 Load balancer initialized")
        self.install_default_flow()

    def install_default_flow(self):
        """Install catch-all flow for unknown traffic"""
        msg = of.ofp_flow_mod()
        msg.priority = 0  # Lowest priority
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)
        log.info("Installed default flooding flow")

    def _handle_PacketIn(self, event):
        """Main packet handler"""
        packet = event.parsed
        
        # Ignore IPv6 and malformed packets
        if not packet or packet.type == ethernet.IPV6_TYPE:
            return

        if packet.type == ethernet.ARP_TYPE:
            self._handle_arp(event, packet)
        elif packet.type == ethernet.IP_TYPE:
            self._handle_ip(event, packet)

    def _handle_arp(self, event, packet):
        log.info("In handle_arp method")
        arp_pkt = packet.payload
        log.info(f"Received ARP packet: {arp_pkt}")
        
        if arp_pkt.opcode == arp.REQUEST:
            log.info(f"ARP request from {arp_pkt.protosrc} for {arp_pkt.protodst}")
            
            # Handle requests for virtual IP
            if arp_pkt.protodst == VIRTUAL_IP:
                log.info("Handling ARP request for virtual IP")
                self._handle_virtual_ip_arp(event, arp_pkt)
            # Handle server requests for client IPs
            elif arp_pkt.protodst in CLIENTS and arp_pkt.protosrc in SERVERS:
                log.info("Handling ARP request from server")
                self._handle_server_arp(event, arp_pkt)
            else:
                log.warning(f"Unhandled ARP request: {arp_pkt}")
        else:
            log.warning(f"Unhandled ARP packet: {arp_pkt}")

    def _handle_virtual_ip_arp(self, event, arp_pkt):
        global server_index
        
        client_ip = arp_pkt.protosrc
        client_mac = arp_pkt.hwsrc
        client_port = event.port
        
        # Select server using round-robin
        server_ip = SERVERS[server_index]
        server_mac = MACS[server_ip]
        server_port = SERVER_PORTS[server_ip]
        server_index = (server_index + 1) % len(SERVERS)
        
        log.info(f"Mapping {client_ip} -> {server_ip} (Round-robin index: {server_index})")
        
        # Send ARP reply with virtual MAC
        self._send_arp_reply(
            src_mac=VIRTUAL_MAC,
            src_ip=VIRTUAL_IP,
            dst_mac=client_mac,
            dst_ip=client_ip,
            out_port=client_port
        )
        
        # Install bidirectional flow rules
        self._install_client_server_flows(
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            server_mac=server_mac
        )

    def _handle_server_arp(self, event, arp_pkt):
        client_ip = arp_pkt.protodst
        server_ip = arp_pkt.protosrc
        
        if client_ip not in CLIENT_MACS:
            log.error(f"Unknown client IP {client_ip}")
            return
            
        self._send_arp_reply(
            src_mac=CLIENT_MACS[client_ip],
            src_ip=client_ip,
            dst_mac=MACS[server_ip],
            dst_ip=server_ip,
            out_port=SERVER_PORTS[server_ip]
        )

    def _handle_ip(self, event, packet):
        """Handle IP packets"""
        ip_pkt = packet.payload
        
        if isinstance(ip_pkt, ipv4) and ip_pkt.protocol == ipv4.ICMP_PROTOCOL:
            self._handle_icmp(event, packet, ip_pkt)

    def _handle_icmp(self, event, packet, ip_pkt):
        """Handle ICMP traffic"""
        # Only process echo requests (ping)
        if not isinstance(ip_pkt.payload, icmp) or ip_pkt.payload.type != icmp.ECHO_REQUEST:
            return

        client_ip = ip_pkt.srcip
        client_port = event.port
        
        log.info(f"ICMP request from {client_ip} to {ip_pkt.dstip}")
        
        # If destination is virtual IP, install flows
        if ip_pkt.dstip == VIRTUAL_IP:
            self._install_client_server_flows(
                client_ip=client_ip,
                client_port=client_port,
                server_ip=SERVERS[server_index],
                server_port=SERVER_PORTS[SERVERS[server_index]],
                server_mac=MACS[SERVERS[server_index]]
            )

    def _send_arp_reply(self, src_mac, src_ip, dst_mac, dst_ip, out_port):
        """Construct and send ARP reply"""
        reply = arp()
        reply.opcode = arp.REPLY
        reply.hwsrc = src_mac
        reply.protosrc = src_ip
        reply.hwdst = dst_mac
        reply.protodst = dst_ip

        eth = ethernet()
        eth.type = ethernet.ARP_TYPE
        eth.src = src_mac
        eth.dst = dst_mac
        eth.payload = reply

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)
        
        log.debug(f"Sent ARP reply: {src_ip} -> {dst_ip}")

    def _install_client_server_flows(self, client_ip, client_port, server_ip, server_port, server_mac):
        # Client -> Server flow
        match = of.ofp_match(
            in_port=client_port,
            dl_type=ethernet.IP_TYPE,
            nw_proto=ipv4.ICMP_PROTOCOL,
            nw_src=client_ip,
            nw_dst=VIRTUAL_IP
        )
        
        actions = [
            of.ofp_action_dl_addr.set_dst(server_mac),
            of.ofp_action_nw_addr.set_dst(server_ip),
            of.ofp_action_output(port=server_port)
        ]
        
        self._send_flow_mod(match, actions)
        
        # Server -> Client flow
        match = of.ofp_match(
            in_port=server_port,
            dl_type=ethernet.IP_TYPE,
            nw_proto=ipv4.ICMP_PROTOCOL,
            nw_src=server_ip,
            nw_dst=client_ip
        )
        
        actions = [
            of.ofp_action_dl_addr.set_src(VIRTUAL_MAC),
            of.ofp_action_nw_addr.set_src(VIRTUAL_IP),
            of.ofp_action_output(port=client_port)
        ]
        
        self._send_flow_mod(match, actions)

    def _send_flow_mod(self, match, actions, idle_timeout=10, hard_timeout=60):
        """Helper to create and send flow mods"""
        fm = of.ofp_flow_mod()
        fm.match = match
        fm.actions = actions
        fm.idle_timeout = idle_timeout
        fm.hard_timeout = hard_timeout
        fm.priority = 100  # Higher than default flow
        self.connection.send(fm)

def launch():
    """POX entry point"""
    def start_switch(event):
        log.info(f"Controlling switch: {event.connection.dpid}")
        LoadBalancer(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)