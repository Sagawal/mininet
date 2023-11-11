from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import in_proto

class SimpleLoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    VIRTUAL_IP = '10.0.0.42'
    SERVERS = [
        {'ip': '192.168.1.4', 'mac': '00:00:00:00:11:14', 'port': 1},
        {'ip': '192.168.1.5', 'mac': '00:00:00:00:11:15', 'port': 2}
    ]
    
    def __init__(self, *args, **kwargs):
        super(SimpleLoadBalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.server_index = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # Ignore LLDP packet

        dst_mac = eth.dst
        src_mac = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn MAC address to avoid FLOOD next time
        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac == self.VIRTUAL_IP:
            # Handle ARP Requests for the Virtual IP
            self.handle_arp(datapath, in_port, pkt, eth)
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            # Handle TCP Packets
            self.handle_tcp(datapath, in_port, pkt, eth)

    def handle_arp(self, datapath, in_port, pkt, eth):
        arp_header = pkt.get_protocol(arp.arp)
        if arp_header.opcode == arp.ARP_REQUEST and arp_header.dst_ip == self.VIRTUAL_IP:
            # Build ARP reply packet using source IP and source MAC
            reply_packet = self.generate_arp_reply(arp_header.src_ip, arp_header.src_mac)
            actions = [parser.OFPActionOutput(in_port)]
            packet_out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY,
                                             data=reply_packet.data, actions=actions, buffer_id=ofproto.OFP_NO_BUFFER)
            datapath.send_msg(packet_out)

    def handle_tcp(self, datapath, in_port, pkt, eth):
        ip_header = pkt.get_protocol(ipv4.ipv4)
        if ip_header.dst == self.VIRTUAL_IP and ip_header.proto == in_proto.IPPROTO_TCP:
            # Round-robin between servers
            server = self.SERVERS[self.server_index]
            self.server_index = (self.server_index + 1) % len(self.SERVERS)

            # Route to the selected server
            match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                                    ip_proto=ip_header.proto, ipv4_dst=self.VIRTUAL_IP)
            actions = [parser.OFPActionSetField(ipv4_dst=server['ip']),
                       parser.OFPActionOutput(server['port'])]
            self.add_flow(datapath, 20, match, actions)

            # Reverse route from server
            match = parser.OFPMatch(in_port=server['port'], eth_type=ether_types.ETH_TYPE_IP,
                                    ip_proto=ip_header.proto, ipv4_src=server['ip'],
                                    eth_dst=eth.src)
            actions = [parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP),
                       parser.OFPActionOutput(in_port)]
            self.add_flow(datapath, 20, match, actions)

    def generate_arp_reply(self, dst_ip, dst_mac):
        src_ip = self.VIRTUAL_IP

        # Round-robin between servers for ARP reply
        server = self.SERVERS[self.server_index]
        self.server_index = (self.server_index + 1) % len(self.SERVERS)

        if haddr_to_int(dst_mac) % 2 == 1:
            src_mac = server['mac']
        else:
            src_mac = self.SERVERS[1 - self.server_index]['mac']

        pkt = packet.Packet()
        pkt.add_protocol(
            ethernet.ethernet(
                dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP)
        )
        pkt.add_protocol(
            arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip,
                    dst_mac=dst_mac, dst_ip=dst_ip)
        )
        pkt.serialize()
        return pkt
