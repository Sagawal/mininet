# Import necessary modules from Ryu
from ryu.base import app_manager
from ryu.lib.packet import ethernet
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types
from ryu.controller import ofp_event
from ryu.lib.packet import packet


# Define a Ryu application class for a simple firewall monitor
class FirewallMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Initialize the Ryu application
    def __init__(self, *args, **kwargs):
        super(FirewallMonitor, self).__init__(*args, **kwargs)
        # Dictionary to store MAC addresses to corresponding ports
        self.mac_to_port = {}


    # Event handler for packet-in events
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Extract Ethernet packet from the message
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Implement your firewall rules here
        # Block communication between H2 and H5
        if (src == "00:00:00:00:11:12" and dst == "00:00:00:00:11:15") or (src == "00:00:00:00:11:13" and dst == "00:00:00:00:11:15"):
            return
        
        # Block communication between H3 and H5
        if (src == "00:00:00:00:11:15" and dst == "00:00:00:00:11:12") or (src == "00:00:00:00:11:15" and dst == "00:00:00:00:11:13"):
            return

        # Block communication between H1 and H4
        if (src == "00:00:00:00:11:11" and dst == "00:00:00:00:11:14") or (src == "00:00:00:00:11:14" and dst == "00:00:00:00:11:11"):
            return

        # Count all packets coming from host H3 on switch S1
        if dpid == 1 and src == "00:00:00:00:11:13":
            self.logger.info("Packet from H3 on Switch S1: %s", pkt)

        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # Method to add a flow to the switch
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
                ]

        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id,
                priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match, instructions=inst)

        datapath.send_msg(mod)

    # Event handler for switch features
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install a table-miss flow entry to send unmatched packets to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    

