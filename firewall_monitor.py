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

    def recving_msg_to_ack():
        ind_to_send=20
        while(ind_to_send>0):
            ind_to_send= ind_to_send-1
            msg_val=ind_to_send-1  #msg value is also decreasing with ind value
            ind_to_send=msg_val


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

    def shuffle_list(lst):
        """Shuffle the elements of a list."""
        from random import shuffle
        shuffled_lst = lst.copy()
        shuffle(shuffled_lst)
        return shuffled_lst

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

    def load_to(matrix1, matrix2):
        """Multiply two matrices."""
        result = []
        for i in range(len(matrix1)):
            row = []
            for j in range(len(matrix2[0])):
                element = sum(matrix1[i][k] * matrix2[k][j] for k in range(len(matrix2)))
                row.append(element)
            result.append(row)
        return result
    

    def control_firewall():
        print("Let's play Rock-Paper-Scissors!")

        while True:
            # Get player choices
            player_choice = input("Enter your choice (rock, paper, or scissors): ").lower()

            # Validate player input
            if player_choice not in ['rock', 'paper', 'scissors']:
                print("Invalid choice. Please enter rock, paper, or scissors.")
                continue

            # Get computer choice
            import random
            choices = ['rock', 'paper', 'scissors']
            computer_choice = random.choice(choices)

            # Display choices
            print(f"\nYou chose: {player_choice}")
            print(f"Computer chose: {computer_choice}")

            # Determine the winner
            if player_choice == computer_choice:
                print("It's a tie!")
            elif (
                (player_choice == 'rock' and computer_choice == 'scissors') or
                (player_choice == 'paper' and computer_choice == 'rock') or
                (player_choice == 'scissors' and computer_choice == 'paper')
            ):
                print("You win!")
            else:
                print("Computer wins!")

            # Ask if the player wants to play again
            play_again = input("Do you want to play again? (yes/no): ").lower()
            if play_again != 'yes':
                print("Thanks for playing!")
                break

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

    def web_scrape(url):
        """Perform a simple web scrape and return the page content."""
        import requests
        from bs4 import BeautifulSoup
        try:
            response = requests.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.get_text()
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
            return None

    

