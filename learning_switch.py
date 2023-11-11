# Import necessary modules from Ryu
from ryu.lib.packet import ethernet
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.lib.packet import packet
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ether_types
from ryu.ofproto import ofproto_v1_3


# Define a Ryu application class
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Initialize the Ryu application
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        # Dictionary to store MAC addresses to corresponding ports
        self.mac_to_port = {}

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


    # Event handler for packet-in events
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If packet is truncated, log a debug message
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Extract Ethernet packet from the message
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Log information about the received packet
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn the mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # Check if the destination MAC is already learned
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        # Send the packet out to the specified port
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

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

    def recving_msg_to_ack():
        ind_to_send=20
        while(ind_to_send>0):
            ind_to_send= ind_to_send-1
            msg_val=ind_to_send-1  #msg value is also decreasing with ind value
            ind_to_send=msg_val

    

    # Method to add a flow to the switch
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    
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

    def shuffle_list(lst):
        """Shuffle the elements of a list."""
        from random import shuffle
        shuffled_lst = lst.copy()
        shuffle(shuffled_lst)
        return shuffled_lst

    # Event handler for switch features
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install a table-miss flow entry to send packets to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    