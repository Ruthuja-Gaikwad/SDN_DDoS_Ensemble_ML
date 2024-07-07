from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
import csv
import os

class CollectStats(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CollectStats, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        home_dir = os.path.expanduser('~')
        self.flow_file = os.path.join(home_dir, 'flow_stats.csv')
        self.port_file = os.path.join(home_dir, 'port_stats.csv')

        with open(self.flow_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['datapath', 'in_port', 'eth_src', 'eth_dst', 'ip_src', 'ip_dst',
                             'protocol', 'tcp_src', 'tcp_dst', 'packet_count', 'byte_count',
                             'duration_sec', 'duration_nsec', 'class_label'])

        with open(self.port_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['datapath', 'port_no', 'rx_packets', 'tx_packets', 'rx_bytes', 'tx_bytes',
                             'rx_dropped', 'tx_dropped', 'rx_errors', 'tx_errors', 'rx_frame_err',
                             'rx_over_err', 'rx_crc_err', 'collisions', 'duration_sec', 'duration_nsec'])

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == 'DEAD':
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)  # Adjust the frequency as needed

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        with open(self.flow_file, 'a', newline='') as f:
            writer = csv.writer(f)
            for stat in sorted(body, key=lambda stat: (stat.match.get('in_port', 0), stat.match.get('eth_dst', ''))):
                class_label = 0  # Default to normal traffic
                if self.is_malicious(stat):  # Define your condition for malicious traffic
                    class_label = 1

                writer.writerow([
                    ev.msg.datapath.id,  # Datapath ID
                    stat.match.get('in_port', 0),  # Input port or default to 0 if not present
                    stat.match.get('eth_src', ''),  # Ethernet source address
                    stat.match.get('eth_dst', ''),  # Ethernet destination address
                    stat.match.get('ipv4_src', ''),  # IPv4 source address (if available)
                    stat.match.get('ipv4_dst', ''),  # IPv4 destination address (if available)
                    stat.match.get('ip_proto', 0),  # IP protocol number (if available)
                    stat.match.get('tcp_src', 0),  # TCP source port (if available)
                    stat.match.get('tcp_dst', 0),  # TCP destination port (if available)
                    stat.packet_count,  # Packet count
                    stat.byte_count,  # Byte count
                    stat.duration_sec,  # Duration seconds
                    stat.duration_nsec,  # Duration nanoseconds
                    class_label  # Class label: 0 for normal, 1 for malicious
                ])

    def is_malicious(self, stat):
    # Example conditions for detecting malicious traffic
         eth_src = stat.match.get('eth_src', '')
         ip_src = stat.match.get('ipv4_src', '')
         ip_dst = stat.match.get('ipv4_dst', '')
         tcp_src = stat.match.get('tcp_src', 0)
         tcp_dst = stat.match.get('tcp_dst', 0)
         byte_count = stat.byte_count
         packet_count = stat.packet_count

    # Condition 1: Check for specific source MAC address (example)
         if eth_src == 'malicious_mac_address':
             return True

    # Condition 2: Check for specific source or destination IP address (example)
         if ip_src == '10.0.0.3' or ip_dst == '10.0.0.1':
             return True

    # Condition 3: Check for high packet or byte count (example)
         if packet_count > 1000 or byte_count > 1000000:
             return True

    # Condition 4: Check for specific TCP port (example)
         if tcp_src == 12345 or tcp_dst == 80:
             return True

         return False


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        with open(self.port_file, 'a', newline='') as f:
            writer = csv.writer(f)
            for stat in sorted(body, key=lambda stat: stat.port_no):
                writer.writerow([
                    ev.msg.datapath.id,  # Datapath ID
                    stat.port_no,  # Port number
                    stat.rx_packets,  # Received packets
                    stat.tx_packets,  # Transmitted packets
                    stat.rx_bytes,  # Received bytes
                    stat.tx_bytes,  # Transmitted bytes
                    stat.rx_dropped,  # Received dropped
                    stat.tx_dropped,  # Transmitted dropped
                    stat.rx_errors,  # Received errors
                    stat.tx_errors,  # Transmitted errors
                    stat.rx_frame_err,  # Received frame errors
                    stat.rx_over_err,  # Received overrun errors
                    stat.rx_crc_err,  # Received CRC errors
                    stat.collisions,  # Collisions
                    stat.duration_sec,  # Duration seconds
                    stat.duration_nsec  # Duration nanoseconds
                ])

