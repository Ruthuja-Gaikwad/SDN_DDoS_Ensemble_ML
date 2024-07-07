import logging
import psutil
import joblib
import time
import warnings
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from sklearn.exceptions import InconsistentVersionWarning

LOG = logging.getLogger('ryu.app.mitmigation_app')

class MitigationApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MitigationApp, self).__init__(*args, **kwargs)
        self.logger.setLevel(logging.INFO)  # Set log level to INFO or DEBUG
        logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)

        self.malicious_ips = set()  # Set of IPs identified as malicious
        self.legitimate_ips = {'10.0.0.1', '10.0.0.2', '10.0.0.10', '10.0.0.11', '10.0.0.20', '10.0.0.21'}  # Example legitimate IPs
        self.model = joblib.load('voting_classifier.joblib')  # Load the trained model

        # Measure CPU and Memory Usage before the attack
        self.cpu_before = psutil.cpu_percent(interval=1)
        self.memory_before = psutil.virtual_memory().percent

        # Track the number of packets
        self.total_packets = 0
        self.dropped_legitimate_packets = 0

        # Suppress scikit-learn version warnings
        warnings.filterwarnings('ignore', category=InconsistentVersionWarning)

        self.attack_detected_time = 0

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self.logger.info("Packet received and processing started.")

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == 0x0800:  # IPv4
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip_pkt.src

            flow_stats = self.collect_flow_stats(pkt)

            self.logger.info(f"Flow stats collected: {flow_stats}")

            start_time = time.time()
            self.predict_and_block(flow_stats)
            end_time = time.time()

            response_time = end_time - start_time
            self.logger.info(f"Response Time: {response_time} seconds")

            # Measure CPU and Memory Usage during the attack
            self.cpu_during = psutil.cpu_percent(interval=1)
            self.memory_during = psutil.virtual_memory().percent
            self.logger.info(f"CPU Usage During: {self.cpu_during}%")
            self.logger.info(f"Memory Usage During: {self.memory_during}%")

            # Track legitimate packets
            if src_ip in self.legitimate_ips:
                self.total_packets += 1

            # Check if the packet is from a malicious IP
            if src_ip in self.malicious_ips:
                self.drop_packet(datapath, msg.in_port, msg.buffer_id)
                self.logger.info(f"Dropped packet from malicious IP: {src_ip}")

        # Measure CPU and Memory Usage after the attack
        self.cpu_after = psutil.cpu_percent(interval=1)
        self.memory_after = psutil.virtual_memory().percent
        self.logger.info(f"CPU Usage After: {self.cpu_after}%")
        self.logger.info(f"Memory Usage After: {self.memory_after}%")

        # Log legitimate packet loss
        legitimate_packet_loss = self.measure_legitimate_packet_loss()
        self.logger.info(f"Legitimate Packet Loss: {legitimate_packet_loss}%")

    def collect_flow_stats(self, pkt):
        # Extract flow statistics from the packet
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        flow_stats = {
            'src_ip': ip_pkt.src,
            'dst_ip': ip_pkt.dst,
            'src_port': ip_pkt.src_port if hasattr(ip_pkt, 'src_port') else 0,
            'dst_port': ip_pkt.dst_port if hasattr(ip_pkt, 'dst_port') else 0,
            'protocol': ip_pkt.proto
        }
        return flow_stats

    def drop_packet(self, datapath, in_port, buffer_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(in_port=in_port)
        actions = []  # No actions = drop the packet

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                priority=1, match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_malicious_ip(self, ip):
        self.malicious_ips.add(ip)

    def predict_and_block(self, flow_stats):
        # Extract features from flow_stats
        features = self.extract_features(flow_stats)

        # Predict if the flow is malicious
        is_malicious = self.model.predict([features])[0]  # Assuming model.predict expects a 2D array

        if is_malicious:
            ip = flow_stats['src_ip']
            self.add_malicious_ip(ip)
            if ip in self.legitimate_ips:
                self.dropped_legitimate_packets += 1  # Track dropped legitimate packets
                self.detect_attack()  # Trigger attack detection

    def extract_features(self, flow_stats):
        # Implement feature extraction logic here
        # This is an example assuming you have specific features you need
        return [
            self.ip_to_numeric(flow_stats['src_ip']),
            self.ip_to_numeric(flow_stats['dst_ip']),
            flow_stats['src_port'],
            flow_stats['dst_port'],
            flow_stats['protocol']
        ]

    def ip_to_numeric(self, ip):
        # Convert IP address to a numeric format if necessary
        parts = ip.split('.')
        return int(parts[0]) * 256**3 + int(parts[1]) * 256**2 + int(parts[2]) * 256 + int(parts[3])

    def measure_legitimate_packet_loss(self):
        if self.total_packets == 0:
            return 0.0
        return (self.dropped_legitimate_packets / self.total_packets) * 100

    def detect_attack(self):
        self.attack_detected_time = time.time()
        LOG.info("Attack detected at: %s", self.attack_detected_time)

    def mitigate_attack(self):
        response_time = time.time() - self.attack_detected_time
        LOG.info("Mitigation initiated at: %s, Response time: %s seconds", time.time(), response_time)
        # Perform mitigation (e.g., dropping packets)


