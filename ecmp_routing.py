"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

#!/usr/bin/env python3

from collections import defaultdict, deque
import hashlib
import ipaddress
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp, ether_types
from ryu.topology.api import get_switch, get_link
from ryu.lib import hub


TCP_PROTO = 6
UDP_PROTO = 17
ICMP_PROTO = 1


class FTRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FTRouter, self).__init__(*args, **kwargs)
        self.k = 4

        
        self.arp_table = {}         
        self.host_locations = {}  
        self.rules_installed = False
        self.last_log_time = {}

        self.switches = {}
        self.link_map = defaultdict(dict)  
        self.graph = defaultdict(set)     

        self.path_cache = {}        
        self.installed_flows = set() 

        self.monitor_thread = hub.spawn(self.monitor)

    def should_log(self, message_key):
        now = time.time()
        last = self.last_log_time.get(message_key)
        if last is not None and now - last < 2.0:
            return False
        self.last_log_time[message_key] = now
        return True

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    # Sending the packet immediately after installing the flow entries
    def send_packet_out(self, datapath, out_port, data, in_port=None, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if in_port is None:
            in_port = ofproto.OFPP_CONTROLLER

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=buffer_id if buffer_id is not None else ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    # Decode the switch's role from its DPID
    def get_switch_info(self, dpid):
        k = self.k
        edge_start = 1
        agg_start = 1 + (k * k // 2)
        core_start = 1 + k * k

        if dpid >= core_start:
            return "core", -1, dpid - core_start

        if dpid >= agg_start:
            agg_index = dpid - agg_start
            pod = agg_index // (k // 2)
            index = agg_index % (k // 2)
            return "aggregation", pod, index

        edge_index = dpid - edge_start
        pod = edge_index // (k // 2)
        index = edge_index % (k // 2)
        return "edge", pod, index

    # Build the switch graph and port mappings from Ryu topology discovery
    def build_topology(self, switches, links):
        self.switches = {sw.dp.id: sw.dp for sw in switches}
        self.link_map = defaultdict(dict)
        self.graph = defaultdict(set)

        for link in links:
            src = link.src.dpid
            dst = link.dst.dpid
            self.link_map[src][dst] = link.src.port_no
            self.graph[src].add(dst)

    # Return a stable flow key used for ECMP hashing
    def extract_5tuple(self, pkt):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return None

        proto = ip_pkt.proto
        src_port = 0
        dst_port = 0
        l4_name = "other"

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if tcp_pkt is not None:
            l4_name = "tcp"
            src_port = tcp_pkt.src_port or 0
            dst_port = tcp_pkt.dst_port or 0
            #proto = TCP_PROTO
        elif udp_pkt is not None:
            l4_name = "udp"
            src_port = udp_pkt.src_port or 0
            dst_port = udp_pkt.dst_port or 0
            #proto = UDP_PROTO
        elif icmp_pkt is not None:
            l4_name = "icmp"
            src_port = 0
            dst_port = 0
            proto = ICMP_PROTO

        return {
            "src_ip": ip_pkt.src,
            "dst_ip": ip_pkt.dst,
            "proto": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "l4": l4_name,
        }

    # Convert the 5-tuple to a canonical byte string for hashing
    def flow_key_to_bytes(self, flow_key):
        return (
            f'{flow_key["src_ip"]}|{flow_key["dst_ip"]}|'
            f'{flow_key["proto"]}|{flow_key["src_port"]}|{flow_key["dst_port"]}'
        ).encode("utf-8")

    def choose_path_index(self, flow_key, num_paths):
        digest = hashlib.sha256(self.flow_key_to_bytes(flow_key)).digest()
        value = int.from_bytes(digest[:8], byteorder="big", signed=False)
        return value % num_paths

    # Enumerate all shortest paths in the switch graph
    def all_shortest_paths(self, start, goal):
        if start == goal:
            return [[start]]

        dist = {start: 0}
        parents = defaultdict(set)
        q = deque([start])

        while q:
            u = q.popleft()
            for v in self.graph.get(u, []):
                nd = dist[u] + 1
                if v not in dist:
                    dist[v] = nd
                    parents[v].add(u)
                    q.append(v)
                elif dist[v] == nd:
                    parents[v].add(u)

        if goal not in dist:
            return []

        paths = []

        def backtrack(node, suffix):
            if node == start:
                paths.append([start] + suffix[::-1])
                return
            for parent in parents[node]:
                backtrack(parent, suffix + [node])

        backtrack(goal, [])
        # Remove accidental duplicates while preserving order
        unique = []
        seen = set()
        for p in paths:
            t = tuple(p)
            if t not in seen:
                seen.add(t)
                unique.append(p)
        return unique

    # Convert a switch path to a list of (dpid, out_port) forwarding steps
    def build_path_ports(self, path, dst_host_port):
        steps = []
        if not path:
            return steps

        for i, dpid in enumerate(path):
            if i == len(path) - 1:
                steps.append((dpid, dst_host_port))
            else:
                nxt = path[i + 1]
                out_port = self.link_map[dpid].get(nxt)
                if out_port is None:
                    return []
                steps.append((dpid, out_port))
        return steps

    # Find one ECMP candidate path for a flow by hashing the 5-tuple
    def path_for_flow(self, flow_key, src_switch, dst_switch):
        cache_key = (
            flow_key["src_ip"],
            flow_key["dst_ip"],
            flow_key["proto"],
            flow_key["src_port"],
            flow_key["dst_port"],
            src_switch,
            dst_switch,
        )

        if cache_key in self.path_cache:
            return self.path_cache[cache_key]

        candidates = self.all_shortest_paths(src_switch, dst_switch)
        if not candidates:
            return None

        idx = self.choose_path_index(flow_key, len(candidates))
        chosen = candidates[idx]
        self.path_cache[cache_key] = chosen
        return chosen

    # Create a match that keeps the rule specific to the chosen 5-tuple
    def match_from_flow_key(self, parser, flow_key):
        kwargs = {
            "eth_type": ether_types.ETH_TYPE_IP,
            "ipv4_src": flow_key["src_ip"],
            "ipv4_dst": flow_key["dst_ip"],
            "ip_proto": flow_key["proto"],
        }

        if flow_key["l4"] == "tcp":
            kwargs["tcp_src"] = flow_key["src_port"]
            kwargs["tcp_dst"] = flow_key["dst_port"]
        elif flow_key["l4"] == "udp":
            kwargs["udp_src"] = flow_key["src_port"]
            kwargs["udp_dst"] = flow_key["dst_port"]

        return parser.OFPMatch(**kwargs)

    # Remember where a host lives and install a direct host-delivery rule
    def learn_host(self, datapath, in_port, src_ip, src_mac):
        self.host_locations[src_ip] = (datapath.id, in_port)
        self.arp_table[src_ip] = src_mac 
        self.install_host_delivery_rule(datapath, src_ip, in_port)

        if self.should_log(f"host_learned_{src_ip}"):
            self.logger.info("Host learned: %s -> s%s port %s", src_ip, datapath.id, in_port)

    # Deliver any IPv4 packet for the host directly to its attachment port
    def install_host_delivery_rule(self, datapath, host_ip, out_port):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=host_ip)
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, 50, match, actions)

    # Install exact-match forwarding rules on every switch in the chosen path
    def install_flow_along_path(self, flow_key, path, dst_host_port):
        if not path:
            return

        parser_by_dpid = {}
        for dpid in path:
            parser_by_dpid[dpid] = self.switches[dpid].ofproto_parser

        for i, dpid in enumerate(path):
            key = (
                dpid,
                flow_key["src_ip"],
                flow_key["dst_ip"],
                flow_key["proto"],
                flow_key["src_port"],
                flow_key["dst_port"],
            )
            if key in self.installed_flows:
                continue

            parser = parser_by_dpid[dpid]
            match = self.match_from_flow_key(parser, flow_key)

            if i == len(path) - 1:
                out_port = dst_host_port
            else:
                nxt = path[i + 1]
                out_port = self.link_map[dpid].get(nxt)
                if out_port is None:
                    return

            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(self.switches[dpid], 40, match, actions)
            self.installed_flows.add(key)

    ###################### The Topology Installation #####################

    # Waiting until topology discovery is complete, then install routing rules
    def monitor(self):
        while not self.rules_installed:
            hub.sleep(4)

            switches = get_switch(self, None)
            links = get_link(self, None)

            expected_switches = (self.k * self.k) + (self.k * self.k // 4)
            expected_links = self.k * self.k * self.k

            if len(switches) < expected_switches or len(links) < expected_links:
                continue

            self.build_topology(switches, links)

            self.logger.info("Topology discovered. Installing ECMP rules.")
            if self.install_base_rules(switches):
                self.rules_installed = True
                self.logger.info("ECMP routing rules installed successfully.")
            else:
                self.logger.error("ECMP installation failed; will retry.")

    # Install switch-role-specific baseline rules
    def install_base_rules(self, switches):
        try:
            for sw in switches:
                datapath = sw.dp
                dpid = datapath.id
                switch_type, pod, index = self.get_switch_info(dpid)

                if switch_type == "core":
                    self.install_core_rules(datapath, dpid)
                elif switch_type == "aggregation":
                    self.install_aggregation_rules(datapath, dpid, pod, index)
                elif switch_type == "edge":
                    self.install_edge_rules(datapath, dpid, pod, index)
            return True
        except Exception as exc:
            self.logger.exception("Error while installing base ECMP rules: %s", exc)
            return False

    # Core switches are only used as path hops; no static ECMP rule is needed
    def install_core_rules(self, datapath, dpid):
        # We keep the core switch table-miss rule and install per-flow rules on demand.
        # This makes the controller explicitly choose among the equal-cost paths.
        return

    # Aggregation switches only need host delivery learned dynamically
    def install_aggregation_rules(self, datapath, dpid, pod, index):
        return

    # Edge switches only need host delivery learned dynamically
    def install_edge_rules(self, datapath, dpid, pod, index):
        return


    ###################### The Packet handling #####################

    # Table-miss entry to send unknown packets to the controller
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth is None:
            return

        # Learn hosts from ARP first
        # location discovery before ECMP path selection.
        if arp_pkt is not None:
            if arp_pkt.src_ip not in self.host_locations:
                self.learn_host(datapath, in_port, arp_pkt.src_ip, eth.src)

            if arp_pkt.opcode == arp.ARP_REQUEST:
                dst_ip = arp_pkt.dst_ip
                if dst_ip in self.arp_table:
                    src_mac = self.arp_table[dst_ip]

                    reply_pkt = packet.Packet()
                    reply_pkt.add_protocol(
                        ethernet.ethernet(dst=eth.src, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP)
                    )
                    reply_pkt.add_protocol(
                        arp.arp(
                            opcode=arp.ARP_REPLY,
                            src_mac=src_mac,
                            src_ip=dst_ip,
                            dst_mac=eth.src,
                            dst_ip=arp_pkt.src_ip,
                        )
                    )
                    reply_pkt.serialize()

                    self.send_packet_out(
                        datapath,
                        in_port,
                        reply_pkt.data,
                        in_port=ofproto.OFPP_CONTROLLER,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                    )
                    if self.should_log(f"arp_reply_{dst_ip}"):
                        self.logger.info("ARP reply sent: %s is at %s", dst_ip, src_mac)
                else:
                    self.send_packet_out(
                        datapath,
                        ofproto.OFPP_FLOOD,
                        msg.data,
                        in_port=in_port,
                        buffer_id=msg.buffer_id,
                    )
                    if self.should_log(f"arp_flood_{arp_pkt.dst_ip}"):
                        self.logger.info("ARP request flooded for %s", arp_pkt.dst_ip)
            return

        # Handle IPv4 packets for ECMP routing.
        if ip_pkt is None:
            return

        flow_key = self.extract_5tuple(pkt)
        if flow_key is None:
            return

        src_ip = flow_key["src_ip"]
        dst_ip = flow_key["dst_ip"]

        if src_ip not in self.host_locations:
            # Learn from IPv4 traffic as a fallback.
            self.learn_host(datapath, in_port, src_ip, eth.src)

        if dst_ip not in self.host_locations:
            # If the destination is still unknown, let ARP discovery continue.
            self.send_packet_out(
                datapath,
                ofproto.OFPP_FLOOD,
                msg.data,
                in_port=in_port,
                buffer_id=msg.buffer_id,
            )
            return

        src_switch, _ = self.host_locations[src_ip]
        dst_switch, dst_host_port = self.host_locations[dst_ip]

        path = self.path_for_flow(flow_key, src_switch, dst_switch)
        if not path:
            return

        self.install_flow_along_path(flow_key, path, dst_host_port)

        # Send the triggering packet immediately along the chosen path.
        first_out_port = dst_host_port if len(path) == 1 else self.link_map[path[0]].get(path[1])
        if first_out_port is None:
            return

        self.send_packet_out(
            datapath,
            first_out_port,
            msg.data,
            in_port=in_port,
            buffer_id=msg.buffer_id,
        )

        if self.should_log(f"path_{src_ip}_{dst_ip}"):
            self.logger.info(
                "ECMP path chosen for %s -> %s via %s",
                src_ip,
                dst_ip,
                " -> ".join(f"s{d}" for d in path),
            )
