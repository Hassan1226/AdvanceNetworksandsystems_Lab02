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

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
import heapq

import topo


class SPRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)
        self.switches = {}
        self.links = {}
        self.arp_table = {}
        self.host_location = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install entry-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):

        switch_list = get_switch(self, None)
        self.switches = {s.dp.id: s.dp for s in switch_list}
        link_list = get_link(self, None)
        self.links = {}
        for link in link_list:
            self.links.setdefault(link.src.dpid, {})[link.dst.dpid] = link.src.port_no
            self.links.setdefault(link.dst.dpid, {})[link.src.dpid] = link.dst.port_no
        self.logger.info("Topology: %d switches, %d links", len(self.switches), len(link_list))

    def dijkstra_algorithm(self, src_dpid, dst_dpid):

        if src_dpid not in self.switches or dst_dpid not in self.switches: return None
        distances = {dpid: float('inf') for dpid in self.switches}
        previous = {dpid: None for dpid in self.switches}
        distances[src_dpid] = 0
        pq = [(0, src_dpid)]
        while pq:
            dist, current_dpid = heapq.heappop(pq)
            if dist > distances[current_dpid] or current_dpid == dst_dpid:
                if current_dpid == dst_dpid: break
                continue
            for neighbor_dpid in self.links.get(current_dpid, {}):
                if distances[current_dpid] + 1 < distances[neighbor_dpid]:
                    distances[neighbor_dpid] = distances[current_dpid] + 1
                    previous[neighbor_dpid] = current_dpid
                    heapq.heappush(pq, (distances[neighbor_dpid], neighbor_dpid))
        path = []
        curr = dst_dpid
        while curr is not None:
            path.insert(0, curr)
            curr = previous[curr]
        return path if path and path[0] == src_dpid else None

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid, in_port = datapath.id, msg.match['in_port']
        
        # TODO: handle new packets at the controller

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP: return

        is_from_switch = dpid in self.links and in_port in self.links[dpid].values()
        if not is_from_switch:
            src_ip = None
            arp_pkt = pkt.get_protocol(arp.arp)
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            if arp_pkt: src_ip = arp_pkt.src_ip
            elif ipv4_pkt: src_ip = ipv4_pkt.src

            if src_ip and src_ip != '0.0.0.0':
                self.arp_table[src_ip] = eth.src
                if self.host_location.get(src_ip) != (dpid, in_port):
                    self.logger.info("Host Discovery: %s at switch %d, port %d", src_ip, dpid, in_port)
                    self.host_location[src_ip] = (dpid, in_port)

        arp_pkt_check = pkt.get_protocol(arp.arp)
        ipv4_pkt_check = pkt.get_protocol(ipv4.ipv4)
        if arp_pkt_check: self.arp_handler(datapath, pkt, arp_pkt_check, in_port)
        elif ipv4_pkt_check: self.ipv4_handler(datapath, pkt, ipv4_pkt_check)

    def arp_handler(self, datapath, pkt, arp_pkt, in_port):
        if arp_pkt.opcode == arp.ARP_REQUEST:
            if arp_pkt.dst_ip in self.arp_table:
                self.send_arp_reply(datapath, arp_pkt.dst_ip, arp_pkt.src_ip, in_port)
            else:
                self.flood_packet(datapath, pkt)

    def ipv4_handler(self, datapath, pkt, ipv4_pkt):
        dst_ip = ipv4_pkt.dst
        if dst_ip not in self.host_location:
            self.flood_packet(datapath, pkt)
            return

        dst_dpid, _ = self.host_location[dst_ip]
        path = self.dijkstra_algorithm(datapath.id, dst_dpid)

        if path:
            self.logger.info("Path Found: %s", path)
            for i in range(len(path) - 1):
                out_port = self.links[path[i]][path[i+1]]
                self.install_path_flow(self.switches[path[i]], dst_ip, out_port)
            
            final_dpid, final_port = self.host_location[dst_ip]
            self.install_path_flow(self.switches[final_dpid], dst_ip, final_port)
            
            first_hop_dpid = path[0]
            if len(path) > 1: out_port = self.links[first_hop_dpid][path[1]]
            else: out_port = self.host_location[dst_ip][1]
            self.send_packet_out(self.switches[first_hop_dpid], out_port, pkt)

    def install_path_flow(self, datapath, dst_ip, out_port):
        match = datapath.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, 1, match, actions)

    def send_packet_out(self, datapath, port, pkt):
        ofproto, parser = datapath.ofproto, datapath.ofproto_parser
        pkt.serialize()
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
        datapath.send_msg(out)

    def send_arp_reply(self, datapath, src_ip, dst_ip, out_port):
        src_mac, dst_mac = self.arp_table[src_ip], self.arp_table[dst_ip]
        e = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP)
        a = arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip, dst_mac=dst_mac, dst_ip=dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        self.send_packet_out(datapath, out_port, p)

    def flood_packet(self, datapath, pkt):
        self.send_packet_out(datapath, datapath.ofproto.OFPP_FLOOD, pkt)