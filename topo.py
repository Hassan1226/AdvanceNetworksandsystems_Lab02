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

# Class for an edge in the graph
class Edge:
    def __init__(self):
        self.lnode = None
        self.rnode = None
    
    def remove(self):
        self.lnode.edges.remove(self)
        self.rnode.edges.remove(self)
        self.lnode = None
        self.rnode = None

# Class for a node in the graph
class Node:

    # Initialize a node with an ID and type (host, edge, aggregation, core)
    def __init__(self, node_id, node_type):
        self.edges = []
        self.id = node_id
        self.type = node_type
        self.ip = None
        self.mac = None
        self.dpid = None

    # Add an edge connected to another node
    def add_edge(self, node):
        edge = Edge()
        edge.lnode = self
        edge.rnode = node
        self.edges.append(edge)
        node.edges.append(edge)
        return edge

    # Remove an edge from the node
    def remove_edge(self, edge):
        self.edges.remove(edge)

    # Decide if another node is a neighbor
    def is_neighbor(self, node):
        for edge in self.edges:
            if edge.lnode == node or edge.rnode == node:
                return True
        return False

# Building a logical fat-tree topology
class Fattree:
    def __init__(self, k):
        
        if k % 2 != 0:
            raise ValueError("Fat-tree k values must be an even number.")
        
        self.hosts = []
        self.core_switches = []
        self.agg_switches = []
        self.edge_switches = []

        self.k = k
        self.num_pods = k
        self.num_core_switches = (k // 2) ** 2
        self.num_agg_switches_per_pod = k // 2
        self.num_edge_switches_per_pod = k // 2
        self.num_hosts_per_edge_switch = k // 2
        
        self.generate()
        self.assign_host_addresses()

    def generate(self):
        self.build_switches()
        self.build_hosts()
        self.link_layers()

    def build_switches(self):
        edge_dpid_start = 1
        agg_dpid_start = edge_dpid_start + (self.k * self.num_edge_switches_per_pod)
        core_dpid_start = agg_dpid_start + (self.k * self.num_agg_switches_per_pod)

        # Create the core layer switches and assign their DPIDs
        for i in range(self.num_core_switches):
            switch = Node(f"c{i+1}", "core")
            switch.dpid = core_dpid_start + i
            self.core_switches.append(switch)

        # Create Pod Switches (edge and aggregation) and assign their DPIDs
        for p in range(self.num_pods):
            for s in range(self.num_edge_switches_per_pod):
                # Edge switch
                edge_switch = Node(f"e_p{p}_s{s}", "edge")
                edge_switch.dpid = edge_dpid_start + (p * self.num_edge_switches_per_pod) + s
                self.edge_switches.append(edge_switch)
                # Aggregation switch
                agg_switch = Node(f"a_p{p}_s{s}", "aggregation")
                agg_switch.dpid = agg_dpid_start + (p * self.num_agg_switches_per_pod) + s
                self.agg_switches.append(agg_switch)

    def build_hosts(self):
        total_hosts = self.num_pods * self.num_edge_switches_per_pod * self.num_hosts_per_edge_switch
        for i in range(total_hosts):
            self.hosts.append(Node(f"h{i}", "host"))

    def link_layers(self):

        # Link each edge switch to its attached hosts
        for p in range(self.num_pods):
            for e in range(self.num_edge_switches_per_pod):
                edge_switch_index = self.edge_switch_index(p, e)
                for h in range(self.num_hosts_per_edge_switch):
                    host_index = edge_switch_index * self.num_hosts_per_edge_switch + h
                    self.edge_switches[edge_switch_index].add_edge(self.hosts[host_index])

        # Link edge switches to aggregation switches within the same pod
        for p in range(self.num_pods):
            for e in range(self.num_edge_switches_per_pod):
                edge_switch_index = self.edge_switch_index(p, e)
                for a in range(self.num_agg_switches_per_pod):
                    agg_switch_index = self.aggregation_switch_index(p, a)
                    self.edge_switches[edge_switch_index].add_edge(self.agg_switches[agg_switch_index])

        # Link aggregation switches to core switches
        for p in range(self.num_pods):
            for a in range(self.num_agg_switches_per_pod):
                agg_switch_index = self.aggregation_switch_index(p, a)
                for c in range(self.num_agg_switches_per_pod):
                    core_switch_index = a * self.num_agg_switches_per_pod + c
                    self.agg_switches[agg_switch_index].add_edge(self.core_switches[core_switch_index])

    def edge_switch_index(self, pod, edge):
        return pod * self.num_edge_switches_per_pod + edge
    
    def aggregation_switch_index(self, pod, agg):
        return pod * self.num_agg_switches_per_pod + agg
    
    # Assign IP and MAC addresses to hosts based on their position in the topology
    def assign_host_addresses(self):
        for p in range(self.num_pods):
            for e in range(self.num_edge_switches_per_pod):
                for h in range(self.num_hosts_per_edge_switch):
                    host_id = h + 2
                    host_index = (self.edge_switch_index(p, e)) * self.num_hosts_per_edge_switch + h
                    host = self.hosts[host_index]
                    host.ip = f"10.{p}.{e}.{host_id}" # IP : 10.<pod>.<edge>.<host_id>
                    host.mac = f"00:00:00:{p:02x}:{e:02x}:{host_id:02x}" # MAC : 00:00:00:<pod>:<edge>:<host_id>

    
    # Return switches in the order expected by Mininet
    def get_all_switches(self):
        return self.core_switches + self.agg_switches + self.edge_switches
    
    # Return All the host nodes
    def get_hosts(self):
        return self.hosts