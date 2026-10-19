
import sys
from collections import defaultdict, Counter

import topo

class FattreeValidator:
    def __init__(self, k):
        self.k = k
        self.fattree = topo.Fattree(k)
        self.test_results = []
    
    def log_test(self, test_name, expected, actual, passed):
        """Log test results"""
        status = "PASS" if passed else "FAIL"
        self.test_results.append({
            'test': test_name,
            'expected': expected,
            'actual': actual,
            'status': status
        })
        print(f"[{status}] {test_name}: Expected {expected}, Got {actual}")
    
    # Test if the number of nodes matches fat-tree specifications
    def test_node_counts(self):
        print("\n=== Testing Node Counts ===")
        
        # Expected counts
        expected_hosts = (self.k ** 3) // 4
        expected_core_switches = (self.k // 2) ** 2
        expected_agg_switches = self.k * (self.k // 2)
        expected_edge_switches = self.k * (self.k // 2)
        expected_total_switches = expected_core_switches + expected_agg_switches + expected_edge_switches
        
        # Actual counts
        actual_hosts = len(self.fattree.hosts)
        actual_core_switches = len(self.fattree.core_switches)
        actual_agg_switches = len(self.fattree.agg_switches)
        actual_edge_switches = len(self.fattree.edge_switches)
        actual_total_switches = len(self.fattree.get_all_switches())
        
        # Test assertions
        self.log_test("Host count", expected_hosts, actual_hosts, 
                     expected_hosts == actual_hosts)
        self.log_test("Core switch count", expected_core_switches, actual_core_switches,
                     expected_core_switches == actual_core_switches)
        self.log_test("Aggregation switch count", expected_agg_switches, actual_agg_switches,
                     expected_agg_switches == actual_agg_switches)
        self.log_test("Edge switch count", expected_edge_switches, actual_edge_switches,
                     expected_edge_switches == actual_edge_switches)
        self.log_test("Total switch count", expected_total_switches, actual_total_switches,
                     expected_total_switches == actual_total_switches)
    
    # Test if node degrees match fat-tree specifications
    def test_node_degrees(self):
        print("\n=== Testing Node Degrees ===")
        
        # Count degrees for each node type
        host_degrees = [len(host.edges) for host in self.fattree.hosts]
        core_degrees = [len(switch.edges) for switch in self.fattree.core_switches]
        agg_degrees = [len(switch.edges) for switch in self.fattree.agg_switches]
        edge_degrees = [len(switch.edges) for switch in self.fattree.edge_switches]
        
        # Expected degrees
        expected_host_degree = 1 
        expected_core_degree = self.k  
        expected_agg_degree = self.k 
        expected_edge_degree = self.k  
        
        # Test host degrees
        unique_host_degrees = set(host_degrees)
        self.log_test("Host degree consistency", {expected_host_degree}, unique_host_degrees,
                     unique_host_degrees == {expected_host_degree})
        
        # Test core switch degrees
        unique_core_degrees = set(core_degrees)
        self.log_test("Core switch degree consistency", {expected_core_degree}, unique_core_degrees,
                     unique_core_degrees == {expected_core_degree})
        
        # Test aggregation switch degrees
        unique_agg_degrees = set(agg_degrees)
        self.log_test("Aggregation switch degree consistency", {expected_agg_degree}, unique_agg_degrees,
                     unique_agg_degrees == {expected_agg_degree})
        
        # Test edge switch degrees
        unique_edge_degrees = set(edge_degrees)
        self.log_test("Edge switch degree consistency", {expected_edge_degree}, unique_edge_degrees,
                     unique_edge_degrees == {expected_edge_degree})
    
    # Test if link counts match fat-tree specifications
    def test_link_counts(self):
        print("\n=== Testing Link Counts ===")
        
        # Count different types of links
        host_to_edge_links = 0
        edge_to_agg_links = 0
        agg_to_core_links = 0
        
        # Count host-to-edge links
        for host in self.fattree.hosts:
            for edge in host.edges:
                neighbor = edge.rnode if edge.lnode == host else edge.lnode
                if neighbor.type == "edge":
                    host_to_edge_links += 1
        
        # Count edge-to-aggregation links
        for edge_switch in self.fattree.edge_switches:
            for edge in edge_switch.edges:
                neighbor = edge.rnode if edge.lnode == edge_switch else edge.lnode
                if neighbor.type == "aggregation":
                    edge_to_agg_links += 1
        
        # Count aggregation-to-core links
        for agg_switch in self.fattree.agg_switches:
            for edge in agg_switch.edges:
                neighbor = edge.rnode if edge.lnode == agg_switch else edge.lnode
                if neighbor.type == "core":
                    agg_to_core_links += 1
        
        # Expected link counts
        expected_host_to_edge = (self.k ** 3) // 4 
        expected_edge_to_agg = (self.k ** 3) // 4   
        expected_agg_to_core = (self.k ** 3) // 4   
        
        self.log_test("Host-to-Edge links", expected_host_to_edge, host_to_edge_links,
                     expected_host_to_edge == host_to_edge_links)
        self.log_test("Edge-to-Aggregation links", expected_edge_to_agg, edge_to_agg_links,
                     expected_edge_to_agg == edge_to_agg_links)
        self.log_test("Aggregation-to-Core links", expected_agg_to_core, agg_to_core_links,
                     expected_agg_to_core == agg_to_core_links)
    
    # Test if pod structure is correct
    def test_pod_structure(self):
        print("\n=== Testing Pod Structure ===")
        
        expected_edge_per_pod = self.k // 2
        expected_agg_per_pod = self.k // 2
        expected_hosts_per_pod = (self.k ** 2) // 4
        
        # Count switches per pod
        pod_edge_count = {}
        pod_agg_count = {}
        pod_host_count = defaultdict(int)
        
        for switch in self.fattree.edge_switches:
            # Extract pod number from switch ID (format: e_p{pod}_s{switch})
            pod_num = int(switch.id.split('_')[1][1:])
            pod_edge_count[pod_num] = pod_edge_count.get(pod_num, 0) + 1
        
        for switch in self.fattree.agg_switches:
            # Extract pod number from switch ID (format: a_p{pod}_s{switch})
            pod_num = int(switch.id.split('_')[1][1:])
            pod_agg_count[pod_num] = pod_agg_count.get(pod_num, 0) + 1
        
        # Count hosts per pod by analyzing their IP addresses
        for host in self.fattree.hosts:
            pod_num = int(host.ip.split('.')[1])
            pod_host_count[pod_num] += 1
        
        # Test pod structure
        all_pods_correct_edges = all(count == expected_edge_per_pod for count in pod_edge_count.values())
        all_pods_correct_agg = all(count == expected_agg_per_pod for count in pod_agg_count.values())
        all_pods_correct_hosts = all(count == expected_hosts_per_pod for count in pod_host_count.values())
        
        self.log_test("Edge switches per pod", expected_edge_per_pod, 
                     f"varies: {set(pod_edge_count.values())}", all_pods_correct_edges)
        self.log_test("Aggregation switches per pod", expected_agg_per_pod,
                     f"varies: {set(pod_agg_count.values())}", all_pods_correct_agg)
        self.log_test("Hosts per pod", expected_hosts_per_pod,
                     f"varies: {set(pod_host_count.values())}", all_pods_correct_hosts)
        
        self.log_test("Number of pods", self.k, len(pod_edge_count), len(pod_edge_count) == self.k)
    
    # Test if IP and MAC addressing follows the correct scheme
    def test_addressing_scheme(self):
        print("\n=== Testing Addressing Scheme ===")
        
        ip_format_correct = True
        mac_format_correct = True
        unique_ips = set()
        unique_macs = set()
        
        for host in self.fattree.hosts:
            # Check IP format: 10.pod.switch.host_id
            ip_parts = host.ip.split('.')
            if len(ip_parts) != 4 or ip_parts[0] != '10':
                ip_format_correct = False
            
            # Check MAC format: 00:00:00:pod:switch:host_id
            mac_parts = host.mac.split(':')
            if len(mac_parts) != 6 or not all(len(part) == 2 for part in mac_parts):
                mac_format_correct = False
            
            unique_ips.add(host.ip)
            unique_macs.add(host.mac)
        
        expected_unique_count = len(self.fattree.hosts)
        
        self.log_test("IP format correctness", True, ip_format_correct, ip_format_correct)
        self.log_test("MAC format correctness", True, mac_format_correct, mac_format_correct)
        self.log_test("Unique IP addresses", expected_unique_count, len(unique_ips),
                     len(unique_ips) == expected_unique_count)
        self.log_test("Unique MAC addresses", expected_unique_count, len(unique_macs),
                     len(unique_macs) == expected_unique_count)
    
    # Test if DPID assignment is correct and unique
    def test_dpid_assignment(self):
        print("\n=== Testing DPID Assignment ===")
        
        all_dpids = []
        for switch in self.fattree.get_all_switches():
            all_dpids.append(switch.dpid)
        
        unique_dpids = set(all_dpids)
        expected_unique_count = len(self.fattree.get_all_switches())
        
        self.log_test("Unique DPID assignment", expected_unique_count, len(unique_dpids),
                     len(unique_dpids) == expected_unique_count)
        
        # Check if DPIDs are positive integers
        all_positive = all(dpid > 0 for dpid in all_dpids)
        self.log_test("DPID positive values", True, all_positive, all_positive)
    
    # Test if there are multiple paths between different pods (basic connectivity check)
    def test_connectivity_paths(self):
        print("\n=== Testing Basic Connectivity Properties ===")
        
        # Test: Each host should be reachable from its edge switch
        hosts_connected_to_edge = 0
        for host in self.fattree.hosts:
            for edge in host.edges:
                neighbor = edge.rnode if edge.lnode == host else edge.lnode
                if neighbor.type == "edge":
                    hosts_connected_to_edge += 1
                    break
        
        expected_connected = len(self.fattree.hosts)
        self.log_test("Hosts connected to edge switches", expected_connected, hosts_connected_to_edge,
                     hosts_connected_to_edge == expected_connected)
        
        # Test: Each edge switch should connect to all aggregation switches in its pod
        edge_to_agg_connections_correct = True
        for pod in range(self.k):
            pod_edge_switches = [s for s in self.fattree.edge_switches if f"_p{pod}_" in s.id]
            pod_agg_switches = [s for s in self.fattree.agg_switches if f"_p{pod}_" in s.id]
            
            for edge_switch in pod_edge_switches:
                connected_agg_switches = []
                for edge in edge_switch.edges:
                    neighbor = edge.rnode if edge.lnode == edge_switch else edge.lnode
                    if neighbor.type == "aggregation" and f"_p{pod}_" in neighbor.id:
                        connected_agg_switches.append(neighbor)
                
                if len(connected_agg_switches) != len(pod_agg_switches):
                    edge_to_agg_connections_correct = False
                    break
        
        self.log_test("Edge-to-Aggregation connectivity within pods", True, edge_to_agg_connections_correct,
                     edge_to_agg_connections_correct)
    
    # Run all test suites
    def run_all_tests(self):
        print(f"Testing Fat-Tree Topology with k={self.k}")
        print("=" * 50)
        
        self.test_node_counts()
        self.test_node_degrees()
        self.test_link_counts()
        self.test_pod_structure()
        self.test_addressing_scheme()
        self.test_dpid_assignment()
        self.test_connectivity_paths()
        
        # Summary
        print("\n" + "=" * 50)
        print("TEST SUMMARY")
        print("=" * 50)
        
        passed_tests = sum(1 for result in self.test_results if result['status'] == 'PASS')
        total_tests = len(self.test_results)
        
        print(f"Passed: {passed_tests}/{total_tests}")
        
        if passed_tests == total_tests:
            print("All tests PASSED! Fat-tree topology is correctly implemented.")
        else:
            print("Some tests FAILED. Please check the implementation.")
            print("\nFailed tests:")
            for result in self.test_results:
                if result['status'] == 'FAIL':
                    print(f"  - {result['test']}: Expected {result['expected']}, Got {result['actual']}")
        
        return passed_tests == total_tests

# Test multiple k values
def main():
    test_k_values = [4, 6, 8, 10]  # Test with different k values
    
    for k in test_k_values:
        print(f"\n{'='*60}")
        print(f"TESTING TOPOLOGY WITH K={k}")
        print(f"{'='*60}")
        
        try:
            validator = FattreeValidator(k)
            success = validator.run_all_tests()
            
            if not success:
                print(f"\n Tests failed for k={k}")
            else:
                print(f"\n All tests passed for k={k}")
                
        except Exception as e:
            print(f" Error testing k={k}: {str(e)}")
        
        print("\n")

if __name__ == '__main__':
    main()