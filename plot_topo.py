import networkx as nx
import matplotlib.pyplot as plt
from topo import Fattree

def plot_fattree(k):
    ft = Fattree(k)
    G = nx.Graph()

    for sw in ft.edge_switches:
        G.add_node(sw.id, layer=1, ftype='edge')
    
    for sw in ft.agg_switches:
        G.add_node(sw.id, layer=2, ftype='agg')
    
    for sw in ft.core_switches:
        G.add_node(sw.id, layer=3, ftype='core')

    for h in ft.hosts:
        G.add_node(h.id, layer=0, ftype='host')

    seen = set()
    all_nodes = ft.core_switches + ft.agg_switches + ft.edge_switches + ft.hosts
    
    for node in all_nodes:
        for edge in node.edges:
            edge_id = tuple(sorted([edge.lnode.id, edge.rnode.id]))
            if edge_id in seen:
                continue
            seen.add(edge_id)
            u = edge.lnode.id
            v = edge.rnode.id
            G.add_edge(u, v)

    pos = nx.multipartite_layout(G, subset_key="layer")

    plt.figure(figsize=(12, 8))
    node_colors = []
    node_sizes = []
    for n, data in G.nodes(data=True):
        t = data['ftype']
        if t == 'host':
            node_colors.append('green')
            node_sizes.append(200)
        elif t == 'edge':
            node_colors.append('blue')
            node_sizes.append(400)
        elif t == 'agg':
            node_colors.append('orange')
            node_sizes.append(400)
        else:  # core
            node_colors.append('red')
            node_sizes.append(400)

    nx.draw(
        G,
        pos,
        with_labels=True,
        labels={n: n for n in G.nodes()},
        node_color=node_colors,
        node_size=node_sizes,
        font_size=6,
        font_color='black',
        linewidths=0.5,
        edge_color='gray'
    )

    plt.title(f"Fat-tree (k={k})", fontsize=14)
    plt.axis('off')

    filename = f'fattree_k{k}.jpg'
    plt.savefig(filename, format='jpg', dpi=300, bbox_inches='tight')
    print(f"Saved plot as {filename}")
    plt.close()

# Plot fat-tree topologies for multiple k values
def plot_multiple_k_values(k_values):
    for k in k_values:
        if k % 2 != 0:
            print(f"Skipping k={k} (must be even)")
            continue
        print(f"Plotting fat-tree for k={k}...")
        plot_fattree(k)

if __name__ == "__main__":
    # Plot for different k values
    k_values = [4, 6, 8, 10]
    plot_multiple_k_values(k_values)