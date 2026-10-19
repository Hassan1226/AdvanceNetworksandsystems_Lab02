#!/usr/bin/env python3
import sys
import matplotlib.pyplot as plt
import numpy as np


# Plot and save a latency comparison between Shortest-Path and Two-Level routing
def create_latency_plot(sp_rtt, tl_rtt):
    """
    sp_rtt is a list of 3 average RTT values for Shortest-Path
    tl_rtt is a list of 3 average RTT values for Two-Level
    """
    labels = ['Local Pair', 'Intra-Pod', 'Inter-Pod']
    x = np.arange(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(12, 7))
    ax.bar(x - width / 2, sp_rtt, width, label='Shortest-Path')
    ax.bar(x + width / 2, tl_rtt, width, label='Two-Level')
    ax.set_ylabel('Average RTT (ms)')
    ax.set_title('Latency Comparison of Routing Schemes')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    fig.tight_layout()
    plt.savefig('routing_latency_comparison.png', dpi=300)
    plt.close(fig)


# Plot and save a grouped bar chart comparing the throughput of Shortest-Path and Two-Level routing
def create_throughput_plot(sp_results, tl_results):
    """
    sp_results is a list of 3 throughput values for Shortest-Path
    tl_results is a list of 3 throughput values for Two-Level
    """
    labels = [
        'Single Flow\n(Baseline)',
        'Parallel Cross-Pod\n(Traffic)',
        'Parallel Local-Pod\n(Traffic)'
    ]

    x = np.arange(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(12, 7))

    rects1 = ax.bar(
        x - width / 2, sp_results, width,
        label='Shortest-Path', alpha=0.9
    )
    rects2 = ax.bar(
        x + width / 2, tl_results, width,
        label='Two-Level', alpha=0.9
    )

    ax.set_ylabel('Aggregate Throughput (Mbps)', fontsize=12)
    ax.set_title('Throughput Comparison of Routing Schemes', fontsize=16, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=11)
    ax.legend(fontsize=11)

    max_throughput = max(max(sp_results), max(tl_results))
    ax.set_ylim(0, max_throughput * 1.25)

    ax.bar_label(rects1, padding=3, fmt='%.1f')
    ax.bar_label(rects2, padding=3, fmt='%.1f')

    ax.yaxis.grid(True, linestyle='--', which='major', alpha=0.5)

    fig.tight_layout()

    output_filename = 'routing_throughput_comparison.png'
    try:
        plt.savefig(output_filename, dpi=300)
        print(f"Plot saved successfully as '{output_filename}'")
    except Exception as e:
        print(f"Error saving throughput plot: {e}")
    finally:
        plt.close(fig)


def parse_args(argv):
    """
    The command-line used to plot our results:
        python3 plot_results.py 11.9 11.9 14.01 52.2 50.3 54.6 133.765 133.303 164.511 154.070 186.581 187.085
    """
    if len(argv) != 13:
        print("\nError: Incorrect number of arguments.")
        print(
            "Usage: python3 plot_results.py "
            "sp_single tl_single sp_parallel_best tl_parallel_best sp_parallel_worst tl_parallel_worst "
            "sp_single_rtt tl_single_rtt sp_parallel_best_rtt tl_parallel_best_rtt sp_parallel_worst_rtt tl_parallel_worst_rtt"
        )
        sys.exit(1)

    try:
        values = [float(arg) for arg in argv[1:]]
    except ValueError:
        print("\nError: All arguments must be numbers.")
        sys.exit(1)

    sp_throughput = [values[0], values[2], values[4]]
    tl_throughput = [values[1], values[3], values[5]]

    sp_rtt = [values[6], values[8], values[10]]
    tl_rtt = [values[7], values[9], values[11]]

    return sp_throughput, tl_throughput, sp_rtt, tl_rtt


def main():
    sp_throughput, tl_throughput, sp_rtt, tl_rtt = parse_args(sys.argv)

    create_throughput_plot(sp_throughput, tl_throughput)
    create_latency_plot(sp_rtt, tl_rtt)


if __name__ == '__main__':
    main()
