import argparse
from collections import defaultdict
from scapy.all import rdpcap, Raw
from scapy.layers.l2 import Dot1Q
import matplotlib.pyplot as plt
import numpy as np
import hashlib

# Default values
DEFAULT_PCAP = "F1.pcapng"

GOOSE_ETHERTYPE = 0x88B8

def get_stNum(payload):
    """
    Parses the GOOSE PDU to find the stNum (Tag 0x85).
    GOOSE uses ASN.1 BER encoding.
    """
    try:
        # stNum is typically encoded as Tag 0x85
        tag_idx = payload.find(b'\x85')
        if tag_idx != -1:
            length = payload[tag_idx + 1]
            value_bytes = payload[tag_idx + 2 : tag_idx + 2 + length]
            return int.from_bytes(value_bytes, byteorder='big')
    except Exception:
        return None
    return None

parser = argparse.ArgumentParser(description="Plot GOOSE occurrences with stNum change highlights.")
parser.add_argument("-p", "--pcap", default=DEFAULT_PCAP, help="PCAP file path")
parser.add_argument("-o", "--output", default="goose_block_timeplot.png", help="Output plot filename")
parser.add_argument("--bin-size", type=float, default=1.0, help="Time bin size in seconds")
args = parser.parse_args()

print(f"Loading PCAP: {args.pcap}")
packets = rdpcap(args.pcap)

block_times = defaultdict(list)
state_change_times = defaultdict(list)
last_stNum = {}
seen_hashes = set()

total_packets = len(packets)
non_vlan_count = 0
non_goose_vlan_count = 0
duplicate_count = 0
processed_count = 0

for pkt in packets:

    # 2. VLAN/GOOSE filtering
    if not pkt.haslayer(Dot1Q):
        non_vlan_count += 1
        continue

    dot1q = pkt[Dot1Q]
    if dot1q.type != GOOSE_ETHERTYPE:
        non_goose_vlan_count += 1
        continue

    # 3. Payload processing
    raw_payload = bytes(dot1q.payload)
    if len(raw_payload) < 2:
        continue

    # Extract block tag (first 2 bytes)
    block_tag = raw_payload[:2].hex()
    pkt_time = float(pkt.time)
    
    block_times[block_tag].append(pkt_time)
    
    # 4. Check for stNum changes
    current_st = get_stNum(raw_payload)
    if current_st is not None:
        if block_tag in last_stNum and current_st != last_stNum[block_tag]:
            # This packet marks a transition in state
            state_change_times[block_tag].append(pkt_time)
        last_stNum[block_tag] = current_st

    processed_count += 1

if not block_times:
    print("No VLAN-tagged GOOSE blocks found.")
    raise SystemExit(1)

# Timing normalization
all_times = [t for times in block_times.values() for t in times]
start = min(all_times)
end = max(all_times)
relative_block_times = {tag: [t - start for t in times] for tag, times in block_times.items()}

bins = np.arange(0, (end - start) + args.bin_size, args.bin_size)

# Stats Printing
print("\nPacket statistics:")
print(f"  Total packets: {total_packets}")
print(f"  Processed VLAN-tagged GOOSE: {processed_count}")
print(f"  Duplicates ignored: {duplicate_count}")

# Plotting
sorted_tags = sorted(relative_block_times.keys(), key=lambda x: int(x, 16))
n_blocks = len(sorted_tags)
fig, axes = plt.subplots(n_blocks, 1, sharex=True, figsize=(12, max(4, 2.5 * n_blocks)))
if n_blocks == 1:
    axes = [axes]

# Compute common Y limit
max_count = 0
all_counts = {}
for tag in sorted_tags:
    counts, edges = np.histogram(relative_block_times[tag], bins=bins)
    all_counts[tag] = (counts, edges)
    if counts.max() > max_count:
        max_count = int(counts.max())

for ax, tag in zip(axes, sorted_tags):
    counts, edges = all_counts[tag]
    ax.step(edges[:-1], counts, where="post", color="tab:blue", label="Packet Count")
    
    # Highlight stNum changes with vertical red lines
    #if tag in state_change_times:
     #   for i, change_t in enumerate(state_change_times[tag]):
      #      label = "stNum Change" if i == 0 else ""
       #     ax.axvline(x=change_t - start, color='red', linestyle='--', alpha=0.7, label=label)
    
    ax.set_ylabel(f"Block {tag}\ncount")
    ax.grid(True, alpha=0.3)
    ax.set_xlim(0, bins[-1])
    ax.set_ylim(0, max_count + 1)
    if tag in state_change_times:
        ax.legend(loc='upper right', fontsize='small')

axes[-1].set_xlabel("Time since first packet (seconds)")
fig.suptitle("GOOSE Block Traffic with State Change (stNum) Highlights", fontsize=14)
plt.tight_layout(rect=[0, 0, 1, 0.96])
plt.savefig(args.output, dpi=300)
print(f"\nSaved time plot to {args.output}")
plt.show()