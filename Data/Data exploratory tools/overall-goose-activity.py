import argparse
import struct
from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np
from scapy.all import rdpcap
from scapy.layers.l2 import Dot1Q

# Default values
DEFAULT_PCAP = "Z2.pcapng"
GOOSE_ETHERTYPE = 0x88B8


# -----------------------------
# GOOSE ASN.1 SIMPLE PARSING
# -----------------------------

def parse_goose_fields(goose_pdu: bytes):
    """
    Lightweight extractor for key GOOSE fields:
    - gocbRef (0x80)
    - datSet  (0x82)
    - goID    (0x83)
    - stNum   (0x85)
    - sqNum   (0x86)

    NOTE: This is a simplified parser, not a full ASN.1 decoder.
    """
    fields = {}

    if len(goose_pdu) < 10:
        return fields

    try:
        # skip ethernet + vlan assumption handled outside
        if goose_pdu[9] <= 127:
            i = 10
        elif goose_pdu[9] == 0x81:
            i = 11
        elif goose_pdu[9] == 0x82:
            i = 12
        else:
            return fields

        while i < len(goose_pdu):
            if i + 1 >= len(goose_pdu):
                break

            tag = goose_pdu[i]
            length = goose_pdu[i + 1]

            if length <= 127:
                header_len = 2
                data_len = length
            else:
                num_len_bytes = length & 0x7F
                data_len = int.from_bytes(goose_pdu[i+2:i+2+num_len_bytes], 'big')
                header_len = 2 + num_len_bytes

            start = i + header_len
            end = start + data_len

            if end > len(goose_pdu):
                break

            value = goose_pdu[start:end]

            # decode only integer fields
            if tag in (0x85, 0x86):
                fields[tag] = int.from_bytes(value, 'big')
            # decode ASCII-like fields
            elif tag in (0x80, 0x82, 0x83):
                try:
                    fields[tag] = value.decode(errors='ignore')
                except:
                    fields[tag] = str(value)

            i += header_len + data_len

    except Exception as e:
        print(f"GOOSE parse error: {e}")

    return fields


def extract_appid(goose_payload: bytes):
    if len(goose_payload) < 2:
        return None
    try:
        return struct.unpack("!H", goose_payload[:2])[0]
    except:
        return None


# -----------------------------
# MAIN
# -----------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pcap", default=DEFAULT_PCAP)
    parser.add_argument("-o", "--output", default="goose_plot.png")
    parser.add_argument("--bin-size", type=float, default=1.0)
    args = parser.parse_args()

    packets = rdpcap(args.pcap)
    packets = sorted(packets, key=lambda x: float(x.time))

    prio_config = {
        0: {"color": "blue", "label": "Priority 0"},
        4: {"color": "green", "label": "Priority 4"},
        7: {"color": "red", "label": "Priority 7"},
    }

    priority_map = defaultdict(list)

    # state tracking
    last_state = {}
    state_events = []

    for pkt in packets:
        if not pkt.haslayer(Dot1Q):
            continue

        dot1q = pkt[Dot1Q]
        if dot1q.type != GOOSE_ETHERTYPE:
            continue

        prio = dot1q.prio
        if prio not in prio_config:
            continue

        t = float(pkt.time)
        priority_map[prio].append(t)

        if prio != 4:
            continue

        goose_payload = bytes(dot1q.payload)
        fields = parse_goose_fields(goose_payload)

        appid = extract_appid(goose_payload)
        stNum = fields.get(0x85)
        sqNum = fields.get(0x86)

        if appid is None or stNum is None:
            continue

        if appid not in last_state:
            last_state[appid] = stNum
            continue

        if stNum != last_state[appid]:

            event = {
                "time": t,
                "appid": appid,
                "gocbRef": fields.get(0x80),
                "datSet": fields.get(0x82),
                "goID": fields.get(0x83),
                "stNum": stNum,
                "prev_stNum": last_state[appid],
                "sqNum": sqNum,
            }

            state_events.append(event)
            last_state[appid] = stNum

    # -----------------------------
    # PLOTTING
    # -----------------------------

    all_times = [t for v in priority_map.values() for t in v]
    start = min(all_times)
    end = max(all_times)

    bins = np.arange(0, (end - start) + args.bin_size, args.bin_size)

    plt.figure(figsize=(12, 7))

    for p in sorted(priority_map.keys()):
        times = [t - start for t in priority_map[p]]
        counts, edges = np.histogram(times, bins=bins)

        plt.step(
            edges[:-1], counts,
            where="post",
            label=prio_config[p]["label"],
            color=prio_config[p]["color"]
        )

    # state changes
    if state_events:
        sc_times = [e["time"] - start for e in state_events]
        counts_sc, edges_sc = np.histogram(sc_times, bins=bins)

        plt.step(
            edges_sc[:-1], counts_sc,
            where="post",
            linestyle="--",
            color="black",
            label="GOOSE State Changes"
        )

    plt.title("GOOSE Analysis (Priorities + State Changes) NEW")
    plt.xlabel("Time (s)")
    plt.ylabel("Packets per bin")
    plt.legend()
    plt.grid(True, linestyle=":", alpha=0.5)

    plt.tight_layout()
    plt.savefig(args.output, dpi=300)
    plt.show()

    # -----------------------------
    # PRINT EVENT DETAILS
    # -----------------------------

    print("\nSTATE CHANGE DETAILS:\n")
    for e in state_events:
        print(f"Time: {e['time']:.3f}s")
        print(f"  APPID: {e['appid']}")
        print(f"  goID: {e.get('goID')}")
        print(f"  gocbRef: {e.get('gocbRef')}")
        print(f"  datSet: {e.get('datSet')}")
        print(f"  stNum: {e['prev_stNum']} -> {e['stNum']}")
        print(f"  sqNum: {e.get('sqNum')}")
        print("---")


if __name__ == "__main__":
    main()
