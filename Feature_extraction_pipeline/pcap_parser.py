import sys
import pyshark
import pandas as pd

# ---------- per-packet extractors ----------

def vlan_pcp_from_raw(raw_hex: str):
    """
    Extract 802.1Q PCP from raw bytes.
    Looks for TPID 0x8100 then reads TCI (2 bytes).
    PCP = (TCI >> 13) & 0x7
    """
    if not isinstance(raw_hex, str) or len(raw_hex) < 32:
        return None

    s = raw_hex.lower()
    idx = s.find("8100")
    if idx == -1:
        return None

    tci_start = idx + 4
    tci_end = tci_start + 4
    if tci_end > len(s):
        return None

    try:
        tci = int(s[tci_start:tci_end], 16)
    except ValueError:
        return None

    return int((tci >> 13) & 0x7)

def extract_goose_fields(pkt):
    """Grab parsed GOOSE fields (camelCase preserved) plus timing/MACs."""
    if not hasattr(pkt, "goose"):
        return None

    g = pkt.goose
    ether = pkt.eth
    frame = getattr(pkt, "frame_info", None)

    row = {
        "gocbRef": getattr(g, "gocbRef", None),
        "timeAllowedtoLive": int(getattr(g, "timeAllowedtoLive", 0) or 0),
        "datSet": getattr(g, "datSet", None),
        "goID": getattr(g, "goID", None),
        "t": str(getattr(g, "t", None)),
        "stNum": int(getattr(g, "stNum", 0) or 0),
        "sqNum": int(getattr(g, "sqNum", 0) or 0),
        "simulation": (getattr(g, "simulation", None) == "True"),
        "confRev": int(getattr(g, "confRev", 0) or 0),
        "ndsCom": (getattr(g, "ndsCom", None) == "True"),
        "numDatSetEntries": int(getattr(g, "numDatSetEntries", 0) or 0),
        "Source": getattr(ether, "src", None),
        "Destination": getattr(ether, "dst", None),
        "Length": int(getattr(pkt, "length", 0) or 0),
        "EpochArrivalTime": pkt.sniff_time.timestamp(),
    }
    return row

def extract_raw_bytes(pkt):
    """Return full frame bytes as hex string."""
    try:
        data = pkt.get_raw_packet()
        return data.hex() if data else None
    except Exception:
        return None

# ---------- main conversion ----------

def pcapng_to_json(pcapng_file):
    rows = []

    # A: parsed GOOSE fields
    cap_fields = pyshark.FileCapture(
        pcapng_file,
        display_filter="goose",
        keep_packets=False
    )

    # B: raw bytes (JSON backend required when include_raw=True)
    cap_raw = pyshark.FileCapture(
        pcapng_file,
        include_raw=True,
        use_json=True,
        display_filter="goose",
        keep_packets=False
    )

    for pkt_fields, pkt_raw in zip(cap_fields, cap_raw):
        row = extract_goose_fields(pkt_fields)
        if row is None:
            continue
        row["raw_bytes"] = extract_raw_bytes(pkt_raw)
        rows.append(row)

    

    cap_fields.close()
    cap_raw.close()

    df = pd.DataFrame(rows)

    # Ensure EpochArrivalTime exists
    df["EpochArrivalTime"] = df["EpochArrivalTime"]
    
    def get_time_interval(df):
        time_interval = [0.0]
        for i in range(1, len(df)):
            dt = df["EpochArrivalTime"][i]-df["EpochArrivalTime"][i-1]
            time_interval.append(dt)
        return time_interval

    df["timeInterval"] = get_time_interval(df)

    if "vlan_pcp" not in df.columns:
        if "raw_bytes" not in df.columns:
            raise RuntimeError("Need raw_bytes to extract VLAN PCP (or precompute vlan_pcp in xlsx).")
        df["vlan_pcp"] = df["raw_bytes"].apply(vlan_pcp_from_raw)

    # malicious packets
    ids = list(df[df["vlan_pcp"] == 0].index)
    
    labels = [True if i in ids else False for i in range(len(df.index))]
    df = df.assign(label=labels)

    # Save to Excel
    output_file = sys.argv[2]
    df.to_excel(output_file, index=False)

# ---------- run ----------

pcapng_file = str(sys.argv[1])
pcapng_to_json(pcapng_file)
