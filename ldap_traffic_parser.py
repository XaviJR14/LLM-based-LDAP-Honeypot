import os
import json
import csv
from collections import OrderedDict
import pandas as pd
from scapy.all import Ether, TCP, raw, rdpcap
from pyasn1.codec.ber.decoder import decode as ber_decode
from pyasn1.codec.native import encoder as native_encoder
from pyasn1_ldap import rfc4511


def asn1_to_plain(obj):
    """
    Recursively convert ASN.1 native objects into plain Python types (dicts, lists, strings)."""
    if isinstance(obj, OrderedDict) or isinstance(obj, dict):
        return {k: asn1_to_plain(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [asn1_to_plain(item) for item in obj]
    if isinstance(obj, bytes):
        try:
            return obj.decode('utf-8')
        except UnicodeDecodeError:
            return obj.hex()
    return obj


def parse_ldap_from_hex(hex_stream: str):
    """
    Decode a raw Ethernet/TCP packet hex stream into an LDAPMessage ASN.1 object.
    Returns None for empty or non-LDAP payloads."""
    packet = Ether(bytes.fromhex(hex_stream))
    ldap_data = raw(packet[TCP].payload)

    # Ignore empty binds or keep-alive messages
    if ldap_data.hex() == "30050201034200":
        return None

    ldap_msg, _ = ber_decode(ldap_data, asn1Spec=rfc4511.LDAPMessage())
    return ldap_msg


def convert_ldap_to_json(ldap_msg) -> (int, str):
    """
    Convert an LDAPMessage ASN.1 object to a tuple of (messageID, JSON string)."""
    native = native_encoder.encode(ldap_msg)
    plain = asn1_to_plain(native)
    msg_id = plain.get('messageID')
    json_str = json.dumps(plain, indent=2, ensure_ascii=False)
    return msg_id, json_str


def split_ldap_packets(packets):
    """
    Separate packets into inbound (to port 389) and outbound (from port 389) LDAP packets."""
    inbound, outbound = [], []
    for pkt in packets:
        if pkt.haslayer(TCP) and (pkt[TCP].flags & 0x18) == 0x18:
            payload = bytes(pkt[TCP].payload)
            if payload and payload[0] == 0x30:
                if pkt[TCP].dport == 389:
                    inbound.append(pkt)
                elif pkt[TCP].sport == 389:
                    outbound.append(pkt)
    return inbound, outbound


def process_ldap_packets(pcap_path: str):
    """
    Load PCAP, filter LDAP packets, parse requests and responses,
    and map them by messageID.
    Returns two dicts: inbound_dict and outbound_dict."""
    packets = rdpcap(pcap_path)
    inbound_pkts, outbound_pkts = split_ldap_packets(packets)

    inbound_dict = {}
    outbound_dict = {}

    for pkt in inbound_pkts:
        hex_stream = bytes(pkt).hex()
        ldap_req = parse_ldap_from_hex(hex_stream)
        if ldap_req:
            msg_id, json_str = convert_ldap_to_json(ldap_req)
            inbound_dict.setdefault(msg_id, []).append(json_str)

    for pkt in outbound_pkts:
        hex_stream = bytes(pkt).hex()
        ldap_resp = parse_ldap_from_hex(hex_stream)
        if ldap_resp:
            msg_id, json_str = convert_ldap_to_json(ldap_resp)
            outbound_dict.setdefault(msg_id, []).append(json_str)

    return inbound_dict, outbound_dict


def _pretty_json_or_raw(s: str) -> str:
    """Try to pretty-print a JSON string; if it isn't valid JSON, return raw."""
    try:
        obj = json.loads(s)
        return json.dumps(obj, indent=2, ensure_ascii=False)
    except (json.JSONDecodeError, TypeError):
        return s if isinstance(s, str) else "{}"

def create_dataframe(inbound: dict, outbound: dict) -> pd.DataFrame:
    """
    Build a pandas DataFrame with one row per message,
    columns 'input' and 'output' (pretty-printed, concatenated), without including messageID.

    - `inbound[msg_id]` can be either a string (legacy) or a list[str] (nuevo comportamiento).
    - `outbound[msg_id]` se asume list[str].
    """
    rows = []
    for msg_id, responses in outbound.items():

        # --- INPUT / REQUESTS ---
        raw_req = inbound.get(msg_id, None)

        # Normaliza a lista de strings
        if isinstance(raw_req, list):
            req_list = raw_req
        elif isinstance(raw_req, str):
            req_list = [raw_req]
        elif raw_req is None:
            req_list = []
        else:
            # Cualquier otro tipo inesperado
            req_list = [str(raw_req)]

        # Pretty-print de cada request y concatenación
        pretty_reqs = [_pretty_json_or_raw(x) for x in req_list] or ["{}"]
        pretty_req_concat = "\n---\n".join(pretty_reqs)

        # --- OUTPUT / RESPONSES ---
        pretty_resps = []
        for r in (responses or []):
            pretty_resps.append(_pretty_json_or_raw(r))
        concatenated_resps = "\n".join(prety for prety in pretty_resps)

        rows.append({
            "input": pretty_req_concat,
            "output": concatenated_resps
        })

    return pd.DataFrame(rows)


def write_csv(df: pd.DataFrame, output_path: str):
    """
    Export DataFrame to a CSV file with UTF-8 encoding and quoted fields."""
    df.to_csv(output_path, index=False, encoding='utf-8', quoting=csv.QUOTE_ALL)


def combine_csvs(directory: str, combined_filename: str = 'combined.csv'):
    """
    Combine all CSV files in `directory` into a single CSV named `combined_filename`.
    Preserves header from the first file."""
    csv_paths = [os.path.join(directory, f) for f in os.listdir(directory)
                 if f.lower().endswith('.csv')]
    if not csv_paths:
        print("No CSV files found to combine.")
        return

    # Read and concatenate
    df_list = []
    for path in csv_paths:
        df = pd.read_csv(path, quotechar='"')
        df_list.append(df)

    combined = pd.concat(df_list, ignore_index=True)
    combined_path = os.path.join(directory, combined_filename)
    combined.to_csv(combined_path, index=False, encoding='utf-8', quoting=csv.QUOTE_ALL)
    print(f"Combined {len(csv_paths)} files into '{combined_filename}'.")


def process_directory(input_dir: str, output_dir: str):
    """
    Process all PCAP files in input_dir, generating corresponding CSVs in output_dir,
    then combine those CSVs into one file in the output_dir."""
    os.makedirs(output_dir, exist_ok=True)
    for filename in os.listdir(input_dir):
        if not filename.lower().endswith(('.pcap', '.pcapng','.cap')):
            continue

        pcap_path = os.path.join(input_dir, filename)
        inbound, outbound = process_ldap_packets(pcap_path)
        df = create_dataframe(inbound, outbound)

        base, _ = os.path.splitext(filename)
        csv_name = f"{base}.csv"
        output_path = os.path.join(output_dir, csv_name)
        write_csv(df, output_path)
        print(f"Exported {len(df)} transactions from '{filename}' to '{csv_name}'.")

    # After individual CSVs are written, combine them
    combine_csvs(output_dir, combined_filename='combined.csv')


def main():
    """
    Entry point: parse command-line args for input/output directories and process all PCAPs."""

    process_directory('..\\Wireshark\\Input_eval', '..\\Wireshark\\Output_eval')

if __name__ == '__main__':
    main()
