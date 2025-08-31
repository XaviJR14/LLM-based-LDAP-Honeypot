from scapy.all import Ether, IP, TCP
from pyasn1.codec.ber.decoder import decode as ber_decode
from pyasn1.codec.ber.encoder import encode as ber_encode
from pyasn1.codec.native import encoder as native_encoder
from pyasn1.codec.native import decoder as native_decoder
from pyasn1_ldap import rfc4511
from collections import OrderedDict
from ldap_colab_client import send_ldap_to_colab
import argparse
import json
import csv
import os
from datetime import datetime, timezone

def asn1_to_plain(obj):
    """
    Recursively convert ASN.1 native objects into plain Python types.
    """
    if isinstance(obj, (OrderedDict, dict)):
        return {k: asn1_to_plain(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [asn1_to_plain(x) for x in obj]
    if isinstance(obj, bytes):
        try:
            return obj.decode('utf-8')
        except UnicodeDecodeError:
            return obj.hex()
    return obj


def plain_to_ordered(data):
    """
    Recursively convert plain dict/list to OrderedDict for ASN.1 decoding.
    """
    if isinstance(data, dict):
        return OrderedDict((k, plain_to_ordered(v)) for k, v in data.items())
    if isinstance(data, list):
        return [plain_to_ordered(x) for x in data]
    return data


def parse_ldap_request(hex_stream: str):
    """
    Decode a LDAP hexstream into LDAPMessage.
    Returns decoded LDAPMessage ASN.1 object.
    """
    ldap_bytes = bytes.fromhex(hex_stream)
    ldap_request_msg, _ = ber_decode(ldap_bytes, asn1Spec=rfc4511.LDAPMessage())
    return ldap_request_msg


def build_ldap_response_from_json(response_json: str):
    """
    Build an LDAPMessage ASN.1 object from a JSON template.
    """
    template = json.loads(response_json)
    ordered = plain_to_ordered(template)
    ldap_response_msg = native_decoder.decode(ordered, asn1Spec=rfc4511.LDAPMessage())
    return ldap_response_msg


def send_request_to_llm(ldap_request_msg):
    """
    Send the parsed LDAP request to the LLM via Colab.
    """
    native_request = native_encoder.encode(ldap_request_msg)
    plain_request = asn1_to_plain(native_request)
    ldap_request_json = json.dumps(plain_request, indent=2, ensure_ascii=False)
    print(f"[#] JSON representation of request: {ldap_request_json}")

    llm_responses = send_ldap_to_colab(ldap_request_json)

    return ldap_request_json, llm_responses

def append_ldap_log(request_json: str, responses_json: list[str], client_ip: str, log_path: str = "logs.csv"):
    """
    Append one row to a CSV log with timestamp (UTC), client IP,
    request JSON (pretty), and all response JSONs grouped as a pretty JSON array.
    """
    headers = ["timestamp", "client_ip", "request_json", "responses_json"]
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Convert each response string to a Python object (if possible),
    # then dump the whole list as pretty JSON so it doesn't have escaped \n or \"
    response_objects = []
    for r in responses_json:
        if isinstance(r, str):
            try:
                response_objects.append(json.loads(r))
            except json.JSONDecodeError:
                # Fallback if r is not valid JSON: keep raw string
                response_objects.append(r)
        else:
            response_objects.append(r)

    responses_str = json.dumps(response_objects, ensure_ascii=False, indent=2)

    file_exists = os.path.exists(log_path)
    with open(log_path, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        if not file_exists:
            writer.writerow(headers)
        writer.writerow([timestamp, client_ip or "", request_json, responses_str])
        f.flush()
        os.fsync(f.fileno())

def main(request_hex: str, client_ip=None):
    """
    Parse LDAP request hexstream, send to LLM, and return response hexstream.
    """
    ldap_responses: list[str] = []

    # Parse request
    ldap_request_msg = parse_ldap_request(request_hex)
    print(f"[#] LDAP request ASN.1 object: {ldap_request_msg}")

    ldap_request_json, llm_responses = send_request_to_llm(ldap_request_msg)  # Send Request to LLM on Colab

    for ldap_response_msg in llm_responses:
        # Build response ASN.1
        ldap_response = build_ldap_response_from_json(ldap_response_msg)
        print(f"[#] LDAP response ASN.1 object: {ldap_response}")

        # Encode LDAP response
        ber_bytes = ber_encode(ldap_response)
        ldap_response_msg_hex = ber_bytes.hex()

        ldap_responses.append(ldap_response_msg_hex)

    # Log interaction
    append_ldap_log(request_json=ldap_request_json,responses_json=llm_responses,client_ip=client_ip or "")

    return ldap_responses


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Process an LDAP packet hexstream and generate a bind response.")
    parser.add_argument('hexstream', nargs='?', help='Raw packet hexstream to parse')
    args = parser.parse_args()

    if args.hexstream:
        response_hex = main(args.hexstream)
        print("Hexstream Response:", response_hex)
    else:
        print("Please provide a packet hexstream. For testing, you can uncomment the sample in the script.")
