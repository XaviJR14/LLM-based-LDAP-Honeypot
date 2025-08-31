#!/usr/bin/env python3
import socket

DEST_IP   = "127.0.0.1"
DEST_PORT = 389

# LDAP operation templates (hex → bytes)
LDAP_BIND = bytes.fromhex("300c020101600702010304008000")
LDAP_SEARCH = bytes.fromhex("3060020103635b040c636e3d537562736368656d610a01000a0103020100020100010100a318040b6f626a656374436c6173730409737562736368656d613022040f63726561746554696d657374616d70040f6d6f6469667954696d657374616d70")
LDAP_UNBIND = bytes.fromhex("30050201034200")

def recv_full_search_responses(sock, idle_timeout: float = 3600.0):
    """
    Receive all LDAP SearchResponse packets until we go `idle_timeout`
    seconds with no new data. Returns a list of complete BER blobs.
    """
    # switch the socket to non-blocking with timeout
    sock.settimeout(idle_timeout)

    buffer = b''
    messages = []

    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                # connection closed by server
                break
            buffer += chunk

            # try to extract complete BER messages
            offset = 0
            while True:
                # need at least 2 bytes for tag+len
                if offset + 2 > len(buffer):
                    break

                tag = buffer[offset]
                length_byte = buffer[offset + 1]

                # short form length
                if (length_byte & 0x80) == 0:
                    length = length_byte
                    header_len = 2
                else:
                    # long form
                    num_len_bytes = length_byte & 0x7F
                    if offset + 2 + num_len_bytes > len(buffer):
                        break
                    length = int.from_bytes(
                        buffer[offset+2 : offset+2+num_len_bytes], 'big'
                    )
                    header_len = 2 + num_len_bytes

                total_len = header_len + length
                if offset + total_len > len(buffer):
                    break

                # we have a full message
                msg = buffer[offset : offset + total_len]
                messages.append(msg)
                offset += total_len

            # discard parsed bytes
            buffer = buffer[offset:]

        except socket.timeout:
            # no data arrived for idle_timeout seconds → assume done
            break

        except Exception as e:
            print(f"[!] Error while receiving or parsing: {e}")
            break

    return messages

def send_ldap_via_socket():
    """
    Connect to a local LDAP listener and send a sequence of LDAP operations:
    BindRequest, SearchRequest, and UnbindRequest.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((DEST_IP, DEST_PORT))
    print(f"[+] Connected to {DEST_IP}:{DEST_PORT}")

    # 1) Send BindRequest
    print(f"[>] Sending BindRequest ({len(LDAP_BIND)} bytes)")
    sock.sendall(LDAP_BIND)
    response = sock.recv(4096)
    print(f"[<] Received {len(response)} bytes (hex): {response.hex()}")

    # 2 ) Send SearchRequest
    print(f"[>] Sending SearchRequest ({len(LDAP_SEARCH)} bytes)")
    sock.sendall(LDAP_SEARCH)
    search_messages = recv_full_search_responses(sock, idle_timeout=3600.0)
    for i, msg in enumerate(search_messages, 1):
        print(f"[<] SearchResponse #{i}: {msg.hex()}")

    # 3) Send UnbindRequest
    print(f"[>] Sending UnbindRequest ({len(LDAP_UNBIND)} bytes)")
    sock.sendall(LDAP_UNBIND)
    # No esperamos respuesta a unbind: el servidor debe cerrar
    sock.close()
    print("[+] Connection closed after UnbindRequest")

if __name__ == "__main__":
    send_ldap_via_socket()
