#!/usr/bin/env python3
import socketserver
import socket
from ldap_parser_and_responder import main as parse_ldap_payload

LISTEN_HOST = "127.0.0.1" # IP to listen on
LISTEN_PORT = 389  # Port to listen on


class LDAPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        """
        Handle incoming LDAP requests from clients.
        Parses the payload and sends one or more responses based on LLM output.
        """
        client = self.request
        client_address = self.client_address
        print(f"[*] Listener: Incoming connection from {client_address}")

        client.settimeout(2.0) # Avoid blocking recv() indefinitely

        try:
            while True:
                data = client.recv(65535)
                if not data:
                    print("[*] Listener: Client closed the connection") # Client closed the connection
                    break

                hex_payload = data.hex()

                if hex_payload == "30050201034200": # Unbind Operation (no response)
                    continue

                client_ip = client_address[0]

                print(f"[<] Listener: LDAP payload (hex): {hex_payload}")
                responses_hex = parse_ldap_payload(hex_payload,client_ip)

                for response_hex in responses_hex:

                    response_bytes = bytes.fromhex(response_hex)
                    client.sendall(response_bytes)
                    print(f"[>] Listener: Sent response (hex): {response_hex}")

                print("##############################################")

        except socket.timeout:
            print("[*] Listener: Timeout reached, waiting for more data...")
        except Exception as e:
            print(f"[!] Listener error: {e}")


if __name__ == "__main__":
    with socketserver.TCPServer((LISTEN_HOST, LISTEN_PORT), LDAPRequestHandler) as server:
        print(f"[*] LDAP Listener running on {LISTEN_HOST}:{LISTEN_PORT}")
        server.serve_forever()
