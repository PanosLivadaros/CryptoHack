from scapy.all import rdpcap, IP, TCP, raw


pkts = rdpcap('./cryptohack.org.pcapng')

for pkt in pkts:
    if IP in pkt and TCP in pkt and pkt[IP].src == '178.62.74.206':
        payload = raw(pkt[TCP].payload)
        if len(payload) >= 5 and payload[0] == 22:
            handshake = payload[5:]
            if len(handshake) >= 4 and handshake[0] == 2:
                server_hello_body = handshake[4:]
                if len(server_hello_body) >= 34:
                    legacy_version = server_hello_body[0:2]
                    random_bytes = server_hello_body[2:34]
                    print("legacy_version:", legacy_version.hex())
                    print("random (hex):", random_bytes.hex())
                    break
