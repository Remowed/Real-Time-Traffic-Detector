from scapy.all import sniff, IP
import numpy as np
from collections import deque
import time

WINDOW_SIZE = 100
THRESHOLD = 5

packet_sizes = deque(maxlen=WINDOW_SIZE)

def handle_packet(pkt):
    if IP not in pkt:
        return

    size = len(pkt)
    src = pkt[IP].src
    dst = pkt[IP].dst
    timestamp = time.time()

    packet_sizes.append(size)

    if len(packet_sizes) < 20:
        return

    mean = np.mean(packet_sizes)
    std = np.std(packet_sizes)

    if std == 0:
        return

    z = (size - mean) / std

    if abs(z) > THRESHOLD:
        print("  Anomalous packet detected")
        print(f"   Time       : {timestamp}")
        print(f"   Source IP  : {src}")
        print(f"   Dest IP    : {dst}")
        print(f"   Size       : {size}")
        print(f"   Z-score    : {z:.2f}\n")

print("Starting real-time packet capture...")
sniff(prn=handle_packet, store=False)