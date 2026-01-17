# Real-Time-Traffic-Detector

I captured network traffic and extracted packets to detect anomalous packets in real time.
I am using a sliding window to maintain a recent baseline of normal traffic.

Alerts include source and destination IPs, packet size, timestamp and Z-score for interpretation.
(Z-score is for flagging packets whose sizes significantly deviate from normal behavior.)

