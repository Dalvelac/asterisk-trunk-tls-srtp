# Recalculate the trunk measurements

The inputs to each trial are one original tcpdump file, the two answered Asterisk channel readings in the call log, and tcpdump's final capture counters. You can repeat the calculations with both PBXs stopped. All rates use IPv4 total length (`ip.len`) and decimal kilobits per second.

The six scheduled trials were recorded in alternating baseline/secure order on 22 November 2026 (UTC). All six contributed. Their first-to-last audio spans ranged from 61.974 to 61.981 seconds. All six capture counters reported zero kernel drops. No steady-window RTP sequence discontinuities, atypical timestamp steps or TShark TCP retransmission indications appeared. Each window contained 18–20 separate control packets and zero TCP packets. The earlier short smoke calls and the later security checks serve as build and policy evidence only.

## Reproduce the published values

From the top of the source tree, use Python 3 and TShark. Matplotlib is used only to draw the figure.

```sh
python3 analysis/measure.py
python3 analysis/chart.py
```

The analyzer uses `tshark` on PATH or the prepared workstation’s `.lab/bin/tshark`. Use `--tshark /path/to/tshark` to select a different installation. The two commands generate the following files in `site/data/`.

| File | Contents and units |
|---|---|
| `runs.csv` | Capture hash, call ID, UTC times, ports, SSRCs, packet numbers, relative boundaries, literal Wireshark display filters and diagnostic counts. |
| `results.csv` | One row per call and direction, plus one row for both directions. Setup bytes and packet count, steady audio packets and IP bytes, packets/s, median/minimum/maximum IP length in bytes, and mean kb/s. |
| `summary.csv` | Arithmetic mean, observed range and sample standard deviation (denominator n−1) across repeated calls of each mode. |
| `differences.csv` | Secure mean minus baseline mean. Percentage change is 100 × difference / baseline mean. |
| `paired-changes.csv` | Absolute and percentage changes within each baseline/secure trial pair, by direction and metric. |
| `comparison.svg` | Mean setup bytes and steady audio kb/s for both directions combined, with all individual trials plotted. The figure reads `results.csv`. |

To analyze a fresh set while keeping the submitted values, point the analyzer at a separate experiment directory that has the same `captures/` and `logs/` layout.

```sh
python3 analysis/measure.py --experiment repeat --out repeat/data
python3 analysis/chart.py --data repeat/data
```

## How one run becomes a row

1. Read the unique SIP Call-ID from `logs/<run>.log`. Require two answered legs with the expected `tls` and `srtp` flags, `ulaw`, positive send and receive counters and completed hangup. A's `remote` field gives B's audio port, and B's `remote` gives A's. Both ends sometimes choose the same port number. Matching source **and** destination IP and port preserves direction in that case.
2. Open the capture with TShark and explicitly decode the negotiated audio tuple's port as RTP. RTP's clear header lets TShark read timestamps and sequence numbers on both modes. SRTP negotiation comes from the active channels. In baseline mode the SIP Call-ID in the capture must also match the log. For secure mode, check the TLS ClientHello, ServerHello, CertificateRequest, both certificate messages and application data on the single TCP stream. The agreement between the run log and the two media sockets associates this stream with the measured call. The full-file audit checks endpoints, captured frame lengths, tcpdump's packet count, and unexpected port pairs before producing rows.
3. Define **S** as the first outgoing TCP SYN without ACK and **M** as the earliest packet on the active audio port pair. Sum every TCP `ip.len` in the interval **S ≤ t < M** for the signaling stream, separately by sender. This is a cold connection-to-first-audio measurement. A TLS record can contain encrypted SIP, and the first audio is an observable proxy for the answer in both modes. The SDP answer is readable only in baseline mode. Any delayed TCP acknowledgments arriving after M fall outside this boundary. Local interface offload can affect observed TCP segmentation.
4. Count audio packets with **M + 5 s ≤ t < M + 55 s**. Both SSRCs must span this full 50-second window. Read payload type 0 (PCMU), 20-byte IPv4 headers and the basic RTP header with zero CSRCs, no extension and no padding. Check consecutive sequence numbers modulo 65,536, then measure their RTP timestamp difference modulo 2³². At PCMU's 8,000 Hz clock, 160 ticks are 20 ms. Record timestamp steps and sequence discontinuities separately from arrival timing. [RTP clock and PCMU assignment](https://www.rfc-editor.org/rfc/rfc3551#section-6) · [RTP header](https://www.rfc-editor.org/rfc/rfc3550#section-5.1)
5. For each direction, compute **packet rate = packet count / 50** and **bitrate in kb/s = 8 × sum of ip.len / 50 / 1000**. The typical size is the median over selected packets. The combined row pools both directions over the same 50 seconds. Its packet count and byte total add the directions, and its size is the pooled median.
6. RTCP/SRTCP on the adjacent port pair and TCP traffic in the steady window are counted in diagnostic columns and excluded from audio. Any retransmitted TCP packets inside setup count toward observed network demand. The run log gives the number of TShark retransmission indications. TCP traffic later in the call, including teardown, stays outside setup. A successful SIP hangup can leave the underlying connection open. RTP packets are counted as observed, including duplicate arrivals if present. Detected sequence discontinuities and kernel capture drops are recorded. The short starter smoke calls never enter the six-trial comparison because they end before the selected window.
7. The publisher also reviews downloadable captures. The analyzer checks classic pcap format, the exact two lab endpoints, and the absence of readable SIP authorization fields, SDP crypto attributes and literal key markers. Public TLS certificates and lab-only addresses are expected. The baseline intentionally retains its two synthetic tones. The secure capture retains encrypted TLS application data and SRTP payloads.

## Cross-check one figure directly in Wireshark

Open an original pcap, find its row in `runs.csv`, and paste the row's `setup_filter` or `steady_filter` into the display filter bar. Click a packet and expand **Internet Protocol Version 4 → Total Length**. Compare `frame.len` and `ip.len` to see the link-layer bytes that are outside this accounting layer.

For an independent sum, use the published filter and TShark. This example rechecks the combined steady row for the first baseline call.

```sh
export PATH="$PWD/.lab/bin:$PATH"
filter=$(python3 -c 'import csv; print(next(r["steady_filter"] for r in csv.DictReader(open("site/data/runs.csv")) if r["run"] == "plain-1"))')
tshark -n -r experiment/captures/plain-1.pcap -Y "$filter" -T fields -e ip.len |
  awk '{packets++; bytes += $1} END {printf "%d packets, %d IPv4 bytes, %.3f kb/s\n", packets, bytes, 8*bytes/50/1000}'
```

TShark's `-Y` selects saved packets and `-T fields -e ip.len` prints the IPv4 byte count on each line. In `awk`, adding the lines counts all IP headers and payload at the chosen capture point. [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html)

## Interpreting a 10-byte difference

For 20-ms G.711 µ-law the expected payload is 160 one-byte samples. Adding 20 bytes IPv4, 8 UDP and 12 RTP gives **200 bytes** per baseline packet. Sending 50 packets/s gives **80 kb/s per direction**. With an 80-bit SRTP authentication tag, a 10-byte trailer raises that prediction to **210 bytes and 84 kb/s per direction**, assuming the same basic headers and payload. In a separate secure call using the same profile, both nodes reported that libSRTP installed `AES_CM_128_HMAC_SHA1_80` with a 10-byte tag. The six timed calls independently establish the actual packet sizes and the live channel protection flags. Their captures and recorded media counts agree with the prediction. [Endpoint verification](../experiment/verification.txt) · [SRTP packet structure](https://www.rfc-editor.org/rfc/rfc3711#section-3.1) · [SDES protection profiles](https://www.rfc-editor.org/rfc/rfc4568#section-6.2)

The setup result includes TCP opens and acknowledgments, SIP request/response sizes, and, for secure calls, TLS certificates, key exchange and encrypted records. It is specific to this fresh-connection configuration, certificate chain, capture point, and first-audio boundary. The measured difference does not isolate the cost of each of those components. The media estimate applies at the IP layer on this trunk. Physical-link capacity planning also involves link-layer framing, control traffic, concurrent calls and peak allowance. Three local replicates describe repeatability under these conditions.
