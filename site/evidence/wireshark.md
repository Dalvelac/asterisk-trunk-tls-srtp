# Read or reproduce the Wireshark evidence

All six original captures were opened in Wireshark 4.7.4. The baseline files showed readable SIP invitations, answers and RTP, and the secure files showed TLS certificate exchanges and encrypted application records. The project screenshots use the first recorded call of each mode. The plain RTP screenshot is cropped to the packet list and RTP Streams window. Both exchanges ran on the same internal bridge. All packets were captured at PBX A's eth0. Times in the original files are relative to the first captured packet.

| Original capture | GUI view | What to check |
|---|---|---|
| plain-1.pcap | [Readable SIP and SDP](plain-sip.png) | Enter `sip`. Frame 4 dials 200. Select frame 8 and expand SIP → Message Body → Session Description Protocol. B answers with port 10038, RTP/AVP format 0, PCMU/8000 and a requested packet duration of 20 ms. Frame 10 acknowledges the answer. Frames 6235 and 6237 show the BYE and final response. |
| plain-1.pcap | [Two RTP streams](plain-rtp.png) | Enter `rtp`, then select Telephony → RTP → RTP Streams. Each sender has a separate SSRC. For this call both nodes chose port 10038. Wireshark counts 3,100 packets from A and 3,099 from B across the entire call. Both reported lost counts are zero. Use consecutive packets from one SSRC to check the 160-sample timestamp increment. |
| secure-1.pcap | [TLS handshake and application records](secure-tls.png) | Enter `tcp.port == 5061 && tls`. A's ClientHello in frame 4 names B. In frame 6 B sends its certificate and requests a client certificate. A sends its certificate and Certificate Verify in frame 8. The application-data records follow. Certificate acceptance and the audio security state have separate endpoint evidence. |
| secure-1.pcap | [UDP audio flow and IP length](secure-media.png) | Enter `udp.port == 10018 && udp.port == 10020`. Select Analyze → Decode As and choose RTP for UDP port 10018. Columns in the screenshot show `udp.srcport`, `udp.dstport`, `ip.len`, `rtp.seq` and `rtp.timestamp`. Frame 16 travels from A:10018 to B:10020. Its IPv4 Total Length is 210 bytes. The visible RTP headers provide sequence and timing information. |

The secure call's Asterisk record identifies Call-ID `429fe836-0a3d-4ab5-acae-97721e0b6010`. Both endpoints report `tls=1`, `srtp=1`, codec `ulaw` and positive transmit and receive packet counters. A reports B:10020 as its media destination. B reports A:10018. Match these sockets to the UDP screenshot. Decode As controls Wireshark's interpretation of the header. The independent live Asterisk reading establishes negotiated SRTP for that flow.

## Reproduce the I/O graph

The [graph screenshot](io-graph.png) compares the first trial of each mode. The two calls took place at different times. To overlay them, [align-graph.py](align-graph.py) reads each call's two logged remote sockets and exports the two matching directions from its original pcap with TShark. It shifts every timestamp in the secure media **copy** by the same offset so its first audio packet coincides with the baseline's first audio packet. It merges both copies into one file using separate pcapng interface IDs. The frame contents and within-run packet spacing come directly from the captures. Signaling and the adjacent-port control packets remain in the originals, which were used for the reported measurements.

From the project root, with TShark, editcap, mergecap and Wireshark available, run the following commands. Choose a new output file path for each invocation.

```sh
GRAPH_DIR=$(mktemp -d)
python3 site/evidence/align-graph.py experiment "$GRAPH_DIR/run-1-aligned.pcapng"
mkdir "$GRAPH_DIR/profile"
cp site/evidence/io_graphs "$GRAPH_DIR/profile/io_graphs"
WIRESHARK_CONFIG_DIR="$GRAPH_DIR/profile" wireshark -n -r "$GRAPH_DIR/run-1-aligned.pcapng" -z io,stat
```

On the prepared Artix workstation, if the host lacks editcap or mergecap on PATH, use the bundled Wireshark tools for the Python step. The existing `.lab/bin/wireshark` launcher opens the GUI.

```sh
GRAPH_DIR=$(mktemp -d)
WS_BASE=$(dirname "$(dirname "$(readlink -f .lab/bin/tshark)")")/analysis/usr
PATH="$WS_BASE/bin:$PATH" LD_LIBRARY_PATH="$WS_BASE/lib" \
  python3 site/evidence/align-graph.py experiment "$GRAPH_DIR/run-1-aligned.pcapng"
mkdir "$GRAPH_DIR/profile"
cp site/evidence/io_graphs "$GRAPH_DIR/profile/io_graphs"
WIRESHARK_CONFIG_DIR="$GRAPH_DIR/profile" .lab/bin/wireshark -n -r "$GRAPH_DIR/run-1-aligned.pcapng" -z io,stat
```

The horizontal axis is seconds since first audio. Each curve uses **THROUGHPUT(Y Field)**, field `ip.len`, factor **8**, a **one-second interval** and no moving average. These settings give combined IPv4 bits per second for both media directions. The vertical axis is zoomed to the observed range. The individual points correspond to one-second bins starting at each labeled time.

| Graph row | Display filter | Style |
|---|---|---|
| Plain media | `frame.interface_id == 0` | Teal line |
| Secure media | `frame.interface_id == 1` | Orange line |
| Window [5,55) s | `frame.interface_id == 0 && frame.time_relative >= 5 && frame.time_relative < 55` | Circles on the baseline curve identify the 50 bins included for **both** curves |

For run 1 the timestamp shift was −75.165311 seconds. The [native Wireshark graph CSV](io-graph.csv) was exported from the I/O Graphs window with **Save As → Comma Separated Values**. This version exports the unscaled byte values per one-second bin. Multiply each value by 8 to recover the displayed bit/s. Outside the window the CSV marker series has zeros; the points on the plot occupy only bins 5 through 54.

An independent sum of `ip.len` in each original media capture reproduced every exported bin. The 50 selected bins contain 1,000,000 baseline bytes and 1,050,000 secure bytes in both directions combined. This gives 160,000 and 168,000 bit/s for the representative run pair. The site's results table uses all six original files.

Wireshark documents the advanced field-based Y-axis calculation, scale factor and graph export in its [I/O Graphs guide](https://www.wireshark.org/docs/wsug_html_chunked/ChStatIOGraphs.html).
