# Reproduce the Asterisk trunk experiment

Daniel Alves · VoIP I · VŠB–TUO · Topic 1

## Read the original six calls without starting Docker

Use the lab source archive, captures archive and run logs archive from the website. Extract all three in the same empty directory. Run the following from that directory. TShark, Python 3 and OpenSSL are required. The optional chart uses Matplotlib. On the prepared workstation, work in the original project directory and use `export PATH="$PWD/.lab/bin:$PATH"`. The six calls are already there.

```sh
tar -xzf lab-source.tar.gz
unzip captures.zip
unzip run-logs.zip
python3 analysis/measure.py --out replay/data
python3 analysis/chart.py --data replay/data
python3 experiment/review-captures.py experiment/captures/*.pcap
```

Compare `replay/data/results.csv` with the downloadable results CSV. There are three rows per call, A to B, B to A and combined. The combined rate is the sum of both directions. Each row uses decimal kilobits per second. The run log in `runs.csv` includes exact packet boundaries, source files and identifiers. The original 12-second files in `smoke/` are teaching examples. The experiment uses the six longer files in `experiment/captures/`.

Open the first plain and secure pcaps separately in Wireshark. On plain traffic, filter `sip`, select the INVITE and expand its Session Description Protocol body. B's 200 OK gives B's receive port. Open **Telephony → RTP → RTP Streams** for the two senders. On secure traffic, filter `tcp.port == 5061 && tls` for the handshake. Compare the certificate exchange and encrypted application data against the matching call log. Use the two `remote` sockets from that log to locate the bidirectional UDP audio. The far party's log gives the local port. The reported `srtp=1` comes from each live audio channel. Wireshark can decode the outer RTP header at those ports using **Analyze → Decode As → RTP**. Leave TLS secrets and raw SIP tracing disabled.

## Collect a new series

Install a running Linux-container Docker Engine with Compose v2 supporting `up --wait`, Python 3, Bash and OpenSSL. On a fresh machine the first build downloads the pinned Asterisk base image and tcpdump. The repository README provides the complete build, CLI and reset guide.

```sh
./lab up plain
./lab status
./lab call
for i in 1 2 3; do
    for mode in plain secure; do
        bash experiment/record.sh "$mode" "$i" repeat
    done
done
./lab down
python3 analysis/measure.py --experiment repeat --out repeat/data
python3 analysis/chart.py --data repeat/data
```

Choose a new output directory on each repetition. The recorder refuses to overwrite a trial. It cold-starts the same two nodes for every call, leaving their existing certificates and editable configuration on the host. In both Asterisk consoles it runs `dialplan set global AFTER_CHECK_SECONDS 60`, verified with `dialplan show globals`. This adds 60 seconds to the dialplan's existing two-second media check. The next `./lab up` restores the 12-second starter default. A originates the only call to B's extension 200. Each node generates a continuous tone (440 Hz on A, 660 Hz on B), with PCMU as the only permitted codec. There are no handsets, registration, NAT traversal, published ports or direct media bypass.

The capture command runs **inside PBX A**, on its single trunk-facing `eth0`. To run the same capture from a terminal, use the following command.

```sh
./lab compose exec pbx-a tcpdump -p -n -i eth0 -s 0 -U -w /tmp/trunk.pcap \
  'ip and host 172.30.76.10 and host 172.30.76.11 and (tcp or udp)'
```

The recorder waits for tcpdump's listening message, runs `./lab call`, waits for hangup plus one second, then sends SIGINT, waits for file flush, and copies the pcap to the host. The companion `.tcpdump` file records the kernel drop count. The `.log` contains UTC command times, one shared SIP Call-ID, peer sockets, protection flags and a two-second TX/RX sample on each PBX. The `.status` file records the running version, modules and endpoint settings. Clock timestamps in the pcap provide the measurement boundaries.

## Count bytes consistently

Use the IPv4 Total Length field `ip.len` throughout. This includes the IP header, transport headers and data. Ethernet, preamble and link interframe time lie outside it. Setup counts every TCP packet on the one signaling stream from its opening SYN (inclusive) to the first confirmed audio packet M (exclusive), including pure ACKs and any retransmissions. This defines connection-to-first-media even when TLS conceals the INVITE and answer. Signaling after M, including teardown or idle traffic, falls outside setup. Cold setup bytes depend on TCP packetization, certificates and SIP/SDP. They are specific to this capture point on a virtual Ethernet interface.

In each capture the media interval is [M+5 s, M+55 s). M is a shared observable proxy for the start of answered audio. This is a 50-second window with both sources active before hangup. Count the two exact direction/port combinations reported by the PBXs, check RTP version, payload type, SSRC, sequence and timestamp increments. RTP timestamps advance on an 8 kHz clock. Divide the sum of IP bytes times eight by 50, then by 1000 for kb/s. Packet rate is packet count divided by 50. Keep reports on the adjacent RTCP/SRTCP ports out of audio. Inspect the per-run audit and group statistics for retransmissions, missing packets, drops and observed variation.

To inspect a single run's TShark filter, open the setup_filter and steady_filter fields in runs.csv. Use the filter in Wireshark or as the `-Y` argument to TShark. Packet counts from the whole call and Ethernet frame lengths answer different questions.

## Supplemental security checks

With idle PBXs on a Linux host matching the Linux-container architecture, run the script below. It needs a C compiler and libSRTP 2 development headers (Debian package `libsrtp2-dev`; Artix package `libsrtp`). These extra dependencies are used only by this diagnostic. Use the normal two-mode installation on other platforms for the timed experiment.

```sh
bash experiment/verify-security.sh
```

The script checks the certificates and live TLS listeners, tries a TLS connection with and without A's certificate, and places a separate short secure call. For this one call only, a small observer reports the algorithm identifiers and tag length of successfully installed libSRTP policies. It forwards the normal library calls and reads only public policy fields. Its source is in `experiment/verify-policy.c`. The measurement containers use the original image and start command. The script also tests a TLS call offering plain RTP and a connection to B under an unlisted DNS name. For the two rejection tests, a temporary copy of the configuration is mounted only on A, and both peers are cold-started. The working files stay on the host. The script stops these peers on exit. Use `./lab up plain` to resume the starter lab.

## Review of downloadable evidence

All six measured files are original classic pcaps. The release check inspects the network endpoints, frame completeness, transport ports, reconstructed signaling, secret markers and certificate names. The traces contain synthetic tones and public certificates used on this private lab only. Capture hashes and public certificate fingerprints are in the review manifest inside captures.zip. The source archive contains the issuance script. Each new installation generates fresh lab identities locally.
