#!/usr/bin/env python3
"""Render a self-contained English report from the reviewed local measurements."""
import argparse
import csv
from html import escape
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
NAMES = {"plain":"Baseline", "secure":"Secure"}
DIRECTIONS = ("A→B", "B→A", "combined")


def read_csv(directory, name):
    with (directory / (name + ".csv")).open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def number(value, places=2):
    return f"{float(value):,.{places}f}".rstrip("0").rstrip(".") if places else f"{float(value):,.0f}"


def signed(value):
    return ("+" if float(value) > 0 else "") + number(value, 3)


def table(headings, rows):
    head = "".join(f'<th scope="col">{escape(label)}</th>' for label in headings)
    body = []
    for first, *rest in rows:
        cells = "".join(f"<td>{escape(str(value))}</td>" for value in rest)
        body.append(f'<tr><th scope="row">{escape(str(first))}</th>{cells}</tr>')
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def figure(filename, title, caption):
    path = "evidence/" + filename + ".png"
    return (f'<figure><a class="imagebox" href="{path}" aria-label="Open full-size figure: {title}">'
            f'<img loading="lazy" src="{path}" alt="{escape(title)}"></a>'
            f'<figcaption><strong>{escape(title)}.</strong> {caption}</figcaption></figure>')


def run_table(records, measurements):
    rows = []
    for r in records:
        a, b, c = [measurements[r["run"], direction] for direction in DIRECTIONS]
        rows.append([r["run"], number(c["setup_bytes"],0), number(a["mean_kbps"],3),
                     number(b["mean_kbps"],3), number(c["mean_kbps"],3),
                     number(c["packets_s"],2), number(c["typical_ip_bytes"])])
    return table(["Run","Setup (B)","A → B (kb/s)","B → A (kb/s)","Both (kb/s)",
                  "Both (pkt/s)","Median IP (B)"],rows)


def change_table(deltas):
    rows = []
    for direction, metric, label in (
            ("combined","setup_bytes","Setup, both (B)"),
            ("A→B","mean_kbps","Steady A → B (kb/s)"),
            ("B→A","mean_kbps","Steady B → A (kb/s)"),
            ("combined","mean_kbps","Steady both (kb/s)"),
            ("A→B","packets_s","A → B packets/s"),
            ("B→A","packets_s","B → A packets/s"),
            ("combined","packets_s","Both packets/s"),
            ("combined","typical_ip_bytes","Median IP packet (B)")):
        r = deltas[direction,metric]
        rows.append([label,number(r["plain_mean"],3),number(r["secure_mean"],3),
                     signed(r["absolute_change"]),signed(r["percent_change"])+"%"])
    return table(["Quantity","Baseline","Secure","Absolute change","Change (%)"],rows)


def variation(records, summary):
    rows = []
    for mode, label in NAMES.items():
        for field,title in (("setup_bytes","setup (B)"),("mean_kbps","steady both (kb/s)")):
            entry=summary[mode,"combined",field]
            sd=number(entry["sd"],3) if entry["sd"] else "n/a"
            rows.append([label+" "+title,entry["n"],number(entry["min"],3),
                         number(entry["max"],3),sd])
    out=table(["Group","Calls","Minimum","Maximum","Sample SD"],rows)
    retries=sum(int(r["total_retransmission_indications"]) for r in records)
    late=sum(int(r["tcp_packets_in_window"]) for r in records)
    drops=sum(int(r["tcpdump_kernel_drops"]) for r in records)
    ctl=[int(r["rtcp_packets_in_window"]) for r in records]
    anomalies=[escape(r["run"]+": "+r["anomalies"]) for r in records if r["anomalies"]!="none detected"]
    quality=(f"tcpdump reported {drops} kernel drops across the recordings. TShark flagged "
             f"{retries} TCP retransmissions. The steady windows contained {late} TCP packets "
             f"and {min(ctl)}–{max(ctl)} RTCP/SRTCP packets per call. Both categories were excluded "
             "from steady audio. The capture log lists their observed IP bytes for each window.")
    quality+=" All six benchmark attempts completed and entered the comparison. The short starter and diagnostic calls are outside the series." if len(records)==6 else ""
    if anomalies:
        quality+=" The run log also records "+". ".join(anomalies)+"."
    return (f'<div class="scroll" tabindex="0" role="region" aria-label="Between-call variation">{out}</div>'
            f'<p class="reading">{quality} <a href="data/runs.csv">Inspect every interval</a>.</p>')


def theory(records, results, verification):
    ticks={int(float(r[key])) for r in records for key in ("timestamp_step_a","timestamp_step_b")}
    sizes={mode:{int(r["min_ip_bytes"]) for r in results if r["mode"]==mode} |
                {int(r["max_ip_bytes"]) for r in results if r["mode"]==mode}
           for mode in NAMES}
    if ticks!={160} or sizes["plain"]!={200}:
        return "<p>The captured packets depart from the fixed 20 ms baseline assumptions. Use the observed packet lengths and rates in the CSV for this series.</p>"
    statement = ('<p>The visible RTP timestamps advance by 160 ticks per consecutive packet in the steady streams. '
                 'G.711 µ-law uses an 8 kHz clock and one byte per sample. This gives 160 bytes of sound per 20 ms packet, '
                 'or 50 packets per second. The header audit found a 20-byte IPv4 header, 8-byte UDP header and '
                 '12-byte RTP header. <a href="#ref-audio">RTP and audio profile</a>.</p>'
                 '<p class="formula"><strong>Baseline prediction, one direction</strong><br>'
                 '(160 + 20 + 8 + 12) bytes × 8 × 50 = 80,000 bit/s.</p>')
    matched=re.search(r"tag_bytes=10[^\n]*profile=AES_CM_128_HMAC_SHA1_80",verification)
    if matched and sizes["secure"]=={210}:
        return statement+('<p>A separate answered diagnostic call on the same build and configuration reported '
            '<code>AES_CM_128_HMAC_SHA1_80</code> after libSRTP installed the stream policies. '
            'AES counter mode encrypts the payload without expanding it, and the HMAC-SHA1 authentication tag adds 80 bits '
            '(10 bytes) per RTP packet. All measured secure audio packets were 210 IPv4 bytes in the selected windows. '
            'The diagnostic establishes the profile for that configuration. The timed calls supply the independent '
            'wire-length and channel evidence. <a href="downloads/verification.txt">Installed policy parameters</a>, '
            '<a href="#ref-sdes">SDES protection profiles</a>.</p>'
            '<p class="formula"><strong>Secure prediction, one direction</strong><br>'
            '(200 + 10) bytes × 8 × 50 = 84,000 bit/s. Across both directions the predicted increase is 8 kb/s.</p>')
    return statement+('<p>The negotiation method was SDES. An authenticated call and its active SRTP flags establish protection. '
        'The exact SRTP cipher and tag have not been independently confirmed for this report. '
        'The recorded secure sizes are in the per-run table. The observed byte difference alone cannot identify a cryptographic suite.</p>')


def certificate_checks(checks):
    if "Verified peername: pbx-b.lab.test" not in checks or "alert handshake failure" not in checks:
        return "<p>The separate certificate-enforcement checks have not been verified.</p>"
    observations = ("The TLS control verified B’s DNS name using A’s client identity. B rejected a "
                    "client that omitted its certificate. Together with the certificate request and "
                    "exchange in the captured calls, this confirms mutual TLS on the trunk.")
    if "The server identity does not match" in checks:
        observations += (" When A contacted B at its correct IP under the alternate name "
                         "<code>pbx-b</code>, A rejected the server identity.")
    return "<p>"+observations+' <a href="downloads/verification.txt">Certificate checks</a>.</p>'


def build(data, output):
    records=read_csv(data,"runs")
    results=read_csv(data,"results")
    measurements={(r["run"],r["direction"]):r for r in results}
    deltas={(r["direction"],r["metric"]):r for r in read_csv(data,"differences")}
    summary={(r["mode"],r["direction"],r["metric"]):r for r in read_csv(data,"summary")}
    text=(ROOT/"website/page.html").read_text()
    rate=deltas["combined","mean_kbps"]
    setup=deltas["combined","setup_bytes"]
    plain=next(r for r in records if r["run"]=="plain-1")
    secure=next(r for r in records if r["run"]=="secure-1")
    verification=ROOT/"experiment/verification.txt"
    checks=verification.read_text() if verification.exists() else ""
    log=(ROOT/"experiment/logs/secure-1.log").read_text()
    leg_lines=[line for line in log.splitlines() if line.startswith(("pbx-a channel=","pbx-b channel="))]
    if len(leg_lines)!=2 or any("tls=1 srtp=1" not in leg for leg in leg_lines):
        raise ValueError("Missing secure call readings")
    evidence="".join([
        figure("plain-sip","Readable SIP offer and answer",
            f'In baseline run 1, frame 8 is B’s <code>200 OK</code> to the INVITE. Its SDP names '
            f'UDP port {plain["port_b"]}, PCMU/8000 and a requested 20 ms packet time.'),
        figure("plain-rtp","RTP streams in both directions",
            f'The baseline RTP Streams view identifies A’s stream by SSRC <code>{plain["ssrc_a"]}</code> and B’s by '
            f'<code>{plain["ssrc_b"]}</code>. The rows cover the whole call. The measurement uses only the inner 50 seconds.'),
        figure("secure-tls","TLS certificate exchange",
            'The secure TCP stream carries a ClientHello, ServerHello, a certificate request, the client '
            'certificate exchange and encrypted application records. Frames 4, 6 and 8 show the certificate handshake.'),
        figure("secure-media","The separate UDP media flow",
            f'The first audio packet in secure run 1 is frame {secure["first_audio_frame"]}. '
            f'A sends from port {secure["port_a"]} to B’s port {secure["port_b"]}. The reverse flow uses the same pair. '
            'Decode As RTP exposes timestamps and sequence numbers. The channel readings below establish the active media protection.')])
    fig_graph=figure("io-graph","One-second IPv4 media throughput",
        'Baseline run 1 and secure run 1 are aligned to their first audio packets. The profile curves count '
        'audio in both directions. The marked interval from second 5 through the start of second 55 matches the '
        'CSV calculation. The exported values are bytes in each one-second bin. Wireshark multiplies them by 8 for the displayed bit/s. '
        '<a href="evidence/wireshark.md">Graph filters and alignment</a>, '
        '<a href="evidence/io-graph.csv">native CSV export</a>.')
    vmap=dict(
        AUTH_CHECKS=certificate_checks(checks),
        FALLBACK_CHECK=('<p>In a separate control call A offered only plain RTP over authenticated TLS. '
                        'B logged an audio negotiation failure and the call did not reach the answer dialplan. '
                        'The strict policy therefore rejected plaintext fallback. '
                        '<a href="downloads/verification.txt">Control-call evidence</a>.</p>')
                        if "Authenticated TLS with plaintext-only audio offered by A" in checks and
                        "Couldn't negotiate stream" in checks else
                        '<p>A control test for rejecting a plaintext audio offer has not been verified.</p>',
        LEAD=(f'<strong>{signed(rate["percent_change"])}% steady-media bandwidth.</strong> '
              f'The combined IPv4 rate averaged {number(rate["plain_mean"],3)} kb/s with RTP and '
              f'{number(rate["secure_mean"],3)} kb/s with SRTP.'),
        CONTROLS='On each PBX the recorder sets <code>AFTER_CHECK_SECONDS=60</code>. The dialplan already waits two seconds before '
                 'its channel reading, giving approximately 62 seconds of answered audio in each run.',
        DIRECTION_ROWS=table(["Run and flow", "Setup (B)", "Audio packets", "Packets/s", "Median IP (B)", "Steady kb/s"],
            [[r["run"] + " " + r["direction"],number(r["setup_bytes"], 0),number(r["media_packets"],0),
              number(r["packets_s"],3),number(r["typical_ip_bytes"]),number(r["mean_kbps"],3)]
             for r in results if r["direction"] != "combined"]),
        CAPTURE_COMMAND='<pre class="pad"><code>tcpdump -p -n -i eth0 -s 0 -U -w /tmp/trunk.pcap \\\n'
                        "  'ip and host 172.30.76.10 and host 172.30.76.11 and (tcp or udp)'</code></pre>",
        TYPICAL='the median IPv4 packet length in the selected direction and window',
        SECURE_LOG=('<pre><code>'+escape("Call-ID "+secure["call_id"]+"\n"+"\n".join(leg_lines))+'</code></pre>'),
        EVIDENCE=evidence, IO_GRAPH=fig_graph,
        RESULTS_INTRO=(f'On {escape(records[0]["syn_utc"][:10])} (UTC) the experiment recorded {len(records)} fresh connections, {summary["plain","combined","mean_kbps"]["n"]} baseline and '
                       f'{summary["secure","combined","mean_kbps"]["n"]} secure. Each rate uses the same 50 seconds of steady audio.'),
        RUN_TABLE=run_table(records,measurements), DELTA_TABLE=change_table(deltas),
        VARIATION=variation(records,summary), THEORY=theory(records,results,checks),
        CONCLUSION=(f'<p>Securing this trunk changed the combined steady rate by <strong>{signed(rate["absolute_change"])} kb/s</strong> '
                    f'({signed(rate["percent_change"])}%). Cold setup averaged {number(setup["plain_mean"],2)} IPv4 bytes in the '
                    f'baseline and {number(setup["secure_mean"],2)} with TLS and SDES, a change of {signed(setup["absolute_change"])} bytes '
                    f'({signed(setup["percent_change"])}%). For a full-duplex link carrying this codec, start the media budget at '
                    f'{number(deltas["A→B","mean_kbps"]["secure_mean"],3)} kb/s per active call in each direction. '
                    'Allow additional capacity for control packets and link framing. Estimate cold setup from the '
                    'number of new connections the trunk actually opens.</p>'))
    for name,value in vmap.items():
        text=text.replace("@@"+name+"@@",value)
    if "@@" in text:
        raise ValueError("Unexpanded report field")
    output.write_text(text,encoding="utf-8")

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data",type=Path,default=SITE/"data")
    parser.add_argument("--out",type=Path,default=SITE/"index.html")
    args=parser.parse_args()
    build(args.data,args.out)
