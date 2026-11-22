#!/usr/bin/env python3
"""Account for IPv4 packets on the two-PBX trunk using TShark's dissectors."""
import argparse
import csv
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
from pathlib import Path
import re
import shutil
import statistics as stats
import subprocess

ROOT = Path(__file__).resolve().parents[1]
A, B = "172.30.76.10", "172.30.76.11"
DIRECTIONS = {"A→B": A, "B→A": B, "combined": None}
METRICS = ("setup_bytes", "packets_s", "typical_ip_bytes", "mean_kbps")
FIELDS = """
frame.number frame.time_epoch frame.time_relative frame.len frame.cap_len
ip.src ip.dst ip.len ip.hdr_len ip.flags.mf ip.frag_offset
tcp.stream tcp.srcport tcp.dstport tcp.flags.syn tcp.flags.ack
tcp.analysis.retransmission tcp.analysis.fast_retransmission tcp.analysis.spurious_retransmission
udp.srcport udp.dstport udp.length rtp.version rtp.p_type rtp.ssrc rtp.seq rtp.timestamp
rtp.cc rtp.ext rtp.padding sip.Call-ID sip.Method sip.CSeq.method sip.Status-Code
tls.handshake.type tls.record.content_type
""".split()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def call_info(run, log, secure):
    call_ids = re.findall(r"Answered on both peers\. SIP Call-ID (\S+)", log)
    require(len(call_ids) == 1 and "Both legs hung up." in log, f"{run}: incomplete or ambiguous call log")
    ports = {}
    for node, remote in (("a", B), ("b", A)):
        lines = re.findall(rf"^pbx-{node} (channel=.*)$", log, re.MULTILINE)
        require(len(lines) == 1, f"{run}: missing or ambiguous {node} channel record")
        leg = dict(item.split("=", 1) for item in lines[0].split() if "=" in item)
        require(leg["tls"] == leg["srtp"] == str(int(secure)), f"{run}: active channel security mismatch")
        require(leg["codec"] == "(ulaw)" and min(int(leg[k]) for k in ("tx", "rx")) > 0,
                f"{run}: need two-way G.711 µ-law")
        address, port = leg["remote"].split(":")
        require(address == remote, f"{run}: far media endpoint mismatch")
        ports[remote] = int(port)
    return call_ids[0], ports


def read_capture(tshark, path, audio_port, secure):
    transport = "5061,tls" if secure else "5060,sip"
    command = [tshark, "-n", "-r", str(path), "-d", f"udp.port=={audio_port},rtp",
               "-d", f"tcp.port=={transport}", "-T", "fields"]
    for field in FIELDS:
        command.extend(("-e", field))
    output = subprocess.check_output(command, text=True)
    packets = list(csv.DictReader(output.splitlines(), fieldnames=FIELDS, delimiter="\t"))
    for p in packets:
        require({p["ip.src"], p["ip.dst"]} == {A, B}, "Unexpected endpoints or non-IPv4 frame")
        require(p["frame.cap_len"] == p["frame.len"], "Truncated frame")
        require(p["ip.frag_offset"] == "0" and p["ip.flags.mf"] in ("0", "False"),
                "Fragments require reassembly before port-based classification")
        p["t"] = Decimal(p["frame.time_relative"])
        p["bytes"] = int(p["ip.len"])
    return packets


def review_capture(path, tshark):
    raw = path.read_bytes()
    magics = ("a1b2c3d4", "d4c3b2a1", "a1b23c4d", "4d3cb2a1")
    require(raw[:4].hex() in magics, "Expected standard pcap without embedded key-log blocks")
    require(all(marker not in raw.lower() for marker in
                (b"a=crypto:", b"inline:", b"private key-----", b"client_random ")),
            "Sensitive marker detected; hold this capture for review")
    # Request frame numbers only. Never export credential values.
    suspect = ('sip.Authorization || sip.Proxy-Authorization || sdp.crypto.crypto_suite || '
               'sdp.media_attribute.field == "crypto"')
    matches = subprocess.check_output([tshark, "-n", "-r", str(path), "-Y", suspect,
                                       "-T", "fields", "-e", "frame.number"], text=True)
    require(not matches.strip(), "Readable authorization or SDES field; hold this capture for review")
    return hashlib.sha256(raw).hexdigest()


def utc(packet):
    stamp = Decimal(packet["frame.time_epoch"])
    dt = datetime.fromtimestamp(int(stamp), timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f"{stamp % 1:.6f}"[1:] + "Z"


def is_audio_pair(p, ports, offset=0):
    if not p["udp.srcport"]:
        return False
    return (int(p["udp.srcport"]) == ports[p["ip.src"]] + offset and
            int(p["udp.dstport"]) == ports[p["ip.dst"]] + offset)


def is_retry(p):
    return any(p[k] for k in FIELDS if k.startswith("tcp.analysis."))


def handshake_values(packets, field):
    return {v for p in packets for v in p[field].split(",") if v}


def check_dialog(sig, secure, call_id, media_start):
    early = [p for p in sig if p["t"] < media_start]
    if secure:
        require(all(not p["sip.Call-ID"] for p in sig), "Readable SIP in secure capture")
        for sender, types in [(A, {"1", "11"}), (B, {"2", "11", "13"})]:
            leg = [p for p in early if p["ip.src"] == sender]
            require(types <= handshake_values(leg, "tls.handshake.type"), "Missing TLS 1.2 certificate exchange")
            require("23" in handshake_values(leg, "tls.record.content_type"), "Missing encrypted signaling before audio")
    else:
        require({p["sip.Call-ID"] for p in sig if p["sip.Call-ID"]} == {call_id}, "SIP Call-ID mismatch")
        require(any(p["sip.Method"] == "INVITE" for p in early), "Missing INVITE")
        require(any(p["sip.Status-Code"] == "200" and p["sip.CSeq.method"] == "INVITE" for p in early),
                "Missing successful INVITE response before first audio")
        require(any(p["sip.Method"] == "BYE" for p in sig) and
                any(p["sip.Status-Code"] == "200" and p["sip.CSeq.method"] == "BYE" for p in sig),
                "Incomplete SIP hangup")


def header_audit(media):
    require(all(p["rtp.version"] == "2" and p["rtp.p_type"] == "0" and p["rtp.cc"] == "0"
                and p["rtp.ext"] in ("False", "0") and p["rtp.padding"] in ("False", "0")
                and p["ip.hdr_len"] == "20" for p in media), "Unexpected media header or payload type")
    require(len({p["rtp.ssrc"] for p in media}) == 1, "More than one stream per sender")
    steps, gaps = [], 0
    for previous, current in zip(media, media[1:]):
        if (int(current["rtp.seq"]) - int(previous["rtp.seq"])) % 65536 == 1:
            steps.append((int(current["rtp.timestamp"]) - int(previous["rtp.timestamp"])) % 2**32)
        else:
            gaps += 1
    require(steps, "Too few consecutive media packets")
    return stats.median(steps), sum(s != 160 for s in steps), gaps


def measure(run, directory, tshark, offset, stop):
    mode = run.split("-")[0]
    secure = mode == "secure"
    cap = directory / "captures" / f"{run}.pcap"
    log = (directory / "logs" / f"{run}.log").read_text()
    call_id, ports = call_info(run, log, secure)
    counters = (directory / "logs" / f"{run}.tcpdump").read_text()
    drops = re.findall(r"(\d+) packets? dropped by kernel", counters)
    require(len(drops) == 1, "Missing tcpdump kernel drop count")
    packets = read_capture(tshark, cap, ports[A], secure)
    saved = re.search(r"(\d+) packets? captured", counters)
    require(saved and int(saved[1]) == len(packets), "tcpdump capture count differs from saved packets")
    audio = [p for p in packets if is_audio_pair(p, ports)]
    control = [p for p in packets if is_audio_pair(p, ports, 1)]
    tcp = [p for p in packets if p["tcp.stream"]]
    sigport = "5061" if secure else "5060"
    require(len({p["tcp.stream"] for p in tcp}) == 1 and
            all(sigport in (p["tcp.srcport"], p["tcp.dstport"]) for p in tcp), "Unexpected TCP stream")
    syn = [p for p in tcp if p["tcp.flags.syn"] in ("True", "1") and p["tcp.flags.ack"] in ("False", "0")]
    require(syn and syn[0] == tcp[0] and syn[0]["ip.src"] == A, "Missing cold outbound SYN")
    require(audio and syn[0]["t"] < audio[0]["t"], "Inconsistent setup order or missing audio")
    first = audio[0]
    check_dialog(tcp, secure, call_id, first["t"])
    start, end = first["t"] + offset, first["t"] + stop
    duration = float(end - start)
    signaling = [p for p in tcp if syn[0]["t"] <= p["t"] < first["t"]]
    window = [p for p in audio if start <= p["t"] < end]
    extra = len(packets) - len(audio) - len(control) - len(tcp)
    require(extra == 0, "Unexpected UDP tuple or non-TCP/UDP packet")
    require(any(p["t"] > end for p in tcp), "No captured signaling after the steady window")
    if secure:
        # A completed dialplan and these encrypted records corroborate teardown.
        # TLS record boundaries do not identify the SIP BYE or its response.
        for src in (A, B):
            require(any(p["ip.src"] == src and "23" in p["tls.record.content_type"].split(",")
                        and p["t"] >= audio[-1]["t"] - 1 for p in tcp),
                    "Missing late TLS application data in a direction")
    rows, notes = [], []
    if int(drops[0]):
        notes.append(f"tcpdump kernel drop counter {drops[0]}")
    audits = {}
    for name, src in DIRECTIONS.items():
        data = [p for p in window if src is None or p["ip.src"] == src]
        setup = [p for p in signaling if src is None or p["ip.src"] == src]
        require(data, f"No steady audio in {name}")
        if src:
            stream = [p for p in audio if p["ip.src"] == src]
            require(stream[0]["t"] < start and stream[-1]["t"] >= end, f"Audio does not span window for {name}")
            ticks, other_steps, gaps = header_audit(data)
            audits[src] = (stream[0]["rtp.ssrc"], ticks, other_steps, gaps)
            if gaps or other_steps:
                notes.append(f"{name}: {gaps} adjacent sequence discontinuities, {other_steps} timestamp steps other than 160")
        sizes = [p["bytes"] for p in data]
        rows.append(dict(run=run, mode=mode, direction=name, setup_bytes=sum(p["bytes"] for p in setup),
                         setup_packets=len(setup), media_packets=len(data), media_bytes=sum(sizes),
                         packets_s=len(data)/duration, typical_ip_bytes=stats.median(sizes),
                         min_ip_bytes=min(sizes), max_ip_bytes=max(sizes), mean_kbps=sum(sizes)*8/duration/1000))
    rtcp = [p for p in control if start <= p["t"] < end]
    retries = sum(is_retry(p) for p in tcp)
    if retries:
        notes.append(f"{retries} TCP retransmission indications over entire capture")
    late = [p for p in tcp if start <= p["t"] < end]
    meta = dict(run=run, mode=mode, capture=cap.name, sha256=review_capture(cap, tshark),
                capture_format="pcap", readable_auth_or_crypto_frames=0,
                call_id=call_id, ip_a=A, port_a=ports[A], ip_b=B, port_b=ports[B],
                ssrc_a=audits[A][0], ssrc_b=audits[B][0], tcp_stream=tcp[0]["tcp.stream"],
                syn_utc=utc(syn[0]), first_audio_utc=utc(first), last_frame_utc=utc(packets[-1]),
                syn_frame=syn[0]["frame.number"], first_audio_frame=first["frame.number"],
                syn_s=syn[0]["t"], first_audio_s=first["t"], setup_duration_s=first["t"]-syn[0]["t"],
                steady_start_s=start, steady_end_s=end, audio_span_s=audio[-1]["t"]-first["t"],
                timestamp_step_a=audits[A][1], timestamp_step_b=audits[B][1],
                rtcp_packets_in_window=len(rtcp), rtcp_ip_bytes_in_window=sum(p["bytes"] for p in rtcp),
                tcp_packets_in_window=len(late), tcp_bytes_in_window=sum(p["bytes"] for p in late),
                setup_retransmission_indications=sum(is_retry(p) for p in signaling),
                total_retransmission_indications=retries, tcpdump_kernel_drops=drops[0],
                connection="cold", anomalies="; ".join(notes) or "none detected")
    for event in ("started", "finished"):
        stamp = re.search(rf"^call_command_{event}_utc=(\S+)", log, re.MULTILINE)
        meta[f"call_command_{event}_utc"] = stamp[1] if stamp else ""
    meta["setup_filter"] = (f"tcp.stream == {meta['tcp_stream']} && frame.time_relative >= {meta['syn_s']:f} "
                            f"&& frame.time_relative < {first['t']:f}")
    meta["steady_filter"] = (
        f"((ip.src == {A} && udp.srcport == {ports[A]} && udp.dstport == {ports[B]}) || "
        f"(ip.src == {B} && udp.srcport == {ports[B]} && udp.dstport == {ports[A]})) "
        f"&& frame.time_relative >= {start} && frame.time_relative < {end}"
    )
    return rows, meta


def save(path, data):
    with path.open("w", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=data[0], lineterminator="\n")
        writer.writeheader()
        for row in data:
            result = dict(row)
            for key, value in row.items():
                if isinstance(value, float):
                    result[key] = round(value, 6)
                elif isinstance(value, Decimal):
                    result[key] = format(value, "f")
            writer.writerow(result)


def summaries(rows):
    summary, deltas = [], []
    for direction in DIRECTIONS:
        for metric in METRICS:
            means = {}
            for mode in ("plain", "secure"):
                sample = [r[metric] for r in rows if r["direction"] == direction and r["mode"] == mode]
                if sample:
                    means[mode] = stats.mean(sample)
                    summary.append(dict(mode=mode, direction=direction, metric=metric, n=len(sample),
                                        mean=means[mode], min=min(sample), max=max(sample),
                                        sd=stats.stdev(sample) if len(sample)>1 else ""))
            if len(means) == 2:
                change = means["secure"] - means["plain"]
                deltas.append(dict(direction=direction, metric=metric, plain_mean=means["plain"],
                                   secure_mean=means["secure"], absolute_change=change,
                                   percent_change=100*change/means["plain"]))
    return summary, deltas


def paired_differences(rows):
    """Compare adjacent acquisition pairs by trial number, preserving direction."""
    indexed = {(r["run"], r["direction"]): r for r in rows}
    output = []
    for plain in rows:
        if plain["mode"] != "plain":
            continue
        index = plain["run"].split("-")[1]
        secure = indexed.get((f"secure-{index}", plain["direction"]))
        if secure:
            for metric in METRICS:
                delta = secure[metric] - plain[metric]
                output.append(dict(trial=index, direction=plain["direction"], metric=metric,
                                   plain_value=plain[metric], secure_value=secure[metric],
                                   absolute_change=delta, percent_change=100*delta/plain[metric]))
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment", type=Path, default=ROOT / "experiment")
    parser.add_argument("--out", type=Path, default=ROOT / "site/data")
    parser.add_argument("--tshark", default=shutil.which("tshark") or str(ROOT / ".lab/bin/tshark"))
    parser.add_argument("--start", default=5, type=Decimal, help="steady window start, seconds after first audio")
    parser.add_argument("--end", default=55, type=Decimal, help="exclusive steady window end, seconds after first audio")
    parser.add_argument("runs", nargs="*", default=[f"{m}-{i}" for m in ("plain","secure") for i in range(1,4)])
    args = parser.parse_args()
    require(0 < args.start < args.end, "Need 0 < window start < window end")
    require(len(set(args.runs)) == len(args.runs), "Duplicate run name")
    rows, meta = [], []
    for run in args.runs:
        require(re.fullmatch(r"(plain|secure)-\d+", run), f"Unknown run name: {run}")
        try:
            measurements, record = measure(run, args.experiment, args.tshark, args.start, args.end)
        except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
            parser.exit(1, f"{run}: {exc}\n")
        rows.extend(measurements)
        meta.append(record)
    require(len(set(r["call_id"] for r in meta)) == len(meta), "Repeated Call-ID across runs")
    meta.sort(key=lambda record: record["syn_utc"])
    for order, record in enumerate(meta, 1):
        record["trial_order"] = order
    args.out.mkdir(exist_ok=True, parents=True)
    summary, deltas = summaries(rows)
    outputs = (("results", rows), ("runs", meta), ("summary", summary),
               ("differences", deltas), ("paired-changes", paired_differences(rows)))
    for name, records in outputs:
        if records:
            save(args.out / f"{name}.csv", records)
        elif (args.out / f"{name}.csv").exists():
            (args.out / f"{name}.csv").unlink()
    print(f"Analyzed {len(meta)} calls; CSV files written to {args.out}")


if __name__ == "__main__":
    main()
