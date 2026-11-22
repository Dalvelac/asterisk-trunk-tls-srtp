#!/usr/bin/env python3
"""Review the original laboratory pcaps before copying them into public archives."""
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TSHARK = shutil.which("tshark") or str(ROOT / ".lab/bin/tshark")
HOSTS = {"172.30.76.10": "pbx-a.lab.test", "172.30.76.11": "pbx-b.lab.test"}
SECRET = re.compile(rb"(?im)(-----BEGIN .*PRIVATE KEY-----|a=crypto:|inline:[A-Za-z0-9+/]{12}|(?:^|\n)(?:Proxy-)?Authorization:|CLIENT_RANDOM [0-9a-f]+|TRAFFIC_SECRET_0 )")

def require(condition, message):
    if not condition:
        raise ValueError(message)

def review(path):
    content = path.read_bytes()
    require(content[:4].hex() in {"d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d"}, "Expected classic pcap")
    require(not SECRET.search(content), "A secret marker was detected")
    secure = path.stem.startswith("secure")
    port = "5061" if secure else "5060"
    def tshark(*args):
        return subprocess.check_output([TSHARK, "-n", "-r", str(path), *args], text=True)
    peers = set(HOSTS)
    rows = tshark("-T", "fields", *[arg for field in
        "ip.src ip.dst tcp.srcport tcp.dstport udp.srcport udp.dstport tcp.stream frame.len frame.cap_len".split()
        for arg in ("-e", field)]).splitlines()
    for row in rows:
        src, dst, ts, td, us, ud, stream, length, captured = row.split("\t")
        require({src, dst} == peers and length == captured, "Unexpected endpoints or truncated frame")
        require((port in (ts, td) and stream == "0") if ts else
                10000 <= int(us) <= 10039 and 10000 <= int(ud) <= 10039, "Unexpected transport")
    streams = [bytearray(), bytearray()]
    for line in tshark("-q", "-z", "follow,tcp,raw,0").splitlines():
        if re.fullmatch(r"\t?(?:[a-fA-F0-9]{2})+", line):
            streams[int(line.startswith("\t"))].extend(bytes.fromhex(line.strip()))
    require(all(streams) and not any(SECRET.search(s) for s in streams), "Check reassembled signaling")
    certs = {}
    if secure:
        require(not any(b"SIP/2.0" in s for s in streams), "Clear SIP in TLS capture")
        for row in tshark("-d", "tcp.port==5061,tls", "-Y", "tls.handshake.certificate", "-T", "fields",
                          "-e", "ip.src", "-e", "tls.handshake.certificate").splitlines():
            src, values = row.split("\t")
            for i, value in enumerate(values.split(",")):
                der = bytes.fromhex(value.replace(":", ""))
                names = subprocess.check_output(["openssl", "x509", "-inform", "DER", "-noout",
                    "-nameopt", "RFC2253", "-subject", "-issuer"], input=der).decode().splitlines()
                subject = HOSTS[src] if i == 0 else "VSB VoIP disposable lab CA"
                require(names == ["subject=CN=" + subject, "issuer=CN=VSB VoIP disposable lab CA"],
                        "Unexpected certificate identity in capture")
                if i == 0:
                    certs[subject] = hashlib.sha256(der).hexdigest()
        require(set(certs) == set(HOSTS.values()), "Missing peer certificates in handshake")
    else:
        require(b"INVITE sip:200@" in streams[0] and b"RTP/AVP 0" in streams[0]
                and b"RTP/AVP 0" in streams[1] and b"BYE " in streams[0]+streams[1],
                "Expected one lab tone call")
    return dict(file=str(path), sha256=hashlib.sha256(content).hexdigest(), frames=len(rows),
                peer_certificate_sha256=certs, review="passed")

if __name__ == "__main__":
    paths = [Path(arg) for arg in sys.argv[1:]]
    if not paths:
        sys.exit("Usage: python3 experiment/review-captures.py FILE.pcap [...]")
    print(json.dumps([review(path) for path in paths], indent=2))
