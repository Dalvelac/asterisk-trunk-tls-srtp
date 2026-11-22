#!/usr/bin/env python3
"""Prepare two media-only pcapng interfaces with first audio at the same time."""
import argparse
from decimal import Decimal
from pathlib import Path
import re
import subprocess
import tempfile


def command(*args):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE).stdout


def first_time(file):
    rows = command("tshark", "-n", "-r", file, "-c", "1", "-T", "fields",
                   "-e", "frame.time_epoch").splitlines()
    if not rows:
        raise ValueError(f"Empty media extract {file}")
    return Decimal(rows[0])


def extract(root, mode, trial, output):
    stem = f"{mode}-{trial}"
    log = (root / "logs" / f"{stem}.log").read_text()
    # The B-channel's remote address belongs to A, and vice versa.
    ports = {}
    for peer, ip, port in re.findall(r"^pbx-([ab]) .*? remote=([0-9.]+):(\d+) ", log, re.M):
        ports[peer] = (ip, int(port))
    b, a = ports["a"], ports["b"]
    directions = [
        f"(ip.src == {src[0]} && ip.dst == {dst[0]} && "
        f"udp.srcport == {src[1]} && udp.dstport == {dst[1]})"
        for src, dst in [(a, b), (b, a)]
    ]
    filt = " || ".join(directions)
    print(f"{stem}: {filt}")
    command("tshark", "-n", "-r", root / "captures" / f"{stem}.pcap",
            "-Y", filt, "-F", "pcapng", "-w", output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiment", type=Path, help="Directory containing captures/ and logs/")
    parser.add_argument("output", type=Path, help="New .pcapng for the graph only")
    parser.add_argument("--trial", type=int, default=1)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output already exists. Choose a new file.")
    with tempfile.TemporaryDirectory() as directory:
        tmp = Path(directory)
        plain, secure, shifted = (tmp / (n + ".pcapng") for n in ("plain", "secure", "shifted"))
        extract(args.experiment, "plain", args.trial, plain)
        extract(args.experiment, "secure", args.trial, secure)
        delay = first_time(plain) - first_time(secure)
        print(f"Secure timestamps shifted by {delay} s in graph copy only")
        command("editcap", "-t", str(delay), secure, shifted)
        if first_time(plain) != first_time(shifted):
            raise ValueError("Media time origins differ after alignment.")
        command("mergecap", "-I", "none", "-w", args.output, plain, shifted)
    print("Graph interfaces: 0 = plain, 1 = secure. Both start at M = 0.")


if __name__ == "__main__":
    main()
