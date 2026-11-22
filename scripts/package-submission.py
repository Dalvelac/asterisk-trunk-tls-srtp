#!/usr/bin/env python3
"""Refresh the public downloads from explicit laboratory sources and reviewed evidence."""
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
RUNS = [f"{mode}-{i}" for i in (1, 2, 3) for mode in ("plain", "secure")]
DOWNLOADS = ROOT / "site/downloads"

def write_zip(destination, members):
    with ZipFile(destination, "w", compression=ZIP_DEFLATED) as archive:
        for member in members:
            archive.write(ROOT / member, member)

def main():
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    pcaps = [f"experiment/captures/{run}.pcap" for run in RUNS]
    logs = [f"experiment/logs/{run}.{ext}" for run in RUNS for ext in ("log", "status", "tcpdump")]
    smoke = ["smoke/plain.pcap", "smoke/secure.pcap"]
    review = subprocess.check_output([sys.executable, "experiment/review-captures.py", *pcaps, *smoke],
                                     text=True, cwd=ROOT)
    records = json.loads(review)
    # Compare measured handshake certificates with the independent live OpenSSL checks.
    verification = (ROOT / "experiment/verification.txt").read_text()
    verified = verification.lower().replace(":", "")
    for record in records:
        if record["file"] in pcaps:
            for digest in record["peer_certificate_sha256"].values():
                if digest not in verified:
                    raise ValueError("Capture and live certificate evidence differ")
    manifest = "experiment/capture-review.json"
    (ROOT / manifest).write_text(review)
    write_zip(DOWNLOADS / "captures.zip", [*pcaps, manifest])
    write_zip(DOWNLOADS / "run-logs.zip", logs)
    shutil.copyfile(ROOT / "experiment/verification.txt", DOWNLOADS / "verification.txt")
    shutil.copyfile(ROOT / "experiment/REPRODUCE.md", DOWNLOADS / "reproduce.md")
    source = ["README.md", "lab", ".gitignore", "compose.yaml", "docker/Dockerfile", "docker/start",
              "scripts/make-certs", *smoke, "experiment/record.sh", "experiment/verify-security.sh",
              "experiment/policy.compose.yaml", "experiment/verify-policy.c", "experiment/review-captures.py",
              "experiment/REPRODUCE.md", "analysis/measure.py", "analysis/chart.py", "analysis/README.md"]
    source += sorted(str(p.relative_to(ROOT)) for p in (ROOT / "starter").rglob("*.conf"))
    with tarfile.open(DOWNLOADS / "lab-source.tar.gz", "w:gz") as archive:
        for member in source:
            archive.add(ROOT / member, arcname=member, recursive=False)
    for name in ("captures.zip", "run-logs.zip", "lab-source.tar.gz"):
        print(hashlib.sha256((DOWNLOADS / name).read_bytes()).hexdigest(), name)

if __name__ == "__main__":
    main()
