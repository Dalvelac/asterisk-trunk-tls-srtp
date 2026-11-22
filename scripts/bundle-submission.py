#!/usr/bin/env python3
"""Check the static site and create a public build and a separate editable project."""
import csv
from html.parser import HTMLParser
from pathlib import Path
import tarfile
from urllib.parse import unquote, urlsplit
from zipfile import ZipFile, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"

class Report(HTMLParser):
    def __init__(self):
        super().__init__()
        self.targets = []
        self.ids = set()
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        for key in ("href", "src"):
            if key in attrs:
                self.targets.append(attrs[key])
        if "id" in attrs:
            self.ids.add(attrs["id"])

def pack(name, paths, base):
    with ZipFile(ROOT / name, "w", ZIP_DEFLATED) as output:
        for path in sorted(set(paths)):
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Expected regular file: {path}")
            output.write(path, path.relative_to(base))
    with ZipFile(ROOT / name) as archive:
        if archive.testzip():
            raise ValueError(f"Invalid CRC in {name}")

def main():
    site_files = [p for p in SITE.rglob("*") if p.is_file()]
    html = (SITE / "index.html").read_text()
    report = Report()
    report.feed(html)
    for target in report.targets:
        url = urlsplit(target)
        if url.scheme in ("http", "https"):
            continue
        if url.path:
            local = SITE / unquote(url.path)
            if local.resolve() not in site_files:
                raise ValueError(f"Missing site file: {target}")
        elif url.fragment and url.fragment not in report.ids:
            raise ValueError(f"Missing section: {target}")
    rows = list(csv.DictReader((SITE / "data/results.csv").read_text().splitlines()))
    if len(rows) != 18 or "@@" in html:
        raise ValueError("Incomplete measured report")
    pack("submission-site.zip", site_files, SITE)
    # The private source handoff includes the supplied brief and recorded evidence.
    # Use the reviewed archives' explicit inventories to avoid collecting local state.
    with tarfile.open(SITE / "downloads/lab-source.tar.gz") as lab:
        project = [ROOT / member for member in lab.getnames()]
    for name in ["run-logs.zip", "captures.zip"]:
        with ZipFile(SITE / "downloads" / name) as evidence:
            project += [ROOT / member for member in evidence.namelist()]
    brief = ROOT / "VoIP_zadani_projektu.pdf"
    if brief.is_file():
        project.append(brief)
    for name in ["HANDOFF.md", "experiment/verification.txt",
                 "scripts/package-submission.py", "scripts/bundle-submission.py",
                 "website/page.html", "website/build.py", "website/tones.py"]:
        project.append(ROOT / name)
    pack("submission-source.zip", project + site_files, ROOT)
    print("Verified the local site references and both ZIP archives.")

if __name__ == "__main__":
    main()
