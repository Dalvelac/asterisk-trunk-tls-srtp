"""Export a plaintext PCMU excerpt for the report. Usage: python3 website/tones.py."""
import argparse
import array
import shutil
import subprocess
import sys
import wave
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.ticker import MultipleLocator

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "site/assets"

def decode(octet):
    value = (~octet) & 255
    magnitude = (((value & 15) << 3) + 132) << ((value >> 4) & 7)
    return 132 - magnitude if value & 128 else magnitude - 132

def samples(capture, addr):
    tshark = shutil.which("tshark") or str(ROOT / ".lab/bin/tshark")
    cmd = [tshark, "-n", "-r", str(capture), "-Y",
           f"ip.src == {addr} && rtp.p_type == 0", "-T", "fields",
           "-e", "rtp.seq", "-e", "rtp.payload"]
    rows = subprocess.check_output(cmd, text=True).splitlines()[50:150]
    seqs, chunks = zip(*(row.split("\t") for row in rows))
    if len(rows) != 100 or any((int(b)-int(a)) % 65536 != 1 for a,b in zip(seqs, seqs[1:])):
        raise ValueError("The selected RTP excerpt must contain 100 consecutive PCMU packets.")
    payload = bytes.fromhex("".join(chunks).replace(":", ""))
    if len(payload) != 16000:
        raise ValueError("Expected two seconds of PCMU samples.")
    return array.array("h", (decode(byte) for byte in payload))

def render(capture):
    plt.rcParams.update({"axes.facecolor":"#173b54", "figure.facecolor":"#173b54"})
    font_manager.fontManager.addfont(DEST / "instrument-sans.ttf")
    plt.rcParams["font.family"] = "Instrument Sans"
    fig, axes = plt.subplots(2, 1, figsize=(6.3, 2.8), sharex=True)
    fig.subplots_adjust(left=.105,right=.97,top=.96,bottom=.19,hspace=.17)
    for node, octet, color, ax in zip(("a","b"), (10,11), ("#9cecdd","#b5d4ff"), axes):
        values = samples(capture, f"172.30.76.{octet}")
        with wave.open(str(DEST / f"tone-{node}.wav"), "wb") as wav:
            wav.setparams((1, 2, 8000, 0, "NONE", "not compressed"))
            pcm = values[:]
            if sys.byteorder != "little":
                pcm.byteswap()
            wav.writeframes(pcm.tobytes())
        ax.plot([j/8 for j in range(81)], [v/32768 for v in values[:81]], color=color,
                linewidth=1.75, solid_capstyle="round")
        ax.set_xlim(0, 10)
        ax.set_ylim(-.34,.34)
        ax.set_yticks([-.25, 0, .25])
        ax.set_yticklabels(["−0.25", "0", "0.25"])
        ax.set_axisbelow(True)
        ax.xaxis.set_major_locator(MultipleLocator(2))
        ax.xaxis.set_minor_locator(MultipleLocator(.5))
        ax.grid(which="major", color="#577587", linewidth=.7)
        ax.grid(which="minor", axis="x", color="#2f556d", linewidth=.45)
        ax.spines[:].set_visible(False)
        ax.tick_params(colors="#cedce6", labelsize=10, length=0, pad=6)
        ax.tick_params(which="minor",length=0)
    axes[-1].set_xlabel("Time (ms)", color="#cedce6", fontsize=10)
    fig.savefig(DEST / "tone-traces.png", dpi=170)
    plt.close(fig)

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, nargs="?", default=ROOT/"experiment/captures/plain-1.pcap")
    render(parser.parse_args().capture)
