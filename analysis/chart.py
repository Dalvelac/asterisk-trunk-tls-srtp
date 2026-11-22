#!/usr/bin/env python3
"""Render the two summary measures directly from results.csv."""
import argparse
import csv
from pathlib import Path
from statistics import mean

import matplotlib as mpl
mpl.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator, StrMethodFormatter

ROOT = Path(__file__).resolve().parents[1]
COLORS = {"plain": "#0f6865", "secure": "#2c5589"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=ROOT / "site/data")
    data = parser.parse_args().data
    with (data / "results.csv").open(encoding="utf-8", newline="") as source:
        records = [r for r in csv.DictReader(source) if r["direction"] == "combined"]
    mpl.rcParams.update({"svg.fonttype": "none", "svg.hashsalt": "vsb-trunk",
                         "font.size": 11, "text.color": "#172d36", "axes.labelcolor": "#172d36"})
    fig, axes = plt.subplots(2, 1, figsize=(8.7, 5.6))
    fig.subplots_adjust(left=.145, right=.95, top=.92, bottom=.14, hspace=1.10)
    panels = [
        ("setup_bytes", "Cold signaling setup", "IPv4 bytes per new call, both directions", ",.1f"),
        ("mean_kbps", "Steady audio", "IPv4 kilobits per second, both directions", ".3f"),
    ]
    for ax, (metric, title, xlabel, fmt) in zip(axes, panels):
        maximum = max(float(r[metric]) for r in records)
        for y, mode in enumerate(COLORS):
            values = [float(r[metric]) for r in records if r["mode"] == mode]
            average = mean(values)
            ax.barh(y, average, color=COLORS[mode], height=.46, zorder=2)
            # Offset each trial vertically so identical values remain visible.
            for i, value in enumerate(values):
                stagger = (i - (len(values)-1)/2) * .11
                ax.scatter(value, y+stagger, s=20, color="white", edgecolors=COLORS[mode], zorder=3)
            ax.text(max(values) + .024*maximum, y, format(average, fmt), ha="left", va="center",
                    color=COLORS[mode], weight="bold")
        ax.set(xlim=(0, 1.22*maximum), ylim=(1.45, -.45), yticks=[0, 1], yticklabels=["Baseline", "Secure"])
        ax.set_title(title, loc="left", fontsize=14, weight="bold", pad=8)
        ax.set_xlabel(xlabel, fontsize=10)
        ax.xaxis.set_major_formatter(StrMethodFormatter("{x:,.0f}"))
        ax.xaxis.set_major_locator(MaxNLocator(nbins=6, min_n_ticks=3))
        ax.xaxis.grid(True, color="#d5dfe1", linewidth=.7)
        ax.tick_params(axis="both", labelsize=10, length=0, pad=5)
        for edge, spine in ax.spines.items():
            spine.set_visible(edge == "bottom")
            spine.set_color("#99a9aa")
    fig.text(.145, .025, "Bar and label = across-call mean.  Each dot = one measured call.",
             color="#52646b", fontsize=10)
    fig.savefig(data / "comparison.svg", metadata={"Date": None,
                "Title": "Cold signaling setup and steady audio by trunk protection mode",
                "Description": "Two zero-based horizontal bar charts. Numeric values are in results.csv."})
    plt.close(fig)


if __name__ == "__main__":
    main()
