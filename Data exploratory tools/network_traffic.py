"""
VLAN ID 0 Packet Rate Plot  —  Corporate Light Theme  (Batch Mode)
Two lines per figure:
  - Priority 4      : frames with PCP == 4
  - Priority 4 + 0  : frames with PCP == 4 OR PCP == 0

Batch usage (processes every .pcapng / .pcap in a folder):
    python vlan0_plot_corporate.py --dir "../Data/pcap-files"

Single-file usage (original behaviour):
    python vlan0_plot_corporate.py --file capture.pcapng
    python vlan0_plot_corporate.py --file capture.pcapng --bin-ms 50

Output PNGs are written next to each source file unless --out-dir is supplied:
    python vlan0_plot_corporate.py --dir /path/to/captures --out-dir /path/to/plots

Dependencies:
    pip install scapy matplotlib pandas
"""

import sys
import argparse
from pathlib import Path

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib.lines import Line2D
from scapy.all import rdpcap, Dot1Q, conf

conf.verb = 0

# ── Palette ────────────────────────────────────────────────────────────────
C_BG       = "#ffffff"
C_PLOT_BG  = "#f8f9fb"
C_GRID     = "#e4e7ed"
C_SPINE    = "#d1d5db"
C_TICK     = "#6b7280"
C_LABEL    = "#374151"
C_TITLE    = "#111827"
C_SUBTITLE = "#6b7280"
C_PRIO4    = "#1d4ed8"   # deep blue
C_PRIO4_0  = "#0ea5e9"   # sky blue


# ── Data loading ───────────────────────────────────────────────────────────

def load_vlan0(path: Path) -> pd.DataFrame | None:
    """Return a DataFrame of VLAN-ID-0 frames, or None if none are found."""
    print(f"  [*] Reading: {path.name}")
    try:
        packets = rdpcap(str(path))
    except Exception as exc:
        print(f"  [!] Could not read {path.name}: {exc}")
        return None

    print(f"  [*] Total packets: {len(packets)}")

    rows = []
    for pkt in packets:
        if not pkt.haslayer(Dot1Q):
            continue
        if pkt[Dot1Q].vlan != 0:
            continue
        rows.append({
            "timestamp": float(pkt.time),
            "pcp":       pkt[Dot1Q].prio,
        })

    if not rows:
        print("  [!] No VLAN ID 0 frames found — skipping.")
        return None

    df = pd.DataFrame(rows)
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)
    print(f"  [*] VLAN-0 frames: {len(df)}  "
          f"(PCP 4: {(df['pcp']==4).sum()}  PCP 0: {(df['pcp']==0).sum()})")
    return df


# ── Plotting ───────────────────────────────────────────────────────────────

def plot_traffic(df: pd.DataFrame, output_path: Path, bin_ms: int,
                 source_name: str = "") -> None:
    start    = df["timestamp"].min()
    end      = df["timestamp"].max()
    duration = end - start

    if duration == 0:
        bin_s = 0.001
    elif duration < 0.5:
        bin_s = duration / 50
    elif duration < 5:
        bin_s = 0.05
    else:
        bin_s = bin_ms / 1000.0

    n_bins = max(2, int(duration / bin_s))
    df = df.copy()
    df["bin"] = ((df["timestamp"] - start) / bin_s).astype(int).clip(upper=n_bins - 1)

    all_bins = pd.RangeIndex(n_bins)
    prio4    = df[df["pcp"] == 4].groupby("bin").size().reindex(all_bins, fill_value=0)
    prio4_0  = df[df["pcp"].isin([4, 0])].groupby("bin").size().reindex(all_bins, fill_value=0)

    if duration < 1.0:
        xs     = all_bins * bin_s * 1000
        xlabel = "Time (ms)"
    elif duration < 60:
        xs     = all_bins * bin_s
        xlabel = "Time (s)"
    else:
        xs     = all_bins * bin_s / 60
        xlabel = "Time (min)"

    # ── Figure ────────────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(14, 5))
    fig.patch.set_facecolor(C_BG)
    ax.set_facecolor(C_PLOT_BG)

    ax.fill_between(xs, prio4_0.values, alpha=0.12, color=C_PRIO4_0)
    ax.plot(xs, prio4_0.values, color=C_PRIO4_0, linewidth=1.8)

    ax.fill_between(xs, prio4.values, alpha=0.18, color=C_PRIO4)
    ax.plot(xs, prio4.values, color=C_PRIO4, linewidth=1.8)

    # ── Spines ────────────────────────────────────────────────────────────
    for side, spine in ax.spines.items():
        if side in ("top", "right"):
            spine.set_visible(False)
        else:
            spine.set_edgecolor(C_SPINE)
            spine.set_linewidth(0.8)

    # ── Ticks and labels ──────────────────────────────────────────────────
    ax.tick_params(colors=C_TICK, labelsize=9, length=3, width=0.8)
    ax.set_xlabel(xlabel, color=C_LABEL, fontsize=10, labelpad=8)
    ax.set_ylabel("Packets / bin", color=C_LABEL, fontsize=10, labelpad=8)
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True, nbins=6))

    # ── Grid ──────────────────────────────────────────────────────────────
    ax.grid(axis="y", color=C_GRID, linewidth=0.7, zorder=0)
    ax.grid(axis="x", color=C_GRID, linewidth=0.4, zorder=0)
    ax.set_axisbelow(True)

    # ── Title — includes source filename ─────────────────────────────────
    title_text = "VLAN ID 0  —  Packet Rate by Priority Class"
    if source_name:
        title_text += f"   |   {source_name}"
    ax.set_title(title_text, color=C_TITLE, fontsize=12, fontweight="bold",
                 pad=16, loc="left")

    subtitle = (
        f"Total VLAN-0 frames: {len(df)}"
        f"    PCP 4: {(df['pcp']==4).sum()}"
        f"    PCP 0: {(df['pcp']==0).sum()}"
        f"    Duration: {duration:.3f} s"
        f"    Bin: {bin_s*1000:.1f} ms"
    )
    ax.annotate(subtitle, xy=(0, 1.01), xycoords="axes fraction",
                fontsize=8, color=C_SUBTITLE)

    # ── Legend ────────────────────────────────────────────────────────────
    legend_elements = [
        Line2D([0], [0], color=C_PRIO4_0, linewidth=2,
               label="Priority 4 + 0  (PCP 4 or 0)"),
        Line2D([0], [0], color=C_PRIO4,   linewidth=2,
               label="Priority 4  (PCP 4 only)"),
    ]
    ax.legend(handles=legend_elements, loc="upper right",
              framealpha=1.0, facecolor=C_BG, edgecolor=C_SPINE,
              labelcolor=C_LABEL, fontsize=9)

    plt.tight_layout(pad=1.4)
    fig.savefig(str(output_path), dpi=180, bbox_inches="tight", facecolor=C_BG)
    print(f"  [*] Saved: {output_path}")
    plt.close(fig)


# ── Batch helper ───────────────────────────────────────────────────────────

def process_directory(input_dir: Path, out_dir: Path | None, bin_ms: int) -> None:
    patterns = ["*.pcapng", "*.pcap"]
    files = sorted(f for p in patterns for f in input_dir.glob(p))

    if not files:
        print(f"[!] No .pcapng or .pcap files found in: {input_dir}")
        sys.exit(1)

    print(f"[*] Found {len(files)} capture file(s) in: {input_dir}\n")

    ok, skipped = 0, 0
    for pcap_path in files:
        print(f"[+] Processing: {pcap_path.name}")
        df = load_vlan0(pcap_path)
        if df is None:
            skipped += 1
            print()
            continue

        dest_dir = out_dir if out_dir else pcap_path.parent
        dest_dir.mkdir(parents=True, exist_ok=True)
        out_png = dest_dir / (pcap_path.stem + "_vlan0.png")

        plot_traffic(df, out_png, bin_ms, source_name=pcap_path.name)
        ok += 1
        print()

    print(f"[*] Done.  Plots saved: {ok}   Skipped (no VLAN-0 frames): {skipped}")


# ── Entry point ────────────────────────────────────────────────────────────

def main():
    default_dir = Path(__file__).resolve().parents[1] / "Data" / "pcap-files"

    parser = argparse.ArgumentParser(
        description="Plot VLAN ID 0 packet rate for one file or a whole folder."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--dir",
        metavar="FOLDER",
        default=default_dir,
        help=(
            "Folder containing .pcapng/.pcap files "
            f"(default: {default_dir})"
        ),
    )
    group.add_argument(
        "--file",
        metavar="FILE",
        help="Single .pcapng or .pcap file to process.",
    )
    parser.add_argument(
        "--out-dir",
        metavar="FOLDER",
        default=None,
        help="Output folder for PNGs (default: same folder as each source file).",
    )
    parser.add_argument(
        "--bin-ms",
        type=int,
        default=5000,
        help="Bin width in milliseconds (default: 100).",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir) if args.out_dir else None

    if args.file:
        pcap_path = Path(args.file)
        if not pcap_path.is_file():
            print(f"[!] File not found: {pcap_path}")
            sys.exit(1)
        df = load_vlan0(pcap_path)
        if df is None:
            sys.exit(0)
        dest_dir = out_dir if out_dir else pcap_path.parent
        dest_dir.mkdir(parents=True, exist_ok=True)
        out_png = dest_dir / (pcap_path.stem + "_vlan0.png")
        plot_traffic(df, out_png, args.bin_ms, source_name=pcap_path.name)
    else:
        input_dir = Path(args.dir)
        if not input_dir.is_dir():
            print(f"[!] Directory not found: {input_dir}")
            sys.exit(1)
        process_directory(input_dir, out_dir, args.bin_ms)

    print("[*] All done.")


if __name__ == "__main__":
    main()