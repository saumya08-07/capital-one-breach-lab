"""
make_figures.py -- regenerate all three report figures using ONLY matplotlib.
No Cairo, no SVG, no extra libraries. Works on Windows.

    pip install matplotlib
    python make_figures.py

Writes fig1_attack_chain.png, fig2_blast_radius.png, fig3_matrix.png next to
this file. Figure 2 reads ../results/results.csv if present (so it reflects
your own run); otherwise it falls back to the measured values.
"""

import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

plt.rcParams["font.family"] = "serif"
plt.rcParams["font.serif"] = ["DejaVu Serif", "Times New Roman"]

HERE = Path(__file__).parent

# palette (colorblind-safe)
BLUE_F, BLUE_E = "#E8F1F8", "#1F6FB2"
ORA_F, ORA_E = "#FBEEE6", "#D35400"
TEAL_F, TEAL_E = "#E7F6F0", "#0E8C6A"
AMB_F, AMB_E = "#FEF8E7", "#C9A227"
GRY_F, GRY_E = "#F4F4F2", "#CCCCCC"
INK = "#333333"
NAVY = "#0F4C81"


def box(ax, cx, cy, w, h, fc, ec, lw=1.6, dashed=False):
    p = FancyBboxPatch((cx - w / 2, cy - h / 2), w, h,
                       boxstyle="round,pad=0.02,rounding_size=0.12",
                       linewidth=lw, facecolor=fc, edgecolor=ec,
                       linestyle=(":" if dashed else "-"), mutation_aspect=0.6)
    ax.add_patch(p)


def lines(ax, cx, cy, rows):
    """rows: list of (text, dy, size, color, bold)"""
    for text, dy, size, color, bold in rows:
        ax.text(cx, cy + dy, text, ha="center", va="center", fontsize=size,
                color=color, fontweight=("bold" if bold else "normal"))


# ---------------------------------------------------------------- Figure 1
def fig1():
    fig, ax = plt.subplots(figsize=(13, 5.4), dpi=200)
    ax.set_xlim(0, 13); ax.set_ylim(0, 5.4); ax.axis("off")

    stage_y, ctrl_y = 3.6, 1.45
    xs = [3.6, 6.0, 8.4, 10.8]  # S1..S4 centers
    # Attacker
    box(ax, 1.2, stage_y, 1.8, 1.0, ORA_F, ORA_E)
    lines(ax, 1.2, stage_y, [("Attacker", 0.24, 12, ORA_E, True),
                             ("(external,", -0.02, 9.5, INK, False),
                             ("GET-only SSRF)", -0.24, 9.5, INK, False)])

    stages = [
        ("S1 \u00b7 Access", ["Misconfigured WAF", "on EC2 instance"], "CWE-918 \u00b7 T1190"),
        ("S2 \u00b7 Credentials", ["IMDSv1 at", "169.254.169.254"], "T1552.005"),
        ("S3 \u00b7 Discovery", ["Over-privileged", "ISRM-WAF-Role"], "T1580 \u00b7 T1530"),
        ("S4 \u00b7 Exfiltration", ["~30 GB from", "700+ S3 buckets"], "T1537"),
    ]
    controls = [
        ("Input validation", ["+ subnet egress deny", "to link-local range"]),
        ("IMDSv2", ["PUT-token required;", "GET-only SSRF fails"]),
        ("Least privilege", ["resource-scoped role;", "blast radius bounded"]),
        ("Origin detection", ["credential used from", "foreign address"]),
    ]
    arrow_lbl = ["forge request", "GET credentials", "list buckets"]

    for x, (title, body, attck) in zip(xs, stages):
        box(ax, x, stage_y, 2.1, 1.05, BLUE_F, BLUE_E)
        lines(ax, x, stage_y, [(title, 0.35, 11, BLUE_E, True),
                               (body[0], 0.09, 10, INK, False),
                               (body[1], -0.13, 10, INK, False),
                               (attck, -0.37, 9, "#777777", False)])
    # flow arrows
    ax.annotate("", xy=(xs[0] - 1.08, stage_y), xytext=(2.12, stage_y),
                arrowprops=dict(arrowstyle="-|>", color=INK, lw=1.6))
    for i in range(3):
        ax.annotate("", xy=(xs[i + 1] - 1.08, stage_y), xytext=(xs[i] + 1.08, stage_y),
                    arrowprops=dict(arrowstyle="-|>", color=INK, lw=1.6))
        ax.text((xs[i] + xs[i + 1]) / 2, stage_y + 0.78, arrow_lbl[i],
                ha="center", fontsize=9.5, color="#555555")

    ax.text(0.3, 2.5, "Control that severs each stage:", fontsize=11,
            fontweight="bold", color=TEAL_E)
    for x, (title, body) in zip(xs, controls):
        box(ax, x, ctrl_y, 2.1, 0.9, TEAL_F, TEAL_E, lw=1.5)
        lines(ax, x, ctrl_y, [(title, 0.23, 10.5, TEAL_E, True),
                              (body[0], -0.02, 9, INK, False),
                              (body[1], -0.22, 9, INK, False)])
        ax.annotate("", xy=(x, ctrl_y + 0.45), xytext=(x, stage_y - 0.53),
                    arrowprops=dict(arrowstyle="-|>", color=TEAL_E, lw=1.3,
                                    linestyle=(0, (4, 3))))
    ax.text(0.3, 0.5,
            "The SSRF (S1) determines that an intrusion occurs; the role scope (S3) determines its magnitude.",
            fontsize=10.5, style="italic", color="#555555")
    plt.savefig(HERE / "fig1_attack_chain.png", dpi=200, facecolor="white",
                bbox_inches="tight", pad_inches=0.15)
    plt.close()
    print("  wrote fig1_attack_chain.png")


# ---------------------------------------------------------------- Figure 2
def fig2():
    csv_path = HERE.parent / "results" / "results.csv"
    wildcard, scoped = 12041, 41
    if csv_path.exists():
        rows = {r["config"]: int(r["objects_reachable"])
                for r in csv.DictReader(csv_path.open())}
        wildcard, scoped = rows.get("A", wildcard), rows.get("C", scoped)
    reduction = 100 * (wildcard - scoped) / wildcard

    fig, ax = plt.subplots(figsize=(7.6, 4.6), dpi=200)
    bars = ax.bar(["Wildcard role\n(2019 baseline)", "Least-privilege role\n(scoped to WAF config)"],
                  [wildcard, scoped], color=[ORA_E, TEAL_E], width=0.56,
                  zorder=3, edgecolor="white", linewidth=1.5)
    for b, v in zip(bars, [wildcard, scoped]):
        ax.text(b.get_x() + b.get_width() / 2, v + wildcard * 0.02, f"{v:,}",
                ha="center", va="bottom", fontsize=14, fontweight="bold", color="#222222")
    ax.annotate("", xy=(1, scoped + wildcard * 0.012), xytext=(0, wildcard + wildcard * 0.012),
                arrowprops=dict(arrowstyle="->", color="#555555", lw=1.3,
                                connectionstyle="arc3,rad=-0.25"))
    ax.text(0.5, wildcard * 0.78, f"{reduction:.2f}% reduction\nin reachable objects",
            ha="center", va="center", fontsize=12.5, color=INK,
            bbox=dict(boxstyle="round,pad=0.4", fc="#F5F5F3", ec="#CCCCCC", lw=1))
    ax.set_ylabel("Objects readable with stolen credentials", fontsize=12)
    ax.set_ylim(0, wildcard * 1.13)
    ax.set_title("Blast radius under identical credential theft (IMDSv1 retained)",
                 fontsize=13.5, fontweight="bold", color=NAVY, pad=14)
    ax.yaxis.grid(True, color="#E4E4E2", linewidth=0.9, zorder=0)
    ax.set_axisbelow(True)
    for s in ["top", "right"]:
        ax.spines[s].set_visible(False)
    for s in ["left", "bottom"]:
        ax.spines[s].set_color("#999999")
    ax.tick_params(labelsize=11, color="#999999")
    plt.tight_layout()
    plt.savefig(HERE / "fig2_blast_radius.png", dpi=200, facecolor="white", bbox_inches="tight")
    plt.close()
    print("  wrote fig2_blast_radius.png")


# ---------------------------------------------------------------- Figure 3
def fig3():
    fig, ax = plt.subplots(figsize=(12.8, 5.4), dpi=200)
    ax.set_xlim(0, 12.8); ax.set_ylim(0, 5.4); ax.axis("off")

    col_x = [3.7, 5.5, 7.3, 9.1]       # S1..S4
    out_x = 11.2
    hdr = ["S1 Access", "S2 Credentials", "S3 Discovery", "S4 Exfiltration"]
    ax.text(1.5, 5.05, "Configuration", ha="center", fontsize=12, fontweight="bold", color=NAVY)
    for x, h in zip(col_x, hdr):
        ax.text(x, 5.05, h, ha="center", fontsize=10.5, fontweight="bold", color=BLUE_E)
    ax.text(out_x, 5.05, "Outcome", ha="center", fontsize=12, fontweight="bold", color=NAVY)

    P = ("proceeds", ORA_F, ORA_E, False)
    def BL(sub): return ("BLOCKED\n" + sub, TEAL_F, TEAL_E, False)
    def BND(t, sub): return (t + "\n" + sub, AMB_F, AMB_E, False)
    U = ("unreached", GRY_F, GRY_E, True)

    rows = [
        ("A \u2014 Baseline", "IMDSv1 + wildcard", [P, P, P, P], ("12,041", "objects (100%)", ORA_E)),
        ("B \u2014 IMDSv2", "IMDSv2 + wildcard", [P, BL("no PUT token"), U, U], ("0", "objects (0%)", TEAL_E)),
        ("C \u2014 Least priv.", "IMDSv1 + scoped", [P, P, BND("BOUNDED", "scope limited"), BND("41 only", "WAF config")], ("41", "objects (0.34%)", "#A5831F")),
        ("D \u2014 Full stack", "IMDSv2 + scoped", [P, BL("no PUT token"), U, U], ("0", "objects (0%)", TEAL_E)),
    ]
    ys = [4.2, 3.3, 2.4, 1.5]
    for y, (name, sub, cells, (num, unit, ncol)) in zip(ys, rows):
        ax.text(0.2, y + 0.12, name, ha="left", fontsize=12, fontweight="bold", color=INK)
        ax.text(0.2, y - 0.14, sub, ha="left", fontsize=10, color="#777777")
        for x, (txt, fc, ec, grey) in zip(col_x, cells):
            box(ax, x, y, 1.55, 0.62, fc, ec, lw=(1.3 if grey else 1.8),
                dashed=grey)
            parts = txt.split("\n")
            if len(parts) == 2:
                ax.text(x, y + 0.11, parts[0], ha="center", fontsize=10.5,
                        fontweight="bold", color=ec)
                ax.text(x, y - 0.13, parts[1], ha="center", fontsize=9, color=ec)
            else:
                ax.text(x, y, txt, ha="center", fontsize=10.5,
                        color=(ec if not grey else "#999999"))
        ax.text(out_x, y + 0.1, num, ha="center", fontsize=13, fontweight="bold", color=ncol)
        ax.text(out_x, y - 0.16, unit, ha="center", fontsize=9.5, color="#777777")

    # legend
    leg = [("attack proceeds", ORA_F, ORA_E, False),
           ("proceeds but bounded", AMB_F, AMB_E, False),
           ("control blocks the chain", TEAL_F, TEAL_E, False),
           ("stage never reached", GRY_F, GRY_E, True)]
    lx = 0.4
    for txt, fc, ec, grey in leg:
        box(ax, lx + 0.18, 0.75, 0.34, 0.3, fc, ec, lw=1.4, dashed=grey)
        ax.text(lx + 0.42, 0.75, txt, ha="left", va="center", fontsize=10, color=INK)
        lx += 0.42 + 0.028 * len(txt) + 1.35
    ax.text(0.2, 0.28,
            "Defence in depth: the earliest effective control (IMDSv2 at S2) terminates the chain, so later stages are never reached.",
            fontsize=10, style="italic", color="#555555")
    plt.savefig(HERE / "fig3_matrix.png", dpi=200, facecolor="white",
                bbox_inches="tight", pad_inches=0.15)
    plt.close()
    print("  wrote fig3_matrix.png")


if __name__ == "__main__":
    print("Rendering figures (matplotlib only)...")
    fig1(); fig2(); fig3()
    print("Done.")