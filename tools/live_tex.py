"""Write docs/results_live.tex from results/live/rows.json and report.txt (the live run's output)."""

import collections
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIVE = os.path.join(ROOT, "results", "live")
OUT = os.path.join(ROOT, "docs", "results_live.tex")

NAMES = [("ja4t", "JA4T"), ("ja4ts", "JA4TS"), ("ja4l_c", "JA4L-C (TTL)"), ("ja4l_s", "JA4L-S (TTL)"),
         ("ja4", "JA4"), ("ja4s", "JA4S"), ("ja4h", "JA4H (per connection)"), ("ja4ssh", "JA4SSH (per connection)"),
         ("ja4x", "JA4X (per chain)"), ("ja4d", "JA4D / JA4D6 (per message)")]
VERDICTS = ["EXACT", "EXPLAINED", "WRONG", "MISSING", "EXTRA"]


def main():
    rows = json.load(open(os.path.join(LIVE, "rows.json")))
    report = open(os.path.join(LIVE, "report.txt")).read()
    count = collections.Counter((r["name"], r["verdict"]) for r in rows)
    lines = [r"\begin{center}\begin{tabular}{lrrrrr}\toprule",
             r"\textbf{Fingerprint} & " + " & ".join(rf"\textbf{{{v}}}" for v in VERDICTS) + r"\\\midrule"]
    for key, label in NAMES:
        lines.append(label + " & " + " & ".join(str(count[key, v]) for v in VERDICTS) + r"\\")
    total = collections.Counter(r["verdict"] for r in rows)
    lines.append(r"\midrule Total & " + " & ".join(str(total[v]) for v in VERDICTS) + r"\\\bottomrule\end{tabular}\end{center}")

    forwarding = re.findall(r"FORWARDING (\S+) -> (\S+): (\d+) of (\d+) frames", report)
    fwd = "; ".join(f"{a} $\\to$ {b}: {n:,} of {m:,}" for a, b, n, m in
                    [(a, b, int(n), int(m)) for a, b, n, m in forwarding])
    d = sorted(abs(int(r["switch"].split("_")[0]) - int(r["reference"].split("_")[0]))
               for r in rows if r["name"] in ("ja4l_c", "ja4l_s"))
    steps = re.search(r"^STEPS(?: FAILED:)? *(.*)$", report, re.M)
    if steps and "FAILED" in steps.group(0):
        lines.append(f"\\textbf{{Steps that failed: {steps.group(1)}.}} ")
    lines.append(
        f"One live run of \\code{{network/run\\_live.py}}, compared on the frames that entered the switch. "
        f"\\textbf{{Forwarding: {fwd} frames left the switch unchanged.}} "
        f"JA4L latency (a measurement), difference to the reference over the same frames: {len(d)} halves, "
        f"median {d[len(d) // 2]}~µs, maximum {d[-1]}~µs. Source: \\texttt{{results/live/rows.json}}.")
    with open(OUT, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(OUT)


if __name__ == "__main__":
    main()
