"""Replay captures through the switch and compare every fingerprint with the reference.

    python3 -m tools.compare [pcap ...]        (default: every capture in ~/ja4/pcap)

For each fingerprint of each connection the result is one of
    EXACT     the switch's value equals the reference
    WRONG     both have a value and they differ
    MISSING   the reference has it, the switch does not
    EXTRA     the switch has it, the reference does not
    EXPLAINED a difference checked by hand and listed in EXPLAINED, with the reason
JA4L is a measurement, so it is not scored EXACT/WRONG on its latency. It is compared against the reference run on
the frames as the replay sent them (sent.pcap): the TTL part must be equal (EXACT / WRONG as for the other
fingerprints), and the latency difference is reported as a measurement (median, 90th percentile, maximum, and how
many halves differ by more than LATENCY_NOTE_US). The difference is the time a frame waits between the replay and
the moment BMv2's pipeline takes it up and stamps it: BMv2 stamps a packet when its ingress pipeline starts, so a
packet queued behind a slow one (a TLS hello walk) is stamped late. The JA4L arithmetic itself is checked by a test
with known, large gaps (tests/test_ja4l_gaps.py).

Forwarding is checked too: every frame sent into the switch must come out, byte for byte unchanged (a lost or
altered frame is reported as FORWARDING and fails the run).

Not compared, and listed as such: connections the reference reports over QUIC (not implemented yet), JA4H of
HTTP/2 and HTTP/3 requests that the reference could compute only by decrypting TLS with keys stored in the capture,
and the captures in EXCLUDED (the switch does not open tunnels).
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import reference, replay  # noqa: E402

DEFAULT_PCAPS = Path.home() / "ja4/pcap"
LATENCY_NOTE_US = 2000
# Differences checked by hand, where the reference cannot see what the switch reports. Counted as EXPLAINED.
EXPLAINED = {
    ("socks4-https.pcap", "ja4s", ("10.0.0.1", 50606, "10.0.0.2", 9901)):
        "the ClientHello is missing from the capture and TLS runs on port 9901, so FoxIO's tool decodes no TLS; "
        "the ServerHello bytes decoded by hand give version 0x0303, cipher c027, extensions 0005,ff01, no ALPN: "
        "t120200_c027_fee41c0d62a8, the switch's value",
}
_MALFORMED_SSH = ("the stream is deliberately malformed: tshark refuses frame 21 (an 80-byte server segment on port 22) "
                  "as SSH, so FoxIO's tool does not count it; the switch counts every payload segment on port 22 "
                  "as SSH, giving one more server SSH packet (s6 instead of s5); every other part equal")
EXPLAINED.update({
    ("ssh2-malformed.pcap", "ja4ssh", ("10.0.0.1", 61672, "10.0.0.2", 22)): _MALFORMED_SSH,
    ("ssh2-moloch-crash.pcap", "ja4ssh", ("10.0.0.1", 61672, "10.0.0.2", 22)): _MALFORMED_SSH,
    ("v6.pcap", "ja4ssh", ("3ffe:507:0:1:200:86ff:fe05:80da", 1022, "3ffe:501:410:0:2c0:dfff:fe47:33e", 22)):
        "the same SSH version 1 connection as in sshv1.pcap (same addresses and ports), with the same difference: "
        "tshark does not dissect frames 68 and 70 as SSH",
    ("sshv1.pcap", "ja4ssh", ("3ffe:507:0:1:200:86ff:fe05:80da", 1022, "3ffe:501:410:0:2c0:dfff:fe47:33e", 22)):
        "SSH protocol version 1: tshark does not dissect frames 68 and 70 (server, 28 and 20 bytes) as SSH, so "
        "FoxIO's tool does not count them; the switch counts every payload segment on port 22, giving 25 server SSH "
        "packets instead of 23, and the extra 20-byte packet makes 20 the server's most frequent length (s20, not "
        "s12)",
})
EXCLUDED = {
    "gre-erspan-vxlan.pcap": "tunnel (GRE/ERSPAN/VXLAN): the switch reads only the outer headers",
    "gre-sample.pcap": "tunnel (GRE): the switch reads only the outer headers",
    "tcpdump-geneve.pcap": "tunnel (Geneve): the switch reads only the outer headers",
}
EXACT_NAMES = ("ja4t", "ja4ts", "ja4", "ja4s", "ja4h", "ja4ssh", "ja4x")   # ja4h: the list of a connection's requests, in order
LATENCY_NAMES = ("ja4l_c", "ja4l_s")


def switch_records(res):
    """The switch's records keyed as the references are: endpoints, and the connection's place among those on the
    same endpoints, in the order of the switch's connection numbers (port reuse)."""
    out = {}
    count = Counter()
    for r in sorted((r for r in res["records"] if "client" in r), key=lambda r: r.get("conn_id") or 0):
        ends = (r["client"], r["client_port"], r["server"], r["server_port"])
        count[tuple(sorted([ends[:2], ends[2:]]))] += 1
        out[reference.key(*ends, count[tuple(sorted([ends[:2], ends[2:]]))])] = r
    return out


latency_diffs = []      # |switch - reference| of every JA4L half compared, in microseconds


def latency_ttl_equal(mine, ref):
    """JA4L: the TTL must be equal; the latency difference is kept as a measurement."""
    (m_lat, m_ttl), (r_lat, r_ttl) = mine.split("_"), ref.split("_")
    latency_diffs.append(abs(int(m_lat) - int(r_lat)))
    return m_ttl == r_ttl


decrypted_only = [0, 0]  # JA4H, JA4X the reference computed from decrypted traffic (see compare())


def compare(pcap, timing=True, work_root=None):
    """Replay `pcap` through the switch and compare (see compare_records)."""
    work = Path(work_root) / Path(pcap).stem if work_root else None
    res = replay.run(pcap, timing, work)
    return compare_records(res, pcap, Path(res["work"]) / "sent.pcap", timing), res


def compare_records(res, pcap, timed_pcap, timing=True):
    """Rows comparing the switch's records (res["records"], res["messages"]) with the references computed on `pcap`
    (exact fingerprints) and `timed_pcap` (the same frames as the switch saw them, with their times: JA4L, and
    JA4TS from tshark). Used for replays and for the live Mininet run."""
    mine = switch_records(res)
    tcp_only = lambda recs: {k: r for k, r in recs.items() if r.get("transport", "tcp") == "tcp"}  # noqa: E731
    ref_orig = tcp_only(reference.foxio(pcap))
    ref_sent = tcp_only(reference.foxio(timed_pcap))
    ref_ts = reference.tshark_ja4ts(timed_pcap)

    rows = []
    for k in sorted(set(mine) | set(ref_orig) | set(ref_ts) | set(ref_sent), key=str):
        m = mine.get(k, {})
        # JA4H of HTTP/2 and HTTP/3 (version "20", "30") come from requests inside TLS or QUIC, which FoxIO's tool
        # decrypts with keys stored in some sample captures; a switch on the wire cannot: not compared, counted.
        http_all = [h.get("ja4h") for h in ref_orig.get(k, {}).get("http", [])]
        http_ref = [v for v in http_all if v and v[2:4] in ("10", "11")]
        decrypted_only[0] += len(http_all) - len(http_ref)
        want = {"ja4t": ref_orig.get(k, {}).get("ja4t"), "ja4ts": ref_ts.get(k),
                "ja4": ref_orig.get(k, {}).get("ja4"), "ja4s": ref_orig.get(k, {}).get("ja4s"),
                "ja4h": http_ref or None, "ja4ssh": ref_orig.get(k, {}).get("ja4ssh")}
        # JA4X: the first certificate chain of the connection. Only TLS 1.2 (and older) send it in the clear; a TLS
        # 1.3 chain in the reference was decrypted with keys stored in the capture: not compared, counted.
        chains = ref_orig.get(k, {}).get("tls_certs", [])
        if chains:
            values = [c.get("ja4x") for c in chains[0].get("x509", [])]
            if str(ref_orig[k].get("ja4s", "")).startswith("t13"):
                decrypted_only[1] += len(values)
            else:
                want["ja4x"] = values
        if timing:      # without the capture's time gaps, JA4L measures nothing meaningful
            for n in LATENCY_NAMES:
                want[n] = ref_sent.get(k, {}).get(n)
        for name, ref_val in want.items():
            got = m.get(name)
            if ref_val is None and got is None:
                continue
            if name in LATENCY_NAMES and not timing:
                continue
            if ref_val is None:
                verdict = "EXTRA"
            elif got is None:
                verdict = "MISSING"
            elif name in LATENCY_NAMES:
                verdict = "EXACT" if latency_ttl_equal(got, ref_val) else "WRONG"
            else:
                verdict = "EXACT" if got == ref_val else "WRONG"
            note = EXPLAINED.get((Path(pcap).name, name, tuple(k)))
            if note and verdict != "EXACT":
                verdict = "EXPLAINED"
            rows.append({"conn": k, "name": name, "switch": got, "reference": ref_val, "verdict": verdict,
                         **({"note": note} if note else {})})
    # per-message fingerprints (DHCP): the whole sequence of the capture, message by message. Reference: FoxIO's
    # Wireshark plugin's stored output where it exists, else the same rule on tshark's fields (reference.py)
    want_d = reference.foxio_wireshark_ja4d(pcap)
    if want_d is None:
        want_d = reference.tshark_ja4d(pcap) or None
    got_d = [v for _, v in res.get("messages", [])]
    if want_d is not None or got_d:
        for i in range(max(len(want_d or []), len(got_d))):
            ref_val = (want_d or [])[i] if i < len(want_d or []) else None
            got = got_d[i] if i < len(got_d) else None
            verdict = "EXACT" if got == ref_val else "MISSING" if got is None else "EXTRA" if ref_val is None \
                else "WRONG"
            rows.append({"conn": f"DHCP message {i + 1}", "name": "ja4d", "switch": got, "reference": ref_val,
                         "verdict": verdict})
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcaps", nargs="*")
    ap.add_argument("--no-timing", action="store_true")
    ap.add_argument("--work", help="keep each replay's files under this folder")
    ap.add_argument("--out", help="write every row as JSON")
    ap.add_argument("-v", "--verbose", action="store_true", help="print EXACT rows too")
    args = ap.parse_args()
    pcaps = args.pcaps or sorted(str(p) for p in DEFAULT_PCAPS.iterdir())

    total = Counter()
    all_rows = []
    frames_sent = frames_unchanged = 0
    for pcap in pcaps:
        if Path(pcap).name in EXCLUDED:
            print(f"{Path(pcap).name:<45} EXCLUDED: {EXCLUDED[Path(pcap).name]}")
            continue
        rows, res = compare(pcap, not args.no_timing, args.work)
        c = Counter(r["verdict"] for r in rows)
        total.update(c)
        frames_sent += res["sent"]
        frames_unchanged += res["unchanged"]
        fwd = "" if res["unchanged"] == res["sent"] else \
            f"  FORWARDING: only {res['unchanged']} of {res['sent']} frames left unchanged"
        print(f"{Path(pcap).name:<45} " + "  ".join(f"{v} {c[v]}" for v in ("EXACT", "EXPLAINED", "WRONG", "MISSING", "EXTRA")
                                                     if c[v]) + fwd)
        for r in rows:
            if args.verbose or r["verdict"] not in ("EXACT", "EXPLAINED"):
                print(f"    {r['verdict']:<8} {r['name']:<7} switch={r['switch']}  reference={r['reference']}  "
                      f"{r['conn']}")
            r["pcap"] = Path(pcap).name
            all_rows.append(r)
    print("TOTAL  " + "  ".join(f"{v} {total[v]}" for v in ("EXACT", "EXPLAINED", "WRONG", "MISSING", "EXTRA")))
    print(f"FORWARDING  {frames_unchanged} of {frames_sent} frames left the switch byte for byte unchanged")
    if latency_diffs:
        d = sorted(latency_diffs)
        print(f"JA4L LATENCY  {len(d)} halves (TTL scored above); difference to the reference: median "
              f"{d[len(d) // 2]} us, 90th percentile {d[int(0.9 * len(d))]} us, maximum {d[-1]} us; "
              f"{sum(x > LATENCY_NOTE_US for x in d)} above {LATENCY_NOTE_US} us")
    print(f"NOT COMPARED  {decrypted_only[0]} JA4H of HTTP/2 or HTTP/3 requests that FoxIO's tool decrypted with keys "
          f"stored in the capture, and {decrypted_only[1]} JA4X of TLS 1.3 certificates it decrypted the same way "
          f"(a switch cannot decrypt TLS)")
    if args.out:
        Path(args.out).write_text(json.dumps(all_rows, indent=1, default=str))
    return 0 if total["WRONG"] == 0 and frames_unchanged == frames_sent else 1


if __name__ == "__main__":
    sys.exit(main())
