"""Reference fingerprints for a capture, from tools that know nothing about this project.

* FoxIO's Rust tool (`ja4`, ~/ja4/rust/target/release/ja4, or $JA4_BIN): JA4T, JA4L and later every other JA4+
  fingerprint it implements.
* tshark fields for JA4TS, which FoxIO's open-source tool does not implement: the first SYN-ACK of each TCP
  stream, written in the same format as JA4T (FoxIO's JA4T/S specification: window, options, MSS, scale).

Each record is keyed by (client, client port, server, server port); a later TCP connection on the same endpoints (port
reuse) by (client, client port, server, server port, n), n = 2, 3, ... its place among them (see key()).
"""
import json
import os
import subprocess
from pathlib import Path

JA4_BIN = os.environ.get("JA4_BIN", str(Path.home() / "ja4/rust/target/release/ja4"))


def key(client, cport, server, sport, occurrence=1):
    """A connection's key: its endpoints, and, when it is not the first TCP connection on them (port reuse), its
    place among them (2, 3, ...). Both the references and the switch's records are keyed this way (compare.py)."""
    k = (str(client), int(cport), str(server), int(sport))
    return k if occurrence == 1 else k + (int(occurrence),)


def tcp_occurrences(pcap):
    """{tshark TCP stream number: its place among the streams on the same endpoints (1, 2, ...)}. tshark starts a
    new stream for a new connection on reused endpoints; FoxIO's tool reports tshark's stream numbers."""
    out = subprocess.run(["tshark", "-r", str(pcap), "-Y", "tcp", "-T", "fields", "-E", "separator=|",
                          "-e", "tcp.stream", "-e", "ip.src", "-e", "ipv6.src", "-e", "ip.dst", "-e", "ipv6.dst",
                          "-e", "tcp.srcport", "-e", "tcp.dstport"], capture_output=True, text=True, check=True).stdout
    first = {}
    for line in out.splitlines():
        stream, s4, s6, d4, d6, sport, dport = line.split("|")
        if stream and stream not in first:
            a = ((s4 or s6).split(",")[-1], int(sport))
            b = ((d4 or d6).split(",")[-1], int(dport))
            first[stream] = tuple(sorted([a, b]))
    count, occ = {}, {}
    for stream in sorted(first, key=int):
        count[first[stream]] = count.get(first[stream], 0) + 1
        occ[int(stream)] = count[first[stream]]
    return occ


def foxio(pcap):
    out = subprocess.run([JA4_BIN, "-j", str(pcap)], capture_output=True, text=True, check=True).stdout
    occ = None
    recs = {}
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        r = json.loads(line)
        if "src_port" not in r:
            continue
        n = 1
        if r.get("transport", "tcp") == "tcp" and "stream" in r:
            occ = tcp_occurrences(pcap) if occ is None else occ
            n = occ.get(int(r["stream"]), 1)
        recs[key(r["src"], r["src_port"], r["dst"], r["dst_port"], n)] = r
    return recs


def _tcp_text(window, kinds, mss, wscale):
    opts = "-".join(kinds) if kinds else "00"
    mss = int(mss) if mss else 0
    ws = int(wscale) if wscale else 0
    return f"{window}_{opts}_{mss:02d}_{ws:02d}" if ws == 0 else f"{window}_{opts}_{mss:02d}_{ws}"


def tshark_ja4ts(pcap):
    """JA4TS of the first SYN-ACK of every TCP stream; keyed with the SYN-ACK's destination as the client."""
    fields = ["tcp.stream", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport",
              "tcp.window_size_value", "tcp.option_kind", "tcp.options.mss_val", "tcp.options.wscale.shift"]
    cmd = ["tshark", "-r", str(pcap), "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 1", "-T", "fields",
           "-E", "separator=|", "-E", "occurrence=a", "-E", "aggregator=,"]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    recs, seen = {}, set()
    occ = None
    for line in out.splitlines():
        stream, s4, s6, d4, d6, sport, dport, win, kinds, mss, ws = line.split("|")
        if stream in seen:
            continue
        seen.add(stream)
        occ = tcp_occurrences(pcap) if occ is None else occ
        src, dst = (s4 or s6).split(",")[-1], (d4 or d6).split(",")[-1]
        kinds = kinds.split(",") if kinds else []
        recs[key(dst, dport, src, sport, occ.get(int(stream), 1))] = \
            _tcp_text(win, kinds, mss.split(",")[-1], ws.split(",")[-1])
    return recs


WIRESHARK_TESTDATA = Path.home() / "ja4/wireshark/test/testdata"


def foxio_wireshark_ja4d(pcap):
    """JA4D / JA4D6 of every DHCP message, in frame order, as FoxIO's Wireshark plugin wrote them in its own test
    data (wireshark/test/testdata/<capture>.json). The plugin itself cannot be loaded here (it is built for older
    tshark versions), so its stored output is the reference; None if there is none for this capture."""
    path = WIRESHARK_TESTDATA / (Path(pcap).name + ".json")
    if not path.exists():
        return None
    out = []
    for pkt in json.loads(path.read_text()):
        layers = pkt["_source"]["layers"]
        if "ja4.ja4d" in layers:
            out.append(layers["ja4.ja4d"][0])
    return out or None


DHCP4_TYPES = [None, "disco", "offer", "reqst", "decln", "dpack", "dpnak", "relse", "infor", "frenw", "lqery",
               "lunas", "lunkn", "lactv", "blklq", "lqdon", "actlq", "lqsta", "dhtls"]
DHCP6_TYPES = [None, "solct", "advrt", "reqst", "confm", "renew", "rebnd", "reply", "relse", "decln", "recon",
               "inreq", "rlayf", "rlayr", "query", "qrply", "qdone", "qdata", "rereq", "rrply", "v4qry", "v4res",
               "acqry", "sttls", "bdudp", "brply", "poreq", "pores", "urqst", "ureqa", "udone", "conne", "connr",
               "dconn", "state", "conta", "arinf", "arrep"]


def tshark_ja4d(pcap):
    """JA4D / JA4D6 of every DHCP message, from tshark's dissection, following FoxIO's Wireshark plugin step by step
    (packet-ja4.c reads exactly these tshark fields). Used where the plugin's own output is not available (traffic
    captured here); checked against the plugin's stored output on FoxIO's samples first (tests/test_reference.py)."""
    import xml.etree.ElementTree as ET
    # An ICMP error quotes the packet that caused it, and tshark dissects the quoted DHCP message as DHCP: that is
    # not a DHCP message on the wire (the live run's "port unreachable" replies quote DHCP offers and replies).
    out = subprocess.run(["tshark", "-r", str(pcap), "-Y", "(dhcp || dhcpv6) && !icmp && !icmpv6", "-T", "pdml"],
                         capture_output=True, text=True, check=True).stdout
    values = []
    for pkt in ET.fromstring(out).iter("packet"):
        kind = size = None
        ip = fqdn = "n"
        opts, req = [], []
        opt1_seen = False
        for f in pkt.iter("field"):
            name, show = f.get("name"), f.get("show")
            if name == "dhcp.option.dhcp":
                t = int(show)
                kind = DHCP4_TYPES[t] if t < len(DHCP4_TYPES) and DHCP4_TYPES[t] else f"{t:05d}"
            elif name == "dhcp.option.dhcp_max_message_size":
                v = int(show)
                size = f"{v:04d}" if v < 9999 else "9999"
            elif name == "dhcp.option.requested_ip_address":
                ip = "i"
            elif name == "dhcp.fqdn.name":
                fqdn = "d"
            elif name == "dhcp.option.type":
                v = int(show)
                if v not in (0, 53, 50, 81):
                    opts.append(str(v))
            elif name == "dhcp.option.request_list_item":
                req.append(str(int(show)))
            elif name == "dhcpv6.msgtype":
                t = int(show)
                kind = DHCP6_TYPES[t] if t < len(DHCP6_TYPES) and DHCP6_TYPES[t] else f"{t:05d}"
            elif name == "dhcpv6.duid.bytes" and size is None and opt1_seen:
                n = int(f.get("size"))
                size = f"{n:04d}" if n < 9999 else "9999"
            elif name == "dhcpv6.iata":
                ip = "i"
            elif name == "dhcpv6.client_domain":
                fqdn = "d"
            elif name == "dhcpv6.option.type":
                v = int(show)
                opt1_seen = opt1_seen or v == 1
                opts.append(str(v))
            elif name == "dhcpv6.requested_option_code":
                req.append(str(int(show)))
        values.append(f"{kind or '00000'}{size or '0000'}{ip}{fqdn}_{'-'.join(opts) or '00'}_{'-'.join(req) or '00'}")
    return values
