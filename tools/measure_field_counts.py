"""Measurement study for the switch's capacities: how long are the lists the switch keeps, in real messages?

The P4 program keeps every variable-length list in fixed-size fields (p4/headers.p4, parser_*.p4). A message whose
list is longer than its capacity is reported as incomplete, never guessed. This script measures each of those
quantities over a corpus of messages and reports, per quantity, the distribution and how many messages fit:

    TLS ClientHello  cipher suites (without GREASE)        TLS_CIPHER_CAP   128
                     extensions (without GREASE)           TLS_EXT_CAP       64
                     signature algorithms (ext 13)         TLS_SIG_CAP       64
    TLS ServerHello  extensions                            TLS_EXT_CAP       64
    HTTP request     bytes of header names (JA4H part b)   HTTP_NAMES_CAP   512
                     bytes of cookie pairs (JA4H part c)   HTTP_COOKIES_CAP 1024
    DHCP message     option codes                          DHCP_OPT_CAP      64
                     requested codes                       DHCP_REQ_CAP     128
    certificate      bytes of issuer / subject / extension OIDs (<len><bytes> each)   X509_LIST_CAP 256

The counts come from tshark's dissection (it reassembles split messages) and, for certificates, from Python's
`cryptography` package: independent of the switch's parser.

Corpus: FoxIO's sample captures, the live run's capture, captures of earlier work on this machine, and messages
generated here by every client installed (--local): each client connects to a local listener that records its first
message (a ClientHello or a request) and closes; the messages are written to results/measure/local.pcap.

    python3 -m tools.measure_field_counts [--local] [pcap ...]
"""
import argparse
import json
import math
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

from scapy.all import IP, TCP, Ether, wrpcap

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import reference  # noqa: E402

OUT = ROOT / "results" / "measure"

CAPS = {   # quantity: (capacity, where it is defined)
    "TLS ClientHello cipher suites": (128, "TLS_CIPHER_CAP, p4/headers.p4"),
    "TLS ClientHello extensions": (64, "TLS_EXT_CAP, p4/headers.p4"),
    "TLS ClientHello signature algorithms": (64, "TLS_SIG_CAP, p4/headers.p4"),
    "TLS ServerHello extensions": (64, "TLS_EXT_CAP, p4/headers.p4"),
    "HTTP header-name bytes": (512, "HTTP_NAMES_CAP, p4/parser_http.p4"),
    "HTTP cookie bytes": (1024, "HTTP_COOKIES_CAP, p4/parser_http.p4"),
    "DHCP option codes": (64, "DHCP_OPT_CAP, p4/parser_dhcp.p4"),
    "DHCP requested codes": (128, "DHCP_REQ_CAP, p4/parser_dhcp.p4"),
    "certificate issuer OID bytes": (256, "X509_LIST_CAP, p4/parser_x509.p4"),
    "certificate subject OID bytes": (256, "X509_LIST_CAP, p4/parser_x509.p4"),
    "certificate extension OID bytes": (256, "X509_LIST_CAP, p4/parser_x509.p4"),
}


def is_grease(v):
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def descendants(node, name):
    return [f for f in node.iter("field") if f.get("name") == name]


# ---------------------------------------------------------------- counting, from captures

def tls_counts(pcap, add):
    out = subprocess.run(["tshark", "-r", str(pcap), "-o", "tls.desegment_ssl_records:TRUE",
                          "-Y", "tls.handshake.type == 1 || tls.handshake.type == 2", "-T", "pdml"],
                         capture_output=True, text=True).stdout
    if not out.strip():
        return
    for msg in ET.fromstring(out).iter("field"):
        if msg.get("name") != "tls.handshake":
            continue
        types = descendants(msg, "tls.handshake.type")
        if not types or types[0].get("show") not in ("1", "2"):
            continue
        hello = "ClientHello" if types[0].get("show") == "1" else "ServerHello"
        exts = [e for e in descendants(msg, "tls.handshake.extension")]
        ext_types = [int(descendants(e, "tls.handshake.extension.type")[0].get("show")) for e in exts
                     if descendants(e, "tls.handshake.extension.type")]
        ciphers = [int(f.get("show"), 16) for f in descendants(msg, "tls.handshake.ciphersuite")]
        sigs = []
        for e in exts:
            t = descendants(e, "tls.handshake.extension.type")
            if t and t[0].get("show") == "13":
                sigs = [int(f.get("show"), 16) for f in descendants(e, "tls.handshake.sig_hash_alg")]
        key = (hello, tuple(ciphers), tuple(ext_types))
        if hello == "ClientHello":
            add("TLS ClientHello cipher suites", len([c for c in ciphers if not is_grease(c)]), pcap, key)
            add("TLS ClientHello extensions", len([e for e in ext_types if not is_grease(e)]), pcap, key)
            add("TLS ClientHello signature algorithms", len([s for s in sigs if not is_grease(s)]), pcap, key)
        else:
            add("TLS ServerHello extensions", len(ext_types), pcap, key)


def http_counts(pcap, add):
    out = subprocess.run(["tshark", "-r", str(pcap), "-Y", "http.request", "-T", "pdml"],
                         capture_output=True, text=True).stdout
    if not out.strip():
        return
    for pkt in ET.fromstring(out).iter("packet"):
        lines = [f.get("show") for f in pkt.iter("field") if f.get("name") == "http.request.line"]
        names, cookie = [], None
        for line in lines:
            name, _, value = line.partition(":")
            if name.lower() == "cookie":
                if cookie is None:
                    cookie = value.strip().rstrip("\\r\\n").strip()
            elif name.lower() != "referer":
                names.append(name)
        key = tuple(names)
        add("HTTP header-name bytes", sum(len(n) + 1 for n in names), pcap, key)
        if cookie is not None:   # only requests that carry cookies
            add("HTTP cookie bytes", sum(len(p) + 1 for p in cookie.split("; ")), pcap, key + (cookie,))


def dhcp_counts(pcap, add):
    for v in reference.tshark_ja4d(pcap):
        _, opts, req = v.split("_")
        add("DHCP option codes", 0 if opts == "00" else len(opts.split("-")), pcap, v)
        add("DHCP requested codes", 0 if req == "00" else len(req.split("-")), pcap, v)


def oid_der_len(oid):
    """Length of the DER content of a dotted OID (first two arcs in one value, base-128 for each)."""
    arcs = [int(a) for a in oid.split(".")]
    values = [arcs[0] * 40 + arcs[1]] + arcs[2:]
    return sum(max(1, math.ceil(v.bit_length() / 7)) for v in values)


def x509_counts(pcap, add, failures):
    from cryptography import x509
    out = subprocess.run(["tshark", "-r", str(pcap), "-Y", "tls.handshake.certificate", "-T", "fields",
                          "-e", "tls.handshake.certificate"], capture_output=True, text=True).stdout
    for line in out.split():
        for cert_hex in line.split(","):
            try:
                cert = x509.load_der_x509_certificate(bytes.fromhex(cert_hex.replace(":", "")))
                issuer = [a.oid.dotted_string for a in cert.issuer]
                subject = [a.oid.dotted_string for a in cert.subject]
                exts = [e.oid.dotted_string for e in cert.extensions]
            except Exception as e:   # noqa: BLE001 - a certificate cryptography refuses is counted, not measured
                failures.append((str(pcap), type(e).__name__))
                continue
            key = cert_hex[:64]
            add("certificate issuer OID bytes", sum(1 + oid_der_len(o) for o in issuer), pcap, key)
            add("certificate subject OID bytes", sum(1 + oid_der_len(o) for o in subject), pcap, key)
            add("certificate extension OID bytes", sum(1 + oid_der_len(o) for o in exts), pcap, key)


# ---------------------------------------------------------------- local clients

class Recorder:
    """A listener that keeps each connection's first message (a whole TLS handshake message, or an HTTP header)."""

    def __init__(self, port, kind):
        self.kind, self.messages = kind, []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(16)
        self.label = None
        threading.Thread(target=self.serve, daemon=True).start()

    def complete(self, data):
        if self.kind == "http":
            return b"\r\n\r\n" in data
        if len(data) < 9:
            return False
        return len(data) >= 9 + int.from_bytes(data[6:9], "big") or len(data) > 65536

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            conn.settimeout(3)
            data = b""
            try:
                while not self.complete(data):
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            conn.close()
            if data:
                self.messages.append((self.label, data))


def local_clients():
    tls_port, http_port = 18443, 18080
    host = "measure.example"
    tls_url, http_url = f"https://{host}:{tls_port}/", f"http://127.0.0.1:{http_port}/"
    resolve = f"--resolve {host}:{tls_port}:127.0.0.1"
    py = sys.executable
    clients = [
        ("tls", "openssl s_client", f"openssl s_client -connect 127.0.0.1:{tls_port} -servername {host}"),
        ("tls", "openssl s_client -tls1_2", f"openssl s_client -connect 127.0.0.1:{tls_port} -servername {host} -tls1_2"),
        ("tls", "curl", f"curl -sk {resolve} {tls_url}"),
        ("tls", "curl --tlsv1.2 --tls-max 1.2", f"curl -sk --tlsv1.2 --tls-max 1.2 {resolve} {tls_url}"),
        ("tls", "wget", f"wget -q -O /dev/null --no-check-certificate https://127.0.0.1:{tls_port}/"),
        ("tls", "python requests", f"{py} -c \"import requests; requests.get('https://127.0.0.1:{tls_port}/', verify=False, timeout=3)\""),
        ("tls", "python urllib", f"{py} -c \"import ssl, urllib.request as u; u.urlopen('https://127.0.0.1:{tls_port}/', context=ssl._create_unverified_context(), timeout=3)\""),
        ("tls", "busybox wget", f"busybox wget -q -O /dev/null https://127.0.0.1:{tls_port}/"),
        ("http", "curl", f"curl -s {http_url}"),
        ("http", "wget", f"wget -q -O /dev/null {http_url}"),
        ("http", "python requests", f"{py} -c \"import requests; requests.get('{http_url}', timeout=3)\""),
        ("http", "python urllib", f"{py} -c \"import urllib.request as u; u.urlopen('{http_url}', timeout=3)\""),
        ("http", "busybox wget", f"busybox wget -q -O /dev/null {http_url}"),
    ]
    firefox = shutil.which("firefox")
    profile = None
    if firefox:
        # a throw-away profile where the snap's confinement allows it; removed at the end
        base = Path.home() / "snap/firefox/common" if (Path.home() / "snap/firefox").exists() else Path(tempfile.gettempdir())
        profile = Path(tempfile.mkdtemp(prefix="measure-profile-", dir=base))
        for kind, url in (("tls", f"https://127.0.0.1:{tls_port}/"), ("http", http_url)):
            clients.append((kind, "firefox (headless)",
                            f"{firefox} --headless --new-instance --profile {profile} --screenshot {profile}/s.png {url}"))
    tls, http = Recorder(tls_port, "tls"), Recorder(http_port, "http")
    ran = []
    for kind, label, cmd in clients:
        rec = tls if kind == "tls" else http
        rec.label = label
        before = len(rec.messages)
        subprocess.run(f"timeout 30 {cmd} </dev/null >/dev/null 2>&1", shell=True)
        time.sleep(0.5)
        ran.append((kind, label, len(rec.messages) - before))
    if profile:
        shutil.rmtree(profile, ignore_errors=True)
    frames = []
    for i, (label, data) in enumerate(tls.messages + http.messages):
        dport = 443 if data[:1] == b"\x16" else 80
        frames.append(Ether() / IP(src=f"10.9.{i // 250}.{i % 250 + 1}", dst="10.9.255.2")
                      / TCP(sport=40000 + i, dport=dport, flags="PA", seq=1) / data)
    OUT.mkdir(parents=True, exist_ok=True)
    wrpcap(str(OUT / "local.pcap"), frames)
    (OUT / "local_clients.json").write_text(json.dumps(
        [{"kind": k, "client": l, "messages": n} for k, l, n in ran], indent=1))
    return ran


# ---------------------------------------------------------------- report

def percentile(values, q):
    s = sorted(values)
    return s[min(len(s) - 1, max(0, math.ceil(q * len(s)) - 1))]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--local", action="store_true", help="generate messages with the clients installed here")
    ap.add_argument("pcaps", nargs="*")
    args = ap.parse_args()

    if args.local:
        for kind, label, n in local_clients():
            print(f"local {kind:<4} {label:<30} {n} message(s)")
    pcaps = [Path(p) for p in args.pcaps] or (
        sorted((Path.home() / "ja4/pcap").glob("*.pcap*"))
        + [p for p in (ROOT / "results/live/entered.pcap", Path.home() / "curl-impersonate/chrome_impersonate.pcap",
                       Path.home() / "ja4-p4/pcaps/curl_client.pcap", OUT / "local.pcap") if p.exists()])

    samples = defaultdict(list)            # quantity -> [(value, pcap, key)]

    def add(quantity, value, pcap, key):
        samples[quantity].append((value, Path(pcap).name, key))

    failures = []
    for p in pcaps:
        tls_counts(p, add)
        http_counts(p, add)
        dhcp_counts(p, add)
        x509_counts(p, add, failures)

    rows = []
    for quantity, (cap, where) in CAPS.items():
        all_ = samples.get(quantity, [])
        distinct = {}
        for v, src, key in all_:
            distinct.setdefault(key, v)
        values, dvalues = [v for v, _, _ in all_], list(distinct.values())
        if not values:
            rows.append(dict(quantity=quantity, cap=cap, where=where, messages=0))
            continue
        over = sorted({(v, src) for v, src, _ in all_ if v > cap})
        rows.append(dict(quantity=quantity, cap=cap, where=where, messages=len(values), distinct=len(dvalues),
                         p50=percentile(values, 0.5), p95=percentile(values, 0.95), p99=percentile(values, 0.99),
                         max=max(values), distinct_p95=percentile(dvalues, 0.95), distinct_max=max(dvalues),
                         within=sum(v <= cap for v in values), over=over))

    lines = [f"corpus: {len(pcaps)} captures"]
    lines.append(f"{'quantity':<38} {'cap':>5} {'msgs':>5} {'dist':>5} {'p50':>5} {'p95':>5} {'p99':>5} {'max':>5}  within cap")
    for r in rows:
        if not r["messages"]:
            lines.append(f"{r['quantity']:<38} {r['cap']:>5}     0")
            continue
        lines.append(f"{r['quantity']:<38} {r['cap']:>5} {r['messages']:>5} {r['distinct']:>5} {r['p50']:>5} "
                     f"{r['p95']:>5} {r['p99']:>5} {r['max']:>5}  {r['within']}/{r['messages']} "
                     f"({100 * r['within'] / r['messages']:.1f}%)")
        for v, src in r["over"]:
            lines.append(f"    over the cap: {v} in {src}")
    if failures:
        lines.append(f"certificates cryptography could not parse: {len(failures)}")
    print("\n".join(lines))
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "field_counts.txt").write_text("\n".join(lines) + "\n")
    (OUT / "field_counts.json").write_text(json.dumps(
        {"pcaps": [str(p) for p in pcaps], "rows": rows, "certificate_failures": failures}, indent=1, default=str))


if __name__ == "__main__":
    main()
