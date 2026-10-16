"""Hellos and HTTP requests split over several TCP segments, sent in order, out of order, duplicated, overlapping.

Real ClientHellos and ServerHellos are taken from FoxIO's sample captures; the HTTP requests are FoxIO's cookie
request and a browser-like request of about 1,700 bytes. For HTTP the expected value is the connection's whole list
of JA4H (one per request), so a request reported twice is a failure too. Each case is one TCP connection through
the switch (SYN, SYN-ACK, ACK, then the hello cut into segments and sent in the case's order). The expected value is
what FoxIO's tool reports for the same hello sent whole, in one segment, so the reference never sees the split.

    python3 -m unittest tests.test_split_reorder -v
"""
import itertools
import sys
import tempfile
import time
import unittest
from pathlib import Path

from scapy.all import IP, TCP, Ether, PcapReader, wrpcap

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import reference  # noqa: E402
from tools.replay import Bench, CLIENT_PORT, SERVER_PORT  # noqa: E402

PCAPS = Path.home() / "ja4/pcap"
C, S = "10.1.0.1", "10.1.0.2"
ISN_C, ISN_S = 100000, 900000


def find_hello(pcap, hs_type):
    """The first TCP payload of `pcap` that is a whole TLS hello of type hs_type in one segment."""
    for pkt in PcapReader(str(pcap)):
        if TCP in pkt:
            p = bytes(pkt[TCP].payload)
            if len(p) > 9 and p[0] == 0x16 and p[5] == hs_type:
                hs_len = int.from_bytes(p[6:9], "big")
                if hs_len + 9 <= len(p):
                    return p[:hs_len + 9]       # the record header and the hello only
    raise LookupError(f"no whole hello of type {hs_type} in {pcap}")


def two_records(hello_record, cut):
    """The same hello carried in two TLS records, the handshake message cut at `cut`."""
    hdr, msg = hello_record[:3], hello_record[5:]
    a, b = msg[:cut], msg[cut:]
    return hdr + len(a).to_bytes(2, "big") + a + hdr + len(b).to_bytes(2, "big") + b


NEVER_WRONG_ONLY = {"no SYN seen, second piece first", "after 20 other bytes, split, second piece first"}


SERVER_PORTS = {"ja4": 443, "ja4s": 443, "ja4h": 80}


class Connection:
    """Frames of one TCP connection between C:port and S:server_port."""

    def __init__(self, port, server_port=443):
        self.port = port
        self.sport = server_port

    def handshake(self):
        return [
            (CLIENT_PORT, Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=C, dst=S) / TCP(sport=self.port, dport=self.sport, flags="S", seq=ISN_C)),
            (SERVER_PORT, Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=S, dst=C) / TCP(sport=self.sport, dport=self.port, flags="SA", seq=ISN_S,
                                                           ack=ISN_C + 1)),
            (CLIENT_PORT, Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=C, dst=S) / TCP(sport=self.port, dport=self.sport, flags="A", seq=ISN_C + 1,
                                                           ack=ISN_S + 1)),
        ]

    def segment(self, from_client, offset, data):
        if from_client:
            return (CLIENT_PORT, Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=C, dst=S) / TCP(sport=self.port, dport=self.sport, flags="PA",
                                                                  seq=ISN_C + 1 + offset, ack=ISN_S + 1) / data)
        return (SERVER_PORT, Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=S, dst=C) / TCP(sport=self.sport, dport=self.port, flags="PA",
                                                              seq=ISN_S + 1 + offset, ack=ISN_C + 1) / data)


def pieces(data, cuts):
    """(offset, bytes) pieces of `data` cut at the given offsets."""
    edges = [0] + list(cuts) + [len(data)]
    return [(a, data[a:b]) for a, b in zip(edges, edges[1:])]


def foxio_value(msg, from_client, name):
    """FoxIO's value of fingerprint `name` (ja4, ja4s, ja4h) for `msg` sent whole in one segment of a normal
    connection."""
    conn = Connection(50000, SERVER_PORTS[name])
    frames = [f for _, f in conn.handshake()] + [conn.segment(from_client, 0, msg)[1]]
    with tempfile.NamedTemporaryFile(suffix=".pcap") as f:
        wrpcap(f.name, frames)
        rec = reference.foxio(f.name)[(C, 50000, S, SERVER_PORTS[name])]
    if name == "ja4h":
        return [h["ja4h"] for h in rec["http"]]
    return rec[name]


def http_request():
    """A browser-like request of about 1,700 bytes: many headers, a long Cookie header, Referer, Accept-Language."""
    cookie = "; ".join(f"c{i:02d}={'v' * (i % 7 + 3)}{i}" for i in range(40))
    lines = ["GET /search?q=split+requests&page=2 HTTP/1.1", "Host: www.example.org",
             "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
             "Accept-Language: en-GB,en;q=0.7", "Accept-Encoding: gzip, deflate, br, zstd",
             "Referer: https://www.example.org/start", "Connection: keep-alive", f"Cookie: {cookie}",
             "Upgrade-Insecure-Requests: 1", "Sec-Fetch-Dest: document", "Sec-Fetch-Mode: navigate",
             "Sec-Fetch-Site: same-origin", "Sec-Fetch-User: ?1", "Priority: u=0, i",
             "X-Padding: " + "p" * 600]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def find_request(pcap):
    """The first HTTP request header block of `pcap` sent whole in one segment."""
    for pkt in PcapReader(str(pcap)):
        raw = bytes(pkt)
        start = raw.find(b"GET ")
        end = raw.find(b"\r\n\r\n", start)
        if start >= 0 and end > start:
            return raw[start:end + 4]
    raise LookupError(pcap)


def cases(hello):
    """name -> list of (offset, bytes) in the order they are sent."""
    n = len(hello)
    out = {}
    for cut in sorted({1, 4, 5, 6, 9, 10, 43, 44, 100, n // 2, n - 10, n - 1}):
        out[f"in order, cut at {cut}"] = pieces(hello, [cut])
        out[f"second piece first, cut at {cut}"] = list(reversed(pieces(hello, [cut])))
    three = pieces(hello, [n // 3, 2 * n // 3])
    for order in itertools.permutations(range(3)):
        out[f"three pieces, order {order}"] = [three[i] for i in order]
    a, b = pieces(hello, [n // 2])
    out["first piece twice"] = [a, a, b]
    out["second piece twice, first last"] = [b, b, a]
    out["whole hello again after it"] = [a, b, (0, hello)]
    out["overlap: second piece starts 20 bytes early"] = [a, (b[0] - 20, hello[b[0] - 20:])]
    out["overlap, sent second first"] = [(b[0] - 20, hello[b[0] - 20:]), a]
    out["one byte per segment, last byte first"] = list(reversed(pieces(hello, range(1, n))))
    # Without the handshake the switch learns where the stream starts only from the hello's first segment:
    out["no SYN seen, in order, cut at 100"] = pieces(hello, [100])
    out["no SYN seen, three pieces in order"] = three
    out["no SYN seen, second piece first"] = list(reversed(pieces(hello, [100])))
    # A hello after 20 bytes of something else (as after a SOCKS or HTTP CONNECT exchange):
    prefix = b"\x05\x01\x00" + bytes(17)
    out["after 20 other bytes, whole"] = [(0, prefix), (20, hello)]
    out["after 20 other bytes, split in two, in order"] = [(0, prefix)] + [(20 + o, d) for o, d in pieces(hello, [100])]
    out["after 20 other bytes, split, second piece first"] = \
        [(0, prefix)] + [(20 + o, d) for o, d in reversed(pieces(hello, [100]))]
    return out


class TestSplitReorder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hellos = {      # name -> (message, sent by the client?, fingerprint)
            "ClientHello, 2,039 bytes (Chrome, post-quantum key share)":
                (two_part_join(PCAPS / "sigalg-grease.pcapng"), True, "ja4"),
            "ClientHello, 517 bytes (Firefox)": (find_hello(PCAPS / "latest.pcapng", 1), True, "ja4"),
            "ServerHello (TLS 1.3)": (find_hello(PCAPS / "latest.pcapng", 2), False, "ja4s"),
            "HTTP request with cookies (FoxIO sample)":
                (find_request(PCAPS / "http1-with-cookies.pcapng"), True, "ja4h"),
            "HTTP request, 1,700 bytes (browser-like)": (http_request(), True, "ja4h"),
        }
        cls.bench = Bench(Path(tempfile.mkdtemp(prefix="split-")))
        cls.results = {}
        port = 20000
        cls.expected = {}
        for hname, (hello, from_client, fp) in cls.hellos.items():
            cls.expected[hname] = foxio_value(hello, from_client, fp)
            variants = dict(cases(hello))
            if fp == "ja4h":        # a request after 20 bytes of something else is not an HTTP request
                variants = {k: v for k, v in variants.items() if not k.startswith("after 20")}
            if not from_client:
                # a TLS 1.2-style server flight: ServerHello and 3,000 bytes of certificate in ONE record
                long_rec = hello[:3] + (len(hello) - 5 + 3000).to_bytes(2, "big") + hello[5:] + bytes(3000)
                variants["ServerHello in a long record, cut inside the ServerHello"] = \
                    pieces(long_rec[:1400], [40]) + [(1400, long_rec[1400:2800])]
                variants["ServerHello in a long record, cut inside it, reversed"] = \
                    list(reversed(pieces(long_rec[:2800], [40, 1400])))
            if fp == "ja4":
                variants["two TLS records, one segment"] = [(0, two_records(hello, 200))]
                rec2 = two_records(hello, 200)
                variants["two TLS records, split between them, reversed"] = \
                    list(reversed(pieces(rec2, [5 + 200])))
            for cname, segs in variants.items():
                port += 1
                conn = Connection(port, SERVER_PORTS[fp])
                for p, f in conn.handshake():
                    if not cname.startswith("no SYN"):
                        cls.bench.port.send(p, bytes(f))
                for off, data in segs:
                    p, f = conn.segment(from_client, off, data)
                    cls.bench.port.send(p, bytes(f))
                    time.sleep(0.002)
                cls.results[(hname, cname)] = port
        cls.bench.settle(quiet=2.0)
        cls.records = {r["client_port"]: r for r in cls.bench.ctl.records.all() if "client_port" in r}
        cls.bench.close()

    def test_limits_are_never_wrong(self):
        """Documented limits: a piece that arrives before the hello's first segment cannot be placed when the switch
        does not know where the hello's stream starts (no SYN seen), or when the stream did not start with a hello
        (the copying of early pieces has stopped). The hello is then not reported (or reported exactly), never
        reported wrong."""
        for (hname, cname), port in self.results.items():
            if cname in NEVER_WRONG_ONLY:
                got = self.records.get(port, {}).get(self.hellos[hname][2])
                print(f"\n  limit case {hname} / {cname}: "
                      f"{'not reported' if got is None else 'exact' if got == self.expected[hname] else got}")
                self.assertIn(got, (None, self.expected[hname]), f"{hname} / {cname}")

    def test_every_case(self):
        failures = []
        scored = 0
        for (hname, cname), port in self.results.items():
            if cname in NEVER_WRONG_ONLY:
                continue                    # see test_limits_are_never_wrong
            scored += 1
            got = self.records.get(port, {}).get(self.hellos[hname][2])
            want = self.expected[hname]
            if got != want:
                failures.append(f"{hname} / {cname}: switch {got}, FoxIO {want}")
        print(f"\n{scored - len(failures)} of {scored} cases exact")
        self.assertEqual(failures, [])


def two_part_join(pcap):
    """A ClientHello that the capture itself carries in two segments, joined (the reference gets it whole)."""
    data = b""
    for pkt in PcapReader(str(pcap)):
        if TCP in pkt and pkt[TCP].dport == 443 and len(pkt[TCP].payload):
            data += bytes(pkt[TCP].payload)
            if len(data) > 9 and int.from_bytes(data[6:9], "big") + 9 <= len(data):
                return data[:int.from_bytes(data[6:9], "big") + 9]
    raise LookupError(pcap)


if __name__ == "__main__":
    unittest.main()
