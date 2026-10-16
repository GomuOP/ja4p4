"""A later request on a keep-alive connection, split over several segments and out of order.

On one HTTP/1.1 connection: a first request sent whole, then a second request (browser-like, about 1,700 bytes) cut
into pieces and sent in the case's order, then a third request sent whole. Before the second request's first piece
arrives, its later pieces lie ahead of a gap in a direction that has already started (copy rule (c) covers only a
direction that has not). The expected value is FoxIO's list of the connection's three JA4H, computed on the same
three requests sent whole.

    python3 -m unittest tests.test_keepalive_reorder -v
"""
import itertools
import sys
import tempfile
import time
import unittest
from pathlib import Path

from scapy.all import wrpcap

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import reference  # noqa: E402
from tools.replay import Bench  # noqa: E402
from tests.test_split_reorder import (PCAPS, C, S, Connection, find_request, http_request,  # noqa: E402
                                      pieces)

FIRST = find_request(PCAPS / "http1-with-cookies.pcapng")
SECOND = http_request()
THIRD = b"GET /favicon.ico HTTP/1.1\r\nHost: www.example.org\r\nAccept: image/avif,image/webp,*/*\r\n\r\n"


def cases():
    n = len(SECOND)
    out = {}
    for cut in (1, 10, 100, n // 2, n - 1):
        out[f"two pieces, cut at {cut}, in order"] = pieces(SECOND, [cut])
        out[f"two pieces, cut at {cut}, second first"] = list(reversed(pieces(SECOND, [cut])))
    three = pieces(SECOND, [n // 3, 2 * n // 3])
    for order in itertools.permutations(range(3)):
        out[f"three pieces, order {order}"] = [three[i] for i in order]
    a, b = pieces(SECOND, [n // 2])
    out["second piece twice, first last"] = [b, b, a]
    out["overlap, sent second first"] = [(b[0] - 20, SECOND[b[0] - 20:]), a]
    return out


def segments(second_pieces):
    """(offset, bytes) of the client's whole stream: the first request, the second in pieces, the third."""
    base = len(FIRST)
    return [(0, FIRST)] + [(base + o, d) for o, d in second_pieces] + [(base + len(SECOND), THIRD)]


class TestKeepAliveReorder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        conn = Connection(50000, 80)
        frames = [f for _, f in conn.handshake()] + [conn.segment(True, o, d)[1] for o, d in segments([(0, SECOND)])]
        with tempfile.NamedTemporaryFile(suffix=".pcap") as f:
            wrpcap(f.name, frames)
            cls.expected = [h["ja4h"] for h in reference.foxio(f.name)[(C, 50000, S, 80)]["http"]]
        cls.bench = Bench(Path(tempfile.mkdtemp(prefix="keepalive-")))
        cls.ports = {}
        port = 40000
        for name, second in cases().items():
            port += 1
            conn = Connection(port, 80)
            for p, f in conn.handshake():
                cls.bench.port.send(p, bytes(f))
            for off, data in segments(second):
                p, f = conn.segment(True, off, data)
                cls.bench.port.send(p, bytes(f))
                time.sleep(0.002)
            cls.ports[name] = port
        cls.bench.settle(quiet=2.0)
        cls.records = {r["client_port"]: r for r in cls.bench.ctl.records.all() if "client_port" in r}
        cls.bench.close()

    def test_reference(self):
        self.assertEqual(len(self.expected), 3)

    def test_every_order(self):
        failures = []
        for name, port in self.ports.items():
            got = self.records.get(port, {}).get("ja4h")
            if got != self.expected:
                failures.append(f"{name}: switch {got}")
        print(f"\n{len(self.ports) - len(failures)} of {len(self.ports)} cases exact (all three JA4H, in order)")
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
