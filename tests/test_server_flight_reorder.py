"""The server's side split and out of order: a TLS 1.2 server flight (ServerHello, Certificate with a chain of two,
ServerKeyExchange, ServerHelloDone; 2,241 bytes) cut into segments and sent in order, reversed, in every order of
three pieces, duplicated and overlapping.

The flight is h2's from the live run (tests/data/tls12_server_flight.bin: openssl s_server on port 8443, with the
run's own test certificates). The expected JA4S and JA4X are what FoxIO's tool reports for the same flight sent
whole, in one segment. A ServerHello that is itself split starts no certificate copy (a documented limit): there
JA4S must be exact and JA4X not reported or exact, never wrong.

    python3 -m unittest tests.test_server_flight_reorder -v
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
from tests.test_split_reorder import C, S, Connection, pieces  # noqa: E402

FLIGHT = (ROOT / "tests/data/tls12_server_flight.bin").read_bytes()
HELLO_END = 5 + int.from_bytes(FLIGHT[3:5], "big")        # the ServerHello record ends here (98)


def foxio_values():
    conn = Connection(50000)
    frames = [f for _, f in conn.handshake()] + [conn.segment(False, 0, FLIGHT)[1]]
    with tempfile.NamedTemporaryFile(suffix=".pcap") as f:
        wrpcap(f.name, frames)
        rec = reference.foxio(f.name)[(C, 50000, S, 443)]
    return rec["ja4s"], [c.get("ja4x") for c in rec["tls_certs"][0]["x509"]]


def cases():
    n = len(FLIGHT)
    out = {}
    tcp = pieces(FLIGHT, [1448])                          # as TCP cut it in the live run
    out["as in the live run (cut at 1448), in order"] = tcp
    out["as in the live run, second segment first"] = list(reversed(tcp))
    three = pieces(FLIGHT, [HELLO_END, 1200])             # ServerHello alone, then the certificates in two
    for order in itertools.permutations(range(3)):
        out[f"ServerHello alone + two pieces, order {order}"] = [three[i] for i in order]
    mixed = pieces(FLIGHT, [700, 1500])                   # ServerHello with the start of the certificates
    for order in itertools.permutations(range(3)):
        out[f"three pieces cut at 700 / 1500, order {order}"] = [mixed[i] for i in order]
    a, b = tcp
    out["second segment twice, first last"] = [b, b, a]
    out["first segment twice"] = [a, a, b]
    out["overlap: second starts 50 bytes early, sent first"] = [(1398, FLIGHT[1398:]), a]
    out["100-byte pieces, ServerHello piece whole, rest reversed"] = \
        [(0, FLIGHT[:HELLO_END])] + list(reversed([(HELLO_END + o, d) for o, d in
                                                 pieces(FLIGHT[HELLO_END:], range(100, n - HELLO_END, 100))]))
    out["100-byte pieces, all reversed (ServerHello last)"] = \
        list(reversed([(0, FLIGHT[:HELLO_END])] +
                      [(HELLO_END + o, d) for o, d in pieces(FLIGHT[HELLO_END:], range(100, n - HELLO_END, 100))]))
    return out


LIMITS = {   # the ServerHello itself split: no certificate copy starts (documented limit)
    "ServerHello split at 40, in order": pieces(FLIGHT, [40, 1448]),
    "ServerHello split at 40, reversed": list(reversed(pieces(FLIGHT, [40, 1448]))),
}


class TestServerFlightReorder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ja4s, cls.ja4x = foxio_values()
        cls.bench = Bench(Path(tempfile.mkdtemp(prefix="flight-")))
        cls.ports = {}
        port = 30000
        for name, segs in {**cases(), **LIMITS}.items():
            port += 1
            conn = Connection(port)
            for p, f in conn.handshake():
                cls.bench.port.send(p, bytes(f))
            for off, data in segs:
                p, f = conn.segment(False, off, data)
                cls.bench.port.send(p, bytes(f))
                time.sleep(0.002)
            cls.ports[name] = port
        cls.bench.settle(quiet=2.0)
        cls.records = {r["client_port"]: r for r in cls.bench.ctl.records.all() if "client_port" in r}
        cls.bench.close()

    def test_reference(self):
        self.assertEqual(len(self.ja4x), 2)

    def test_every_order(self):
        failures = []
        for name in cases():
            rec = self.records.get(self.ports[name], {})
            if rec.get("ja4s") != self.ja4s or rec.get("ja4x") != self.ja4x:
                failures.append(f"{name}: switch {rec.get('ja4s')} {rec.get('ja4x')}")
        print(f"\n{len(cases()) - len(failures)} of {len(cases())} cases exact (JA4S and both JA4X)")
        self.assertEqual(failures, [])

    def test_split_server_hello_is_never_wrong(self):
        for name in LIMITS:
            rec = self.records.get(self.ports[name], {})
            print(f"\n  limit case {name}: JA4S {'exact' if rec.get('ja4s') == self.ja4s else rec.get('ja4s')}, "
                  f"JA4X {'not reported' if rec.get('ja4x') is None else rec.get('ja4x')}")
            self.assertEqual(rec.get("ja4s"), self.ja4s, name)
            self.assertIn(rec.get("ja4x"), (None, self.ja4x), name)


if __name__ == "__main__":
    unittest.main()
