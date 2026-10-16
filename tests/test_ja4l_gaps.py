"""JA4L with known gaps: SYN, then SYN-ACK 1 s later, then ACK 0.5 s later.

Expected: JA4L-S = (SYN-ACK time - SYN time) / 2 with the server's TTL, JA4L-C = (ACK time - SYN-ACK time) / 2 with
the client's TTL, the times being those at which the test handed each frame to the switch (about 500,000 and 250,000
us). The switch timestamps frames when its pipeline takes them up, a little later; the difference (a few ms on this 2-CPU VM) is
small against these gaps, so the test allows 2 % of each half. Run it on an otherwise idle machine: under heavy load
(once, with headless Firefox and a full comparison running on the 2-CPU VM) BMv2 took the SYN up 130 ms after it
was handed over, and the server half came out 13 % short. That is the stamping delay above, not an arithmetic error;
widening the tolerance would hide real arithmetic errors (a wrong halving is off by 50-100 %).
Also checks JA4T and JA4TS of the same crafted handshake exactly.

    python3 -m unittest tests.test_ja4l_gaps
"""
import sys
import time
import tempfile
import unittest
from pathlib import Path

from scapy.all import IP, TCP, Ether

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools.replay import Bench, CLIENT_PORT, SERVER_PORT  # noqa: E402

C, S = "10.0.0.1", "10.0.0.2"


def frames():
    syn = Ether() / IP(src=C, dst=S, ttl=64) / TCP(sport=40000, dport=443, flags="S", seq=1000, window=64240,
                                                  options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)),
                                                           ("NOP", None), ("WScale", 7)])
    synack = Ether() / IP(src=S, dst=C, ttl=128) / TCP(sport=443, dport=40000, flags="SA", seq=5000, ack=1001,
                                                      window=65535, options=[("MSS", 1400), ("NOP", None),
                                                                             ("WScale", 0)])
    ack = Ether() / IP(src=C, dst=S, ttl=64) / TCP(sport=40000, dport=443, flags="A", seq=1001, ack=5001)
    return syn, synack, ack


class TestJa4lGaps(unittest.TestCase):
    def test_known_gaps(self):
        bench = Bench(Path(tempfile.mkdtemp(prefix="ja4l-")))
        try:
            syn, synack, ack = frames()
            t_a = time.monotonic()
            bench.port.send(CLIENT_PORT, bytes(syn))
            time.sleep(1.0)
            t_b = time.monotonic()
            bench.port.send(SERVER_PORT, bytes(synack))
            time.sleep(0.5)
            t_c = time.monotonic()
            bench.port.send(CLIENT_PORT, bytes(ack))
            bench.settle()
            recs = bench.ctl.records.all()
        finally:
            bench.close()
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual(r["ja4t"], "64240_2-4-8-1-3_1460_7")
        self.assertEqual(r["ja4ts"], "65535_2-1-3_1400_00")
        lat_c, ttl_c = map(int, r["ja4l_c"].split("_"))
        lat_s, ttl_s = map(int, r["ja4l_s"].split("_"))
        self.assertEqual((ttl_c, ttl_s), (64, 128))
        want_s = (t_b - t_a) * 1e6 / 2
        want_c = (t_c - t_b) * 1e6 / 2
        self.assertAlmostEqual(lat_s, want_s, delta=0.02 * want_s)
        self.assertAlmostEqual(lat_c, want_c, delta=0.02 * want_c)


if __name__ == "__main__":
    unittest.main()
