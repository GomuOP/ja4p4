"""Traffic a real network carries that the h1 -- s1 -- h2 runs did not: VLAN tags, and SSH on a port other than 22.

* A TLS connection inside one 802.1Q tag, and an HTTP request inside two tags (802.1ad outer, 802.1Q inner): FoxIO's
  tool reads through the tags, so the switch must too (and forward the tagged frames unchanged).
* The live run's SSH session moved to port 2222: tshark, under FoxIO's tool, recognises SSH by its "SSH-" banner
  on any port, so the switch must too.

The capture is replayed through the switch and compared with FoxIO's tool; every fingerprint must be exact.

    python3 -m unittest tests.test_vlan_and_ssh_port -v
"""
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from scapy.all import IP, TCP, Dot1AD, Dot1Q, Ether, wrpcap

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import compare, replay  # noqa: E402
from tests.test_split_reorder import PCAPS, find_hello, find_request  # noqa: E402
from tests.test_port_reuse import ssh_connection  # noqa: E402

C, S = "10.5.0.1", "10.5.0.2"


def tagged(tags, src_is_client, sport, dport, flags, seq, ack, data=b""):
    src, dst = (C, S) if src_is_client else (S, C)
    macs = ("02:00:00:00:05:01", "02:00:00:00:05:02") if src_is_client else ("02:00:00:00:05:02", "02:00:00:00:05:01")
    l2 = Ether(src=macs[0], dst=macs[1])
    for tag in tags:
        l2 = l2 / tag
    return l2 / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack) / data


def connection(tags, cport, sport, message):
    f = lambda *a, **k: tagged(tags(), *a, **k)  # noqa: E731
    end = 1001 + len(message)
    return [f(True, cport, sport, "S", 1000, 0), f(False, sport, cport, "SA", 5000, 1001),
            f(True, cport, sport, "A", 1001, 5001), f(True, cport, sport, "PA", 1001, 5001, message),
            f(True, cport, sport, "FA", end, 5001), f(False, sport, cport, "FA", 5001, end + 1),
            f(True, cport, sport, "A", end + 1, 5002)]


def ssh_on_port(port):
    frames = ssh_connection(42022, 30000, 70000)
    for p in frames:
        t = p[TCP]
        t.sport, t.dport = (port if t.sport == 22 else t.sport), (port if t.dport == 22 else t.dport)
        p[IP].src, p[IP].dst = (C, S) if t.dport == port else (S, C)
    return frames


class TestVlanAndSshPort(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        frames = connection(lambda: [Dot1Q(vlan=10)], 41443, 443, find_hello(PCAPS / "latest.pcapng", 1))
        frames += connection(lambda: [Dot1AD(vlan=100), Dot1Q(vlan=20)], 41080, 80,
                             find_request(PCAPS / "http1-with-cookies.pcapng"))
        frames += ssh_on_port(2222)
        work = Path(tempfile.mkdtemp(prefix="vlan-"))
        cls.pcap = work / "vlan.pcap"
        wrpcap(str(cls.pcap), frames)
        cls.res = replay.run(cls.pcap, timing=False, work=work / "replay")
        cls.rows = compare.compare_records(cls.res, cls.pcap, Path(cls.res["work"]) / "sent.pcap", timing=False)
        for r in cls.rows:
            print(f"\n  {r['verdict']:<8} {r['name']:<7} {r['switch']}  {r['conn']}", end="")
        print()

    def test_every_fingerprint_exact(self):
        self.assertEqual([r for r in self.rows if r["verdict"] != "EXACT"], [])

    def test_each_fingerprint_compared(self):
        names = Counter(r["name"] for r in self.rows)
        self.assertEqual((names["ja4t"], names["ja4"], names["ja4h"], names["ja4ssh"]), (3, 1, 1, 1))

    def test_forwarding(self):
        self.assertEqual(self.res["unchanged"], self.res["sent"])


if __name__ == "__main__":
    unittest.main()
