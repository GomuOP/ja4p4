"""Port reuse: a new connection on the same four-tuple (addresses and ports) as an earlier, closed one.

Clients reuse ports (and NATs reuse them faster), so the second connection must get its own fingerprints, not the
first one's, and the first connection's last JA4SSH window must not be lost or mixed with the second's counts.

The capture built here has, on one TLS four-tuple, a connection with Firefox's ClientHello (its SYN sent twice: a
retransmission is not a new connection), closed with FIN, then a new connection with Chrome's 2,039-byte ClientHello
split in two (in order: tshark, under FoxIO's tool, does not reorder a split hello; the switch's reordering is
tested in test_split_reorder); and, on one SSH four-tuple, the live run's SSH session twice (new initial sequence
numbers). It is replayed through the switch and compared with FoxIO's tool, which tells the connections apart by its
TCP stream number; every fingerprint of every connection must be exact.

    python3 -m unittest tests.test_port_reuse -v
"""
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from scapy.all import IP, TCP, Ether, PcapReader, wrpcap

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import compare, replay  # noqa: E402
from tests.test_split_reorder import PCAPS, find_hello, pieces, two_part_join  # noqa: E402

C, S = "10.3.0.1", "10.3.0.2"
MAC_C, MAC_S = "02:00:00:00:03:01", "02:00:00:00:03:02"


def frame(src_is_client, sport, dport, flags, seq, ack, data=b""):
    src, dst = (C, S) if src_is_client else (S, C)
    mac = (MAC_C, MAC_S) if src_is_client else (MAC_S, MAC_C)
    return Ether(src=mac[0], dst=mac[1]) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags,
                                                                        seq=seq, ack=ack) / data


def tls_connection(cport, isn_c, isn_s, segments, syn_twice=False):
    """A TLS connection: handshake, the client's segments [(offset, bytes)] in the given order, then FIN both ways."""
    out = [frame(True, cport, 443, "S", isn_c, 0)]
    if syn_twice:
        out.append(frame(True, cport, 443, "S", isn_c, 0))
    out += [frame(False, 443, cport, "SA", isn_s, isn_c + 1), frame(True, cport, 443, "A", isn_c + 1, isn_s + 1)]
    for off, data in segments:
        out.append(frame(True, cport, 443, "PA", isn_c + 1 + off, isn_s + 1, data))
    end = isn_c + 1 + max(off + len(d) for off, d in segments)
    out += [frame(True, cport, 443, "FA", end, isn_s + 1), frame(False, 443, cport, "FA", isn_s + 1, end + 1),
            frame(True, cport, 443, "A", end + 1, isn_s + 2)]
    return out


def ssh_connection(cport, isn_c, isn_s):
    """The live run's SSH session (tests/data/ssh_session.pcap) moved to C:cport -> S:22 with new sequence numbers."""
    frames = list(PcapReader(str(ROOT / "tests/data/ssh_session.pcap")))
    orig_c = frames[0][TCP].seq
    orig_s = frames[1][TCP].seq
    out = []
    for p in frames:
        t = p[TCP]
        from_client = t.dport == 22
        seq = (t.seq - (orig_c if from_client else orig_s) + (isn_c if from_client else isn_s)) & 0xFFFFFFFF
        ack = 0 if t.ack == 0 else \
            (t.ack - (orig_s if from_client else orig_c) + (isn_s if from_client else isn_c)) & 0xFFFFFFFF
        out.append(frame(from_client, cport if from_client else 22, 22 if from_client else cport, t.flags, seq, ack,
                         bytes(t.payload)))
    return out


class TestPortReuse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        firefox = find_hello(PCAPS / "latest.pcapng", 1)
        chrome = two_part_join(PCAPS / "sigalg-grease.pcapng")
        frames = tls_connection(40443, 1000, 5000, [(0, firefox)], syn_twice=True)
        frames += tls_connection(40443, 3_000_000_000, 7000, pieces(chrome, [1000]))
        frames += ssh_connection(40022, 20000, 60000)
        frames += ssh_connection(40022, 4_000_000_000, 90000)
        work = Path(tempfile.mkdtemp(prefix="reuse-"))
        cls.pcap = work / "reuse.pcap"
        wrpcap(str(cls.pcap), frames)
        cls.res = replay.run(cls.pcap, timing=False, work=work / "replay")
        cls.rows = compare.compare_records(cls.res, cls.pcap, Path(cls.res["work"]) / "sent.pcap", timing=False)
        for r in cls.rows:
            print(f"\n  {r['verdict']:<8} {r['name']:<7} {r['switch']}  {r['conn']}", end="")
        print()

    def test_every_fingerprint_exact(self):
        bad = [r for r in self.rows if r["verdict"] != "EXACT"]
        self.assertEqual(bad, [])

    def test_each_connection_compared(self):
        """Both TLS connections and both SSH connections have their own rows (JA4T, JA4TS, JA4 / JA4SSH)."""
        names = Counter(r["name"] for r in self.rows)
        self.assertEqual((names["ja4t"], names["ja4ts"], names["ja4"], names["ja4ssh"]), (4, 4, 2, 2))

    def test_forwarding(self):
        self.assertEqual(self.res["unchanged"], self.res["sent"])


if __name__ == "__main__":
    unittest.main()
