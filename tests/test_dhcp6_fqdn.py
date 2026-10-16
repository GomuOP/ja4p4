"""JA4D6's domain flag: 'd' only when the Client FQDN option (39) carries a name.

Found in the live run (network/run_live.py): busybox udhcpc6 sends option 39 with length 2, the flags byte and a single 0x00, a root-only
(empty) name. FoxIO's plugin sets 'd' on tshark's dhcpv6.client_domain field, which tshark does not give for a
root-only name, so the expected flag is 'n'. A real name (a label, then 0x00) must still give 'd'.

    python3 -m unittest tests.test_dhcp6_fqdn
"""
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

from scapy.all import UDP, Ether, IPv6, wrpcap

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import reference  # noqa: E402
from tools.replay import Bench, CLIENT_PORT  # noqa: E402


def option(code, data):
    return struct.pack("!HH", code, len(data)) + data


def solicit(fqdn_name):
    """A Solicit like udhcpc6's: elapsed time, IA_NA, option request, client FQDN (flags + name), client id."""
    body = (option(8, b"\x00\x00")
            + option(3, b"\x00\x00\x00\x01" + b"\x00" * 8)
            + option(6, b"\x00\x17\x00\x18")
            + option(39, b"\x00" + fqdn_name)
            + option(1, bytes.fromhex("00030001000000000001")))
    return (Ether(src="00:00:00:00:00:01", dst="33:33:00:01:00:02")
            / IPv6(src="fe80::200:ff:fe00:1", dst="ff02::1:2") / UDP(sport=546, dport=547)
            / (b"\x01\x3f\xc7\x78" + body))


class TestDhcp6Fqdn(unittest.TestCase):
    def test_domain_flag(self):
        work = Path(tempfile.mkdtemp(prefix="dhcp6fqdn-"))
        frames = [solicit(b"\x00"),                      # root-only name: no domain
                  solicit(b"\x02h1\x04test\x00")]         # h1.test: a domain
        wrpcap(str(work / "sent.pcap"), frames)
        expected = reference.tshark_ja4d(work / "sent.pcap")
        self.assertEqual([v[10] for v in expected], ["n", "d"])   # the reference itself makes the distinction
        bench = Bench(work)
        try:
            for f in frames:
                bench.port.send(CLIENT_PORT, bytes(f))
                time.sleep(0.05)
            bench.settle()
            got = [v for name, v in bench.ctl.records.messages if name == "ja4d6"]
        finally:
            bench.close()
        self.assertEqual(got, expected)


if __name__ == "__main__":
    unittest.main()
