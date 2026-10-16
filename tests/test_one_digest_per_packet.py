"""BMv2 keeps one digest per packet. Two fingerprints completed by the same packet must both be reported.

The case: the client's ACK that completes the TCP handshake (JA4L) also carries a whole ClientHello (JA4), or a
whole HTTP request (JA4H). Expected: JA4L, and the message's fingerprint equal to FoxIO's for the same message.

    python3 -m unittest tests.test_one_digest_per_packet
"""
import sys
import tempfile
import time
import unittest
from pathlib import Path

from scapy.all import IP, TCP, Ether

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.test_split_reorder import PCAPS, find_hello, find_request, foxio_value  # noqa: E402
from tools.replay import Bench, CLIENT_PORT, SERVER_PORT  # noqa: E402

C, S = "10.2.0.1", "10.2.0.2"
MAC = dict(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def handshake_with_data(cport, sport, payload):
    syn = Ether(**MAC) / IP(src=C, dst=S) / TCP(sport=cport, dport=sport, flags="S", seq=100)
    synack = Ether(**MAC) / IP(src=S, dst=C) / TCP(sport=sport, dport=cport, flags="SA", seq=900, ack=101)
    ack = Ether(**MAC) / IP(src=C, dst=S) / TCP(sport=cport, dport=sport, flags="PA", seq=101, ack=901) / payload
    return syn, synack, ack


class TestOneDigestPerPacket(unittest.TestCase):
    def test_message_on_the_handshake_ack(self):
        hello = find_hello(PCAPS / "latest.pcapng", 1)
        request = find_request(PCAPS / "http1-with-cookies.pcapng")
        bench = Bench(Path(tempfile.mkdtemp(prefix="onedigest-")))
        try:
            for cport, sport, payload in ((31001, 443, hello), (31002, 80, request)):
                syn, synack, ack = handshake_with_data(cport, sport, payload)
                bench.port.send(CLIENT_PORT, bytes(syn))
                time.sleep(0.01)
                bench.port.send(SERVER_PORT, bytes(synack))
                time.sleep(0.01)
                bench.port.send(CLIENT_PORT, bytes(ack))
            bench.settle()
            recs = {r["client_port"]: r for r in bench.ctl.records.all() if "client_port" in r}
        finally:
            bench.close()
        tls, http = recs[31001], recs[31002]
        self.assertIn("ja4l_c", tls)
        self.assertIn("ja4l_c", http)
        self.assertEqual(tls.get("ja4"), foxio_value(hello, True, "ja4"))
        self.assertEqual(http.get("ja4h"), foxio_value(request, True, "ja4h"))


if __name__ == "__main__":
    unittest.main()
