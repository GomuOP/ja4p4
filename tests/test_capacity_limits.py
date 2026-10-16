"""The switch keeps every list in fixed-size fields (TLS_CIPHER_CAP, TLS_EXT_CAP, TLS_SIG_CAP, DHCP_OPT_CAP,
HTTP_NAMES_CAP, HTTP_COOKIES_CAP). At its capacity a list must still give FoxIO's exact value; one past it, the
fingerprint must be reported incomplete, never a wrong value. (tools/measure_field_counts.py shows that every message
of the corpus fits; this test checks the path for the ones that would not.)

    python3 -m unittest tests.test_capacity_limits
"""
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

from scapy.all import BOOTP, DHCP, IP, TCP, UDP, Ether, wrpcap

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.test_split_reorder import foxio_value  # noqa: E402
from tools import reference  # noqa: E402
from tools.replay import Bench, CLIENT_PORT  # noqa: E402

MAC = dict(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
C, S = "10.5.0.1", "10.5.0.2"
TLS_CIPHER_CAP, TLS_EXT_CAP, TLS_SIG_CAP = 128, 64, 64
DHCP_OPT_CAP = 64
HTTP_NAMES_CAP, HTTP_COOKIES_CAP = 512, 1024


def client_hello(n_ciphers, n_exts, n_sigs):
    """A TLS 1.2 ClientHello: n_ciphers suites, n_exts extensions (SNI, signature_algorithms with n_sigs values,
    then empty private-use extensions), none of them GREASE."""
    ciphers = b"".join(struct.pack("!H", 0x0100 + i) for i in range(n_ciphers))
    sni_name = b"cap.test"
    sni = struct.pack("!HHHBH", 0, len(sni_name) + 5, len(sni_name) + 3, 0, len(sni_name)) + sni_name
    sig_list = b"".join(struct.pack("!H", 0x0401 + i) for i in range(n_sigs))
    sigs = struct.pack("!HHH", 13, len(sig_list) + 2, len(sig_list)) + sig_list
    others = b"".join(struct.pack("!HH", 0xff00 + i, 0) for i in range(n_exts - 2))
    exts = sni + sigs + others
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack("!H", len(ciphers)) + ciphers + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def request(names_bytes, cookie_bytes):
    """A GET whose header names (with one separator byte each, as the switch keeps them) take about names_bytes,
    and whose Cookie pairs (with one separator each) take about cookie_bytes."""
    lines = [b"Host: cap.test"]
    used = len("Host") + 1
    i = 0
    while used + 12 <= names_bytes:
        name = f"X-Pad-{i:05d}".encode()               # 11 bytes + separator
        lines.append(name + b": v")
        used += len(name) + 1
        i += 1
    pairs, size, j = [], 0, 0
    while size + 16 <= cookie_bytes:
        pairs.append(f"k{j:04d}=vvvvvvvvv".encode())    # 15 bytes + separator
        size += 16
        j += 1
    if pairs:
        lines.append(b"Cookie: " + b"; ".join(pairs))
    return b"GET / HTTP/1.1\r\n" + b"\r\n".join(lines) + b"\r\n\r\n"


def dhcp_discover(n_opts):
    """A DHCPDISCOVER listing n_opts options in JA4D's option list (53 and 255 are not listed)."""
    opts = [("message-type", "discover")] + [(224 + (i % 30), b"x" * (1 + i // 30)) for i in range(n_opts)] + ["end"]
    return (Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67) / BOOTP(chaddr=b"\x02\x00\x00\x00\x00\x01", xid=n_opts) / DHCP(options=opts))


def tcp_message(cport, sport, payload):
    c = Ether(**MAC) / IP(src=C, dst=S)
    s = Ether(**MAC) / IP(src=S, dst=C)
    return [c / TCP(sport=cport, dport=sport, flags="S", seq=100),
            s / TCP(sport=sport, dport=cport, flags="SA", seq=900, ack=101),
            c / TCP(sport=cport, dport=sport, flags="A", seq=101, ack=901),
            c / TCP(sport=cport, dport=sport, flags="PA", seq=101, ack=901) / payload]


class TestCapacityLimits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tls_cases = {   # client port: (hello, at the capacity?)
            33001: (client_hello(TLS_CIPHER_CAP, 10, 10), True),
            33002: (client_hello(TLS_CIPHER_CAP + 1, 10, 10), False),
            33003: (client_hello(10, TLS_EXT_CAP, 10), True),
            33004: (client_hello(10, TLS_EXT_CAP + 1, 10), False),
            33005: (client_hello(10, 10, TLS_SIG_CAP), True),
            33006: (client_hello(10, 10, TLS_SIG_CAP + 1), False),
        }
        cls.http_cases = {
            33101: (request(HTTP_NAMES_CAP - 16, 0), True),
            33102: (request(HTTP_NAMES_CAP + 40, 0), False),
            33103: (request(64, HTTP_COOKIES_CAP - 16), True),
            33104: (request(64, HTTP_COOKIES_CAP + 40), False),
        }
        cls.dhcp_frames = [dhcp_discover(DHCP_OPT_CAP), dhcp_discover(DHCP_OPT_CAP + 1)]
        bench = Bench(Path(tempfile.mkdtemp(prefix="caps-")))
        try:
            for cport, (hello, _) in cls.tls_cases.items():
                for f in tcp_message(cport, 443, hello):
                    bench.port.send(CLIENT_PORT, bytes(f))
                    time.sleep(0.01)
            for cport, (req, _) in cls.http_cases.items():
                for f in tcp_message(cport, 80, req):
                    bench.port.send(CLIENT_PORT, bytes(f))
                    time.sleep(0.01)
            for f in cls.dhcp_frames:
                bench.port.send(CLIENT_PORT, bytes(f))
                time.sleep(0.05)
            bench.settle()
            cls.recs = {r["client_port"]: r for r in bench.ctl.records.all() if "client_port" in r}
            cls.dhcp = [v for name, v in bench.ctl.records.messages if name == "ja4d"]
        finally:
            bench.close()

    def test_tls(self):
        for cport, (hello, at_cap) in self.tls_cases.items():
            rec = self.recs[cport]
            with self.subTest(port=cport, at_cap=at_cap):
                if at_cap:
                    self.assertEqual(rec.get("ja4"), foxio_value(hello, True, "ja4"))
                else:
                    self.assertNotIn("ja4", rec)
                    self.assertIn("than the switch keeps", rec.get("ja4_incomplete", ""))

    def test_http(self):
        for cport, (req, at_cap) in self.http_cases.items():
            rec = self.recs[cport]
            with self.subTest(port=cport, at_cap=at_cap):
                if at_cap:
                    self.assertEqual(rec.get("ja4h"), foxio_value(req, True, "ja4h"))
                else:
                    self.assertEqual(len(rec.get("ja4h", [])), 1)
                    self.assertTrue(rec["ja4h"][0].startswith("incomplete: "), rec["ja4h"])

    def test_dhcp(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap") as f:
            wrpcap(f.name, self.dhcp_frames)
            expected = reference.tshark_ja4d(f.name)
        self.assertEqual(len(expected[0].split("_")[1].split("-")), DHCP_OPT_CAP)
        self.assertEqual(self.dhcp[0], expected[0])
        self.assertIsNone(self.dhcp[1])     # recorded as incomplete, no value


if __name__ == "__main__":
    unittest.main()
