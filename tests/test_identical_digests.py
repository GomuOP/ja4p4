"""Identical messages close together must each be reported.

BMv2's learn engine holds every digest until the controller acknowledges it and drops a digest identical to one it
holds. Found in the live run: dnsmasq answered three DHCP Discover retransmissions with three identical Offers 0.1 ms
apart, and the replay reported two. The same can happen to two identical HTTP requests on one keep-alive connection.
FoxIO reports each message, so the switch must too. JA4SSH too: its counts start again at every 200-packet window,
so steady traffic (a bulk copy) gives identical windows, sent as fast as the link allows. The replay cannot send 200
packets within one acknowledgement time, as a fast link can; the SSH case holds each acknowledgement back instead
(ACK_DELAY), which makes the same overlap.

    python3 -m unittest tests.test_identical_digests
"""
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from p4.v1 import p4runtime_pb2
from scapy.all import BOOTP, DHCP, IP, TCP, UDP, Ether, wrpcap

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from controller.p4runtime_client import SwitchConnection  # noqa: E402
from tools import compare, reference  # noqa: E402
from tools.replay import Bench, CLIENT_PORT, SERVER_PORT  # noqa: E402

REPEATS = 3
ROUNDS = 5          # the loss depends on how fast the controller acknowledges: several rounds make it show
MAC = dict(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
ACK_DELAY = 0.5     # seconds


def on_digest_slow_ack(self, digest_list):
    """SwitchConnection._on_digest, with the acknowledgement sent ACK_DELAY seconds late."""
    handler = self._digest_handlers.get(self.p4info.digest_name(digest_list.digest_id))
    for data in digest_list.data:
        if handler:
            handler([int.from_bytes(m.bitstring, "big") for m in data.struct.members])
    ack = p4runtime_pb2.StreamMessageRequest()
    ack.digest_ack.digest_id = digest_list.digest_id
    ack.digest_ack.list_id = digest_list.list_id
    threading.Timer(ACK_DELAY, self._requests.put, (ack,)).start()


def offer(xid):
    return (Ether(**MAC) / IP(src="10.0.0.2", dst="10.0.0.101") / UDP(sport=67, dport=68)
            / BOOTP(op=2, xid=xid, yiaddr="10.0.0.101")
            / DHCP(options=[("message-type", "offer"), ("server_id", "10.0.0.2"), ("lease_time", 43200),
                            ("subnet_mask", "255.255.255.0"), "end"]))


class TestIdenticalDigests(unittest.TestCase):
    def test_dhcp_messages(self):
        work = Path(tempfile.mkdtemp(prefix="identical-dhcp-"))
        frames = [offer(0x1000 + r) for r in range(ROUNDS) for _ in range(REPEATS)]
        wrpcap(str(work / "sent.pcap"), frames)
        expected = reference.tshark_ja4d(work / "sent.pcap")
        self.assertEqual(len(expected), ROUNDS * REPEATS)
        bench = Bench(work)
        try:
            for r in range(ROUNDS):
                for f in frames[r * REPEATS:(r + 1) * REPEATS]:
                    bench.port.send(SERVER_PORT, bytes(f))
                time.sleep(0.2)
            bench.settle()
            got = [v for name, v in bench.ctl.records.messages if name == "ja4d"]
        finally:
            bench.close()
        self.assertEqual(got, expected)

    def test_http_requests_on_one_connection(self):
        request = b"GET / HTTP/1.1\r\nHost: 10.0.0.2\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n"
        bench = Bench(Path(tempfile.mkdtemp(prefix="identical-http-")))
        try:
            for r in range(ROUNDS):
                cport = 32000 + r
                c = Ether(**MAC) / IP(src="10.3.0.1", dst="10.3.0.2")
                s = Ether(**MAC) / IP(src="10.3.0.2", dst="10.3.0.1")
                bench.port.send(CLIENT_PORT, bytes(c / TCP(sport=cport, dport=80, flags="S", seq=100)))
                time.sleep(0.01)
                bench.port.send(SERVER_PORT, bytes(s / TCP(sport=80, dport=cport, flags="SA", seq=900, ack=101)))
                time.sleep(0.01)
                bench.port.send(CLIENT_PORT, bytes(c / TCP(sport=cport, dport=80, flags="A", seq=101, ack=901)))
                time.sleep(0.01)
                for i in range(REPEATS):
                    seq = 101 + i * len(request)
                    bench.port.send(CLIENT_PORT, bytes(c / TCP(sport=cport, dport=80, flags="PA", seq=seq, ack=901)
                                                       / request))
                time.sleep(0.2)
            bench.settle()
            counts = {r["client_port"]: len(r.get("ja4h", [])) for r in bench.ctl.records.all()
                      if "client_port" in r}
        finally:
            bench.close()
        self.assertEqual(counts, {32000 + r: REPEATS for r in range(ROUNDS)})


    def test_ssh_identical_windows(self):
        c = Ether(**MAC) / IP(src="10.4.0.1", dst="10.4.0.2")
        s = Ether(**MAC) / IP(src="10.4.0.2", dst="10.4.0.1")
        frames = [c / TCP(sport=40000, dport=22, flags="S", seq=100),
                  s / TCP(sport=22, dport=40000, flags="SA", seq=900, ack=101),
                  c / TCP(sport=40000, dport=22, flags="A", seq=101, ack=901)]
        cseq, sseq = 101, 901
        for _ in range(4 * 100):                 # four windows of 200 SSH packets, all alike: 100 exchanges each
            frames.append(c / TCP(sport=40000, dport=22, flags="PA", seq=cseq, ack=sseq) / (b"\x00" * 36))
            cseq += 36
            frames.append(s / TCP(sport=22, dport=40000, flags="PA", seq=sseq, ack=cseq) / (b"\x00" * 52))
            sseq += 52
        work = Path(tempfile.mkdtemp(prefix="identical-ssh-"))
        wrpcap(str(work / "ssh.pcap"), frames)
        with mock.patch.object(SwitchConnection, "_on_digest", on_digest_slow_ack):
            rows, _ = compare.compare(work / "ssh.pcap", timing=False, work_root=work)
        ssh = [r for r in rows if r["name"] == "ja4ssh"]
        self.assertEqual(len(ssh), 1)
        self.assertEqual(len(ssh[0]["reference"]), 4)
        self.assertEqual(ssh[0]["switch"], ssh[0]["reference"])


if __name__ == "__main__":
    unittest.main()
