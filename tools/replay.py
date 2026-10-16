"""Replay a capture through the real switch and controller, without root.

    python3 -m tools.replay data/x.pcap [--out results/x.json] [--no-timing]

Starts simple_switch_grpc with its ports on a nanomsg socket, starts the controller in this process, sends every
frame of the capture into the switch (the client's frames on port 1, the server's on port 2, keeping the capture's
time gaps unless --no-timing), and writes the controller's records. The switch also writes what it received to
<work>/sent.pcap with the time each frame was sent: the reference tool runs on it for timing-based fingerprints
(JA4L), so both sides measure the same packets.
"""
import argparse
import ctypes
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path

from scapy.all import IP, IPv6, TCP, Ether, Loopback, PcapReader, wrpcap

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from controller.main import BUILD, Controller  # noqa: E402
from controller.p4runtime_client import SwitchConnection  # noqa: E402
from tools.nanoport import NanoPort  # noqa: E402

CLIENT_PORT, SERVER_PORT = 1, 2
MAX_GAP = 2.0          # seconds; longer pauses in a capture are shortened to this


def endpoints(pkt):
    ip = pkt[IP] if IP in pkt else pkt[IPv6] if IPv6 in pkt else None
    if ip is None or TCP not in pkt:
        return None
    return (ip.src, pkt[TCP].sport), (ip.dst, pkt[TCP].dport)


def to_ethernet(pkt):
    """The switch's ports carry Ethernet; frames from loopback or cooked captures get an Ethernet header."""
    if isinstance(pkt, Ether):
        return pkt
    if isinstance(pkt, Loopback):
        # BSD loopback: 4-byte address family, then the IP packet (scapy does not decode every family value)
        raw = bytes(pkt)[4:]
        version = raw[0] >> 4 if raw else 0
        if version == 4:
            return Ether(type=0x0800) / IP(raw)
        if version == 6:
            return Ether(type=0x86DD) / IPv6(raw)
        return None
    if IP in pkt:
        return Ether(type=0x0800) / pkt[IP]
    if IPv6 in pkt:
        return Ether(type=0x86DD) / pkt[IPv6]
    return None


class PortChooser:
    """The client side of a connection is the sender of its first SYN; without one, the side with the higher port.
    Everything else (non-TCP) enters on the client port."""

    def __init__(self):
        self.client_of = {}

    def port(self, pkt):
        ends = endpoints(pkt)
        if ends is None:
            return CLIENT_PORT
        src, dst = ends
        key = frozenset((src, dst))
        if key not in self.client_of:
            flags = int(pkt[TCP].flags)
            if flags & 0x02 and not flags & 0x10:
                self.client_of[key] = src
            elif flags & 0x02:
                self.client_of[key] = dst
            else:
                self.client_of[key] = src if src[1] >= dst[1] else dst
        return CLIENT_PORT if self.client_of[key] == src else SERVER_PORT


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def die_with_parent():
    """Run in the child before exec: the switch gets SIGTERM when this process ends, however it ends."""
    ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, signal.SIGTERM)    # PR_SET_PDEATHSIG


class Bench:
    """The switch process, the controller and the packet socket."""

    runs = 0

    def __init__(self, work: Path):
        # free ports for every bench: a switch left from another run can never answer for this one
        grpc_port, thrift_port = free_port(), free_port()
        self.work = work
        # A Unix socket path is limited to 107 characters, so the packet socket lives in the short runtime folder.
        run_dir = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
        Bench.runs += 1
        self.addr = f"ipc://{run_dir}/ja4p4-{os.getpid()}-{Bench.runs}.ipc"
        self.grpc = f"127.0.0.1:{grpc_port}"
        self.log = open(work / "switch.log", "w")
        self.proc = subprocess.Popen(
            ["simple_switch_grpc", "--no-p4", "--packet-in", self.addr, *os.environ.get("BMV2_LOG", "").split(),
             "--thrift-port", str(thrift_port), "--device-id", "0", "--", "--grpc-server-addr", self.grpc, "--cpu-port", "255"],
            stdout=self.log, stderr=subprocess.STDOUT, preexec_fn=die_with_parent)
        self.port = None
        self.conn = None
        self._stop = threading.Event()
        for _ in range(100):
            if self.proc.poll() is not None:
                break
            try:
                self.conn = SwitchConnection(self.grpc, str(BUILD / "main.p4info.txtpb"), timeout=2)
                break
            except Exception:
                time.sleep(0.1)
        if self.conn is None:
            self.close()
            raise RuntimeError(f"switch did not start, see {work}/switch.log")
        # Connect the packet socket once, after the switch answers: its PAIR socket takes a single peer, so a
        # socket left over from a failed attempt would take the place of this one.
        self.port = NanoPort(self.addr)
        self.conn.load_program(str(BUILD / "main.json"))
        self.lines = []
        self.ctl = Controller(self.conn, echo=self.lines.append)
        self.ctl.install_forwarding([(CLIENT_PORT, SERVER_PORT)])
        self.ctl.start()
        self.out = []
        self._drain = threading.Thread(target=self._drain_out, daemon=True)
        self._drain.start()
        # The first frame after the program is loaded reaches the pipeline a few ms late (seen as a 2-4 ms error in
        # JA4L when that frame is a SYN), so a frame no fingerprint uses goes first.
        self.port.send(CLIENT_PORT, bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02", type=0x88B5) / b"warm-up"))
        time.sleep(0.3)
        self.out.clear()

    def _drain_out(self):
        while not self._stop.is_set():
            got = self.port.recv()
            if got:
                self.out.append(got)

    def replay(self, pcap, timing=True):
        """Send every frame; also write <work>/sent.pcap: each frame stamped with the time it was handed to the
        switch, the capture the reference tool reads for timing-based fingerprints."""
        chooser = PortChooser()
        prev = None
        sent = []
        self.sent_raw = []
        for pkt in PcapReader(str(pcap)):
            frame = to_ethernet(pkt)
            if frame is None:
                continue
            t = float(pkt.time)
            if timing and prev is not None:
                time.sleep(min(max(t - prev, 0), MAX_GAP))
            prev = t
            raw = bytes(frame)
            self.port.send(chooser.port(frame), raw)
            self.sent_raw.append(raw)
            stamped = Ether(raw)
            stamped.time = time.time()
            sent.append(stamped)
        wrpcap(str(self.work / "sent.pcap"), sent)
        return len(sent)

    def settle(self, quiet=1.0, limit=30.0):
        """Wait until the controller has received nothing new for `quiet` seconds."""
        end = time.time() + limit
        n = -1
        while time.time() < end:
            if len(self.lines) == n:
                return
            n = len(self.lines)
            time.sleep(quiet)

    def close(self):
        self._stop.set()
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
        self.proc.terminate()
        self.proc.wait(timeout=10)
        if self.port:
            self._drain.join(timeout=2)
            self.port.close()
        self.log.close()
        try:
            os.unlink(self.addr[len("ipc://"):])
        except OSError:
            pass


def run(pcap, timing=True, work=None):
    work = Path(work or tempfile.mkdtemp(prefix="replay-", dir=os.environ.get("REPLAY_DIR")))
    work.mkdir(parents=True, exist_ok=True)
    bench = Bench(work)
    try:
        sent = bench.replay(pcap, timing)
        bench.settle()
        bench.ctl.finish()
        # forwarding must be untouched by fingerprinting: every frame sent comes out, byte for byte
        unchanged = sum((Counter(bench.sent_raw) & Counter(f for _, f in bench.out)).values())
        return {"pcap": str(pcap), "sent": sent, "forwarded": len(bench.out), "unchanged": unchanged,
                "work": str(work), "records": bench.ctl.records.all(), "lines": bench.lines,
                "messages": list(bench.ctl.records.messages)}
    finally:
        bench.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--out")
    ap.add_argument("--no-timing", action="store_true")
    ap.add_argument("--work")
    args = ap.parse_args()
    res = run(args.pcap, not args.no_timing, args.work)
    print("\n".join(res["lines"]))
    print(f"sent {res['sent']} frames, forwarded {res['forwarded']}, {res['unchanged']} of them byte for byte "
          f"unchanged; switch files in {res['work']}")
    if args.out:
        Path(args.out).write_text(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
