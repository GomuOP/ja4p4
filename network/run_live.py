#!/usr/bin/env python3
"""The live run: h1 -- s1 -- h2 in Mininet, real servers and clients, the real switch and controller.

    sudo env PYTHONPATH="$PYTHONPATH" python3 network/run_live.py

(root is needed for Mininet's network namespaces; PYTHONPATH is passed on because sudo drops it and the P4Runtime
Python modules are found through it.)

What happens:
  1. Mininet builds h1 (10.0.0.1, fd00::1) and h2 (10.0.0.2, fd00::2), each on a port of s1, a simple_switch_grpc
     running build/main.json; the controller (controller/main.py) connects, loads the program, installs forwarding.
     Offloads are switched off on every interface, so frames on the wire are what a real network carries.
  2. h2 runs servers: HTTP (python), TLS 1.3 and TLS 1.2 (openssl s_server, a two-certificate chain), DHCP and
     DHCPv6 (dnsmasq), SSH if an sshd is installed.
  3. h1 runs clients: plain and cookie HTTP requests, a 3 KB request (split over segments by TCP itself), TLS 1.3
     and TLS 1.2 handshakes, a ClientHello of about 2 KB (split over segments), DHCP and DHCPv6 requests, SSH.
  4. tcpdump records, on the switch's two ports, every frame entering and every frame leaving the switch.
  5. The controller's records are compared with FoxIO's references computed on the frames as they entered the
     switch (tools/compare.py), and every frame that entered must have left unchanged.

Results: results/live/ (report.txt, rows.json, records.json and the captures).
"""
import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
USER = os.environ.get("SUDO_USER")
USER_HOME = Path(f"~{USER}").expanduser() if USER else Path.home()
# references live in the user's home, not root's
os.environ.setdefault("JA4_BIN", str(USER_HOME / "ja4/rust/target/release/ja4"))
sys.path.insert(0, str(ROOT))

from mininet.log import setLogLevel  # noqa: E402
from mininet.net import Mininet  # noqa: E402
from mininet.node import Switch  # noqa: E402
from scapy.all import PcapReader  # noqa: E402

from controller.main import BUILD, Controller  # noqa: E402
from controller.p4runtime_client import SwitchConnection  # noqa: E402
from tools import compare  # noqa: E402

OUT = ROOT / "results" / "live"
GRPC = "127.0.0.1:50051"


class Bmv2Switch(Switch):
    """A Mininet switch that is simple_switch_grpc, its ports being the Mininet links' interfaces."""

    def __init__(self, name, **params):
        super().__init__(name, **params)
        self.proc = None

    def start(self, controllers):
        args = ["simple_switch_grpc", "--no-p4", "--device-id", "0", "--thrift-port", "9090"]
        for port, intf in sorted(self.intfs.items()):
            if intf.name != "lo":
                args += ["-i", f"{port}@{intf.name}"]
        args += ["--", "--grpc-server-addr", GRPC, "--cpu-port", "255"]
        self.log = open(OUT / "switch.log", "w")
        self.proc = subprocess.Popen(args, stdout=self.log, stderr=subprocess.STDOUT)

    def stop(self, deleteIntfs=True):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=10)
            self.log.close()
        super().stop(deleteIntfs)


def connect(timeout=30):
    end = time.time() + timeout
    while True:
        try:
            return SwitchConnection(GRPC, str(BUILD / "main.p4info.txtpb"), timeout=2)
        except Exception:
            if time.time() > end:
                raise
            time.sleep(0.5)


def no_offload(node, intf):
    node.cmd(f"ethtool -K {intf} rx off tx off sg off tso off gso off gro off lro off >/dev/null 2>&1")


def certificates(work):
    """A CA and a server certificate signed by it: the server sends a chain of two (JA4X of each)."""
    def run(cmd):
        subprocess.run(cmd, shell=True, check=True, cwd=work, capture_output=True)
    run("openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 30 "
        "-subj '/C=IN/O=ja4p4 test CA/CN=ja4p4 CA'")
    run("openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr "
        "-subj '/C=IN/ST=Delhi/O=ja4p4/CN=h2.test'")
    (work / "ext.cnf").write_text("subjectAltName=DNS:h2.test,IP:10.0.0.2\nkeyUsage=digitalSignature\n"
                                   "extendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n")
    run("openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out srv.pem -days 30 "
        "-extfile ext.cnf")


def main():
    if os.geteuid() != 0:
        sys.exit('run with root: sudo env PYTHONPATH="$PYTHONPATH" python3 network/run_live.py')
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    work = OUT / "work"
    work.mkdir()
    certificates(work)
    report = []

    def say(line=""):
        print(line, flush=True)
        report.append(line)

    setLogLevel("warning")
    net = Mininet(controller=None, autoSetMacs=True, waitConnected=False)
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    s1 = net.addSwitch("s1", cls=Bmv2Switch)
    net.addLink(h1, s1, port2=1)
    net.addLink(h2, s1, port2=2)
    net.start()
    procs = []
    try:
        for node, intf in ((h1, "h1-eth0"), (h2, "h2-eth0"), (s1, "s1-eth1"), (s1, "s1-eth2")):
            no_offload(node, intf)
        h1.cmd("ip -6 addr add fd00::1/64 dev h1-eth0 nodad")
        h2.cmd("ip -6 addr add fd00::2/64 dev h2-eth0 nodad")

        conn = connect()
        conn.load_program(str(BUILD / "main.json"))
        lines = []
        ctl = Controller(conn, echo=lambda l: (lines.append(l), print("  switch:", l, flush=True)))
        ctl.install_forwarding([(1, 2)])
        ctl.start()
        say("switch and controller ready")

        # captures on the switch's ports: frames entering (in) and leaving (out)
        for intf in ("s1-eth1", "s1-eth2"):
            for d in ("in", "out"):
                procs.append(subprocess.Popen(["tcpdump", "-i", intf, "-Q", d, "-s", "0", "-U", "-w",
                                               str(OUT / f"{intf}-{d}.pcap")],
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(2)

        # servers on h2
        h2.cmd(f"cd {work} && python3 -m http.server 80 --bind 10.0.0.2 >http.log 2>&1 & echo $! >>{work}/pids")
        h2.cmd(f"cd {work} && openssl s_server -accept 443 -cert srv.pem -key srv.key -cert_chain ca.pem "
               f"-www -quiet >tls13.log 2>&1 & echo $! >>{work}/pids")
        h2.cmd(f"cd {work} && openssl s_server -accept 8443 -tls1_2 -cert srv.pem -key srv.key -cert_chain ca.pem "
               f"-www -quiet >tls12.log 2>&1 & echo $! >>{work}/pids")
        # --no-ping: by default dnsmasq pings an address and waits about 3 s before offering it; udhcpc had given up by
        # then (its 3 tries take 3 s), so the run never got past Discover / Offer
        h2.cmd(f"dnsmasq --no-daemon --no-ping --conf-file=/dev/null --user=root --port=0 --interface=h2-eth0 "
               f"--bind-interfaces --dhcp-range=10.0.0.100,10.0.0.150,12h --dhcp-range=fd00::100,fd00::1ff,64,12h "
               f"--dhcp-leasefile={work}/leases >{work}/dnsmasq.log 2>&1 & echo $! >>{work}/pids")
        sshd = shutil.which("sshd") or ("/usr/sbin/sshd" if Path("/usr/sbin/sshd").exists() else None)
        if sshd:
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(work / "hostkey")], check=True)
            os.makedirs("/run/sshd", mode=0o755, exist_ok=True)       # sshd's privilege-separation directory
            h2.cmd(f"{sshd} -D -f /dev/null -h {work}/hostkey -p 22 -o PidFile=none "
                   f"-o UsePAM=no >{work}/sshd.log 2>&1 & echo $! >>{work}/pids")

        # wait until every TCP server listens: a fixed 2 s pause was once too short (python's http.server was not
        # yet listening, h2 answered the HTTP steps with RST and no JA4H was produced)
        wanted = {80, 443, 8443} | ({22} if sshd else set())
        deadline = time.time() + 30
        while True:
            listening = {int(line.split()[3].rsplit(":", 1)[1])
                         for line in h2.cmd("ss -ltnH").splitlines() if len(line.split()) > 3}
            if wanted <= listening:
                break
            if time.time() > deadline:
                raise RuntimeError(f"servers on h2 not listening after 30 s: ports {sorted(wanted - listening)}")
            time.sleep(0.2)
        say(f"servers listening on h2: ports {', '.join(str(p) for p in sorted(wanted))}")

        # clients on h1
        big = "p" * 3000
        alpn = ",".join(f"proto{i:02d}-" + "x" * 190 for i in range(10))     # about 2 KB of ALPN names
        steps = [
            ("HTTP GET", "curl -s -o /dev/null http://10.0.0.2/"),
            ("HTTP with cookies, Referer, Accept-Language",
             "curl -s -o /dev/null -H 'Cookie: session=abc123; theme=dark; lang=en' "
             "-H 'Accept-Language: en-GB,en;q=0.8' -e http://10.0.0.2/start http://10.0.0.2/page"),
            ("HTTP request of 3 KB (split by TCP)", f"curl -s -o /dev/null -H 'X-Padding: {big}' http://10.0.0.2/big"),
            ("TLS 1.3", "curl -sk -o /dev/null https://10.0.0.2/"),
            ("TLS 1.2 (certificates in the clear)", "curl -sk -o /dev/null --tlsv1.2 --tls-max 1.2 "
                                                    "https://10.0.0.2:8443/"),
            ("ClientHello of about 2 KB (split by TCP)",
             f"echo | openssl s_client -connect 10.0.0.2:443 -alpn {alpn}"),
            ("DHCP", "busybox udhcpc -i h1-eth0 -n -q -f -t 3 -T 1 -s /bin/true"),
            ("DHCPv6", "busybox udhcpc6 -i h1-eth0 -n -q -f -t 3 -T 1 -s /bin/true"),
        ]
        if sshd:
            steps.append(("SSH", "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes "
                                 "-o ConnectTimeout=5 nobody@10.0.0.2 true"))
        else:
            say("no sshd on this machine: the SSH step is skipped")
        # exit status each step must have: the SSH login is refused (255: no key for "nobody"); everything else
        # succeeds. A step that fails is reported, so a broken setup cannot pass as a clean run.
        failed = []
        for name, cmd in steps:
            say(f"h1: {name}")
            start = time.time()
            out = h1.cmd(f"timeout -k 2 15 {cmd} >/dev/null 2>&1; echo EXIT=$?")
            status = int(out.strip().rsplit("EXIT=", 1)[1]) if "EXIT=" in out else -1
            expected = 255 if name == "SSH" else 0
            print(f"  ({time.time() - start:.1f} s, exit {status})", flush=True)
            if status != expected:
                failed.append(f"{name} (exit {status}, expected {expected})")
            time.sleep(1)

        time.sleep(3)
        ctl.finish()
        time.sleep(1)
    finally:
        # a Ctrl-C can land while a host runs a command: stop that command first, or Mininet cannot clean up
        for node in (h1, h2):
            if node.waiting:
                node.sendInt()
                node.waitOutput()
        for p in procs:
            p.terminate()
            p.wait(timeout=10)
        # stop exactly the servers this run started (their process ids), nothing else on the machine
        h2.cmd(f"kill $(cat {work}/pids 2>/dev/null) 2>/dev/null")
        net.stop()

    # every frame that entered the switch on one port must have left it unchanged on the other
    def frames(name):
        return Counter(bytes(p) for p in PcapReader(str(OUT / name)))
    fwd = []
    for a, b in (("s1-eth1", "s1-eth2"), ("s1-eth2", "s1-eth1")):
        entered, left = frames(f"{a}-in.pcap"), frames(f"{b}-out.pcap")
        fwd.append((a, b, sum(entered.values()), sum((entered & left).values())))

    # the reference sees the frames as they entered the switch
    subprocess.run(["mergecap", "-w", str(OUT / "entered.pcap"), str(OUT / "s1-eth1-in.pcap"),
                    str(OUT / "s1-eth2-in.pcap")], check=True)
    records = ctl.records.all()
    res = {"records": records, "messages": list(ctl.records.messages)}
    rows = compare.compare_records(res, OUT / "entered.pcap", OUT / "entered.pcap", timing=True)

    say()
    say("RESULTS (switch against FoxIO's references on the frames that entered the switch)")
    c = Counter(r["verdict"] for r in rows)
    for r in rows:
        say(f"  {r['verdict']:<9} {r['name']:<7} switch={r['switch']}  reference={r['reference']}  {r['conn']}")
    say("TOTAL  " + "  ".join(f"{v} {c[v]}" for v in ("EXACT", "EXPLAINED", "WRONG", "MISSING", "EXTRA")))
    for a, b, n, same in fwd:
        say(f"FORWARDING {a} -> {b}: {same} of {n} frames left unchanged")
    if compare.latency_diffs:
        d = sorted(compare.latency_diffs)
        say(f"JA4L LATENCY  {len(d)} halves; difference to the reference: median {d[len(d) // 2]} us, "
            f"maximum {d[-1]} us")
    say(f"STEPS FAILED: {'; '.join(failed)}" if failed else f"STEPS  all {len(steps)} steps ended as expected")
    (OUT / "report.txt").write_text("\n".join(report) + "\n")
    (OUT / "rows.json").write_text(json.dumps(rows, indent=1, default=str))
    (OUT / "records.json").write_text(json.dumps(records, indent=1, default=str))
    if USER:
        subprocess.run(["chown", "-R", f"{USER}:{USER}", str(OUT)])
    print(f"\nwritten to {OUT}")


if __name__ == "__main__":
    main()
