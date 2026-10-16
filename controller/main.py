"""The controller: connects to the switch, loads the program, installs forwarding, prints fingerprints.

    python3 -m controller.main --grpc 127.0.0.1:9559 --out results/fingerprints.json

Runs until interrupted (Ctrl-C / SIGTERM) or for --duration seconds, then writes every record to --out.
"""
import argparse
import signal
import threading
import time
from pathlib import Path

from scapy.all import IP, TCP, Ether, IPv6

from controller import dhcp, handshake, http, ssh, tls, x509
from controller.p4runtime_client import SwitchConnection
from controller.reassembly import SERVER_FLIGHT, Reassembler
from controller.records import Records, connection_key

CPU_PORT = 255          # simple_switch_grpc --cpu-port
COPY_SESSION = 100      # clone session of p4/tls.p4
REINJECT = 1            # packet_out.kind: a joined message
FLUSH = 2               # packet_out.kind: report an SSH connection's partial window
CERT = 3                # packet_out.kind: one certificate of a TLS 1.2 chain

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"


def rec_endpoints(src, sport, dst, dport):
    """(client, client port, server, server port) of a port-22 connection: the server is the side on port 22."""
    return (src, sport, dst, dport) if dport == 22 else (dst, dport, src, sport)


class Controller:
    def __init__(self, conn: SwitchConnection, echo=print):
        self.conn = conn
        self.records = Records(echo)
        self.reassembler = Reassembler()
        self.ssh = ssh.SshWindows()

    def install_forwarding(self, port_pairs):
        """port_pairs: [(a, b), ...]: frames entering a leave on b and back."""
        for a, b in port_pairs:
            self.conn.add_exact_entry("forward", a, "send", {"port": b})
            self.conn.add_exact_entry("forward", b, "send", {"port": a})

    def start(self):
        self.conn.add_clone_session(COPY_SESSION, CPU_PORT)
        self.conn.on_packet_in(self.on_packet_in)
        self.conn.enable_digest("hs_digest_t", self.on_handshake)
        self.conn.enable_digest("tls_digest_t", self.on_tls)
        self.conn.enable_digest("http_digest_t", self.on_http)
        self.conn.enable_digest("ssh_digest_t", self.on_ssh)
        self.conn.enable_digest("dhcp_digest_t", self.on_dhcp)
        self.conn.enable_digest("x509_digest_t", self.on_x509)

    def on_x509(self, fields):
        d = x509.X509Digest.from_fields(fields)
        src, sport, dst, dport = d.endpoints
        with self.records.lock:
            rec = self.records.get(src, sport, dst, dport, d.connId)
            self.records.set_endpoints(rec, dst, dport, src, sport)     # sent by the server
            value = "incomplete: an OID list longer than the switch keeps" if d.overflow else x509.ja4x(d)
            certs = rec.setdefault("ja4x_by_index", {})
            certs[d.index] = value
            rec["ja4x"] = [certs[i] for i in sorted(certs)]
            self.records.echo(f"{'ja4x':<8} {value:<50} certificate {d.index} of "
                              f"{rec.get('client')}:{rec.get('client_port')} -> {src}:{sport}")

    def on_dhcp(self, fields):
        """DHCP is not a connection: each message is kept, in arrival order, in the record of its endpoints."""
        d = dhcp.DhcpDigest.from_fields(fields)
        src, sport, dst, dport = d.endpoints
        with self.records.lock:
            rec = self.records.get(src, sport, dst, dport)
            self.records.set_endpoints(rec, src, sport, dst, dport)
            reason = d.incomplete_reason()
            name = "ja4d" if d.version == 4 else "ja4d6"
            self.records.append(rec, name, f"incomplete: {reason}" if reason else dhcp.ja4d(d))
            self.records.messages.append((name, dhcp.ja4d(d) if not reason else None))

    def on_ssh(self, fields):
        d = ssh.SshDigest.from_fields(fields)
        src, sport, dst, dport = d.endpoints
        with self.records.lock:
            rec = self.records.get(src, sport, dst, dport, d.connId)
            if d.fromClient:
                self.records.set_endpoints(rec, src, sport, dst, dport)
            else:
                self.records.set_endpoints(rec, dst, dport, src, sport)
            key = (connection_key(src, sport, dst, dport), d.connId)
            self.ssh_connection(key, (d.ipVersion, rec["client"], rec["client_port"], rec["server"],
                                      rec["server_port"]))
            self.ssh.add_batch(key, d.batch, d.batchCount)
            if d.kind in (ssh.SSH_WINDOW_END, ssh.SSH_FINAL):
                if d.kind == ssh.SSH_FINAL:
                    self.ssh.connections[key] = None        # answered
                value = self.ssh.close(key, d.sshClient, d.sshServer, d.ackClient, d.ackServer)
                if value:
                    self.records.append(rec, "ja4ssh", value)

    def ssh_connection(self, key, endpoints):
        """Remember an SSH connection (key: endpoints, connection number), to ask for its last window at the end.
        An earlier connection on the same endpoints is over (port reuse): the switch reported its last window on the
        new connection's SYN (p4/ssh.p4), so it is not asked for."""
        ends, conn_id = key
        earlier = self.ssh.latest.get(ends)
        if earlier is None or conn_id > earlier:
            if earlier is not None:
                self.ssh.connections[(ends, earlier)] = None
            self.ssh.latest[ends] = conn_id
        self.ssh.connections.setdefault(key, endpoints)

    def finish(self, wait=10.0):
        """The last, partial JA4SSH window of every SSH connection (FoxIO's tool reports it at the end of its
        capture). Call once, when the traffic is over: the switch is asked, connection by connection, to report it
        (P4Runtime on BMv2 cannot read registers), and the answers are awaited."""
        with self.records.lock:
            pending = [c for c in self.ssh.connections.values() if c]
        for version, client, cport, server, sport in pending:
            l3 = IP(src=client, dst=server) if version == 4 else IPv6(src=client, dst=server)
            flush = Ether(src="02:00:00:00:00:fe", dst="02:00:00:00:00:fe") / l3 / TCP(sport=cport, dport=sport,
                                                                                        flags="A")
            self.conn.packet_out(bytes(flush), kind=FLUSH)
        end = time.time() + wait
        while any(self.ssh.connections.values()) and time.time() < end:
            time.sleep(0.05)

    def on_packet_in(self, meta, frame):
        """A segment the switch copied because it may hold a piece of a split message: keep it; once a message is
        complete, send it back into the switch (as a segment starting at the message's first byte), which reads it
        like any other."""
        pkt = Ether(frame)
        ip = pkt[IP] if IP in pkt else pkt[IPv6] if IPv6 in pkt else None
        if ip is None or TCP not in pkt:
            return
        t = pkt[TCP]
        key = (connection_key(ip.src, t.sport, ip.dst, t.dport), meta["connId"], meta["fromClient"])
        done = self.reassembler.add(key, t.seq, meta["offset"], meta["msgStart"], meta["msgType"],
                                    bytes(t.payload))
        for seq, kind, message in done:
            l3 = IP(src=ip.src, dst=ip.dst) if IP in pkt else IPv6(src=ip.src, dst=ip.dst)
            tcp = TCP(sport=t.sport, dport=t.dport, flags="PA", seq=seq, ack=t.ack)
            if kind == SERVER_FLIGHT:   # one packet per certificate, in chain order
                for i, der in enumerate(message, 1):
                    self.conn.packet_out(bytes(Ether(src=pkt.src, dst=pkt.dst) / l3 / tcp / der), kind=CERT,
                                         index=i)
            else:
                self.conn.packet_out(bytes(Ether(src=pkt.src, dst=pkt.dst) / l3 / tcp / message), kind=REINJECT)

    def on_http(self, fields):
        d = http.HttpDigest.from_fields(fields)
        src, sport, dst, dport = d.endpoints
        with self.records.lock:
            rec = self.records.get(src, sport, dst, dport, d.connId)
            self.records.set_endpoints(rec, src, sport, dst, dport)
            reason = d.incomplete_reason()
            value = f"incomplete: {reason}" if reason else http.ja4h(d)
            if value is not None:
                # in stream order, as FoxIO lists them: a request joined by the controller (split over segments)
                # comes back after the requests that followed it whole
                order = rec.setdefault("ja4h_seq", [])
                order.append(d.seq)
                self.records.append(rec, "ja4h", value)
                first = order[0]
                by_place = sorted(zip(order, rec["ja4h"]), key=lambda sv: (sv[0] - first + (1 << 31)) % (1 << 32))
                rec["ja4h_seq"] = [s for s, _ in by_place]
                rec["ja4h"] = [v for _, v in by_place]

    def on_tls(self, fields):
        d = tls.TlsDigest.from_fields(fields)
        src, sport, dst, dport = d.endpoints
        with self.records.lock:
            rec = self.records.get(src, sport, dst, dport, d.connId)
            name = "ja4" if d.hsType == tls.CLIENT_HELLO else "ja4s"
            if d.hsType == tls.CLIENT_HELLO:
                self.records.set_endpoints(rec, src, sport, dst, dport)
            else:
                self.records.set_endpoints(rec, dst, dport, src, sport)
            if d.reassembled:
                rec[name + "_reassembled"] = True
            reason = d.incomplete_reason()
            if reason:
                self.records.add(rec, name + "_incomplete", reason)
            else:
                self.records.add(rec, name, tls.ja4(d) if d.hsType == tls.CLIENT_HELLO else tls.ja4s(d))

    def on_handshake(self, fields):
        d = handshake.HandshakeDigest.from_fields(fields)
        src, sport, dst, dport = d.endpoints
        with self.records.lock:
            rec = self.records.get(src, sport, dst, dport, d.connId)
            if 22 in (sport, dport):    # an SSH connection: its last JA4SSH window is asked for at the end
                self.ssh_connection((connection_key(src, sport, dst, dport), d.connId),
                                    (d.ipVersion, *(rec_endpoints(src, sport, dst, dport))))
            if d.kind == handshake.FP_JA4T:
                self.records.set_endpoints(rec, src, sport, dst, dport)
                self.records.add(rec, "ja4t", handshake.tcp_fingerprint(d))
            elif d.kind == handshake.FP_JA4TS:
                self.records.set_endpoints(rec, dst, dport, src, sport)
                self.records.add(rec, "ja4ts", handshake.tcp_fingerprint(d))
            elif d.kind == handshake.FP_JA4L:
                c, s = handshake.latency_fingerprints(d)
                self.records.add(rec, "ja4l_c", c)
                self.records.add(rec, "ja4l_s", s)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--grpc", default="127.0.0.1:9559")
    ap.add_argument("--p4info", default=str(BUILD / "main.p4info.txtpb"))
    ap.add_argument("--json", default=str(BUILD / "main.json"), help="compiled BMv2 program")
    ap.add_argument("--ports", default="1:2", help="port pairs to connect, e.g. 1:2")
    ap.add_argument("--out", default=str(ROOT / "results" / "fingerprints.json"))
    ap.add_argument("--duration", type=float, default=None)
    args = ap.parse_args()

    conn = SwitchConnection(args.grpc, args.p4info)
    conn.load_program(args.json)
    ctl = Controller(conn)
    ctl.install_forwarding([tuple(int(p) for p in pair.split(":")) for pair in args.ports.split(",")])
    ctl.start()
    print(f"controller ready on {args.grpc}", flush=True)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        stop.wait(args.duration)
    except KeyboardInterrupt:
        pass
    ctl.finish()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    ctl.records.write_json(args.out)
    print(f"{len(ctl.records.order)} connections written to {args.out}")
    conn.close()


if __name__ == "__main__":
    main()
