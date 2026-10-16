/* SSH fingerprint: JA4SSH, one per window of 200 SSH packets of a connection.

       JA4SSH = c<mode of client payload lengths>s<mode of server payload lengths>
                _c<client SSH packets>s<server SSH packets>_c<client bare ACKs>s<server bare ACKs>

   An SSH connection is one on port 22, or one where a side's data begins with the banner "SSH-" (tshark, under
   FoxIO's tool, recognises SSH on any port that way; there the client is the side that sent the SYN).
   FoxIO's reference counts, per window: an "SSH packet" is a TCP segment of the connection that carries
   payload; a "bare ACK" is a segment without payload whose flags are exactly ACK. The window closes when the client
   and server SSH packets reach 200 together; then every count starts again from 0. At the end of the capture the
   last, partial window is reported too.

   The switch counts everything exactly, per connection, in registers. The one thing it cannot compute is the mode
   (the most frequent payload length, the smallest one on a tie): that needs a histogram of every length in the
   window. So the switch sends the lengths to the controller in batches of 8 (16 bits each: the direction, then the
   length), and closes each window with a digest carrying its counts. The controller builds the histogram.
   The last, partial window: when the traffic is over the controller sends, for every SSH connection it knows (from
   the connection's handshake digests on port 22, or from its SSH digests), a "flush" packet (packet-out
   kind 2) with the connection's endpoints; the switch then reports the connection's current counts and lengths as a
   FINAL digest and clears them (as the reference reports the partial window at the end of its capture). P4Runtime
   on BMv2 cannot read registers, so the switch reports them itself. */
#ifndef SSH_P4
#define SSH_P4

#include "headers.p4"

#define SSH_WINDOW 200
#define SSH_BATCH  8

const bit<8> SSH_BATCH_FULL = 2; // 8 lengths
const bit<8> SSH_WINDOW_END = 3; // the window's counts and its last lengths
const bit<8> SSH_FINAL      = 4; // on the controller's flush: the current, partial window
const bit<8> SSH_START      = 5; // a connection recognised by its banner (not on port 22): ask for its last window

struct ssh_digest_t {
    bit<8>   kind;
    bit<8>   ipVersion;
    bit<128> src;
    bit<128> dst;
    bit<16>  srcPort;
    bit<16>  dstPort;
    bit<128> batch;          // up to 8 entries: bit 15 = from the client, bits 14..0 = payload length
    bit<8>   batchCount;
    bit<16>  sshClient;
    bit<16>  sshServer;
    bit<16>  ackClient;
    bit<16>  ackServer;
    bit<32>  serial;         // counts SSH digests: the counts start again every window, so steady traffic gives
                             // identical windows, and BMv2 drops a digest identical to one not yet acknowledged.
                             // 32 bits and the wrap at 2^32: see the same field in dhcp.p4.
    bit<32>  connId;         // the connection the counts belong to (ConnId in main.p4)
    bit<8>   fromClient;     // this packet was sent by the client
}

control Ssh(inout headers_t hdr, inout metadata_t meta) {

    register<bit<32>>(CONN_SLOTS)  sshConn;
    register<bit<16>>(CONN_SLOTS)  sshClient;
    register<bit<16>>(CONN_SLOTS)  sshServer;
    register<bit<16>>(CONN_SLOTS)  ackClient;
    register<bit<16>>(CONN_SLOTS)  ackServer;
    register<bit<128>>(CONN_SLOTS) batch;
    register<bit<32>>(1)           sshSerial;
    register<bit<8>>(CONN_SLOTS)   batchCount;
    register<bit<8>>(CONN_SLOTS)   bannerSeen;  // 1: an "SSH-" banner was seen on this connection

    apply {
        bool flush = meta.outKind == OUT_FLUSH;
        bool port22 = hdr.tcp.srcPort == 22 || hdr.tcp.dstPort == 22;
        /* the controller's flush is sent from the client's side */
        bool fromClient = flush || (port22 ? hdr.tcp.dstPort == 22 : meta.fromClient == 1);
        bool bareAck = meta.payLen == 0 && hdr.tcp.flags == 0x10 && hdr.tcp.reserved == 0;

        bit<32> storedConn;
        bit<16> sc;  bit<16> ss;  bit<16> ac;  bit<16> as;
        bit<128> b;  bit<8> bn;
        sshConn.read(storedConn, meta.slot);
        sshClient.read(sc, meta.slot);
        sshServer.read(ss, meta.slot);
        ackClient.read(ac, meta.slot);
        ackServer.read(as, meta.slot);
        batch.read(b, meta.slot);
        batchCount.read(bn, meta.slot);
        bit<8> storedBanner;
        bannerSeen.read(storedBanner, meta.slot);
        bit<8> banner = (storedConn == meta.connId) ? storedBanner : 8w0;
        bool newBanner = banner == 0 && meta.sshBanner == 1 && meta.reinjected == 0 && !port22;
        if (newBanner) {
            banner = 1;
        }

        /* Port reuse (ConnId in main.p4): this SYN opens a new connection on the endpoints of an SSH connection whose
           counts are still here. That connection is over: its last, partial window is reported now, before its
           state is replaced (FoxIO's tool reports every connection's partial window). */
        bool previous = meta.connReused == 1 && storedConn == meta.prevConnId && (port22 || storedBanner == 1) &&
                        (sc != 0 || ss != 0 || ac != 0 || as != 0 || bn != 0);
        if (!port22 && banner == 0 && !previous && !bareAck) {
            /* not (yet) an SSH connection. Its bare ACKs are counted all the same: FoxIO's tool counts the
               handshake's ACK of a connection it recognises as SSH only later, by its banner. */
            return;
        }
        if (meta.payLen == 0 && !bareAck && !flush && !previous) {
            return;                             // neither counted (SYN, SYN-ACK, FIN, RST, ...)
        }

        ssh_digest_t d;
        d = { 0, meta.ipVersion, meta.srcAddr, meta.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort,
              0, 0, 0, 0, 0, 0, 0, meta.connId, (bit<8>) (fromClient ? 1w1 : 1w0) };
        if (previous) {
            d.kind = SSH_FINAL;
            d.connId = meta.prevConnId;
            d.batch = b;  d.batchCount = bn;
            d.sshClient = sc;  d.sshServer = ss;  d.ackClient = ac;  d.ackServer = as;
            sc = 0;  ss = 0;  ac = 0;  as = 0;  b = 0;  bn = 0;
        } else if (flush) {
            /* report the partial window, then forget the connection (nothing if it is not, or no longer, here) */
            if (storedConn == meta.connId) {
                d.kind = SSH_FINAL;
                d.batch = b;  d.batchCount = bn;
                d.sshClient = sc;  d.sshServer = ss;  d.ackClient = ac;  d.ackServer = as;
            }
            sc = 0;  ss = 0;  ac = 0;  as = 0;  b = 0;  bn = 0;
        } else {
            if (storedConn != meta.connId) {    // another connection in this slot, or a new one on these endpoints
                sc = 0;  ss = 0;  ac = 0;  as = 0;  b = 0;  bn = 0;
            }
            if (bareAck) {
                if (fromClient) { ac = ac + 1; } else { as = as + 1; }
            } else {
                if (fromClient) { sc = sc + 1; } else { ss = ss + 1; }
                bit<16> entry = (fromClient ? 16w0x8000 : 16w0) | (meta.payLen & 0x7fff);
                b = b[111:0] ++ entry;
                bn = bn + 1;
            }
            if (sc + ss == SSH_WINDOW) {
                d.kind = SSH_WINDOW_END;
                d.batch = b;  d.batchCount = bn;
                d.sshClient = sc;  d.sshServer = ss;  d.ackClient = ac;  d.ackServer = as;
                sc = 0;  ss = 0;  ac = 0;  as = 0;  b = 0;  bn = 0;
            } else if (bn == SSH_BATCH) {
                d.kind = SSH_BATCH_FULL;
                d.batch = b;  d.batchCount = bn;
                b = 0;  bn = 0;
            } else if (newBanner) {
                d.kind = SSH_START;
            }
        }
        /* one digest call for the whole control (one learn list per call site, see handshake.p4). BMv2 keeps one
           digest per packet: when this packet also completes the handshake record (JA4T on a SYN, JA4L on the
           handshake's ACK), main.p4 sends that record on a second pass. */
        if (d.kind != 0) {
            bit<32> serial;
            sshSerial.read(serial, 0);
            sshSerial.write(0, serial + 1);
            d.serial = serial;
            digest<ssh_digest_t>(4, d);
            meta.digestSent = 1;                // the SYN's handshake record then goes out on a second pass
        }

        sshConn.write(meta.slot, flush ? 32w0 : meta.connId);
        sshClient.write(meta.slot, sc);
        sshServer.write(meta.slot, ss);
        ackClient.write(meta.slot, ac);
        ackServer.write(meta.slot, as);
        batch.write(meta.slot, b);
        batchCount.write(meta.slot, bn);
        bannerSeen.write(meta.slot, flush ? 8w0 : banner);
    }
}

#endif
