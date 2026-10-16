/* ja4p4: JA4+ fingerprinting in a P4 switch (v1model, BMv2).

   Topology: h1 -- s1 -- h2. The switch forwards between its ports by the table `forward`, which the controller
   fills, and fingerprints what passes. Every packet is forwarded unchanged; fingerprinting only reads it. */
#include <core.p4>
#include <v1model.p4>

#include "headers.p4"
#include "parser.p4"
#include "handshake.p4"
#include "stream.p4"
#include "tls.p4"
#include "http.p4"
#include "ssh.p4"
#include "dhcp.p4"
#include "x509.p4"

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

/* The connection's slot in the per-connection registers and its check value. The endpoints are put in a fixed order
   (the smaller (address, port) first), so both directions of a connection find the same slot. */
control ConnKey(in headers_t hdr, inout metadata_t meta) {
    apply {
        bit<128> a1 = meta.srcAddr;  bit<16> p1 = hdr.tcp.srcPort;
        bit<128> a2 = meta.dstAddr;  bit<16> p2 = hdr.tcp.dstPort;
        meta.srcIsFirst = 1;
        if (meta.srcAddr > meta.dstAddr || (meta.srcAddr == meta.dstAddr && hdr.tcp.srcPort > hdr.tcp.dstPort)) {
            a1 = meta.dstAddr;  p1 = hdr.tcp.dstPort;
            a2 = meta.srcAddr;  p2 = hdr.tcp.srcPort;
            meta.srcIsFirst = 0;
        }
        hash(meta.slot,  HashAlgorithm.crc16, 32w0, { meta.ipVersion, a1, p1, a2, p2 }, 32w65536);
        hash(meta.check, HashAlgorithm.crc32, 32w0, { meta.ipVersion, a1, p1, a2, p2 }, 32w0xffffffff);
    }
}

/* The connection's number. Every control keeps its per-connection state with this number and starts over when it
   changes, and every digest carries it, so the controller keeps one record per connection. A new number is given
     * to the first packet of a connection in its slot (another connection was there, or none), and
     * to a SYN with a new initial sequence number on the endpoints of the slot's connection: port reuse (a client,
       or a NAT, opening a new connection with the same addresses and ports). A repeated SYN keeps the number.
   Packets from the controller never get a new number: they belong to the connection they were copied from. Numbers
   count from 1 (0: none); they wrap after 2^32 connections, long after any connection with an old number is over. */
control ConnId(in headers_t hdr, inout metadata_t meta) {

    register<bit<32>>(CONN_SLOTS) connCheck;
    register<bit<32>>(CONN_SLOTS) connNumber;
    register<bit<32>>(CONN_SLOTS) connSynSeq;  // the initial sequence number of the connection's SYN
    register<bit<32>>(1)          connCounter;

    apply {
        bit<32> storedCheck;  bit<32> id;  bit<32> synSeq;
        connCheck.read(storedCheck, meta.slot);
        connNumber.read(id, meta.slot);
        connSynSeq.read(synSeq, meta.slot);
        bool syn = (hdr.tcp.flags & 0x12) == 0x02;
        bool another = storedCheck != meta.check || id == 0;
        bool reused = !another && syn && hdr.tcp.seq != synSeq;
        if (meta.reinjected == 0) {
            if (another || reused) {
                if (reused) {
                    meta.connReused = 1;
                    meta.prevConnId = id;
                }
                connCounter.read(id, 0);
                id = id + 1;
                connCounter.write(0, id);
                connCheck.write(meta.slot, meta.check);
                connNumber.write(meta.slot, id);
            }
            if (syn) {
                connSynSeq.write(meta.slot, hdr.tcp.seq);
            }
            meta.connId = id;
        } else {
            meta.connId = another ? 32w0 : id;    // its connection has left the slot: 0, which matches no state
        }
    }
}

control MyIngress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t std) {

    ConnKey() connKey;
    ConnId() connId;
    Handshake() handshake;
    Stream() stream;
    Tls() tls;
    Http() http;
    Ssh() ssh;
    Dhcp() dhcp;
    X509() x509;

    action drop() {
        mark_to_drop(std);
    }

    action send(port_t port) {
        std.egress_spec = port;
    }

    /* filled by the controller: h1's port -> h2's port and back. Keyed on meta.inPort, the arrival port kept
       across a resubmit. */
    table forward {
        key = { meta.inPort: exact @name("ingress_port"); }
        actions = { send; drop; }
        default_action = drop();
        size = 64;
    }

    apply {
        if (std.instance_type != PKT_INSTANCE_RESUBMIT) {
            meta.inPort = std.ingress_port;
        }
        if (meta.reinjected == 1) {
            /* a packet from the controller: a joined message to fingerprint, or an SSH flush; never forwarded */
            mark_to_drop(std);
            hdr.packet_out.setInvalid();
        } else {
            forward.apply();
        }

        if (std.instance_type == PKT_INSTANCE_RESUBMIT) {
            /* second pass of a packet whose message was walked: only Ethernet was parsed, the original bytes are
               forwarded (and copied at egress if the first pass decided so) */
        } else if (hdr.tcp.isValid()) {
            connKey.apply(hdr, meta);
            connId.apply(hdr, meta);
            if (meta.reinjected == 0) {
                handshake.apply(hdr, meta, std);
            }
            if (meta.outKind == OUT_CERT) {
                stream.apply(hdr, meta);                // the certificate flight was read
                x509.apply(hdr, meta);
            } else if (meta.outKind != OUT_FLUSH) {
                stream.apply(hdr, meta);
                tls.apply(hdr, meta);
                http.apply(hdr, meta);
            }
            if (meta.outKind == 0 || meta.outKind == OUT_FLUSH) {
                ssh.apply(hdr, meta);                   // real packets, and the controller's flush (after Stream:
            }                                           // it needs meta.fromClient)
            if (meta.reinjected == 0 && (meta.tls.walked == 1 || meta.http.walked == 1)) {
                /* the walk dropped bytes from this copy of the packet: forward (and copy) the original on a second
                   pass instead */
                resubmit_preserving_field_list(0);
            }
        } else if (hdr.udp.isValid() && meta.reinjected == 0) {
            dhcp.apply(hdr, meta);
            if (meta.dhcp.walked == 1) {
                resubmit_preserving_field_list(0);     // forward the original bytes on a second pass
            }
        }

        /* The handshake record (JA4T, JA4TS, JA4L), from this single call: BMv2 keeps one digest per packet, so on a
           packet that carries a message's digest (TLS, HTTP) it waits for the second pass. */
        bool walkedNow = std.instance_type != PKT_INSTANCE_RESUBMIT &&
                         (meta.tls.walked == 1 || meta.http.walked == 1);
        if (meta.hsPending == 1 && !walkedNow) {
            if (meta.digestSent == 1) {
                /* this pass already carries another digest (ssh.p4: the previous connection's last window, on the
                   SYN of a port reuse): the handshake record goes out on a second pass */
                resubmit_preserving_field_list(0);
            } else {
                digest<hs_digest_t>(1, meta.hsd);
            }
        }
    }
}

const bit<32> PKT_INSTANCE_NORMAL    = 0;
const bit<32> PKT_INSTANCE_CLONE_E2E = 2;

control MyEgress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t std) {
    apply {
        /* the forwarded packet, with all its bytes: copy it for the controller if stream.p4 decided so */
        if (meta.copy == 1 &&
            (std.instance_type == PKT_INSTANCE_NORMAL || std.instance_type == PKT_INSTANCE_RESUBMIT)) {
            clone_preserving_field_list(CloneType.E2E, COPY_SESSION, 1);
        }
        /* the copy: say where its payload sits in its direction's byte stream */
        if (std.instance_type == PKT_INSTANCE_CLONE_E2E) {
            hdr.packet_in.setValid();
            hdr.packet_in.offset = meta.copyOffset;
            hdr.packet_in.fromClient = meta.copyFromClient;
            hdr.packet_in.msgStart = meta.copyMsgStart;
            hdr.packet_in.msgType = meta.copyMsgType;
            hdr.packet_in.connId = meta.connId;
        }
    }
}

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.packet_in);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlanOuter);
        pkt.emit(hdr.vlanInner);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv4_options);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.tcp_opt);
        pkt.emit(hdr.udp);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
