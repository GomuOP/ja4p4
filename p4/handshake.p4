/* TCP handshake fingerprints: JA4T (client SYN), JA4TS (server SYN-ACK) and JA4L (handshake latency).

   JA4T and JA4TS need nothing but the parsed SYN / SYN-ACK: window, option kinds, MSS, window scale. The switch
   sends these fields to the controller, which only writes them as text.

   JA4L needs three timestamps of one connection: A = the SYN, B = the SYN-ACK, C = the first ACK after it.
       JA4L-C = (C - B) / 2 "_" client TTL        JA4L-S = (B - A) / 2 "_" server TTL
   The switch keeps A, B and the TTLs in registers, computes both halves itself when C passes, and sends the
   finished numbers. Timestamps are the switch's own ingress time in microseconds.

   Per-connection state lives in registers at the connection's slot (meta.slot, computed by ConnKey in main.p4), with
   the connection's number (meta.connId, ConnId in main.p4) to tell two connections in one slot apart, or a new
   connection on the endpoints of an earlier one. The order of events follows FoxIO's reference: the first SYN,
   then the first SYN-ACK, then the first packet with ACK and without SYN, from either side. A repeated SYN
   or SYN-ACK changes nothing. */
#ifndef HANDSHAKE_P4
#define HANDSHAKE_P4

#include "headers.p4"

#define HS_SLOTS 65536

const bit<8> TCP_SYN = 0x02;
const bit<8> TCP_ACK = 0x10;

/* Slot states */
const bit<8> HS_EMPTY       = 0;
const bit<8> HS_SYN         = 1;   // SYN seen (A stored)
const bit<8> HS_SYNACK      = 2;   // SYN, then SYN-ACK seen (A, B stored)
const bit<8> HS_DONE        = 3;   // JA4L sent
const bit<8> HS_SYNACK_ONLY = 4;   // SYN-ACK seen without its SYN: JA4TS sent, no JA4L possible

/* Digest kinds */
const bit<8> FP_JA4T  = 1;
const bit<8> FP_JA4TS = 2;
const bit<8> FP_JA4L  = 3;

/* hs_digest_t is declared in headers.p4: the record travels in metadata (meta.hsd), see main.p4 */

control Handshake(in headers_t hdr, inout metadata_t meta, in standard_metadata_t std) {

    register<bit<32>>(HS_SLOTS) hsConn;
    register<bit<8>>(HS_SLOTS)  hsState;
    register<bit<48>>(HS_SLOTS) hsTimeSyn;
    register<bit<48>>(HS_SLOTS) hsTimeSynAck;
    register<bit<8>>(HS_SLOTS)  hsTtlClient;
    register<bit<8>>(HS_SLOTS)  hsTtlServer;

    bit<32> storedConn;
    bit<8>  state;
    hs_digest_t d;

    action fillTcpFields(bit<8> kind) {
        d.kind = kind;
        d.window = hdr.tcp.window;
        d.optCount = meta.opt.count;
        d.optKinds = meta.opt.kinds;
        d.mss = meta.opt.mss;
        d.wscale = meta.opt.wscale;
        d.optFlags = (bit<8>) meta.opt.hasMss | (((bit<8>) meta.opt.hasWscale) << 1);
    }

    apply {
        bit<32> slot = meta.slot;
        bit<32> conn = meta.connId;
        hsConn.read(storedConn, slot);
        hsState.read(state, slot);
        bool mine = (storedConn == conn) && (state != HS_EMPTY);

        d = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        d.ipVersion = meta.ipVersion;
        d.src = meta.srcAddr;
        d.dst = meta.dstAddr;
        d.srcPort = hdr.tcp.srcPort;
        d.dstPort = hdr.tcp.dstPort;
        d.connId = meta.connId;

        bit<8> f = hdr.tcp.flags & (TCP_SYN | TCP_ACK);
        d.kind = 0;
        bit<48> now = std.ingress_global_timestamp;

        if (f == TCP_SYN) {
            /* client SYN: a new connection unless this connection's SYN was already seen (a retransmission).
               A SYN on a finished entry, or on another connection's slot, starts over. */
            if (!mine || state == HS_DONE || state == HS_SYNACK_ONLY) {
                hsConn.write(slot, conn);
                hsState.write(slot, HS_SYN);
                hsTimeSyn.write(slot, now);
                hsTtlClient.write(slot, meta.ttl);
                fillTcpFields(FP_JA4T);
            }
        } else if (f == (TCP_SYN | TCP_ACK)) {
            if (mine && state == HS_SYN) {
                hsState.write(slot, HS_SYNACK);
                hsTimeSynAck.write(slot, now);
                hsTtlServer.write(slot, meta.ttl);
                fillTcpFields(FP_JA4TS);
            } else if (!mine) {
                /* the SYN was not seen: JA4TS is still possible, JA4L is not */
                hsConn.write(slot, conn);
                hsState.write(slot, HS_SYNACK_ONLY);
                fillTcpFields(FP_JA4TS);
            }
        } else if (f == TCP_ACK) {
            if (mine && state == HS_SYNACK) {
                bit<48> tSyn;  bit<48> tSynAck;
                hsTimeSyn.read(tSyn, slot);
                hsTimeSynAck.read(tSynAck, slot);
                hsTtlClient.read(d.ttlC, slot);
                hsTtlServer.read(d.ttlS, slot);
                d.kind = FP_JA4L;
                d.latencyC = (now - tSynAck) >> 1;
                d.latencyS = (tSynAck - tSyn) >> 1;
                hsState.write(slot, HS_DONE);
            }
        }

        /* The record is not sent from here: BMv2 keeps one digest per packet, and the same packet may carry another
           fingerprint's digest (a message on the handshake's ACK). main.p4 sends it, from a single call. */
        if (d.kind != 0) {
            meta.hsd = d;
            meta.hsPending = 1;
        }
    }
}

#endif
