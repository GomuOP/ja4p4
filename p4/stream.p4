/* Per-direction stream bookkeeping, shared by every fingerprint that reads a message (TLS hellos, HTTP requests):
   which segments the controller must see so that a message split over several segments, or arriving out of order,
   can be joined and read.

   P4 processes one packet at a time and cannot hold a packet back, so a message that does not fit in one segment is
   joined in the controller: the switch copies the segments that may hold its pieces (packet-in, with each segment's
   offset in its direction's byte stream), the controller puts the bytes in order, and sends the complete message
   back into the switch (packet-out), where the same parser reads it. The switch reads every message itself; the
   controller only orders bytes.

   Per connection and direction:
     * the initial sequence number (from the SYN or SYN-ACK): offset = seq - ISN - 1;
     * started: the direction's first data segment (offset 0) has been seen;
     * pending, pendingSeq: a message started at pendingSeq and is not complete yet;
     * edge: the sequence number after the furthest byte seen; a gap and where it starts (rule (e)).
   A data segment is copied when
     (a) it starts a message that continues beyond it                    -> pending, copy (message start);
     (b) a message is pending and the segment lies within STREAM_WINDOW bytes of its start;
     (c) the direction has not started yet and the segment lies within its first STREAM_WINDOW bytes: it may be a
         piece that arrived before the message's first segment (the out-of-order case);
     (d) it holds a complete TLS 1.2 ServerHello: the server's flight (with its certificates) starts there;
     (e) the direction has carried an HTTP request, and the segment lies ahead of a gap (bytes not seen yet), within
         STREAM_WINDOW bytes of the gap's start: it may be a later piece of the next request on a keep-alive
         connection, arriving before that request's first segment. (c) is the same case for a direction's first
         message. The gap closes when a segment covering its first byte arrives, or is given up past the window.
   A joined message sent back by the controller clears `pending`.
   Without the SYN, the offsets are learned from the first segment that starts a message; a piece that arrives
   before it cannot be placed (a documented limit). */
#ifndef STREAM_P4
#define STREAM_P4

#include "headers.p4"

#define STREAM_WINDOW 16384

control Stream(inout headers_t hdr, inout metadata_t meta) {

    register<bit<32>>(CONN_SLOTS) streamConn;
    register<bit<8>>(CONN_SLOTS)  clientSide;   // 0 unknown, 1: the client is ConnKey's first endpoint, 2: second
    register<bit<32>>(CONN_SLOTS) isnClient;
    register<bit<32>>(CONN_SLOTS) isnServer;
    register<bit<8>>(CONN_SLOTS)  isnKnown;     // bit 0 client, bit 1 server
    register<bit<8>>(CONN_SLOTS)  started;      // bit 0 client, bit 1 server
    register<bit<8>>(CONN_SLOTS)  pending;      // bit 0 client, bit 1 server
    register<bit<32>>(CONN_SLOTS) pendingSeqClient;
    register<bit<32>>(CONN_SLOTS) pendingSeqServer;
    register<bit<32>>(CONN_SLOTS) edgeClient;
    register<bit<32>>(CONN_SLOTS) edgeServer;
    register<bit<32>>(CONN_SLOTS) gapClient;
    register<bit<32>>(CONN_SLOTS) gapServer;
    register<bit<8>>(CONN_SLOTS)  gapOpen;      // bit 0 client, bit 1 server
    register<bit<8>>(CONN_SLOTS)  httpDir;      // bit 0 client, bit 1 server: an HTTP request was seen

    apply {
        bit<32> storedConn;
        bit<8> side;  bit<8> known;  bit<8> st;  bit<8> pend;
        bit<32> isnC;  bit<32> isnS;  bit<32> pseqC;  bit<32> pseqS;
        bit<32> edgeC;  bit<32> edgeS;  bit<32> gapC;  bit<32> gapS;  bit<8> gaps;  bit<8> httpd;
        streamConn.read(storedConn, meta.slot);
        clientSide.read(side, meta.slot);
        isnKnown.read(known, meta.slot);
        started.read(st, meta.slot);
        pending.read(pend, meta.slot);
        isnClient.read(isnC, meta.slot);
        isnServer.read(isnS, meta.slot);
        pendingSeqClient.read(pseqC, meta.slot);
        pendingSeqServer.read(pseqS, meta.slot);
        edgeClient.read(edgeC, meta.slot);
        edgeServer.read(edgeS, meta.slot);
        gapClient.read(gapC, meta.slot);
        gapServer.read(gapS, meta.slot);
        gapOpen.read(gaps, meta.slot);
        httpDir.read(httpd, meta.slot);
        if (storedConn != meta.connId) {        // another connection in this slot, or a new one on these endpoints
            side = 0;  known = 0;  st = 0;  pend = 0;  gaps = 0;  httpd = 0;
        }
        bit<8> first = (meta.srcIsFirst == 1) ? 8w1 : 8w2;    // this packet's source, in ConnKey's order
        bit<8> other = (meta.srcIsFirst == 1) ? 8w2 : 8w1;
        bit<8> flags = hdr.tcp.flags & 0x12;
        bool msgStart = meta.tls.incomplete == 1 || meta.http.incomplete == 1;
        bool msgDone = meta.tls.parsed == 1 || meta.http.parsed == 1;
        /* A complete TLS 1.2 (or older) ServerHello: the certificates follow in the server's flight, in the clear
           (TLS 1.3 encrypts them). The flight is copied from the ServerHello's first byte, so the controller can
           cut the certificates out and send them back (JA4X, x509.p4). */
        bit<16> chosen = meta.tls.hasSupportedVersions == 1 ? meta.tls.maxVersion : meta.tls.legacyVersion;
        bool certStart = meta.tls.parsed == 1 && meta.tls.hsType == 2 && chosen <= 0x0303 && meta.reinjected == 0;

        /* ---- the client side and the initial sequence numbers ---- */
        if (flags == 0x02 && meta.reinjected == 0) {          // SYN: a new connection, from the client
            side = first;
            isnC = hdr.tcp.seq;
            edgeC = hdr.tcp.seq + 1;
            known = 1;  st = 0;  pend = 0;  gaps = 0;  httpd = 0;
        } else if (flags == 0x12 && meta.reinjected == 0) {   // SYN-ACK, from the server
            side = other;
            isnS = hdr.tcp.seq;
            edgeS = hdr.tcp.seq + 1;
            known = known | 2;
        } else if (side == 0 && (meta.tls.hsType == 1 || meta.http.incomplete == 1 || meta.http.parsed == 1)) {
            side = first;                                       // no handshake seen: a ClientHello or a request
        } else if (side == 0 && meta.tls.hsType == 2) {
            side = other;
        }
        meta.fromClient = (side == first) ? 1w1 : 1w0;

        /* ---- a data segment: copy it to the controller or not ---- */
        if (meta.payLen > 0 && side != 0) {
            bit<8> bit_ = (meta.fromClient == 1) ? 8w1 : 8w2;
            bit<32> isn = (meta.fromClient == 1) ? isnC : isnS;
            bit<32> pseq = (meta.fromClient == 1) ? pseqC : pseqS;
            bit<32> edge = (meta.fromClient == 1) ? edgeC : edgeS;
            bit<32> gap = (meta.fromClient == 1) ? gapC : gapS;
            bool copy = false;

            if (meta.reinjected == 1) {
                if ((msgDone || meta.outKind == OUT_CERT) && (pend & bit_) != 0 && hdr.tcp.seq == pseq) {
                    pend = pend & ~bit_;                        // the joined message / the certificates were read
                }
            } else {
                if ((known & bit_) == 0 && msgStart) {          // no SYN seen: the stream starts with this message
                    isn = hdr.tcp.seq - 1;
                    edge = hdr.tcp.seq;
                    known = known | bit_;
                }
                bit<32> offset = hdr.tcp.seq - isn - 1;
                if (meta.http.parsed == 1 || meta.http.incomplete == 1) {
                    httpd = httpd | bit_;
                }

                /* a gap: bytes after `edge` not seen yet (sequence numbers compared modulo 2^32) */
                bit<32> end = hdr.tcp.seq + (bit<32>) meta.payLen;
                bool aheadOfGap = false;
                if ((known & bit_) != 0 && (st & bit_) != 0) {
                    if ((gaps & bit_) != 0) {
                        int<32> fromGap = (int<32>) (hdr.tcp.seq - gap);
                        if (fromGap <= 0 && (int<32>) (end - gap) > 0) {
                            gaps = gaps & ~bit_;                // the missing bytes arrived
                        } else if (fromGap > 0 && fromGap < STREAM_WINDOW) {
                            aheadOfGap = true;
                        } else if (fromGap >= STREAM_WINDOW) {
                            gaps = gaps & ~bit_;                // too far from the gap: given up
                        }
                    } else if ((int<32>) (hdr.tcp.seq - edge) > 0) {
                        gaps = gaps | bit_;                     // this segment is ahead of bytes not seen yet
                        gap = edge;
                        aheadOfGap = true;
                    }
                }
                if ((known & bit_) != 0 && (int<32>) (end - edge) > 0) {
                    edge = end;
                }

                if (msgStart) {
                    pend = pend | bit_;                         // (a)
                    pseq = hdr.tcp.seq;
                    copy = true;
                    meta.copyMsgStart = 1;
                    meta.copyMsgType = meta.tls.incomplete == 1 ? 8w1 : 8w2;
                } else if (certStart) {
                    pend = pend | bit_;                         // (d) a TLS 1.2 server flight
                    pseq = hdr.tcp.seq;
                    copy = true;
                    meta.copyMsgStart = 1;
                    meta.copyMsgType = 3;
                } else if ((pend & bit_) != 0 && hdr.tcp.seq - pseq < STREAM_WINDOW) {
                    copy = true;                                // (b)
                } else if ((st & bit_) == 0 && (known & bit_) != 0 && offset != 0 && offset < STREAM_WINDOW) {
                    copy = true;                                // (c)
                } else if (aheadOfGap && (httpd & bit_) != 0) {
                    copy = true;                                // (e)
                }
                if (msgDone && !certStart && (pend & bit_) != 0 && hdr.tcp.seq == pseq) {
                    pend = pend & ~bit_;                        // a retransmission brought the whole message
                }
                if ((known & bit_) != 0 && offset == 0) {
                    st = st | bit_;
                }
                if (copy) {
                    meta.copy = 1;
                    meta.copyOffset = offset;
                    meta.copyFromClient = (bit<8>) meta.fromClient;
                }
            }
            if (meta.fromClient == 1) {
                isnC = isn;  pseqC = pseq;  edgeC = edge;  gapC = gap;
            } else {
                isnS = isn;  pseqS = pseq;  edgeS = edge;  gapS = gap;
            }
        }

        streamConn.write(meta.slot, meta.connId);
        clientSide.write(meta.slot, side);
        isnKnown.write(meta.slot, known);
        started.write(meta.slot, st);
        pending.write(meta.slot, pend);
        isnClient.write(meta.slot, isnC);
        isnServer.write(meta.slot, isnS);
        pendingSeqClient.write(meta.slot, pseqC);
        pendingSeqServer.write(meta.slot, pseqS);
        edgeClient.write(meta.slot, edgeC);
        edgeServer.write(meta.slot, edgeS);
        gapClient.write(meta.slot, gapC);
        gapServer.write(meta.slot, gapS);
        gapOpen.write(meta.slot, gaps);
        httpDir.write(meta.slot, httpd);
    }
}

#endif
