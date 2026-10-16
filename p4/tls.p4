/* TLS fingerprints: JA4 (ClientHello) and JA4S (ServerHello).

   The parser (parser_tls.p4) has walked a complete hello, from a packet or from a hello the controller joined
   (stream.p4), and left every value JA4/JA4S needs in meta.tls. This control sends them to the controller in one
   digest, once per connection and direction (a retransmitted hello is not reported again). The controller sorts the
   lists, computes the SHA-256 parts and writes the text; the switch does all the reading. */
#ifndef TLS_P4
#define TLS_P4

#include "headers.p4"

struct tls_digest_t {
    bit<8>    hsType;           // 1 ClientHello, 2 ServerHello
    bit<8>    reassembled;      // 1: read from the controller's join of several segments
    bit<8>    ipVersion;
    bit<128>  src;
    bit<128>  dst;
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<16>   legacyVersion;
    bit<8>    hasSupportedVersions;
    bit<16>   maxVersion;
    bit<8>    sni;
    bit<16>   cipher;           // ServerHello
    bit<8>    cipherCount;
    bit<2048> ciphers;
    bit<8>    extCount;
    bit<1024> exts;
    bit<8>    sigCount;
    bit<1024> sigs;
    bit<8>    alpnLen;
    bit<8>    alpnFirst;
    bit<8>    alpnLast;
    bit<8>    overflow;
    bit<32>   connId;           // the connection's number (ConnId in main.p4)
}

control Tls(inout headers_t hdr, inout metadata_t meta) {

    register<bit<32>>(CONN_SLOTS) tlsConn;
    register<bit<8>>(CONN_SLOTS)  tlsDone;      // bit 0: ClientHello reported, bit 1: ServerHello reported

    apply {
        if (meta.tls.parsed == 1) {
            bit<32> storedConn;
            bit<8> done;
            tlsConn.read(storedConn, meta.slot);
            tlsDone.read(done, meta.slot);
            if (storedConn != meta.connId) {
                done = 0;
            }
            bit<8> mine = (meta.tls.hsType == 1) ? 8w1 : 8w2;
            if ((done & mine) == 0) {
                tlsConn.write(meta.slot, meta.connId);
                tlsDone.write(meta.slot, done | mine);
                digest<tls_digest_t>(2, {
                    meta.tls.hsType, (bit<8>) meta.reinjected, meta.ipVersion, meta.srcAddr, meta.dstAddr,
                    hdr.tcp.srcPort, hdr.tcp.dstPort,
                    meta.tls.legacyVersion, (bit<8>) meta.tls.hasSupportedVersions, meta.tls.maxVersion,
                    (bit<8>) meta.tls.sni, meta.tls.cipher,
                    meta.tls.cipherCount, meta.tls.ciphers, meta.tls.extCount, meta.tls.exts,
                    meta.tls.sigCount, meta.tls.sigs,
                    meta.tls.alpnLen, meta.tls.alpnFirst, meta.tls.alpnLast, meta.tls.overflow, meta.connId });
            }
        }
    }
}

#endif
