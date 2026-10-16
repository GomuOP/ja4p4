/* Certificate fingerprint: JA4X, one per certificate of a TLS 1.2 server's chain.

       JA4X = hash(issuer attribute OIDs) _ hash(subject attribute OIDs) _ hash(extension OIDs)
   each hash being the first 12 hex digits of SHA-256 over the OIDs (hex of their DER content), joined by ','.

   The parser (parser_x509.p4) has walked one certificate sent back by the controller and copied the three OID lists.
   This control sends them in one digest; the controller writes the hex, joins and hashes. (TLS 1.3 encrypts the
   certificate, so only TLS 1.2 chains can be read on the wire.) */
#ifndef X509_P4
#define X509_P4

#include "headers.p4"

struct x509_digest_t {
    bit<8>    ipVersion;
    bit<128>  src;
    bit<128>  dst;
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<8>    index;            // position in the chain, from the controller
    bit<2048> issuer;
    bit<16>   issuerLen;
    bit<2048> subject;
    bit<16>   subjectLen;
    bit<2048> exts;
    bit<16>   extsLen;
    bit<8>    overflow;
    bit<32>   connId;           // the connection's number (ConnId in main.p4)
}

control X509(inout headers_t hdr, inout metadata_t meta) {
    apply {
        if (meta.x509.parsed == 1) {
            digest<x509_digest_t>(6, {
                meta.ipVersion, meta.srcAddr, meta.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, meta.certIndex,
                meta.x509.issuer, meta.x509.issuerLen, meta.x509.subject, meta.x509.subjectLen,
                meta.x509.exts, meta.x509.extsLen, meta.x509.overflow, meta.connId });
        }
    }
}

#endif
