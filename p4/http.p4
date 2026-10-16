/* HTTP fingerprint: JA4H, one per HTTP/1.x request.

   The parser (parser_http.p4) has walked a complete request header block, from a packet or from a request the
   controller joined (stream.p4), and left in meta.http: the method and version as bytes, whether Cookie and Referer
   headers were present, the number of other headers, the first four characters of Accept-Language, the header
   names in order and the cookie pairs (each list as bytes, its items separated by a zero byte). This control sends
   them in one digest. The controller sorts the cookies, computes the SHA-256 parts and writes the text.

   Every request of a connection is reported (FoxIO's reference gives one JA4H per request). A retransmitted request
   is not reported again: the switch remembers, per direction, the sequence number of the last request reported. */
#ifndef HTTP_P4
#define HTTP_P4

#include "headers.p4"

struct http_digest_t {
    bit<8>     reassembled;
    bit<8>     ipVersion;
    bit<128>   src;
    bit<128>   dst;
    bit<16>    srcPort;
    bit<16>    dstPort;
    bit<64>    method;          // the method's bytes (at most 8)
    bit<8>     methodLen;
    bit<64>    version;         // the last 8 bytes of the request line, e.g. "HTTP/1.1"
    bit<8>     hasCookie;
    bit<8>     hasReferer;
    bit<8>     headerCount;     // headers other than Cookie and Referer
    bit<32>    lang;            // Accept-Language: up to 4 characters before the first ',', without '-'
    bit<8>     langLen;
    bit<2048>  names1;          // header names in order, each followed by a zero byte (names1:names0)
    bit<2048>  names0;
    bit<16>    namesLen;
    bit<2048>  cookies3;        // the first Cookie header's pairs, separated by a zero byte (cookies3..cookies0)
    bit<2048>  cookies2;
    bit<2048>  cookies1;
    bit<2048>  cookies0;
    bit<16>    cookiesLen;
    bit<8>     overflow;        // bit 0 header names, bit 1 cookies
    bit<32>    serial;          // counts HTTP digests: BMv2 drops a digest identical to one not yet acknowledged,
                                // so two identical requests close together would be one. 32 bits and the wrap
                                // at 2^32: see the same field in dhcp.p4.
    bit<32>    connId;          // the connection's number (ConnId in main.p4)
    bit<32>    seq;             // the request's first sequence number: a joined request is reported after the
                                // requests that followed it whole, so the controller lists them by this
}

control Http(inout headers_t hdr, inout metadata_t meta) {

    register<bit<32>>(CONN_SLOTS) httpConn;
    register<bit<8>>(CONN_SLOTS)  httpSeen;     // bit 0 client direction has a last request
    register<bit<32>>(CONN_SLOTS) httpLastSeq;  // sequence number of the last request reported (client direction)
    register<bit<32>>(1)          httpSerial;

    apply {
        if (meta.http.parsed == 1) {
            bit<32> storedConn;
            bit<8> seen;
            bit<32> last;
            httpConn.read(storedConn, meta.slot);
            httpSeen.read(seen, meta.slot);
            httpLastSeq.read(last, meta.slot);
            if (storedConn != meta.connId) {
                seen = 0;
            }
            if (seen == 0 || hdr.tcp.seq != last) {
                httpConn.write(meta.slot, meta.connId);
                httpSeen.write(meta.slot, 1);
                httpLastSeq.write(meta.slot, hdr.tcp.seq);
                bit<32> serial;
                httpSerial.read(serial, 0);
                httpSerial.write(0, serial + 1);
                digest<http_digest_t>(3, {
                    (bit<8>) meta.reinjected, meta.ipVersion, meta.srcAddr, meta.dstAddr,
                    hdr.tcp.srcPort, hdr.tcp.dstPort,
                    meta.http.method, meta.http.methodLen, meta.http.version,
                    (bit<8>) meta.http.hasCookie, (bit<8>) meta.http.hasReferer, meta.http.headerCount,
                    meta.http.lang, meta.http.langLen,
                    meta.http.names1, meta.http.names0, meta.http.namesLen,
                    meta.http.cookies3, meta.http.cookies2, meta.http.cookies1, meta.http.cookies0,
                    meta.http.cookiesLen,
                    meta.http.overflow, serial, meta.connId, hdr.tcp.seq });
            }
        }
    }
}

#endif
