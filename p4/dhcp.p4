/* DHCP fingerprints: JA4D (DHCPv4) and JA4D6 (DHCPv6), one per message.

       JA4D = <message type, 5 letters><maximum message size, 4 digits><i|n requested IP><d|n domain>
              _<option codes joined by '-'>_<requested codes joined by '-'>
   (JA4D6 has the client DUID's length where JA4D has the maximum message size.)

   The parser (parser_dhcp.p4) has read every value; this control sends them in one digest. The controller writes
   the text: the message type's letters, zero padding, the lists joined with '-' (FoxIO's Wireshark plugin,
   packet-ja4.c). DHCP is not a connection: every message is reported. */
#ifndef DHCP_P4
#define DHCP_P4

#include "headers.p4"

struct dhcp_digest_t {
    bit<8>    version;
    bit<128>  src;
    bit<128>  dst;
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<8>    msgType;
    bit<8>    hasType;
    bit<16>   maxSize;          // DHCPv4: option 57
    bit<8>    hasMaxSize;
    bit<16>   duidLen;          // DHCPv6: option 1's length
    bit<8>    hasDuid;
    bit<8>    requestedIp;
    bit<8>    domain;
    bit<8>    optCount;
    bit<1024> opts;
    bit<8>    reqCount;
    bit<2048> req;
    bit<8>    overflow;
    bit<32>   serial;           // counts this kind's digests: BMv2 drops a digest identical to one not yet
                                // acknowledged, so two identical messages close together would be one.
                                // Only unacknowledged digests must differ (far fewer than 2^20 even at 10^6/s
                                // with 1 s to acknowledge); wrapping at 2^32 is harmless, the controller never
                                // reads it. design.pdf, "The digest serial number".
}

control Dhcp(inout headers_t hdr, inout metadata_t meta) {

    register<bit<32>>(1) dhcpSerial;

    apply {
        if (meta.dhcp.parsed == 1) {
            bit<32> serial;
            dhcpSerial.read(serial, 0);
            dhcpSerial.write(0, serial + 1);
            digest<dhcp_digest_t>(5, {
                meta.dhcp.version, meta.srcAddr, meta.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort,
                meta.dhcp.msgType, (bit<8>) meta.dhcp.hasType, meta.dhcp.maxSize, (bit<8>) meta.dhcp.hasMaxSize,
                meta.dhcp.duidLen, (bit<8>) meta.dhcp.hasDuid, (bit<8>) meta.dhcp.requestedIp,
                (bit<8>) meta.dhcp.domain, meta.dhcp.optCount, meta.dhcp.opts, meta.dhcp.reqCount, meta.dhcp.req,
                meta.dhcp.overflow, serial });
        }
    }
}

#endif
