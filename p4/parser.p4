/* Parser: Ethernet, IPv4 (with options) or IPv6, TCP, every TCP option byte, TLS hellos (parser_tls.p4) and HTTP
   requests (parser_http.p4).

   TCP options are walked one byte at a time. Each byte is extracted into the stack hdr.tcp_opt, so the deparser
   re-emits the options unchanged, and the walk records, in metadata:
     * the kind of every option, in order (JA4T field b),
     * the MSS value (kind 2) and the window scale shift (kind 3), the last one seen if repeated.
   meta.opt.left counts the option bytes still to read (data offset * 4 - 20), so the walk never reads payload.
   EOL (kind 0) and NOP (kind 1) are single bytes. The walk does not stop at EOL: FoxIO's reference reads the options
   through tshark, which lists every zero padding byte after an EOL as another EOL, so the switch does the same
   (a SYN ending "8-4-0-0" has one EOL and one padding byte). An option whose length byte is below 2 or runs past the
   end of the options is malformed: the rest is taken as padding. */
#ifndef PARSER_P4
#define PARSER_P4

#include "headers.p4"

const bit<16> ETH_IPV4 = 0x0800;
const bit<16> ETH_IPV6 = 0x86DD;
const bit<16> ETH_VLAN = 0x8100;    // 802.1Q
const bit<16> ETH_QINQ = 0x88A8;    // 802.1ad (the outer tag of two)
const bit<8>  PROTO_TCP = 6;
const bit<8>  PROTO_UDP = 17;
const bit<32> PKT_INSTANCE_RESUBMIT = 6;

parser MyParser(packet_in pkt, out headers_t hdr, inout metadata_t meta, inout standard_metadata_t std) {

    /* A resubmitted packet (second pass, see tls.p4) is forwarded exactly as it arrived: only Ethernet is parsed and
       every other byte stays payload. A packet from the controller starts with the packet_out header. */
    state start {
        transition select(std.instance_type, std.ingress_port) {
            (PKT_INSTANCE_RESUBMIT, _): parse_ethernet_only;
            (_, CPU_PORT):              parse_packet_out;
            default:                    parse_ethernet;
        }
    }

    state parse_ethernet_only {
        pkt.extract(hdr.ethernet);
        transition accept;
    }

    state parse_packet_out {
        pkt.extract(hdr.packet_out);
        meta.reinjected = 1;
        meta.outKind = hdr.packet_out.kind;
        meta.certIndex = hdr.packet_out.index;
        transition parse_ethernet;
    }

    /* Up to two VLAN tags are read (one 802.1Q tag, or 802.1ad outside 802.1Q), then IPv4 or IPv6. A frame with
       more tags is forwarded, not fingerprinted. */
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETH_VLAN: parse_vlan_outer;
            ETH_QINQ: parse_vlan_outer;
            ETH_IPV4: parse_ipv4;
            ETH_IPV6: parse_ipv6;
            default:  accept;
        }
    }

    state parse_vlan_outer {
        pkt.extract(hdr.vlanOuter);
        transition select(hdr.vlanOuter.etherType) {
            ETH_VLAN: parse_vlan_inner;
            ETH_IPV4: parse_ipv4;
            ETH_IPV6: parse_ipv6;
            default:  accept;
        }
    }

    state parse_vlan_inner {
        pkt.extract(hdr.vlanInner);
        transition select(hdr.vlanInner.etherType) {
            ETH_IPV4: parse_ipv4;
            ETH_IPV6: parse_ipv6;
            default:  accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.ipVersion = 4;
        meta.srcAddr = (bit<128>) hdr.ipv4.src;
        meta.dstAddr = (bit<128>) hdr.ipv4.dst;
        meta.ttl = hdr.ipv4.ttl;
        meta.ipPayLen = hdr.ipv4.totalLen - ((bit<16>) hdr.ipv4.ihl) * 4;
        transition select(hdr.ipv4.ihl) {
            5:       ipv4_check_tcp;
            default: parse_ipv4_options;
        }
    }

    state parse_ipv4_options {
        pkt.extract(hdr.ipv4_options, ((bit<32>) hdr.ipv4.ihl - 5) * 32);
        transition ipv4_check_tcp;
    }

    /* Only the first fragment carries the TCP header. */
    state ipv4_check_tcp {
        transition select(hdr.ipv4.protocol, hdr.ipv4.fragOffset) {
            (PROTO_TCP, 0): parse_tcp;
            (PROTO_UDP, 0): parse_udp;
            default:        accept;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        meta.ipVersion = 6;
        meta.srcAddr = hdr.ipv6.src;
        meta.dstAddr = hdr.ipv6.dst;
        meta.ttl = hdr.ipv6.hopLimit;
        meta.ipPayLen = hdr.ipv6.payloadLen;
        transition select(hdr.ipv6.nextHeader) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default:   accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.isTcp = 1;
        meta.opt.left = ((bit<8>) hdr.tcp.dataOffset) * 4 - 20;
        meta.payLen = meta.ipPayLen - ((bit<16>) hdr.tcp.dataOffset) * 4;
        transition opt_next;
    }

    /* ---- TCP options, one byte at a time ---- */

    state opt_next {
        transition select(meta.opt.left) {
            0:       tcp_payload;
            default: opt_kind;
        }
    }

    state opt_kind {
        meta.opt.kind = pkt.lookahead<bit<8>>();
        pkt.extract(hdr.tcp_opt.next);
        meta.opt.left = meta.opt.left - 1;
        meta.opt.kinds = (meta.opt.kinds << 8) | (bit<320>) meta.opt.kind;
        meta.opt.count = meta.opt.count + 1;
        transition select(meta.opt.kind) {
            0:       opt_next;          // EOL: a single byte; any padding after it is read as more EOLs, as tshark does
            1:       opt_next;          // NOP: a single byte
            default: opt_len_check;
        }
    }

    state opt_len_check {
        transition select(meta.opt.left) {
            0:       tcp_payload;       // malformed: no room for the length byte
            default: opt_len;
        }
    }

    state opt_len {
        meta.opt.len = pkt.lookahead<bit<8>>();
        pkt.extract(hdr.tcp_opt.next);
        meta.opt.left = meta.opt.left - 1;
        /* valid only if 2 <= len and the body (len - 2) fits in what is left */
        transition select(meta.opt.len < 2 || meta.opt.len - 2 > meta.opt.left, meta.opt.kind, meta.opt.len) {
            (true,  _, _): opt_padding; // malformed: the rest is padding
            (false, 2, 4): opt_mss;
            (false, 3, 3): opt_wscale;
            default:       opt_skip;
        }
    }

    /* Values are read with lookahead before the byte is extracted. */
    state opt_mss {
        meta.opt.mss = pkt.lookahead<bit<16>>();
        meta.opt.hasMss = 1;
        pkt.extract(hdr.tcp_opt.next);
        pkt.extract(hdr.tcp_opt.next);
        meta.opt.left = meta.opt.left - 2;
        transition opt_next;
    }

    state opt_wscale {
        meta.opt.wscale = pkt.lookahead<bit<8>>();
        pkt.extract(hdr.tcp_opt.next);
        meta.opt.hasWscale = 1;
        meta.opt.left = meta.opt.left - 1;
        transition opt_next;
    }

    /* Skip the body of any other option: meta.opt.len counts down the body bytes still to read. */
    state opt_skip {
        meta.opt.len = meta.opt.len - 2;
        transition opt_skip_loop;
    }

    state opt_skip_loop {
        transition select(meta.opt.len) {
            0:       opt_next;
            default: opt_skip_byte;
        }
    }

    state opt_skip_byte {
        pkt.extract(hdr.tcp_opt.next);
        meta.opt.left = meta.opt.left - 1;
        meta.opt.len = meta.opt.len - 1;
        transition opt_skip_loop;
    }

    /* After a malformed option: keep the remaining option bytes, read nothing from them. */
    state opt_padding {
        transition select(meta.opt.left) {
            0:       tcp_payload;
            default: opt_padding_byte;
        }
    }

    state opt_padding_byte {
        pkt.extract(hdr.tcp_opt.next);
        meta.opt.left = meta.opt.left - 1;
        transition opt_padding;
    }

    /* ---- TCP payload: TLS hellos, then HTTP requests ---- */
#include "parser_tls.p4"
#include "parser_http.p4"

    /* ---- UDP: DHCP and DHCPv6 ---- */
#include "parser_dhcp.p4"

    /* ---- X.509 certificates sent back by the controller ---- */
#include "parser_x509.p4"
}

#endif
