/* DHCP (JA4D) and DHCPv6 (JA4D6) walk. Included inside MyParser (parser.p4).

   DHCPv4 (UDP 67/68): the fixed BOOTP header and the magic cookie (240 bytes) are skipped; then every option
   (code, length, value) is read: its code joins the options list (except 0 pad, 53 message type, 50 requested IP,
   81 client FQDN, 255 end), and these values are taken: 53 the message type, 57 the maximum message size, 50 present
   (requesting a specific IP), 81 with a name (a domain), 55 the parameter request list (one byte per code).

   DHCPv6 (UDP 546/547): message type (1) and transaction id (3), then every option (code 2, length 2): every code
   joins the options list, including options nested in IA_NA (3), IA_TA (4), IA_PD (25), IAADDR (5) and IAPREFIX
   (26), in packet order: such a container skips only its fixed fields, so the walk reads its sub-options next, as
   tshark lists them. Taken: 1 (client identifier) its length (the DUID's length), 4 present (a temporary address
   requested), 39 (client FQDN) with a name, 6 (option request) the requested codes (2 bytes each).

   Like the TLS and HTTP walks, this one skips bytes with advance, so the packet is resubmitted and forwarded unchanged
   on its second pass. */

#define DHCP_OPT_CAP 64     // option codes kept (16 bits each)
#define DHCP_REQ_CAP 128    // requested codes kept (16 bits each)

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.srcPort, hdr.udp.dstPort) {
            (67, _):  dhcp4_check;
            (68, _):  dhcp4_check;
            (_, 67):  dhcp4_check;
            (_, 68):  dhcp4_check;
            (546, _): dhcp6_start;
            (547, _): dhcp6_start;
            (_, 546): dhcp6_start;
            (_, 547): dhcp6_start;
            default:  accept;
        }
    }

    /* ---- DHCPv4 ---- */

    state dhcp4_check {
        transition select(hdr.udp.length < 8 + 240) {
            true:  accept;                          // too short for the BOOTP header and the magic cookie
            false: dhcp4_start;
        }
    }

    state dhcp4_start {
        meta.dhcp.walked = 1;
        meta.dhcp.version = 4;
        meta.dhcp.left = hdr.udp.length - 8 - 240;
        pkt.advance(240 * 8);
        transition d4_next;
    }

    state d4_next {
        transition select(meta.dhcp.left) {
            0:       dhcp_done;
            default: d4_code;
        }
    }

    state d4_code {
        meta.dhcp.code = (bit<16>) pkt.lookahead<bit<8>>();
        pkt.advance(8);
        meta.dhcp.left = meta.dhcp.left - 1;
        transition select(meta.dhcp.code, meta.dhcp.left == 0) {
            (0, _):      d4_next;                   // pad
            (255, _):    dhcp_done;                 // end
            (_, true):   dhcp_done;                 // truncated
            default:     d4_len;
        }
    }

    state d4_len {
        meta.dhcp.len = (bit<16>) pkt.lookahead<bit<8>>();
        pkt.advance(8);
        meta.dhcp.left = meta.dhcp.left - 1;
        transition select(meta.dhcp.len > meta.dhcp.left, meta.dhcp.code) {
            (true, _):  dhcp_done;                  // malformed: the value runs past the packet
            (_, 53):    d4_type;
            (_, 50):    d4_requested_ip;
            (_, 81):    d4_fqdn;
            default:    d4_list_code;
        }
    }

    state d4_list_code {
        transition select(meta.dhcp.optCount == DHCP_OPT_CAP) {
            true:  d4_list_overflow;
            false: d4_list_keep;
        }
    }

    state d4_list_keep {
        meta.dhcp.opts = meta.dhcp.opts[1007:0] ++ meta.dhcp.code;
        meta.dhcp.optCount = meta.dhcp.optCount + 1;
        transition d4_value;
    }

    state d4_list_overflow {
        meta.dhcp.overflow = meta.dhcp.overflow | 1;
        transition d4_value;
    }

    state d4_value {
        transition select(meta.dhcp.code, meta.dhcp.len) {
            (57, 2):  d4_max_size;
            (55, _):  d4_request_list;
            default:  d4_skip;
        }
    }

    state d4_type {
        transition select(meta.dhcp.len) {
            0:       d4_skip;
            default: d4_type_read;
        }
    }

    state d4_type_read {
        meta.dhcp.msgType = pkt.lookahead<bit<8>>();
        meta.dhcp.hasType = 1;
        transition d4_skip;
    }

    state d4_max_size {
        meta.dhcp.maxSize = pkt.lookahead<bit<16>>();
        meta.dhcp.hasMaxSize = 1;
        transition d4_skip;
    }

    state d4_requested_ip {
        meta.dhcp.requestedIp = 1;
        transition d4_skip;
    }

    state d4_fqdn {
        meta.dhcp.domain = (meta.dhcp.len > 3) ? 1w1 : 1w0;    // flags, two result codes, then the name
        transition d4_skip;
    }

    state d4_request_list {
        meta.dhcp.listLeft = meta.dhcp.len;
        transition d4_req_next;
    }

    state d4_req_next {
        transition select(meta.dhcp.listLeft, meta.dhcp.reqCount == DHCP_REQ_CAP) {
            (0, _):    d4_next;
            (_, true): d4_req_overflow;
            default:   d4_req;
        }
    }

    state d4_req {
        meta.dhcp.req = meta.dhcp.req[2031:0] ++ (bit<16>) pkt.lookahead<bit<8>>();
        meta.dhcp.reqCount = meta.dhcp.reqCount + 1;
        pkt.advance(8);
        meta.dhcp.listLeft = meta.dhcp.listLeft - 1;
        meta.dhcp.left = meta.dhcp.left - 1;
        transition d4_req_next;
    }

    state d4_req_overflow {
        meta.dhcp.overflow = meta.dhcp.overflow | 2;
        meta.dhcp.len = meta.dhcp.listLeft;
        transition d4_skip;
    }

    state d4_skip {
        pkt.advance((bit<32>) meta.dhcp.len * 8);
        meta.dhcp.left = meta.dhcp.left - meta.dhcp.len;
        transition d4_next;
    }

    /* ---- DHCPv6 ---- */

    state dhcp6_start {
        transition select(hdr.udp.length < 8 + 4) {
            true:  accept;
            false: dhcp6_header;
        }
    }

    state dhcp6_header {
        meta.dhcp.walked = 1;
        meta.dhcp.version = 6;
        meta.dhcp.msgType = pkt.lookahead<bit<8>>();
        meta.dhcp.hasType = 1;
        pkt.advance(32);
        meta.dhcp.left = hdr.udp.length - 8 - 4;
        transition d6_next;
    }

    state d6_next {
        transition select(meta.dhcp.left < 4) {
            true:  dhcp_done;
            false: d6_opt;
        }
    }

    state d6_opt {
        bit<32> h = pkt.lookahead<bit<32>>();
        meta.dhcp.code = h[31:16];
        meta.dhcp.len = h[15:0];
        pkt.advance(32);
        meta.dhcp.left = meta.dhcp.left - 4;
        transition select(meta.dhcp.optCount == DHCP_OPT_CAP) {
            true:  d6_list_overflow;
            false: d6_list_keep;
        }
    }

    state d6_list_keep {
        meta.dhcp.opts = meta.dhcp.opts[1007:0] ++ meta.dhcp.code;
        meta.dhcp.optCount = meta.dhcp.optCount + 1;
        transition d6_value;
    }

    state d6_list_overflow {
        meta.dhcp.overflow = meta.dhcp.overflow | 1;
        transition d6_value;
    }

    /* containers: skip their fixed fields only, so their sub-options are read next (in packet order) */
    state d6_value {
        transition select(meta.dhcp.len > meta.dhcp.left, meta.dhcp.code) {
            (true, _): dhcp_done;                   // malformed
            (_, 1):    d6_client_id;
            (_, 4):    d6_ia_ta;
            (_, 3):    d6_fixed12;                  // IA_NA: IAID, T1, T2
            (_, 25):   d6_fixed12;                  // IA_PD: IAID, T1, T2
            (_, 5):    d6_fixed24;                  // IAADDR: address, preferred, valid lifetime
            (_, 26):   d6_fixed25;                  // IAPREFIX: preferred, valid, prefix length, prefix
            (_, 39):   d6_fqdn;
            (_, 6):    d6_oro;
            default:   d6_skip;
        }
    }

    state d6_client_id {
        meta.dhcp.duidLen = meta.dhcp.len;
        meta.dhcp.hasDuid = 1;
        transition d6_skip;
    }

    state d6_ia_ta {
        meta.dhcp.requestedIp = 1;
        transition select(meta.dhcp.len < 4) {
            true:  d6_skip;
            false: d6_fixed4;
        }
    }

    state d6_fixed4 {
        pkt.advance(4 * 8);
        meta.dhcp.left = meta.dhcp.left - 4;
        transition d6_next;
    }

    state d6_fixed12 {
        transition select(meta.dhcp.len < 12) {
            true:  d6_skip;
            false: d6_fixed12_go;
        }
    }

    state d6_fixed12_go {
        pkt.advance(12 * 8);
        meta.dhcp.left = meta.dhcp.left - 12;
        transition d6_next;
    }

    state d6_fixed24 {
        transition select(meta.dhcp.len < 24) {
            true:  d6_skip;
            false: d6_fixed24_go;
        }
    }

    state d6_fixed24_go {
        pkt.advance(24 * 8);
        meta.dhcp.left = meta.dhcp.left - 24;
        transition d6_next;
    }

    state d6_fixed25 {
        transition select(meta.dhcp.len < 25) {
            true:  d6_skip;
            false: d6_fixed25_go;
        }
    }

    state d6_fixed25_go {
        pkt.advance(25 * 8);
        meta.dhcp.left = meta.dhcp.left - 25;
        transition d6_next;
    }

    /* flags, then the name. A name of the single byte 0x00 is the root only (an empty name): no domain, as in
       FoxIO's plugin (tshark gives dhcpv6.client_domain only for a non-empty name). */
    state d6_fqdn {
        meta.dhcp.domain = (meta.dhcp.len > 2) ? 1w1 : 1w0;
        transition select(meta.dhcp.len) {
            2:       d6_fqdn_one_byte;
            default: d6_skip;
        }
    }

    state d6_fqdn_one_byte {
        bit<16> flagsAndName = pkt.lookahead<bit<16>>();
        meta.dhcp.domain = (flagsAndName[7:0] != 0) ? 1w1 : 1w0;
        transition d6_skip;
    }

    state d6_oro {
        meta.dhcp.listLeft = meta.dhcp.len;
        transition d6_oro_next;
    }

    state d6_oro_next {
        transition select(meta.dhcp.listLeft < 2, meta.dhcp.reqCount == DHCP_REQ_CAP) {
            (true, _):  d6_oro_rest;
            (_, true):  d6_oro_overflow;
            default:    d6_oro_code;
        }
    }

    state d6_oro_code {
        meta.dhcp.req = meta.dhcp.req[2031:0] ++ pkt.lookahead<bit<16>>();
        meta.dhcp.reqCount = meta.dhcp.reqCount + 1;
        pkt.advance(16);
        meta.dhcp.listLeft = meta.dhcp.listLeft - 2;
        meta.dhcp.left = meta.dhcp.left - 2;
        transition d6_oro_next;
    }

    state d6_oro_overflow {
        meta.dhcp.overflow = meta.dhcp.overflow | 2;
        transition d6_oro_rest;
    }

    state d6_oro_rest {
        meta.dhcp.len = meta.dhcp.listLeft;
        transition d6_skip;
    }

    state d6_skip {
        pkt.advance((bit<32>) meta.dhcp.len * 8);
        meta.dhcp.left = meta.dhcp.left - meta.dhcp.len;
        transition d6_next;
    }

    state dhcp_done {
        meta.dhcp.parsed = 1;
        transition accept;
    }
