/* TLS ClientHello / ServerHello walk (JA4, JA4S). Included inside MyParser (parser.p4).

   Entered after the TCP options. The walk starts only if the payload begins with a TLS handshake record holding a
   ClientHello (1) or ServerHello (2), AND the whole hello is in this packet and in this record:
       handshake length + 9 <= TCP payload length   and   handshake length + 4 <= record length.
   The record itself may continue in later packets: servers often put ServerHello, Certificate and the rest in one
   record, and only the ServerHello is needed.
   A hello that starts here but continues in a later packet is only marked `incomplete` (nothing is consumed).

   The walk reads values with lookahead and skips with advance. advance drops the skipped bytes from the packet, so a
   walked packet is resubmitted by the ingress (tls.p4) and forwarded unchanged on its second pass.

   Every list is read value by value; GREASE values (0x?a?a with equal bytes) are left out of the lists and counts,
   except a ServerHello's extensions, which FoxIO's reference keeps as they are.
   Bodies that are read (ALPN, supported_versions, signature_algorithms) decrease extLen as they are consumed; what is
   left of a body is then skipped by ext_skip. */

#define IS_GREASE(v) (((v) & 0x0f0f) == 0x0a0a && (v)[15:8] == (v)[7:0])

    /* An SSH banner ("SSH-") marks an SSH connection on any port (ssh.p4); then the payload is read as below. */
    state tcp_payload {
        transition select(meta.outKind == OUT_CERT, meta.payLen < 4) {
            (false, false): ssh_banner;
            default:        tcp_message;
        }
    }

    state ssh_banner {
        meta.sshBanner = (pkt.lookahead<bit<32>>() == 0x5353482d) ? 1w1 : 1w0;
        transition tcp_message;
    }

    state tcp_message {
        transition select(meta.outKind == OUT_CERT, meta.payLen == 0, meta.payLen < 9) {
            (true, false, _):      x509_start;  // a certificate from the controller (parser_x509.p4)
            (_, true, _):          accept;
            (false, false, true):  tls_short;   // too short to hold a record header and a handshake header
            default:               tls_peek;
        }
    }

    /* A segment of 1 to 8 bytes can still be the start of a message cut very early: if its first byte is 0x16 (a TLS
       handshake record) it may start a hello, if it is the first letter of an HTTP method it may start a request.
       Its bytes are then copied to the controller like an incomplete message; the controller's join decides. */
    state tls_short {
        transition select(pkt.lookahead<bit<8>>()) {
            0x16:    tls_incomplete;
            0x47:    http_incomplete;           // G(ET)
            0x50:    http_incomplete;           // P(OST, UT, ATCH)
            0x48:    http_incomplete;           // H(EAD)
            0x44:    http_incomplete;           // D(ELETE)
            0x4f:    http_incomplete;           // O(PTIONS)
            0x43:    http_incomplete;           // C(ONNECT)
            0x54:    http_incomplete;           // T(RACE)
            default: accept;
        }
    }

    state tls_peek {
        bit<72> h = pkt.lookahead<bit<72>>();   // record: type, version, length; handshake: type, length
        meta.tls.recLen = h[47:32];
        meta.tls.hsLen = h[23:0];
        transition select(h[71:64], h[63:56], h[31:24]) {
            (0x16, 0x03, 1): tls_check;
            (0x16, 0x03, 2): tls_check;
            default:         http_check;        // parser_http.p4
        }
    }

    state tls_check {
        meta.tls.hsType = pkt.lookahead<bit<72>>()[31:24];
        transition select(((bit<32>) meta.tls.hsLen + 9 <= (bit<32>) meta.payLen) &&
                          ((bit<32>) meta.tls.hsLen + 4 <= (bit<32>) meta.tls.recLen)) {
            true:  tls_hello;
            false: tls_incomplete;
        }
    }

    state tls_incomplete {
        meta.tls.incomplete = 1;
        transition accept;
    }

    /* version (2), random (32), session id (1 + n) */
    state tls_hello {
        meta.tls.walked = 1;
        pkt.advance(72);                                        // record header (5) + handshake header (4)
        meta.tls.hsLeft = (bit<32>) meta.tls.hsLen;
        meta.tls.legacyVersion = pkt.lookahead<bit<16>>();
        pkt.advance(16 + 256);
        meta.tls.sessionIdLen = (bit<16>) pkt.lookahead<bit<8>>();
        pkt.advance(8 + (bit<32>) meta.tls.sessionIdLen * 8);
        meta.tls.hsLeft = meta.tls.hsLeft - 35 - (bit<32>) meta.tls.sessionIdLen;
        transition select(meta.tls.hsType) {
            1: ch_ciphers;
            2: sh_body;
        }
    }

    /* ---- ClientHello: cipher suites, compression methods ---- */

    state ch_ciphers {
        meta.tls.cipherLeft = pkt.lookahead<bit<16>>();
        pkt.advance(16);
        meta.tls.hsLeft = meta.tls.hsLeft - 2 - (bit<32>) meta.tls.cipherLeft;
        transition ch_cipher_next;
    }

    state ch_cipher_next {
        transition select(meta.tls.cipherLeft) {
            0:       ch_compression;
            default: ch_cipher;
        }
    }

    state ch_cipher {
        meta.tls.value = pkt.lookahead<bit<16>>();
        pkt.advance(16);
        meta.tls.cipherLeft = meta.tls.cipherLeft - 2;
        transition select(IS_GREASE(meta.tls.value), meta.tls.cipherCount == TLS_CIPHER_CAP) {
            (true, _):      ch_cipher_next;
            (false, false): ch_cipher_keep;
            (false, true):  ch_cipher_overflow;
        }
    }

    state ch_cipher_keep {
        meta.tls.ciphers = (meta.tls.ciphers << 16) | (bit<2048>) meta.tls.value;
        meta.tls.cipherCount = meta.tls.cipherCount + 1;
        transition ch_cipher_next;
    }

    state ch_cipher_overflow {
        meta.tls.overflow = meta.tls.overflow | 1;
        transition ch_cipher_next;
    }

    state ch_compression {
        bit<8> n = pkt.lookahead<bit<8>>();
        pkt.advance(8 + (bit<32>) n * 8);
        meta.tls.hsLeft = meta.tls.hsLeft - 1 - (bit<32>) n;
        transition ext_block;
    }

    /* ---- ServerHello: chosen cipher suite, compression method ---- */

    state sh_body {
        meta.tls.cipher = pkt.lookahead<bit<16>>();
        pkt.advance(24);
        meta.tls.hsLeft = meta.tls.hsLeft - 3;
        transition ext_block;
    }

    /* ---- extensions (both hellos) ---- */

    state ext_block {
        transition select(meta.tls.hsLeft) {
            0:       tls_done;                  // a hello without extensions
            default: ext_block_len;
        }
    }

    state ext_block_len {
        meta.tls.extLeft = pkt.lookahead<bit<16>>();
        pkt.advance(16);
        transition ext_next;
    }

    state ext_next {
        transition select(meta.tls.extLeft) {
            0:       tls_done;
            default: ext_hdr;
        }
    }

    state ext_hdr {
        bit<32> h = pkt.lookahead<bit<32>>();
        meta.tls.extType = h[31:16];
        meta.tls.extLen = h[15:0];
        pkt.advance(32);
        meta.tls.extLeft = meta.tls.extLeft - 4 - meta.tls.extLen;
        transition select(meta.tls.hsType, IS_GREASE(meta.tls.extType)) {
            (1, true): ext_skip;                // a client's GREASE extension is not counted
            default:   ext_count;
        }
    }

    state ext_count {
        transition select(meta.tls.extCount == TLS_EXT_CAP) {
            false: ext_keep;
            true:  ext_overflow;
        }
    }

    state ext_keep {
        meta.tls.exts = (meta.tls.exts << 16) | (bit<1024>) meta.tls.extType;
        meta.tls.extCount = meta.tls.extCount + 1;
        transition ext_body;
    }

    state ext_overflow {
        meta.tls.overflow = meta.tls.overflow | 2;
        transition ext_body;
    }

    state ext_body {
        transition select(meta.tls.hsType, meta.tls.extType) {
            (1, 0):  ext_sni;                   // server_name
            (_, 16): ext_alpn;                  // application_layer_protocol_negotiation
            (1, 43): ch_versions;               // supported_versions, client: a list
            (2, 43): sh_version;                // supported_versions, server: the selected one
            (1, 13): ext_sigs;                  // signature_algorithms
            default: ext_skip;
        }
    }

    state ext_skip {
        pkt.advance((bit<32>) meta.tls.extLen * 8);
        transition ext_next;
    }

    state ext_sni {
        meta.tls.sni = 1;
        transition ext_skip;
    }

    /* ALPN: list length (2), then the first protocol name: length (1), bytes. Only the first name is used: its first
       and last byte and its length (the controller turns them into FoxIO's two characters). */
    state ext_alpn {
        transition select(meta.tls.extLen < 3 || meta.tls.alpnSeen == 1) {
            true:  ext_skip;
            false: alpn_len;
        }
    }

    state alpn_len {
        meta.tls.alpnSeen = 1;
        pkt.advance(16);
        meta.tls.alpnLen = pkt.lookahead<bit<8>>();
        pkt.advance(8);
        meta.tls.extLen = meta.tls.extLen - 3;
        transition select(meta.tls.alpnLen) {
            0:       ext_skip;
            default: alpn_first;
        }
    }

    state alpn_first {
        meta.tls.alpnFirst = pkt.lookahead<bit<8>>();
        pkt.advance(((bit<32>) meta.tls.alpnLen - 1) * 8);
        transition alpn_last;
    }

    state alpn_last {
        meta.tls.alpnLast = pkt.lookahead<bit<8>>();
        pkt.advance(8);
        meta.tls.extLen = meta.tls.extLen - (bit<16>) meta.tls.alpnLen;
        transition ext_skip;
    }

    /* supported_versions in a ClientHello: list length (1), then 2-byte versions; keep the highest non-GREASE one */
    state ch_versions {
        meta.tls.hasSupportedVersions = 1;
        meta.tls.listLeft = (bit<16>) pkt.lookahead<bit<8>>();
        pkt.advance(8);
        meta.tls.extLen = meta.tls.extLen - 1 - meta.tls.listLeft;
        transition ch_version_next;
    }

    state ch_version_next {
        transition select(meta.tls.listLeft) {
            0:       ext_skip;
            default: ch_version;
        }
    }

    state ch_version {
        meta.tls.value = pkt.lookahead<bit<16>>();
        pkt.advance(16);
        meta.tls.listLeft = meta.tls.listLeft - 2;
        transition select(!IS_GREASE(meta.tls.value) && meta.tls.value > meta.tls.maxVersion) {
            true:  ch_version_max;
            false: ch_version_next;
        }
    }

    state ch_version_max {
        meta.tls.maxVersion = meta.tls.value;
        transition ch_version_next;
    }

    /* supported_versions in a ServerHello: the selected version (2) */
    state sh_version {
        transition select(meta.tls.extLen < 2) {
            true:  ext_skip;
            false: sh_version_read;
        }
    }

    state sh_version_read {
        meta.tls.hasSupportedVersions = 1;
        meta.tls.maxVersion = pkt.lookahead<bit<16>>();
        pkt.advance(16);
        meta.tls.extLen = meta.tls.extLen - 2;
        transition ext_skip;
    }

    /* signature_algorithms: list length (2), then 2-byte values in order. Only the first such extension counts. */
    state ext_sigs {
        transition select(meta.tls.extLen < 2 || meta.tls.sigSeen == 1) {
            true:  ext_skip;
            false: sigs_len;
        }
    }

    state sigs_len {
        meta.tls.sigSeen = 1;
        meta.tls.listLeft = pkt.lookahead<bit<16>>();
        pkt.advance(16);
        meta.tls.extLen = meta.tls.extLen - 2 - meta.tls.listLeft;
        transition sig_next;
    }

    state sig_next {
        transition select(meta.tls.listLeft) {
            0:       ext_skip;
            default: sig;
        }
    }

    state sig {
        meta.tls.value = pkt.lookahead<bit<16>>();
        pkt.advance(16);
        meta.tls.listLeft = meta.tls.listLeft - 2;
        transition select(IS_GREASE(meta.tls.value), meta.tls.sigCount == TLS_SIG_CAP) {
            (true, _):      sig_next;
            (false, false): sig_keep;
            (false, true):  sig_overflow;
        }
    }

    state sig_keep {
        meta.tls.sigs = (meta.tls.sigs << 16) | (bit<1024>) meta.tls.value;
        meta.tls.sigCount = meta.tls.sigCount + 1;
        transition sig_next;
    }

    state sig_overflow {
        meta.tls.overflow = meta.tls.overflow | 4;
        transition sig_next;
    }

    state tls_done {
        meta.tls.parsed = 1;
        transition accept;
    }
