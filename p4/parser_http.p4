/* HTTP/1.x request walk (JA4H). Included inside MyParser (parser.p4).

   Entered when the TCP payload begins with an HTTP method ("GET ", "POST", ...). The request header block is read
   one byte per state (lookahead, then advance), up to the empty line that ends it:

   (a bare LF is accepted wherever CR LF is, as tshark does)
       METHOD SP target SP HTTP/1.x CR LF       method bytes; the last 8 bytes of the line (the version)
       Name: value CR LF        (repeated)      every name; the first Cookie value split at "; ";
                                                the first Accept-Language value up to ',' without '-'
       CR LF                                    end: parsed = 1

   meta.http.left counts the payload bytes not read yet. If it reaches 0 before the empty line, the request continues
   in a later segment: `incomplete` is set and stream.p4 copies the segments to the controller, which joins them and
   sends the whole header block back to be walked here. A walked packet lost the bytes `advance` skipped, so it is
   resubmitted and forwarded unchanged on its second pass (main.p4).

   Only constant shifts exist on this target (and at most 2,048 bits per field), so every list grows one byte at a
   time through a chain of 2,048-bit fields.
   Header names are compared without regard to case by setting bit 5 of every byte (a letter's lower case);
   the three names looked for (cookie, referer, accept-language) contain only letters and '-', which bit 5 leaves
   unchanged. */

#define HTTP_NAMES_CAP    512           // bytes of header names kept (2 fields of 2,048 bits)
#define HTTP_COOKIES_CAP 1024           // bytes of cookie pairs kept (4 fields of 2,048 bits)

#define HTTP_READ_BYTE \
        meta.http.b = pkt.lookahead<bit<8>>(); \
        pkt.advance(8); \
        meta.http.left = meta.http.left - 1

    /* the four first bytes name a method FoxIO knows (the full method is checked by the controller) */
    state http_check {
        transition select(pkt.lookahead<bit<32>>()) {
            0x47455420: http_start;     // "GET "
            0x504f5354: http_start;     // "POST"
            0x50555420: http_start;     // "PUT "
            0x48454144: http_start;     // "HEAD"
            0x44454c45: http_start;     // "DELE"
            0x4f505449: http_start;     // "OPTI"
            0x434f4e4e: http_start;     // "CONN"
            0x50415443: http_start;     // "PATC"
            0x54524143: http_start;     // "TRAC"
            default:    accept;
        }
    }

    state http_start {
        meta.http.walked = 1;
        meta.http.left = meta.payLen;
        transition m_read;
    }

    /* ---- request line ---- */

    state m_read {
        HTTP_READ_BYTE;
        transition select(meta.http.b, meta.http.left == 0, meta.http.methodLen == 8) {
            (0x20, false, _): uri_read;
            (_, true, _):     http_incomplete;
            (_, _, true):     accept;               // not a method: no fingerprint
            default:          m_store;
        }
    }

    state m_store {
        meta.http.method = (meta.http.method << 8) | (bit<64>) meta.http.b;
        meta.http.methodLen = meta.http.methodLen + 1;
        transition m_read;
    }

    state uri_read {
        HTTP_READ_BYTE;
        transition select(meta.http.b, meta.http.left == 0) {
            (0x20, false): ver_read;
            (0x0d, _):     accept;                  // no version: not HTTP/1.x
            (_, true):     http_incomplete;
            default:       uri_read;
        }
    }

    state ver_read {
        HTTP_READ_BYTE;
        transition select(meta.http.b, meta.http.left == 0) {
            (0x0d, false): line_lf;
            (0x0a, false): hdr_start;               // a bare LF also ends a line (tshark accepts it)
            (_, true):     http_incomplete;
            default:       ver_store;
        }
    }

    state ver_store {
        meta.http.version = (meta.http.version << 8) | (bit<64>) meta.http.b;
        transition ver_read;
    }

    /* LF after a CR: the next line starts */
    state line_lf {
        HTTP_READ_BYTE;
        transition select(meta.http.b, meta.http.left == 0) {
            (0x0a, false): hdr_start;
            (0x0a, true):  http_incomplete;
            default:       accept;                  // malformed
        }
    }

    /* ---- header lines ---- */

    state hdr_start {
        transition select(pkt.lookahead<bit<8>>()) {
            0x0d:    end_cr;
            0x0a:    end_lf;                        // empty line ended by a bare LF
            default: name_init;
        }
    }

    state end_cr {
        HTTP_READ_BYTE;
        transition select(meta.http.left == 0) {
            true:  http_incomplete;
            false: end_lf;
        }
    }

    state end_lf {
        HTTP_READ_BYTE;
        transition select(meta.http.b) {
            0x0a:    http_done;
            default: accept;
        }
    }

    /* A name's bytes go into names1:names0 as they are read (only constant shifts are possible on this target, so
       the chain moves one byte at a time). `cur` keeps the name's last 16 bytes for the comparisons at ':'. */
    state name_init {
        meta.http.cur = 0;
        meta.http.curLen = 0;
        transition name_read;
    }

    state name_read {
        HTTP_READ_BYTE;
        transition select(meta.http.b, meta.http.left == 0) {
            (0x3a, false): name_end;
            (_, true):     http_incomplete;
            (0x0d, _):     accept;                  // a header line without ':' (malformed)
            (0x0a, _):     accept;
            default:       name_store;
        }
    }

    state name_store {
        meta.http.cur = meta.http.cur[119:0] ++ meta.http.b;
        meta.http.curLen = meta.http.curLen + 1;
        transition select(meta.http.namesLen == HTTP_NAMES_CAP) {
            true:  name_store_over;
            false: name_store_chain;
        }
    }

    state name_store_chain {
        meta.http.names1 = meta.http.names1[2039:0] ++ meta.http.names0[2047:2040];
        meta.http.names0 = meta.http.names0[2039:0] ++ meta.http.b;
        meta.http.namesLen = meta.http.namesLen + 1;
        transition name_read;
    }

    state name_store_over {
        meta.http.overflow = meta.http.overflow | 1;
        transition name_read;
    }

    state name_end {
        transition select(
            meta.http.curLen == 6 && (meta.http.cur[47:0] | 0x202020202020) == 0x636f6f6b6965,
            meta.http.curLen == 7 && (meta.http.cur[55:0] | 0x20202020202020) == 0x72656665726572,
            meta.http.curLen == 15 &&
                (meta.http.cur[119:0] | 0x202020202020202020202020202020) == 0x6163636570742d6c616e6775616765) {
            (true, _, _): hdr_cookie;               // "cookie"
            (_, true, _): hdr_referer;              // "referer"
            (_, _, true): hdr_lang;                 // "accept-language"
            default:      hdr_other;
        }
    }

    state hdr_other {
        meta.http.hdrKind = 0;
        transition name_separator;
    }

    state hdr_lang {
        meta.http.hdrKind = 3;
        transition name_separator;
    }

    /* a listed name: count it and put a zero byte after it */
    state name_separator {
        meta.http.headerCount = meta.http.headerCount + 1;
        transition select(meta.http.namesLen == HTTP_NAMES_CAP) {
            true:  names_overflow;
            false: names_append;
        }
    }

    state names_append {
        meta.http.names1 = meta.http.names1[2039:0] ++ meta.http.names0[2047:2040];
        meta.http.names0 = meta.http.names0[2039:0] ++ 8w0;
        meta.http.namesLen = meta.http.namesLen + 1;
        transition select(meta.http.hdrKind, meta.http.langSeen) {
            (3, 0):  lang_first;
            default: value_skip;
        }
    }

    state names_overflow {
        meta.http.overflow = meta.http.overflow | 1;
        transition select(meta.http.hdrKind, meta.http.langSeen) {
            (3, 0):  lang_first;
            default: value_skip;
        }
    }

    /* Cookie and Referer are not listed, only flagged: take their bytes back out of the chain (a constant shift right
       by 6 or 7 bytes). With the list already over capacity the record is incomplete anyway. */
    state hdr_referer {
        meta.http.hasReferer = 1;
        transition select(meta.http.overflow & 1) {
            0:       referer_unlist;
            default: value_skip;
        }
    }

    state referer_unlist {
        meta.http.names0 = meta.http.names1[55:0] ++ meta.http.names0[2047:56];
        meta.http.names1 = 56w0 ++ meta.http.names1[2047:56];
        meta.http.namesLen = meta.http.namesLen - 7;
        transition value_skip;
    }

    state hdr_cookie {
        meta.http.hasCookie = 1;
        transition select(meta.http.overflow & 1) {
            0:       cookie_unlist;
            default: cookie_which;
        }
    }

    state cookie_unlist {
        meta.http.names0 = meta.http.names1[47:0] ++ meta.http.names0[2047:48];
        meta.http.names1 = 48w0 ++ meta.http.names1[2047:48];
        meta.http.namesLen = meta.http.namesLen - 6;
        transition cookie_which;
    }

    state cookie_which {
        transition select(meta.http.cookieSeen) {
            1:       value_skip;                    // only the first Cookie header is read
            default: cookie_first;
        }
    }

    /* the rest of a line, not read */
    state value_skip {
        HTTP_READ_BYTE;
        transition select(meta.http.b, meta.http.left == 0) {
            (0x0d, false): line_lf;
            (0x0a, false): hdr_start;
            (_, true):     http_incomplete;
            default:       value_skip;
        }
    }

    /* ---- Cookie value: pairs separated by "; " ---- */

    state cookie_first {
        meta.http.cookieSeen = 1;
        transition cookie_ws;
    }

    state cookie_ws {
        transition select(pkt.lookahead<bit<8>>()) {
            0x20:    cookie_ws_eat;
            0x09:    cookie_ws_eat;
            default: cookie_read;
        }
    }

    state cookie_ws_eat {
        HTTP_READ_BYTE;
        transition select(meta.http.left == 0) {
            true:  http_incomplete;
            false: cookie_ws;
        }
    }

    state cookie_read {
        HTTP_READ_BYTE;
        transition select(meta.http.b, meta.http.left == 0) {
            (0x0d, false): line_lf;
            (0x0a, false): hdr_start;
            (_, true):     http_incomplete;
            (0x3b, false): cookie_semicolon;
            default:       cookie_store;
        }
    }

    /* "; " separates two pairs; a ';' not followed by a space is part of the value */
    state cookie_semicolon {
        transition select(pkt.lookahead<bit<8>>()) {
            0x20:    cookie_separator;
            default: cookie_store;
        }
    }

    state cookie_separator {
        HTTP_READ_BYTE;                             // the space
        meta.http.b = 0;                            // stored as the zero separator
        transition select(meta.http.left == 0) {
            true:  http_incomplete;
            false: cookie_store;
        }
    }

    state cookie_store {
        transition select(meta.http.cookiesLen == HTTP_COOKIES_CAP) {
            true:  cookie_overflow;
            false: cookie_append;
        }
    }

    /* cookies3:cookies2:cookies1:cookies0 shifted left by one byte, the byte put in */
    state cookie_append {
        meta.http.cookies3 = meta.http.cookies3[2039:0] ++ meta.http.cookies2[2047:2040];
        meta.http.cookies2 = meta.http.cookies2[2039:0] ++ meta.http.cookies1[2047:2040];
        meta.http.cookies1 = meta.http.cookies1[2039:0] ++ meta.http.cookies0[2047:2040];
        meta.http.cookies0 = meta.http.cookies0[2039:0] ++ meta.http.b;
        meta.http.cookiesLen = meta.http.cookiesLen + 1;
        transition cookie_read;
    }

    state cookie_overflow {
        meta.http.overflow = meta.http.overflow | 2;
        transition cookie_read;
    }

    /* ---- Accept-Language value: up to 4 characters before the first ',', '-' left out ---- */

    state lang_first {
        meta.http.langSeen = 1;
        transition lang_ws;
    }

    state lang_ws {
        transition select(pkt.lookahead<bit<8>>()) {
            0x20:    lang_ws_eat;
            0x09:    lang_ws_eat;
            default: lang_read;
        }
    }

    state lang_ws_eat {
        HTTP_READ_BYTE;
        transition select(meta.http.left == 0) {
            true:  http_incomplete;
            false: lang_ws;
        }
    }

    state lang_read {
        HTTP_READ_BYTE;
        transition select(meta.http.b, meta.http.left == 0, meta.http.langLen == 4) {
            (0x0d, false, _): line_lf;
            (0x0a, false, _): hdr_start;
            (_, true, _):     http_incomplete;
            (0x2c, false, _): value_skip;           // ',': the first language ends
            (0x2d, false, _): lang_read;            // '-' is left out
            (_, false, true): lang_read;            // 4 characters kept already
            default:          lang_store;
        }
    }

    state lang_store {
        meta.http.lang = (meta.http.lang << 8) | (bit<32>) meta.http.b;
        meta.http.langLen = meta.http.langLen + 1;
        transition lang_read;
    }

    state http_done {
        meta.http.parsed = 1;
        transition accept;
    }

    state http_incomplete {
        meta.http.incomplete = 1;
        transition accept;
    }
