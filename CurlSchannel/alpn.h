#ifndef __ALPN_H_
#define __ALPN_H_

#include "curlcode.h"

#define ALPN_ACCEPTED "ALPN: server accepted "

#define VTLS_INFOF_NO_ALPN                                      \
  "ALPN: server did not agree on a protocol. Uses default."
#define VTLS_INFOF_ALPN_OFFER_1STR              \
  "ALPN: offers %s"
#define VTLS_INFOF_ALPN_ACCEPTED_1STR           \
  ALPN_ACCEPTED "%s"
#define VTLS_INFOF_ALPN_ACCEPTED_LEN_1STR       \
  ALPN_ACCEPTED "%.*s"

/* see https://www.iana.org/assignments/tls-extensiontype-values/ */
#define ALPN_HTTP_1_1_LENGTH 8
#define ALPN_HTTP_1_1 "http/1.1"
#define ALPN_HTTP_1_0_LENGTH 8
#define ALPN_HTTP_1_0 "http/1.0"
#define ALPN_H2_LENGTH 2
#define ALPN_H2 "h2"
#define ALPN_H3_LENGTH 2
#define ALPN_H3 "h3"

/* conservative sizes on the ALPN entries and count we are handling,
 * we can increase these if we ever feel the need or have to accommodate
 * ALPN strings from the "outside". */
#define ALPN_NAME_MAX     10
#define ALPN_ENTRIES_MAX  3
#define ALPN_PROTO_BUF_MAX   (ALPN_ENTRIES_MAX * (ALPN_NAME_MAX + 1))

struct alpn_spec {
    const char entries[ALPN_ENTRIES_MAX][ALPN_NAME_MAX];
    size_t count; /* number of entries */
};

struct alpn_proto_buf {
    unsigned char data[ALPN_PROTO_BUF_MAX];
    int len;
};

CURLcode Curl_alpn_to_proto_buf(struct alpn_proto_buf* buf,
    const struct alpn_spec* spec);
CURLcode Curl_alpn_to_proto_str(struct alpn_proto_buf* buf,
    const struct alpn_spec* spec);

CURLcode Curl_alpn_set_negotiated(struct wintls* tls,
    const unsigned char* proto,
    size_t proto_len);

#endif