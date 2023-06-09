#define WANT_PARSEX509 /* uses Curl_parseX509() */


#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <stdio.h>
#include "curlcode.h"
#include "strerror.h"
#include "version_win32.h"
#include "wintls.h"

#include "alpn.h"
#include "debug.h"

CURLcode Curl_alpn_to_proto_buf(struct alpn_proto_buf* buf,
    const struct alpn_spec* spec)
{
    size_t i, len;
    int off = 0;
    unsigned char blen;

    memset(buf, 0, sizeof(*buf));
    for (i = 0; spec && i < spec->count; ++i) {
        len = strlen(spec->entries[i]);
        if (len >= ALPN_NAME_MAX)
            return CURLE_FAILED_INIT;
        blen = (unsigned  char)len;
        if (off + blen + 1 >= (int)sizeof(buf->data))
            return CURLE_FAILED_INIT;
        buf->data[off++] = blen;
        memcpy(buf->data + off, spec->entries[i], blen);
        off += blen;
    }
    buf->len = off;
    return CURLE_OK;
}

CURLcode Curl_alpn_to_proto_str(struct alpn_proto_buf* buf,
    const struct alpn_spec* spec)
{
    size_t i, len;
    size_t off = 0;

    memset(buf, 0, sizeof(*buf));
    for (i = 0; spec && i < spec->count; ++i) {
        len = strlen(spec->entries[i]);
        if (len >= ALPN_NAME_MAX)
            return CURLE_FAILED_INIT;
        if (off + len + 2 >= sizeof(buf->data))
            return CURLE_FAILED_INIT;
        if (off)
            buf->data[off++] = ',';
        memcpy(buf->data + off, spec->entries[i], len);
        off += len;
    }
    buf->data[off] = '\0';
    buf->len = (int)off;
    return CURLE_OK;
}

CURLcode Curl_alpn_set_negotiated(struct wintls* tls,
    struct Curl_easy* data,
    const unsigned char* proto,
    size_t proto_len)
{
    int can_multi = 0;
    unsigned char* palpn = tls->alpn;
//#ifndef CURL_DISABLE_PROXY
 //   (tls->conn->bits.tunnel_proxy && Curl_ssl_cf_is_proxy(cf)) ?
 //       &cf->conn->proxy_alpn : &cf->conn->alpn
//.#else
//        & cf->conn->alpn
//#endif
        ;

    if (proto && proto_len) {
        if (proto_len == ALPN_HTTP_1_1_LENGTH &&
            !memcmp(ALPN_HTTP_1_1, proto, ALPN_HTTP_1_1_LENGTH)) {
            *palpn = CURL_HTTP_VERSION_1_1;
        }
        else if (proto_len == ALPN_HTTP_1_0_LENGTH &&
            !memcmp(ALPN_HTTP_1_0, proto, ALPN_HTTP_1_0_LENGTH)) {
            *palpn = CURL_HTTP_VERSION_1_0;
        }
#ifdef USE_HTTP2
        else if (proto_len == ALPN_H2_LENGTH &&
            !memcmp(ALPN_H2, proto, ALPN_H2_LENGTH)) {
            *palpn = CURL_HTTP_VERSION_2;
            can_multi = 1;
        }
#endif
#ifdef USE_HTTP3
        else if (proto_len == ALPN_H3_LENGTH &&
            !memcmp(ALPN_H3, proto, ALPN_H3_LENGTH)) {
            *palpn = CURL_HTTP_VERSION_3;
            can_multi = 1;
        }
#endif
        else {
            *palpn = CURL_HTTP_VERSION_NONE;
            failf(data, "unsupported ALPN protocol: '%.*s'", (int)proto_len, proto);
            /* TODO: do we want to fail this? Previous code just ignored it and
             * some vtls backends even ignore the return code of this function. */
             /* return CURLE_NOT_BUILT_IN; */
            goto out;
        }
        infof(data, VTLS_INFOF_ALPN_ACCEPTED_LEN_1STR, (int)proto_len, proto);
    }
    else {
        *palpn = CURL_HTTP_VERSION_NONE;
        infof(data, VTLS_INFOF_NO_ALPN);
    }

out:
    //if (!Curl_ssl_cf_is_proxy(cf))
   //     Curl_multiuse_state(data, can_multi ?
    //        BUNDLE_MULTIPLEX : BUNDLE_NO_MULTIUSE);
    return CURLE_OK;
}
