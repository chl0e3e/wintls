#ifndef __CONNECTION_DATA_H
#ifdef _MSC_VER
typedef BOOL bit;
#define BIT(x) BOOL x
#else
typedef unsigned int bit;
#define BIT(x) bit x:1
#endif

#include<stdio.h>

#if defined(_MSC_VER)
#  if (_MSC_VER >= 900) && (_INTEGRAL_MAX_BITS >= 64)
#    define CURL_TYPEOF_CURL_OFF_T     __int64
#    define CURL_FORMAT_CURL_OFF_T     "I64d"
#    define CURL_FORMAT_CURL_OFF_TU    "I64u"
#    define CURL_SUFFIX_CURL_OFF_T     i64
#    define CURL_SUFFIX_CURL_OFF_TU    ui64
#  else
#    define CURL_TYPEOF_CURL_OFF_T     long
#    define CURL_FORMAT_CURL_OFF_T     "ld"
#    define CURL_FORMAT_CURL_OFF_TU    "lu"
#    define CURL_SUFFIX_CURL_OFF_T     L
#    define CURL_SUFFIX_CURL_OFF_TU    UL
#  endif
#define CURL_TYPEOF_CURL_SOCKLEN_T int
#endif

#ifdef CURL_TYPEOF_CURL_OFF_T
typedef CURL_TYPEOF_CURL_OFF_T curl_off_t;
#endif


#define PROTO_TYPE_SMALL
#ifndef PROTO_TYPE_SMALL
typedef curl_off_t curl_prot_t;
#else
typedef unsigned int curl_prot_t;
#endif


#ifndef curl_socket_typedef
/* socket typedef */
#if defined(CURL_WIN32) && !defined(__LWIP_OPT_H__) && !defined(LWIP_HDR_OPT_H)
typedef SOCKET curl_socket_t;
#define CURL_SOCKET_BAD INVALID_SOCKET
#else
typedef int curl_socket_t;
#define CURL_SOCKET_BAD -1
#endif
#define curl_socket_typedef
#endif /* curl_socket_typedef */


typedef struct CURL CURL;
#define curlcheck_cb_compatible(func, type)                             \
  (__builtin_types_compatible_p(__typeof__(func), type) ||              \
   __builtin_types_compatible_p(__typeof__(func) *, type))

typedef CURLcode(*curl_ssl_ctx_callback)(CURL* curl,    /* easy handle */
    void* ssl_ctx, /* actually an OpenSSL
                      or WolfSSL SSL_CTX,
                      or an mbedTLS
                    mbedtls_ssl_config */
    void* userptr);
#define curlcheck_ssl_ctx_cb(expr)                                      \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_ssl_ctx_callback) ||            \
   curlcheck_cb_compatible((expr), _curl_ssl_ctx_callback1) ||          \
   curlcheck_cb_compatible((expr), _curl_ssl_ctx_callback2) ||          \
   curlcheck_cb_compatible((expr), _curl_ssl_ctx_callback3) ||          \
   curlcheck_cb_compatible((expr), _curl_ssl_ctx_callback4) ||          \
   curlcheck_cb_compatible((expr), _curl_ssl_ctx_callback5) ||          \
   curlcheck_cb_compatible((expr), _curl_ssl_ctx_callback6) ||          \
   curlcheck_cb_compatible((expr), _curl_ssl_ctx_callback7) ||          \
   curlcheck_cb_compatible((expr), _curl_ssl_ctx_callback8))
#ifdef HEADER_SSL_H
/* hack: if we included OpenSSL's ssl.h, we know about SSL_CTX
 * this will of course break if we're included before OpenSSL headers...
 */
typedef CURLcode(*_curl_ssl_ctx_callback5)(CURL*, SSL_CTX*, void*);
typedef CURLcode(*_curl_ssl_ctx_callback6)(CURL*, SSL_CTX*, const void*);
typedef CURLcode(*_curl_ssl_ctx_callback7)(CURL*, const SSL_CTX*, void*);
typedef CURLcode(*_curl_ssl_ctx_callback8)(CURL*, const SSL_CTX*,
    const void*);
#else
typedef _curl_ssl_ctx_callback1 _curl_ssl_ctx_callback5;
typedef _curl_ssl_ctx_callback1 _curl_ssl_ctx_callback6;
typedef _curl_ssl_ctx_callback1 _curl_ssl_ctx_callback7;
typedef _curl_ssl_ctx_callback1 _curl_ssl_ctx_callback8;
#endif
typedef CURLcode(*_curl_ssl_ctx_callback1)(CURL*, void*, void*);
typedef CURLcode(*_curl_ssl_ctx_callback1)(CURL*, void*, void*);
typedef CURLcode(*_curl_ssl_ctx_callback2)(CURL*, void*, const void*);
typedef CURLcode(*_curl_ssl_ctx_callback3)(CURL*, const void*, void*);
typedef CURLcode(*_curl_ssl_ctx_callback4)(CURL*, const void*,
    const void*);

#define CURL_BLOB_COPY   1 /* tell libcurl to copy the data */
#define CURL_BLOB_NOCOPY 0 /* tell libcurl to NOT copy the data */
typedef enum {
    CURLSSLBACKEND_NONE = 0,
    CURLSSLBACKEND_OPENSSL = 1,
    CURLSSLBACKEND_GNUTLS = 2,
    CURLSSLBACKEND_SCHANNEL = 8
} curl_sslbackend;
struct curl_blob {
    void* data;
    size_t len;
    unsigned int flags; /* bit 0 is defined, the rest are reserved and should be
                           left zeroes */
};

/* SSL backend-specific data; declared differently by each SSL backend */
struct ssl_backend_data;

struct ssl_primary_config {
    char* CApath;          /* certificate dir (doesn't work on windows) */
    char* CAfile;          /* certificate to verify peer against */
    char* issuercert;      /* optional issuer certificate filename */
    char* clientcert;
    char* cipher_list;     /* list of ciphers to use */
    char* cipher_list13;   /* list of TLS 1.3 cipher suites to use */
    char* pinned_key;
    char* CRLfile;         /* CRL to check certificate revocation */
    struct curl_blob* cert_blob;
    struct curl_blob* ca_info_blob;
    struct curl_blob* issuercert_blob;
#ifdef USE_TLS_SRP
    char* username; /* TLS username (for, e.g., SRP) */
    char* password; /* TLS password (for, e.g., SRP) */
#endif
    char* curves;          /* list of curves to use */
    unsigned char ssl_options;  /* the CURLOPT_SSL_OPTIONS bitmask */
    unsigned int version_max; /* max supported version the client wants to use */
    unsigned char version;    /* what version the client wants to use */
    BOOL verifypeer;       /* set TRUE if this is desired */
    BOOL verifyhost;       /* set TRUE if CN/SAN must match hostname */
    BOOL verifystatus;     /* set TRUE if certificate status must be checked */
    BOOL sessionid;        /* cache session IDs or not */
};

struct ssl_config_data {
    struct ssl_primary_config primary;
    long certverifyresult; /* result from the certificate verification */
    curl_ssl_ctx_callback fsslctx; /* function to initialize ssl ctx */
    void* fsslctxp;        /* parameter for call back */
    char* cert_type; /* format for certificate (default: PEM)*/
    char* key; /* private key file name */
    struct curl_blob* key_blob;
    char* key_type; /* format for private key (default: PEM) */
    char* key_passwd; /* plain text private key password */
    BOOL certinfo;     /* gather lots of certificate info */
    BOOL falsestart;
    BOOL enable_beast; /* allow this flaw for interoperability's sake */
    BOOL no_revoke;    /* disable SSL certificate revocation checks */
    BOOL no_partialchain; /* don't accept partial certificate chains */
    BOOL revoke_best_effort; /* ignore SSL revocation offline/missing revocation
                                list errors */
    BOOL native_ca_store; /* use the native ca store of operating system */
    BOOL auto_client_cert;   /* automatically locate and use a client
                                certificate for authentication (Schannel) */
};

struct ssl_general_config {
    size_t max_ssl_sessions; /* SSL session id cache size */
    int ca_cache_timeout;  /* Certificate store cache timeout (seconds) */
};

/* information stored about one single SSL session */
struct Curl_ssl_session {
    char* name;       /* host name for which this ID was used */
    char* conn_to_host; /* host name for the connection (may be NULL) */
    const char* scheme; /* protocol scheme used */
    void* sessionid;  /* as returned from the SSL layer */
    size_t idsize;    /* if known, otherwise 0 */
    long age;         /* just a number, the higher the more recent */
    int remote_port;  /* remote port */
    int conn_to_port; /* remote port for the connection (may be -1) */
    struct ssl_primary_config ssl_config; /* setup for this session */
};

#ifndef _SSIZE_T_DEFINED
#  if defined(__POCC__) || defined(__MINGW32__)
#  elif defined(_WIN64)
#    define _SSIZE_T_DEFINED
#    define ssize_t __int64
#  else
#    define _SSIZE_T_DEFINED
#    define ssize_t int
#  endif
#endif

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

CURLcode Curl_alpn_set_negotiated(struct Curl_cfilter* cf,
    struct Curl_easy* data,
    const unsigned char* proto,
    size_t proto_len);

/* enum for the nonblocking SSL connection state machine */
typedef enum {
    ssl_connect_1,
    ssl_connect_2,
    ssl_connect_2_reading,
    ssl_connect_2_writing,
    ssl_connect_3,
    ssl_connect_done
} ssl_connect_state;

typedef enum {
    ssl_connection_none,
    ssl_connection_negotiating,
    ssl_connection_complete
} ssl_connection_state;

struct curltime {
    time_t tv_sec; /* seconds */
    int tv_usec;   /* microseconds */
};

struct cf_call_data {
    struct Curl_easy* data;
#ifdef DEBUGBUILD
    int depth;
#endif
};

/* Information in each SSL cfilter context: cf->ctx */
struct ssl_connect_data {
    ssl_connection_state state;
    ssl_connect_state connecting_state;
    char* hostname;                   /* hostname for verification */
    char* dispname;                   /* display version of hostname */
    const struct alpn_spec* alpn;     /* ALPN to use or NULL for none */
    struct ssl_backend_data* backend; /* vtls backend specific props */
    struct cf_call_data call_data;    /* data handle used in current call */
    struct curltime handshake_done;   /* time when handshake finished */
    int port;                         /* remote port at origin */
    BOOL use_alpn;                    /* if ALPN shall be used in handshake */
};

#define CURLINFO_STRING   0x100000
#define CURLINFO_LONG     0x200000
#define CURLINFO_DOUBLE   0x300000
#define CURLINFO_SLIST    0x400000
#define CURLINFO_PTR      0x400000 /* same as SLIST */
#define CURLINFO_SOCKET   0x500000
#define CURLINFO_OFF_T    0x600000
#define CURLINFO_MASK     0x0fffff
#define CURLINFO_TYPEMASK 0xf00000

#define CURL_DEPRECATED(version, message)                       \
  __attribute__((deprecated("since " # version ". " message)))

typedef enum {
    CURLINFO_NONE, /* first, never use this */
    CURLINFO_EFFECTIVE_URL = CURLINFO_STRING + 1,
    CURLINFO_RESPONSE_CODE = CURLINFO_LONG + 2,
    CURLINFO_TOTAL_TIME = CURLINFO_DOUBLE + 3,
    CURLINFO_NAMELOOKUP_TIME = CURLINFO_DOUBLE + 4,
    CURLINFO_CONNECT_TIME = CURLINFO_DOUBLE + 5,
    CURLINFO_PRETRANSFER_TIME = CURLINFO_DOUBLE + 6,
   // CURLINFO_SIZE_UPLOAD CURL_DEPRECATED(7.55.0, "Use CURLINFO_SIZE_UPLOAD_T")
   // = CURLINFO_DOUBLE + 7,
    CURLINFO_SIZE_UPLOAD_T = CURLINFO_OFF_T + 7,
    //CURLINFO_SIZE_DOWNLOAD
    //CURL_DEPRECATED(7.55.0, "Use CURLINFO_SIZE_DOWNLOAD_T")
    //= CURLINFO_DOUBLE + 8,
    CURLINFO_SIZE_DOWNLOAD_T = CURLINFO_OFF_T + 8,
    //CURLINFO_SPEED_DOWNLOAD
    //CURL_DEPRECATED(7.55.0, "Use CURLINFO_SPEED_DOWNLOAD_T")
    //= CURLINFO_DOUBLE + 9,
    CURLINFO_SPEED_DOWNLOAD_T = CURLINFO_OFF_T + 9,
    //CURLINFO_SPEED_UPLOAD
    //CURL_DEPRECATED(7.55.0, "Use CURLINFO_SPEED_UPLOAD_T")
    //= CURLINFO_DOUBLE + 10,
    CURLINFO_SPEED_UPLOAD_T = CURLINFO_OFF_T + 10,
    CURLINFO_HEADER_SIZE = CURLINFO_LONG + 11,
    CURLINFO_REQUEST_SIZE = CURLINFO_LONG + 12,
    CURLINFO_SSL_VERIFYRESULT = CURLINFO_LONG + 13,
    CURLINFO_FILETIME = CURLINFO_LONG + 14,
    CURLINFO_FILETIME_T = CURLINFO_OFF_T + 14,
    //CURLINFO_CONTENT_LENGTH_DOWNLOAD
    //CURL_DEPRECATED(7.55.0,
    //    "Use CURLINFO_CONTENT_LENGTH_DOWNLOAD_T")
    //= CURLINFO_DOUBLE + 15,
    CURLINFO_CONTENT_LENGTH_DOWNLOAD_T = CURLINFO_OFF_T + 15,
    //CURLINFO_CONTENT_LENGTH_UPLOAD
    //CURL_DEPRECATED(7.55.0,
    //    "Use CURLINFO_CONTENT_LENGTH_UPLOAD_T")
    //= CURLINFO_DOUBLE + 16,
    CURLINFO_CONTENT_LENGTH_UPLOAD_T = CURLINFO_OFF_T + 16,
    CURLINFO_STARTTRANSFER_TIME = CURLINFO_DOUBLE + 17,
    CURLINFO_CONTENT_TYPE = CURLINFO_STRING + 18,
    CURLINFO_REDIRECT_TIME = CURLINFO_DOUBLE + 19,
    CURLINFO_REDIRECT_COUNT = CURLINFO_LONG + 20,
    CURLINFO_PRIVATE = CURLINFO_STRING + 21,
    CURLINFO_HTTP_CONNECTCODE = CURLINFO_LONG + 22,
    CURLINFO_HTTPAUTH_AVAIL = CURLINFO_LONG + 23,
    CURLINFO_PROXYAUTH_AVAIL = CURLINFO_LONG + 24,
    CURLINFO_OS_ERRNO = CURLINFO_LONG + 25,
    CURLINFO_NUM_CONNECTS = CURLINFO_LONG + 26,
    CURLINFO_SSL_ENGINES = CURLINFO_SLIST + 27,
    CURLINFO_COOKIELIST = CURLINFO_SLIST + 28,
    //CURLINFO_LASTSOCKET  CURL_DEPRECATED(7.45.0, "Use CURLINFO_ACTIVESOCKET")
    //= CURLINFO_LONG + 29,
    CURLINFO_FTP_ENTRY_PATH = CURLINFO_STRING + 30,
    CURLINFO_REDIRECT_URL = CURLINFO_STRING + 31,
    CURLINFO_PRIMARY_IP = CURLINFO_STRING + 32,
    CURLINFO_APPCONNECT_TIME = CURLINFO_DOUBLE + 33,
    CURLINFO_CERTINFO = CURLINFO_PTR + 34,
    CURLINFO_CONDITION_UNMET = CURLINFO_LONG + 35,
    CURLINFO_RTSP_SESSION_ID = CURLINFO_STRING + 36,
    CURLINFO_RTSP_CLIENT_CSEQ = CURLINFO_LONG + 37,
    CURLINFO_RTSP_SERVER_CSEQ = CURLINFO_LONG + 38,
    CURLINFO_RTSP_CSEQ_RECV = CURLINFO_LONG + 39,
    CURLINFO_PRIMARY_PORT = CURLINFO_LONG + 40,
    CURLINFO_LOCAL_IP = CURLINFO_STRING + 41,
    CURLINFO_LOCAL_PORT = CURLINFO_LONG + 42,
    //CURLINFO_TLS_SESSION CURL_DEPRECATED(7.48.0, "Use CURLINFO_TLS_SSL_PTR")
    //= CURLINFO_PTR + 43,
    CURLINFO_ACTIVESOCKET = CURLINFO_SOCKET + 44,
    CURLINFO_TLS_SSL_PTR = CURLINFO_PTR + 45,
    CURLINFO_HTTP_VERSION = CURLINFO_LONG + 46,
    CURLINFO_PROXY_SSL_VERIFYRESULT = CURLINFO_LONG + 47,
    //CURLINFO_PROTOCOL    CURL_DEPRECATED(7.85.0, "Use CURLINFO_SCHEME")
    //= CURLINFO_LONG + 48,
    CURLINFO_SCHEME = CURLINFO_STRING + 49,
    CURLINFO_TOTAL_TIME_T = CURLINFO_OFF_T + 50,
    CURLINFO_NAMELOOKUP_TIME_T = CURLINFO_OFF_T + 51,
    CURLINFO_CONNECT_TIME_T = CURLINFO_OFF_T + 52,
    CURLINFO_PRETRANSFER_TIME_T = CURLINFO_OFF_T + 53,
    CURLINFO_STARTTRANSFER_TIME_T = CURLINFO_OFF_T + 54,
    CURLINFO_REDIRECT_TIME_T = CURLINFO_OFF_T + 55,
    CURLINFO_APPCONNECT_TIME_T = CURLINFO_OFF_T + 56,
    CURLINFO_RETRY_AFTER = CURLINFO_OFF_T + 57,
    CURLINFO_EFFECTIVE_METHOD = CURLINFO_STRING + 58,
    CURLINFO_PROXY_ERROR = CURLINFO_LONG + 59,
    CURLINFO_REFERER = CURLINFO_STRING + 60,
    CURLINFO_CAINFO = CURLINFO_STRING + 61,
    CURLINFO_CAPATH = CURLINFO_STRING + 62,
    CURLINFO_LASTONE = 62
} CURLINFO;


#define CF_CTX_CALL_DATA(cf)  \
  ((struct ssl_connect_data *)(cf)->ctx)->call_data


struct curl_ssl_backend {
    curl_sslbackend id;
    const char* name;
};
typedef struct curl_ssl_backend curl_ssl_backend;


/* Definitions for SSL Implementations */

struct Curl_ssl {
    /*
     * This *must* be the first entry to allow returning the list of available
     * backends in curl_global_sslset().
     */
    curl_ssl_backend info;
    unsigned int supports; /* bitfield, see above */
    size_t sizeof_ssl_backend_data;

    int (*init)(void);
    void (*cleanup)(void);

    size_t(*version)(char* buffer, size_t size);
    int (*check_cxn)(struct Curl_cfilter* cf, struct Curl_easy* data);
    int (*shut_down)(struct Curl_cfilter* cf,
        struct Curl_easy* data);
    BOOL (*data_pending)(struct Curl_cfilter* cf,
        const struct Curl_easy* data);

    /* return 0 if a find random is filled in */
    CURLcode(*random)(struct Curl_easy* data, unsigned char* entropy,
        size_t length);
    BOOL (*cert_status_request)(void);

    CURLcode(*connect_blocking)(struct Curl_cfilter* cf,
        struct Curl_easy* data);
    CURLcode(*connect_nonblocking)(struct Curl_cfilter* cf,
        struct Curl_easy* data,
        BOOL* done);

    /* If the SSL backend wants to read or write on this connection during a
       handshake, set socks[0] to the connection's FIRSTSOCKET, and return
       a bitmap indicating read or write with GETSOCK_WRITESOCK(0) or
       GETSOCK_READSOCK(0). Otherwise return GETSOCK_BLANK.
       Mandatory. */
    int (*get_select_socks)(struct Curl_cfilter* cf, struct Curl_easy* data,
        curl_socket_t* socks);

    void* (*get_internals)(struct ssl_connect_data* connssl, CURLINFO info);
    void (*close)(struct Curl_cfilter* cf, struct Curl_easy* data);
    void (*close_all)(struct Curl_easy* data);
    void (*session_free)(void* ptr);

    CURLcode(*set_engine)(struct Curl_easy* data, const char* engine);
    CURLcode(*set_engine_default)(struct Curl_easy* data);
    struct curl_slist* (*engines_list)(struct Curl_easy* data);

    BOOL (*false_start)(void);
    CURLcode(*sha256sum)(const unsigned char* input, size_t inputlen,
        unsigned char* sha256sum, size_t sha256sumlen);

    BOOL (*attach_data)(struct Curl_cfilter* cf, struct Curl_easy* data);
    void (*detach_data)(struct Curl_cfilter* cf, struct Curl_easy* data);

    void (*free_multi_ssl_backend_data)(struct multi_ssl_backend_data* mbackend);

    ssize_t(*recv_plain)(struct Curl_cfilter* cf, struct Curl_easy* data,
        char* buf, size_t len, CURLcode* code);
    ssize_t(*send_plain)(struct Curl_cfilter* cf, struct Curl_easy* data,
        const void* mem, size_t len, CURLcode* code);

};

extern const struct Curl_ssl* Curl_ssl;



/* callback that gets called when this easy handle is completed within a multi
   handle.  Only used for internally created transfers, like for example
   DoH. */
typedef int (*multidone_func)(struct Curl_easy* easy, CURLcode result);

typedef size_t(*curl_write_callback)(char* buffer,
    size_t size,
    size_t nitems,
    void* outstream);
typedef int (*curl_progress_callback)(void* clientp,
    double dltotal,
    double dlnow,
    double ultotal,
    double ulnow);
/* This is the CURLOPT_XFERINFOFUNCTION callback prototype. It was introduced
   in 7.32.0, avoids the use of floating point numbers and provides more
   detailed information. */
typedef int (*curl_xferinfo_callback)(void* clientp,
    curl_off_t dltotal,
    curl_off_t dlnow,
    curl_off_t ultotal,
    curl_off_t ulnow);
typedef size_t(*curl_read_callback)(char* buffer,
    size_t size,
    size_t nitems,
    void* instream);

typedef int (*curl_trailer_callback)(struct curl_slist** list,
    void* userdata);
/* These are the return codes for the seek callbacks */
#define CURL_SEEKFUNC_OK       0
#define CURL_SEEKFUNC_FAIL     1 /* fail the entire transfer */
#define CURL_SEEKFUNC_CANTSEEK 2 /* tell libcurl seeking can't be done, so
                                    libcurl might try other means instead */
typedef int (*curl_seek_callback)(void* instream,
    curl_off_t offset,
    int origin); /* 'whence' */

/* the kind of data that is passed to information_callback */
typedef enum {
    CURLINFO_TEXT = 0,
    CURLINFO_HEADER_IN,    /* 1 */
    CURLINFO_HEADER_OUT,   /* 2 */
    CURLINFO_DATA_IN,      /* 3 */
    CURLINFO_DATA_OUT,     /* 4 */
    CURLINFO_SSL_DATA_IN,  /* 5 */
    CURLINFO_SSL_DATA_OUT, /* 6 */
    CURLINFO_END
} curl_infotype;

typedef int (*curl_debug_callback)
(CURL* handle,      /* the handle/transfer this concerns */
    curl_infotype type, /* what kind of data */
    char* data,        /* points to the data */
    size_t size,       /* size of the data pointed to */
    void* userptr);    /* whatever the user please */
/* evaluates to true if expr is of type curl_debug_callback or "similar" */
#define curlcheck_debug_cb(expr)                                        \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_debug_callback) ||              \
   curlcheck_cb_compatible((expr), _curl_debug_callback1) ||            \
   curlcheck_cb_compatible((expr), _curl_debug_callback2) ||            \
   curlcheck_cb_compatible((expr), _curl_debug_callback3) ||            \
   curlcheck_cb_compatible((expr), _curl_debug_callback4) ||            \
   curlcheck_cb_compatible((expr), _curl_debug_callback5) ||            \
   curlcheck_cb_compatible((expr), _curl_debug_callback6) ||            \
   curlcheck_cb_compatible((expr), _curl_debug_callback7) ||            \
   curlcheck_cb_compatible((expr), _curl_debug_callback8))
typedef int (*_curl_debug_callback1) (CURL*,
    curl_infotype, char*, size_t, void*);
typedef int (*_curl_debug_callback2) (CURL*,
    curl_infotype, char*, size_t, const void*);
typedef int (*_curl_debug_callback3) (CURL*,
    curl_infotype, const char*, size_t, void*);
typedef int (*_curl_debug_callback4) (CURL*,
    curl_infotype, const char*, size_t, const void*);
typedef int (*_curl_debug_callback5) (CURL*,
    curl_infotype, unsigned char*, size_t, void*);
typedef int (*_curl_debug_callback6) (CURL*,
    curl_infotype, unsigned char*, size_t, const void*);
typedef int (*_curl_debug_callback7) (CURL*,
    curl_infotype, const unsigned char*, size_t, void*);
typedef int (*_curl_debug_callback8) (CURL*,
    curl_infotype, const unsigned char*, size_t, const void*);

typedef enum {
    CURLIOE_OK,            /* I/O operation successful */
    CURLIOE_UNKNOWNCMD,    /* command was unknown to callback */
    CURLIOE_FAILRESTART,   /* failed to restart the read */
    CURLIOE_LAST           /* never use */
} curlioerr;

typedef enum {
    CURLIOCMD_NOP,         /* no operation */
    CURLIOCMD_RESTARTREAD, /* restart the read stream from start */
    CURLIOCMD_LAST         /* never use */
} curliocmd;

typedef curlioerr(*curl_ioctl_callback)(CURL* handle,
    int cmd,
    void* clientp);

typedef enum {
    CURLSOCKTYPE_IPCXN,  /* socket created for a specific IP connection */
    CURLSOCKTYPE_ACCEPT, /* socket created by accept() call */
    CURLSOCKTYPE_LAST    /* never use */
} curlsocktype;

/* The return code from the sockopt_callback can signal information back
   to libcurl: */
#define CURL_SOCKOPT_OK 0
#define CURL_SOCKOPT_ERROR 1 /* causes libcurl to abort and return
                                CURLE_ABORTED_BY_CALLBACK */
#define CURL_SOCKOPT_ALREADY_CONNECTED 2

typedef int (*curl_sockopt_callback)(void* clientp,
    curl_socket_t curlfd,
    curlsocktype purpose);

struct curl_sockaddr {
    int family;
    int socktype;
    int protocol;
    unsigned int addrlen; /* addrlen was a socklen_t type before 7.18.0 but it
                             turned really ugly and painful on the systems that
                             lack this type */
    struct sockaddr addr;
};

typedef curl_socket_t
(*curl_opensocket_callback)(void* clientp,
    curlsocktype purpose,
    struct curl_sockaddr* address);

typedef int
(*curl_closesocket_callback)(void* clientp, curl_socket_t item);

/* This is the CURLOPT_PREREQFUNCTION callback prototype. */
typedef int (*curl_prereq_callback)(void* clientp,
    char* conn_primary_ip,
    char* conn_local_ip,
    int conn_primary_port,
    int conn_local_port);

struct curl_hstsentry {
    char* name;
    size_t namelen;
    unsigned int includeSubDomains : 1;
    char expire[18]; /* YYYYMMDD HH:MM:SS [null-terminated] */
};

struct curl_index {
    size_t index; /* the provided entry's "index" or count */
    size_t total; /* total number of entries to save */
};

typedef enum {
    CURLSTS_OK,
    CURLSTS_DONE,
    CURLSTS_FAIL
} CURLSTScode;

typedef CURLSTScode(*curl_hstsread_callback)(CURL* easy,
    struct curl_hstsentry* e,
    void* userp);
typedef CURLSTScode(*curl_hstswrite_callback)(CURL* easy,
    struct curl_hstsentry* e,
    struct curl_index* i,
    void* userp);


#ifndef CURL_DID_MEMORY_FUNC_TYPEDEFS
/*
 * The following typedef's are signatures of malloc, free, realloc, strdup and
 * calloc respectively.  Function pointers of these types can be passed to the
 * curl_global_init_mem() function to set user defined memory management
 * callback routines.
 */
typedef void* (*curl_malloc_callback)(size_t size);
typedef void (*curl_free_callback)(void* ptr);
typedef void* (*curl_realloc_callback)(void* ptr, size_t size);
typedef char* (*curl_strdup_callback)(const char* str);
typedef void* (*curl_calloc_callback)(size_t nmemb, size_t size);

#define CURL_DID_MEMORY_FUNC_TYPEDEFS
#endif


#define MIME_BOUNDARY_DASHES            24  /* leading boundary dashes */
#define MIME_RAND_BOUNDARY_CHARS        16  /* Nb. of random boundary chars. */
#define MAX_ENCODED_LINE_LENGTH         76  /* Maximum encoded line length. */
#define ENCODING_BUFFER_SIZE            256 /* Encoding temp buffers size. */

/* Part flags. */
#define MIME_USERHEADERS_OWNER  (1 << 0)
#define MIME_BODY_ONLY          (1 << 1)
#define MIME_FAST_READ          (1 << 2)

#define FILE_CONTENTTYPE_DEFAULT        "application/octet-stream"
#define MULTIPART_CONTENTTYPE_DEFAULT   "multipart/mixed"
#define DISPOSITION_DEFAULT             "attachment"

/* Part source kinds. */
enum mimekind {
    MIMEKIND_NONE = 0,            /* Part not set. */
    MIMEKIND_DATA,                /* Allocated mime data. */
    MIMEKIND_FILE,                /* Data from file. */
    MIMEKIND_CALLBACK,            /* Data from `read' callback. */
    MIMEKIND_MULTIPART,           /* Data is a mime subpart. */
    MIMEKIND_LAST
};

/* Readback state tokens. */
enum mimestate {
    MIMESTATE_BEGIN,              /* Readback has not yet started. */
    MIMESTATE_CURLHEADERS,        /* In curl-generated headers. */
    MIMESTATE_USERHEADERS,        /* In caller's supplied headers. */
    MIMESTATE_EOH,                /* End of headers. */
    MIMESTATE_BODY,               /* Placeholder. */
    MIMESTATE_BOUNDARY1,          /* In boundary prefix. */
    MIMESTATE_BOUNDARY2,          /* In boundary. */
    MIMESTATE_CONTENT,            /* In content. */
    MIMESTATE_END,                /* End of part reached. */
    MIMESTATE_LAST
};

/* Mime headers strategies. */
enum mimestrategy {
    MIMESTRATEGY_MAIL,            /* Mime mail. */
    MIMESTRATEGY_FORM,            /* HTTP post form. */
    MIMESTRATEGY_LAST
};

/* Content transfer encoder. */
struct mime_encoder {
    const char* name;          /* Encoding name. */
    size_t(*encodefunc)(char* buffer, size_t size, BOOL ateof,
        curl_mimepart* part);  /* Encoded read. */
    curl_off_t(*sizefunc)(curl_mimepart* part);  /* Encoded size. */
};

/* Content transfer encoder state. */
struct mime_encoder_state {
    size_t         pos;           /* Position on output line. */
    size_t         bufbeg;        /* Next data index in input buffer. */
    size_t         bufend;        /* First unused byte index in input buffer. */
    char           buf[ENCODING_BUFFER_SIZE]; /* Input buffer. */
};

/* Mime readback state. */
struct mime_state {
    enum mimestate state;       /* Current state token. */
    void* ptr;                  /* State-dependent pointer. */
    curl_off_t offset;          /* State-dependent offset. */
};

/* Boundary string length. */
#define MIME_BOUNDARY_LEN (MIME_BOUNDARY_DASHES + MIME_RAND_BOUNDARY_CHARS)

/* A mime multipart. */
struct curl_mime {
    curl_mimepart* parent;           /* Parent part. */
    curl_mimepart* firstpart;        /* First part. */
    curl_mimepart* lastpart;         /* Last part. */
    char boundary[MIME_BOUNDARY_LEN + 1]; /* The part boundary. */
    struct mime_state state;         /* Current readback state. */
};

/* A mime part. */
struct curl_mimepart {
    curl_mime* parent;               /* Parent mime structure. */
    curl_mimepart* nextpart;         /* Forward linked list. */
    enum mimekind kind;              /* The part kind. */
    unsigned int flags;              /* Flags. */
    char* data;                      /* Memory data or file name. */
    curl_read_callback readfunc;     /* Read function. */
    curl_seek_callback seekfunc;     /* Seek function. */
    curl_free_callback freefunc;     /* Argument free function. */
    void* arg;                       /* Argument to callback functions. */
    FILE* fp;                        /* File pointer. */
    struct curl_slist* curlheaders;  /* Part headers. */
    struct curl_slist* userheaders;  /* Part headers. */
    char* mimetype;                  /* Part mime type. */
    char* filename;                  /* Remote file name. */
    char* name;                      /* Data name. */
    curl_off_t datasize;             /* Expected data size. */
    struct mime_state state;         /* Current readback state. */
    const struct mime_encoder* encoder; /* Content data encoder. */
    struct mime_encoder_state encstate; /* Data encoder state. */
    size_t lastreadstatus;           /* Last read callback returned status. */
};
typedef struct curl_mime      curl_mime;      /* Mime context. */
typedef struct curl_mimepart  curl_mimepart;  /* Mime part context. */

enum dupstring {
    STRING_CERT,            /* client certificate file name */
    STRING_CERT_PROXY,      /* client certificate file name */
    STRING_CERT_TYPE,       /* format for certificate (default: PEM)*/
    STRING_CERT_TYPE_PROXY, /* format for certificate (default: PEM)*/
    STRING_COOKIE,          /* HTTP cookie string to send */
    STRING_COOKIEJAR,       /* dump all cookies to this file */
    STRING_CUSTOMREQUEST,   /* HTTP/FTP/RTSP request/method to use */
    STRING_DEFAULT_PROTOCOL, /* Protocol to use when the URL doesn't specify */
    STRING_DEVICE,          /* local network interface/address to use */
    STRING_ENCODING,        /* Accept-Encoding string */
    STRING_FTP_ACCOUNT,     /* ftp account data */
    STRING_FTP_ALTERNATIVE_TO_USER, /* command to send if USER/PASS fails */
    STRING_FTPPORT,         /* port to send with the FTP PORT command */
    STRING_KEY,             /* private key file name */
    STRING_KEY_PROXY,       /* private key file name */
    STRING_KEY_PASSWD,      /* plain text private key password */
    STRING_KEY_PASSWD_PROXY, /* plain text private key password */
    STRING_KEY_TYPE,        /* format for private key (default: PEM) */
    STRING_KEY_TYPE_PROXY,  /* format for private key (default: PEM) */
    STRING_KRB_LEVEL,       /* krb security level */
    STRING_NETRC_FILE,      /* if not NULL, use this instead of trying to find
                               $HOME/.netrc */
                               STRING_PROXY,           /* proxy to use */
                               STRING_PRE_PROXY,       /* pre socks proxy to use */
                               STRING_SET_RANGE,       /* range, if used */
                               STRING_SET_REFERER,     /* custom string for the HTTP referer field */
                               STRING_SET_URL,         /* what original URL to work on */
                               STRING_SSL_CAPATH,      /* CA directory name (doesn't work on windows) */
                               STRING_SSL_CAPATH_PROXY, /* CA directory name (doesn't work on windows) */
                               STRING_SSL_CAFILE,      /* certificate file to verify peer against */
                               STRING_SSL_CAFILE_PROXY, /* certificate file to verify peer against */
                               STRING_SSL_PINNEDPUBLICKEY, /* public key file to verify peer against */
                               STRING_SSL_PINNEDPUBLICKEY_PROXY, /* public key file to verify proxy */
                               STRING_SSL_CIPHER_LIST, /* list of ciphers to use */
                               STRING_SSL_CIPHER_LIST_PROXY, /* list of ciphers to use */
                               STRING_SSL_CIPHER13_LIST, /* list of TLS 1.3 ciphers to use */
                               STRING_SSL_CIPHER13_LIST_PROXY, /* list of TLS 1.3 ciphers to use */
                               STRING_USERAGENT,       /* User-Agent string */
                               STRING_SSL_CRLFILE,     /* crl file to check certificate */
                               STRING_SSL_CRLFILE_PROXY, /* crl file to check certificate */
                               STRING_SSL_ISSUERCERT, /* issuer cert file to check certificate */
                               STRING_SSL_ISSUERCERT_PROXY, /* issuer cert file to check certificate */
                               STRING_SSL_ENGINE,      /* name of ssl engine */
                               STRING_USERNAME,        /* <username>, if used */
                               STRING_PASSWORD,        /* <password>, if used */
                               STRING_OPTIONS,         /* <options>, if used */
                               STRING_PROXYUSERNAME,   /* Proxy <username>, if used */
                               STRING_PROXYPASSWORD,   /* Proxy <password>, if used */
                               STRING_NOPROXY,         /* List of hosts which should not use the proxy, if
                                                          used */
                                                          STRING_RTSP_SESSION_ID, /* Session ID to use */
                                                          STRING_RTSP_STREAM_URI, /* Stream URI for this request */
                                                          STRING_RTSP_TRANSPORT,  /* Transport for this session */
                                                          STRING_SSH_PRIVATE_KEY, /* path to the private key file for auth */
                                                          STRING_SSH_PUBLIC_KEY,  /* path to the public key file for auth */
                                                          STRING_SSH_HOST_PUBLIC_KEY_MD5, /* md5 of host public key in ascii hex */
                                                          STRING_SSH_HOST_PUBLIC_KEY_SHA256, /* sha256 of host public key in base64 */
                                                          STRING_SSH_KNOWNHOSTS,  /* file name of knownhosts file */
                                                          STRING_PROXY_SERVICE_NAME, /* Proxy service name */
                                                          STRING_SERVICE_NAME,    /* Service name */
                                                          STRING_MAIL_FROM,
                                                          STRING_MAIL_AUTH,
                                                          STRING_TLSAUTH_USERNAME,  /* TLS auth <username> */
                                                          STRING_TLSAUTH_USERNAME_PROXY, /* TLS auth <username> */
                                                          STRING_TLSAUTH_PASSWORD,  /* TLS auth <password> */
                                                          STRING_TLSAUTH_PASSWORD_PROXY, /* TLS auth <password> */
                                                          STRING_BEARER,                /* <bearer>, if used */
                                                          STRING_UNIX_SOCKET_PATH,      /* path to Unix socket, if used */
                                                          STRING_TARGET,                /* CURLOPT_REQUEST_TARGET */
                                                          STRING_DOH,                   /* CURLOPT_DOH_URL */
                                                          STRING_ALTSVC,                /* CURLOPT_ALTSVC */
                                                          STRING_HSTS,                  /* CURLOPT_HSTS */
                                                          STRING_SASL_AUTHZID,          /* CURLOPT_SASL_AUTHZID */
                                                          STRING_DNS_SERVERS,
                                                          STRING_DNS_INTERFACE,
                                                          STRING_DNS_LOCAL_IP4,
                                                          STRING_DNS_LOCAL_IP6,
                                                          STRING_SSL_EC_CURVES,
                                                          STRING_AWS_SIGV4, /* Parameters for V4 signature */

                                                          /* -- end of null-terminated strings -- */

                                                          STRING_LASTZEROTERMINATED,

                                                          /* -- below this are pointers to binary data that cannot be strdup'ed. --- */

                                                          STRING_COPYPOSTFIELDS,  /* if POST, set the fields' values here */

                                                          STRING_LAST /* not used, just an end-of-list marker */
};

enum dupblob {
    BLOB_CERT,
    BLOB_CERT_PROXY,
    BLOB_KEY,
    BLOB_KEY_PROXY,
    BLOB_SSL_ISSUERCERT,
    BLOB_SSL_ISSUERCERT_PROXY,
    BLOB_CAINFO,
    BLOB_CAINFO_PROXY,
    BLOB_LAST
};
/* This callback will be called when a new resolver request is made */
typedef int (*curl_resolver_start_callback)(void* resolver_state,
    void* reserved, void* userdata);

struct UserDefined {
    FILE* err;         /* the stderr user data goes here */
    void* debugdata;   /* the data that will be passed to fdebug */
    char* errorbuffer; /* (Static) store failure messages in here */
    void* out;         /* CURLOPT_WRITEDATA */
    void* in_set;      /* CURLOPT_READDATA */
    void* writeheader; /* write the header to this if non-NULL */
    unsigned short use_port; /* which port to use (when not using default) */
    unsigned long httpauth;  /* kind of HTTP authentication to use (bitmask) */
    unsigned long proxyauth; /* kind of proxy authentication to use (bitmask) */
    long maxredirs;    /* maximum no. of http(s) redirects to follow, set to -1
                          for infinity */

    void* postfields;  /* if POST, set the fields' values here */
    curl_seek_callback seek_func;      /* function that seeks the input */
    curl_off_t postfieldsize; /* if POST, this might have a size to use instead
                                 of strlen(), and then the data *may* be binary
                                 (contain zero bytes) */
    unsigned short localport; /* local port number to bind to */
    unsigned short localportrange; /* number of additional port numbers to test
                                      in case the 'localport' one can't be
                                      bind()ed */
    curl_write_callback fwrite_func;   /* function that stores the output */
    curl_write_callback fwrite_header; /* function that stores headers */
    curl_write_callback fwrite_rtp;    /* function that stores interleaved RTP */
    curl_read_callback fread_func_set; /* function that reads the input */
    curl_progress_callback fprogress; /* OLD and deprecated progress callback  */
    curl_xferinfo_callback fxferinfo; /* progress callback */
    curl_debug_callback fdebug;      /* function that write informational data */
    curl_ioctl_callback ioctl_func;  /* function for I/O control */
    curl_sockopt_callback fsockopt;  /* function for setting socket options */
    void* sockopt_client; /* pointer to pass to the socket options callback */
    curl_opensocket_callback fopensocket; /* function for checking/translating
                                             the address and opening the
                                             socket */
    void* opensocket_client;
    curl_closesocket_callback fclosesocket; /* function for closing the
                                               socket */
    void* closesocket_client;
    curl_prereq_callback fprereq; /* pre-initial request callback */
    void* prereq_userp; /* pre-initial request user data */

    void* seek_client;    /* pointer to pass to the seek callback */
#ifndef CURL_DISABLE_COOKIES
    struct curl_slist* cookielist; /* list of cookie files set by
                                      curl_easy_setopt(COOKIEFILE) calls */
#endif
#ifndef CURL_DISABLE_HSTS
    struct curl_slist* hstslist; /* list of HSTS files set by
                                    curl_easy_setopt(HSTS) calls */
    curl_hstsread_callback hsts_read;
    void* hsts_read_userp;
    curl_hstswrite_callback hsts_write;
    void* hsts_write_userp;
#endif
    void* progress_client; /* pointer to pass to the progress callback */
    void* ioctl_client;   /* pointer to pass to the ioctl callback */
    unsigned int timeout;        /* ms, 0 means no timeout */
    unsigned int connecttimeout; /* ms, 0 means no timeout */
    unsigned int happy_eyeballs_timeout; /* ms, 0 is a valid value */
    unsigned int server_response_timeout; /* ms, 0 means no timeout */
    long maxage_conn;     /* in seconds, max idle time to allow a connection that
                             is to be reused */
    long maxlifetime_conn; /* in seconds, max time since creation to allow a
                              connection that is to be reused */
#ifndef CURL_DISABLE_TFTP
    long tftp_blksize;    /* in bytes, 0 means use default */
#endif
    curl_off_t filesize;  /* size of file to upload, -1 means unknown */
    long low_speed_limit; /* bytes/second */
    long low_speed_time;  /* number of seconds */
    curl_off_t max_send_speed; /* high speed limit in bytes/second for upload */
    curl_off_t max_recv_speed; /* high speed limit in bytes/second for
                                  download */
    curl_off_t set_resume_from;  /* continue [ftp] transfer from here */
    struct curl_slist* headers; /* linked list of extra headers */
    struct curl_httppost* httppost;  /* linked list of old POST data */
    curl_mimepart mimepost;  /* MIME/POST data. */
#ifndef CURL_DISABLE_TELNET
    struct curl_slist* telnet_options; /* linked list of telnet options */
#endif
    struct curl_slist* resolve;     /* list of names to add/remove from
                                       DNS cache */
    struct curl_slist* connect_to; /* list of host:port mappings to override
                                      the hostname and port to connect to */
    time_t timevalue;       /* what time to compare with */
    unsigned char timecondition; /* kind of time comparison: curl_TimeCond */
    unsigned char method;   /* what kind of HTTP request: Curl_HttpReq */
    unsigned char httpwant; /* when non-zero, a specific HTTP version requested
                               to be used in the library's request(s) */
    struct ssl_config_data ssl;  /* user defined SSL stuff */
#ifndef CURL_DISABLE_PROXY
    struct ssl_config_data proxy_ssl;  /* user defined SSL stuff for proxy */
    struct curl_slist* proxyheaders; /* linked list of extra CONNECT headers */
    unsigned short proxyport; /* If non-zero, use this port number by
                                 default. If the proxy string features a
                                 ":[port]" that one will override this. */
    unsigned char proxytype; /* what kind of proxy: curl_proxytype */
    unsigned char socks5auth;/* kind of SOCKS5 authentication to use (bitmask) */
#endif
    struct ssl_general_config general_ssl; /* general user defined SSL stuff */
    int dns_cache_timeout; /* DNS cache timeout (seconds) */
    unsigned int buffer_size;      /* size of receive buffer to use */
    unsigned int upload_buffer_size; /* size of upload buffer to use,
                                        keep it >= CURL_MAX_WRITE_SIZE */
    void* private_data; /* application-private data */
#ifndef CURL_DISABLE_HTTP
    struct curl_slist* http200aliases; /* linked list of aliases for http200 */
#endif
    unsigned char ipver; /* the CURL_IPRESOLVE_* defines in the public header
                            file 0 - whatever, 1 - v2, 2 - v6 */
    curl_off_t max_filesize; /* Maximum file size to download */
#ifndef CURL_DISABLE_FTP
    unsigned char ftp_filemethod; /* how to get to a file: curl_ftpfile  */
    unsigned char ftpsslauth; /* what AUTH XXX to try: curl_ftpauth */
    unsigned char ftp_ccc;   /* FTP CCC options: curl_ftpccc */
    unsigned int accepttimeout;   /* in milliseconds, 0 means no timeout */
#endif
#if !defined(CURL_DISABLE_FTP) || defined(USE_SSH)
    struct curl_slist* quote;     /* after connection is established */
    struct curl_slist* postquote; /* after the transfer */
    struct curl_slist* prequote; /* before the transfer, after type */
    /* Despite the name, ftp_create_missing_dirs is for FTP(S) and SFTP
       1 - create directories that don't exist
       2 - the same but also allow MKD to fail once
    */
    unsigned char ftp_create_missing_dirs;
#endif
#ifdef USE_LIBSSH2
    curl_sshhostkeycallback ssh_hostkeyfunc; /* hostkey check callback */
    void* ssh_hostkeyfunc_userp;         /* custom pointer to callback */
#endif
#ifdef USE_SSH
    curl_sshkeycallback ssh_keyfunc; /* key matching callback */
    void* ssh_keyfunc_userp;         /* custom pointer to callback */
    int ssh_auth_types;    /* allowed SSH auth types */
    unsigned int new_directory_perms; /* when creating remote dirs */
#endif
#ifndef CURL_DISABLE_NETRC
    unsigned char use_netrc;        /* enum CURL_NETRC_OPTION values  */
#endif
    unsigned int new_file_perms;      /* when creating remote files */
    char* str[STRING_LAST]; /* array of strings, pointing to allocated memory */
    struct curl_blob* blobs[BLOB_LAST];
#ifdef ENABLE_IPV6
    unsigned int scope_id;  /* Scope id for IPv6 */
#endif
    curl_prot_t allowed_protocols;
    curl_prot_t redir_protocols;
#ifndef CURL_DISABLE_MIME
    unsigned int mime_options;      /* Mime option flags. */
#endif
#ifndef CURL_DISABLE_RTSP
   // void* rtp_out;     /* write RTP to this if non-NULL */
    /* Common RTSP header options */
    //Curl_RtspReq rtspreq; /* RTSP request type */
#endif
#ifndef CURL_DISABLE_FTP
    //curl_chunk_bgn_callback chunk_bgn; /* called before part of transfer
                                      //    starts */
    //curl_chunk_end_callback chunk_end; /* called after part transferring
                                      //    stopped */
    //curl_fnmatch_callback fnmatch; /* callback to decide which file corresponds
                                   //   to pattern (e.g. if WILDCARDMATCH is on) */
    //void* fnmatch_data;
    //void* wildcardptr;
#endif
    /* GSS-API credential delegation, see the documentation of
       CURLOPT_GSSAPI_DELEGATION */
    unsigned char gssapi_delegation;

    int tcp_keepidle;     /* seconds in idle before sending keepalive probe */
    int tcp_keepintvl;    /* seconds between TCP keepalive probes */

    size_t maxconnects;    /* Max idle connections in the connection cache */

    long expect_100_timeout; /* in milliseconds */
#if defined(USE_HTTP2) || defined(USE_HTTP3)
    struct Curl_data_priority priority;
#endif
    curl_resolver_start_callback resolver_start; /* optional callback called
                                                    before resolver start */
    void* resolver_start_client; /* pointer to pass to resolver start callback */
    long upkeep_interval_ms;      /* Time between calls for connection upkeep. */
    multidone_func fmultidone;
#ifndef CURL_DISABLE_DOH
    struct Curl_easy* dohfor; /* this is a DoH request for that transfer */
#endif
    CURLU* uh; /* URL handle for the current parsed URL */
#ifndef CURL_DISABLE_HTTP
    void* trailer_data; /* pointer to pass to trailer data callback */
    curl_trailer_callback trailer_callback; /* trailing data callback */
#endif
    char keep_post;     /* keep POSTs as POSTs after a 30x request; each
                           bit represents a request, from 301 to 303 */
#ifndef CURL_DISABLE_SMTP
    struct curl_slist* mail_rcpt; /* linked list of mail recipients */
    BOOL mail_rcpt_allowfails; /* allow RCPT TO command to fail for some
                                  recipients */
#endif
    unsigned char use_ssl;   /* if AUTH TLS is to be attempted etc, for FTP or
                                IMAP or POP3 or others! (type: curl_usessl)*/
    unsigned char connect_only; /* make connection/request, then let
                                   application use the socket */
    BOOL is_fread_set; /* has read callback been set to non-NULL? */
#ifndef CURL_DISABLE_TFTP
    BOOL tftp_no_options; /* do not send TFTP options requests */
#endif
    BOOL sep_headers;     /* handle host and proxy headers separately */
    BOOL cookiesession;   /* new cookie session? */
    BOOL crlf;            /* convert crlf on ftp upload(?) */
    BOOL ssh_compression;            /* enable SSH compression */

    /* Here follows BOOLean settings that define how to behave during
       this session. They are STATIC, set by libcurl users or at least initially
       and they don't change during operations. */
    BOOL quick_exit;       /* set 1L when it is okay to leak things (like
                              threads), as we're about to exit() anyway and
                              don't want lengthy cleanups to delay termination,
                              e.g. after a DNS timeout */
    BOOL get_filetime;     /* get the time and get of the remote file */
    BOOL tunnel_thru_httpproxy; /* use CONNECT through an HTTP proxy */
    BOOL prefer_ascii;     /* ASCII rather than binary */
    BOOL remote_append;    /* append, not overwrite, on upload */
    BOOL list_only;        /* list directory */
#ifndef CURL_DISABLE_FTP
    BOOL ftp_use_port;     /* use the FTP PORT command */
    BOOL ftp_use_epsv;     /* if EPSV is to be attempted or not */
    BOOL ftp_use_eprt;     /* if EPRT is to be attempted or not */
    BOOL ftp_use_pret;     /* if PRET is to be used before PASV or not */
    BOOL ftp_skip_ip;      /* skip the IP address the FTP server passes on to
                              us */
    BOOL wildcard_enabled; /* enable wildcard matching */
#endif
    BOOL hide_progress;    /* don't use the progress meter */
    BOOL http_fail_on_error;  /* fail on HTTP error codes >= 400 */
    BOOL http_keep_sending_on_error; /* for HTTP status codes >= 300 */
    BOOL http_follow_location; /* follow HTTP redirects */
    BOOL http_transfer_encoding; /* request compressed HTTP transfer-encoding */
    BOOL allow_auth_to_other_hosts;
    BOOL include_header; /* include received protocol headers in data output */
    BOOL http_set_referer; /* is a custom referer used */
    BOOL http_auto_referer; /* set "correct" referer when following
                               location: */
    BOOL opt_no_body;    /* as set with CURLOPT_NOBODY */
    BOOL verbose;        /* output verbosity */
    BOOL krb;            /* Kerberos connection requested */
    BOOL reuse_forbid;   /* forbidden to be reused, close after use */
    BOOL reuse_fresh;    /* do not re-use an existing connection  */
    BOOL no_signal;      /* do not use any signal/alarm handler */
    BOOL tcp_nodelay;    /* whether to enable TCP_NODELAY or not */
    BOOL ignorecl;       /* ignore content length */
    BOOL http_te_skip;   /* pass the raw body data to the user, even when
                            transfer-encoded (chunked, compressed) */
    BOOL http_ce_skip;   /* pass the raw body data to the user, even when
                            content-encoded (chunked, compressed) */
    BOOL proxy_transfer_mode; /* set transfer mode (;type=<a|i>) when doing
                                 FTP via an HTTP proxy */
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    BOOL socks5_gssapi_nec; /* Flag to support NEC SOCKS5 server */
#endif
    BOOL sasl_ir;         /* Enable/disable SASL initial response */
    BOOL tcp_keepalive;  /* use TCP keepalives */
    BOOL tcp_fastopen;   /* use TCP Fast Open */
    BOOL ssl_enable_alpn;/* TLS ALPN extension? */
    BOOL path_as_is;     /* allow dotdots? */
    BOOL pipewait;       /* wait for multiplex status before starting a new
                            connection */
    BOOL suppress_connect_headers; /* suppress proxy CONNECT response headers
                                      from user callbacks */
    BOOL dns_shuffle_addresses; /* whether to shuffle addresses before use */
    BOOL haproxyprotocol; /* whether to send HAProxy PROXY protocol v1
                             header */
    BOOL abstract_unix_socket;
    BOOL disallow_username_in_url; /* disallow username in url */
#ifndef CURL_DISABLE_DOH
    BOOL doh; /* DNS-over-HTTPS enabled */
    BOOL doh_verifypeer;     /* DoH certificate peer verification */
    BOOL doh_verifyhost;     /* DoH certificate hostname verification */
    BOOL doh_verifystatus;   /* DoH certificate status verification */
#endif
    BOOL http09_allowed; /* allow HTTP/0.9 responses */
#ifdef USE_WEBSOCKETS
    BOOL ws_raw_mode;
#endif
};

struct Names {
    struct Curl_hash* hostcache;
    enum {
        HCACHE_NONE,    /* not pointing to anything */
        HCACHE_MULTI,   /* points to a shared one in the multi handle */
        HCACHE_SHARED   /* points to a shared one in a shared object */
    } hostcachetype;
};

typedef void (*Curl_llist_dtor)(void*, void*);
struct Curl_llist_element {
    void* ptr;
    struct Curl_llist_element* prev;
    struct Curl_llist_element* next;
};

struct Curl_llist {
    struct Curl_llist_element* head;
    struct Curl_llist_element* tail;
    Curl_llist_dtor dtor;
    size_t size;
};
#define MAX_SOCKSPEREASYHANDLE 5

/*
 * The 'connectdata' struct MUST have all the connection oriented stuff as we
 * may have several simultaneous connections and connection structs in memory.
 *
 * The 'struct UserDefined' must only contain data that is set once to go for
 * many (perhaps) independent connections. Values that are generated or
 * calculated internally for the "session handle" must be defined within the
 * 'struct UrlState' instead.
 */

struct Curl_easy {
    /* First a simple identifier to easier detect if a user mix up this easy
       handle with a multi handle. Set this to CURLEASY_MAGIC_NUMBER */
    unsigned int magic;

    /* first, two fields for the linked list of these */
    struct Curl_easy* next;
    struct Curl_easy* prev;

    struct connectdata* conn;
    struct Curl_llist_element connect_queue; /* for the pending and msgsent
                                                lists */
    struct Curl_llist_element conn_queue; /* list per connectdata */

    CURLMstate mstate;  /* the handle's state */
    CURLcode result;   /* previous result */

    struct Curl_message msg; /* A single posted message. */

    /* Array with the plain socket numbers this handle takes care of, in no
       particular order. Note that all sockets are added to the sockhash, where
       the state etc are also kept. This array is mostly used to detect when a
       socket is to be removed from the hash. See singlesocket(). */
    curl_socket_t sockets[MAX_SOCKSPEREASYHANDLE];
    unsigned char actions[MAX_SOCKSPEREASYHANDLE]; /* action for each socket in
                                                      sockets[] */
    int numsocks;

    struct Names dns;
    struct Curl_multi* multi;    /* if non-NULL, points to the multi handle
                                    struct to which this "belongs" when used by
                                    the multi interface */
    struct Curl_multi* multi_easy; /* if non-NULL, points to the multi handle
                                      struct to which this "belongs" when used
                                      by the easy interface */
    struct Curl_share* share;    /* Share, handles global variable mutexing */
#ifdef USE_LIBPSL
    struct PslCache* psl;        /* The associated PSL cache. */
#endif
    struct SingleRequest req;    /* Request-specific data */
    struct UserDefined set;      /* values set by the libcurl user */
#ifndef CURL_DISABLE_COOKIES
    struct CookieInfo* cookies;  /* the cookies, read from files and servers.
                                    NOTE that the 'cookie' field in the
                                    UserDefined struct defines if the "engine"
                                    is to be used or not. */
#endif
#ifndef CURL_DISABLE_HSTS
    struct hsts* hsts;
#endif
#ifndef CURL_DISABLE_ALTSVC
    struct altsvcinfo* asi;      /* the alt-svc cache */
#endif
    struct Progress progress;    /* for all the progress meter data */
    struct UrlState state;       /* struct for fields used for state info and
                                    other dynamic purposes */
#ifndef CURL_DISABLE_FTP
    struct WildcardData* wildcard; /* wildcard download state info */
#endif
    struct PureInfo info;        /* stats, reports and info data */
    struct curl_tlssessioninfo tsi; /* Information about the TLS session, only
                                       valid after a client has asked for it */
#ifdef USE_HYPER
    struct hyptransfer hyp;
#endif
};

#define LIBCURL_NAME "libcurl"

#define __CONNECTION_DATA_H
#endif