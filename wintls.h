/*
 * wintls - a small TLS client library for Windows (Schannel backend).
 *
 * Public API. Link against the wintls library (wintls.c) and the system
 * libraries it needs: ws2_32 secur32 crypt32 bcrypt ncrypt.
 *
 *     wintls_client *c = wintls_client_new();
 *     wintls_set_verify(c, 1, 1);
 *     wintls_connect(c, sock, "example.com", 443);   // sock: connected TCP socket
 *     wintls_send(c, request, request_len);
 *     int n = wintls_recv(c, buf, sizeof buf);
 *     wintls_client_free(c);
 */
#ifndef WINTLS_H
#define WINTLS_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>   /* SOCKET */
#include <stddef.h>     /* size_t */

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque TLS client handle. */
typedef struct wintls_client wintls_client;

/* TLS protocol versions, used with wintls_set_versions(). */
typedef enum {
    WINTLS_TLS1_0 = 0,
    WINTLS_TLS1_1,
    WINTLS_TLS1_2,
    WINTLS_TLS1_3
} wintls_version;

/*
 * Create a new client with sensible defaults (peer + hostname verification on,
 * TLS 1.2-1.3, 30s timeouts). Returns NULL on allocation failure.
 */
wintls_client *wintls_client_new(void);

/* Release a client and all resources it owns (including the TLS session). */
void wintls_client_free(wintls_client *c);

/* --- options: call before wintls_connect() --- */

/* Toggle certificate-chain (peer) and hostname verification. Non-zero = on. */
void wintls_set_verify(wintls_client *c, int verify_peer, int verify_host);

/* Restrict the negotiated TLS version to the [min_ver, max_ver] range. */
void wintls_set_versions(wintls_client *c,
                         wintls_version min_ver, wintls_version max_ver);

/* Offer ALPN "http/1.1" during the handshake. Non-zero = on. */
void wintls_set_alpn(wintls_client *c, int enable_http11);

/* Override the connect / per-I/O timeouts in milliseconds (0 = no timeout). */
void wintls_set_timeout_ms(wintls_client *c,
                           unsigned int connect_ms, unsigned int io_ms);

/*
 * Perform the TLS handshake over an already-connected, blocking TCP socket.
 * 'hostname' is used for SNI and certificate verification; 'port' is the
 * remote port (informational). Returns 0 on success, -1 on failure
 * (see wintls_last_error() / wintls_error_string()).
 */
int wintls_connect(wintls_client *c, SOCKET sock,
                   const char *hostname, int port);

/*
 * Send / receive application data over the established TLS session.
 * Returns the number of bytes transferred (>0), 0 if the peer closed the
 * connection, or -1 on error.
 */
int wintls_send(wintls_client *c, const void *buf, size_t len);
int wintls_recv(wintls_client *c, void *buf, size_t len);

/* The last internal error code recorded for this client (0 = none). */
int wintls_last_error(const wintls_client *c);

/* A static, human-readable description for a code from wintls_last_error(). */
const char *wintls_error_string(int code);

#ifdef __cplusplus
}
#endif

#endif /* WINTLS_H */
