/*
 * example.c - minimal wintls client: HTTPS GET over TLS using the public API.
 *
 * Builds against the wintls library; demonstrates the full handshake +
 * application data flow without touching any Schannel internals.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

#include "wintls.h"

#pragma comment(lib, "ws2_32.lib")

/* Open a blocking TCP connection to host:port, returning the socket or
   INVALID_SOCKET. */
static SOCKET tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints, *res = NULL, *ai;
    SOCKET sock = INVALID_SOCKET;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host, port, &hints, &res) != 0)
        return INVALID_SOCKET;

    for (ai = res; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock == INVALID_SOCKET)
            continue;
        if (connect(sock, ai->ai_addr, (int)ai->ai_addrlen) == 0)
            break;
        closesocket(sock);
        sock = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    return sock;
}

int main(int argc, char **argv)
{
    const char *host = (argc > 1) ? argv[1] : "tls13.akamai.io";
    WSADATA wsa;
    SOCKET sock;
    wintls_client *c;
    char request[512];
    char buf[4096];
    int n, total = 0;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    sock = tcp_connect(host, "443");
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "could not connect to %s:443\n", host);
        WSACleanup();
        return 1;
    }

    c = wintls_client_new();
    if (!c) {
        fprintf(stderr, "wintls_client_new failed\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    wintls_set_verify(c, 1, 1);
    wintls_set_versions(c, WINTLS_TLS1_2, WINTLS_TLS1_3);

    if (wintls_connect(c, sock, host, 443) != 0) {
        fprintf(stderr, "TLS handshake failed: %s\n",
                wintls_error_string(wintls_last_error(c)));
        wintls_client_free(c);
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    printf("[+] TLS handshake with %s complete\n\n", host);

    n = _snprintf_s(request, sizeof(request), _TRUNCATE,
                    "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                    host);
    if (wintls_send(c, request, (size_t)n) < 0) {
        fprintf(stderr, "send failed: %s\n",
                wintls_error_string(wintls_last_error(c)));
    } else {
        while ((n = wintls_recv(c, buf, sizeof(buf))) > 0) {
            fwrite(buf, 1, (size_t)n, stdout);
            total += n;
            if (total > 8192)   /* enough to show headers + some body */
                break;
        }
        if (n < 0)
            fprintf(stderr, "\nrecv error: %s\n",
                    wintls_error_string(wintls_last_error(c)));
    }

    wintls_client_free(c);
    closesocket(sock);
    WSACleanup();
    return 0;
}
