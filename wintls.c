/*
 * wintls - a single-file Windows Schannel TLS client.
 *
 * This is an amalgamation of a Windows Schannel TLS implementation into one
 * translation unit. Build with MSVC:  cl /Fe:wintls.exe wintls.c
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define WITH_SCHANNEL
#define EXPOSE_SCHANNEL_INTERNAL_STRUCTS
/* expose the modern SCH_CREDENTIALS / TLS_PARAMETERS structs in <schannel.h>;
   must be defined before <schannel.h> is first pulled in. */
#define SCHANNEL_USE_BLACKLISTS 1
#undef SECURITY_WIN32
#define SECURITY_WIN32 1

#include <Windows.h>
#include <subauth.h>   /* UNICODE_STRING, required by <schannel.h> structs */
#include <wincrypt.h>  /* HCERTSTORE / PCCERT_CONTEXT, used by SCH_CREDENTIALS */
#include <schnlsp.h>
#include <schannel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "advapi32.lib")

/* forward declarations (final, de-branded names) */
struct wintls;
struct wintlstime;
struct alpn_spec;
struct wintls_blob;
struct wintls_slist;
struct wintls_easy;



/* ======================================================================
 * INLINED HEADERS
 ====================================================================== */



/* ======================================================================
 * header: wintlscode.h
 ====================================================================== */

#ifndef __WINTLSCODE_H_
#define __WINTLSCODE_H_

typedef enum {
	WINTLS_OK = 0,
	WINTLS_UNSUPPORTED_PROTOCOL,    /* 1 */
	WINTLS_FAILED_INIT,             /* 2 */
	WINTLS_URL_MALFORMAT,           /* 3 */
	WINTLS_NOT_BUILT_IN,            /* 4 - [was obsoleted in August 2007 for 7.17.0, reused in April 2011 for 7.21.5] */
	WINTLS_COULDNT_RESOLVE_PROXY,   /* 5 */
	WINTLS_COULDNT_RESOLVE_HOST,    /* 6 */
	WINTLS_COULDNT_CONNECT,         /* 7 */
	WINTLS_WEIRD_SERVER_REPLY,      /* 8 */
	WINTLS_REMOTE_ACCESS_DENIED,    /* 9 a service was denied by the server due to lack of access - when login fails this is not returned. */
	WINTLS_FTP_ACCEPT_FAILED,       /* 10 - [was obsoleted in April 2006 for 7.15.4, reused in Dec 2011 for 7.24.0]*/
	WINTLS_FTP_WEIRD_PASS_REPLY,    /* 11 */
	WINTLS_FTP_ACCEPT_TIMEOUT,      /* 12 - timeout occurred accepting server [was obsoleted in August 2007 for 7.17.0, reused in Dec 2011 for 7.24.0]*/
	WINTLS_FTP_WEIRD_PASV_REPLY,    /* 13 */
	WINTLS_FTP_WEIRD_227_FORMAT,    /* 14 */
	WINTLS_FTP_CANT_GET_HOST,       /* 15 */
	WINTLS_HTTP2,                   /* 16 - A problem in the http2 framing layer.  [was obsoleted in August 2007 for 7.17.0, reused in July 2014 for 7.38.0] */
	WINTLS_FTP_COULDNT_SET_TYPE,    /* 17 */
	WINTLS_PARTIAL_FILE,            /* 18 */
	WINTLS_FTP_COULDNT_RETR_FILE,   /* 19 */
	WINTLS_OBSOLETE20,              /* 20 - NOT USED */
	WINTLS_QUOTE_ERROR,             /* 21 - quote command failure */
	WINTLS_HTTP_RETURNED_ERROR,     /* 22 */
	WINTLS_WRITE_ERROR,             /* 23 */
	WINTLS_OBSOLETE24,              /* 24 - NOT USED */
	WINTLS_UPLOAD_FAILED,           /* 25 - failed upload "command" */
	WINTLS_READ_ERROR,              /* 26 - couldn't open/read from file */
	WINTLS_OUT_OF_MEMORY,           /* 27 */
	WINTLS_OPERATION_TIMEDOUT,      /* 28 - the timeout time was reached */
	WINTLS_OBSOLETE29,              /* 29 - NOT USED */
	WINTLS_FTP_PORT_FAILED,         /* 30 - FTP PORT operation failed */
	WINTLS_FTP_COULDNT_USE_REST,    /* 31 - the REST command failed */
	WINTLS_OBSOLETE32,              /* 32 - NOT USED */
	WINTLS_RANGE_ERROR,             /* 33 - RANGE "command" didn't work */
	WINTLS_HTTP_POST_ERROR,         /* 34 */
	WINTLS_SSL_CONNECT_ERROR,       /* 35 - wrong when connecting with SSL */
	WINTLS_BAD_DOWNLOAD_RESUME,     /* 36 - couldn't resume download */
	WINTLS_FILE_COULDNT_READ_FILE,  /* 37 */
	WINTLS_LDAP_CANNOT_BIND,        /* 38 */
	WINTLS_LDAP_SEARCH_FAILED,      /* 39 */
	WINTLS_OBSOLETE40,              /* 40 - NOT USED */
	WINTLS_FUNCTION_NOT_FOUND,      /* 41 - NOT USED starting with 7.53.0 */
	WINTLS_ABORTED_BY_CALLBACK,     /* 42 */
	WINTLS_BAD_FUNCTION_ARGUMENT,   /* 43 */
	WINTLS_OBSOLETE44,              /* 44 - NOT USED */
	WINTLS_INTERFACE_FAILED,        /* 45 - WINTLSOPT_INTERFACE failed */
	WINTLS_OBSOLETE46,              /* 46 - NOT USED */
	WINTLS_TOO_MANY_REDIRECTS,      /* 47 - catch endless re-direct loops */
	WINTLS_UNKNOWN_OPTION,          /* 48 - User specified an unknown option */
	WINTLS_SETOPT_OPTION_SYNTAX,    /* 49 - Malformed setopt option */
	WINTLS_OBSOLETE50,              /* 50 - NOT USED */
	WINTLS_OBSOLETE51,              /* 51 - NOT USED */
	WINTLS_GOT_NOTHING,             /* 52 - when this is a specific error */
	WINTLS_SSL_ENGINE_NOTFOUND,     /* 53 - SSL crypto engine not found */
	WINTLS_SSL_ENGINE_SETFAILED,    /* 54 - can not set SSL crypto engine as default */
	WINTLS_SEND_ERROR,              /* 55 - failed sending network data */
	WINTLS_RECV_ERROR,              /* 56 - failure in receiving network data */
	WINTLS_OBSOLETE57,              /* 57 - NOT IN USE */
	WINTLS_SSL_CERTPROBLEM,         /* 58 - problem with the local certificate */
	WINTLS_SSL_CIPHER,              /* 59 - couldn't use specified cipher */
	WINTLS_PEER_FAILED_VERIFICATION, /* 60 - peer's certificate or fingerprint wasn't verified fine */
	WINTLS_BAD_CONTENT_ENCODING,    /* 61 - Unrecognized/bad encoding */
	WINTLS_OBSOLETE62,              /* 62 - NOT IN USE since 7.82.0 */
	WINTLS_FILESIZE_EXCEEDED,       /* 63 - Maximum file size exceeded */
	WINTLS_USE_SSL_FAILED,          /* 64 - Requested FTP SSL level failed */
	WINTLS_SEND_FAIL_REWIND,        /* 65 - Sending the data requires a rewind that failed */
	WINTLS_SSL_ENGINE_INITFAILED,   /* 66 - failed to initialise ENGINE */
	WINTLS_LOGIN_DENIED,            /* 67 - user, password or similar was not accepted and we failed to login */
	WINTLS_TFTP_NOTFOUND,           /* 68 - file not found on server */
	WINTLS_TFTP_PERM,               /* 69 - permission problem on server */
	WINTLS_REMOTE_DISK_FULL,        /* 70 - out of disk space on server */
	WINTLS_TFTP_ILLEGAL,            /* 71 - Illegal TFTP operation */
	WINTLS_TFTP_UNKNOWNID,          /* 72 - Unknown transfer ID */
	WINTLS_REMOTE_FILE_EXISTS,      /* 73 - File already exists */
	WINTLS_TFTP_NOSUCHUSER,         /* 74 - No such user */
	WINTLS_OBSOLETE75,              /* 75 - NOT IN USE since 7.82.0 */
	WINTLS_OBSOLETE76,              /* 76 - NOT IN USE since 7.82.0 */
	WINTLS_SSL_CACERT_BADFILE,      /* 77 - could not load CACERT file, missing or wrong format */
	WINTLS_REMOTE_FILE_NOT_FOUND,   /* 78 - remote file not found */
	WINTLS_SSH,                     /* 79 - error from the SSH layer, somewhat generic so the error message will be of interest when this has happened */

	WINTLS_SSL_SHUTDOWN_FAILED,     /* 80 - Failed to shut down the SSL connection */
	WINTLS_AGAIN,                   /* 81 - socket is not ready for send/recv, wait till it's ready and try again (Added in 7.18.2) */
	WINTLS_SSL_CRL_BADFILE,         /* 82 - could not load CRL file, missing or wrong format (Added in 7.19.0) */
	WINTLS_SSL_ISSUER_ERROR,        /* 83 - Issuer check failed.  (Added in 7.19.0) */
	WINTLS_FTP_PRET_FAILED,         /* 84 - a PRET command failed */
	WINTLS_RTSP_CSEQ_ERROR,         /* 85 - mismatch of RTSP CSeq numbers */
	WINTLS_RTSP_SESSION_ERROR,      /* 86 - mismatch of RTSP Session Ids */
	WINTLS_FTP_BAD_FILE_LIST,       /* 87 - unable to parse FTP file list */
	WINTLS_CHUNK_FAILED,            /* 88 - chunk callback reported error */
	WINTLS_NO_CONNECTION_AVAILABLE, /* 89 - No connection available, thesession will be queued */
	WINTLS_SSL_PINNEDPUBKEYNOTMATCH,/* 90 - specified pinned public key did not match */
	WINTLS_SSL_INVALIDCERTSTATUS,   /* 91 - invalid certificate status */
	WINTLS_HTTP2_STREAM,            /* 92 - stream error in HTTP/2 framing layer */
	WINTLS_RECURSIVE_API_CALL,      /* 93 - an api function was called from inside a callback */
	WINTLS_AUTH_ERROR,              /* 94 - an authentication function returned an error */
	WINTLS_HTTP3,                   /* 95 - An HTTP/3 layer problem */
	WINTLS_QUIC_CONNECT_ERROR,      /* 96 - QUIC connection error */
	WINTLS_PROXY,                   /* 97 - proxy handshake error */
	WINTLS_SSL_CLIENTCERT,          /* 98 - client-side certificate required */
	WINTLS_UNRECOVERABLE_POLL,      /* 99 - poll/select returned fatal error */
	WINTLS_LAST /* never use! */
} wintls_code;
/* These enums are for use with the WINTLSOPT_HTTP_VERSION option. */
enum {
	WINTLS_HTTP_VERSION_NONE, /* setting this means we don't care, and that we'd
							   like the library to choose the best possible
							   for us! */
							   WINTLS_HTTP_VERSION_1_0,  /* please use HTTP 1.0 in the request */
							   WINTLS_HTTP_VERSION_1_1,  /* please use HTTP 1.1 in the request */
							   WINTLS_HTTP_VERSION_2_0,  /* please use HTTP 2 in the request */
							   WINTLS_HTTP_VERSION_2TLS, /* use version 2 for HTTPS, version 1.1 for HTTP */
							   WINTLS_HTTP_VERSION_2_PRIOR_KNOWLEDGE,  /* please use HTTP 2 without HTTP/1.1
																		Upgrade */
																		WINTLS_HTTP_VERSION_3 = 30, /* Use HTTP/3, fallback to HTTP/2 or HTTP/1 if
																									 needed. For HTTPS only. For HTTP, this option
																									 makes libwintls return error. */
																									 WINTLS_HTTP_VERSION_3ONLY = 31, /* Use HTTP/3 without fallback. For HTTPS
																																	  only. For HTTP, this makes libwintls
																																	  return error. */

																																	  WINTLS_HTTP_VERSION_LAST /* *ILLEGAL* http version */
};

#endif


/* ======================================================================
 * header: charhelper.h
 ====================================================================== */

#ifndef __CHARHELPER_H_
#define __CHARHELPER_H_

#define ISUPPER(x)  (((x) >= 'A') && ((x) <= 'Z'))
#define ISLOWER(x)  (((x) >= 'a') && ((x) <= 'z'))
#define ISDIGIT(x)  (((x) >= '0') && ((x) <= '9'))
#endif


/* ======================================================================
 * header: msvc.h
 ====================================================================== */

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

#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SIZE_T size_t;
#endif

#define wintls_safefree(ptr) \
  do { free((ptr)); (ptr) = NULL;} while(0)



/* ======================================================================
 * header: debug.h
 ====================================================================== */

#ifndef __DEBUG_H
#define __DEBUG_H

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <stdio.h>
#include <limits.h>

//#ifdef DEBUGBUILD
//#define DEBUGF(x) x
//#else
//#define DEBUGF(x) do { } while(0)
//#endif

#define DEBUGF(x) x

#if defined(DEBUGBUILD)
#define DEBUGASSERT(x) assert(x)
#else
#define DEBUGASSERT(x) do { } while(0)
#endif

void wintls_infof(struct wintls_easy*, const char* fmt, ...);
void wintls_failf(struct wintls_easy*, const char* fmt, ...);

#define infof wintls_infof
#define failf wintls_failf
/*
 * Macro used to include assertion code only in debug builds.
 */

#undef DEBUGASSERT
#if defined(DEBUGBUILD)
#define DEBUGASSERT(x) assert(x)
#else
#define DEBUGASSERT(x) do { } while(0)
#endif


 /*
  * Macro SOCKERRNO / SET_SOCKERRNO() returns / sets the *socket-related* errno
  * (or equivalent) on this platform to hide platform details to code using it.
  */

#define SOCKERRNO         ((int)WSAGetLastError())
#define SET_SOCKERRNO(x)  (WSASetLastError((int)(x)))

#undef  EBADF            /* override definition in errno.h */
#define EBADF            WSAEBADF
#undef  EINTR            /* override definition in errno.h */
#define EINTR            WSAEINTR
#undef  EINVAL           /* override definition in errno.h */
#define EINVAL           WSAEINVAL
#undef  EWOULDBLOCK      /* override definition in errno.h */
#define EWOULDBLOCK      WSAEWOULDBLOCK
#undef  EINPROGRESS      /* override definition in errno.h */
#define EINPROGRESS      WSAEINPROGRESS
#undef  EALREADY         /* override definition in errno.h */
#define EALREADY         WSAEALREADY
#undef  ENOTSOCK         /* override definition in errno.h */
#define ENOTSOCK         WSAENOTSOCK
#undef  EDESTADDRREQ     /* override definition in errno.h */
#define EDESTADDRREQ     WSAEDESTADDRREQ
#undef  EMSGSIZE         /* override definition in errno.h */
#define EMSGSIZE         WSAEMSGSIZE
#undef  EPROTOTYPE       /* override definition in errno.h */
#define EPROTOTYPE       WSAEPROTOTYPE
#undef  ENOPROTOOPT      /* override definition in errno.h */
#define ENOPROTOOPT      WSAENOPROTOOPT
#undef  EPROTONOSUPPORT  /* override definition in errno.h */
#define EPROTONOSUPPORT  WSAEPROTONOSUPPORT
#define ESOCKTNOSUPPORT  WSAESOCKTNOSUPPORT
#undef  EOPNOTSUPP       /* override definition in errno.h */
#define EOPNOTSUPP       WSAEOPNOTSUPP
#define EPFNOSUPPORT     WSAEPFNOSUPPORT
#undef  EAFNOSUPPORT     /* override definition in errno.h */
#define EAFNOSUPPORT     WSAEAFNOSUPPORT
#undef  EADDRINUSE       /* override definition in errno.h */
#define EADDRINUSE       WSAEADDRINUSE
#undef  EADDRNOTAVAIL    /* override definition in errno.h */
#define EADDRNOTAVAIL    WSAEADDRNOTAVAIL
#undef  ENETDOWN         /* override definition in errno.h */
#define ENETDOWN         WSAENETDOWN
#undef  ENETUNREACH      /* override definition in errno.h */
#define ENETUNREACH      WSAENETUNREACH
#undef  ENETRESET        /* override definition in errno.h */
#define ENETRESET        WSAENETRESET
#undef  ECONNABORTED     /* override definition in errno.h */
#define ECONNABORTED     WSAECONNABORTED
#undef  ECONNRESET       /* override definition in errno.h */
#define ECONNRESET       WSAECONNRESET
#undef  ENOBUFS          /* override definition in errno.h */
#define ENOBUFS          WSAENOBUFS
#undef  EISCONN          /* override definition in errno.h */
#define EISCONN          WSAEISCONN
#undef  ENOTCONN         /* override definition in errno.h */
#define ENOTCONN         WSAENOTCONN
#define ESHUTDOWN        WSAESHUTDOWN
#define ETOOMANYREFS     WSAETOOMANYREFS
#undef  ETIMEDOUT        /* override definition in errno.h */
#define ETIMEDOUT        WSAETIMEDOUT
#undef  ECONNREFUSED     /* override definition in errno.h */
#define ECONNREFUSED     WSAECONNREFUSED
#undef  ELOOP            /* override definition in errno.h */
#define ELOOP            WSAELOOP
#ifndef ENAMETOOLONG     /* possible previous definition in errno.h */
#define ENAMETOOLONG     WSAENAMETOOLONG
#endif
#define EHOSTDOWN        WSAEHOSTDOWN
#undef  EHOSTUNREACH     /* override definition in errno.h */
#define EHOSTUNREACH     WSAEHOSTUNREACH
#ifndef ENOTEMPTY        /* possible previous definition in errno.h */
#define ENOTEMPTY        WSAENOTEMPTY
#endif
#define EPROCLIM         WSAEPROCLIM
#define EUSERS           WSAEUSERS
#define EDQUOT           WSAEDQUOT
#define ESTALE           WSAESTALE
#define EREMOTE          WSAEREMOTE

#endif


/* ======================================================================
 * header: wintls_opts.h
 ====================================================================== */

#ifndef __WINTLS_OPTS_H
#define __WINTLS_OPTS_H
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
	STRING_NETRC_FILE,      /* if not NULL, use this instead of trying to find $HOME/.netrc */
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
	STRING_NOPROXY,         /* List of hosts which should not use the proxy, if used */
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
	STRING_TARGET,                /* WINTLSOPT_REQUEST_TARGET */
	STRING_DOH,                   /* WINTLSOPT_DOH_URL */
	STRING_ALTSVC,                /* WINTLSOPT_ALTSVC */
	STRING_HSTS,                  /* WINTLSOPT_HSTS */
	STRING_SASL_AUTHZID,          /* WINTLSOPT_SASL_AUTHZID */
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

#endif


/* ======================================================================
 * header: timeleft.h
 ====================================================================== */

#ifndef __TIMELEFT_H_
#define __TIMELEFT_H_
#include <time.h>
#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define timediff_t clock_t
/* generic function that returns how much time there's left to run, according
   to the timeouts set */
timediff_t wintls_timeleft(struct wintls* data,
    struct wintlstime* nowp,
    BOOL duringconnect);


struct wintlstime {
    time_t tv_sec; /* seconds */
    int tv_usec;   /* microseconds */
};

#define DEFAULT_CONNECT_TIMEOUT 300000 /* milliseconds == five minutes */

#define WINTLS_FORMAT_TIMEDIFF_T WINTLS_FORMAT_WINTLS_OFF_T

#define TIMEDIFF_T_MAX WINTLS_OFF_T_MAX
#define TIMEDIFF_T_MIN WINTLS_OFF_T_MIN

/*
 * Converts number of milliseconds into a timeval structure.
 *
 * Return values:
 *    NULL IF tv is NULL or ms < 0 (eg. no timeout -> blocking select)
 *    tv with 0 in both fields IF ms == 0 (eg. 0ms timeout -> polling select)
 *    tv with converted fields IF ms > 0 (eg. >0ms timeout -> waiting select)
 */
struct timeval* wintlsx_mstotv(struct timeval* tv, timediff_t ms);

/*
 * Converts a timeval structure into number of milliseconds.
 */
timediff_t wintlsx_tvtoms(struct timeval* tv);
struct wintlstime wintls_now(void);

/*
 * Make sure that the first argument (t1) is the more recent time and t2 is
 * the older time, as otherwise you get a weird negative time-diff back...
 *
 * Returns: the time difference in number of milliseconds.
 */
timediff_t wintls_timediff(struct wintlstime t1, struct wintlstime t2);

/*
 * Make sure that the first argument (t1) is the more recent time and t2 is
 * the older time, as otherwise you get a weird negative time-diff back...
 *
 * Returns: the time difference in number of microseconds.
 */
timediff_t wintls_timediff_us(struct wintlstime newer, struct wintlstime older);
#ifdef __cplusplus
}
#endif
#endif


/* ======================================================================
 * header: select.h
 ====================================================================== */

#ifndef __SELECT_H_
#define __SELECT_H_
#ifdef HAVE_POLL_H
#include <poll.h>
#elif defined(HAVE_SYS_POLL_H)
#include <sys/poll.h>
#endif
#include<ws2tcpip.h>

#define WINTLS_SOCKET_BAD INVALID_SOCKET

/*
 * Definition of pollfd struct and constants for platforms lacking them.
 */

#ifndef POLLIN
#define POLLIN      0x01
#define POLLPRI     0x02
#define POLLOUT     0x04
#define POLLERR     0x08
#define POLLHUP     0x10
#define POLLNVAL    0x20
#endif

#define WINTLS_POLL_NONE   0
#define WINTLS_POLL_IN     1
#define WINTLS_POLL_OUT    2
#define WINTLS_POLL_INOUT  3
#define WINTLS_POLL_REMOVE 4

#define WINTLS_SOCKET_TIMEOUT WINTLS_SOCKET_BAD

#define WINTLS_CSELECT_IN   0x01
#define WINTLS_CSELECT_OUT  0x02
#define WINTLS_CSELECT_ERR  0x04

#ifndef POLLRDNORM
#define POLLRDNORM POLLIN
#endif

#ifndef POLLWRNORM
#define POLLWRNORM POLLOUT
#endif

#ifndef POLLRDBAND
#define POLLRDBAND POLLPRI
#endif

/* there are three CSELECT defines that are defined in the public header that
   are exposed to users, but this *IN2 bit is only ever used internally and
   therefore defined here */
#define WINTLS_CSELECT_IN2 (WINTLS_CSELECT_ERR << 1)

int wintls_socket_check(struct wintls* tls,
    timediff_t timeout_ms);
#define SOCKET_READABLE(x,z) \
  wintls_socket_check(x, WINTLS_SOCKET_BAD, WINTLS_SOCKET_BAD, z)
#define SOCKET_WRITABLE(x,z) \
  wintls_socket_check(WINTLS_SOCKET_BAD, WINTLS_SOCKET_BAD, x, z)

int wintls_poll(struct pollfd ufds[], unsigned int nfds, timediff_t timeout_ms);
int wintls_wait_ms(timediff_t timeout_ms);

/*
   With Winsock the valid range is [0..INVALID_SOCKET-1] according to
   https://docs.microsoft.com/en-us/windows/win32/winsock/socket-data-type-2
*/
#define VALID_SOCK(s) ((s) < INVALID_SOCKET)
#define FDSET_SOCK(x) 1
#define VERIFY_SOCK(x) do { \
  if(!VALID_SOCK(x)) { \
    SET_SOCKERRNO(WSAEINVAL); \
    return -1; \
  } \
} while(0);

#endif


/* ======================================================================
 * header: wintls.h
 ====================================================================== */

#ifndef __WINTLS_H
#define __WINTLS_H

#ifdef __cplusplus
extern "C" {
#endif

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#undef SECURITY_WIN32
#undef SECURITY_KERNEL
#define SECURITY_WIN32 1
#include <schannel.h>
#include <sspi.h>
#include <WinSock2.h>
typedef enum {
	WINTLSINFO_TEXT = 0,
	WINTLSINFO_HEADER_IN,    /* 1 */
	WINTLSINFO_HEADER_OUT,   /* 2 */
	WINTLSINFO_DATA_IN,      /* 3 */
	WINTLSINFO_DATA_OUT,     /* 4 */
	WINTLSINFO_SSL_DATA_IN,  /* 5 */
	WINTLSINFO_SSL_DATA_OUT, /* 6 */
	WINTLSINFO_END
} wintls_infotype;

/* Different data locks for a single share */
typedef enum {
	WINTLS_LOCK_DATA_NONE = 0,
	/*  WINTLS_LOCK_DATA_SHARE is used internally to say that
	 *  the locking is just made to change the internal state of the share
	 *  itself.
	 */
	 WINTLS_LOCK_DATA_SHARE,
	 WINTLS_LOCK_DATA_COOKIE,
	 WINTLS_LOCK_DATA_DNS,
	 WINTLS_LOCK_DATA_SSL_SESSION,
	 WINTLS_LOCK_DATA_CONNECT,
	 WINTLS_LOCK_DATA_PSL,
	 WINTLS_LOCK_DATA_HSTS,
	 WINTLS_LOCK_DATA_LAST
} wintls_lock_data;

/* Different lock access types */
typedef enum {
	WINTLS_LOCK_ACCESS_NONE = 0,   /* unspecified action */
	WINTLS_LOCK_ACCESS_SHARED = 1, /* for read perhaps */
	WINTLS_LOCK_ACCESS_SINGLE = 2, /* for write perhaps */
	WINTLS_LOCK_ACCESS_LAST        /* never use */
} wintls_lock_access;

BOOL blobcmp(struct wintls_blob* first, struct wintls_blob* second);

typedef void (*wintls_lock_function)(struct wintls* handle,
	wintls_lock_data data,
	wintls_lock_access locktype,
	void* userptr);

typedef void (*wintls_unlock_function)(struct wintls* handle,
	wintls_lock_data data,
	void* userptr);


typedef void*(malloc_func)(int size);
typedef void (free_func)(void* p);
typedef void*(memmove_func)(void* dest, const void* src, size_t count);
typedef void* (realloc_func)(void* dest, size_t oldCount, size_t count);
typedef void* (memcpy_func)(void* dest, const void* src, size_t count);
struct wintls_blob {
	void* data;
	size_t len;
	unsigned int flags; /* bit 0 is defined, the rest are reserved and should be
						   left zeroes */
};
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


#define WINTLS_GOOD_SHARE 0x7e117a1e
#define GOOD_SHARE_HANDLE(x) ((x) && (x)->magic == WINTLS_GOOD_SHARE)

/* information stored about one single SSL session */
struct wintls_ssl_session {
	char* name;       /* host name for which this ID was used */
	char* conn_to_host; /* host name for the connection (may be NULL) */
	const char* scheme; /* protocol scheme used */
	void* sessionid;  /* as returned from the SSL layer */
	size_t idsize;    /* if known, otherwise 0 */
	long age;         /* just a number, the higher the more recent */
	int remote_port;  /* remote port */
	int conn_to_port; /* remote port for the connection (may be -1) */
};

/* info about the certificate chain, only for OpenSSL, GnuTLS, Schannel, NSS
   and GSKit builds. Asked for with WINTLSOPT_CERTINFO / WINTLSINFO_CERTINFO */
struct wintls_certinfo {
	int num_of_certs;             /* number of certificates with information */
	struct wintls_slist** certinfo; /* for each index in this array, there's a
									 linked list with textual information in the
									 format "name: value" */
};

typedef ssize_t wintls_cft_send(struct wintls* tls,
	const void* buf,        /* data to write */
	size_t len,             /* amount to write */
	wintls_code* err);         /* error to return */
typedef ssize_t wintls_cft_recv(struct wintls* tls,
	char* buf,              /* store data here */
	size_t len,             /* amount to read */
	wintls_code* err);         /* error to return */

struct wintls_share
{
	unsigned int magic; /* WINTLS_GOOD_SHARE */
	char uuid[32];
	unsigned int specifier;
	wintls_lock_function lockfunc;
	wintls_unlock_function unlockfunc;
	void* clientdata;
	struct wintls* session; /* array of 'max_ssl_sessions' size */
	size_t max_ssl_sessions;
	long sessionage;
};

struct wintls
{
	char* CApath;          /* certificate dir (doesn't work on windows) */
	char* CAfile;          /* certificate to verify peer against */
	char* issuercert;      /* optional issuer certificate filename */
	char* clientcert;
	char* cipher_list;     /* list of ciphers to use */
	char* cipher_list13;   /* list of TLS 1.3 cipher suites to use */
	char* pinned_key;
	char* CRLfile;         /* CRL to check certificate revocation */
	struct wintls_blob* cert_blob;
	struct wintls_blob* ca_info_blob;
	struct wintls_blob* issuercert_blob;
#ifdef USE_TLS_SRP
	char* username; /* TLS username (for, e.g., SRP) */
	char* password; /* TLS password (for, e.g., SRP) */
#endif
	char* curves;          /* list of curves to use */
	unsigned char ssl_options;  /* the WINTLSOPT_SSL_OPTIONS bitmask */
	unsigned int version_max; /* max supported version the client wants to use */
	unsigned char version;    /* what version the client wants to use */
	BOOL verifypeer;       /* set TRUE if this is desired */
	BOOL verifyhost;       /* set TRUE if CN/SAN must match hostname */
	BOOL verifystatus;     /* set TRUE if certificate status must be checked */
	BOOL cachesessionid;        /* cache session IDs or not */

	SecPkgContext_StreamSizes stream_sizes;
	size_t encdata_length, decdata_length;
	size_t encdata_offset, decdata_offset;
	unsigned char* encdata_buffer, *decdata_buffer;
	/* encdata_is_incomplete: if encdata contains only a partial record that
	   can't be decrypted without another recv() (that is, status is
	   SEC_E_INCOMPLETE_MESSAGE) then set this true. after an recv() adds
	   more bytes into encdata then set this back to false. */
	BOOL encdata_is_incomplete;
	unsigned long req_flags, ret_flags;
	wintls_code recv_unrecoverable_err; /* schannel_recv had an unrecoverable err */
	BOOL recv_sspi_close_notify; /* true if connection closed by close_notify */
	BOOL recv_connection_closed; /* true if connection closed, regardless how */
	BOOL recv_renegotiating;     /* true if recv is doing renegotiation */
	BOOL use_alpn; /* true if ALPN is used for this connection */
	BOOL use_manual_cred_validation; /* true if manual cred validation is used */

	long certverifyresult; /* result from the certificate verification */
	char* cert_type; /* format for certificate (default: PEM)*/
	char* key; /* private key file name */
	struct wintls_blob* key_blob;
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

	ssl_connection_state state;
	ssl_connect_state connecting_state;
	char* hostname;                   /* hostname for verification */
	char* dispname;                   /* display version of hostname */
	const struct alpn_spec* alpn;     /* ALPN to use or NULL for none */
	struct wintlstime handshake_done;   /* time when handshake finished */
	int port;                         /* remote port at origin */
	struct wintls_share* share;

	char* name;       /* host name for which this ID was used */
	char* conn_to_host; /* host name for the connection (may be NULL) */
	const char* scheme; /* protocol scheme used */
	void* sessionid;  /* as returned from the SSL layer */
	size_t idsize;    /* if known, otherwise 0 */
	long age;         /* just a number, the higher the more recent */
	int remote_port;  /* remote port */
	int conn_to_port; /* remote port for the connection (may be -1) */
	char* buffer;
	size_t buffer_size;

	wintls_cft_send* do_send;                 /* send data */
	wintls_cft_recv* do_recv;                 /* receive data */
	malloc_func* do_malloc;
	free_func* do_free;
	memmove_func* do_memmove;
	realloc_func* do_realloc;
	memcpy_func* do_memcpy;

	char* pinnedPubKey;
	unsigned int timeout;        /* ms, 0 means no timeout */
	unsigned int connecttimeout; /* ms, 0 means no timeout */
	struct wintlstime t_startsingle;
	struct wintlstime t_startop;

	struct wintls_certinfo certs; /* info about the certs, only populated in
								   OpenSSL, GnuTLS, Schannel, NSS and GSKit
								   builds. Asked for with WINTLSOPT_CERTINFO
								   / WINTLSINFO_CERTINFO */

	char* str[STRING_LAST]; /* array of strings, pointing to allocated memory */
	struct wintls_blob* blobs[BLOB_LAST];
	SOCKET socket;

	BOOL cred_setup;
	CredHandle cred_handle;
	TimeStamp time_stamp;
	TCHAR* sni_hostname;
	HCERTSTORE client_cert_store;
	int refcount;

	BOOL ctxt_setup;
	CtxtHandle ctxt_handle;
	TimeStamp ctxt_time_stamp;
};
#ifdef __cplusplus
}
#endif

#endif


/* ======================================================================
 * header: alpn.h
 ====================================================================== */

#ifndef __ALPN_H_
#define __ALPN_H_


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

wintls_code wintls_alpn_to_proto_buf(struct alpn_proto_buf* buf,
    const struct alpn_spec* spec);
wintls_code wintls_alpn_to_proto_str(struct alpn_proto_buf* buf,
    const struct alpn_spec* spec);

wintls_code wintls_alpn_set_negotiated(struct wintls* tls,
    const unsigned char* proto,
    size_t proto_len);

#endif


/* ======================================================================
 * header: version_win32.h
 ====================================================================== */

#ifndef HEADER_WINTLS_VERSION_WIN32_H
#define HEADER_WINTLS_VERSION_WIN32_H

#define WINTLSX_FUNCTION_CAST(target_type, func) \
  (target_type)(void (*) (void))(func)

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
/* Version condition */
typedef enum {
    VERSION_LESS_THAN,
    VERSION_LESS_THAN_EQUAL,
    VERSION_EQUAL,
    VERSION_GREATER_THAN_EQUAL,
    VERSION_GREATER_THAN
} VersionCondition;

/* Platform identifier */
typedef enum {
    PLATFORM_DONT_CARE,
    PLATFORM_WINDOWS,
    PLATFORM_WINNT
} PlatformIdentifier;

/* This is used to verify if we are running on a specific windows version */
BOOL wintlsx_verify_windows_version(const unsigned int majorVersion,
    const unsigned int minorVersion,
    const unsigned int buildVersion,
    const PlatformIdentifier platform,
    const VersionCondition condition);

#endif /* HEADER_WINTLS_VERSION_WIN32_H */



/* ======================================================================
 * header: strcase.h
 ====================================================================== */

#ifndef HEADER_WINTLS_STRCASE_H
#define HEADER_WINTLS_STRCASE_H

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>


 /*
  * Only "raw" case insensitive strings. This is meant to be locale independent
  * and only compare strings we know are safe for this.
  *
  * The function is capable of comparing a-z case insensitively.
  *
  * Result is 1 if text matches and 0 if not.
  */

#define strcasecompare(a,b) wintls_strequal(a,b)
#define strncasecompare(a,b,c) wintls_strnequal(a,b,c)

char wintls_raw_toupper(char in);
char wintls_raw_tolower(char in);

/* checkprefix() is a shorter version of the above, used when the first
   argument is the string literal */
#define checkprefix(a,b)    wintls_strnequal(b, STRCONST(a))

void wintls_strntoupper(char* dest, const char* src, size_t n);
void wintls_strntolower(char* dest, const char* src, size_t n);

BOOL wintls_safecmp(char* a, char* b);
int wintls_timestrcmp(const char* first, const char* second);

#endif /* HEADER_WINTLS_STRCASE_H */



/* ======================================================================
 * header: wintls_multibyte.h
 ====================================================================== */

#ifndef HEADER_WINTLS_MULTIBYTE_H
#define HEADER_WINTLS_MULTIBYTE_H

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>

#if defined(WIN32)

 /*
  * MultiByte conversions using Windows kernel32 library.
  */

wchar_t* wintlsx_convert_UTF8_to_wchar(const char* str_utf8);
char* wintlsx_convert_wchar_to_UTF8(const wchar_t* str_w);
#endif /* WIN32 */

/*
 * Macros wintlsx_convert_UTF8_to_tchar(), wintlsx_convert_tchar_to_UTF8()
 * and wintlsx_unicodefree() main purpose is to minimize the number of
 * preprocessor conditional directives needed by code using these
 * to differentiate UNICODE from non-UNICODE builds.
 *
 * In the case of a non-UNICODE build the tchar strings are char strings that
 * are duplicated via strdup and remain in whatever the passed in encoding is,
 * which is assumed to be UTF-8 but may be other encoding. Therefore the
 * significance of the conversion functions is primarily for UNICODE builds.
 *
 * Allocated memory should be free'd with wintlsx_unicodefree().
 *
 * Note: Because these are wintlsx functions their memory usage is not tracked
 * by the wintls memory tracker memdebug. You'll notice that wintlsx function-like
 * macros call free and strdup in parentheses, eg (strdup)(ptr), and that's to
 * ensure that the wintls memdebug override macros do not replace them.
 */

#if defined(UNICODE) && defined(WIN32)

#define wintlsx_convert_UTF8_to_tchar(ptr) wintlsx_convert_UTF8_to_wchar((ptr))
#define wintlsx_convert_tchar_to_UTF8(ptr) wintlsx_convert_wchar_to_UTF8((ptr))

typedef union {
    unsigned short* tchar_ptr;
    const unsigned short* const_tchar_ptr;
    unsigned short* tbyte_ptr;
    const unsigned short* const_tbyte_ptr;
} xcharp_u;

#else

#define wintlsx_convert_UTF8_to_tchar(ptr) (strdup)(ptr)
#define wintlsx_convert_tchar_to_UTF8(ptr) (strdup)(ptr)

typedef union {
    char* tchar_ptr;
    const char* const_tchar_ptr;
    unsigned char* tbyte_ptr;
    const unsigned char* const_tbyte_ptr;
} xcharp_u;

#endif /* UNICODE && WIN32 */

#define wintlsx_unicodefree(ptr)                          \
  do {                                                  \
    if(ptr) {                                           \
      free(ptr);                                      \
      (ptr) = NULL;                                     \
    }                                                   \
  } while(0)

#endif /* HEADER_WINTLS_MULTIBYTE_H */



/* ======================================================================
 * header: dynbuf.h
 ====================================================================== */

#ifndef HEADER_WINTLS_DYNBUF_H
#define HEADER_WINTLS_DYNBUF_H

#ifndef BUILDING_LIBWINTLS
 /* this renames the functions so that the tool code can use the same code
	without getting symbol collisions */
#define wintls_dyn_init(a,b) wintlsx_dyn_init(a,b)
#define wintls_dyn_add(a,b) wintlsx_dyn_add(a,b)
#define wintls_dyn_addn(a,b,c) wintlsx_dyn_addn(a,b,c)
#define wintls_dyn_addf wintlsx_dyn_addf
#define wintls_dyn_vaddf wintlsx_dyn_vaddf
#define wintls_dyn_free(a) wintlsx_dyn_free(a)
#define wintls_dyn_ptr(a) wintlsx_dyn_ptr(a)
#define wintls_dyn_uptr(a) wintlsx_dyn_uptr(a)
#define wintls_dyn_len(a) wintlsx_dyn_len(a)
#define wintls_dyn_reset(a) wintlsx_dyn_reset(a)
#define wintls_dyn_tail(a,b) wintlsx_dyn_tail(a,b)
#define wintls_dyn_setlen(a,b) wintlsx_dyn_setlen(a,b)
#define wintlsx_dynbuf dynbuf /* for the struct name */
#endif

struct dynbuf {
	char* bufr;    /* point to a null-terminated allocated buffer */
	size_t leng;   /* number of bytes *EXCLUDING* the null-terminator */
	size_t allc;   /* size of the current allocation */
	size_t toobig; /* size limit for the buffer */
#ifdef DEBUGBUILD
	int init;     /* detect API usage mistakes */
#endif
};

void wintls_dyn_init(struct dynbuf* s, size_t toobig);
void wintls_dyn_free(struct dynbuf* s);
wintls_code wintls_dyn_addn(struct dynbuf* s, const void* mem, size_t len);
wintls_code wintls_dyn_add(struct dynbuf* s, const char* str);
wintls_code wintls_dyn_addf(struct dynbuf* s, const char* fmt, ...);
wintls_code wintls_dyn_vaddf(struct dynbuf* s, const char* fmt, va_list ap);
void wintls_dyn_reset(struct dynbuf* s);
wintls_code wintls_dyn_tail(struct dynbuf* s, size_t trail);
wintls_code wintls_dyn_setlen(struct dynbuf* s, size_t set);
char* wintls_dyn_ptr(const struct dynbuf* s);
unsigned char* wintls_dyn_uptr(const struct dynbuf* s);
size_t wintls_dyn_len(const struct dynbuf* s);

/* returns 0 on success, -1 on error */
/* The implementation of this function exists in mprintf.c */
int wintls_dyn_vprintf(struct dynbuf* dyn, const char* format, va_list ap_save);

/* Dynamic buffer max sizes */
#define DYN_DOH_RESPONSE    3000
#define DYN_DOH_CNAME       256
#define DYN_PAUSE_BUFFER    (64 * 1024 * 1024)
#define DYN_HAXPROXY        2048
#define DYN_HTTP_REQUEST    (1024*1024)
#define DYN_H2_HEADERS      (128*1024)
#define DYN_H2_TRAILERS     (128*1024)
#define DYN_APRINTF         8000000
#define DYN_RTSP_REQ_HEADER (64*1024)
#define DYN_TRAILERS        (64*1024)
#define DYN_PROXY_CONNECT_HEADERS 16384
#define DYN_QLOG_NAME       1024
#define DYN_H1_TRAILER      4096
#define DYN_PINGPPONG_CMD   (64*1024)
#define DYN_IMAP_CMD        (64*1024)
#endif


/* ======================================================================
 * header: wintls_printf.h
 ====================================================================== */

#ifndef HEADER_WINTLS_WINTLSX_H
#define HEADER_WINTLS_WINTLSX_H


 /*
  * Defines protos and includes all header files that provide the wintlsx_*
  * functions. The wintlsx_* functions are not part of the libwintls API, but are
  * stand-alone functions whose sources can be built and linked by apps if need
  * be.
  */



#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <stdio.h>
#include <limits.h>


	 /* "strcase.h" provides the strcasecompare protos */

//#include "strtoofft.h"
/* "strtoofft.h" provides this function: wintlsx_strtoofft(), returns a
   wintls_off_t number from a given string.
*/

//#include "nonblock.h"
/* "nonblock.h" provides wintlsx_nonblock() */

//#include "warnless.h"
/* "warnless.h" provides functions:

  wintlsx_ultous()
  wintlsx_ultouc()
  wintlsx_uztosi()
*/

/* "wintls_multibyte.h" provides these functions and macros:

  wintlsx_convert_UTF8_to_wchar()
  wintlsx_convert_wchar_to_UTF8()
  wintlsx_convert_UTF8_to_tchar()
  wintlsx_convert_tchar_to_UTF8()
  wintlsx_unicodefree()
*/

/* "version_win32.h" provides wintlsx_verify_windows_version() */

/* Now setup wintlsx_ * names for the functions that are to become wintlsx_ and
   be removed from a future libwintls official API:
   wintlsx_getenv
   wintlsx_mprintf (and its variations)
   wintlsx_strcasecompare
   wintlsx_strncasecompare

*/
int wintls_mprintf(const char* format, ...);
int wintls_mfprintf(FILE* fd, const char* format, ...);
int wintls_msprintf(char* buffer, const char* format, ...);
int wintls_msnprintf(char* buffer, size_t maxlength,
    const char* format, ...);
int wintls_mvprintf(const char* format, va_list args);
int wintls_mvfprintf(FILE* fd, const char* format, va_list args);
int wintls_mvsprintf(char* buffer, const char* format, va_list args);
int wintls_mvsnprintf(char* buffer, size_t maxlength,
    const char* format, va_list args);
char* wintls_maprintf(const char* format, ...);
char* wintls_mvaprintf(const char* format, va_list args);

#define wintlsx_getenv wintls_getenv
#define wintlsx_mvsnprintf wintls_mvsnprintf
#define wintlsx_msnprintf wintls_msnprintf
#define wintlsx_maprintf wintls_maprintf
#define wintlsx_mvaprintf wintls_mvaprintf
#define wintlsx_msprintf wintls_msprintf
#define wintlsx_mprintf wintls_mprintf
#define wintlsx_mfprintf wintls_mfprintf
#define wintlsx_mvsprintf wintls_mvsprintf
#define wintlsx_mvprintf wintls_mvprintf
#define wintlsx_mvfprintf wintls_mvfprintf

#ifdef ENABLE_WINTLSX_PRINTF
/* If this define is set, we define all "standard" printf() functions to use
   the wintlsx_* version instead. It makes the source code transparent and
   easier to understand/patch. Undefine them first. */
# undef printf
# undef fprintf
# undef sprintf
# undef msnprintf
# undef vprintf
# undef vfprintf
# undef vsprintf
# undef mvsnprintf
# undef aprintf
# undef vaprintf

# define printf wintlsx_mprintf
# define fprintf wintlsx_mfprintf
# define sprintf wintlsx_msprintf
# define msnprintf wintlsx_msnprintf
# define vprintf wintlsx_mvprintf
# define vfprintf wintlsx_mvfprintf
# define mvsnprintf wintlsx_mvsnprintf
# define aprintf wintlsx_maprintf
# define vaprintf wintlsx_mvaprintf
#endif /* ENABLE_WINTLSX_PRINTF */
# define vaprintf wintlsx_mvaprintf
# define msnprintf wintlsx_msnprintf
# define mvsnprintf wintlsx_mvsnprintf

#endif /* HEADER_WINTLS_WINTLSX_H */



/* ======================================================================
 * header: system_win32.h
 ====================================================================== */

#ifndef HEADER_WINTLS_SYSTEM_WIN32_H
#define HEADER_WINTLS_SYSTEM_WIN32_H

#ifdef __cplusplus
extern "C" {
#endif

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <WinSock2.h>
extern LARGE_INTEGER wintls_freq;
extern BOOL wintls_isVistaOrGreater;

extern wintls_code wintls_win32_init(long flags);
void wintls_win32_cleanup(long init_flags);

/* We use our own typedef here since some headers might lack this */
typedef unsigned int(WINAPI* IF_NAMETOINDEX_FN)(const char*);

/* This is used instead of if_nametoindex if available on Windows */
extern IF_NAMETOINDEX_FN wintls_if_nametoindex;

/* This is used to dynamically load DLLs */
HMODULE wintls_load_library(LPCTSTR filename);



#define WINTLS_GLOBAL_SSL (1<<0) /* no purpose since 7.57.0 */
#define WINTLS_GLOBAL_WIN32 (1<<1)
#define WINTLS_GLOBAL_ALL (WINTLS_GLOBAL_SSL|WINTLS_GLOBAL_WIN32)
#define WINTLS_GLOBAL_NOTHING 0
#define WINTLS_GLOBAL_DEFAULT WINTLS_GLOBAL_ALL
#define WINTLS_GLOBAL_ACK_EINTR (1<<2)

#ifdef __cplusplus
}
#endif
#endif /* HEADER_WINTLS_SYSTEM_WIN32_H */



/* ======================================================================
 * header: strerror.h
 ====================================================================== */

#ifndef HEADER_WINTLS_STRERROR_H
#define HEADER_WINTLS_STRERROR_H


#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>

#define STRERROR_LEN 256 /* a suitable length */

const char* wintls_strerror(int err, char* buf, size_t buflen);
#if defined(WIN32) || defined(_WIN32_WCE)
const char* wintls_winapi_strerror(DWORD err, char* buf, size_t buflen);
#endif
const char* wintls_sspi_strerror(int err, char* buf, size_t buflen);

#endif /* HEADER_WINTLS_STRERROR_H */



/* ======================================================================
 * header: memrchr.h
 ====================================================================== */

#ifndef HEADER_WINTLS_MEMRCHR_H
#define HEADER_WINTLS_MEMRCHR_H


#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>


void* wintls_memrchr(const void* s, int c, SIZE_T n);

#define memrchr(x,y,z) wintls_memrchr((x),(y),(z))


#endif /* HEADER_WINTLS_MEMRCHR_H */



/* ======================================================================
 * header: slist.h
 ====================================================================== */

#ifndef HEADER_WINTLS_SLIST_H
#define HEADER_WINTLS_SLIST_H

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
/* linked-list structure for the WINTLSOPT_QUOTE option (and other) */
struct wintls_slist {
    char* data;
    struct wintls_slist* next;
};

 /*
  * wintls_slist_duplicate() duplicates a linked list. It always returns the
  * address of the first record of the cloned list or NULL in case of an
  * error (or if the input list was NULL).
  */
struct wintls_slist* wintls_slist_duplicate(struct wintls_slist* inlist);

/*
 * wintls_slist_append_nodup() takes ownership of the given string and appends
 * it to the list.
 */
struct wintls_slist* wintls_slist_append_nodup(struct wintls_slist* list,
    char* data);

void wintls_slist_free_all(struct wintls_slist* list);
#endif /* HEADER_WINTLS_SLIST_H */



/* ======================================================================
 * header: base64.h
 ====================================================================== */

#ifndef HEADER_WINTLS_BASE64_H
#define HEADER_WINTLS_BASE64_H

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>



wintls_code wintls_base64_encode(const char* inputbuff, size_t insize,
    char** outptr, size_t* outlen);
wintls_code wintls_base64url_encode(const char* inputbuff, size_t insize,
    char** outptr, size_t* outlen);
wintls_code wintls_base64_decode(const char* src,
    unsigned char** outptr, size_t* outlen);

#endif /* HEADER_WINTLS_BASE64_H */



/* ======================================================================
 * header: hostcheck.h
 ====================================================================== */

#ifndef HEADER_WINTLS_HOSTCHECK_H
#define HEADER_WINTLS_HOSTCHECK_H



#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <ws2tcpip.h>

 /* returns TRUE if there's a match */
BOOL wintls_cert_hostcheck(const char* match_pattern, size_t matchlen,
    const char* hostname, size_t hostlen);

#endif /* HEADER_WINTLS_HOSTCHECK_H */



/* ======================================================================
 * header: wintls_sspi.h
 ====================================================================== */

#ifndef HEADER_WINTLS_SSPI_H
#define HEADER_WINTLS_SSPI_H


 /*
  * When including the following three headers, it is mandatory to define either
  * SECURITY_WIN32 or SECURITY_KERNEL, indicating who is compiling the code.
  */

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#undef SECURITY_WIN32
#undef SECURITY_KERNEL
#define SECURITY_WIN32 1
#include <security.h>
#include <sspi.h>
#include <rpc.h>

wintls_code wintls_sspi_global_init(void);
void wintls_sspi_global_cleanup(void);

/* This is used to populate the domain in a SSPI identity structure */
wintls_code wintls_override_sspi_http_realm(const char* chlg,
    SEC_WINNT_AUTH_IDENTITY* identity);

/* This is used to generate an SSPI identity structure */
wintls_code wintls_create_sspi_identity(const char* userp, const char* passwdp,
    SEC_WINNT_AUTH_IDENTITY* identity);

/* This is used to free an SSPI identity structure */
void wintls_sspi_free_identity(SEC_WINNT_AUTH_IDENTITY* identity);

unsigned long wintlsx_uztoul(size_t uznum);

/* Forward-declaration of global variables defined in wintls_sspi.c */
extern HMODULE s_hSecDll;
extern PSecurityFunctionTable s_pSecFn;

/* Provide some definitions missing in old headers */
#define SP_NAME_DIGEST              "WDigest"
#define SP_NAME_NTLM                "NTLM"
#define SP_NAME_NEGOTIATE           "Negotiate"
#define SP_NAME_KERBEROS            "Kerberos"

#ifndef ISC_REQ_USE_HTTP_STYLE
#define ISC_REQ_USE_HTTP_STYLE                0x01000000
#endif

#ifndef ISC_RET_REPLAY_DETECT
#define ISC_RET_REPLAY_DETECT                 0x00000004
#endif

#ifndef ISC_RET_SEQUENCE_DETECT
#define ISC_RET_SEQUENCE_DETECT               0x00000008
#endif

#ifndef ISC_RET_CONFIDENTIALITY
#define ISC_RET_CONFIDENTIALITY               0x00000010
#endif

#ifndef ISC_RET_ALLOCATED_MEMORY
#define ISC_RET_ALLOCATED_MEMORY              0x00000100
#endif

#ifndef ISC_RET_STREAM
#define ISC_RET_STREAM                        0x00008000
#endif

#ifndef SEC_E_INSUFFICIENT_MEMORY
# define SEC_E_INSUFFICIENT_MEMORY            ((HRESULT)0x80090300L)
#endif
#ifndef SEC_E_INVALID_HANDLE
# define SEC_E_INVALID_HANDLE                 ((HRESULT)0x80090301L)
#endif
#ifndef SEC_E_UNSUPPORTED_FUNCTION
# define SEC_E_UNSUPPORTED_FUNCTION           ((HRESULT)0x80090302L)
#endif
#ifndef SEC_E_TARGET_UNKNOWN
# define SEC_E_TARGET_UNKNOWN                 ((HRESULT)0x80090303L)
#endif
#ifndef SEC_E_INTERNAL_ERROR
# define SEC_E_INTERNAL_ERROR                 ((HRESULT)0x80090304L)
#endif
#ifndef SEC_E_SECPKG_NOT_FOUND
# define SEC_E_SECPKG_NOT_FOUND               ((HRESULT)0x80090305L)
#endif
#ifndef SEC_E_NOT_OWNER
# define SEC_E_NOT_OWNER                      ((HRESULT)0x80090306L)
#endif
#ifndef SEC_E_CANNOT_INSTALL
# define SEC_E_CANNOT_INSTALL                 ((HRESULT)0x80090307L)
#endif
#ifndef SEC_E_INVALID_TOKEN
# define SEC_E_INVALID_TOKEN                  ((HRESULT)0x80090308L)
#endif
#ifndef SEC_E_CANNOT_PACK
# define SEC_E_CANNOT_PACK                    ((HRESULT)0x80090309L)
#endif
#ifndef SEC_E_QOP_NOT_SUPPORTED
# define SEC_E_QOP_NOT_SUPPORTED              ((HRESULT)0x8009030AL)
#endif
#ifndef SEC_E_NO_IMPERSONATION
# define SEC_E_NO_IMPERSONATION               ((HRESULT)0x8009030BL)
#endif
#ifndef SEC_E_LOGON_DENIED
# define SEC_E_LOGON_DENIED                   ((HRESULT)0x8009030CL)
#endif
#ifndef SEC_E_UNKNOWN_CREDENTIALS
# define SEC_E_UNKNOWN_CREDENTIALS            ((HRESULT)0x8009030DL)
#endif
#ifndef SEC_E_NO_CREDENTIALS
# define SEC_E_NO_CREDENTIALS                 ((HRESULT)0x8009030EL)
#endif
#ifndef SEC_E_MESSAGE_ALTERED
# define SEC_E_MESSAGE_ALTERED                ((HRESULT)0x8009030FL)
#endif
#ifndef SEC_E_OUT_OF_SEQUENCE
# define SEC_E_OUT_OF_SEQUENCE                ((HRESULT)0x80090310L)
#endif
#ifndef SEC_E_NO_AUTHENTICATING_AUTHORITY
# define SEC_E_NO_AUTHENTICATING_AUTHORITY    ((HRESULT)0x80090311L)
#endif
#ifndef SEC_E_BAD_PKGID
# define SEC_E_BAD_PKGID                      ((HRESULT)0x80090316L)
#endif
#ifndef SEC_E_CONTEXT_EXPIRED
# define SEC_E_CONTEXT_EXPIRED                ((HRESULT)0x80090317L)
#endif
#ifndef SEC_E_INCOMPLETE_MESSAGE
# define SEC_E_INCOMPLETE_MESSAGE             ((HRESULT)0x80090318L)
#endif
#ifndef SEC_E_INCOMPLETE_CREDENTIALS
# define SEC_E_INCOMPLETE_CREDENTIALS         ((HRESULT)0x80090320L)
#endif
#ifndef SEC_E_BUFFER_TOO_SMALL
# define SEC_E_BUFFER_TOO_SMALL               ((HRESULT)0x80090321L)
#endif
#ifndef SEC_E_WRONG_PRINCIPAL
# define SEC_E_WRONG_PRINCIPAL                ((HRESULT)0x80090322L)
#endif
#ifndef SEC_E_TIME_SKEW
# define SEC_E_TIME_SKEW                      ((HRESULT)0x80090324L)
#endif
#ifndef SEC_E_UNTRUSTED_ROOT
# define SEC_E_UNTRUSTED_ROOT                 ((HRESULT)0x80090325L)
#endif
#ifndef SEC_E_ILLEGAL_MESSAGE
# define SEC_E_ILLEGAL_MESSAGE                ((HRESULT)0x80090326L)
#endif
#ifndef SEC_E_CERT_UNKNOWN
# define SEC_E_CERT_UNKNOWN                   ((HRESULT)0x80090327L)
#endif
#ifndef SEC_E_CERT_EXPIRED
# define SEC_E_CERT_EXPIRED                   ((HRESULT)0x80090328L)
#endif
#ifndef SEC_E_ENCRYPT_FAILURE
# define SEC_E_ENCRYPT_FAILURE                ((HRESULT)0x80090329L)
#endif
#ifndef SEC_E_DECRYPT_FAILURE
# define SEC_E_DECRYPT_FAILURE                ((HRESULT)0x80090330L)
#endif
#ifndef SEC_E_ALGORITHM_MISMATCH
# define SEC_E_ALGORITHM_MISMATCH             ((HRESULT)0x80090331L)
#endif
#ifndef SEC_E_SECURITY_QOS_FAILED
# define SEC_E_SECURITY_QOS_FAILED            ((HRESULT)0x80090332L)
#endif
#ifndef SEC_E_UNFINISHED_CONTEXT_DELETED
# define SEC_E_UNFINISHED_CONTEXT_DELETED     ((HRESULT)0x80090333L)
#endif
#ifndef SEC_E_NO_TGT_REPLY
# define SEC_E_NO_TGT_REPLY                   ((HRESULT)0x80090334L)
#endif
#ifndef SEC_E_NO_IP_ADDRESSES
# define SEC_E_NO_IP_ADDRESSES                ((HRESULT)0x80090335L)
#endif
#ifndef SEC_E_WRONG_CREDENTIAL_HANDLE
# define SEC_E_WRONG_CREDENTIAL_HANDLE        ((HRESULT)0x80090336L)
#endif
#ifndef SEC_E_CRYPTO_SYSTEM_INVALID
# define SEC_E_CRYPTO_SYSTEM_INVALID          ((HRESULT)0x80090337L)
#endif
#ifndef SEC_E_MAX_REFERRALS_EXCEEDED
# define SEC_E_MAX_REFERRALS_EXCEEDED         ((HRESULT)0x80090338L)
#endif
#ifndef SEC_E_MUST_BE_KDC
# define SEC_E_MUST_BE_KDC                    ((HRESULT)0x80090339L)
#endif
#ifndef SEC_E_STRONG_CRYPTO_NOT_SUPPORTED
# define SEC_E_STRONG_CRYPTO_NOT_SUPPORTED    ((HRESULT)0x8009033AL)
#endif
#ifndef SEC_E_TOO_MANY_PRINCIPALS
# define SEC_E_TOO_MANY_PRINCIPALS            ((HRESULT)0x8009033BL)
#endif
#ifndef SEC_E_NO_PA_DATA
# define SEC_E_NO_PA_DATA                     ((HRESULT)0x8009033CL)
#endif
#ifndef SEC_E_PKINIT_NAME_MISMATCH
# define SEC_E_PKINIT_NAME_MISMATCH           ((HRESULT)0x8009033DL)
#endif
#ifndef SEC_E_SMARTCARD_LOGON_REQUIRED
# define SEC_E_SMARTCARD_LOGON_REQUIRED       ((HRESULT)0x8009033EL)
#endif
#ifndef SEC_E_SHUTDOWN_IN_PROGRESS
# define SEC_E_SHUTDOWN_IN_PROGRESS           ((HRESULT)0x8009033FL)
#endif
#ifndef SEC_E_KDC_INVALID_REQUEST
# define SEC_E_KDC_INVALID_REQUEST            ((HRESULT)0x80090340L)
#endif
#ifndef SEC_E_KDC_UNABLE_TO_REFER
# define SEC_E_KDC_UNABLE_TO_REFER            ((HRESULT)0x80090341L)
#endif
#ifndef SEC_E_KDC_UNKNOWN_ETYPE
# define SEC_E_KDC_UNKNOWN_ETYPE              ((HRESULT)0x80090342L)
#endif
#ifndef SEC_E_UNSUPPORTED_PREAUTH
# define SEC_E_UNSUPPORTED_PREAUTH            ((HRESULT)0x80090343L)
#endif
#ifndef SEC_E_DELEGATION_REQUIRED
# define SEC_E_DELEGATION_REQUIRED            ((HRESULT)0x80090345L)
#endif
#ifndef SEC_E_BAD_BINDINGS
# define SEC_E_BAD_BINDINGS                   ((HRESULT)0x80090346L)
#endif
#ifndef SEC_E_MULTIPLE_ACCOUNTS
# define SEC_E_MULTIPLE_ACCOUNTS              ((HRESULT)0x80090347L)
#endif
#ifndef SEC_E_NO_KERB_KEY
# define SEC_E_NO_KERB_KEY                    ((HRESULT)0x80090348L)
#endif
#ifndef SEC_E_CERT_WRONG_USAGE
# define SEC_E_CERT_WRONG_USAGE               ((HRESULT)0x80090349L)
#endif
#ifndef SEC_E_DOWNGRADE_DETECTED
# define SEC_E_DOWNGRADE_DETECTED             ((HRESULT)0x80090350L)
#endif
#ifndef SEC_E_SMARTCARD_CERT_REVOKED
# define SEC_E_SMARTCARD_CERT_REVOKED         ((HRESULT)0x80090351L)
#endif
#ifndef SEC_E_ISSUING_CA_UNTRUSTED
# define SEC_E_ISSUING_CA_UNTRUSTED           ((HRESULT)0x80090352L)
#endif
#ifndef SEC_E_REVOCATION_OFFLINE_C
# define SEC_E_REVOCATION_OFFLINE_C           ((HRESULT)0x80090353L)
#endif
#ifndef SEC_E_PKINIT_CLIENT_FAILURE
# define SEC_E_PKINIT_CLIENT_FAILURE          ((HRESULT)0x80090354L)
#endif
#ifndef SEC_E_SMARTCARD_CERT_EXPIRED
# define SEC_E_SMARTCARD_CERT_EXPIRED         ((HRESULT)0x80090355L)
#endif
#ifndef SEC_E_NO_S4U_PROT_SUPPORT
# define SEC_E_NO_S4U_PROT_SUPPORT            ((HRESULT)0x80090356L)
#endif
#ifndef SEC_E_CROSSREALM_DELEGATION_FAILURE
# define SEC_E_CROSSREALM_DELEGATION_FAILURE  ((HRESULT)0x80090357L)
#endif
#ifndef SEC_E_REVOCATION_OFFLINE_KDC
# define SEC_E_REVOCATION_OFFLINE_KDC         ((HRESULT)0x80090358L)
#endif
#ifndef SEC_E_ISSUING_CA_UNTRUSTED_KDC
# define SEC_E_ISSUING_CA_UNTRUSTED_KDC       ((HRESULT)0x80090359L)
#endif
#ifndef SEC_E_KDC_CERT_EXPIRED
# define SEC_E_KDC_CERT_EXPIRED               ((HRESULT)0x8009035AL)
#endif
#ifndef SEC_E_KDC_CERT_REVOKED
# define SEC_E_KDC_CERT_REVOKED               ((HRESULT)0x8009035BL)
#endif
#ifndef SEC_E_INVALID_PARAMETER
# define SEC_E_INVALID_PARAMETER              ((HRESULT)0x8009035DL)
#endif
#ifndef SEC_E_DELEGATION_POLICY
# define SEC_E_DELEGATION_POLICY              ((HRESULT)0x8009035EL)
#endif
#ifndef SEC_E_POLICY_NLTM_ONLY
# define SEC_E_POLICY_NLTM_ONLY               ((HRESULT)0x8009035FL)
#endif

#ifndef SEC_I_CONTINUE_NEEDED
# define SEC_I_CONTINUE_NEEDED                ((HRESULT)0x00090312L)
#endif
#ifndef SEC_I_COMPLETE_NEEDED
# define SEC_I_COMPLETE_NEEDED                ((HRESULT)0x00090313L)
#endif
#ifndef SEC_I_COMPLETE_AND_CONTINUE
# define SEC_I_COMPLETE_AND_CONTINUE          ((HRESULT)0x00090314L)
#endif
#ifndef SEC_I_LOCAL_LOGON
# define SEC_I_LOCAL_LOGON                    ((HRESULT)0x00090315L)
#endif
#ifndef SEC_I_CONTEXT_EXPIRED
# define SEC_I_CONTEXT_EXPIRED                ((HRESULT)0x00090317L)
#endif
#ifndef SEC_I_INCOMPLETE_CREDENTIALS
# define SEC_I_INCOMPLETE_CREDENTIALS         ((HRESULT)0x00090320L)
#endif
#ifndef SEC_I_RENEGOTIATE
# define SEC_I_RENEGOTIATE                    ((HRESULT)0x00090321L)
#endif
#ifndef SEC_I_NO_LSA_CONTEXT
# define SEC_I_NO_LSA_CONTEXT                 ((HRESULT)0x00090323L)
#endif
#ifndef SEC_I_SIGNATURE_NEEDED
# define SEC_I_SIGNATURE_NEEDED               ((HRESULT)0x0009035CL)
#endif

#ifndef CRYPT_E_REVOKED
# define CRYPT_E_REVOKED                      ((HRESULT)0x80092010L)
#endif

#ifdef UNICODE
#  define SECFLAG_WINNT_AUTH_IDENTITY \
     (unsigned long)SEC_WINNT_AUTH_IDENTITY_UNICODE
#else
#  define SECFLAG_WINNT_AUTH_IDENTITY \
     (unsigned long)SEC_WINNT_AUTH_IDENTITY_ANSI
#endif

/*
 * Definitions required from ntsecapi.h are directly provided below this point
 * to avoid including ntsecapi.h due to a conflict with OpenSSL's safestack.h
 */
#define KERB_WRAP_NO_ENCRYPT 0x80000001

#endif /* HEADER_WINTLS_SSPI_H */


/* ======================================================================
 * header: schannel_wintls.h
 ====================================================================== */

#ifndef HEADER_WINTLS_SCHANNEL_H
#define HEADER_WINTLS_SCHANNEL_H

//#include "wintls_setup.h"
#ifdef __cplusplus
extern "C" {
#endif

#define SCHANNEL_USE_BLACKLISTS 1

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4201)
#endif
#include <subauth.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif
 /* Wincrypt must be included before anything that could include OpenSSL. */
#include <wincrypt.h>
/* Undefine wincrypt conflicting symbols for BoringSSL. */
#undef X509_NAME
#undef X509_EXTENSIONS
#undef PKCS7_ISSUER_AND_SERIAL
#undef PKCS7_SIGNER_INFO
#undef OCSP_REQUEST
#undef OCSP_RESPONSE

#include <schnlsp.h>
#include <schannel.h>


/* <wincrypt.h> has been included via the above <schnlsp.h>.
 * Or in case of ldap.c, it was included via <winldap.h>.
 * And since <wincrypt.h> has this:
 *   #define X509_NAME  ((LPCSTR) 7)
 *
 * And in BoringSSL's <openssl/base.h> there is:
 *  typedef struct X509_name_st X509_NAME;
 *  etc.
 *
 * this will cause all kinds of C-preprocessing paste errors in
 * BoringSSL's <openssl/x509.h>: So just undefine those defines here
 * (and only here).
 */
#if defined(HAVE_BORINGSSL) || defined(OPENSSL_IS_BORINGSSL)
# undef X509_NAME
# undef X509_CERT_PAIR
# undef X509_EXTENSIONS
#endif

extern const struct wintls_ssl wintls_ssl_schannel;

wintls_code wintls_verify_certificate(struct wintls* data);

/* structs to expose only in schannel.c and schannel_verify.c */
#ifdef EXPOSE_SCHANNEL_INTERNAL_STRUCTS

#ifdef __MINGW32__
#ifdef __MINGW64_VERSION_MAJOR
#define HAS_MANUAL_VERIFY_API
#endif
#else
#ifdef CERT_CHAIN_REVOCATION_CHECK_CHAIN
#define HAS_MANUAL_VERIFY_API
#endif
#endif

#if defined(CryptStringToBinary) && defined(CRYPT_STRING_HEX)   \
  && !defined(DISABLE_SCHANNEL_CLIENT_CERT)
#define HAS_CLIENT_CERT_PATH
#endif

#ifndef SCH_CREDENTIALS_VERSION

#define SCH_CREDENTIALS_VERSION  0x00000005

typedef enum _eTlsAlgorithmUsage
{
    TlsParametersCngAlgUsageKeyExchange,
    TlsParametersCngAlgUsageSignature,
    TlsParametersCngAlgUsageCipher,
    TlsParametersCngAlgUsageDigest,
    TlsParametersCngAlgUsageCertSig
} eTlsAlgorithmUsage;

typedef struct _CRYPTO_SETTINGS
{
    eTlsAlgorithmUsage  eAlgorithmUsage;
    UNICODE_STRING      strCngAlgId;
    DWORD               cChainingModes;
    PUNICODE_STRING     rgstrChainingModes;
    DWORD               dwMinBitLength;
    DWORD               dwMaxBitLength;
} CRYPTO_SETTINGS, * PCRYPTO_SETTINGS;

typedef struct _TLS_PARAMETERS
{
    DWORD               cAlpnIds;
    PUNICODE_STRING     rgstrAlpnIds;
    DWORD               grbitDisabledProtocols;
    DWORD               cDisabledCrypto;
    PCRYPTO_SETTINGS    pDisabledCrypto;
    DWORD               dwFlags;
} TLS_PARAMETERS, * PTLS_PARAMETERS;

typedef struct _SCH_CREDENTIALS
{
    DWORD               dwVersion;
    DWORD               dwCredFormat;
    DWORD               cCreds;
    PCCERT_CONTEXT* paCred;
    HCERTSTORE          hRootStore;

    DWORD               cMappers;
    struct _HMAPPER** aphMappers;

    DWORD               dwSessionLifespan;
    DWORD               dwFlags;
    DWORD               cTlsParameters;
    PTLS_PARAMETERS     pTlsParameters;
} SCH_CREDENTIALS, * PSCH_CREDENTIALS;

#define SCH_CRED_MAX_SUPPORTED_PARAMETERS 16
#define SCH_CRED_MAX_SUPPORTED_ALPN_IDS 16
#define SCH_CRED_MAX_SUPPORTED_CRYPTO_SETTINGS 16
#define SCH_CRED_MAX_SUPPORTED_CHAINING_MODES 16

#endif
#endif /* EXPOSE_SCHANNEL_INTERNAL_STRUCTS */

#ifndef WINTLS_SHA256_DIGEST_LENGTH
#define WINTLS_SHA256_DIGEST_LENGTH 32 /* fixed size */
#endif

#ifndef MAX_PINNED_PUBKEY_SIZE
#define MAX_PINNED_PUBKEY_SIZE 1048576 /* 1MB */
#endif
#define WINTLS_MASK_USIZE_T ((size_t)~0)
#define WINTLS_MASK_SSIZE_T (WINTLS_MASK_USIZE_T >> 1)
#define WINTLS_MASK_USHORT  ((unsigned short)~0)
#define WINTLS_MASK_SSHORT  (WINTLS_MASK_USHORT >> 1)


enum {
    WINTLS_SSLVERSION_DEFAULT,
    WINTLS_SSLVERSION_TLSv1, /* TLS 1.x */
    WINTLS_SSLVERSION_SSLv2,
    WINTLS_SSLVERSION_SSLv3,
    WINTLS_SSLVERSION_TLSv1_0,
    WINTLS_SSLVERSION_TLSv1_1,
    WINTLS_SSLVERSION_TLSv1_2,
    WINTLS_SSLVERSION_TLSv1_3,

    WINTLS_SSLVERSION_LAST /* never use, keep last */
};

enum {
    WINTLS_SSLVERSION_MAX_NONE = 0,
    WINTLS_SSLVERSION_MAX_DEFAULT = (WINTLS_SSLVERSION_TLSv1 << 16),
    WINTLS_SSLVERSION_MAX_TLSv1_0 = (WINTLS_SSLVERSION_TLSv1_0 << 16),
    WINTLS_SSLVERSION_MAX_TLSv1_1 = (WINTLS_SSLVERSION_TLSv1_1 << 16),
    WINTLS_SSLVERSION_MAX_TLSv1_2 = (WINTLS_SSLVERSION_TLSv1_2 << 16),
    WINTLS_SSLVERSION_MAX_TLSv1_3 = (WINTLS_SSLVERSION_TLSv1_3 << 16),

    /* never use, keep last */
    WINTLS_SSLVERSION_MAX_LAST = (WINTLS_SSLVERSION_LAST << 16)
};

wintls_code schannel_connect_nonblocking(struct wintls* data,
    BOOL* done);

wintls_code schannel_connect(struct wintls* data);

wintls_code
schannel_acquire_credential_handle(struct wintls* tls);

int schannel_init(void);


ssize_t
schannel_send(struct wintls* tls,
    const void* buf, size_t len, wintls_code* err);
ssize_t
schannel_recv(struct wintls* tls,
    char* buf, size_t len, wintls_code* err);
#ifdef __cplusplus
}
#endif

#endif /* HEADER_WINTLS_SCHANNEL_H */


/* ======================================================================
 * header: x509asn1.h
 ====================================================================== */

#ifndef __X509ASN1_H_
#define __X509ASN1_H_
/*
 * Types.
 */

 /* ASN.1 parsed element. */
struct wintls_asn1Element {
	const char* header;         /* Pointer to header byte. */
	const char* beg;            /* Pointer to element data. */
	const char* end;            /* Pointer to 1st byte after element. */
	unsigned char class;        /* ASN.1 element class. */
	unsigned char tag;          /* ASN.1 element tag. */
	BOOL          constructed;  /* Element is constructed. */
};

/* X509 certificate: RFC 5280. */
struct wintls_X509certificate {
	struct wintls_asn1Element certificate;
	struct wintls_asn1Element version;
	struct wintls_asn1Element serialNumber;
	struct wintls_asn1Element signatureAlgorithm;
	struct wintls_asn1Element signature;
	struct wintls_asn1Element issuer;
	struct wintls_asn1Element notBefore;
	struct wintls_asn1Element notAfter;
	struct wintls_asn1Element subject;
	struct wintls_asn1Element subjectPublicKeyInfo;
	struct wintls_asn1Element subjectPublicKeyAlgorithm;
	struct wintls_asn1Element subjectPublicKey;
	struct wintls_asn1Element issuerUniqueID;
	struct wintls_asn1Element subjectUniqueID;
	struct wintls_asn1Element extensions;
};
int wintls_parseX509(struct wintls_X509certificate* cert,
	const char* beg, const char* end);
wintls_code wintls_extract_certinfo(struct wintls* tls, int certnum,
	const char* beg, const char* end);
wintls_code wintls_verifyhost(struct wintls* tls,
	const char* beg, const char* end);

#endif


/* ======================================================================
 * header: schannel_verify.h
 ====================================================================== */




/* ======================================================================
 * IMPLEMENTATION
 ====================================================================== */



/* ======================================================================
 * source: debug.c
 ====================================================================== */



#define MAXINFO 2048
#define WINTLS_ERROR_SIZE 256

void wintls_debug(struct wintls* data, wintls_infotype type,
    char* ptr, size_t size)
{
    static const char s_infotype[WINTLSINFO_END][3] = {
             "* ", "< ", "> ", "{ ", "} ", "{ ", "} " };
    printf(s_infotype[type]);
    printf(ptr);
}

void wintls_infof(struct wintls* data, const char* fmt, ...)
{
    DEBUGASSERT(!strchr(fmt, '\n'));
    if (data) { //&& data->set.verbose) {
        va_list ap;
        int len;
        char buffer[MAXINFO + 2];
        va_start(ap, fmt);
        len = mvsnprintf(buffer, MAXINFO, fmt, ap);
        va_end(ap);
        buffer[len++] = '\n';
        buffer[len] = '\0';
        wintls_debug(data, WINTLSINFO_TEXT, buffer, len);
    }
}

/* wintls_failf() is for messages stating why we failed.
 * The message SHALL NOT include any LF or CR.
 */
void wintls_failf(struct wintls* data, const char* fmt, ...)
{
    DEBUGASSERT(!strchr(fmt, '\n'));
    if (data) {
        va_list ap;
        int len;
        char error[WINTLS_ERROR_SIZE + 2];
        va_start(ap, fmt);
        len = mvsnprintf(error, WINTLS_ERROR_SIZE, fmt, ap);

        error[len++] = '\n';
        error[len] = '\0';
        wintls_debug(data, WINTLSINFO_TEXT, error, len);
        va_end(ap);
    }
}


/* ======================================================================
 * source: wintls_printf.c
 ====================================================================== */


/*
 * If SIZEOF_SIZE_T has not been defined, default to the size of long.
 */

#ifdef HAVE_LONGLONG
#  define LONG_LONG_TYPE long long
#  define HAVE_LONG_LONG_TYPE
#else
#  if defined(_MSC_VER) && (_MSC_VER >= 900) && (_INTEGRAL_MAX_BITS >= 64)
#    define LONG_LONG_TYPE __int64
#    define HAVE_LONG_LONG_TYPE
#  else
#    undef LONG_LONG_TYPE
#    undef HAVE_LONG_LONG_TYPE
#  endif
#endif

 /*
  * Non-ANSI integer extensions
  */

#if (defined(__BORLANDC__) && (__BORLANDC__ >= 0x520)) || \
    (defined(__POCC__) && defined(_MSC_VER)) || \
    (defined(_WIN32_WCE)) || \
    (defined(__MINGW32__)) || \
    (defined(_MSC_VER) && (_MSC_VER >= 900) && (_INTEGRAL_MAX_BITS >= 64))
#  define MP_HAVE_INT_EXTENSIONS
#endif

  /*
   * Max integer data types that mprintf.c is capable
   */

#ifdef HAVE_LONG_LONG_TYPE
#  define mp_intmax_t LONG_LONG_TYPE
#  define mp_uintmax_t unsigned LONG_LONG_TYPE
#else
#  define mp_intmax_t long
#  define mp_uintmax_t unsigned long
#endif

#define BUFFSIZE 326 /* buffer for long-to-str and float-to-str calcs, should
                        fit negative DBL_MAX (317 letters) */
#define MAX_PARAMETERS 128 /* lame static limit */

#ifdef __AMIGA__
# undef FORMAT_INT
#endif

                        /* Lower-case digits.  */
static const char lower_digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";

/* Upper-case digits.  */
static const char upper_digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

#define OUTCHAR(x)                                     \
  do {                                                 \
    if(stream((unsigned char)(x), (FILE *)data) != -1) \
      done++;                                          \
    else                                               \
      return done; /* return immediately on failure */ \
  } while(0)

/* Data type to read from the arglist */
typedef enum {
    FORMAT_UNKNOWN = 0,
    FORMAT_STRING,
    FORMAT_PTR,
    FORMAT_INT,
    FORMAT_INTPTR,
    FORMAT_LONG,
    FORMAT_LONGLONG,
    FORMAT_DOUBLE,
    FORMAT_LONGDOUBLE,
    FORMAT_WIDTH /* For internal use */
} FormatType;

/* conversion and display flags */
enum {
    FLAGS_NEW = 0,
    FLAGS_SPACE = 1 << 0,
    FLAGS_SHOWSIGN = 1 << 1,
    FLAGS_LEFT = 1 << 2,
    FLAGS_ALT = 1 << 3,
    FLAGS_SHORT = 1 << 4,
    FLAGS_LONG = 1 << 5,
    FLAGS_LONGLONG = 1 << 6,
    FLAGS_LONGDOUBLE = 1 << 7,
    FLAGS_PAD_NIL = 1 << 8,
    FLAGS_UNSIGNED = 1 << 9,
    FLAGS_OCTAL = 1 << 10,
    FLAGS_HEX = 1 << 11,
    FLAGS_UPPER = 1 << 12,
    FLAGS_WIDTH = 1 << 13, /* '*' or '*<num>$' used */
    FLAGS_WIDTHPARAM = 1 << 14, /* width PARAMETER was specified */
    FLAGS_PREC = 1 << 15, /* precision was specified */
    FLAGS_PRECPARAM = 1 << 16, /* precision PARAMETER was specified */
    FLAGS_CHAR = 1 << 17, /* %c story */
    FLAGS_FLOATE = 1 << 18, /* %e or %E */
    FLAGS_FLOATG = 1 << 19  /* %g or %G */
};

struct va_stack {
    FormatType type;
    int flags;
    long width;     /* width OR width parameter number */
    long precision; /* precision OR precision parameter number */
    union {
        char* str;
        void* ptr;
        union {
            mp_intmax_t as_signed;
            mp_uintmax_t as_unsigned;
        } num;
        double dnum;
    } data;
};

struct nsprintf {
    char* buffer;
    SIZE_T length;
    SIZE_T max;
};

struct asprintf {
    struct dynbuf* b;
    BOOL fail; /* if an alloc has failed and thus the output is not the complete
                  data */
};

static long dprintf_DollarString(char* input, char** end)
{
    int number = 0;
    while (ISDIGIT(*input)) {
        if (number < MAX_PARAMETERS) {
            number *= 10;
            number += *input - '0';
        }
        input++;
    }
    if (number <= MAX_PARAMETERS && ('$' == *input)) {
        *end = ++input;
        return number;
    }
    return 0;
}

static BOOL dprintf_IsQualifierNoDollar(const char* fmt)
{
#if defined(MP_HAVE_INT_EXTENSIONS)
    if (!strncmp(fmt, "I32", 3) || !strncmp(fmt, "I64", 3)) {
        return TRUE;
    }
#endif

    switch (*fmt) {
    case '-': case '+': case ' ': case '#': case '.':
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
    case 'h': case 'l': case 'L': case 'z': case 'q':
    case '*': case 'O':
#if defined(MP_HAVE_INT_EXTENSIONS)
    case 'I':
#endif
        return TRUE;

    default:
        return FALSE;
    }
}

/******************************************************************
 *
 * Pass 1:
 * Create an index with the type of each parameter entry and its
 * value (may vary in size)
 *
 * Returns zero on success.
 *
 ******************************************************************/

static int dprintf_Pass1(const char* format, struct va_stack* vto,
    char** endpos, va_list arglist)
{
    char* fmt = (char*)format;
    int param_num = 0;
    long this_param;
    long width;
    long precision;
    int flags;
    long max_param = 0;
    long i;

    while (*fmt) {
        if (*fmt++ == '%') {
            if (*fmt == '%') {
                fmt++;
                continue; /* while */
            }

            flags = FLAGS_NEW;

            /* Handle the positional case (N$) */

            param_num++;

            this_param = dprintf_DollarString(fmt, &fmt);
            if (0 == this_param)
                /* we got no positional, get the next counter */
                this_param = param_num;

            if (this_param > max_param)
                max_param = this_param;

            /*
             * The parameter with number 'i' should be used. Next, we need
             * to get SIZE and TYPE of the parameter. Add the information
             * to our array.
             */

            width = 0;
            precision = 0;

            /* Handle the flags */

            while (dprintf_IsQualifierNoDollar(fmt)) {
#if defined(MP_HAVE_INT_EXTENSIONS)
                if (!strncmp(fmt, "I32", 3)) {
                    flags |= FLAGS_LONG;
                    fmt += 3;
                }
                else if (!strncmp(fmt, "I64", 3)) {
                    flags |= FLAGS_LONGLONG;
                    fmt += 3;
                }
                else
#endif

                    switch (*fmt++) {
                    case ' ':
                        flags |= FLAGS_SPACE;
                        break;
                    case '+':
                        flags |= FLAGS_SHOWSIGN;
                        break;
                    case '-':
                        flags |= FLAGS_LEFT;
                        flags &= ~FLAGS_PAD_NIL;
                        break;
                    case '#':
                        flags |= FLAGS_ALT;
                        break;
                    case '.':
                        if ('*' == *fmt) {
                            /* The precision is picked from a specified parameter */

                            flags |= FLAGS_PRECPARAM;
                            fmt++;
                            param_num++;

                            i = dprintf_DollarString(fmt, &fmt);
                            if (i)
                                precision = i;
                            else
                                precision = param_num;

                            if (precision > max_param)
                                max_param = precision;
                        }
                        else {
                            flags |= FLAGS_PREC;
                            precision = strtol(fmt, &fmt, 10);
                        }
                        if ((flags & (FLAGS_PREC | FLAGS_PRECPARAM)) ==
                            (FLAGS_PREC | FLAGS_PRECPARAM))
                            /* it is not permitted to use both kinds of precision for the same
                               argument */
                            return 1;
                        break;
                    case 'h':
                        flags |= FLAGS_SHORT;
                        break;
#if defined(MP_HAVE_INT_EXTENSIONS)
                    case 'I':
#if (SIZEOF_WINTLS_OFF_T > SIZEOF_LONG)
                        flags |= FLAGS_LONGLONG;
#else
                        flags |= FLAGS_LONG;
#endif
                        break;
#endif
                    case 'l':
                        if (flags & FLAGS_LONG)
                            flags |= FLAGS_LONGLONG;
                        else
                            flags |= FLAGS_LONG;
                        break;
                    case 'L':
                        flags |= FLAGS_LONGDOUBLE;
                        break;
                    case 'q':
                        flags |= FLAGS_LONGLONG;
                        break;
                    case 'z':
                        /* the code below generates a warning if -Wunreachable-code is
                           used */
#if (SIZEOF_SIZE_T > SIZEOF_LONG)
                        flags |= FLAGS_LONGLONG;
#else
                        flags |= FLAGS_LONG;
#endif
                        break;
                    case 'O':
#if (SIZEOF_WINTLS_OFF_T > SIZEOF_LONG)
                        flags |= FLAGS_LONGLONG;
#else
                        flags |= FLAGS_LONG;
#endif
                        break;
                    case '0':
                        if (!(flags & FLAGS_LEFT))
                            flags |= FLAGS_PAD_NIL;
                        /* FALLTHROUGH */
                    case '1': case '2': case '3': case '4':
                    case '5': case '6': case '7': case '8': case '9':
                        flags |= FLAGS_WIDTH;
                        width = strtol(fmt - 1, &fmt, 10);
                        break;
                    case '*':  /* Special case */
                        flags |= FLAGS_WIDTHPARAM;
                        param_num++;

                        i = dprintf_DollarString(fmt, &fmt);
                        if (i)
                            width = i;
                        else
                            width = param_num;
                        if (width > max_param)
                            max_param = width;
                        break;
                    case '\0':
                        fmt--;
                    default:
                        break;
                    }
            } /* switch */

            /* Handle the specifier */

            i = this_param - 1;

            if ((i < 0) || (i >= MAX_PARAMETERS))
                /* out of allowed range */
                return 1;

            switch (*fmt) {
            case 'S':
                flags |= FLAGS_ALT;
                /* FALLTHROUGH */
            case 's':
                vto[i].type = FORMAT_STRING;
                break;
            case 'n':
                vto[i].type = FORMAT_INTPTR;
                break;
            case 'p':
                vto[i].type = FORMAT_PTR;
                break;
            case 'd': case 'i':
                vto[i].type = FORMAT_INT;
                break;
            case 'u':
                vto[i].type = FORMAT_INT;
                flags |= FLAGS_UNSIGNED;
                break;
            case 'o':
                vto[i].type = FORMAT_INT;
                flags |= FLAGS_OCTAL;
                break;
            case 'x':
                vto[i].type = FORMAT_INT;
                flags |= FLAGS_HEX | FLAGS_UNSIGNED;
                break;
            case 'X':
                vto[i].type = FORMAT_INT;
                flags |= FLAGS_HEX | FLAGS_UPPER | FLAGS_UNSIGNED;
                break;
            case 'c':
                vto[i].type = FORMAT_INT;
                flags |= FLAGS_CHAR;
                break;
            case 'f':
                vto[i].type = FORMAT_DOUBLE;
                break;
            case 'e':
                vto[i].type = FORMAT_DOUBLE;
                flags |= FLAGS_FLOATE;
                break;
            case 'E':
                vto[i].type = FORMAT_DOUBLE;
                flags |= FLAGS_FLOATE | FLAGS_UPPER;
                break;
            case 'g':
                vto[i].type = FORMAT_DOUBLE;
                flags |= FLAGS_FLOATG;
                break;
            case 'G':
                vto[i].type = FORMAT_DOUBLE;
                flags |= FLAGS_FLOATG | FLAGS_UPPER;
                break;
            default:
                vto[i].type = FORMAT_UNKNOWN;
                break;
            } /* switch */

            vto[i].flags = flags;
            vto[i].width = width;
            vto[i].precision = precision;

            if (flags & FLAGS_WIDTHPARAM) {
                /* we have the width specified from a parameter, so we make that
                   parameter's info setup properly */
                long k = width - 1;
                if ((k < 0) || (k >= MAX_PARAMETERS))
                    /* out of allowed range */
                    return 1;
                vto[i].width = k;
                vto[k].type = FORMAT_WIDTH;
                vto[k].flags = FLAGS_NEW;
                /* can't use width or precision of width! */
                vto[k].width = 0;
                vto[k].precision = 0;
            }
            if (flags & FLAGS_PRECPARAM) {
                /* we have the precision specified from a parameter, so we make that
                   parameter's info setup properly */
                long k = precision - 1;
                if ((k < 0) || (k >= MAX_PARAMETERS))
                    /* out of allowed range */
                    return 1;
                vto[i].precision = k;
                vto[k].type = FORMAT_WIDTH;
                vto[k].flags = FLAGS_NEW;
                /* can't use width or precision of width! */
                vto[k].width = 0;
                vto[k].precision = 0;
            }
            *endpos++ = fmt + ((*fmt == '\0') ? 0 : 1); /* end of this sequence */
        }
    }

    /* Read the arg list parameters into our data list */
    for (i = 0; i < max_param; i++) {
        /* Width/precision arguments must be read before the main argument
           they are attached to */
        if (vto[i].flags & FLAGS_WIDTHPARAM) {
            vto[vto[i].width].data.num.as_signed =
                (mp_intmax_t)va_arg(arglist, int);
        }
        if (vto[i].flags & FLAGS_PRECPARAM) {
            vto[vto[i].precision].data.num.as_signed =
                (mp_intmax_t)va_arg(arglist, int);
        }

        switch (vto[i].type) {
        case FORMAT_STRING:
            vto[i].data.str = va_arg(arglist, char*);
            break;

        case FORMAT_INTPTR:
        case FORMAT_UNKNOWN:
        case FORMAT_PTR:
            vto[i].data.ptr = va_arg(arglist, void*);
            break;

        case FORMAT_INT:
#ifdef HAVE_LONG_LONG_TYPE
            if ((vto[i].flags & FLAGS_LONGLONG) && (vto[i].flags & FLAGS_UNSIGNED))
                vto[i].data.num.as_unsigned =
                (mp_uintmax_t)va_arg(arglist, mp_uintmax_t);
            else if (vto[i].flags & FLAGS_LONGLONG)
                vto[i].data.num.as_signed =
                (mp_intmax_t)va_arg(arglist, mp_intmax_t);
            else
#endif
            {
                if ((vto[i].flags & FLAGS_LONG) && (vto[i].flags & FLAGS_UNSIGNED))
                    vto[i].data.num.as_unsigned =
                    (mp_uintmax_t)va_arg(arglist, unsigned long);
                else if (vto[i].flags & FLAGS_LONG)
                    vto[i].data.num.as_signed =
                    (mp_intmax_t)va_arg(arglist, long);
                else if (vto[i].flags & FLAGS_UNSIGNED)
                    vto[i].data.num.as_unsigned =
                    (mp_uintmax_t)va_arg(arglist, unsigned int);
                else
                    vto[i].data.num.as_signed =
                    (mp_intmax_t)va_arg(arglist, int);
            }
            break;

        case FORMAT_DOUBLE:
            vto[i].data.dnum = va_arg(arglist, double);
            break;

        case FORMAT_WIDTH:
            /* Argument has been read. Silently convert it into an integer
             * for later use
             */
            vto[i].type = FORMAT_INT;
            break;

        default:
            break;
        }
    }

    return 0;

}

static int dprintf_formatf(
    void* data, /* untouched by format(), just sent to the stream() function in
                   the second argument */
                   /* function pointer called for each output character */
    int (*stream)(int, FILE*),
    const char* format,    /* %-formatted string */
    va_list ap_save) /* list of parameters */
{
    /* Base-36 digits for numbers.  */
    const char* digits = lower_digits;

    /* Pointer into the format string.  */
    char* f;

    /* Number of characters written.  */
    int done = 0;

    long param; /* current parameter to read */
    long param_num = 0; /* parameter counter */

    struct va_stack vto[MAX_PARAMETERS];
    char* endpos[MAX_PARAMETERS];
    char** end;
    char work[BUFFSIZE];
    struct va_stack* p;

    /* 'workend' points to the final buffer byte position, but with an extra
       byte as margin to avoid the (false?) warning Coverity gives us
       otherwise */
    char* workend = &work[sizeof(work) - 2];

    /* Do the actual %-code parsing */
    if (dprintf_Pass1(format, vto, endpos, ap_save))
        return 0;

    end = &endpos[0]; /* the initial end-position from the list dprintf_Pass1()
                         created for us */

    f = (char*)format;
    while (*f != '\0') {
        /* Format spec modifiers.  */
        int is_alt;

        /* Width of a field.  */
        long width;

        /* Precision of a field.  */
        long prec;

        /* Decimal integer is negative.  */
        int is_neg;

        /* Base of a number to be written.  */
        unsigned long base;

        /* Integral values to be written.  */
        mp_uintmax_t num;

        /* Used to convert negative in positive.  */
        mp_intmax_t signed_num;

        char* w;

        if (*f != '%') {
            /* This isn't a format spec, so write everything out until the next one
               OR end of string is reached.  */
            do {
                OUTCHAR(*f);
            } while (*++f && ('%' != *f));
            continue;
        }

        ++f;

        /* Check for "%%".  Note that although the ANSI standard lists
           '%' as a conversion specifier, it says "The complete format
           specification shall be `%%'," so we can avoid all the width
           and precision processing.  */
        if (*f == '%') {
            ++f;
            OUTCHAR('%');
            continue;
        }

        /* If this is a positional parameter, the position must follow immediately
           after the %, thus create a %<num>$ sequence */
        param = dprintf_DollarString(f, &f);

        if (!param)
            param = param_num;
        else
            --param;

        param_num++; /* increase this always to allow "%2$s %1$s %s" and then the
                        third %s will pick the 3rd argument */

        p = &vto[param];

        /* pick up the specified width */
        if (p->flags & FLAGS_WIDTHPARAM) {
            width = (long)vto[p->width].data.num.as_signed;
            param_num++; /* since the width is extracted from a parameter, we
                            must skip that to get to the next one properly */
            if (width < 0) {
                /* "A negative field width is taken as a '-' flag followed by a
                   positive field width." */
                width = -width;
                p->flags |= FLAGS_LEFT;
                p->flags &= ~FLAGS_PAD_NIL;
            }
        }
        else
            width = p->width;

        /* pick up the specified precision */
        if (p->flags & FLAGS_PRECPARAM) {
            prec = (long)vto[p->precision].data.num.as_signed;
            param_num++; /* since the precision is extracted from a parameter, we
                            must skip that to get to the next one properly */
            if (prec < 0)
                /* "A negative precision is taken as if the precision were
                   omitted." */
                prec = -1;
        }
        else if (p->flags & FLAGS_PREC)
            prec = p->precision;
        else
            prec = -1;

        is_alt = (p->flags & FLAGS_ALT) ? 1 : 0;

        switch (p->type) {
        case FORMAT_INT:
            num = p->data.num.as_unsigned;
            if (p->flags & FLAGS_CHAR) {
                /* Character.  */
                if (!(p->flags & FLAGS_LEFT))
                    while (--width > 0)
                        OUTCHAR(' ');
                OUTCHAR((char)num);
                if (p->flags & FLAGS_LEFT)
                    while (--width > 0)
                        OUTCHAR(' ');
                break;
            }
            if (p->flags & FLAGS_OCTAL) {
                /* Octal unsigned integer.  */
                base = 8;
                goto unsigned_number;
            }
            else if (p->flags & FLAGS_HEX) {
                /* Hexadecimal unsigned integer.  */

                digits = (p->flags & FLAGS_UPPER) ? upper_digits : lower_digits;
                base = 16;
                goto unsigned_number;
            }
            else if (p->flags & FLAGS_UNSIGNED) {
                /* Decimal unsigned integer.  */
                base = 10;
                goto unsigned_number;
            }

            /* Decimal integer.  */
            base = 10;

            is_neg = (p->data.num.as_signed < (mp_intmax_t)0) ? 1 : 0;
            if (is_neg) {
                /* signed_num might fail to hold absolute negative minimum by 1 */
                signed_num = p->data.num.as_signed + (mp_intmax_t)1;
                signed_num = -signed_num;
                num = (mp_uintmax_t)signed_num;
                num += (mp_uintmax_t)1;
            }

            goto number;

        unsigned_number:
            /* Unsigned number of base BASE.  */
            is_neg = 0;

        number:
            /* Number of base BASE.  */

            /* Supply a default precision if none was given.  */
            if (prec == -1)
                prec = 1;

            /* Put the number in WORK.  */
            w = workend;
            while (num > 0) {
                *w-- = digits[num % base];
                num /= base;
            }
            width -= (long)(workend - w);
            prec -= (long)(workend - w);

            if (is_alt && base == 8 && prec <= 0) {
                *w-- = '0';
                --width;
            }

            if (prec > 0) {
                width -= prec;
                while (prec-- > 0 && w >= work)
                    *w-- = '0';
            }

            if (is_alt && base == 16)
                width -= 2;

            if (is_neg || (p->flags & FLAGS_SHOWSIGN) || (p->flags & FLAGS_SPACE))
                --width;

            if (!(p->flags & FLAGS_LEFT) && !(p->flags & FLAGS_PAD_NIL))
                while (width-- > 0)
                    OUTCHAR(' ');

            if (is_neg)
                OUTCHAR('-');
            else if (p->flags & FLAGS_SHOWSIGN)
                OUTCHAR('+');
            else if (p->flags & FLAGS_SPACE)
                OUTCHAR(' ');

            if (is_alt && base == 16) {
                OUTCHAR('0');
                if (p->flags & FLAGS_UPPER)
                    OUTCHAR('X');
                else
                    OUTCHAR('x');
            }

            if (!(p->flags & FLAGS_LEFT) && (p->flags & FLAGS_PAD_NIL))
                while (width-- > 0)
                    OUTCHAR('0');

            /* Write the number.  */
            while (++w <= workend) {
                OUTCHAR(*w);
            }

            if (p->flags & FLAGS_LEFT)
                while (width-- > 0)
                    OUTCHAR(' ');
            break;

        case FORMAT_STRING:
            /* String.  */
        {
            static const char null[] = "(nil)";
            const char* str;
            SIZE_T len;

            str = (char*)p->data.str;
            if (!str) {
                /* Write null[] if there's space.  */
                if (prec == -1 || prec >= (long)sizeof(null) - 1) {
                    str = null;
                    len = sizeof(null) - 1;
                    /* Disable quotes around (nil) */
                    p->flags &= (~FLAGS_ALT);
                }
                else {
                    str = "";
                    len = 0;
                }
            }
            else if (prec != -1)
                len = (SIZE_T)prec;
            else if (*str == '\0')
                len = 0;
            else
                len = strlen(str);

            width -= (len > LONG_MAX) ? LONG_MAX : (long)len;

            if (p->flags & FLAGS_ALT)
                OUTCHAR('"');

            if (!(p->flags & FLAGS_LEFT))
                while (width-- > 0)
                    OUTCHAR(' ');

            for (; len && *str; len--)
                OUTCHAR(*str++);
            if (p->flags & FLAGS_LEFT)
                while (width-- > 0)
                    OUTCHAR(' ');

            if (p->flags & FLAGS_ALT)
                OUTCHAR('"');
        }
        break;

        case FORMAT_PTR:
            /* Generic pointer.  */
        {
            void* ptr;
            ptr = (void*)p->data.ptr;
            if (ptr) {
                /* If the pointer is not NULL, write it as a %#x spec.  */
                base = 16;
                digits = (p->flags & FLAGS_UPPER) ? upper_digits : lower_digits;
                is_alt = 1;
                num = (SIZE_T)ptr;
                is_neg = 0;
                goto number;
            }
            else {
                /* Write "(nil)" for a nil pointer.  */
                static const char strnil[] = "(nil)";
                const char* point;

                width -= (long)(sizeof(strnil) - 1);
                if (p->flags & FLAGS_LEFT)
                    while (width-- > 0)
                        OUTCHAR(' ');
                for (point = strnil; *point != '\0'; ++point)
                    OUTCHAR(*point);
                if (!(p->flags & FLAGS_LEFT))
                    while (width-- > 0)
                        OUTCHAR(' ');
            }
        }
        break;

        case FORMAT_DOUBLE:
        {
            char formatbuf[32] = "%";
            char* fptr = &formatbuf[1];
            SIZE_T left = sizeof(formatbuf) - strlen(formatbuf);
            int len;

            width = -1;
            if (p->flags & FLAGS_WIDTH)
                width = p->width;
            else if (p->flags & FLAGS_WIDTHPARAM)
                width = (long)vto[p->width].data.num.as_signed;

            prec = -1;
            if (p->flags & FLAGS_PREC)
                prec = p->precision;
            else if (p->flags & FLAGS_PRECPARAM)
                prec = (long)vto[p->precision].data.num.as_signed;

            if (p->flags & FLAGS_LEFT)
                *fptr++ = '-';
            if (p->flags & FLAGS_SHOWSIGN)
                *fptr++ = '+';
            if (p->flags & FLAGS_SPACE)
                *fptr++ = ' ';
            if (p->flags & FLAGS_ALT)
                *fptr++ = '#';

            *fptr = 0;

            if (width >= 0) {
                if (width >= (long)sizeof(work))
                    width = sizeof(work) - 1;
                /* RECURSIVE USAGE */
                len = wintls_msnprintf(fptr, left, "%ld", width);
                fptr += len;
                left -= len;
            }
            if (prec >= 0) {
                /* for each digit in the integer part, we can have one less
                   precision */
                SIZE_T maxprec = sizeof(work) - 2;
                double val = p->data.dnum;
                if (width > 0 && prec <= width)
                    maxprec -= width;
                while (val >= 10.0) {
                    val /= 10;
                    maxprec--;
                }

                if (prec > (long)maxprec)
                    prec = (long)maxprec - 1;
                if (prec < 0)
                    prec = 0;
                /* RECURSIVE USAGE */
                len = wintls_msnprintf(fptr, left, ".%ld", prec);
                fptr += len;
            }
            if (p->flags & FLAGS_LONG)
                *fptr++ = 'l';

            if (p->flags & FLAGS_FLOATE)
                *fptr++ = (char)((p->flags & FLAGS_UPPER) ? 'E' : 'e');
            else if (p->flags & FLAGS_FLOATG)
                *fptr++ = (char)((p->flags & FLAGS_UPPER) ? 'G' : 'g');
            else
                *fptr++ = 'f';

            *fptr = 0; /* and a final null-termination */

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif
            /* NOTE NOTE NOTE!! Not all sprintf implementations return number of
               output characters */
#ifdef HAVE_SNPRINTF
            (snprintf)(work, sizeof(work), formatbuf, p->data.dnum);
#else
            (sprintf)(work, formatbuf, p->data.dnum);
#endif
#ifdef __clang__
#pragma clang diagnostic pop
#endif
            DEBUGASSERT(strlen(work) <= sizeof(work));
            for (fptr = work; *fptr; fptr++)
                OUTCHAR(*fptr);
        }
        break;

        case FORMAT_INTPTR:
            /* Answer the count of characters written.  */
#ifdef HAVE_LONG_LONG_TYPE
            if (p->flags & FLAGS_LONGLONG)
                *(LONG_LONG_TYPE*)p->data.ptr = (LONG_LONG_TYPE)done;
            else
#endif
                if (p->flags & FLAGS_LONG)
                    *(long*)p->data.ptr = (long)done;
                else if (!(p->flags & FLAGS_SHORT))
                    *(int*)p->data.ptr = (int)done;
                else
                    *(short*)p->data.ptr = (short)done;
            break;

        default:
            break;
        }
        f = *end++; /* goto end of %-code */

    }
    return done;
}

/* fputc() look-alike */
static int addbyter(int output, FILE* data)
{
    struct nsprintf* infop = (struct nsprintf*)data;
    unsigned char outc = (unsigned char)output;

    if (infop->length < infop->max) {
        /* only do this if we haven't reached max length yet */
        infop->buffer[0] = outc; /* store */
        infop->buffer++; /* increase pointer */
        infop->length++; /* we are now one byte larger */
        return outc;     /* fputc() returns like this on success */
    }
    return -1;
}

int wintls_mvsnprintf(char* buffer, SIZE_T maxlength, const char* format,
    va_list ap_save)
{
    int retcode;
    struct nsprintf info;

    info.buffer = buffer;
    info.length = 0;
    info.max = maxlength;

    retcode = dprintf_formatf(&info, addbyter, format, ap_save);
    if (info.max) {
        /* we terminate this with a zero byte */
        if (info.max == info.length) {
            /* we're at maximum, scrap the last letter */
            info.buffer[-1] = 0;
            DEBUGASSERT(retcode);
            retcode--; /* don't count the nul byte */
        }
        else
            info.buffer[0] = 0;
    }
    return retcode;
}

int wintls_msnprintf(char* buffer, SIZE_T maxlength, const char* format, ...)
{
    int retcode;
    va_list ap_save; /* argument pointer */
    va_start(ap_save, format);
    retcode = wintls_mvsnprintf(buffer, maxlength, format, ap_save);
    va_end(ap_save);
    return retcode;
}

/* fputc() look-alike */
static int alloc_addbyter(int output, FILE* data)
{
    struct asprintf* infop = (struct asprintf*)data;
    unsigned char outc = (unsigned char)output;

    if (wintls_dyn_addn(infop->b, &outc, 1)) {
        infop->fail = 1;
        return -1; /* fail */
    }
    return outc; /* fputc() returns like this on success */
}

extern int wintls_dyn_vprintf(struct dynbuf* dyn,
    const char* format, va_list ap_save);

/* appends the formatted string, returns 0 on success, 1 on error */
int wintls_dyn_vprintf(struct dynbuf* dyn, const char* format, va_list ap_save)
{
    struct asprintf info;
    info.b = dyn;
    info.fail = 0;

    (void)dprintf_formatf(&info, alloc_addbyter, format, ap_save);
    if (info.fail) {
        wintls_dyn_free(info.b);
        return 1;
    }
    return 0;
}

char* wintls_mvaprintf(const char* format, va_list ap_save)
{
    struct asprintf info;
    struct dynbuf dyn;
    info.b = &dyn;
    wintls_dyn_init(info.b, DYN_APRINTF);
    info.fail = 0;

    (void)dprintf_formatf(&info, alloc_addbyter, format, ap_save);
    if (info.fail) {
        wintls_dyn_free(info.b);
        return NULL;
    }
    if (wintls_dyn_len(info.b))
        return wintls_dyn_ptr(info.b);
    return strdup("");
}

char* wintls_maprintf(const char* format, ...)
{
    va_list ap_save;
    char* s;
    va_start(ap_save, format);
    s = wintls_mvaprintf(format, ap_save);
    va_end(ap_save);
    return s;
}

static int storebuffer(int output, FILE* data)
{
    char** buffer = (char**)data;
    unsigned char outc = (unsigned char)output;
    **buffer = outc;
    (*buffer)++;
    return outc; /* act like fputc() ! */
}

int wintls_msprintf(char* buffer, const char* format, ...)
{
    va_list ap_save; /* argument pointer */
    int retcode;
    va_start(ap_save, format);
    retcode = dprintf_formatf(&buffer, storebuffer, format, ap_save);
    va_end(ap_save);
    *buffer = 0; /* we terminate this with a zero byte */
    return retcode;
}

int wintls_mprintf(const char* format, ...)
{
    int retcode;
    va_list ap_save; /* argument pointer */
    va_start(ap_save, format);

    retcode = dprintf_formatf(stdout, fputc, format, ap_save);
    va_end(ap_save);
    return retcode;
}

int wintls_mfprintf(FILE* whereto, const char* format, ...)
{
    int retcode;
    va_list ap_save; /* argument pointer */
    va_start(ap_save, format);
    retcode = dprintf_formatf(whereto, fputc, format, ap_save);
    va_end(ap_save);
    return retcode;
}

int wintls_mvsprintf(char* buffer, const char* format, va_list ap_save)
{
    int retcode;
    retcode = dprintf_formatf(&buffer, storebuffer, format, ap_save);
    *buffer = 0; /* we terminate this with a zero byte */
    return retcode;
}

int wintls_mvprintf(const char* format, va_list ap_save)
{
    return dprintf_formatf(stdout, fputc, format, ap_save);
}

int wintls_mvfprintf(FILE* whereto, const char* format, va_list ap_save)
{
    return dprintf_formatf(whereto, fputc, format, ap_save);
}




/* ======================================================================
 * source: dynbuf.c
 ====================================================================== */


//#include "wintls.h"

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#define MIN_FIRST_ALLOC 32

#define DYNINIT 0xbee51da /* random pattern */

 /*
  * Init a dynbuf struct.
  */
void wintls_dyn_init(struct dynbuf* s, size_t toobig)
{
    DEBUGASSERT(s);
    DEBUGASSERT(toobig);
    s->bufr = NULL;
    s->leng = 0;
    s->allc = 0;
    s->toobig = toobig;
#ifdef DEBUGBUILD
    s->init = DYNINIT;
#endif
}

/*
 * free the buffer and re-init the necessary fields. It doesn't touch the
 * 'init' field and thus this buffer can be reused to add data to again.
 */
void wintls_dyn_free(struct dynbuf* s)
{
    DEBUGASSERT(s);
    wintls_safefree(s->bufr);
    s->leng = s->allc = 0;
}

/*
 * Store/append an chunk of memory to the dynbuf.
 */
static wintls_code dyn_nappend(struct dynbuf* s,
    const unsigned char* mem, size_t len)
{
    size_t indx = s->leng;
    size_t a = s->allc;
    size_t fit = len + indx + 1; /* new string + old string + zero byte */

    /* try to detect if there's rubbish in the struct */
#ifdef DEBUGBUILD
    DEBUGASSERT(s->init == DYNINIT);
#endif
    DEBUGASSERT(s->toobig);
    DEBUGASSERT(indx < s->toobig);
    DEBUGASSERT(!s->leng || s->bufr);
    DEBUGASSERT(a <= s->toobig);

    if (fit > s->toobig) {
        wintls_dyn_free(s);
        return WINTLS_OUT_OF_MEMORY;
    }
    else if (!a) {
        DEBUGASSERT(!indx);
        /* first invoke */
        if (MIN_FIRST_ALLOC > s->toobig)
            a = s->toobig;
        else if (fit < MIN_FIRST_ALLOC)
            a = MIN_FIRST_ALLOC;
        else
            a = fit;
    }
    else {
        while (a < fit)
            a *= 2;
        if (a > s->toobig)
            /* no point in allocating a larger buffer than this is allowed to use */
            a = s->toobig;
    }

    if (a != s->allc) {
        /* this logic is not using wintls_saferealloc() to make the tool not have to
           include that as well when it uses this code */
        void* p = realloc(s->bufr, a);
        if (!p) {
            wintls_dyn_free(s);
            return WINTLS_OUT_OF_MEMORY;
        }
        s->bufr = p;
        s->allc = a;
    }

    if (len)
        memcpy(&s->bufr[indx], mem, len);
    s->leng = indx + len;
    s->bufr[s->leng] = 0;
    return WINTLS_OK;
}

/*
 * Clears the string, keeps the allocation. This can also be called on a
 * buffer that already was freed.
 */
void wintls_dyn_reset(struct dynbuf* s)
{
    DEBUGASSERT(s);
#ifdef DEBUGBUILD
    DEBUGASSERT(s->init == DYNINIT);
#endif
    DEBUGASSERT(!s->leng || s->bufr);
    if (s->leng)
        s->bufr[0] = 0;
    s->leng = 0;
}

/*
 * Specify the size of the tail to keep (number of bytes from the end of the
 * buffer). The rest will be dropped.
 */
wintls_code wintls_dyn_tail(struct dynbuf* s, size_t trail)
{
    DEBUGASSERT(s);
#ifdef DEBUGBUILD
    DEBUGASSERT(s->init == DYNINIT);
#endif
    DEBUGASSERT(!s->leng || s->bufr);
    if (trail > s->leng)
        return WINTLS_BAD_FUNCTION_ARGUMENT;
    else if (trail == s->leng)
        return WINTLS_OK;
    else if (!trail) {
        wintls_dyn_reset(s);
    }
    else {
        memmove(&s->bufr[0], &s->bufr[s->leng - trail], trail);
        s->leng = trail;
        s->bufr[s->leng] = 0;
    }
    return WINTLS_OK;

}

/*
 * Appends a buffer with length.
 */
wintls_code wintls_dyn_addn(struct dynbuf* s, const void* mem, size_t len)
{
    DEBUGASSERT(s);
#ifdef DEBUGBUILD
    DEBUGASSERT(s->init == DYNINIT);
#endif
    DEBUGASSERT(!s->leng || s->bufr);
    return dyn_nappend(s, mem, len);
}

/*
 * Append a null-terminated string at the end.
 */
wintls_code wintls_dyn_add(struct dynbuf* s, const char* str)
{
    size_t n = strlen(str);
    DEBUGASSERT(s);
#ifdef DEBUGBUILD
    DEBUGASSERT(s->init == DYNINIT);
#endif
    DEBUGASSERT(!s->leng || s->bufr);
    return dyn_nappend(s, (unsigned char*)str, n);
}

/*
 * Append a string vprintf()-style
 */
wintls_code wintls_dyn_vaddf(struct dynbuf* s, const char* fmt, va_list ap)
{
#ifdef BUILDING_LIBWINTLS
    int rc;
    DEBUGASSERT(s);
    DEBUGASSERT(s->init == DYNINIT);
    DEBUGASSERT(!s->leng || s->bufr);
    rc = wintls_dyn_vprintf(s, fmt, ap);

    if (!rc)
        return WINTLS_OK;
#else
    char* str;
    str = vaprintf(fmt, ap); /* this allocs a new string to append */

    if (str) {
        wintls_code result = dyn_nappend(s, (unsigned char*)str, strlen(str));
        free(str);
        return result;
    }
    /* If we failed, we cleanup the whole buffer and return error */
    wintls_dyn_free(s);
#endif
    return WINTLS_OUT_OF_MEMORY;
}

/*
 * Append a string printf()-style
 */
wintls_code wintls_dyn_addf(struct dynbuf* s, const char* fmt, ...)
{
    wintls_code result;
    va_list ap;
    DEBUGASSERT(s);
#ifdef DEBUGBUILD
    DEBUGASSERT(s->init == DYNINIT);
#endif
    DEBUGASSERT(!s->leng || s->bufr);
    va_start(ap, fmt);
    result = wintls_dyn_vaddf(s, fmt, ap);
    va_end(ap);
    return result;
}

/*
 * Returns a pointer to the buffer.
 */
char* wintls_dyn_ptr(const struct dynbuf* s)
{
    DEBUGASSERT(s);
#ifdef DEBUGBUILD
    DEBUGASSERT(s->init == DYNINIT);
#endif
    DEBUGASSERT(!s->leng || s->bufr);
    return s->bufr;
}

/*
 * Returns an unsigned pointer to the buffer.
 */
unsigned char* wintls_dyn_uptr(const struct dynbuf* s)
{
    DEBUGASSERT(s);
#ifdef DEBUGBUILD
    DEBUGASSERT(s->init == DYNINIT);
#endif
    DEBUGASSERT(!s->leng || s->bufr);
    return (unsigned char*)s->bufr;
}

/*
 * Returns the length of the buffer.
 */
size_t wintls_dyn_len(const struct dynbuf* s)
{
    DEBUGASSERT(s);
#ifdef DEBUGBUILD
    DEBUGASSERT(s->init == DYNINIT);
#endif
    DEBUGASSERT(!s->leng || s->bufr);
    return s->leng;
}

/*
 * Set a new (smaller) length.
 */
wintls_code wintls_dyn_setlen(struct dynbuf* s, size_t set)
{
    DEBUGASSERT(s);
#ifdef DEBUGBUILD
    DEBUGASSERT(s->init == DYNINIT);
#endif
    DEBUGASSERT(!s->leng || s->bufr);
    if (set > s->leng)
        return WINTLS_BAD_FUNCTION_ARGUMENT;
    s->leng = set;
    s->bufr[s->leng] = 0;
    return WINTLS_OK;
}



/* ======================================================================
 * source: strcase.c
 ====================================================================== */



/* Mapping table to go from lowercase to uppercase for plain ASCII.*/
static const unsigned char touppermap[256] = {
0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78,
79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 65,
66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
85, 86, 87, 88, 89, 90, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133,
134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181,
182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197,
198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213,
214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229,
230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245,
246, 247, 248, 249, 250, 251, 252, 253, 254, 255
};

/* Mapping table to go from uppercase to lowercase for plain ASCII.*/
static const unsigned char tolowermap[256] = {
0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
62, 63, 64, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 91, 92, 93, 94, 95,
96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175,
176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207,
208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223,
224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255
};


/* Portable, consistent toupper. Do not use toupper() because its behavior is
   altered by the current locale. */
char wintls_raw_toupper(char in)
{
    return touppermap[(unsigned char)in];
}


/* Portable, consistent tolower. Do not use tolower() because its behavior is
   altered by the current locale. */
char wintls_raw_tolower(char in)
{
    return tolowermap[(unsigned char)in];
}

/*
 * wintls_strequal() is for doing "raw" case insensitive strings. This is meant
 * to be locale independent and only compare strings we know are safe for
 * this. See https://daniel.haxx.se/blog/2008/10/15/strcasecmp-in-turkish/ for
 * further explanations as to why this function is necessary.
 */

static int casecompare(const char* first, const char* second)
{
    while (*first && *second) {
        if (wintls_raw_toupper(*first) != wintls_raw_toupper(*second))
            /* get out of the loop as soon as they don't match */
            return 0;
        first++;
        second++;
    }
    /* If we're here either the strings are the same or the length is different.
       We can just test if the "current" character is non-zero for one and zero
       for the other. Note that the characters may not be exactly the same even
       if they match, we only want to compare zero-ness. */
    return !*first == !*second;
}

/* --- public function --- */
int wintls_strequal(const char* first, const char* second)
{
    if (first && second)
        /* both pointers point to something then compare them */
        return casecompare(first, second);

    /* if both pointers are NULL then treat them as equal */
    return (NULL == first && NULL == second);
}

static int ncasecompare(const char* first, const char* second, size_t max)
{
    while (*first && *second && max) {
        if (wintls_raw_toupper(*first) != wintls_raw_toupper(*second))
            return 0;
        max--;
        first++;
        second++;
    }
    if (0 == max)
        return 1; /* they are equal this far */

    return wintls_raw_toupper(*first) == wintls_raw_toupper(*second);
}

/* --- public function --- */
int wintls_strnequal(const char* first, const char* second, size_t max)
{
    if (first && second)
        /* both pointers point to something then compare them */
        return ncasecompare(first, second, max);

    /* if both pointers are NULL then treat them as equal if max is non-zero */
    return (NULL == first && NULL == second && max);
}
/* Copy an upper case version of the string from src to dest.  The
 * strings may overlap.  No more than n characters of the string are copied
 * (including any NUL) and the destination string will NOT be
 * NUL-terminated if that limit is reached.
 */
void wintls_strntoupper(char* dest, const char* src, size_t n)
{
    if (n < 1)
        return;

    do {
        *dest++ = wintls_raw_toupper(*src);
    } while (*src++ && --n);
}

/* Copy a lower case version of the string from src to dest.  The
 * strings may overlap.  No more than n characters of the string are copied
 * (including any NUL) and the destination string will NOT be
 * NUL-terminated if that limit is reached.
 */
void wintls_strntolower(char* dest, const char* src, size_t n)
{
    if (n < 1)
        return;

    do {
        *dest++ = wintls_raw_tolower(*src);
    } while (*src++ && --n);
}

/* Compare case-sensitive NUL-terminated strings, taking care of possible
 * null pointers. Return true if arguments match.
 */
BOOL wintls_safecmp(char* a, char* b)
{
    if (a && b)
        return !strcmp(a, b);
    return !a && !b;
}

/*
 * wintls_timestrcmp() returns 0 if the two strings are identical. The time this
 * function spends is a function of the shortest string, not of the contents.
 */
int wintls_timestrcmp(const char* a, const char* b)
{
    int match = 0;
    int i = 0;

    if (a && b) {
        while (1) {
            match |= a[i] ^ b[i];
            if (!a[i] || !b[i])
                break;
            i++;
        }
    }
    else
        return a || b;
    return match;
}



/* ======================================================================
 * source: wintls_multibyte.c
 ====================================================================== */



wchar_t* wintlsx_convert_UTF8_to_wchar(const char* str_utf8)
{
    wchar_t* str_w = NULL;

    if (str_utf8) {
        int str_w_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            str_utf8, -1, NULL, 0);
        if (str_w_len > 0) {
            str_w = malloc(str_w_len * sizeof(wchar_t));
            if (str_w) {
                if (MultiByteToWideChar(CP_UTF8, 0, str_utf8, -1, str_w,
                    str_w_len) == 0) {
                    free(str_w);
                    return NULL;
                }
            }
        }
    }

    return str_w;
}

char* wintlsx_convert_wchar_to_UTF8(const wchar_t* str_w)
{
    char* str_utf8 = NULL;

    if (str_w) {
        int bytes = WideCharToMultiByte(CP_UTF8, 0, str_w, -1,
            NULL, 0, NULL, NULL);
        if (bytes > 0) {
            str_utf8 = malloc(bytes);
            if (str_utf8) {
                if (WideCharToMultiByte(CP_UTF8, 0, str_w, -1, str_utf8, bytes,
                    NULL, NULL) == 0) {
                    free(str_utf8);
                    return NULL;
                }
            }
        }
    }

    return str_utf8;
}



/* ======================================================================
 * source: memrchr.c
 ====================================================================== */


void*
wintls_memrchr(const void* s, int c, size_t n)
{
    if (n > 0) {
        const unsigned char* p = s;
        const unsigned char* q = s;

        p += n - 1;

        while (p >= q) {
            if (*p == (unsigned char)c)
                return (void*)p;
            p--;
        }
    }
    return NULL;
}



/* ======================================================================
 * source: base64.c
 ====================================================================== */



 /* Base64 encoding/decoding */

#if !defined(WINTLS_DISABLE_HTTP_AUTH) || defined(USE_SSH) || \
  !defined(WINTLS_DISABLE_LDAP) || \
  !defined(WINTLS_DISABLE_SMTP) || \
  !defined(WINTLS_DISABLE_POP3) || \
  !defined(WINTLS_DISABLE_IMAP) || \
  !defined(WINTLS_DISABLE_DOH) || defined(USE_SSL)



/* ---- Base64 Encoding/Decoding Table --- */
/* Padding character string starts at offset 64. */
static const char base64[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/* The Base 64 encoding with a URL and filename safe alphabet, RFC 4648
   section 5 */
static const char base64url[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static const unsigned char decodetable[] =
{ 62, 255, 255, 255, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255,
  255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255, 255, 26, 27, 28,
  29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
  48, 49, 50, 51 };
/*
 * wintls_base64_decode()
 *
 * Given a base64 NUL-terminated string at src, decode it and return a
 * pointer in *outptr to a newly allocated memory area holding decoded
 * data. Size of decoded data is returned in variable pointed by outlen.
 *
 * Returns WINTLS_OK on success, otherwise specific error code. Function
 * output shall not be considered valid unless WINTLS_OK is returned.
 *
 * When decoded data length is 0, returns NULL in *outptr.
 *
 * @unittest: 1302
 */
wintls_code wintls_base64_decode(const char* src,
    unsigned char** outptr, size_t* outlen)
{
    size_t srclen = 0;
    size_t padding = 0;
    size_t i;
    size_t numQuantums;
    size_t fullQuantums;
    size_t rawlen = 0;
    unsigned char* pos;
    unsigned char* newstr;
    unsigned char lookup[256];

    *outptr = NULL;
    *outlen = 0;
    srclen = strlen(src);

    /* Check the length of the input string is valid */
    if (!srclen || srclen % 4)
        return WINTLS_BAD_CONTENT_ENCODING;

    /* srclen is at least 4 here */
    while (src[srclen - 1 - padding] == '=') {
        /* count padding characters */
        padding++;
        /* A maximum of two = padding characters is allowed */
        if (padding > 2)
            return WINTLS_BAD_CONTENT_ENCODING;
    }

    /* Calculate the number of quantums */
    numQuantums = srclen / 4;
    fullQuantums = numQuantums - (padding ? 1 : 0);

    /* Calculate the size of the decoded string */
    rawlen = (numQuantums * 3) - padding;

    /* Allocate our buffer including room for a null-terminator */
    newstr = malloc(rawlen + 1);
    if (!newstr)
        return WINTLS_OUT_OF_MEMORY;

    pos = newstr;

    memset(lookup, 0xff, sizeof(lookup));
    memcpy(&lookup['+'], decodetable, sizeof(decodetable));
    /* replaces
    {
      unsigned char c;
      const unsigned char *p = (const unsigned char *)base64;
      for(c = 0; *p; c++, p++)
        lookup[*p] = c;
    }
    */

    /* Decode the complete quantums first */
    for (i = 0; i < fullQuantums; i++) {
        unsigned char val;
        unsigned int x = 0;
        int j;

        for (j = 0; j < 4; j++) {
            val = lookup[(unsigned char)*src++];
            if (val == 0xff) /* bad symbol */
                goto bad;
            x = (x << 6) | val;
        }
        pos[2] = x & 0xff;
        pos[1] = (x >> 8) & 0xff;
        pos[0] = (x >> 16) & 0xff;
        pos += 3;
    }
    if (padding) {
        /* this means either 8 or 16 bits output */
        unsigned char val;
        unsigned int x = 0;
        int j;
        size_t padc = 0;
        for (j = 0; j < 4; j++) {
            if (*src == '=') {
                x <<= 6;
                src++;
                if (++padc > padding)
                    /* this is a badly placed '=' symbol! */
                    goto bad;
            }
            else {
                val = lookup[(unsigned char)*src++];
                if (val == 0xff) /* bad symbol */
                    goto bad;
                x = (x << 6) | val;
            }
        }
        if (padding == 1)
            pos[1] = (x >> 8) & 0xff;
        pos[0] = (x >> 16) & 0xff;
        pos += 3 - padding;
    }

    /* Zero terminate */
    *pos = '\0';

    /* Return the decoded data */
    *outptr = newstr;
    *outlen = rawlen;

    return WINTLS_OK;
bad:
    free(newstr);
    return WINTLS_BAD_CONTENT_ENCODING;
}

static wintls_code base64_encode(const char* table64,
    const char* inputbuff, size_t insize,
    char** outptr, size_t* outlen)
{
    char* output;
    char* base64data;
    const unsigned char* in = (unsigned char*)inputbuff;
    const char* padstr = &table64[64];    /* Point to padding string. */

    *outptr = NULL;
    *outlen = 0;

    if (!insize)
        insize = strlen(inputbuff);

#if SIZEOF_SIZE_T == 4
    if (insize > UINT_MAX / 4)
        return WINTLS_OUT_OF_MEMORY;
#endif

    base64data = output = malloc((insize + 2) / 3 * 4 + 1);
    if (!output)
        return WINTLS_OUT_OF_MEMORY;

    while (insize >= 3) {
        *output++ = table64[in[0] >> 2];
        *output++ = table64[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *output++ = table64[((in[1] & 0x0F) << 2) | ((in[2] & 0xC0) >> 6)];
        *output++ = table64[in[2] & 0x3F];
        insize -= 3;
        in += 3;
    }
    if (insize) {
        /* this is only one or two bytes now */
        *output++ = table64[in[0] >> 2];
        if (insize == 1) {
            *output++ = table64[((in[0] & 0x03) << 4)];
            if (*padstr) {
                *output++ = *padstr;
                *output++ = *padstr;
            }
        }
        else {
            /* insize == 2 */
            *output++ = table64[((in[0] & 0x03) << 4) | ((in[1] & 0xF0) >> 4)];
            *output++ = table64[((in[1] & 0x0F) << 2)];
            if (*padstr)
                *output++ = *padstr;
        }
    }

    /* Zero terminate */
    *output = '\0';

    /* Return the pointer to the new data (allocated memory) */
    *outptr = base64data;

    /* Return the length of the new data */
    *outlen = output - base64data;

    return WINTLS_OK;
}

/*
 * wintls_base64_encode()
 *
 * Given a pointer to an input buffer and an input size, encode it and
 * return a pointer in *outptr to a newly allocated memory area holding
 * encoded data. Size of encoded data is returned in variable pointed by
 * outlen.
 *
 * Input length of 0 indicates input buffer holds a NUL-terminated string.
 *
 * Returns WINTLS_OK on success, otherwise specific error code. Function
 * output shall not be considered valid unless WINTLS_OK is returned.
 *
 * @unittest: 1302
 */
wintls_code wintls_base64_encode(const char* inputbuff, size_t insize,
    char** outptr, size_t* outlen)
{
    return base64_encode(base64, inputbuff, insize, outptr, outlen);
}

/*
 * wintls_base64url_encode()
 *
 * Given a pointer to an input buffer and an input size, encode it and
 * return a pointer in *outptr to a newly allocated memory area holding
 * encoded data. Size of encoded data is returned in variable pointed by
 * outlen.
 *
 * Input length of 0 indicates input buffer holds a NUL-terminated string.
 *
 * Returns WINTLS_OK on success, otherwise specific error code. Function
 * output shall not be considered valid unless WINTLS_OK is returned.
 *
 * @unittest: 1302
 */
wintls_code wintls_base64url_encode(const char* inputbuff, size_t insize,
    char** outptr, size_t* outlen)
{
    return base64_encode(base64url, inputbuff, insize, outptr, outlen);
}

#endif /* no users so disabled */



/* ======================================================================
 * source: slist.c
 ====================================================================== */


/* returns last node in linked list */
static struct wintls_slist* slist_get_last(struct wintls_slist* list)
{
    struct wintls_slist* item;

    /* if caller passed us a NULL, return now */
    if (!list)
        return NULL;

    /* loop through to find the last item */
    item = list;
    while (item->next) {
        item = item->next;
    }
    return item;
}

/*
 * wintls_slist_append_nodup() appends a string to the linked list. Rather than
 * copying the string in dynamic storage, it takes its ownership. The string
 * should have been malloc()ated. wintls_slist_append_nodup always returns
 * the address of the first record, so that you can use this function as an
 * initialization function as well as an append function.
 * If an error occurs, NULL is returned and the string argument is NOT
 * released.
 */
struct wintls_slist* wintls_slist_append_nodup(struct wintls_slist* list, char* data)
{
    struct wintls_slist* last;
    struct wintls_slist* new_item;

    DEBUGASSERT(data);

    new_item = malloc(sizeof(struct wintls_slist));
    if (!new_item)
        return NULL;

    new_item->next = NULL;
    new_item->data = data;

    /* if this is the first item, then new_item *is* the list */
    if (!list)
        return new_item;

    last = slist_get_last(list);
    last->next = new_item;
    return list;
}

/*
 * wintls_slist_append() appends a string to the linked list. It always returns
 * the address of the first record, so that you can use this function as an
 * initialization function as well as an append function. If you find this
 * bothersome, then simply create a separate _init function and call it
 * appropriately from within the program.
 */
struct wintls_slist* wintls_slist_append(struct wintls_slist* list,
    const char* data)
{
    char* dupdata = strdup(data);

    if (!dupdata)
        return NULL;

    list = wintls_slist_append_nodup(list, dupdata);
    if (!list)
        free(dupdata);

    return list;
}

/*
 * wintls_slist_duplicate() duplicates a linked list. It always returns the
 * address of the first record of the cloned list or NULL in case of an
 * error (or if the input list was NULL).
 */
struct wintls_slist* wintls_slist_duplicate(struct wintls_slist* inlist)
{
    struct wintls_slist* outlist = NULL;
    struct wintls_slist* tmp;

    while (inlist) {
        tmp = wintls_slist_append(outlist, inlist->data);

        if (!tmp) {
            wintls_slist_free_all(outlist);
            return NULL;
        }

        outlist = tmp;
        inlist = inlist->next;
    }
    return outlist;
}

/* be nice and clean up resources */
void wintls_slist_free_all(struct wintls_slist* list)
{
    struct wintls_slist* next;
    struct wintls_slist* item;

    if (!list)
        return;

    item = list;
    do {
        next = item->next;
        wintls_safefree(item->data);
        free(item);
        item = next;
    } while (next);
}



/* ======================================================================
 * source: strerror.c
 ====================================================================== */



#if defined(WIN32) || defined(_WIN32_WCE)
/* This is a helper function for wintls_strerror that converts Windows API error
 * codes (GetLastError) to error messages.
 * Returns NULL if no error message was found for error code.
 */
static const char*
get_winapi_error(int err, char* buf, size_t buflen)
{
    char* p;
    wchar_t wbuf[256];

    if (!buflen)
        return NULL;

    *buf = '\0';
    *wbuf = L'\0';

    /* We return the local codepage version of the error string because if it is
       output to the user's terminal it will likely be with functions which
       expect the local codepage (eg fprintf, failf, infof).
       FormatMessageW -> wcstombs is used for Windows CE compatibility. */
    if (FormatMessageW((FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS), NULL, err,
        LANG_NEUTRAL, wbuf, sizeof(wbuf) / sizeof(wchar_t), NULL)) {
        size_t written = wcstombs(buf, wbuf, buflen - 1);
        if (written != (size_t)-1)
            buf[written] = '\0';
        else
            *buf = '\0';
    }

    /* Truncate multiple lines */
    p = strchr(buf, '\n');
    if (p) {
        if (p > buf && *(p - 1) == '\r')
            *(p - 1) = '\0';
        else
            *p = '\0';
    }

    return (*buf ? buf : NULL);
}
#endif /* WIN32 || _WIN32_WCE */


/*
 * wintls_winapi_strerror:
 * Variant of wintls_strerror if the error code is definitely Windows API.
 */
#if defined(WIN32) || defined(_WIN32_WCE)
const char* wintls_winapi_strerror(DWORD err, char* buf, size_t buflen)
{
#ifdef PRESERVE_WINDOWS_ERROR_CODE
    DWORD old_win_err = GetLastError();
#endif
    int old_errno = errno;

    if (!buflen)
        return NULL;

    *buf = '\0';

#ifndef WINTLS_DISABLE_VERBOSE_STRINGS
    if (!get_winapi_error(err, buf, buflen)) {
        msnprintf(buf, buflen, "Unknown error %u (0x%08X)", err, err);
    }
#else
    {
        const char* txt = (err == ERROR_SUCCESS) ? "No error" : "Error";
        strncpy(buf, txt, buflen);
        buf[buflen - 1] = '\0';
    }
#endif

    if (errno != old_errno)
        errno = old_errno;

#ifdef PRESERVE_WINDOWS_ERROR_CODE
    if (old_win_err != GetLastError())
        SetLastError(old_win_err);
#endif

    return buf;
}
#endif /* WIN32 || _WIN32_WCE */

/*
 * wintls_sspi_strerror:
 * Variant of wintls_strerror if the error code is definitely Windows SSPI.
 */
const char* wintls_sspi_strerror(int err, char* buf, size_t buflen)
{
#ifdef PRESERVE_WINDOWS_ERROR_CODE
    DWORD old_win_err = GetLastError();
#endif
    int old_errno = errno;
    const char* txt;

    if (!buflen)
        return NULL;

    *buf = '\0';

#ifndef WINTLS_DISABLE_VERBOSE_STRINGS

    switch (err) {
    case SEC_E_OK:
        txt = "No error";
        break;
#define SEC2TXT(sec) case sec: txt = #sec; break
        SEC2TXT(CRYPT_E_REVOKED);
        SEC2TXT(SEC_E_ALGORITHM_MISMATCH);
        SEC2TXT(SEC_E_BAD_BINDINGS);
        SEC2TXT(SEC_E_BAD_PKGID);
        SEC2TXT(SEC_E_BUFFER_TOO_SMALL);
        SEC2TXT(SEC_E_CANNOT_INSTALL);
        SEC2TXT(SEC_E_CANNOT_PACK);
        SEC2TXT(SEC_E_CERT_EXPIRED);
        SEC2TXT(SEC_E_CERT_UNKNOWN);
        SEC2TXT(SEC_E_CERT_WRONG_USAGE);
        SEC2TXT(SEC_E_CONTEXT_EXPIRED);
        SEC2TXT(SEC_E_CROSSREALM_DELEGATION_FAILURE);
        SEC2TXT(SEC_E_CRYPTO_SYSTEM_INVALID);
        SEC2TXT(SEC_E_DECRYPT_FAILURE);
        SEC2TXT(SEC_E_DELEGATION_POLICY);
        SEC2TXT(SEC_E_DELEGATION_REQUIRED);
        SEC2TXT(SEC_E_DOWNGRADE_DETECTED);
        SEC2TXT(SEC_E_ENCRYPT_FAILURE);
        SEC2TXT(SEC_E_ILLEGAL_MESSAGE);
        SEC2TXT(SEC_E_INCOMPLETE_CREDENTIALS);
        SEC2TXT(SEC_E_INCOMPLETE_MESSAGE);
        SEC2TXT(SEC_E_INSUFFICIENT_MEMORY);
        SEC2TXT(SEC_E_INTERNAL_ERROR);
        SEC2TXT(SEC_E_INVALID_HANDLE);
        SEC2TXT(SEC_E_INVALID_PARAMETER);
        SEC2TXT(SEC_E_INVALID_TOKEN);
        SEC2TXT(SEC_E_ISSUING_CA_UNTRUSTED);
        SEC2TXT(SEC_E_ISSUING_CA_UNTRUSTED_KDC);
        SEC2TXT(SEC_E_KDC_CERT_EXPIRED);
        SEC2TXT(SEC_E_KDC_CERT_REVOKED);
        SEC2TXT(SEC_E_KDC_INVALID_REQUEST);
        SEC2TXT(SEC_E_KDC_UNABLE_TO_REFER);
        SEC2TXT(SEC_E_KDC_UNKNOWN_ETYPE);
        SEC2TXT(SEC_E_LOGON_DENIED);
        SEC2TXT(SEC_E_MAX_REFERRALS_EXCEEDED);
        SEC2TXT(SEC_E_MESSAGE_ALTERED);
        SEC2TXT(SEC_E_MULTIPLE_ACCOUNTS);
        SEC2TXT(SEC_E_MUST_BE_KDC);
        SEC2TXT(SEC_E_NOT_OWNER);
        SEC2TXT(SEC_E_NO_AUTHENTICATING_AUTHORITY);
        SEC2TXT(SEC_E_NO_CREDENTIALS);
        SEC2TXT(SEC_E_NO_IMPERSONATION);
        SEC2TXT(SEC_E_NO_IP_ADDRESSES);
        SEC2TXT(SEC_E_NO_KERB_KEY);
        SEC2TXT(SEC_E_NO_PA_DATA);
        SEC2TXT(SEC_E_NO_S4U_PROT_SUPPORT);
        SEC2TXT(SEC_E_NO_TGT_REPLY);
        SEC2TXT(SEC_E_OUT_OF_SEQUENCE);
        SEC2TXT(SEC_E_PKINIT_CLIENT_FAILURE);
        SEC2TXT(SEC_E_PKINIT_NAME_MISMATCH);
        SEC2TXT(SEC_E_POLICY_NLTM_ONLY);
        SEC2TXT(SEC_E_QOP_NOT_SUPPORTED);
        SEC2TXT(SEC_E_REVOCATION_OFFLINE_C);
        SEC2TXT(SEC_E_REVOCATION_OFFLINE_KDC);
        SEC2TXT(SEC_E_SECPKG_NOT_FOUND);
        SEC2TXT(SEC_E_SECURITY_QOS_FAILED);
        SEC2TXT(SEC_E_SHUTDOWN_IN_PROGRESS);
        SEC2TXT(SEC_E_SMARTCARD_CERT_EXPIRED);
        SEC2TXT(SEC_E_SMARTCARD_CERT_REVOKED);
        SEC2TXT(SEC_E_SMARTCARD_LOGON_REQUIRED);
        SEC2TXT(SEC_E_STRONG_CRYPTO_NOT_SUPPORTED);
        SEC2TXT(SEC_E_TARGET_UNKNOWN);
        SEC2TXT(SEC_E_TIME_SKEW);
        SEC2TXT(SEC_E_TOO_MANY_PRINCIPALS);
        SEC2TXT(SEC_E_UNFINISHED_CONTEXT_DELETED);
        SEC2TXT(SEC_E_UNKNOWN_CREDENTIALS);
        SEC2TXT(SEC_E_UNSUPPORTED_FUNCTION);
        SEC2TXT(SEC_E_UNSUPPORTED_PREAUTH);
        SEC2TXT(SEC_E_UNTRUSTED_ROOT);
        SEC2TXT(SEC_E_WRONG_CREDENTIAL_HANDLE);
        SEC2TXT(SEC_E_WRONG_PRINCIPAL);
        SEC2TXT(SEC_I_COMPLETE_AND_CONTINUE);
        SEC2TXT(SEC_I_COMPLETE_NEEDED);
        SEC2TXT(SEC_I_CONTEXT_EXPIRED);
        SEC2TXT(SEC_I_CONTINUE_NEEDED);
        SEC2TXT(SEC_I_INCOMPLETE_CREDENTIALS);
        SEC2TXT(SEC_I_LOCAL_LOGON);
        SEC2TXT(SEC_I_NO_LSA_CONTEXT);
        SEC2TXT(SEC_I_RENEGOTIATE);
        SEC2TXT(SEC_I_SIGNATURE_NEEDED);
    default:
        txt = "Unknown error";
    }

    if (err == SEC_E_ILLEGAL_MESSAGE) {
        msnprintf(buf, buflen,
            "SEC_E_ILLEGAL_MESSAGE (0x%08X) - This error usually occurs "
            "when a fatal SSL/TLS alert is received (e.g. handshake failed)."
            " More detail may be available in the Windows System event log.",
            err);
    }
    else {
        char txtbuf[80];
        char msgbuf[256];

        msnprintf(txtbuf, sizeof(txtbuf), "%s (0x%08X)", txt, err);

        if (get_winapi_error(err, msgbuf, sizeof(msgbuf)))
            msnprintf(buf, buflen, "%s - %s", txtbuf, msgbuf);
        else {
            strncpy(buf, txtbuf, buflen);
            buf[buflen - 1] = '\0';
        }
    }

#else
    if (err == SEC_E_OK)
        txt = "No error";
    else
        txt = "Error";
    strncpy(buf, txt, buflen);
    buf[buflen - 1] = '\0';
#endif

    if (errno != old_errno)
        errno = old_errno;

#ifdef PRESERVE_WINDOWS_ERROR_CODE
    if (old_win_err != GetLastError())
        SetLastError(old_win_err);
#endif

    return buf;
}


/* ======================================================================
 * source: version_win32.c
 ====================================================================== */



/* This Unicode version struct works for VerifyVersionInfoW (OSVERSIONINFOEXW)
   and RtlVerifyVersionInfo (RTLOSVERSIONINFOEXW) */
struct OUR_OSVERSIONINFOEXW {
    ULONG  dwOSVersionInfoSize;
    ULONG  dwMajorVersion;
    ULONG  dwMinorVersion;
    ULONG  dwBuildNumber;
    ULONG  dwPlatformId;
    WCHAR  szCSDVersion[128];
    USHORT wServicePackMajor;
    USHORT wServicePackMinor;
    USHORT wSuiteMask;
    UCHAR  wProductType;
    UCHAR  wReserved;
};

/*
 * wintlsx_verify_windows_version()
 *
 * This is used to verify if we are running on a specific windows version.
 *
 * Parameters:
 *
 * majorVersion [in] - The major version number.
 * minorVersion [in] - The minor version number.
 * buildVersion [in] - The build version number. If 0, this parameter is
 *                     ignored.
 * platform     [in] - The optional platform identifier.
 * condition    [in] - The test condition used to specifier whether we are
 *                     checking a version less then, equal to or greater than
 *                     what is specified in the major and minor version
 *                     numbers.
 *
 * Returns TRUE if matched; otherwise FALSE.
 */
BOOL wintlsx_verify_windows_version(const unsigned int majorVersion,
    const unsigned int minorVersion,
    const unsigned int buildVersion,
    const PlatformIdentifier platform,
    const VersionCondition condition)
{
    BOOL matched = FALSE;

#if defined(WINTLS_WINDOWS_APP)
    (void)buildVersion;

    /* We have no way to determine the Windows version from Windows apps,
       so let's assume we're running on the target Windows version. */
    const WORD fullVersion = MAKEWORD(minorVersion, majorVersion);
    const WORD targetVersion = (WORD)_WIN32_WINNT;

    switch (condition) {
    case VERSION_LESS_THAN:
        matched = targetVersion < fullVersion;
        break;

    case VERSION_LESS_THAN_EQUAL:
        matched = targetVersion <= fullVersion;
        break;

    case VERSION_EQUAL:
        matched = targetVersion == fullVersion;
        break;

    case VERSION_GREATER_THAN_EQUAL:
        matched = targetVersion >= fullVersion;
        break;

    case VERSION_GREATER_THAN:
        matched = targetVersion > fullVersion;
        break;
    }

    if (matched && (platform == PLATFORM_WINDOWS)) {
        /* we're always running on PLATFORM_WINNT */
        matched = FALSE;
    }
#elif !defined(_WIN32_WINNT) || !defined(_WIN32_WINNT_WIN2K) || \
    (_WIN32_WINNT < _WIN32_WINNT_WIN2K)
    OSVERSIONINFO osver;

    memset(&osver, 0, sizeof(osver));
    osver.dwOSVersionInfoSize = sizeof(osver);

    /* Find out Windows version */
    if (GetVersionEx(&osver)) {
        /* Verify the Operating System version number */
        switch (condition) {
        case VERSION_LESS_THAN:
            if (osver.dwMajorVersion < majorVersion ||
                (osver.dwMajorVersion == majorVersion &&
                    osver.dwMinorVersion < minorVersion) ||
                (buildVersion != 0 &&
                    (osver.dwMajorVersion == majorVersion &&
                        osver.dwMinorVersion == minorVersion &&
                        osver.dwBuildNumber < buildVersion)))
                matched = TRUE;
            break;

        case VERSION_LESS_THAN_EQUAL:
            if (osver.dwMajorVersion < majorVersion ||
                (osver.dwMajorVersion == majorVersion &&
                    osver.dwMinorVersion < minorVersion) ||
                (osver.dwMajorVersion == majorVersion &&
                    osver.dwMinorVersion == minorVersion &&
                    (buildVersion == 0 ||
                        osver.dwBuildNumber <= buildVersion)))
                matched = TRUE;
            break;

        case VERSION_EQUAL:
            if (osver.dwMajorVersion == majorVersion &&
                osver.dwMinorVersion == minorVersion &&
                (buildVersion == 0 ||
                    osver.dwBuildNumber == buildVersion))
                matched = TRUE;
            break;

        case VERSION_GREATER_THAN_EQUAL:
            if (osver.dwMajorVersion > majorVersion ||
                (osver.dwMajorVersion == majorVersion &&
                    osver.dwMinorVersion > minorVersion) ||
                (osver.dwMajorVersion == majorVersion &&
                    osver.dwMinorVersion == minorVersion &&
                    (buildVersion == 0 ||
                        osver.dwBuildNumber >= buildVersion)))
                matched = TRUE;
            break;

        case VERSION_GREATER_THAN:
            if (osver.dwMajorVersion > majorVersion ||
                (osver.dwMajorVersion == majorVersion &&
                    osver.dwMinorVersion > minorVersion) ||
                (buildVersion != 0 &&
                    (osver.dwMajorVersion == majorVersion &&
                        osver.dwMinorVersion == minorVersion &&
                        osver.dwBuildNumber > buildVersion)))
                matched = TRUE;
            break;
        }

        /* Verify the platform identifier (if necessary) */
        if (matched) {
            switch (platform) {
            case PLATFORM_WINDOWS:
                if (osver.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS)
                    matched = FALSE;
                break;

            case PLATFORM_WINNT:
                if (osver.dwPlatformId != VER_PLATFORM_WIN32_NT)
                    matched = FALSE;
                break;

            default: /* like platform == PLATFORM_DONT_CARE */
                break;
            }
        }
    }
#else
    ULONGLONG cm = 0;
    struct OUR_OSVERSIONINFOEXW osver;
    BYTE majorCondition;
    BYTE minorCondition;
    BYTE buildCondition;
    BYTE spMajorCondition;
    BYTE spMinorCondition;
    DWORD dwTypeMask = VER_MAJORVERSION | VER_MINORVERSION |
        VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR;

    typedef LONG(APIENTRY* RTLVERIFYVERSIONINFO_FN)
        (struct OUR_OSVERSIONINFOEXW*, ULONG, ULONGLONG);
    static RTLVERIFYVERSIONINFO_FN pRtlVerifyVersionInfo;
    static BOOL onetime = TRUE; /* safe because first call is during init */

    if (onetime) {
        pRtlVerifyVersionInfo = WINTLSX_FUNCTION_CAST(RTLVERIFYVERSIONINFO_FN,
            (GetProcAddress(GetModuleHandleA("ntdll"), "RtlVerifyVersionInfo")));
        onetime = FALSE;
    }

    switch (condition) {
    case VERSION_LESS_THAN:
        majorCondition = VER_LESS;
        minorCondition = VER_LESS;
        buildCondition = VER_LESS;
        spMajorCondition = VER_LESS_EQUAL;
        spMinorCondition = VER_LESS_EQUAL;
        break;

    case VERSION_LESS_THAN_EQUAL:
        majorCondition = VER_LESS_EQUAL;
        minorCondition = VER_LESS_EQUAL;
        buildCondition = VER_LESS_EQUAL;
        spMajorCondition = VER_LESS_EQUAL;
        spMinorCondition = VER_LESS_EQUAL;
        break;

    case VERSION_EQUAL:
        majorCondition = VER_EQUAL;
        minorCondition = VER_EQUAL;
        buildCondition = VER_EQUAL;
        spMajorCondition = VER_GREATER_EQUAL;
        spMinorCondition = VER_GREATER_EQUAL;
        break;

    case VERSION_GREATER_THAN_EQUAL:
        majorCondition = VER_GREATER_EQUAL;
        minorCondition = VER_GREATER_EQUAL;
        buildCondition = VER_GREATER_EQUAL;
        spMajorCondition = VER_GREATER_EQUAL;
        spMinorCondition = VER_GREATER_EQUAL;
        break;

    case VERSION_GREATER_THAN:
        majorCondition = VER_GREATER;
        minorCondition = VER_GREATER;
        buildCondition = VER_GREATER;
        spMajorCondition = VER_GREATER_EQUAL;
        spMinorCondition = VER_GREATER_EQUAL;
        break;

    default:
        return FALSE;
    }

    memset(&osver, 0, sizeof(osver));
    osver.dwOSVersionInfoSize = sizeof(osver);
    osver.dwMajorVersion = majorVersion;
    osver.dwMinorVersion = minorVersion;
    osver.dwBuildNumber = buildVersion;
    if (platform == PLATFORM_WINDOWS)
        osver.dwPlatformId = VER_PLATFORM_WIN32_WINDOWS;
    else if (platform == PLATFORM_WINNT)
        osver.dwPlatformId = VER_PLATFORM_WIN32_NT;

    cm = VerSetConditionMask(cm, VER_MAJORVERSION, majorCondition);
    cm = VerSetConditionMask(cm, VER_MINORVERSION, minorCondition);
    cm = VerSetConditionMask(cm, VER_SERVICEPACKMAJOR, spMajorCondition);
    cm = VerSetConditionMask(cm, VER_SERVICEPACKMINOR, spMinorCondition);

    if (platform != PLATFORM_DONT_CARE) {
        cm = VerSetConditionMask(cm, VER_PLATFORMID, VER_EQUAL);
        dwTypeMask |= VER_PLATFORMID;
    }

    /* Later versions of Windows have version functions that may not return the
       real version of Windows unless the application is so manifested. We prefer
       the real version always, so we use the Rtl variant of the function when
       possible. Note though the function signatures have underlying fundamental
       types that are the same, the return values are different. */
    if (pRtlVerifyVersionInfo)
        matched = !pRtlVerifyVersionInfo(&osver, dwTypeMask, cm);
    else
        matched = !!VerifyVersionInfoW((OSVERSIONINFOEXW*)&osver, dwTypeMask, cm);

    /* Compare the build number separately. VerifyVersionInfo normally compares
       major.minor in hierarchical order (eg 1.9 is less than 2.0) but does not
       do the same for build (eg 1.9 build 222 is not less than 2.0 build 111).
       Build comparison is only needed when build numbers are equal (eg 1.9 is
       always less than 2.0 so build comparison is not needed). */
    if (matched && buildVersion &&
        (condition == VERSION_EQUAL ||
            ((condition == VERSION_GREATER_THAN_EQUAL ||
                condition == VERSION_LESS_THAN_EQUAL) &&
                wintlsx_verify_windows_version(majorVersion, minorVersion, 0,
                    platform, VERSION_EQUAL)))) {

        cm = VerSetConditionMask(0, VER_BUILDNUMBER, buildCondition);
        dwTypeMask = VER_BUILDNUMBER;
        if (pRtlVerifyVersionInfo)
            matched = !pRtlVerifyVersionInfo(&osver, dwTypeMask, cm);
        else
            matched = !!VerifyVersionInfoW((OSVERSIONINFOEXW*)&osver,
                dwTypeMask, cm);
    }

#endif

    return matched;
}



/* ======================================================================
 * source: system_win32.c
 ====================================================================== */


LARGE_INTEGER wintls_freq;
BOOL wintls_isVistaOrGreater;

/* Handle of iphlpapp.dll */
static HMODULE s_hIpHlpApiDll = NULL;

/* Pointer to the if_nametoindex function */
IF_NAMETOINDEX_FN wintls_if_nametoindex = NULL;

/* wintls_win32_init() performs win32 global initialization */
extern wintls_code wintls_win32_init(long flags)
{
    /* WINTLS_GLOBAL_WIN32 controls the *optional* part of the initialization which
       is just for Winsock at the moment. Any required win32 initialization
       should take place after this block. */
    if (flags & WINTLS_GLOBAL_WIN32) {
        WORD wVersionRequested;
        WSADATA wsaData;
        int res;

        wVersionRequested = MAKEWORD(2, 2);
        res = WSAStartup(wVersionRequested, &wsaData);

        if (res)
            /* Tell the user that we couldn't find a usable */
            /* winsock.dll.     */
            return WINTLS_FAILED_INIT;

        /* Confirm that the Windows Sockets DLL supports what we need.*/
        /* Note that if the DLL supports versions greater */
        /* than wVersionRequested, it will still return */
        /* wVersionRequested in wVersion. wHighVersion contains the */
        /* highest supported version. */

        if (LOBYTE(wsaData.wVersion) != LOBYTE(wVersionRequested) ||
            HIBYTE(wsaData.wVersion) != HIBYTE(wVersionRequested)) {
            /* Tell the user that we couldn't find a usable */

            /* winsock.dll. */
            WSACleanup();
            return WINTLS_FAILED_INIT;
        }
    } /* WINTLS_GLOBAL_WIN32 */

    {
        wintls_code result = wintls_sspi_global_init();
        if (result)
            return result;
    }

    s_hIpHlpApiDll = LoadLibraryA("iphlpapi.dll");
    if (s_hIpHlpApiDll) {
        /* Get the address of the if_nametoindex function */
        IF_NAMETOINDEX_FN pIfNameToIndex =
            WINTLSX_FUNCTION_CAST(IF_NAMETOINDEX_FN,
                (GetProcAddress(s_hIpHlpApiDll, "if_nametoindex")));

        if (pIfNameToIndex)
            wintls_if_nametoindex = pIfNameToIndex;
    }

    /* wintlsx_verify_windows_version must be called during init at least once
       because it has its own initialization routine. */
    if (wintlsx_verify_windows_version(6, 0, 0, PLATFORM_WINNT,
        VERSION_GREATER_THAN_EQUAL)) {
        wintls_isVistaOrGreater = TRUE;
    }
    else
        wintls_isVistaOrGreater = FALSE;

    QueryPerformanceFrequency(&wintls_freq);
    return WINTLS_OK;
}

/* wintls_win32_cleanup() is the opposite of wintls_win32_init() */
void wintls_win32_cleanup(long init_flags)
{
    if (s_hIpHlpApiDll) {
        FreeLibrary(s_hIpHlpApiDll);
        s_hIpHlpApiDll = NULL;
        wintls_if_nametoindex = NULL;
    }

    wintls_sspi_global_cleanup();

    if (init_flags & WINTLS_GLOBAL_WIN32) {
        WSACleanup();
    }
}

#if !defined(LOAD_WITH_ALTERED_SEARCH_PATH)
#define LOAD_WITH_ALTERED_SEARCH_PATH  0x00000008
#endif

#if !defined(LOAD_LIBRARY_SEARCH_SYSTEM32)
#define LOAD_LIBRARY_SEARCH_SYSTEM32   0x00000800
#endif

/* We use our own typedef here since some headers might lack these */
typedef HMODULE(APIENTRY* LOADLIBRARYEX_FN)(LPCTSTR, HANDLE, DWORD);

/* See function definitions in winbase.h */
#ifdef UNICODE
#  ifdef _WIN32_WCE
#    define LOADLIBARYEX  L"LoadLibraryExW"
#  else
#    define LOADLIBARYEX  "LoadLibraryExW"
#  endif
#else
#  define LOADLIBARYEX    "LoadLibraryExA"
#endif

/*
 * wintls_load_library()
 *
 * This is used to dynamically load DLLs using the most secure method available
 * for the version of Windows that we are running on.
 *
 * Parameters:
 *
 * filename  [in] - The filename or full path of the DLL to load. If only the
 *                  filename is passed then the DLL will be loaded from the
 *                  Windows system directory.
 *
 * Returns the handle of the module on success; otherwise NULL.
 */
HMODULE wintls_load_library(LPCTSTR filename)
{
#ifndef WINTLS_WINDOWS_APP
    HMODULE hModule = NULL;
    LOADLIBRARYEX_FN pLoadLibraryEx = NULL;

    /* Get a handle to kernel32 so we can access it's functions at runtime */
    HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32"));
    if (!hKernel32)
        return NULL;

    /* Attempt to find LoadLibraryEx() which is only available on Windows 2000
       and above */
    pLoadLibraryEx =
        WINTLSX_FUNCTION_CAST(LOADLIBRARYEX_FN,
            (GetProcAddress(hKernel32, LOADLIBARYEX)));

    /* Detect if there's already a path in the filename and load the library if
       there is. Note: Both back slashes and forward slashes have been supported
       since the earlier days of DOS at an API level although they are not
       supported by command prompt */
    if (strpbrk(filename, TEXT("\\/"))) {
        /** !checksrc! disable BANNEDFUNC 1 **/
        hModule = pLoadLibraryEx ?
            pLoadLibraryEx(filename, NULL, LOAD_WITH_ALTERED_SEARCH_PATH) :
            LoadLibrary(filename);
    }
    /* Detect if KB2533623 is installed, as LOAD_LIBRARY_SEARCH_SYSTEM32 is only
       supported on Windows Vista, Windows Server 2008, Windows 7 and Windows
       Server 2008 R2 with this patch or natively on Windows 8 and above */
    else if (pLoadLibraryEx && GetProcAddress(hKernel32, "AddDllDirectory")) {
        /* Load the DLL from the Windows system directory */
        hModule = pLoadLibraryEx(filename, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
    else {
        /* Attempt to get the Windows system path */
        UINT systemdirlen = GetSystemDirectory(NULL, 0);
        if (systemdirlen) {
            /* Allocate space for the full DLL path (Room for the null terminator
               is included in systemdirlen) */
            size_t filenamelen = strlen(filename);
            int n = systemdirlen + 1 + filenamelen;
            char path = (char*)malloc(n * sizeof(char));
            if (path && GetSystemDirectory(path, systemdirlen)) {
                /* Calculate the full DLL path */
                strcpy_s(path + strlen(path), 1, "\\");
                strcpy_s(path + strlen(path), strlen(filename), filename);

                /* Load the DLL from the Windows system directory */
                /** !checksrc! disable BANNEDFUNC 1 **/
                hModule = pLoadLibraryEx ?
                    pLoadLibraryEx(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH) :
                    LoadLibrary(path);

            }
            free(path);
        }
    }
    return hModule;
#else
    /* the Universal Windows Platform (UWP) can't do this */
    (void)filename;
    return NULL;
#endif
}



/* ======================================================================
 * source: timeleft.c
 ====================================================================== */



/*
 * wintls_timeleft() returns the amount of milliseconds left allowed for the
 * transfer/connection. If the value is 0, there's no timeout (ie there's
 * infinite time left). If the value is negative, the timeout time has already
 * elapsed.
 *
 * If 'nowp' is non-NULL, it points to the current time.
 * 'duringconnect' is FALSE if not during a connect, as then of course the
 * connect timeout is not taken into account!
 *
 * @unittest: 1303
 */
#include <limits.h>
#define TIMEOUT_CONNECT 1
#define TIMEOUT_MAXTIME 2

#include <time.h>

struct timeval* wintlsx_mstotv(struct timeval* tv, timediff_t ms)
{
    if (!tv)
        return NULL;

    if (ms < 0)
        return NULL;

    if (ms > 0) {
        timediff_t tv_sec = ms / 1000;
        timediff_t tv_usec = (ms % 1000) * 1000; /* max=999999 */
#ifdef HAVE_SUSECONDS_T
#if TIMEDIFF_T_MAX > TIME_T_MAX
        /* tv_sec overflow check in case time_t is signed */
        if (tv_sec > TIME_T_MAX)
            tv_sec = TIME_T_MAX;
#endif
        tv->tv_sec = (time_t)tv_sec;
        tv->tv_usec = (suseconds_t)tv_usec;
#elif defined(WIN32) /* maybe also others in the future */
#if TIMEDIFF_T_MAX > LONG_MAX
        /* tv_sec overflow check on Windows there we know it is long */
        if (tv_sec > LONG_MAX)
            tv_sec = LONG_MAX;
#endif
        tv->tv_sec = (long)tv_sec;
        tv->tv_usec = (long)tv_usec;
#else
#if TIMEDIFF_T_MAX > INT_MAX
        /* tv_sec overflow check in case time_t is signed */
        if (tv_sec > INT_MAX)
            tv_sec = INT_MAX;
#endif
        tv->tv_sec = (int)tv_sec;
        tv->tv_usec = (int)tv_usec;
#endif
    }
    else {
        tv->tv_sec = 0;
        tv->tv_usec = 0;
    }

    return tv;
}

/*
 * Converts a timeval structure into number of milliseconds.
 */
timediff_t wintlsx_tvtoms(struct timeval* tv)
{
    return (tv->tv_sec * 1000) + (timediff_t)(((double)tv->tv_usec) / 1000.0);
}


timediff_t wintls_timeleft(struct wintls* tls,
    struct wintlstime* nowp,
    BOOL duringconnect)
{
    unsigned int timeout_set = 0;
    timediff_t connect_timeout_ms = 0;
    timediff_t maxtime_timeout_ms = 0;
    timediff_t timeout_ms = 0;
    struct wintlstime now;

    /* The duration of a connect and the total transfer are calculated from two
       different time-stamps. It can end up with the total timeout being reached
       before the connect timeout expires and we must acknowledge whichever
       timeout that is reached first. The total timeout is set per entire
       operation, while the connect timeout is set per connect. */

    if (tls->timeout > 0) {
        timeout_set = TIMEOUT_MAXTIME;
        maxtime_timeout_ms = tls->timeout;
    }
    if (duringconnect) {
        timeout_set |= TIMEOUT_CONNECT;
        connect_timeout_ms = (tls->connecttimeout > 0) ?
            tls->connecttimeout : DEFAULT_CONNECT_TIMEOUT;
    }
    if (!timeout_set)
        /* no timeout  */
        return 0;

    if (!nowp) {
        now = wintls_now();
        nowp = &now;
    }

    if (timeout_set & TIMEOUT_MAXTIME) {
        maxtime_timeout_ms -= wintls_timediff(*nowp, tls->t_startop);
        timeout_ms = maxtime_timeout_ms;
    }

    if (timeout_set & TIMEOUT_CONNECT) {
        connect_timeout_ms -= wintls_timediff(*nowp, tls->t_startsingle);

        if (!(timeout_set & TIMEOUT_MAXTIME) ||
            (connect_timeout_ms < maxtime_timeout_ms))
            timeout_ms = connect_timeout_ms;
    }

    if (!timeout_ms)
        /* avoid returning 0 as that means no timeout! */
        return -1;

    return timeout_ms;
}

/* set in win32_init() */
extern LARGE_INTEGER wintls_freq;
extern BOOL wintls_isVistaOrGreater;
timediff_t wintls_timediff(struct wintlstime newer, struct wintlstime older)
{
    timediff_t diff = (timediff_t)newer.tv_sec - older.tv_sec;
    if (diff >= (LONG_MAX / 1000))
        return LONG_MAX;
    else if (diff <= (LONG_MIN / 1000))
        return LONG_MIN;
    return diff * 1000 + (newer.tv_usec - older.tv_usec) / 1000;
}

/* In case of bug fix this function has a counterpart in tool_util.c */
struct wintlstime wintls_now(void)
{
    struct wintlstime now;
    if (wintls_isVistaOrGreater) { /* QPC timer might have issues pre-Vista */
        LARGE_INTEGER count;
        QueryPerformanceCounter(&count);
        now.tv_sec = (time_t)(count.QuadPart / wintls_freq.QuadPart);
        now.tv_usec = (int)((count.QuadPart % wintls_freq.QuadPart) * 1000000 /
            wintls_freq.QuadPart);
    }
    else {
        /* Disable /analyze warning that GetTickCount64 is preferred  */
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:28159)
#endif
        DWORD milliseconds = GetTickCount();
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

        now.tv_sec = milliseconds / 1000;
        now.tv_usec = (milliseconds % 1000) * 1000;
    }
    return now;
}


/* ======================================================================
 * source: select.c
 ====================================================================== */

#include <limits.h>

/*
 * Internal function used for waiting a specific amount of ms
 * in wintls_socket_check() and wintls_poll() when no file descriptor
 * is provided to wait on, just being used to delay execution.
 * WinSock select() and poll() timeout mechanisms need a valid
 * socket descriptor in a not null file descriptor set to work.
 * Waiting indefinitely with this function is not allowed, a
 * zero or negative timeout value will return immediately.
 * Timeout resolution, accuracy, as well as maximum supported
 * value is system dependent, neither factor is a critical issue
 * for the intended use of this function in the library.
 *
 * Return values:
 *   -1 = system call error, or invalid timeout value
 *    0 = specified timeout has elapsed, or interrupted
 */
int wintls_wait_ms(timediff_t timeout_ms)
{
    int r = 0;

    if (!timeout_ms)
        return 0;
    if (timeout_ms < 0) {
        //SET_SOCKERRNO(WSAEINVAL);
        return -1;
    }
#if defined(MSDOS)
    delay(timeout_ms);
#elif defined(WIN32)
    /* prevent overflow, timeout_ms is typecast to ULONG/DWORD. */
#if TIMEDIFF_T_MAX >= ULONG_MAX
    if (timeout_ms >= ULONG_MAX)
        timeout_ms = ULONG_MAX - 1;
    /* don't use ULONG_MAX, because that is equal to INFINITE */
#endif
    Sleep(timeout_ms);
#else
#if defined(HAVE_POLL_FINE)
    /* prevent overflow, timeout_ms is typecast to int. */
#if TIMEDIFF_T_MAX > INT_MAX
    if (timeout_ms > INT_MAX)
        timeout_ms = INT_MAX;
#endif
    r = poll(NULL, 0, (int)timeout_ms);
#else
    {
        struct timeval pending_tv;
        r = select(0, NULL, NULL, NULL, wintlsx_mstotv(&pending_tv, timeout_ms));
    }
#endif /* HAVE_POLL_FINE */
#endif /* USE_WINSOCK */
    if (r) {
        if ((r == -1) && (WSAGetLastError() == EINTR))
            /* make EINTR from select or poll not a "lethal" error */
            r = 0;
        else
            r = -1;
    }
    return r;
}

#ifndef HAVE_POLL_FINE
/*
 * This is a wrapper around select() to aid in Windows compatibility.
 * A negative timeout value makes this function wait indefinitely,
 * unless no valid file descriptor is given, when this happens the
 * negative timeout is ignored and the function times out immediately.
 *
 * Return values:
 *   -1 = system call error or fd >= FD_SETSIZE
 *    0 = timeout
 *    N = number of signalled file descriptors
 */
static int our_select(SOCKET maxfd,   /* highest socket number */
    fd_set* fds_read,      /* sockets ready for reading */
    fd_set* fds_write,     /* sockets ready for writing */
    fd_set* fds_err,       /* sockets with errors */
    timediff_t timeout_ms) /* milliseconds to wait */
{
    struct timeval pending_tv;
    struct timeval* ptimeout;

    /* WinSock select() can't handle zero events.  See the comment below. */
    if ((!fds_read || fds_read->fd_count == 0) &&
        (!fds_write || fds_write->fd_count == 0) &&
        (!fds_err || fds_err->fd_count == 0)) {
        /* no sockets, just wait */
        return wintls_wait_ms(timeout_ms);
    }
    ptimeout = wintlsx_mstotv(&pending_tv, timeout_ms);

    /* WinSock select() must not be called with an fd_set that contains zero
      fd flags, or it will return WSAEINVAL.  But, it also can't be called
      with no fd_sets at all!  From the documentation:

      Any two of the parameters, readfds, writefds, or exceptfds, can be
      given as null. At least one must be non-null, and any non-null
      descriptor set must contain at least one handle to a socket.

      It is unclear why WinSock doesn't just handle this for us instead of
      calling this an error. Luckily, with WinSock, we can _also_ ask how
      many bits are set on an fd_set. So, let's just check it beforehand.
    */
    return select((int)maxfd + 1,
        fds_read && fds_read->fd_count ? fds_read : NULL,
        fds_write && fds_write->fd_count ? fds_write : NULL,
        fds_err && fds_err->fd_count ? fds_err : NULL, ptimeout);
}

#endif

/*
 * Wait for read or write events on a set of file descriptors. It uses poll()
 * when a fine poll() is available, in order to avoid limits with FD_SETSIZE,
 * otherwise select() is used.  An error is returned if select() is being used
 * and a file descriptor is too large for FD_SETSIZE.
 *
 * A negative timeout value makes this function wait indefinitely,
 * unless no valid file descriptor is given, when this happens the
 * negative timeout is ignored and the function times out immediately.
 *
 * Return values:
 *   -1 = system call error or fd >= FD_SETSIZE
 *    0 = timeout
 *    [bitmask] = action as described below
 *
 * WINTLS_CSELECT_IN - first socket is readable
 * WINTLS_CSELECT_IN2 - second socket is readable
 * WINTLS_CSELECT_OUT - write socket is writable
 * WINTLS_CSELECT_ERR - an error condition occurred
 */
int wintls_socket_check(SOCKET socket, /* socket to write to */
    timediff_t timeout_ms) /* milliseconds to wait */
{
    struct pollfd pfd[3];
    int num;
    int r;

    if (socket == WINTLS_SOCKET_BAD) {
        /* no sockets, just wait */
        return wintls_wait_ms(timeout_ms);
    }

    /* Avoid initial timestamp, avoid wintls_now() call, when elapsed
       time in this function does not need to be measured. This happens
       when function is called with a zero timeout or a negative timeout
       value indicating a blocking call should be performed. */

    num = 0;
    if (socket != WINTLS_SOCKET_BAD) {
        pfd[num].fd = socket;
        pfd[num].events = POLLRDNORM | POLLIN | POLLRDBAND | POLLPRI;
        pfd[num].revents = 0;
        num++;

        pfd[num].fd = socket;
        pfd[num].events = POLLWRNORM | POLLOUT | POLLPRI;
        pfd[num].revents = 0;
    }

    r = wintls_poll(pfd, num, timeout_ms);
    if (r <= 0)
        return r;

    r = 0;
    num = 0;
    if (socket != WINTLS_SOCKET_BAD) {
        if (pfd[num].revents & (POLLRDNORM | POLLIN | POLLERR | POLLHUP))
            r |= WINTLS_CSELECT_IN;
        if (pfd[num].revents & (POLLPRI | POLLNVAL))
            r |= WINTLS_CSELECT_ERR;
        num++;
        if (pfd[num].revents & (POLLWRNORM | POLLOUT))
            r |= WINTLS_CSELECT_OUT;
        if (pfd[num].revents & (POLLERR | POLLHUP | POLLPRI | POLLNVAL))
            r |= WINTLS_CSELECT_ERR;
    }

    return r;
}

/*
 * This is a wrapper around poll().  If poll() does not exist, then
 * select() is used instead.  An error is returned if select() is
 * being used and a file descriptor is too large for FD_SETSIZE.
 * A negative timeout value makes this function wait indefinitely,
 * unless no valid file descriptor is given, when this happens the
 * negative timeout is ignored and the function times out immediately.
 *
 * Return values:
 *   -1 = system call error or fd >= FD_SETSIZE
 *    0 = timeout
 *    N = number of structures with non zero revent fields
 */
int wintls_poll(struct pollfd ufds[], unsigned int nfds, timediff_t timeout_ms)
{
#ifdef HAVE_POLL_FINE
    int pending_ms;
#else
    fd_set fds_read;
    fd_set fds_write;
    fd_set fds_err;
    SOCKET maxfd;
#endif
    BOOL fds_none = TRUE;
    unsigned int i;
    int r;

    if (ufds) {
        for (i = 0; i < nfds; i++) {
            if (ufds[i].fd != WINTLS_SOCKET_BAD) {
                fds_none = FALSE;
                break;
            }
        }
    }
    if (fds_none) {
        /* no sockets, just wait */
        return wintls_wait_ms(timeout_ms);
    }

    /* Avoid initial timestamp, avoid wintls_now() call, when elapsed
       time in this function does not need to be measured. This happens
       when function is called with a zero timeout or a negative timeout
       value indicating a blocking call should be performed. */

#ifdef HAVE_POLL_FINE

       /* prevent overflow, timeout_ms is typecast to int. */
#if TIMEDIFF_T_MAX > INT_MAX
    if (timeout_ms > INT_MAX)
        timeout_ms = INT_MAX;
#endif
    if (timeout_ms > 0)
        pending_ms = (int)timeout_ms;
    else if (timeout_ms < 0)
        pending_ms = -1;
    else
        pending_ms = 0;
    r = poll(ufds, nfds, pending_ms);
    if (r <= 0) {
        if ((r == -1) && (SOCKERRNO == EINTR))
            /* make EINTR from select or poll not a "lethal" error */
            r = 0;
        return r;
    }

    for (i = 0; i < nfds; i++) {
        if (ufds[i].fd == WINTLS_SOCKET_BAD)
            continue;
        if (ufds[i].revents & POLLHUP)
            ufds[i].revents |= POLLIN;
        if (ufds[i].revents & POLLERR)
            ufds[i].revents |= POLLIN | POLLOUT;
    }

#else  /* HAVE_POLL_FINE */

    FD_ZERO(&fds_read);
    FD_ZERO(&fds_write);
    FD_ZERO(&fds_err);
    maxfd = (SOCKET)-1;

    for (i = 0; i < nfds; i++) {
        ufds[i].revents = 0;
        if (ufds[i].fd == WINTLS_SOCKET_BAD)
            continue;
        VERIFY_SOCK(ufds[i].fd);
        if (ufds[i].events & (POLLIN | POLLOUT | POLLPRI |
            POLLRDNORM | POLLWRNORM | POLLRDBAND)) {
            if (ufds[i].fd > maxfd)
                maxfd = ufds[i].fd;
            if (ufds[i].events & (POLLRDNORM | POLLIN))
                FD_SET(ufds[i].fd, &fds_read);
            if (ufds[i].events & (POLLWRNORM | POLLOUT))
                FD_SET(ufds[i].fd, &fds_write);
            if (ufds[i].events & (POLLRDBAND | POLLPRI))
                FD_SET(ufds[i].fd, &fds_err);
        }
    }

    /*
       Note also that WinSock ignores the first argument, so we don't worry
       about the fact that maxfd is computed incorrectly with WinSock (since
       wintls_socket_t is unsigned in such cases and thus -1 is the largest
       value).
    */
    r = our_select(maxfd, &fds_read, &fds_write, &fds_err, timeout_ms);
    if (r <= 0) {
        if ((r == -1) && (WSAGetLastError() == EINTR))
            /* make EINTR from select or poll not a "lethal" error */
            r = 0;
        return r;
    }

    r = 0;
    for (i = 0; i < nfds; i++) {
        ufds[i].revents = 0;
        if (ufds[i].fd == WINTLS_SOCKET_BAD)
            continue;
        if (FD_ISSET(ufds[i].fd, &fds_read)) {
            if (ufds[i].events & POLLRDNORM)
                ufds[i].revents |= POLLRDNORM;
            if (ufds[i].events & POLLIN)
                ufds[i].revents |= POLLIN;
        }
        if (FD_ISSET(ufds[i].fd, &fds_write)) {
            if (ufds[i].events & POLLWRNORM)
                ufds[i].revents |= POLLWRNORM;
            if (ufds[i].events & POLLOUT)
                ufds[i].revents |= POLLOUT;
        }
        if (FD_ISSET(ufds[i].fd, &fds_err)) {
            if (ufds[i].events & POLLRDBAND)
                ufds[i].revents |= POLLRDBAND;
            if (ufds[i].events & POLLPRI)
                ufds[i].revents |= POLLPRI;
        }
        if (ufds[i].revents)
            r++;
    }

#endif  /* HAVE_POLL_FINE */

    return r;
}



/* ======================================================================
 * source: hostcheck.c
 ====================================================================== */






 /*
  * wintls_host_is_ipnum() returns TRUE if the given string is a numerical IPv4
  * (or IPv6 if supported) address.
  */
BOOL wintls_host_is_ipnum(const char* hostname)
{
    struct in_addr in;
#ifdef ENABLE_IPV6
    struct in6_addr in6;
#endif
    if (inet_pton(AF_INET, hostname, &in) > 0
#ifdef ENABLE_IPV6
        || wintls_inet_pton(AF_INET6, hostname, &in6) > 0
#endif
        )
        return TRUE;
    return FALSE;
}


/* check the two input strings with given length, but do not
   assume they end in nul-bytes */
static BOOL pmatch(const char* hostname, size_t hostlen,
    const char* pattern, size_t patternlen)
{
    if (hostlen != patternlen)
        return FALSE;
    return strncasecompare(hostname, pattern, hostlen);
}

/*
 * Match a hostname against a wildcard pattern.
 * E.g.
 *  "foo.host.com" matches "*.host.com".
 *
 * We use the matching rule described in RFC6125, section 6.4.3.
 * https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.3
 *
 * In addition: ignore trailing dots in the host names and wildcards, so that
 * the names are used normalized. This is what the browsers do.
 *
 * Do not allow wildcard matching on IP numbers. There are apparently
 * certificates being used with an IP address in the CN field, thus making no
 * apparent distinction between a name and an IP. We need to detect the use of
 * an IP address and not wildcard match on such names.
 *
 * Only match on "*" being used for the leftmost label, not "a*", "a*b" nor
 * "*b".
 *
 * Return TRUE on a match. FALSE if not.
 *
 * @unittest: 1397
 */

static BOOL hostmatch(const char* hostname,
    size_t hostlen,
    const char* pattern,
    size_t patternlen)
{
    const char* pattern_label_end;

    DEBUGASSERT(pattern);
    DEBUGASSERT(patternlen);
    DEBUGASSERT(hostname);
    DEBUGASSERT(hostlen);

    /* normalize pattern and hostname by stripping off trailing dots */
    if (hostname[hostlen - 1] == '.')
        hostlen--;
    if (pattern[patternlen - 1] == '.')
        patternlen--;

    if (strncmp(pattern, "*.", 2))
        return pmatch(hostname, hostlen, pattern, patternlen);

    /* detect IP address as hostname and fail the match if so */
    else if (wintls_host_is_ipnum(hostname))
        return FALSE;

    /* We require at least 2 dots in the pattern to avoid too wide wildcard
       match. */
    pattern_label_end = memchr(pattern, '.', patternlen);
    if (!pattern_label_end ||
        (memrchr(pattern, '.', patternlen) == pattern_label_end))
        return pmatch(hostname, hostlen, pattern, patternlen);
    else {
        const char* hostname_label_end = memchr(hostname, '.', hostlen);
        if (hostname_label_end) {
            size_t skiphost = hostname_label_end - hostname;
            size_t skiplen = pattern_label_end - pattern;
            return pmatch(hostname_label_end, hostlen - skiphost,
                pattern_label_end, patternlen - skiplen);
        }
    }
    return FALSE;
}

/*
 * wintls_cert_hostcheck() returns TRUE if a match and FALSE if not.
 */
BOOL wintls_cert_hostcheck(const char* match, size_t matchlen,
    const char* hostname, size_t hostlen)
{
    if (match && *match && hostname && *hostname)
        return hostmatch(hostname, hostlen, match, matchlen);
    return FALSE;
}



/* ======================================================================
 * source: wintls_sspi.c
 ====================================================================== */





#define WINTLS_MASK_ULONG   ((unsigned long)~0)
#define WINTLS_MASK_SLONG   (WINTLS_MASK_ULONG >> 1)

unsigned long wintlsx_uztoul(size_t uznum)
{
#ifdef __INTEL_COMPILER
# pragma warning(push)
# pragma warning(disable:810) /* conversion may lose significant bits */
#endif

#if ULONG_MAX < SIZE_T_MAX
    DEBUGASSERT(uznum <= (size_t)WINTLS_MASK_ULONG);
#endif
    return (unsigned long)(uznum & (size_t)WINTLS_MASK_ULONG);

#ifdef __INTEL_COMPILER
# pragma warning(pop)
#endif
}

/* We use our own typedef here since some headers might lack these */
typedef PSecurityFunctionTable(APIENTRY* INITSECURITYINTERFACE_FN)(VOID);

/* See definition of SECURITY_ENTRYPOINT in sspi.h */
#ifdef UNICODE
#  ifdef _WIN32_WCE
#    define SECURITYENTRYPOINT L"InitSecurityInterfaceW"
#  else
#    define SECURITYENTRYPOINT "InitSecurityInterfaceW"
#  endif
#else
#  define SECURITYENTRYPOINT "InitSecurityInterfaceA"
#endif

/* Handle of security.dll or secur32.dll, depending on Windows version */
HMODULE s_hSecDll = 0;

/* Pointer to SSPI dispatch table */
PSecurityFunctionTable s_pSecFn = NULL;

/*
 * wintls_sspi_global_init()
 *
 * This is used to load the Security Service Provider Interface (SSPI)
 * dynamic link library portably across all Windows versions, without
 * the need to directly link libwintls, nor the application using it, at
 * build time.
 *
 * Once this function has been executed, Windows SSPI functions can be
 * called through the Security Service Provider Interface dispatch table.
 *
 * Parameters:
 *
 * None.
 *
 * Returns WINTLS_OK on success.
 */
wintls_code wintls_sspi_global_init(void)
{
    INITSECURITYINTERFACE_FN pInitSecurityInterface;

    /* If security interface is not yet initialized try to do this */
    if (!s_hSecDll) {
        /* Security Service Provider Interface (SSPI) functions are located in
         * security.dll on WinNT 4.0 and in secur32.dll on Win9x. Win2K and XP
         * have both these DLLs (security.dll forwards calls to secur32.dll) */

         /* Load SSPI dll into the address space of the calling process */
        ///if (wintlsx_verify_windows_version(4, 0, 0, PLATFORM_WINNT, VERSION_EQUAL))
        //    s_hSecDll = wintls_load_library(TEXT("security.dll"));
        //else
        s_hSecDll = LoadLibraryA("secur32.dll");
        if (!s_hSecDll)
            return WINTLS_FAILED_INIT;

        /* Get address of the InitSecurityInterfaceA function from the SSPI dll */
        void* sspitest = GetProcAddress(s_hSecDll, SECURITYENTRYPOINT);
        pInitSecurityInterface = WINTLSX_FUNCTION_CAST(INITSECURITYINTERFACE_FN, sspitest);
        if (!pInitSecurityInterface)
            return WINTLS_FAILED_INIT;

        /* Get pointer to Security Service Provider Interface dispatch table */
        s_pSecFn = pInitSecurityInterface();
        if (!s_pSecFn)
            return WINTLS_FAILED_INIT;
    }

    return WINTLS_OK;
}

/*
 * wintls_sspi_global_cleanup()
 *
 * This deinitializes the Security Service Provider Interface from libwintls.
 *
 * Parameters:
 *
 * None.
 */
void wintls_sspi_global_cleanup(void)
{
    if (s_hSecDll) {
        FreeLibrary(s_hSecDll);
        s_hSecDll = NULL;
        s_pSecFn = NULL;
    }
}

/*
 * wintls_create_sspi_identity()
 *
 * This is used to populate a SSPI identity structure based on the supplied
 * username and password.
 *
 * Parameters:
 *
 * userp    [in]     - The user name in the format User or Domain\User.
 * passwdp  [in]     - The user's password.
 * identity [in/out] - The identity structure.
 *
 * Returns WINTLS_OK on success.
 */
wintls_code wintls_create_sspi_identity(const char* userp, const char* passwdp,
    SEC_WINNT_AUTH_IDENTITY* identity)
{
    xcharp_u useranddomain;
    xcharp_u user, dup_user;
    xcharp_u domain, dup_domain;
    xcharp_u passwd, dup_passwd;
    size_t domlen = 0;

    domain.const_tchar_ptr = TEXT("");

    /* Initialize the identity */
    memset(identity, 0, sizeof(*identity));

    useranddomain.tchar_ptr = wintlsx_convert_UTF8_to_tchar((char*)userp);
    if (!useranddomain.tchar_ptr)
        return WINTLS_OUT_OF_MEMORY;

    user.const_tchar_ptr = _tcschr(useranddomain.const_tchar_ptr, TEXT('\\'));
    if (!user.const_tchar_ptr)
        user.const_tchar_ptr = _tcschr(useranddomain.const_tchar_ptr, TEXT('/'));

    if (user.tchar_ptr) {
        domain.tchar_ptr = useranddomain.tchar_ptr;
        domlen = user.tchar_ptr - useranddomain.tchar_ptr;
        user.tchar_ptr++;
    }
    else {
        user.tchar_ptr = useranddomain.tchar_ptr;
        domain.const_tchar_ptr = TEXT("");
        domlen = 0;
    }

    /* Setup the identity's user and length */
    dup_user.tchar_ptr = strdup(user.tchar_ptr);//TODO
    if (!dup_user.tchar_ptr) {
        wintlsx_unicodefree(useranddomain.tchar_ptr);
        return WINTLS_OUT_OF_MEMORY;
    }
    identity->User = dup_user.tbyte_ptr;
    identity->UserLength = wintlsx_uztoul(_tcslen(dup_user.tchar_ptr));
    dup_user.tchar_ptr = NULL;

    /* Setup the identity's domain and length */
    dup_domain.tchar_ptr = malloc(sizeof(TCHAR) * (domlen + 1));
    if (!dup_domain.tchar_ptr) {
        wintlsx_unicodefree(useranddomain.tchar_ptr);
        return WINTLS_OUT_OF_MEMORY;
    }
    _tcsncpy(dup_domain.tchar_ptr, domain.tchar_ptr, domlen);
    *(dup_domain.tchar_ptr + domlen) = TEXT('\0');
    identity->Domain = dup_domain.tbyte_ptr;
    identity->DomainLength = wintlsx_uztoul(domlen);
    dup_domain.tchar_ptr = NULL;

    wintlsx_unicodefree(useranddomain.tchar_ptr);

    /* Setup the identity's password and length */
    passwd.tchar_ptr = wintlsx_convert_UTF8_to_tchar((char*)passwdp);
    if (!passwd.tchar_ptr)
        return WINTLS_OUT_OF_MEMORY;
    dup_passwd.tchar_ptr = strdup(passwd.tchar_ptr);// TODO
    if (!dup_passwd.tchar_ptr) {
        wintlsx_unicodefree(passwd.tchar_ptr);
        return WINTLS_OUT_OF_MEMORY;
    }
    identity->Password = dup_passwd.tbyte_ptr;
    identity->PasswordLength = wintlsx_uztoul(_tcslen(dup_passwd.tchar_ptr));
    dup_passwd.tchar_ptr = NULL;

    wintlsx_unicodefree(passwd.tchar_ptr);

    /* Setup the identity's flags */
    identity->Flags = SECFLAG_WINNT_AUTH_IDENTITY;

    return WINTLS_OK;
}

/*
 * wintls_sspi_free_identity()
 *
 * This is used to free the contents of a SSPI identifier structure.
 *
 * Parameters:
 *
 * identity [in/out] - The identity structure.
 */
void wintls_sspi_free_identity(SEC_WINNT_AUTH_IDENTITY* identity)
{
    if (identity) {
        wintls_safefree(identity->User);
        wintls_safefree(identity->Password);
        wintls_safefree(identity->Domain);
    }
}


/* ======================================================================
 * source: x509asn1.c
 ====================================================================== */

#define WANT_PARSEX509 /* uses wintls_parseX509() */

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <stdio.h>
#include <limits.h>

#define EXPOSE_SCHANNEL_INTERNAL_STRUCTS

/*
 * Constants.
 */

 /* Largest supported ASN.1 structure. */
#define WINTLS_ASN1_MAX                   ((size_t) 0x40000)      /* 256K */

/* ASN.1 classes. */
#define WINTLS_ASN1_UNIVERSAL             0
#define WINTLS_ASN1_APPLICATION           1
#define WINTLS_ASN1_CONTEXT_SPECIFIC      2
#define WINTLS_ASN1_PRIVATE               3

/* ASN.1 types. */
#define WINTLS_ASN1_BOOLEAN               1
#define WINTLS_ASN1_INTEGER               2
#define WINTLS_ASN1_BIT_STRING            3
#define WINTLS_ASN1_OCTET_STRING          4
#define WINTLS_ASN1_NULL                  5
#define WINTLS_ASN1_OBJECT_IDENTIFIER     6
#define WINTLS_ASN1_OBJECT_DESCRIPTOR     7
#define WINTLS_ASN1_INSTANCE_OF           8
#define WINTLS_ASN1_REAL                  9
#define WINTLS_ASN1_ENUMERATED            10
#define WINTLS_ASN1_EMBEDDED              11
#define WINTLS_ASN1_UTF8_STRING           12
#define WINTLS_ASN1_RELATIVE_OID          13
#define WINTLS_ASN1_SEQUENCE              16
#define WINTLS_ASN1_SET                   17
#define WINTLS_ASN1_NUMERIC_STRING        18
#define WINTLS_ASN1_PRINTABLE_STRING      19
#define WINTLS_ASN1_TELETEX_STRING        20
#define WINTLS_ASN1_VIDEOTEX_STRING       21
#define WINTLS_ASN1_IA5_STRING            22
#define WINTLS_ASN1_UTC_TIME              23
#define WINTLS_ASN1_GENERALIZED_TIME      24
#define WINTLS_ASN1_GRAPHIC_STRING        25
#define WINTLS_ASN1_VISIBLE_STRING        26
#define WINTLS_ASN1_GENERAL_STRING        27
#define WINTLS_ASN1_UNIVERSAL_STRING      28
#define WINTLS_ASN1_CHARACTER_STRING      29
#define WINTLS_ASN1_BMP_STRING            30

/* ASN.1 OID table entry. */
struct wintls_OID {
    const char* numoid;  /* Dotted-numeric OID. */
    const char* textoid; /* OID name. */
};

/* ASN.1 OIDs. */
static const char       cnOID[] = "2.5.4.3";    /* Common name. */
static const char       sanOID[] = "2.5.29.17"; /* Subject alternative name. */

static const struct wintls_OID OIDtable[] = {
  { "1.2.840.10040.4.1",        "dsa" },
  { "1.2.840.10040.4.3",        "dsa-with-sha1" },
  { "1.2.840.10045.2.1",        "ecPublicKey" },
  { "1.2.840.10045.3.0.1",      "c2pnb163v1" },
  { "1.2.840.10045.4.1",        "ecdsa-with-SHA1" },
  { "1.2.840.10046.2.1",        "dhpublicnumber" },
  { "1.2.840.113549.1.1.1",     "rsaEncryption" },
  { "1.2.840.113549.1.1.2",     "md2WithRSAEncryption" },
  { "1.2.840.113549.1.1.4",     "md5WithRSAEncryption" },
  { "1.2.840.113549.1.1.5",     "sha1WithRSAEncryption" },
  { "1.2.840.113549.1.1.10",    "RSASSA-PSS" },
  { "1.2.840.113549.1.1.14",    "sha224WithRSAEncryption" },
  { "1.2.840.113549.1.1.11",    "sha256WithRSAEncryption" },
  { "1.2.840.113549.1.1.12",    "sha384WithRSAEncryption" },
  { "1.2.840.113549.1.1.13",    "sha512WithRSAEncryption" },
  { "1.2.840.113549.2.2",       "md2" },
  { "1.2.840.113549.2.5",       "md5" },
  { "1.3.14.3.2.26",            "sha1" },
  { cnOID,                      "CN" },
  { "2.5.4.4",                  "SN" },
  { "2.5.4.5",                  "serialNumber" },
  { "2.5.4.6",                  "C" },
  { "2.5.4.7",                  "L" },
  { "2.5.4.8",                  "ST" },
  { "2.5.4.9",                  "streetAddress" },
  { "2.5.4.10",                 "O" },
  { "2.5.4.11",                 "OU" },
  { "2.5.4.12",                 "title" },
  { "2.5.4.13",                 "description" },
  { "2.5.4.17",                 "postalCode" },
  { "2.5.4.41",                 "name" },
  { "2.5.4.42",                 "givenName" },
  { "2.5.4.43",                 "initials" },
  { "2.5.4.44",                 "generationQualifier" },
  { "2.5.4.45",                 "X500UniqueIdentifier" },
  { "2.5.4.46",                 "dnQualifier" },
  { "2.5.4.65",                 "pseudonym" },
  { "1.2.840.113549.1.9.1",     "emailAddress" },
  { "2.5.4.72",                 "role" },
  { sanOID,                     "subjectAltName" },
  { "2.5.29.18",                "issuerAltName" },
  { "2.5.29.19",                "basicConstraints" },
  { "2.16.840.1.101.3.4.2.4",   "sha224" },
  { "2.16.840.1.101.3.4.2.1",   "sha256" },
  { "2.16.840.1.101.3.4.2.2",   "sha384" },
  { "2.16.840.1.101.3.4.2.3",   "sha512" },
  { (const char*)NULL,        (const char*)NULL }
};


/*
 * Lightweight ASN.1 parser.
 * In particular, it does not check for syntactic/lexical errors.
 * It is intended to support certificate information gathering for SSL backends
 * that offer a mean to get certificates as a whole, but do not supply
 * entry points to get particular certificate sub-fields.
 * Please note there is no pretension here to rewrite a full SSL library.
 */
static const char* getASN1Element(struct wintls_asn1Element* elem,
    const char* beg, const char* end);

static const char* getASN1Element(struct wintls_asn1Element* elem,
    const char* beg, const char* end)
{
    unsigned char b;
    size_t len;
    struct wintls_asn1Element lelem;

    /* Get a single ASN.1 element into `elem', parse ASN.1 string at `beg'
       ending at `end'.
       Returns a pointer in source string after the parsed element, or NULL
       if an error occurs. */
    if (!beg || !end || beg >= end || !*beg ||
        (size_t)(end - beg) > WINTLS_ASN1_MAX)
        return NULL;

    /* Process header byte. */
    elem->header = beg;
    b = (unsigned char)*beg++;
    elem->constructed = (b & 0x20) != 0;
    elem->class = (b >> 6) & 3;
    b &= 0x1F;
    if (b == 0x1F)
        return NULL; /* Long tag values not supported here. */
    elem->tag = b;

    /* Process length. */
    if (beg >= end)
        return NULL;
    b = (unsigned char)*beg++;
    if (!(b & 0x80))
        len = b;
    else if (!(b &= 0x7F)) {
        /* Unspecified length. Since we have all the data, we can determine the
           effective length by skipping element until an end element is found. */
        if (!elem->constructed)
            return NULL;
        elem->beg = beg;
        while (beg < end && *beg) {
            beg = getASN1Element(&lelem, beg, end);
            if (!beg)
                return NULL;
        }
        if (beg >= end)
            return NULL;
        elem->end = beg;
        return beg + 1;
    }
    else if ((unsigned)b > (size_t)(end - beg))
        return NULL; /* Does not fit in source. */
    else {
        /* Get long length. */
        len = 0;
        do {
            if (len & 0xFF000000L)
                return NULL;  /* Lengths > 32 bits are not supported. */
            len = (len << 8) | (unsigned char)*beg++;
        } while (--b);
    }
    if (len > (size_t)(end - beg))
        return NULL;  /* Element data does not fit in source. */
    elem->beg = beg;
    elem->end = beg + len;
    return elem->end;
}

/*
 * Search the null terminated OID or OID identifier in local table.
 * Return the table entry pointer or NULL if not found.
 */
static const struct wintls_OID* searchOID(const char* oid)
{
    const struct wintls_OID* op;
    for (op = OIDtable; op->numoid; op++)
        if (!strcmp(op->numoid, oid) || strcasecompare(op->textoid, oid))
            return op;

    return NULL;
}

/*
 * Convert an ASN.1 Boolean value into its string representation.  Return the
 * dynamically allocated string, or NULL if source is not an ASN.1 Boolean
 * value.
 */

static const char* bool2str(const char* beg, const char* end)
{
    if (end - beg != 1)
        return NULL;
    return strdup(*beg ? "TRUE" : "FALSE");
}

/*
 * Convert an ASN.1 octet string to a printable string.
 * Return the dynamically allocated string, or NULL if an error occurs.
 */
static const char* octet2str(const char* beg, const char* end)
{
    struct dynbuf buf;
    wintls_code result;

    wintls_dyn_init(&buf, 3 * WINTLS_ASN1_MAX + 1);
    result = wintls_dyn_addn(&buf, "", 0);

    while (!result && beg < end)
        result = wintls_dyn_addf(&buf, "%02x:", (unsigned char)*beg++);

    return wintls_dyn_ptr(&buf);
}

static const char* bit2str(const char* beg, const char* end)
{
    /* Convert an ASN.1 bit string to a printable string.
       Return the dynamically allocated string, or NULL if an error occurs. */

    if (++beg > end)
        return NULL;
    return octet2str(beg, end);
}

/*
 * Convert an ASN.1 integer value into its string representation.
 * Return the dynamically allocated string, or NULL if source is not an
 * ASN.1 integer value.
 */
static const char* int2str(const char* beg, const char* end)
{
    unsigned int val = 0;
    size_t n = end - beg;

    if (!n)
        return NULL;

    if (n > 4)
        return octet2str(beg, end);

    /* Represent integers <= 32-bit as a single value. */
    if (*beg & 0x80)
        val = ~val;

    do
        val = (val << 8) | *(const unsigned char*)beg++;
    while (beg < end);
    return wintls_maprintf("%s%x", val >= 10 ? "0x" : "", val);
}

/*
 * Perform a lazy conversion from an ASN.1 typed string to UTF8. Allocate the
 * destination buffer dynamically. The allocation size will normally be too
 * large: this is to avoid buffer overflows.
 * Terminate the string with a nul byte and return the converted
 * string length.
 */
static ssize_t
utf8asn1str(char** to, int type, const char* from, const char* end)
{
    size_t inlength = end - from;
    int size = 1;
    size_t outlength;
    char* buf;

    *to = NULL;
    switch (type) {
    case WINTLS_ASN1_BMP_STRING:
        size = 2;
        break;
    case WINTLS_ASN1_UNIVERSAL_STRING:
        size = 4;
        break;
    case WINTLS_ASN1_NUMERIC_STRING:
    case WINTLS_ASN1_PRINTABLE_STRING:
    case WINTLS_ASN1_TELETEX_STRING:
    case WINTLS_ASN1_IA5_STRING:
    case WINTLS_ASN1_VISIBLE_STRING:
    case WINTLS_ASN1_UTF8_STRING:
        break;
    default:
        return -1;  /* Conversion not supported. */
    }

    if (inlength % size)
        return -1;  /* Length inconsistent with character size. */
    if (inlength / size > (SIZE_MAX - 1) / 4)
        return -1;  /* Too big. */
    buf = malloc(4 * (inlength / size) + 1);
    if (!buf)
        return -1;  /* Not enough memory. */

    if (type == WINTLS_ASN1_UTF8_STRING) {
        /* Just copy. */
        outlength = inlength;
        if (outlength)
            memcpy(buf, from, outlength);
    }
    else {
        for (outlength = 0; from < end;) {
            int charsize;
            unsigned int wc;

            wc = 0;
            switch (size) {
            case 4:
                wc = (wc << 8) | *(const unsigned char*)from++;
                wc = (wc << 8) | *(const unsigned char*)from++;
                /* FALLTHROUGH */
            case 2:
                wc = (wc << 8) | *(const unsigned char*)from++;
                /* FALLTHROUGH */
            default: /* case 1: */
                wc = (wc << 8) | *(const unsigned char*)from++;
            }
            charsize = 1;
            if (wc >= 0x00000080) {
                if (wc >= 0x00000800) {
                    if (wc >= 0x00010000) {
                        if (wc >= 0x00200000) {
                            free(buf);
                            return -1;        /* Invalid char. size for target encoding. */
                        }
                        buf[outlength + 3] = (char)(0x80 | (wc & 0x3F));
                        wc = (wc >> 6) | 0x00010000;
                        charsize++;
                    }
                    buf[outlength + 2] = (char)(0x80 | (wc & 0x3F));
                    wc = (wc >> 6) | 0x00000800;
                    charsize++;
                }
                buf[outlength + 1] = (char)(0x80 | (wc & 0x3F));
                wc = (wc >> 6) | 0x000000C0;
                charsize++;
            }
            buf[outlength] = (char)wc;
            outlength += charsize;
        }
    }
    buf[outlength] = '\0';
    *to = buf;
    return outlength;
}

/*
 * Convert an ASN.1 String into its UTF-8 string representation.
 * Return the dynamically allocated string, or NULL if an error occurs.
 */
static const char* string2str(int type, const char* beg, const char* end)
{
    char* buf;
    if (utf8asn1str(&buf, type, beg, end) < 0)
        return NULL;
    return buf;
}

/*
 * Decimal ASCII encode unsigned integer `x' into the buflen sized buffer at
 * buf.  Return the total number of encoded digits, even if larger than
 * `buflen'.
 */
static size_t encodeUint(char* buf, size_t buflen, unsigned int x)
{
    size_t i = 0;
    unsigned int y = x / 10;

    if (y) {
        i = encodeUint(buf, buflen, y);
        x -= y * 10;
    }
    if (i < buflen)
        buf[i] = (char)('0' + x);
    i++;
    if (i < buflen)
        buf[i] = '\0';      /* Store a terminator if possible. */
    return i;
}

/*
 * Convert an ASN.1 OID into its dotted string representation.
 * Store the result in th `n'-byte buffer at `buf'.
 * Return the converted string length, or 0 on errors.
 */
static size_t encodeOID(char* buf, size_t buflen,
    const char* beg, const char* end)
{
    size_t i;
    unsigned int x;
    unsigned int y;

    /* Process the first two numbers. */
    y = *(const unsigned char*)beg++;
    x = y / 40;
    y -= x * 40;
    i = encodeUint(buf, buflen, x);
    if (i < buflen)
        buf[i] = '.';
    i++;
    if (i >= buflen)
        i += encodeUint(NULL, 0, y);
    else
        i += encodeUint(buf + i, buflen - i, y);

    /* Process the trailing numbers. */
    while (beg < end) {
        if (i < buflen)
            buf[i] = '.';
        i++;
        x = 0;
        do {
            if (x & 0xFF000000)
                return 0;
            y = *(const unsigned char*)beg++;
            x = (x << 7) | (y & 0x7F);
        } while (y & 0x80);
        if (i >= buflen)
            i += encodeUint(NULL, 0, x);
        else
            i += encodeUint(buf + i, buflen - i, x);
    }
    if (i < buflen)
        buf[i] = '\0';
    return i;
}

/*
 * Convert an ASN.1 OID into its dotted or symbolic string representation.
 * Return the dynamically allocated string, or NULL if an error occurs.
 */

static const char* OID2str(const char* beg, const char* end, BOOL symbolic)
{
    char* buf = NULL;
    if (beg < end) {
        size_t buflen = encodeOID(NULL, 0, beg, end);
        if (buflen) {
            buf = malloc(buflen + 1); /* one extra for the zero byte */
            if (buf) {
                encodeOID(buf, buflen, beg, end);
                buf[buflen] = '\0';

                if (symbolic) {
                    const struct wintls_OID* op = searchOID(buf);
                    if (op) {
                        free(buf);
                        buf = strdup(op->textoid);
                    }
                }
            }
        }
    }
    return buf;
}

static const char* GTime2str(const char* beg, const char* end)
{
    const char* tzp;
    const char* fracp;
    char sec1, sec2;
    size_t fracl;
    size_t tzl;
    const char* sep = "";

    /* Convert an ASN.1 Generalized time to a printable string.
       Return the dynamically allocated string, or NULL if an error occurs. */

    for (fracp = beg; fracp < end && *fracp >= '0' && *fracp <= '9'; fracp++)
        ;

    /* Get seconds digits. */
    sec1 = '0';
    switch (fracp - beg - 12) {
    case 0:
        sec2 = '0';
        break;
    case 2:
        sec1 = fracp[-2];
        /* FALLTHROUGH */
    case 1:
        sec2 = fracp[-1];
        break;
    default:
        return NULL;
    }

    /* Scan for timezone, measure fractional seconds. */
    tzp = fracp;
    fracl = 0;
    if (fracp < end && (*fracp == '.' || *fracp == ',')) {
        fracp++;
        do
            tzp++;
        while (tzp < end && *tzp >= '0' && *tzp <= '9');
        /* Strip leading zeroes in fractional seconds. */
        for (fracl = tzp - fracp - 1; fracl && fracp[fracl - 1] == '0'; fracl--)
            ;
    }

    /* Process timezone. */
    if (tzp >= end)
        ;           /* Nothing to do. */
    else if (*tzp == 'Z') {
        tzp = " GMT";
        end = tzp + 4;
    }
    else {
        sep = " ";
        tzp++;
    }

    tzl = end - tzp;
    return wintls_maprintf("%.4s-%.2s-%.2s %.2s:%.2s:%c%c%s%.*s%s%.*s",
        beg, beg + 4, beg + 6,
        beg + 8, beg + 10, sec1, sec2,
        fracl ? "." : "", (int)fracl, fracp,
        sep, (int)tzl, tzp);
}

/*
 *  Convert an ASN.1 UTC time to a printable string.
 * Return the dynamically allocated string, or NULL if an error occurs.
 */
static const char* UTime2str(const char* beg, const char* end)
{
    const char* tzp;
    size_t tzl;
    const char* sec;

    for (tzp = beg; tzp < end && *tzp >= '0' && *tzp <= '9'; tzp++)
        ;
    /* Get the seconds. */
    sec = beg + 10;
    switch (tzp - sec) {
    case 0:
        sec = "00";
    case 2:
        break;
    default:
        return NULL;
    }

    /* Process timezone. */
    if (tzp >= end)
        return NULL;
    if (*tzp == 'Z') {
        tzp = "GMT";
        end = tzp + 3;
    }
    else
        tzp++;

    tzl = end - tzp;
    return wintls_maprintf("%u%.2s-%.2s-%.2s %.2s:%.2s:%.2s %.*s",
        20 - (*beg >= '5'), beg, beg + 2, beg + 4,
        beg + 6, beg + 8, sec,
        (int)tzl, tzp);
}

/*
 * Convert an ASN.1 element to a printable string.
 * Return the dynamically allocated string, or NULL if an error occurs.
 */
static const char* ASN1tostr(struct wintls_asn1Element* elem, int type)
{
    if (elem->constructed)
        return NULL; /* No conversion of structured elements. */

    if (!type)
        type = elem->tag;   /* Type not forced: use element tag as type. */

    switch (type) {
    case WINTLS_ASN1_BOOLEAN:
        return bool2str(elem->beg, elem->end);
    case WINTLS_ASN1_INTEGER:
    case WINTLS_ASN1_ENUMERATED:
        return int2str(elem->beg, elem->end);
    case WINTLS_ASN1_BIT_STRING:
        return bit2str(elem->beg, elem->end);
    case WINTLS_ASN1_OCTET_STRING:
        return octet2str(elem->beg, elem->end);
    case WINTLS_ASN1_NULL:
        return strdup("");
    case WINTLS_ASN1_OBJECT_IDENTIFIER:
        return OID2str(elem->beg, elem->end, TRUE);
    case WINTLS_ASN1_UTC_TIME:
        return UTime2str(elem->beg, elem->end);
    case WINTLS_ASN1_GENERALIZED_TIME:
        return GTime2str(elem->beg, elem->end);
    case WINTLS_ASN1_UTF8_STRING:
    case WINTLS_ASN1_NUMERIC_STRING:
    case WINTLS_ASN1_PRINTABLE_STRING:
    case WINTLS_ASN1_TELETEX_STRING:
    case WINTLS_ASN1_IA5_STRING:
    case WINTLS_ASN1_VISIBLE_STRING:
    case WINTLS_ASN1_UNIVERSAL_STRING:
    case WINTLS_ASN1_BMP_STRING:
        return string2str(type, elem->beg, elem->end);
    }

    return NULL;   /* Unsupported. */
}

/*
 * ASCII encode distinguished name at `dn' into the `buflen'-sized buffer at
 * `buf'.
 *
 * Returns the total string length, even if larger than `buflen' or -1 on
 * error.
 */
static ssize_t encodeDN(char* buf, size_t buflen, struct wintls_asn1Element* dn)
{
    struct wintls_asn1Element rdn;
    struct wintls_asn1Element atv;
    struct wintls_asn1Element oid;
    struct wintls_asn1Element value;
    size_t l = 0;
    const char* p1;
    const char* p2;
    const char* p3;
    const char* str;

    for (p1 = dn->beg; p1 < dn->end;) {
        p1 = getASN1Element(&rdn, p1, dn->end);
        if (!p1)
            return -1;
        for (p2 = rdn.beg; p2 < rdn.end;) {
            p2 = getASN1Element(&atv, p2, rdn.end);
            if (!p2)
                return -1;
            p3 = getASN1Element(&oid, atv.beg, atv.end);
            if (!p3)
                return -1;
            if (!getASN1Element(&value, p3, atv.end))
                return -1;
            str = ASN1tostr(&oid, 0);
            if (!str)
                return -1;

            /* Encode delimiter.
               If attribute has a short uppercase name, delimiter is ", ". */
            if (l) {
                for (p3 = str; ISUPPER(*p3); p3++)
                    ;
                for (p3 = (*p3 || p3 - str > 2) ? "/" : ", "; *p3; p3++) {
                    if (l < buflen)
                        buf[l] = *p3;
                    l++;
                }
            }

            /* Encode attribute name. */
            for (p3 = str; *p3; p3++) {
                if (l < buflen)
                    buf[l] = *p3;
                l++;
            }
            free((char*)str);

            /* Generate equal sign. */
            if (l < buflen)
                buf[l] = '=';
            l++;

            /* Generate value. */
            str = ASN1tostr(&value, 0);
            if (!str)
                return -1;
            for (p3 = str; *p3; p3++) {
                if (l < buflen)
                    buf[l] = *p3;
                l++;
            }
            free((char*)str);
        }
    }

    return l;
}

#ifdef WANT_PARSEX509
/*
 * ASN.1 parse an X509 certificate into structure subfields.
 * Syntax is assumed to have already been checked by the SSL backend.
 * See RFC 5280.
 */
int wintls_parseX509(struct wintls_X509certificate* cert,
    const char* beg, const char* end)
{
    struct wintls_asn1Element elem;
    struct wintls_asn1Element tbsCertificate;
    const char* ccp;
    static const char defaultVersion = 0;  /* v1. */

    cert->certificate.header = 0;
    cert->certificate.beg = beg;
    cert->certificate.end = end;

    /* Get the sequence content. */
    if (!getASN1Element(&elem, beg, end))
        return -1;  /* Invalid bounds/size. */
    beg = elem.beg;
    end = elem.end;

    /* Get tbsCertificate. */
    beg = getASN1Element(&tbsCertificate, beg, end);
    if (!beg)
        return -1;
    /* Skip the signatureAlgorithm. */
    beg = getASN1Element(&cert->signatureAlgorithm, beg, end);
    if (!beg)
        return -1;
    /* Get the signatureValue. */
    if (!getASN1Element(&cert->signature, beg, end))
        return -1;

    /* Parse TBSCertificate. */
    beg = tbsCertificate.beg;
    end = tbsCertificate.end;
    /* Get optional version, get serialNumber. */
    cert->version.header = 0;
    cert->version.beg = &defaultVersion;
    cert->version.end = &defaultVersion + sizeof(defaultVersion);
    beg = getASN1Element(&elem, beg, end);
    if (!beg)
        return -1;
    if (elem.tag == 0) {
        if (!getASN1Element(&cert->version, elem.beg, elem.end))
            return -1;
        beg = getASN1Element(&elem, beg, end);
        if (!beg)
            return -1;
    }
    cert->serialNumber = elem;
    /* Get signature algorithm. */
    beg = getASN1Element(&cert->signatureAlgorithm, beg, end);
    /* Get issuer. */
    beg = getASN1Element(&cert->issuer, beg, end);
    if (!beg)
        return -1;
    /* Get notBefore and notAfter. */
    beg = getASN1Element(&elem, beg, end);
    if (!beg)
        return -1;
    ccp = getASN1Element(&cert->notBefore, elem.beg, elem.end);
    if (!ccp)
        return -1;
    if (!getASN1Element(&cert->notAfter, ccp, elem.end))
        return -1;
    /* Get subject. */
    beg = getASN1Element(&cert->subject, beg, end);
    if (!beg)
        return -1;
    /* Get subjectPublicKeyAlgorithm and subjectPublicKey. */
    beg = getASN1Element(&cert->subjectPublicKeyInfo, beg, end);
    if (!beg)
        return -1;
    ccp = getASN1Element(&cert->subjectPublicKeyAlgorithm,
        cert->subjectPublicKeyInfo.beg,
        cert->subjectPublicKeyInfo.end);
    if (!ccp)
        return -1;
    if (!getASN1Element(&cert->subjectPublicKey, ccp,
        cert->subjectPublicKeyInfo.end))
        return -1;
    /* Get optional issuerUiqueID, subjectUniqueID and extensions. */
    cert->issuerUniqueID.tag = cert->subjectUniqueID.tag = 0;
    cert->extensions.tag = elem.tag = 0;
    cert->issuerUniqueID.header = cert->subjectUniqueID.header = 0;
    cert->issuerUniqueID.beg = cert->issuerUniqueID.end = "";
    cert->subjectUniqueID.beg = cert->subjectUniqueID.end = "";
    cert->extensions.header = 0;
    cert->extensions.beg = cert->extensions.end = "";
    if (beg < end) {
        beg = getASN1Element(&elem, beg, end);
        if (!beg)
            return -1;
    }
    if (elem.tag == 1) {
        cert->issuerUniqueID = elem;
        if (beg < end) {
            beg = getASN1Element(&elem, beg, end);
            if (!beg)
                return -1;
        }
    }
    if (elem.tag == 2) {
        cert->subjectUniqueID = elem;
        if (beg < end) {
            beg = getASN1Element(&elem, beg, end);
            if (!beg)
                return -1;
        }
    }
    if (elem.tag == 3)
        if (!getASN1Element(&cert->extensions, elem.beg, elem.end))
            return -1;
    return 0;
}

#endif /* WANT_PARSEX509 */

/*
 * Copy at most 64-characters, terminate with a newline and returns the
 * effective number of stored characters.
 */
static size_t copySubstring(char* to, const char* from)
{
    size_t i;
    for (i = 0; i < 64; i++) {
        to[i] = *from;
        if (!*from++)
            break;
    }

    to[i++] = '\n';
    return i;
}

static const char* dumpAlgo(struct wintls_asn1Element* param,
    const char* beg, const char* end)
{
    struct wintls_asn1Element oid;

    /* Get algorithm parameters and return algorithm name. */

    beg = getASN1Element(&oid, beg, end);
    if (!beg)
        return NULL;
    param->header = NULL;
    param->tag = 0;
    param->beg = param->end = end;
    if (beg < end)
        if (!getASN1Element(param, beg, end))
            return NULL;
    return OID2str(oid.beg, oid.end, TRUE);
}



/*
 * 'value' is NOT a null-terminated string
 */
wintls_code wintls_ssl_push_certinfo_len(struct wintls* data,
    int certnum,
    const char* label,
    const char* value,
    size_t valuelen)
{
    struct wintls_certinfo* ci = &data->certs;
    char* output;
    struct wintls_slist* nl;
    wintls_code result = WINTLS_OK;
    size_t labellen = strlen(label);
    size_t outlen = labellen + 1 + valuelen + 1; /* label:value\0 */

    output = malloc(outlen);
    if (!output)
        return WINTLS_OUT_OF_MEMORY;

    /* sprintf the label and colon */
    msnprintf(output, outlen, "%s:", label);

    /* memcpy the value (it might not be null-terminated) */
    memcpy(&output[labellen + 1], value, valuelen);

    /* null-terminate the output */
    output[labellen + 1 + valuelen] = 0;

    nl = wintls_slist_append_nodup(ci->certinfo[certnum], output);
    if (!nl) {
        free(output);
        wintls_slist_free_all(ci->certinfo[certnum]);
        result = WINTLS_OUT_OF_MEMORY;
    }

    ci->certinfo[certnum] = nl;
    return result;
}



/*
 * This is a convenience function for push_certinfo_len that takes a zero
 * terminated value.
 */
static wintls_code ssl_push_certinfo(struct wintls* data,
    int certnum,
    const char* label,
    const char* value)
{
    size_t valuelen = strlen(value);

    return wintls_ssl_push_certinfo_len(data, certnum, label, value, valuelen);
}

/* return 0 on success, 1 on error */
static int do_pubkey_field(struct wintls* tls, int certnum,
    const char* label, struct wintls_asn1Element* elem)
{
    const char* output;
    wintls_code result = WINTLS_OK;

    /* Generate a certificate information record for the public key. */

    output = ASN1tostr(elem, 0);
    if (output) {
        if (tls->certinfo)
            result = ssl_push_certinfo(tls, certnum, label, output);
        if (!certnum && !result)
            infof(tls, "   %s: %s", label, output);
        free((char*)output);
    }
    return result ? 1 : 0;
}

/* return 0 on success, 1 on error */
static int do_pubkey(struct wintls* tls, int certnum,
    const char* algo, struct wintls_asn1Element* param,
    struct wintls_asn1Element* pubkey)
{
    struct wintls_asn1Element elem;
    struct wintls_asn1Element pk;
    const char* p;

    /* Generate all information records for the public key. */

    if (strcasecompare(algo, "ecPublicKey")) {
        /*
         * ECC public key is all the data, a value of type BIT STRING mapped to
         * OCTET STRING and should not be parsed as an ASN.1 value.
         */
        const size_t len = ((pubkey->end - pubkey->beg - 2) * 4);
        if (!certnum)
            infof(tls, "   ECC Public Key (%lu bits)", len);
        if (tls->certinfo) {
            char q[sizeof(len) * 8 / 3 + 1];
            (void)msnprintf(q, sizeof(q), "%lu", len);
            if (ssl_push_certinfo(tls, certnum, "ECC Public Key", q))
                return 1;
        }
        return do_pubkey_field(tls, certnum, "ecPublicKey", pubkey);
    }

    /* Get the public key (single element). */
    if (!getASN1Element(&pk, pubkey->beg + 1, pubkey->end))
        return 1;

    if (strcasecompare(algo, "rsaEncryption")) {
        const char* q;
        size_t len;

        p = getASN1Element(&elem, pk.beg, pk.end);
        if (!p)
            return 1;

        /* Compute key length. */
        for (q = elem.beg; !*q && q < elem.end; q++)
            ;
        len = ((elem.end - q) * 8);
        if (len) {
            unsigned int i;
            for (i = *(unsigned char*)q; !(i & 0x80); i <<= 1)
                len--;
        }
        if (len > 32)
            elem.beg = q;     /* Strip leading zero bytes. */
        if (!certnum)
            infof(tls, "   RSA Public Key (%lu bits)", len);
        if (tls->certinfo) {
            char r[sizeof(len) * 8 / 3 + 1];
            msnprintf(r, sizeof(r), "%lu", len);
            if (ssl_push_certinfo(tls, certnum, "RSA Public Key", r))
                return 1;
        }
        /* Generate coefficients. */
        if (do_pubkey_field(tls, certnum, "rsa(n)", &elem))
            return 1;
        if (!getASN1Element(&elem, p, pk.end))
            return 1;
        if (do_pubkey_field(tls, certnum, "rsa(e)", &elem))
            return 1;
    }
    else if (strcasecompare(algo, "dsa")) {
        p = getASN1Element(&elem, param->beg, param->end);
        if (p) {
            if (do_pubkey_field(tls, certnum, "dsa(p)", &elem))
                return 1;
            p = getASN1Element(&elem, p, param->end);
            if (p) {
                if (do_pubkey_field(tls, certnum, "dsa(q)", &elem))
                    return 1;
                if (getASN1Element(&elem, p, param->end)) {
                    if (do_pubkey_field(tls, certnum, "dsa(g)", &elem))
                        return 1;
                    if (do_pubkey_field(tls, certnum, "dsa(pub_key)", &pk))
                        return 1;
                }
            }
        }
    }
    else if (strcasecompare(algo, "dhpublicnumber")) {
        p = getASN1Element(&elem, param->beg, param->end);
        if (p) {
            if (do_pubkey_field(tls, certnum, "dh(p)", &elem))
                return 1;
            if (getASN1Element(&elem, param->beg, param->end)) {
                if (do_pubkey_field(tls, certnum, "dh(g)", &elem))
                    return 1;
                if (do_pubkey_field(tls, certnum, "dh(pub_key)", &pk))
                    return 1;
            }
        }
    }
    return 0;
}

/*
 * Convert an ASN.1 distinguished name into a printable string.
 * Return the dynamically allocated string, or NULL if an error occurs.
 */
static const char* DNtostr(struct wintls_asn1Element* dn)
{
    char* buf = NULL;
    ssize_t buflen = encodeDN(NULL, 0, dn);

    if (buflen >= 0) {
        buf = malloc(buflen + 1);
        if (buf) {
            if (encodeDN(buf, buflen + 1, dn) == -1) {
                free(buf);
                return NULL;
            }
            buf[buflen] = '\0';
        }
    }
    return buf;
}

wintls_code wintls_extract_certinfo(struct wintls* tls,
    int certnum,
    const char* beg,
    const char* end)
{
    struct wintls_X509certificate cert;
    struct wintls_asn1Element param;
    const char* ccp;
    char* cp1;
    size_t cl1;
    char* cp2;
    wintls_code result = WINTLS_OK;
    unsigned int version;
    size_t i;
    size_t j;

    if (!tls->certinfo)
        if (certnum)
            return WINTLS_OK;

    /* Prepare the certificate information for wintls_easy_getinfo(). */

    /* Extract the certificate ASN.1 elements. */
    if (wintls_parseX509(&cert, beg, end))
        return WINTLS_PEER_FAILED_VERIFICATION;

    /* Subject. */
    ccp = DNtostr(&cert.subject);
    if (!ccp)
        return WINTLS_OUT_OF_MEMORY;
    if (tls->certinfo) {
        result = ssl_push_certinfo(tls, certnum, "Subject", ccp);
        if (result)
            return result;
    }
    if (!certnum)
        infof(tls, "%2d Subject: %s", certnum, ccp);
    free((char*)ccp);

    /* Issuer. */
    ccp = DNtostr(&cert.issuer);
    if (!ccp)
        return WINTLS_OUT_OF_MEMORY;
    if (tls->certinfo) {
        result = ssl_push_certinfo(tls, certnum, "Issuer", ccp);
    }
    if (!certnum)
        infof(tls, "   Issuer: %s", ccp);
    free((char*)ccp);
    if (result)
        return result;

    /* Version (always fits in less than 32 bits). */
    version = 0;
    for (ccp = cert.version.beg; ccp < cert.version.end; ccp++)
        version = (version << 8) | *(const unsigned char*)ccp;
    if (tls->certinfo) {
        ccp = wintls_maprintf("%x", version);
        if (!ccp)
            return WINTLS_OUT_OF_MEMORY;
        result = ssl_push_certinfo(tls, certnum, "Version", ccp);
        free((char*)ccp);
        if (result)
            return result;
    }
    if (!certnum)
        infof(tls, "   Version: %u (0x%x)", version + 1, version);

    /* Serial number. */
    ccp = ASN1tostr(&cert.serialNumber, 0);
    if (!ccp)
        return WINTLS_OUT_OF_MEMORY;
    if (tls->certinfo)
        result = ssl_push_certinfo(tls, certnum, "Serial Number", ccp);
    if (!certnum)
        infof(tls, "   Serial Number: %s", ccp);
    free((char*)ccp);
    if (result)
        return result;

    /* Signature algorithm .*/
    ccp = dumpAlgo(&param, cert.signatureAlgorithm.beg,
        cert.signatureAlgorithm.end);
    if (!ccp)
        return WINTLS_OUT_OF_MEMORY;
    if (tls->certinfo)
        result = ssl_push_certinfo(tls, certnum, "Signature Algorithm", ccp);
    if (!certnum)
        infof(tls, "   Signature Algorithm: %s", ccp);
    free((char*)ccp);
    if (result)
        return result;

    /* Start Date. */
    ccp = ASN1tostr(&cert.notBefore, 0);
    if (!ccp)
        return WINTLS_OUT_OF_MEMORY;
    if (tls->certinfo)
        result = ssl_push_certinfo(tls, certnum, "Start Date", ccp);
    if (!certnum)
        infof(tls, "   Start Date: %s", ccp);
    free((char*)ccp);
    if (result)
        return result;

    /* Expire Date. */
    ccp = ASN1tostr(&cert.notAfter, 0);
    if (!ccp)
        return WINTLS_OUT_OF_MEMORY;
    if (tls->certinfo)
        result = ssl_push_certinfo(tls, certnum, "Expire Date", ccp);
    if (!certnum)
        infof(tls, "   Expire Date: %s", ccp);
    free((char*)ccp);
    if (result)
        return result;

    /* Public Key Algorithm. */
    ccp = dumpAlgo(&param, cert.subjectPublicKeyAlgorithm.beg,
        cert.subjectPublicKeyAlgorithm.end);
    if (!ccp)
        return WINTLS_OUT_OF_MEMORY;
    if (tls->certinfo)
        result = ssl_push_certinfo(tls, certnum, "Public Key Algorithm",
            ccp);
    if (!result) {
        int ret;
        if (!certnum)
            infof(tls, "   Public Key Algorithm: %s", ccp);
        ret = do_pubkey(tls, certnum, ccp, &param, &cert.subjectPublicKey);
        if (ret)
            result = WINTLS_OUT_OF_MEMORY; /* the most likely error */
    }
    free((char*)ccp);
    if (result)
        return result;

    /* Signature. */
    ccp = ASN1tostr(&cert.signature, 0);
    if (!ccp)
        return WINTLS_OUT_OF_MEMORY;
    if (tls->certinfo)
        result = ssl_push_certinfo(tls, certnum, "Signature", ccp);
    if (!certnum)
        infof(tls, "   Signature: %s", ccp);
    free((char*)ccp);
    if (result)
        return result;

    /* Generate PEM certificate. */
    result = wintls_base64_encode(cert.certificate.beg,
        cert.certificate.end - cert.certificate.beg,
        &cp1, &cl1);
    if (result)
        return result;
    /* Compute the number of characters in final certificate string. Format is:
       -----BEGIN CERTIFICATE-----\n
       <max 64 base64 characters>\n
       .
       .
       .
       -----END CERTIFICATE-----\n
     */
    i = 28 + cl1 + (cl1 + 64 - 1) / 64 + 26;
    cp2 = malloc(i + 1);
    if (!cp2) {
        free(cp1);
        return WINTLS_OUT_OF_MEMORY;
    }
    /* Build the certificate string. */
    i = copySubstring(cp2, "-----BEGIN CERTIFICATE-----");
    for (j = 0; j < cl1; j += 64)
        i += copySubstring(cp2 + i, cp1 + j);
    i += copySubstring(cp2 + i, "-----END CERTIFICATE-----");
    cp2[i] = '\0';
    free(cp1);
    if (tls->certinfo)
        result = ssl_push_certinfo(tls, certnum, "Cert", cp2);
    if (!certnum)
        infof(tls, "%s", cp2);
    free(cp2);
    return result;
}

static const char* checkOID(const char* beg, const char* end,
    const char* oid)
{
    struct wintls_asn1Element e;
    const char* ccp;
    const char* p;
    BOOL matched;

    /* Check if first ASN.1 element at `beg' is the given OID.
       Return a pointer in the source after the OID if found, else NULL. */

    ccp = getASN1Element(&e, beg, end);
    if (!ccp || e.tag != WINTLS_ASN1_OBJECT_IDENTIFIER)
        return NULL;

    p = OID2str(e.beg, e.end, FALSE);
    if (!p)
        return NULL;

    matched = !strcmp(p, oid);
    free((char*)p);
    return matched ? ccp : NULL;
}

wintls_code wintls_verifyhost(struct wintls* tls,
    const char* beg, const char* end)
{
    struct wintls_X509certificate cert;
    struct wintls_asn1Element dn;
    struct wintls_asn1Element elem;
    struct wintls_asn1Element ext;
    struct wintls_asn1Element name;
    const char* p;
    const char* q;
    char* dnsname;
    int matched = -1;
    size_t addrlen = (size_t)-1;
    ssize_t len;
    size_t hostlen;

#ifdef ENABLE_IPV6
    struct in6_addr addr;
#else
    struct in_addr addr;
#endif

    /* Verify that connection server matches info in X509 certificate at
       `beg'..`end'. */

    if (!tls->verifyhost)
        return WINTLS_OK;

    if (wintls_parseX509(&cert, beg, end))
        return WINTLS_PEER_FAILED_VERIFICATION;

    hostlen = strlen(tls->hostname);

    /* Get the server IP address. */
#ifdef ENABLE_IPV6
    if (cf->conn->bits.ipv6_ip &&
        inet_pton(AF_INET6, tls->hostname, &addr))
        addrlen = sizeof(struct in6_addr);
    else
#endif
        if (inet_pton(AF_INET, tls->hostname, &addr))
            addrlen = sizeof(struct in_addr);

    /* Process extensions. */
    for (p = cert.extensions.beg; p < cert.extensions.end && matched != 1;) {
        p = getASN1Element(&ext, p, cert.extensions.end);
        if (!p)
            return WINTLS_PEER_FAILED_VERIFICATION;

        /* Check if extension is a subjectAlternativeName. */
        ext.beg = checkOID(ext.beg, ext.end, sanOID);
        if (ext.beg) {
            ext.beg = getASN1Element(&elem, ext.beg, ext.end);
            if (!ext.beg)
                return WINTLS_PEER_FAILED_VERIFICATION;
            /* Skip critical if present. */
            if (elem.tag == WINTLS_ASN1_BOOLEAN) {
                ext.beg = getASN1Element(&elem, ext.beg, ext.end);
                if (!ext.beg)
                    return WINTLS_PEER_FAILED_VERIFICATION;
            }
            /* Parse the octet string contents: is a single sequence. */
            if (!getASN1Element(&elem, elem.beg, elem.end))
                return WINTLS_PEER_FAILED_VERIFICATION;
            /* Check all GeneralNames. */
            for (q = elem.beg; matched != 1 && q < elem.end;) {
                q = getASN1Element(&name, q, elem.end);
                if (!q)
                    break;
                switch (name.tag) {
                case 2: /* DNS name. */
                    len = utf8asn1str(&dnsname, WINTLS_ASN1_IA5_STRING,
                        name.beg, name.end);
                    if (len > 0 && (size_t)len == strlen(dnsname))
                        matched = wintls_cert_hostcheck(dnsname, (size_t)len,
                            tls->hostname, hostlen);
                    else
                        matched = 0;
                    free(dnsname);
                    break;

                case 7: /* IP address. */
                    matched = (size_t)(name.end - name.beg) == addrlen &&
                        !memcmp(&addr, name.beg, addrlen);
                    break;
                }
            }
        }
    }

    switch (matched) {
    case 1:
        /* an alternative name matched the server hostname */
        infof(tls, "  subjectAltName: %s matched", tls->dispname);
        return WINTLS_OK;
    case 0:
        /* an alternative name field existed, but didn't match and then
           we MUST fail */
        infof(tls, "  subjectAltName does not match %s", tls->dispname);
        return WINTLS_PEER_FAILED_VERIFICATION;
    }

    /* Process subject. */
    name.header = NULL;
    name.beg = name.end = "";
    q = cert.subject.beg;
    /* we have to look to the last occurrence of a commonName in the
       distinguished one to get the most significant one. */
    while (q < cert.subject.end) {
        q = getASN1Element(&dn, q, cert.subject.end);
        if (!q)
            break;
        for (p = dn.beg; p < dn.end;) {
            p = getASN1Element(&elem, p, dn.end);
            if (!p)
                return WINTLS_PEER_FAILED_VERIFICATION;
            /* We have a DN's AttributeTypeAndValue: check it in case it's a CN. */
            elem.beg = checkOID(elem.beg, elem.end, cnOID);
            if (elem.beg)
                name = elem;    /* Latch CN. */
        }
    }

    /* Check the CN if found. */
    if (!getASN1Element(&elem, name.beg, name.end))
        failf(tls, "SSL: unable to obtain common name from peer certificate");
    else {
        len = utf8asn1str(&dnsname, elem.tag, elem.beg, elem.end);
        if (len < 0) {
            free(dnsname);
            return WINTLS_OUT_OF_MEMORY;
        }
        if (strlen(dnsname) != (size_t)len)         /* Nul byte in string ? */
            failf(tls, "SSL: illegal cert name field");
        else if (wintls_cert_hostcheck((const char*)dnsname,
            len, tls->hostname, hostlen)) {
            infof(tls, "  common name: %s (matched)", dnsname);
            free(dnsname);
            return WINTLS_OK;
        }
        else
            failf(tls, "SSL: certificate subject name '%s' does not match "
                "target host name '%s'", dnsname, tls->dispname);
        free(dnsname);
    }

    return WINTLS_PEER_FAILED_VERIFICATION;
}



/* ======================================================================
 * source: schannel_verify.c
 ====================================================================== */

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <stdio.h>

#define MAX_CAFILE_SIZE 1048576 /* 1 MiB */
#define BEGIN_CERT "-----BEGIN CERTIFICATE-----"
#define END_CERT "\n-----END CERTIFICATE-----"

struct cert_chain_engine_config_win7 {
    DWORD cbSize;
    HCERTSTORE hRestrictedRoot;
    HCERTSTORE hRestrictedTrust;
    HCERTSTORE hRestrictedOther;
    DWORD cAdditionalStore;
    HCERTSTORE* rghAdditionalStore;
    DWORD dwFlags;
    DWORD dwUrlRetrievalTimeout;
    DWORD MaximumCachedCertificates;
    DWORD CycleDetectionModulus;
    HCERTSTORE hExclusiveRoot;
    HCERTSTORE hExclusiveTrustedPeople;
};

static int is_cr_or_lf(char c)
{
    return c == '\r' || c == '\n';
}

/* Search the substring needle,needlelen into string haystack,haystacklen
 * Strings don't need to be terminated by a '\0'.
 * Similar of OSX/Linux memmem (not available on Visual Studio).
 * Return position of beginning of first occurrence or NULL if not found
 */
static const char* c_memmem(const void* haystack, size_t haystacklen,
    const void* needle, size_t needlelen)
{
    const char* p;
    char first;
    const char* str_limit = (const char*)haystack + haystacklen;
    if (!needlelen || needlelen > haystacklen)
        return NULL;
    first = *(const char*)needle;
    for (p = (const char*)haystack; p <= (str_limit - needlelen); p++)
        if (((*p) == first) && (memcmp(p, needle, needlelen) == 0))
            return p;

    return NULL;
}

static wintls_code add_certs_data_to_store(HCERTSTORE trust_store,
    const char* ca_buffer,
    size_t ca_buffer_size,
    const char* ca_file_text,
    struct wintls* data)
{
    const size_t begin_cert_len = strlen(BEGIN_CERT);
    const size_t end_cert_len = strlen(END_CERT);
    wintls_code result = WINTLS_OK;
    int num_certs = 0;
    BOOL more_certs = 1;
    const char* current_ca_file_ptr = ca_buffer;
    const char* ca_buffer_limit = ca_buffer + ca_buffer_size;

    while (more_certs && (current_ca_file_ptr < ca_buffer_limit)) {
        const char* begin_cert_ptr = c_memmem(current_ca_file_ptr,
            ca_buffer_limit - current_ca_file_ptr,
            BEGIN_CERT,
            begin_cert_len);
        if (!begin_cert_ptr || !is_cr_or_lf(begin_cert_ptr[begin_cert_len])) {
            more_certs = 0;
        }
        else {
            const char* end_cert_ptr = c_memmem(begin_cert_ptr,
                ca_buffer_limit - begin_cert_ptr,
                END_CERT,
                end_cert_len);
            if (!end_cert_ptr) {
                failf(data,
                    "schannel: CA file '%s' is not correctly formatted",
                    ca_file_text);
                result = WINTLS_SSL_CACERT_BADFILE;
                more_certs = 0;
            }
            else {
                CERT_BLOB cert_blob;
                CERT_CONTEXT* cert_context = NULL;
                BOOL add_cert_result = FALSE;
                DWORD actual_content_type = 0;
                DWORD cert_size = (DWORD)
                    ((end_cert_ptr + end_cert_len) - begin_cert_ptr);

                cert_blob.pbData = (BYTE*)begin_cert_ptr;
                cert_blob.cbData = cert_size;
                if (!CryptQueryObject(CERT_QUERY_OBJECT_BLOB,
                    &cert_blob,
                    CERT_QUERY_CONTENT_FLAG_CERT,
                    CERT_QUERY_FORMAT_FLAG_ALL,
                    0,
                    NULL,
                    &actual_content_type,
                    NULL,
                    NULL,
                    NULL,
                    (const void**)&cert_context)) {
                    char buffer[STRERROR_LEN];
                    failf(data,
                        "schannel: failed to extract certificate from CA file "
                        "'%s': %s",
                        ca_file_text,
                        wintls_winapi_strerror(GetLastError(), buffer, sizeof(buffer)));
                    result = WINTLS_SSL_CACERT_BADFILE;
                    more_certs = 0;
                }
                else {
                    current_ca_file_ptr = begin_cert_ptr + cert_size;

                    /* Sanity check that the cert_context object is the right type */
                    if (CERT_QUERY_CONTENT_CERT != actual_content_type) {
                        failf(data,
                            "schannel: unexpected content type '%d' when extracting "
                            "certificate from CA file '%s'",
                            actual_content_type, ca_file_text);
                        result = WINTLS_SSL_CACERT_BADFILE;
                        more_certs = 0;
                    }
                    else {
                        add_cert_result =
                            CertAddCertificateContextToStore(trust_store,
                                cert_context,
                                CERT_STORE_ADD_ALWAYS,
                                NULL);
                        CertFreeCertificateContext(cert_context);
                        if (!add_cert_result) {
                            char buffer[STRERROR_LEN];
                            failf(data,
                                "schannel: failed to add certificate from CA file '%s' "
                                "to certificate store: %s",
                                ca_file_text,
                                wintls_winapi_strerror(GetLastError(), buffer,
                                    sizeof(buffer)));
                            result = WINTLS_SSL_CACERT_BADFILE;
                            more_certs = 0;
                        }
                        else {
                            num_certs++;
                        }
                    }
                }
            }
        }
    }

    if (result == WINTLS_OK) {
        if (!num_certs) {
            infof(data,
                "schannel: did not add any certificates from CA file '%s'",
                ca_file_text);
        }
        else {
            infof(data,
                "schannel: added %d certificate(s) from CA file '%s'",
                num_certs, ca_file_text);
        }
    }
    return result;
}

static wintls_code add_certs_file_to_store(HCERTSTORE trust_store,
    const char* ca_file,
    struct wintls* data)
{
    wintls_code result;
    HANDLE ca_file_handle = INVALID_HANDLE_VALUE;
    LARGE_INTEGER file_size;
    char* ca_file_buffer = NULL;
    TCHAR* ca_file_tstr = NULL;
    size_t ca_file_bufsize = 0;
    DWORD total_bytes_read = 0;

    ca_file_tstr = wintlsx_convert_UTF8_to_tchar((char*)ca_file);
    if (!ca_file_tstr) {
        char buffer[STRERROR_LEN];
        failf(data,
            "schannel: invalid path name for CA file '%s': %s",
            ca_file,
            wintls_winapi_strerror(GetLastError(), buffer, sizeof(buffer)));
        result = WINTLS_SSL_CACERT_BADFILE;
        goto cleanup;
    }

    /*
     * Read the CA file completely into memory before parsing it. This
     * optimizes for the common case where the CA file will be relatively
     * small ( < 1 MiB ).
     */
    ca_file_handle = CreateFile(ca_file_tstr,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (ca_file_handle == INVALID_HANDLE_VALUE) {
        char buffer[STRERROR_LEN];
        failf(data,
            "schannel: failed to open CA file '%s': %s",
            ca_file,
            wintls_winapi_strerror(GetLastError(), buffer, sizeof(buffer)));
        result = WINTLS_SSL_CACERT_BADFILE;
        goto cleanup;
    }

    if (!GetFileSizeEx(ca_file_handle, &file_size)) {
        char buffer[STRERROR_LEN];
        failf(data,
            "schannel: failed to determine size of CA file '%s': %s",
            ca_file,
            wintls_winapi_strerror(GetLastError(), buffer, sizeof(buffer)));
        result = WINTLS_SSL_CACERT_BADFILE;
        goto cleanup;
    }

    if (file_size.QuadPart > MAX_CAFILE_SIZE) {
        failf(data,
            "schannel: CA file exceeds max size of %u bytes",
            MAX_CAFILE_SIZE);
        result = WINTLS_SSL_CACERT_BADFILE;
        goto cleanup;
    }

    ca_file_bufsize = (size_t)file_size.QuadPart;
    ca_file_buffer = (char*)malloc(ca_file_bufsize + 1);
    if (!ca_file_buffer) {
        result = WINTLS_OUT_OF_MEMORY;
        goto cleanup;
    }

    while (total_bytes_read < ca_file_bufsize) {
        DWORD bytes_to_read = (DWORD)(ca_file_bufsize - total_bytes_read);
        DWORD bytes_read = 0;

        if (!ReadFile(ca_file_handle, ca_file_buffer + total_bytes_read,
            bytes_to_read, &bytes_read, NULL)) {
            char buffer[STRERROR_LEN];
            failf(data,
                "schannel: failed to read from CA file '%s': %s",
                ca_file,
                wintls_winapi_strerror(GetLastError(), buffer, sizeof(buffer)));
            result = WINTLS_SSL_CACERT_BADFILE;
            goto cleanup;
        }
        if (bytes_read == 0) {
            /* Premature EOF -- adjust the bufsize to the new value */
            ca_file_bufsize = total_bytes_read;
        }
        else {
            total_bytes_read += bytes_read;
        }
    }

    /* Null terminate the buffer */
    ca_file_buffer[ca_file_bufsize] = '\0';

    result = add_certs_data_to_store(trust_store,
        ca_file_buffer, ca_file_bufsize,
        ca_file,
        data);

cleanup:
    if (ca_file_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(ca_file_handle);
    }
    wintls_safefree(ca_file_buffer);
    wintlsx_unicodefree(ca_file_tstr);

    return result;
}

/*
 * Returns the number of characters necessary to populate all the host_names.
 * If host_names is not NULL, populate it with all the host names. Each string
 * in the host_names is null-terminated and the last string is double
 * null-terminated. If no DNS names are found, a single null-terminated empty
 * string is returned.
 */
static DWORD cert_get_name_string(struct wintls* data,
    CERT_CONTEXT* cert_context,
    LPTSTR host_names,
    DWORD length)
{
    DWORD actual_length = 0;
    BOOL compute_content = FALSE;
    CERT_INFO* cert_info = NULL;
    CERT_EXTENSION* extension = NULL;
    CRYPT_DECODE_PARA decode_para = { 0, 0, 0 };
    CERT_ALT_NAME_INFO* alt_name_info = NULL;
    DWORD alt_name_info_size = 0;
    BOOL ret_val = FALSE;
    LPTSTR current_pos = NULL;
    DWORD i;

    /* CERT_NAME_SEARCH_ALL_NAMES_FLAG is available from Windows 8 onwards. */
    if (wintlsx_verify_windows_version(6, 2, 0, PLATFORM_WINNT,
        VERSION_GREATER_THAN_EQUAL)) {
#ifdef CERT_NAME_SEARCH_ALL_NAMES_FLAG
        /* CertGetNameString will provide the 8-bit character string without
         * any decoding */
        DWORD name_flags =
            CERT_NAME_DISABLE_IE4_UTF8_FLAG | CERT_NAME_SEARCH_ALL_NAMES_FLAG;
        actual_length = CertGetNameString(cert_context,
            CERT_NAME_DNS_TYPE,
            name_flags,
            NULL,
            host_names,
            length);
        return actual_length;
#endif
    }

    compute_content = host_names != NULL && length != 0;

    /* Initialize default return values. */
    actual_length = 1;
    if (compute_content) {
        *host_names = '\0';
    }

    if (!cert_context) {
        failf(data, "schannel: Null certificate context.");
        return actual_length;
    }

    cert_info = cert_context->pCertInfo;
    if (!cert_info) {
        failf(data, "schannel: Null certificate info.");
        return actual_length;
    }

    extension = CertFindExtension(szOID_SUBJECT_ALT_NAME2,
        cert_info->cExtension,
        cert_info->rgExtension);
    if (!extension) {
        failf(data, "schannel: CertFindExtension() returned no extension.");
        return actual_length;
    }

    decode_para.cbSize = sizeof(CRYPT_DECODE_PARA);

    ret_val =
        CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            szOID_SUBJECT_ALT_NAME2,
            extension->Value.pbData,
            extension->Value.cbData,
            CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
            &decode_para,
            &alt_name_info,
            &alt_name_info_size);
    if (!ret_val) {
        failf(data,
            "schannel: CryptDecodeObjectEx() returned no alternate name "
            "information.");
        return actual_length;
    }

    current_pos = host_names;

    /* Iterate over the alternate names and populate host_names. */
    for (i = 0; i < alt_name_info->cAltEntry; i++) {
        const CERT_ALT_NAME_ENTRY* entry = &alt_name_info->rgAltEntry[i];
        wchar_t* dns_w = NULL;
        size_t current_length = 0;

        if (entry->dwAltNameChoice != CERT_ALT_NAME_DNS_NAME) {
            continue;
        }
        if (!entry->pwszDNSName) {
            infof(data, "schannel: Empty DNS name.");
            continue;
        }
        current_length = wcslen(entry->pwszDNSName) + 1;
        if (!compute_content) {
            actual_length += (DWORD)current_length;
            continue;
        }
        /* Sanity check to prevent buffer overrun. */
        if ((actual_length + current_length) > length) {
            failf(data, "schannel: Not enough memory to list all host names.");
            break;
        }
        dns_w = entry->pwszDNSName;
        /* pwszDNSName is in ia5 string format and hence doesn't contain any
         * non-ascii characters. */
        while (*dns_w != '\0') {
            *current_pos++ = (char)(*dns_w++);
        }
        *current_pos++ = '\0';
        actual_length += (DWORD)current_length;
    }
    if (compute_content) {
        /* Last string has double null-terminator. */
        *current_pos = '\0';
    }
    return actual_length;
}

static wintls_code verify_host(struct wintls_easy* data,
    CERT_CONTEXT* pCertContextServer,
    const char* conn_hostname)
{
    wintls_code result = WINTLS_PEER_FAILED_VERIFICATION;
    TCHAR* cert_hostname_buff = NULL;
    size_t cert_hostname_buff_index = 0;
    size_t hostlen = strlen(conn_hostname);
    DWORD len = 0;
    DWORD actual_len = 0;

    /* Determine the size of the string needed for the cert hostname */
    len = cert_get_name_string(data, pCertContextServer, NULL, 0);
    if (len == 0) {
        failf(data,
            "schannel: CertGetNameString() returned no "
            "certificate name information");
        result = WINTLS_PEER_FAILED_VERIFICATION;
        goto cleanup;
    }

    /* CertGetNameString guarantees that the returned name will not contain
     * embedded null bytes. This appears to be undocumented behavior.
     */
    cert_hostname_buff = (LPTSTR)malloc(len * sizeof(TCHAR));
    if (!cert_hostname_buff) {
        result = WINTLS_OUT_OF_MEMORY;
        goto cleanup;
    }
    actual_len = cert_get_name_string(
        data, pCertContextServer, (LPTSTR)cert_hostname_buff, len);

    /* Sanity check */
    if (actual_len != len) {
        failf(data,
            "schannel: CertGetNameString() returned certificate "
            "name information of unexpected size");
        result = WINTLS_PEER_FAILED_VERIFICATION;
        goto cleanup;
    }

    /* If HAVE_CERT_NAME_SEARCH_ALL_NAMES is available, the output
     * will contain all DNS names, where each name is null-terminated
     * and the last DNS name is double null-terminated. Due to this
     * encoding, use the length of the buffer to iterate over all names.
     */
    result = WINTLS_PEER_FAILED_VERIFICATION;
    while (cert_hostname_buff_index < len &&
        cert_hostname_buff[cert_hostname_buff_index] != TEXT('\0') &&
        result == WINTLS_PEER_FAILED_VERIFICATION) {

        char* cert_hostname;

        /* Comparing the cert name and the connection hostname encoded as UTF-8
         * is acceptable since both values are assumed to use ASCII
         * (or some equivalent) encoding
         */
        cert_hostname = wintlsx_convert_tchar_to_UTF8(
            &cert_hostname_buff[cert_hostname_buff_index]);
        if (!cert_hostname) {
            result = WINTLS_OUT_OF_MEMORY;
        }
        else {
            if (wintls_cert_hostcheck(cert_hostname, strlen(cert_hostname),
                conn_hostname, hostlen)) {
                infof(data,
                    "schannel: connection hostname (%s) validated "
                    "against certificate name (%s)",
                    conn_hostname, cert_hostname);
                result = WINTLS_OK;
            }
            else {
                size_t cert_hostname_len;

                infof(data,
                    "schannel: connection hostname (%s) did not match "
                    "against certificate name (%s)",
                    conn_hostname, cert_hostname);

                cert_hostname_len =
                    _tcslen(&cert_hostname_buff[cert_hostname_buff_index]);

                /* Move on to next cert name */
                cert_hostname_buff_index += cert_hostname_len + 1;

                result = WINTLS_PEER_FAILED_VERIFICATION;
            }
            wintlsx_unicodefree(cert_hostname);
        }
    }

    if (result == WINTLS_PEER_FAILED_VERIFICATION) {
        failf(data,
            "schannel: CertGetNameString() failed to match "
            "connection hostname (%s) against server certificate names",
            conn_hostname);
    }
    else if (result != WINTLS_OK)
        failf(data, "schannel: server certificate name verification failed");

cleanup:
    wintls_safefree(cert_hostname_buff);

    return result;
}

wintls_code wintls_verify_certificate(struct wintls* tls)
{
    SECURITY_STATUS sspi_status;
    wintls_code result = WINTLS_OK;
    CERT_CONTEXT* pCertContextServer = NULL;
    const CERT_CHAIN_CONTEXT* pChainContext = NULL;
    HCERTCHAINENGINE cert_chain_engine = NULL;
    HCERTSTORE trust_store = NULL;

    DEBUGASSERT(tls);

    sspi_status =
        s_pSecFn->QueryContextAttributes(&tls->ctxt_handle,
            SECPKG_ATTR_REMOTE_CERT_CONTEXT,
            &pCertContextServer);

    if ((sspi_status != SEC_E_OK) || !pCertContextServer) {
        char buffer[STRERROR_LEN];
        failf(tls, "schannel: Failed to read remote certificate context: %s",
            wintls_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
        result = WINTLS_PEER_FAILED_VERIFICATION;
    }

    if (result == WINTLS_OK &&
        (tls->CAfile || tls->ca_info_blob) &&
        tls->use_manual_cred_validation) {
        /*
         * Create a chain engine that uses the certificates in the CA file as
         * trusted certificates. This is only supported on Windows 7+.
         */

        if (wintlsx_verify_windows_version(6, 1, 0, PLATFORM_WINNT,
            VERSION_LESS_THAN)) {
            failf(tls, "schannel: this version of Windows is too old to support "
                "certificate verification via CA bundle file.");
            result = WINTLS_SSL_CACERT_BADFILE;
        }
        else {
            /* Open the certificate store */
            trust_store = CertOpenStore(CERT_STORE_PROV_MEMORY,
                0,
                (HCRYPTPROV)NULL,
                CERT_STORE_CREATE_NEW_FLAG,
                NULL);
            if (!trust_store) {
                char buffer[STRERROR_LEN];
                failf(tls, "schannel: failed to create certificate store: %s",
                    wintls_winapi_strerror(GetLastError(), buffer, sizeof(buffer)));
                result = WINTLS_SSL_CACERT_BADFILE;
            }
            else {
                const struct wintls_blob* ca_info_blob = tls->ca_info_blob;
                if (ca_info_blob) {
                    result = add_certs_data_to_store(trust_store,
                        (const char*)ca_info_blob->data,
                        ca_info_blob->len,
                        "(memory blob)",
                        tls);
                }
                else {
                    result = add_certs_file_to_store(trust_store,
                        tls->CAfile,
                        tls);
                }
            }
        }

        if (result == WINTLS_OK) {
            struct cert_chain_engine_config_win7 engine_config;
            BOOL create_engine_result;

            memset(&engine_config, 0, sizeof(engine_config));
            engine_config.cbSize = sizeof(engine_config);
            engine_config.hExclusiveRoot = trust_store;

            /* CertCreateCertificateChainEngine will check the expected size of the
             * CERT_CHAIN_ENGINE_CONFIG structure and fail if the specified size
             * does not match the expected size. When this occurs, it indicates that
             * CAINFO is not supported on the version of Windows in use.
             */
            create_engine_result =
                CertCreateCertificateChainEngine(
                    (CERT_CHAIN_ENGINE_CONFIG*)&engine_config, &cert_chain_engine);
            if (!create_engine_result) {
                char buffer[STRERROR_LEN];
                failf(tls,
                    "schannel: failed to create certificate chain engine: %s",
                    wintls_winapi_strerror(GetLastError(), buffer, sizeof(buffer)));
                result = WINTLS_SSL_CACERT_BADFILE;
            }
        }
    }

    if (result == WINTLS_OK) {
        CERT_CHAIN_PARA ChainPara;

        memset(&ChainPara, 0, sizeof(ChainPara));
        ChainPara.cbSize = sizeof(ChainPara);

        if (!CertGetCertificateChain(cert_chain_engine,
            pCertContextServer,
            NULL,
            pCertContextServer->hCertStore,
            &ChainPara,
            (tls->no_revoke ? 0 :
                CERT_CHAIN_REVOCATION_CHECK_CHAIN),
            NULL,
            &pChainContext)) {
            char buffer[STRERROR_LEN];
            failf(tls, "schannel: CertGetCertificateChain failed: %s",
                wintls_winapi_strerror(GetLastError(), buffer, sizeof(buffer)));
            pChainContext = NULL;
            result = WINTLS_PEER_FAILED_VERIFICATION;
        }

        if (result == WINTLS_OK) {
            CERT_SIMPLE_CHAIN* pSimpleChain = pChainContext->rgpChain[0];
            DWORD dwTrustErrorMask = ~(DWORD)(CERT_TRUST_IS_NOT_TIME_NESTED);
            dwTrustErrorMask &= pSimpleChain->TrustStatus.dwErrorStatus;

            if (tls->revoke_best_effort) {
                /* Ignore errors when root certificates are missing the revocation
                 * list URL, or when the list could not be downloaded because the
                 * server is currently unreachable. */
                dwTrustErrorMask &= ~(DWORD)(CERT_TRUST_REVOCATION_STATUS_UNKNOWN |
                    CERT_TRUST_IS_OFFLINE_REVOCATION);
            }

            if (dwTrustErrorMask) {
                if (dwTrustErrorMask & CERT_TRUST_IS_REVOKED)
                    failf(tls, "schannel: CertGetCertificateChain trust error"
                        " CERT_TRUST_IS_REVOKED");
                else if (dwTrustErrorMask & CERT_TRUST_IS_PARTIAL_CHAIN)
                    failf(tls, "schannel: CertGetCertificateChain trust error"
                        " CERT_TRUST_IS_PARTIAL_CHAIN");
                else if (dwTrustErrorMask & CERT_TRUST_IS_UNTRUSTED_ROOT)
                    failf(tls, "schannel: CertGetCertificateChain trust error"
                        " CERT_TRUST_IS_UNTRUSTED_ROOT");
                else if (dwTrustErrorMask & CERT_TRUST_IS_NOT_TIME_VALID)
                    failf(tls, "schannel: CertGetCertificateChain trust error"
                        " CERT_TRUST_IS_NOT_TIME_VALID");
                else if (dwTrustErrorMask & CERT_TRUST_REVOCATION_STATUS_UNKNOWN)
                    failf(tls, "schannel: CertGetCertificateChain trust error"
                        " CERT_TRUST_REVOCATION_STATUS_UNKNOWN");
                else
                    failf(tls, "schannel: CertGetCertificateChain error mask: 0x%08x",
                        dwTrustErrorMask);
                result = WINTLS_PEER_FAILED_VERIFICATION;
            }
        }
    }

    if (result == WINTLS_OK) {
        if (tls->verifyhost) {
            result = verify_host(tls, pCertContextServer, tls->hostname);
        }
    }

    if (cert_chain_engine) {
        CertFreeCertificateChainEngine(cert_chain_engine);
    }

    if (trust_store) {
        CertCloseStore(trust_store, 0);
    }

    if (pChainContext)
        CertFreeCertificateChain(pChainContext);

    if (pCertContextServer)
        CertFreeCertificateContext(pCertContextServer);

    return result;
}


/* ======================================================================
 * source: alpn.c
 ====================================================================== */

#define WANT_PARSEX509 /* uses wintls_parseX509() */


#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <stdio.h>


wintls_code wintls_alpn_to_proto_buf(struct alpn_proto_buf* buf,
    const struct alpn_spec* spec)
{
    size_t i, len;
    int off = 0;
    unsigned char blen;

    memset(buf, 0, sizeof(*buf));
    for (i = 0; spec && i < spec->count; ++i) {
        len = strlen(spec->entries[i]);
        if (len >= ALPN_NAME_MAX)
            return WINTLS_FAILED_INIT;
        blen = (unsigned  char)len;
        if (off + blen + 1 >= (int)sizeof(buf->data))
            return WINTLS_FAILED_INIT;
        buf->data[off++] = blen;
        memcpy(buf->data + off, spec->entries[i], blen);
        off += blen;
    }
    buf->len = off;
    return WINTLS_OK;
}

wintls_code wintls_alpn_to_proto_str(struct alpn_proto_buf* buf,
    const struct alpn_spec* spec)
{
    size_t i, len;
    size_t off = 0;

    memset(buf, 0, sizeof(*buf));
    for (i = 0; spec && i < spec->count; ++i) {
        len = strlen(spec->entries[i]);
        if (len >= ALPN_NAME_MAX)
            return WINTLS_FAILED_INIT;
        if (off + len + 2 >= sizeof(buf->data))
            return WINTLS_FAILED_INIT;
        if (off)
            buf->data[off++] = ',';
        memcpy(buf->data + off, spec->entries[i], len);
        off += len;
    }
    buf->data[off] = '\0';
    buf->len = (int)off;
    return WINTLS_OK;
}

wintls_code wintls_alpn_set_negotiated(struct wintls* tls,
    const unsigned char* proto,
    size_t proto_len)
{
    int can_multi = 0;
    unsigned char* palpn = tls->alpn;
//#ifndef WINTLS_DISABLE_PROXY
 //   (tls->conn->bits.tunnel_proxy && wintls_ssl_cf_is_proxy(cf)) ?
 //       &cf->conn->proxy_alpn : &cf->conn->alpn
//.#else
//        & cf->conn->alpn
//#endif
        ;

    if (proto && proto_len) {
        if (proto_len == ALPN_HTTP_1_1_LENGTH &&
            !memcmp(ALPN_HTTP_1_1, proto, ALPN_HTTP_1_1_LENGTH)) {
            *palpn = WINTLS_HTTP_VERSION_1_1;
        }
        else if (proto_len == ALPN_HTTP_1_0_LENGTH &&
            !memcmp(ALPN_HTTP_1_0, proto, ALPN_HTTP_1_0_LENGTH)) {
            *palpn = WINTLS_HTTP_VERSION_1_0;
        }
#ifdef USE_HTTP2
        else if (proto_len == ALPN_H2_LENGTH &&
            !memcmp(ALPN_H2, proto, ALPN_H2_LENGTH)) {
            *palpn = WINTLS_HTTP_VERSION_2;
            can_multi = 1;
        }
#endif
#ifdef USE_HTTP3
        else if (proto_len == ALPN_H3_LENGTH &&
            !memcmp(ALPN_H3, proto, ALPN_H3_LENGTH)) {
            *palpn = WINTLS_HTTP_VERSION_3;
            can_multi = 1;
        }
#endif
        else {
            *palpn = WINTLS_HTTP_VERSION_NONE;
            failf(tls, "unsupported ALPN protocol: '%.*s'", (int)proto_len, proto);
            /* TODO: do we want to fail this? Previous code just ignored it and
             * some vtls backends even ignore the return code of this function. */
             /* return WINTLS_NOT_BUILT_IN; */
            goto out;
        }
        infof(tls, VTLS_INFOF_ALPN_ACCEPTED_LEN_1STR, (int)proto_len, proto);
    }
    else {
        *palpn = WINTLS_HTTP_VERSION_NONE;
        infof(tls, VTLS_INFOF_NO_ALPN);
    }

out:
    //if (!wintls_ssl_cf_is_proxy(cf))
   //     wintls_multiuse_state(data, can_multi ?
    //        BUNDLE_MULTIPLEX : BUNDLE_NO_MULTIUSE);
    return WINTLS_OK;
}



/* ======================================================================
 * source: wintls.c
 ====================================================================== */


/* returns TRUE if the blobs are identical */
BOOL blobcmp(struct wintls_blob* first, struct wintls_blob* second)
{
    if (!first && !second) /* both are NULL */
        return TRUE;
    if (!first || !second) /* one is NULL */
        return FALSE;
    if (first->len != second->len) /* different sizes */
        return FALSE;
    return !memcmp(first->data, second->data, first->len); /* same data */
}



/* ======================================================================
 * source: schannel_wintls.c
 ====================================================================== */



 /*
  * Source file for all Schannel-specific code for the TLS/SSL layer. No code
  * but vtls.c should ever call or use these functions.
  */

  //#include "wintls_setup.h"

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <stdio.h>
#define EXPOSE_SCHANNEL_INTERNAL_STRUCTS


//#include "connection_data.h"

#define VTLS_INFOF_NO_ALPN                                      \
  "ALPN: server did not agree on a protocol. Uses default."
#define VTLS_INFOF_ALPN_OFFER_1STR              \
  "ALPN: offers %s"
#define VTLS_INFOF_ALPN_ACCEPTED_1STR           \
  ALPN_ACCEPTED "%s"
#define VTLS_INFOF_ALPN_ACCEPTED_LEN_1STR       \
  ALPN_ACCEPTED "%.*s"



/* ALPN requires version 8.1 of the Windows SDK, which was
   shipped with Visual Studio 2013, aka _MSC_VER 1800:

   https://technet.microsoft.com/en-us/library/hh831771%28v=ws.11%29.aspx
*/
#if defined(_MSC_VER) && (_MSC_VER >= 1800) && !defined(_USING_V110_SDK71_)
#  define HAS_ALPN 1
#endif

#ifndef UNISP_NAME_A
#define UNISP_NAME_A "Microsoft Unified Security Protocol Provider"
#endif

#ifndef UNISP_NAME_W
#define UNISP_NAME_W L"Microsoft Unified Security Protocol Provider"
#endif

#ifndef UNISP_NAME
#ifdef UNICODE
#define UNISP_NAME  UNISP_NAME_W
#else
#define UNISP_NAME  UNISP_NAME_A
#endif
#endif

#ifndef BCRYPT_CHACHA20_POLY1305_ALGORITHM
#define BCRYPT_CHACHA20_POLY1305_ALGORITHM L"CHACHA20_POLY1305"
#endif

#ifndef BCRYPT_CHAIN_MODE_CCM
#define BCRYPT_CHAIN_MODE_CCM L"ChainingModeCCM"
#endif

#ifndef BCRYPT_CHAIN_MODE_GCM
#define BCRYPT_CHAIN_MODE_GCM L"ChainingModeGCM"
#endif

#ifndef BCRYPT_AES_ALGORITHM
#define BCRYPT_AES_ALGORITHM L"AES"
#endif

#ifndef BCRYPT_SHA256_ALGORITHM
#define BCRYPT_SHA256_ALGORITHM L"SHA256"
#endif

#ifndef BCRYPT_SHA384_ALGORITHM
#define BCRYPT_SHA384_ALGORITHM L"SHA384"
#endif

/* Workaround broken compilers like MinGW.
   Return the number of elements in a statically sized array.
*/
#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

#ifdef HAS_CLIENT_CERT_PATH
#ifdef UNICODE
#define WINTLS_CERT_STORE_PROV_SYSTEM CERT_STORE_PROV_SYSTEM_W
#else
#define WINTLS_CERT_STORE_PROV_SYSTEM CERT_STORE_PROV_SYSTEM_A
#endif
#endif

#ifndef SP_PROT_SSL2_CLIENT
#define SP_PROT_SSL2_CLIENT             0x00000008
#endif

#ifndef SP_PROT_SSL3_CLIENT
#define SP_PROT_SSL3_CLIENT             0x00000008
#endif

#ifndef SP_PROT_TLS1_CLIENT
#define SP_PROT_TLS1_CLIENT             0x00000080
#endif

#ifndef SP_PROT_TLS1_0_CLIENT
#define SP_PROT_TLS1_0_CLIENT           SP_PROT_TLS1_CLIENT
#endif

#ifndef SP_PROT_TLS1_1_CLIENT
#define SP_PROT_TLS1_1_CLIENT           0x00000200
#endif

#ifndef SP_PROT_TLS1_2_CLIENT
#define SP_PROT_TLS1_2_CLIENT           0x00000800
#endif

#ifndef SP_PROT_TLS1_3_CLIENT
#define SP_PROT_TLS1_3_CLIENT           0x00002000
#endif

#ifndef SCH_USE_STRONG_CRYPTO
#define SCH_USE_STRONG_CRYPTO           0x00400000
#endif

#ifndef SECBUFFER_ALERT
#define SECBUFFER_ALERT                 17
#endif

/* Both schannel buffer sizes must be > 0 */
#define WINTLS_SCHANNEL_BUFFER_INIT_SIZE   4096
#define WINTLS_SCHANNEL_BUFFER_FREE_SIZE   1024

#define CERT_THUMBPRINT_STR_LEN 40
#define CERT_THUMBPRINT_DATA_LEN 20

/* Uncomment to force verbose output
 * #define infof(x, y, ...) printf(y, __VA_ARGS__)
 * #define failf(x, y, ...) printf(y, __VA_ARGS__)
 */

#ifndef CALG_SHA_256
#  define CALG_SHA_256 0x0000800c
#endif

 /* Work around typo in classic MinGW's w32api up to version 5.0,
	see https://osdn.net/projects/mingw/ticket/38391 */
#if !defined(ALG_CLASS_DHASH) && defined(ALG_CLASS_HASH)
#define ALG_CLASS_DHASH ALG_CLASS_HASH
#endif

#ifndef PKCS12_NO_PERSIST_KEY
#define PKCS12_NO_PERSIST_KEY 0x00008000
#endif


static void InitSecBuffer(SecBuffer* buffer, unsigned long BufType,
	void* BufDataPtr, unsigned long BufByteSize)
{
	buffer->cbBuffer = BufByteSize;
	buffer->BufferType = BufType;
	buffer->pvBuffer = BufDataPtr;
}

static void InitSecBufferDesc(SecBufferDesc* desc, SecBuffer* BufArr,
	unsigned long NumArrElem)
{
	desc->ulVersion = SECBUFFER_VERSION;
	desc->pBuffers = BufArr;
	desc->cBuffers = NumArrElem;
}


static wintls_code pubkey_pem_to_der(const char* pem,
	unsigned char** der, size_t* der_len)
{
	char* stripped_pem, * begin_pos, * end_pos;
	size_t pem_count, stripped_pem_count = 0, pem_len;
	wintls_code result;

	/* if no pem, exit. */
	if (!pem)
		return WINTLS_BAD_CONTENT_ENCODING;

	begin_pos = strstr(pem, "-----BEGIN PUBLIC KEY-----");
	if (!begin_pos)
		return WINTLS_BAD_CONTENT_ENCODING;

	pem_count = begin_pos - pem;
	/* Invalid if not at beginning AND not directly following \n */
	if (0 != pem_count && '\n' != pem[pem_count - 1])
		return WINTLS_BAD_CONTENT_ENCODING;

	/* 26 is length of "-----BEGIN PUBLIC KEY-----" */
	pem_count += 26;

	/* Invalid if not directly following \n */
	end_pos = strstr(pem + pem_count, "\n-----END PUBLIC KEY-----");
	if (!end_pos)
		return WINTLS_BAD_CONTENT_ENCODING;

	pem_len = end_pos - pem;

	stripped_pem = malloc(pem_len - pem_count + 1);
	if (!stripped_pem)
		return WINTLS_OUT_OF_MEMORY;

	/*
	 * Here we loop through the pem array one character at a time between the
	 * correct indices, and place each character that is not '\n' or '\r'
	 * into the stripped_pem array, which should represent the raw base64 string
	 */
	while (pem_count < pem_len) {
		if ('\n' != pem[pem_count] && '\r' != pem[pem_count])
			stripped_pem[stripped_pem_count++] = pem[pem_count];
		++pem_count;
	}
	/* Place the null terminator in the correct place */
	stripped_pem[stripped_pem_count] = '\0';

	result = wintls_base64_decode(stripped_pem, der, der_len);

	wintls_safefree(stripped_pem);

	return result;
}

wintls_code wintls_pin_peer_pubkey(struct wintls* data,
	const char* pinnedpubkey,
	const unsigned char* pubkey, size_t pubkeylen)
{
	FILE* fp;
	unsigned char* buf = NULL, * pem_ptr = NULL;
	wintls_code result = WINTLS_SSL_PINNEDPUBKEYNOTMATCH;

	/* if a path wasn't specified, don't pin */
	if (!pinnedpubkey)
		return WINTLS_OK;
	if (!pubkey || !pubkeylen)
		return result;

	/* only do this if pinnedpubkey starts with "sha256//", length 8 */
	if (strncmp(pinnedpubkey, "sha256//", 8) == 0) {
		wintls_code encode;
		size_t encodedlen, pinkeylen;
		char* encoded, * pinkeycopy, * begin_pos, * end_pos;
		unsigned char* sha256sumdigest;

		/* compute sha256sum of public key */
		sha256sumdigest = malloc(WINTLS_SHA256_DIGEST_LENGTH);
		if (!sha256sumdigest)
			return WINTLS_OUT_OF_MEMORY;
		encode = schannel_sha256sum(pubkey, pubkeylen,
			sha256sumdigest, WINTLS_SHA256_DIGEST_LENGTH);

		if (encode != WINTLS_OK)
			return encode;

		encode = wintls_base64_encode((char*)sha256sumdigest,
			WINTLS_SHA256_DIGEST_LENGTH, &encoded,
			&encodedlen);
		wintls_safefree(sha256sumdigest);

		if (encode)
			return encode;

		infof(data, " public key hash: sha256//%s", encoded);

		/* it starts with sha256//, copy so we can modify it */
		pinkeylen = strlen(pinnedpubkey) + 1;
		pinkeycopy = malloc(pinkeylen);
		if (!pinkeycopy) {
			wintls_safefree(encoded);
			return WINTLS_OUT_OF_MEMORY;
		}
		data->do_memcpy(pinkeycopy, pinnedpubkey, pinkeylen);
		/* point begin_pos to the copy, and start extracting keys */
		begin_pos = pinkeycopy;
		do {
			end_pos = strstr(begin_pos, ";sha256//");
			/*
			 * if there is an end_pos, null terminate,
			 * otherwise it'll go to the end of the original string
			 */
			if (end_pos)
				end_pos[0] = '\0';

			/* compare base64 sha256 digests, 8 is the length of "sha256//" */
			if (encodedlen == strlen(begin_pos + 8) &&
				!memcmp(encoded, begin_pos + 8, encodedlen)) {
				result = WINTLS_OK;
				break;
			}

			/*
			 * change back the null-terminator we changed earlier,
			 * and look for next begin
			 */
			if (end_pos) {
				end_pos[0] = ';';
				begin_pos = strstr(end_pos, "sha256//");
			}
		} while (end_pos && begin_pos);
		wintls_safefree(encoded);
		wintls_safefree(pinkeycopy);
		return result;
	}

	fp = fopen(pinnedpubkey, "rb");
	if (!fp)
		return result;

	do {
		long filesize;
		size_t size, pem_len;
		wintls_code pem_read;

		/* Determine the file's size */
		if (fseek(fp, 0, SEEK_END))
			break;
		filesize = ftell(fp);
		if (fseek(fp, 0, SEEK_SET))
			break;
		if (filesize < 0 || filesize > MAX_PINNED_PUBKEY_SIZE)
			break;

		/*
		 * if the size of our certificate is bigger than the file
		 * size then it can't match
		 */
		size = (size_t)(filesize & WINTLS_MASK_USIZE_T);
		if (pubkeylen > size)
			break;

		/*
		 * Allocate buffer for the pinned key
		 * With 1 additional byte for null terminator in case of PEM key
		 */
		buf = malloc(size + 1);
		if (!buf)
			break;

		/* Returns number of elements read, which should be 1 */
		if ((int)fread(buf, size, 1, fp) != 1)
			break;

		/* If the sizes are the same, it can't be base64 encoded, must be der */
		if (pubkeylen == size) {
			if (!memcmp(pubkey, buf, pubkeylen))
				result = WINTLS_OK;
			break;
		}

		/*
		 * Otherwise we will assume it's PEM and try to decode it
		 * after placing null terminator
		 */
		buf[size] = '\0';
		pem_read = pubkey_pem_to_der((const char*)buf, &pem_ptr, &pem_len);
		/* if it wasn't read successfully, exit */
		if (pem_read)
			break;

		/*
		 * if the size of our certificate doesn't match the size of
		 * the decoded file, they can't be the same, otherwise compare
		 */
		if (pubkeylen == pem_len && !memcmp(pubkey, pem_ptr, pubkeylen))
			result = WINTLS_OK;
	} while (0);

	wintls_safefree(buf);
	wintls_safefree(pem_ptr);
	fclose(fp);

	return result;
}

static wintls_code pkp_pin_peer_pubkey(struct wintls* tls,
	const char* pinnedpubkey)
{
	CERT_CONTEXT* pCertContextServer = NULL;

	/* Result is returned to caller */
	wintls_code result = WINTLS_SSL_PINNEDPUBKEYNOTMATCH;

	DEBUGASSERT(tls);

	/* if a path wasn't specified, don't pin */
	if (!pinnedpubkey)
		return WINTLS_OK;

	do {
		SECURITY_STATUS sspi_status;
		const char* x509_der;
		DWORD x509_der_len;
		struct wintls_X509certificate x509_parsed;
		struct wintls_asn1Element* pubkey;

		sspi_status =
			s_pSecFn->QueryContextAttributes(&tls->ctxt_handle,
				SECPKG_ATTR_REMOTE_CERT_CONTEXT,
				&pCertContextServer);

		if ((sspi_status != SEC_E_OK) || !pCertContextServer) {
			char buffer[STRERROR_LEN];
			failf(tls, "schannel: Failed to read remote certificate context: %s",
				wintls_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
			break; /* failed */
		}


		if (!(((pCertContextServer->dwCertEncodingType & X509_ASN_ENCODING) != 0) &&
			(pCertContextServer->cbCertEncoded > 0)))
			break;

		x509_der = (const char*)pCertContextServer->pbCertEncoded;
		x509_der_len = pCertContextServer->cbCertEncoded;
		memset(&x509_parsed, 0, sizeof(x509_parsed));
		if (wintls_parseX509(&x509_parsed, x509_der, x509_der + x509_der_len))
			break;

		pubkey = &x509_parsed.subjectPublicKeyInfo;
		if (!pubkey->header || pubkey->end <= pubkey->header) {
			failf(tls, "SSL: failed retrieving public key from server certificate");
			break;
		}

		result = wintls_pin_peer_pubkey(tls,
			pinnedpubkey,
			(const unsigned char*)pubkey->header,
			(size_t)(pubkey->end - pubkey->header));
		if (result) {
			failf(tls, "SSL: public key does not match pinned public key");
		}
	} while (0);

	if (pCertContextServer)
		CertFreeCertificateContext(pCertContextServer);

	return result;
}

static wintls_code
set_ssl_version_min_max(DWORD* enabled_protocols,
	struct wintls* tls)
{
	(*enabled_protocols) |= SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
	return WINTLS_OK;
}

/* longest is 26, buffer is slightly bigger */
#define LONGEST_ALG_ID 32
#define CIPHEROPTION(x) {#x, x}



struct algo {
	const char* name;
	int id;
};

static const struct algo algs[] = {
  CIPHEROPTION(CALG_MD2),
  CIPHEROPTION(CALG_MD4),
  CIPHEROPTION(CALG_MD5),
  CIPHEROPTION(CALG_SHA),
  CIPHEROPTION(CALG_SHA1),
  CIPHEROPTION(CALG_MAC),
  CIPHEROPTION(CALG_RSA_SIGN),
  CIPHEROPTION(CALG_DSS_SIGN),
  /* ifdefs for the options that are defined conditionally in wincrypt.h */
  #ifdef CALG_NO_SIGN
	CIPHEROPTION(CALG_NO_SIGN),
  #endif
	CIPHEROPTION(CALG_RSA_KEYX),
	CIPHEROPTION(CALG_DES),
  #ifdef CALG_3DES_112
	CIPHEROPTION(CALG_3DES_112),
  #endif
	CIPHEROPTION(CALG_3DES),
	CIPHEROPTION(CALG_DESX),
	CIPHEROPTION(CALG_RC2),
	CIPHEROPTION(CALG_RC4),
	CIPHEROPTION(CALG_SEAL),
  #ifdef CALG_DH_SF
	CIPHEROPTION(CALG_DH_SF),
  #endif
	CIPHEROPTION(CALG_DH_EPHEM),
  #ifdef CALG_AGREEDKEY_ANY
	CIPHEROPTION(CALG_AGREEDKEY_ANY),
  #endif
  #ifdef CALG_HUGHES_MD5
	CIPHEROPTION(CALG_HUGHES_MD5),
  #endif
	CIPHEROPTION(CALG_SKIPJACK),
  #ifdef CALG_TEK
	CIPHEROPTION(CALG_TEK),
  #endif
	CIPHEROPTION(CALG_CYLINK_MEK),
	CIPHEROPTION(CALG_SSL3_SHAMD5),
  #ifdef CALG_SSL3_MASTER
	CIPHEROPTION(CALG_SSL3_MASTER),
  #endif
  #ifdef CALG_SCHANNEL_MASTER_HASH
	CIPHEROPTION(CALG_SCHANNEL_MASTER_HASH),
  #endif
  #ifdef CALG_SCHANNEL_MAC_KEY
	CIPHEROPTION(CALG_SCHANNEL_MAC_KEY),
  #endif
  #ifdef CALG_SCHANNEL_ENC_KEY
	CIPHEROPTION(CALG_SCHANNEL_ENC_KEY),
  #endif
  #ifdef CALG_PCT1_MASTER
	CIPHEROPTION(CALG_PCT1_MASTER),
  #endif
  #ifdef CALG_SSL2_MASTER
	CIPHEROPTION(CALG_SSL2_MASTER),
  #endif
  #ifdef CALG_TLS1_MASTER
	CIPHEROPTION(CALG_TLS1_MASTER),
  #endif
  #ifdef CALG_RC5
	CIPHEROPTION(CALG_RC5),
  #endif
  #ifdef CALG_HMAC
	CIPHEROPTION(CALG_HMAC),
  #endif
  #ifdef CALG_TLS1PRF
	CIPHEROPTION(CALG_TLS1PRF),
  #endif
  #ifdef CALG_HASH_REPLACE_OWF
	CIPHEROPTION(CALG_HASH_REPLACE_OWF),
  #endif
  #ifdef CALG_AES_128
	CIPHEROPTION(CALG_AES_128),
  #endif
  #ifdef CALG_AES_192
	CIPHEROPTION(CALG_AES_192),
  #endif
  #ifdef CALG_AES_256
	CIPHEROPTION(CALG_AES_256),
  #endif
  #ifdef CALG_AES
	CIPHEROPTION(CALG_AES),
  #endif
  #ifdef CALG_SHA_256
	CIPHEROPTION(CALG_SHA_256),
  #endif
  #ifdef CALG_SHA_384
	CIPHEROPTION(CALG_SHA_384),
  #endif
  #ifdef CALG_SHA_512
	CIPHEROPTION(CALG_SHA_512),
  #endif
  #ifdef CALG_ECDH
	CIPHEROPTION(CALG_ECDH),
  #endif
  #ifdef CALG_ECMQV
	CIPHEROPTION(CALG_ECMQV),
  #endif
  #ifdef CALG_ECDSA
	CIPHEROPTION(CALG_ECDSA),
  #endif
  #ifdef CALG_ECDH_EPHEM
	CIPHEROPTION(CALG_ECDH_EPHEM),
  #endif
	{NULL, 0},
};



/* convenience macro to check if this handle is using a shared SSL session */
#define SSLSESSION_SHARED(tls) (tls->share &&                        \
                                 (tls->share->specifier &             \
                                  (1<<WINTLS_LOCK_DATA_SSL_SESSION)))

typedef enum {
	WINTLSSHE_OK,  /* all is fine */
	WINTLSSHE_BAD_OPTION, /* 1 */
	WINTLSSHE_IN_USE,     /* 2 */
	WINTLSSHE_INVALID,    /* 3 */
	WINTLSSHE_NOMEM,      /* 4 out of memory */
	WINTLSSHE_NOT_BUILT_IN, /* 5 feature not present in lib */
	WINTLSSHE_LAST        /* never use */
} WINTLSSHcode;

WINTLSSHcode
wintls_share_lock(struct wintls* tls, wintls_lock_data type,
	wintls_lock_access accesstype)
{
	struct wintls_share* share = tls->share;

	if (!share)
		return WINTLSSHE_INVALID;

	if (share->specifier & (1 << type)) {
		if (share->lockfunc) /* only call this if set! */
			share->lockfunc(tls, type, accesstype, share->clientdata);
	}
	/* else if we don't share this, pretend successful lock */

	return WINTLSSHE_OK;
}

WINTLSSHcode
wintls_share_unlock(struct wintls* tls, wintls_lock_data type)
{
	struct wintls_share* share = tls->share;

	if (!share)
		return WINTLSSHE_INVALID;

	if (share->specifier & (1 << type)) {
		if (share->unlockfunc) /* only call this if set! */
			share->unlockfunc(tls, type, share->clientdata);
	}

	return WINTLSSHE_OK;
}




static int
get_alg_id_by_name(char* name)
{
	char* nameEnd = strchr(name, ':');
	size_t n = nameEnd ? (size_t)(nameEnd - name) : strlen(name);
	int i;

	for (i = 0; algs[i].name; i++) {
		if ((n == strlen(algs[i].name) && !strncmp(algs[i].name, name, n)))
			return algs[i].id;
	}
	return 0; /* not found */
}

#define NUM_CIPHERS 47 /* There are 47 options listed above */

static wintls_code
set_ssl_ciphers(SCHANNEL_CRED* schannel_cred, char* ciphers,
	ALG_ID* algIds)
{
	char* startCur = ciphers;
	int algCount = 0;
	while (startCur && (0 != *startCur) && (algCount < NUM_CIPHERS)) {
		long alg = strtol(startCur, 0, 0);
		if (!alg)
			alg = get_alg_id_by_name(startCur);
		if (alg)
			algIds[algCount++] = alg;
		else if (!strncmp(startCur, "USE_STRONG_CRYPTO",
			sizeof("USE_STRONG_CRYPTO") - 1) ||
			!strncmp(startCur, "SCH_USE_STRONG_CRYPTO",
				sizeof("SCH_USE_STRONG_CRYPTO") - 1))
			schannel_cred->dwFlags |= SCH_USE_STRONG_CRYPTO;
		else
			return WINTLS_SSL_CIPHER;
		startCur = strchr(startCur, ':');
		if (startCur)
			startCur++;
	}
	schannel_cred->palgSupportedAlgs = algIds;
	schannel_cred->cSupportedAlgs = algCount;
	return WINTLS_OK;
}

#ifdef HAS_CLIENT_CERT_PATH

/* Function allocates memory for store_path only if WINTLS_OK is returned */
static wintls_code
get_cert_location(TCHAR* path, DWORD* store_name, TCHAR** store_path,
	TCHAR** thumbprint)
{
	TCHAR* sep;
	TCHAR* store_path_start;
	size_t store_name_len;

	sep = _tcschr(path, TEXT('\\'));
	if (!sep)
		return WINTLS_SSL_CERTPROBLEM;

	store_name_len = sep - path;

	if (_tcsncmp(path, TEXT("CurrentUser"), store_name_len) == 0)
		*store_name = CERT_SYSTEM_STORE_CURRENT_USER;
	else if (_tcsncmp(path, TEXT("LocalMachine"), store_name_len) == 0)
		*store_name = CERT_SYSTEM_STORE_LOCAL_MACHINE;
	else if (_tcsncmp(path, TEXT("CurrentService"), store_name_len) == 0)
		*store_name = CERT_SYSTEM_STORE_CURRENT_SERVICE;
	else if (_tcsncmp(path, TEXT("Services"), store_name_len) == 0)
		*store_name = CERT_SYSTEM_STORE_SERVICES;
	else if (_tcsncmp(path, TEXT("Users"), store_name_len) == 0)
		*store_name = CERT_SYSTEM_STORE_USERS;
	else if (_tcsncmp(path, TEXT("CurrentUserGroupPolicy"),
		store_name_len) == 0)
		*store_name = CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY;
	else if (_tcsncmp(path, TEXT("LocalMachineGroupPolicy"),
		store_name_len) == 0)
		*store_name = CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY;
	else if (_tcsncmp(path, TEXT("LocalMachineEnterprise"),
		store_name_len) == 0)
		*store_name = CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE;
	else
		return WINTLS_SSL_CERTPROBLEM;

	store_path_start = sep + 1;

	sep = _tcschr(store_path_start, TEXT('\\'));
	if (!sep)
		return WINTLS_SSL_CERTPROBLEM;

	*thumbprint = sep + 1;
	if (_tcslen(*thumbprint) != CERT_THUMBPRINT_STR_LEN)
		return WINTLS_SSL_CERTPROBLEM;

	*sep = TEXT('\0');
	*store_path = strdup(store_path_start);//_tcsdup(store_path_start);
	*sep = TEXT('\\');
	if (!*store_path)
		return WINTLS_OUT_OF_MEMORY;

	return WINTLS_OK;
}
#endif
wintls_code
schannel_acquire_credential_handle(struct wintls* tls)
{
#ifdef HAS_CLIENT_CERT_PATH
	PCCERT_CONTEXT client_certs[1] = { NULL };
	HCERTSTORE client_cert_store = NULL;
#endif
	SECURITY_STATUS sspi_status = SEC_E_OK;
	wintls_code result;

	/* setup Schannel API options */
	DWORD flags = 0;
	DWORD enabled_protocols = 0;

	DEBUGASSERT(tls);

	if (tls->verifypeer) {
#ifdef HAS_MANUAL_VERIFY_API
		if (tls->use_manual_cred_validation)
			flags = SCH_CRED_MANUAL_CRED_VALIDATION;
		else
#endif
			flags = SCH_CRED_AUTO_CRED_VALIDATION;

		if (tls->no_revoke) {
			flags |= SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
				SCH_CRED_IGNORE_REVOCATION_OFFLINE;

			DEBUGF(infof(tls, "schannel: disabled server certificate revocation "
				"checks"));
		}
		else if (tls->revoke_best_effort) {
			flags |= SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
				SCH_CRED_IGNORE_REVOCATION_OFFLINE | SCH_CRED_REVOCATION_CHECK_CHAIN;

			DEBUGF(infof(tls, "schannel: ignore revocation offline errors"));
		}
		else {
			flags |= SCH_CRED_REVOCATION_CHECK_CHAIN;

			DEBUGF(infof(tls,
				"schannel: checking server certificate revocation"));
		}
	}
	else {
		flags = SCH_CRED_MANUAL_CRED_VALIDATION |
			SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
			SCH_CRED_IGNORE_REVOCATION_OFFLINE;
		DEBUGF(infof(tls,
			"schannel: disabled server cert revocation checks"));
	}

	if (!tls->verifyhost) {
		flags |= SCH_CRED_NO_SERVERNAME_CHECK;
		DEBUGF(infof(tls, "schannel: verifyhost setting prevents Schannel from "
			"comparing the supplied target name with the subject "
			"names in server certificates."));
	}

	if (!tls->auto_client_cert) {
		flags &= ~SCH_CRED_USE_DEFAULT_CREDS;
		flags |= SCH_CRED_NO_DEFAULT_CREDS;
		infof(tls, "schannel: disabled automatic use of client certificate");
	}
	else
		infof(tls, "schannel: enabled automatic use of client certificate");

	switch (tls->version) {
	case WINTLS_SSLVERSION_DEFAULT:
	case WINTLS_SSLVERSION_TLSv1:
	case WINTLS_SSLVERSION_TLSv1_0:
	case WINTLS_SSLVERSION_TLSv1_1:
	case WINTLS_SSLVERSION_TLSv1_2:
	case WINTLS_SSLVERSION_TLSv1_3:
	{
		result = set_ssl_version_min_max(&enabled_protocols, tls);
		if (result != WINTLS_OK)
			return result;
		break;
	}
	case WINTLS_SSLVERSION_SSLv3:
	case WINTLS_SSLVERSION_SSLv2:
		failf(tls, "SSL versions not supported");
		return WINTLS_NOT_BUILT_IN;
	default:
		failf(tls, "Unrecognized parameter passed via WINTLSOPT_SSLVERSION");
		return WINTLS_SSL_CONNECT_ERROR;
	}

#ifdef HAS_CLIENT_CERT_PATH
	/* client certificate */
	if (tls->clientcert || tls->cert_blob) {
		DWORD cert_store_name = 0;
		TCHAR* cert_store_path = NULL;
		TCHAR* cert_thumbprint_str = NULL;
		CRYPT_HASH_BLOB cert_thumbprint;
		BYTE cert_thumbprint_data[CERT_THUMBPRINT_DATA_LEN];
		HCERTSTORE cert_store = NULL;
		FILE* fInCert = NULL;
		void* certdata = NULL;
		size_t certsize = 0;
		BOOL blob = tls->cert_blob != NULL;
		TCHAR* cert_path = NULL;
		if (blob) {
			certdata = tls->cert_blob->data;
			certsize = tls->cert_blob->len;
		}
		else {
			cert_path = wintlsx_convert_UTF8_to_tchar(tls->clientcert);
			if (!cert_path)
				return WINTLS_OUT_OF_MEMORY;

			result = get_cert_location(cert_path, &cert_store_name,
				&cert_store_path, &cert_thumbprint_str);

			if (result && (tls->clientcert[0] != '\0'))
				fInCert = fopen(tls->clientcert, "rb");

			if (result && !fInCert) {
				failf(tls, "schannel: Failed to get certificate location"
					" or file for %s",
					tls->clientcert);
				wintlsx_unicodefree(cert_path);
				return result;
			}
		}

		if ((fInCert || blob) && (tls->cert_type) &&
			(!strcasecompare(tls->cert_type, "P12"))) {
			failf(tls, "schannel: certificate format compatibility error "
				" for %s",
				blob ? "(memory blob)" : tls->clientcert);
			wintlsx_unicodefree(cert_path);
			return WINTLS_SSL_CERTPROBLEM;
		}

		if (fInCert || blob) {
			/* Reading a .P12 or .pfx file, like the example at bottom of
			   https://social.msdn.microsoft.com/Forums/windowsdesktop/
			   en-US/3e7bc95f-b21a-4bcd-bd2c-7f996718cae5
			*/
			CRYPT_DATA_BLOB datablob;
			WCHAR* pszPassword;
			size_t pwd_len = 0;
			int str_w_len = 0;
			const char* cert_showfilename_error = blob ?
				"(memory blob)" : tls->clientcert;
			wintlsx_unicodefree(cert_path);
			if (fInCert) {
				long cert_tell = 0;
				BOOL continue_reading = fseek(fInCert, 0, SEEK_END) == 0;
				if (continue_reading)
					cert_tell = ftell(fInCert);
				if (cert_tell < 0)
					continue_reading = FALSE;
				else
					certsize = (size_t)cert_tell;
				if (continue_reading)
					continue_reading = fseek(fInCert, 0, SEEK_SET) == 0;
				if (continue_reading)
					certdata = malloc(certsize + 1);
				if ((!certdata) ||
					((int)fread(certdata, certsize, 1, fInCert) != 1))
					continue_reading = FALSE;
				fclose(fInCert);
				if (!continue_reading) {
					failf(tls, "schannel: Failed to read cert file %s",
						tls->clientcert);
					free(certdata);
					return WINTLS_SSL_CERTPROBLEM;
				}
			}

			/* Convert key-pair data to the in-memory certificate store */
			datablob.pbData = (BYTE*)certdata;
			datablob.cbData = (DWORD)certsize;

			if (tls->key_passwd)
				pwd_len = strlen(tls->key_passwd);
			pszPassword = (WCHAR*)malloc(sizeof(WCHAR) * (pwd_len + 1));
			if (pszPassword) {
				if (pwd_len > 0)
					str_w_len = MultiByteToWideChar(CP_UTF8,
						MB_ERR_INVALID_CHARS,
						tls->key_passwd,
						(int)pwd_len,
						pszPassword, (int)(pwd_len + 1));

				if ((str_w_len >= 0) && (str_w_len <= (int)pwd_len))
					pszPassword[str_w_len] = 0;
				else
					pszPassword[0] = 0;

				if (wintlsx_verify_windows_version(6, 0, 0, PLATFORM_WINNT,
					VERSION_GREATER_THAN_EQUAL))
					cert_store = PFXImportCertStore(&datablob, pszPassword,
						PKCS12_NO_PERSIST_KEY);
				else
					cert_store = PFXImportCertStore(&datablob, pszPassword, 0);

				free(pszPassword);
			}
			if (!blob)
				free(certdata);
			if (!cert_store) {
				DWORD errorcode = GetLastError();
				if (errorcode == ERROR_INVALID_PASSWORD)
					failf(tls, "schannel: Failed to import cert file %s, "
						"password is bad",
						cert_showfilename_error);
				else
					failf(tls, "schannel: Failed to import cert file %s, "
						"last error is 0x%x",
						cert_showfilename_error, errorcode);
				return WINTLS_SSL_CERTPROBLEM;
			}

			client_certs[0] = CertFindCertificateInStore(
				cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
				CERT_FIND_ANY, NULL, NULL);

			if (!client_certs[0]) {
				failf(tls, "schannel: Failed to get certificate from file %s"
					", last error is 0x%x",
					cert_showfilename_error, GetLastError());
				CertCloseStore(cert_store, 0);
				return WINTLS_SSL_CERTPROBLEM;
			}
		}
		else {
			cert_store =
				CertOpenStore(WINTLS_CERT_STORE_PROV_SYSTEM, 0,
					(HCRYPTPROV)NULL,
					CERT_STORE_OPEN_EXISTING_FLAG | cert_store_name,
					cert_store_path);
			if (!cert_store) {
				failf(tls, "schannel: Failed to open cert store %x %s, "
					"last error is 0x%x",
					cert_store_name, cert_store_path, GetLastError());
				free(cert_store_path);
				wintlsx_unicodefree(cert_path);
				return WINTLS_SSL_CERTPROBLEM;
			}
			free(cert_store_path);

			cert_thumbprint.pbData = cert_thumbprint_data;
			cert_thumbprint.cbData = CERT_THUMBPRINT_DATA_LEN;

			if (!CryptStringToBinary(cert_thumbprint_str,
				CERT_THUMBPRINT_STR_LEN,
				CRYPT_STRING_HEX,
				cert_thumbprint_data,
				&cert_thumbprint.cbData,
				NULL, NULL)) {
				wintlsx_unicodefree(cert_path);
				CertCloseStore(cert_store, 0);
				return WINTLS_SSL_CERTPROBLEM;
			}

			client_certs[0] = CertFindCertificateInStore(
				cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
				CERT_FIND_HASH, &cert_thumbprint, NULL);

			wintlsx_unicodefree(cert_path);

			if (!client_certs[0]) {
				/* CRYPT_E_NOT_FOUND / E_INVALIDARG */
				CertCloseStore(cert_store, 0);
				return WINTLS_SSL_CERTPROBLEM;
			}
		}
		client_cert_store = cert_store;
	}
#else
	if (data->set.ssl.primary.clientcert || data->set.ssl.primary.cert_blob) {
		failf(data, "schannel: client cert support not built in");
		return WINTLS_NOT_BUILT_IN;
	}
#endif

#ifdef HAS_CLIENT_CERT_PATH
	/* Since we did not persist the key, we need to extend the store's
	 * lifetime until the end of the connection
	 */
	tls->client_cert_store = client_cert_store;
#endif

	/* Windows 10, 1809 (a.k.a. Windows 10 build 17763) */
	if (wintlsx_verify_windows_version(10, 0, 17763, PLATFORM_WINNT,
		VERSION_GREATER_THAN_EQUAL)) {

		char* ciphers13 = 0;

		BOOL disable_aes_gcm_sha384 = FALSE;
		BOOL disable_aes_gcm_sha256 = FALSE;
		BOOL disable_chacha_poly = FALSE;
		BOOL disable_aes_ccm_8_sha256 = FALSE;
		BOOL disable_aes_ccm_sha256 = FALSE;

		SCH_CREDENTIALS credentials = { 0 };
		TLS_PARAMETERS tls_parameters = { 0 };
		CRYPTO_SETTINGS crypto_settings[4] = { 0 };
		UNICODE_STRING blocked_ccm_modes[1] = { 0 };
		UNICODE_STRING blocked_gcm_modes[1] = { 0 };

		int crypto_settings_idx = 0;


		/* If TLS 1.3 ciphers are explicitly listed, then
		 * disable all the ciphers and re-enable which
		 * ciphers the user has provided.
		 */
		ciphers13 = tls->cipher_list13;
		if (ciphers13) {
			const int remaining_ciphers = 5;

			/* detect which remaining ciphers to enable
			   and then disable everything else.
			*/

			char* startCur = ciphers13;
			int algCount = 0;
			char tmp[LONGEST_ALG_ID] = { 0 };
			char* nameEnd;
			size_t n;

			disable_aes_gcm_sha384 = TRUE;
			disable_aes_gcm_sha256 = TRUE;
			disable_chacha_poly = TRUE;
			disable_aes_ccm_8_sha256 = TRUE;
			disable_aes_ccm_sha256 = TRUE;

			while (startCur && (0 != *startCur) && (algCount < remaining_ciphers)) {
				nameEnd = strchr(startCur, ':');
				n = nameEnd ? (size_t)(nameEnd - startCur) : strlen(startCur);

				/* reject too-long cipher names */
				if (n > (LONGEST_ALG_ID - 1)) {
					failf(tls, "Cipher name too long, not checked.");
					return WINTLS_SSL_CIPHER;
				}

				strncpy(tmp, startCur, n);
				tmp[n] = 0;

				if (disable_aes_gcm_sha384
					&& !strcmp("TLS_AES_256_GCM_SHA384", tmp)) {
					disable_aes_gcm_sha384 = FALSE;
				}
				else if (disable_aes_gcm_sha256
					&& !strcmp("TLS_AES_128_GCM_SHA256", tmp)) {
					disable_aes_gcm_sha256 = FALSE;
				}
				else if (disable_chacha_poly
					&& !strcmp("TLS_CHACHA20_POLY1305_SHA256", tmp)) {
					disable_chacha_poly = FALSE;
				}
				else if (disable_aes_ccm_8_sha256
					&& !strcmp("TLS_AES_128_CCM_8_SHA256", tmp)) {
					disable_aes_ccm_8_sha256 = FALSE;
				}
				else if (disable_aes_ccm_sha256
					&& !strcmp("TLS_AES_128_CCM_SHA256", tmp)) {
					disable_aes_ccm_sha256 = FALSE;
				}
				else {
					failf(tls, "Passed in an unknown TLS 1.3 cipher.");
					return WINTLS_SSL_CIPHER;
				}

				startCur = nameEnd;
				if (startCur)
					startCur++;

				algCount++;
			}
		}

		if (disable_aes_gcm_sha384 && disable_aes_gcm_sha256
			&& disable_chacha_poly && disable_aes_ccm_8_sha256
			&& disable_aes_ccm_sha256) {
			failf(tls, "All available TLS 1.3 ciphers were disabled.");
			return WINTLS_SSL_CIPHER;
		}

		/* Disable TLS_AES_128_CCM_8_SHA256 and/or TLS_AES_128_CCM_SHA256 */
		if (disable_aes_ccm_8_sha256 || disable_aes_ccm_sha256) {
			/*
			  Disallow AES_CCM algorithm.
			*/
			blocked_ccm_modes[0].Length = sizeof(BCRYPT_CHAIN_MODE_CCM);
			blocked_ccm_modes[0].MaximumLength = sizeof(BCRYPT_CHAIN_MODE_CCM);
			blocked_ccm_modes[0].Buffer = (PWSTR)BCRYPT_CHAIN_MODE_CCM;

			crypto_settings[crypto_settings_idx].eAlgorithmUsage =
				TlsParametersCngAlgUsageCipher;
			crypto_settings[crypto_settings_idx].rgstrChainingModes =
				blocked_ccm_modes;
			crypto_settings[crypto_settings_idx].cChainingModes =
				ARRAYSIZE(blocked_ccm_modes);
			crypto_settings[crypto_settings_idx].strCngAlgId.Length =
				sizeof(BCRYPT_AES_ALGORITHM);
			crypto_settings[crypto_settings_idx].strCngAlgId.MaximumLength =
				sizeof(BCRYPT_AES_ALGORITHM);
			crypto_settings[crypto_settings_idx].strCngAlgId.Buffer =
				(PWSTR)BCRYPT_AES_ALGORITHM;

			/* only disabling one of the CCM modes */
			if (disable_aes_ccm_8_sha256 != disable_aes_ccm_sha256) {
				if (disable_aes_ccm_8_sha256)
					crypto_settings[crypto_settings_idx].dwMinBitLength = 128;
				else /* disable_aes_ccm_sha256 */
					crypto_settings[crypto_settings_idx].dwMaxBitLength = 64;
			}

			crypto_settings_idx++;
		}

		/* Disable TLS_AES_256_GCM_SHA384 and/or TLS_AES_128_GCM_SHA256 */
		if (disable_aes_gcm_sha384 || disable_aes_gcm_sha256) {

			/*
			  Disallow AES_GCM algorithm
			*/
			blocked_gcm_modes[0].Length = sizeof(BCRYPT_CHAIN_MODE_GCM);
			blocked_gcm_modes[0].MaximumLength = sizeof(BCRYPT_CHAIN_MODE_GCM);
			blocked_gcm_modes[0].Buffer = (PWSTR)BCRYPT_CHAIN_MODE_GCM;

			/* if only one is disabled, then explicitly disable the
			   digest cipher suite (sha384 or sha256) */
			if (disable_aes_gcm_sha384 != disable_aes_gcm_sha256) {
				crypto_settings[crypto_settings_idx].eAlgorithmUsage =
					TlsParametersCngAlgUsageDigest;
				crypto_settings[crypto_settings_idx].strCngAlgId.Length =
					sizeof(disable_aes_gcm_sha384 ?
						BCRYPT_SHA384_ALGORITHM : BCRYPT_SHA256_ALGORITHM);
				crypto_settings[crypto_settings_idx].strCngAlgId.MaximumLength =
					sizeof(disable_aes_gcm_sha384 ?
						BCRYPT_SHA384_ALGORITHM : BCRYPT_SHA256_ALGORITHM);
				crypto_settings[crypto_settings_idx].strCngAlgId.Buffer =
					(PWSTR)(disable_aes_gcm_sha384 ?
						BCRYPT_SHA384_ALGORITHM : BCRYPT_SHA256_ALGORITHM);
			}
			else { /* Disable both AES_GCM ciphers */
				crypto_settings[crypto_settings_idx].eAlgorithmUsage =
					TlsParametersCngAlgUsageCipher;
				crypto_settings[crypto_settings_idx].strCngAlgId.Length =
					sizeof(BCRYPT_AES_ALGORITHM);
				crypto_settings[crypto_settings_idx].strCngAlgId.MaximumLength =
					sizeof(BCRYPT_AES_ALGORITHM);
				crypto_settings[crypto_settings_idx].strCngAlgId.Buffer =
					(PWSTR)BCRYPT_AES_ALGORITHM;
			}

			crypto_settings[crypto_settings_idx].rgstrChainingModes =
				blocked_gcm_modes;
			crypto_settings[crypto_settings_idx].cChainingModes = 1;

			crypto_settings_idx++;
		}

		/*
		  Disable ChaCha20-Poly1305.
		*/
		if (disable_chacha_poly) {
			crypto_settings[crypto_settings_idx].eAlgorithmUsage =
				TlsParametersCngAlgUsageCipher;
			crypto_settings[crypto_settings_idx].strCngAlgId.Length =
				sizeof(BCRYPT_CHACHA20_POLY1305_ALGORITHM);
			crypto_settings[crypto_settings_idx].strCngAlgId.MaximumLength =
				sizeof(BCRYPT_CHACHA20_POLY1305_ALGORITHM);
			crypto_settings[crypto_settings_idx].strCngAlgId.Buffer =
				(PWSTR)BCRYPT_CHACHA20_POLY1305_ALGORITHM;
			crypto_settings_idx++;
		}

		tls_parameters.pDisabledCrypto = crypto_settings;

		/* The number of blocked suites */
		tls_parameters.cDisabledCrypto = crypto_settings_idx;
		credentials.pTlsParameters = &tls_parameters;
		credentials.cTlsParameters = 1;

		credentials.dwVersion = SCH_CREDENTIALS_VERSION;
		credentials.dwFlags = flags | SCH_USE_STRONG_CRYPTO;

		credentials.pTlsParameters->grbitDisabledProtocols =
			(DWORD)~enabled_protocols;

#ifdef HAS_CLIENT_CERT_PATH
		if (client_certs[0]) {
			credentials.cCreds = 1;
			credentials.paCred = client_certs;
		}
#endif

		sspi_status =
			s_pSecFn->AcquireCredentialsHandle(NULL, (TCHAR*)UNISP_NAME,
				SECPKG_CRED_OUTBOUND, NULL,
				&credentials, NULL, NULL,
				&tls->cred_handle,
				&tls->time_stamp);
	}
	else {
		/* Pre-Windows 10 1809 */
		ALG_ID algIds[NUM_CIPHERS];
		char* ciphers = tls->cipher_list;
		SCHANNEL_CRED schannel_cred = { 0 };
		schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;
		schannel_cred.dwFlags = flags;
		schannel_cred.grbitEnabledProtocols = enabled_protocols;

		if (ciphers) {
			result = set_ssl_ciphers(&schannel_cred, ciphers, algIds);
			if (WINTLS_OK != result) {
				failf(tls, "Unable to set ciphers to from connection ssl config");
				return result;
			}
		}
		else {
			schannel_cred.dwFlags = flags | SCH_USE_STRONG_CRYPTO;
		}

#ifdef HAS_CLIENT_CERT_PATH
		if (client_certs[0]) {
			schannel_cred.cCreds = 1;
			schannel_cred.paCred = client_certs;
		}
#endif

		sspi_status =
			s_pSecFn->AcquireCredentialsHandle(NULL, (TCHAR*)UNISP_NAME,
				SECPKG_CRED_OUTBOUND, NULL,
				&schannel_cred, NULL, NULL,
				&tls->cred_handle,
				&tls->time_stamp);
	}

#ifdef HAS_CLIENT_CERT_PATH
	if (client_certs[0])
		CertFreeCertificateContext(client_certs[0]);
#endif

	if (sspi_status != SEC_E_OK) {
		char buffer[STRERROR_LEN];
		failf(tls, "schannel: AcquireCredentialsHandle failed: %s",
			wintls_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
		switch (sspi_status) {
		case SEC_E_INSUFFICIENT_MEMORY:
			return WINTLS_OUT_OF_MEMORY;
		case SEC_E_NO_CREDENTIALS:
		case SEC_E_SECPKG_NOT_FOUND:
		case SEC_E_NOT_OWNER:
		case SEC_E_UNKNOWN_CREDENTIALS:
		case SEC_E_INTERNAL_ERROR:
		default:
			return WINTLS_SSL_CONNECT_ERROR;
		}
	}

	return WINTLS_OK;
}

BOOL
wintls_ssl_config_matches(struct wintls* data,
	struct wintls* needle)
{
	if ((data->version == needle->version) &&
		(data->version_max == needle->version_max) &&
		(data->ssl_options == needle->ssl_options) &&
		(data->verifypeer == needle->verifypeer) &&
		(data->verifyhost == needle->verifyhost) &&
		(data->verifystatus == needle->verifystatus) &&
		blobcmp(data->cert_blob, needle->cert_blob) &&
		blobcmp(data->ca_info_blob, needle->ca_info_blob) &&
		blobcmp(data->issuercert_blob, needle->issuercert_blob) &&
		wintls_safecmp(data->CApath, needle->CApath) &&
		wintls_safecmp(data->CAfile, needle->CAfile) &&
		wintls_safecmp(data->issuercert, needle->issuercert) &&
		wintls_safecmp(data->clientcert, needle->clientcert) &&
#ifdef USE_TLS_SRP
		!wintls_timestrcmp(data->username, needle->username) &&
		!wintls_timestrcmp(data->password, needle->password) &&
#endif
		strcasecompare(data->cipher_list, needle->cipher_list) &&
		strcasecompare(data->cipher_list13, needle->cipher_list13) &&
		strcasecompare(data->curves, needle->curves) &&
		strcasecompare(data->CRLfile, needle->CRLfile) &&
		strcasecompare(data->pinned_key, needle->pinned_key))
		return TRUE;

	return FALSE;
}



char* wintls_ssl_snihost(struct wintls* tls, const char* host, size_t* olen)
{
	size_t len = strlen(host);
	if (len && (host[len - 1] == '.'))
		len--;
	if (len >= tls->buffer_size)
		return NULL;

	wintls_strntolower(tls->buffer, host, len);
	tls->buffer[len] = 0;
	if (olen)
		*olen = len;
	return tls->buffer;
}

unsigned short wintlsx_uitous(unsigned int uinum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

	DEBUGASSERT(uinum <= (unsigned int)WINTLS_MASK_USHORT);
	return (unsigned short)(uinum & (unsigned int)WINTLS_MASK_USHORT);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}

static wintls_code
schannel_connect_step1(struct wintls* tls)
{
	ssize_t written = -1;
	SecBuffer outbuf;
	SecBufferDesc outbuf_desc;
	SecBuffer inbuf;
	SecBufferDesc inbuf_desc;
#ifdef HAS_ALPN
	unsigned char alpn_buffer[128];
#endif
	SECURITY_STATUS sspi_status = SEC_E_OK;
	struct wintls_schannel_cred* old_cred = NULL;
	struct in_addr addr;
#ifdef ENABLE_IPV6
	struct in6_addr addr6;
#endif
	wintls_code result;
	const char* hostname = tls->hostname;

	DEBUGASSERT(tls);
	DEBUGF(infof(tls,
		"schannel: SSL/TLS connection with %s port %d (step 1/3)",
		hostname, tls->port));

	if (wintlsx_verify_windows_version(5, 1, 0, PLATFORM_WINNT,
		VERSION_LESS_THAN_EQUAL)) {
		/* Schannel in Windows XP (OS version 5.1) uses legacy handshakes and
		   algorithms that may not be supported by all servers. */
		infof(tls, "schannel: Windows version is old and may not be able to "
			"connect to some servers due to lack of SNI, algorithms, etc.");
	}

#ifdef HAS_ALPN
	/* ALPN is only supported on Windows 8.1 / Server 2012 R2 and above.
	   Also it doesn't seem to be supported for Wine, see wintls bug #983. */
	tls->use_alpn = tls->alpn &&
		!GetProcAddress(GetModuleHandle(TEXT("ntdll")),
			"wine_get_version") &&
		wintlsx_verify_windows_version(6, 3, 0, PLATFORM_WINNT,
			VERSION_GREATER_THAN_EQUAL);
#else
	backend->use_alpn = FALSE;
#endif

#ifdef _WIN32_WCE
#ifdef HAS_MANUAL_VERIFY_API
	/* certificate validation on CE doesn't seem to work right; we'll
	 * do it following a more manual process. */
	backend->use_manual_cred_validation = TRUE;
#else
#error "compiler too old to support requisite manual cert verify for Win CE"
#endif
#else
#ifdef HAS_MANUAL_VERIFY_API
	if (tls->CAfile || tls->ca_info_blob) {
		if (wintlsx_verify_windows_version(6, 1, 0, PLATFORM_WINNT,
			VERSION_GREATER_THAN_EQUAL)) {
			tls->use_manual_cred_validation = TRUE;
		}
		else {
			failf(tls, "schannel: this version of Windows is too old to support "
				"certificate verification via CA bundle file.");
			return WINTLS_SSL_CACERT_BADFILE;
		}
	}
	else
		tls->use_manual_cred_validation = FALSE;
#else
	if (conn_config->CAfile || conn_config->ca_info_blob) {
		failf(data, "schannel: CA cert support not built in");
		return WINTLS_NOT_BUILT_IN;
	}
#endif
#endif

	if (!tls->cred_setup) {
		char* snihost;
		result = schannel_acquire_credential_handle(tls);
		if (result)
			return result;
		/* schannel_acquire_credential_handle() sets backend->cred accordingly or
		   it returns error otherwise. */

		   /* A hostname associated with the credential is needed by
			  InitializeSecurityContext for SNI and other reasons. */
		snihost = wintls_ssl_snihost(tls, hostname, NULL);
		if (!snihost) {
			failf(tls, "Failed to set SNI");
			return WINTLS_SSL_CONNECT_ERROR;
		}
		tls->sni_hostname = snihost;
		tls->cred_setup = TRUE;
	}

	/* Warn if SNI is disabled due to use of an IP address */
	if (inet_pton(AF_INET, hostname, &addr)
#ifdef ENABLE_IPV6
		|| inet_pton(AF_INET6, hostname, &addr6)
#endif
		) {
		infof(tls, "schannel: using IP address, SNI is not supported by OS.");
	}

#ifdef HAS_ALPN
	if (tls->use_alpn) {
		int cur = 0;
		int list_start_index = 0;
		unsigned int* extension_len = NULL;
		unsigned short* list_len = NULL;
		struct alpn_proto_buf proto;

		/* The first four bytes will be an unsigned int indicating number
		   of bytes of data in the rest of the buffer. */
		extension_len = (unsigned int*)(void*)(&alpn_buffer[cur]);
		cur += (int)sizeof(unsigned int);

		/* The next four bytes are an indicator that this buffer will contain
		   ALPN data, as opposed to NPN, for example. */
		*(unsigned int*)(void*)&alpn_buffer[cur] =
			SecApplicationProtocolNegotiationExt_ALPN;
		cur += (int)sizeof(unsigned int);

		/* The next two bytes will be an unsigned short indicating the number
		   of bytes used to list the preferred protocols. */
		list_len = (unsigned short*)(void*)(&alpn_buffer[cur]);
		cur += (int)sizeof(unsigned short);

		list_start_index = cur;

		result = wintls_alpn_to_proto_buf(&proto, tls->alpn);
		if (result) {
			failf(tls, "Error setting ALPN");
			return WINTLS_SSL_CONNECT_ERROR;
		}
		tls->do_memcpy(&alpn_buffer[cur], proto.data, proto.len);
		cur += proto.len;

		*list_len = wintlsx_uitous(cur - list_start_index);
		*extension_len = *list_len +
			(unsigned short)sizeof(unsigned int) +
			(unsigned short)sizeof(unsigned short);

		InitSecBuffer(&inbuf, SECBUFFER_APPLICATION_PROTOCOLS, alpn_buffer, cur);
		InitSecBufferDesc(&inbuf_desc, &inbuf, 1);

		wintls_alpn_to_proto_str(&proto, tls->alpn);
		infof(tls, VTLS_INFOF_ALPN_OFFER_1STR, proto.data);
	}
	else {
		InitSecBuffer(&inbuf, SECBUFFER_EMPTY, NULL, 0);
		InitSecBufferDesc(&inbuf_desc, &inbuf, 1);
	}
#else /* HAS_ALPN */
	InitSecBuffer(&inbuf, SECBUFFER_EMPTY, NULL, 0);
	InitSecBufferDesc(&inbuf_desc, &inbuf, 1);
#endif

	/* setup output buffer */
	InitSecBuffer(&outbuf, SECBUFFER_EMPTY, NULL, 0);
	InitSecBufferDesc(&outbuf_desc, &outbuf, 1);

	/* security request flags */
	tls->req_flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
		ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
		ISC_REQ_STREAM;

	if (!tls->auto_client_cert) {
		tls->req_flags |= ISC_REQ_USE_SUPPLIED_CREDS;
	}
	tls->ctxt_setup = TRUE;

	/* Schannel InitializeSecurityContext:
	   https://msdn.microsoft.com/en-us/library/windows/desktop/aa375924.aspx

	   At the moment we don't pass inbuf unless we're using ALPN since we only
	   use it for that, and Wine (for which we currently disable ALPN) is giving
	   us problems with inbuf regardless. https://github.com/wintls/wintls/issues/983
	*/
	sspi_status = s_pSecFn->InitializeSecurityContext(
		&tls->cred_handle, NULL, tls->sni_hostname,
		tls->req_flags, 0, 0,
		(tls->use_alpn ? &inbuf_desc : NULL),
		0, &tls->ctxt_handle,
		&outbuf_desc, &tls->ret_flags, &tls->ctxt_time_stamp);

	if (sspi_status != SEC_I_CONTINUE_NEEDED) {
		char buffer[STRERROR_LEN];
		//wintls_safefree(tls->ctxt_handle);
		switch (sspi_status) {
		case SEC_E_INSUFFICIENT_MEMORY:
			failf(tls, "schannel: initial InitializeSecurityContext failed: %s",
				wintls_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
			return WINTLS_OUT_OF_MEMORY;
		case SEC_E_WRONG_PRINCIPAL:
			failf(tls, "schannel: SNI or certificate check failed: %s",
				wintls_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
			return WINTLS_PEER_FAILED_VERIFICATION;
			/*
			  case SEC_E_INVALID_HANDLE:
			  case SEC_E_INVALID_TOKEN:
			  case SEC_E_LOGON_DENIED:
			  case SEC_E_TARGET_UNKNOWN:
			  case SEC_E_NO_AUTHENTICATING_AUTHORITY:
			  case SEC_E_INTERNAL_ERROR:
			  case SEC_E_NO_CREDENTIALS:
			  case SEC_E_UNSUPPORTED_FUNCTION:
			  case SEC_E_APPLICATION_PROTOCOL_MISMATCH:
			*/
		default:
			failf(tls, "schannel: initial InitializeSecurityContext failed: %s",
				wintls_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
			return WINTLS_SSL_CONNECT_ERROR;
		}
	}

	DEBUGF(infof(tls, "schannel: sending initial handshake data: "
		"sending %lu bytes.", outbuf.cbBuffer));

	/* send initial handshake data which is now stored in output buffer */
	written = tls->do_send(tls,
		outbuf.pvBuffer, outbuf.cbBuffer,
		&result);
	s_pSecFn->FreeContextBuffer(outbuf.pvBuffer);
	if ((result != WINTLS_OK) || (outbuf.cbBuffer != (size_t)written)) {
		failf(tls, "schannel: failed to send initial handshake data: "
			"sent %zd of %lu bytes", written, outbuf.cbBuffer);
		return WINTLS_SSL_CONNECT_ERROR;
	}

	DEBUGF(infof(tls, "schannel: sent initial handshake data: "
		"sent %zd bytes", written));

	tls->recv_unrecoverable_err = WINTLS_OK;
	tls->recv_sspi_close_notify = FALSE;
	tls->recv_connection_closed = FALSE;
	tls->recv_renegotiating = FALSE;
	tls->encdata_is_incomplete = FALSE;

	/* continue to second handshake step */
	tls->connecting_state = ssl_connect_2;

	return WINTLS_OK;
}

wintls_code
schannel_connect_step2(struct wintls* tls)
{
	int i;
	ssize_t nread = -1, written = -1;
	unsigned char* reallocated_buffer;
	SecBuffer outbuf[3];
	SecBufferDesc outbuf_desc;
	SecBuffer inbuf[2];
	SecBufferDesc inbuf_desc;
	SECURITY_STATUS sspi_status = SEC_E_OK;
	wintls_code result;
	BOOL doread;
	const char* pubkey_ptr;

	DEBUGASSERT(tls);

	doread = (tls->connecting_state != ssl_connect_2_writing) ? TRUE : FALSE;

	DEBUGF(infof(tls,
		"schannel: SSL/TLS connection with %s port %d (step 2/3)",
		tls->hostname, tls->port));

	if (!tls->cred_setup || !tls->ctxt_setup)
		return WINTLS_SSL_CONNECT_ERROR;

	/* buffer to store previously received and decrypted data */
	if (!tls->decdata_buffer) {
		tls->decdata_offset = 0;
		tls->decdata_length = WINTLS_SCHANNEL_BUFFER_INIT_SIZE;
		tls->decdata_buffer = tls->do_malloc(tls->decdata_length);
		if (!tls->decdata_buffer) {
			failf(tls, "schannel: unable to allocate memory");
			return WINTLS_OUT_OF_MEMORY;
		}
	}

	/* buffer to store previously received and encrypted data */
	if (!tls->encdata_buffer) {
		tls->encdata_is_incomplete = FALSE;
		tls->encdata_offset = 0;
		tls->encdata_length = WINTLS_SCHANNEL_BUFFER_INIT_SIZE;
		tls->encdata_buffer = tls->do_malloc(tls->encdata_length);
		if (!tls->encdata_buffer) {
			failf(tls, "schannel: unable to allocate memory");
			return WINTLS_OUT_OF_MEMORY;
		}
	}

	/* if we need a bigger buffer to read a full message, increase buffer now */
	if (tls->encdata_length - tls->encdata_offset <
		WINTLS_SCHANNEL_BUFFER_FREE_SIZE) {
		/* increase internal encrypted data buffer */
		size_t reallocated_length = tls->encdata_offset +
			WINTLS_SCHANNEL_BUFFER_FREE_SIZE;
		reallocated_buffer = tls->do_realloc(tls->encdata_buffer,
			tls->encdata_length, reallocated_length);

		if (!reallocated_buffer) {
			failf(tls, "schannel: unable to re-allocate memory");
			return WINTLS_OUT_OF_MEMORY;
		}
		else {
			tls->encdata_buffer = reallocated_buffer;
			tls->encdata_length = reallocated_length;
		}
	}

	for (;;) {
		if (doread) {
			/* read encrypted handshake data from socket */
			nread = tls->do_recv(tls,
				(char*)(tls->encdata_buffer +
					tls->encdata_offset),
				tls->encdata_length -
				tls->encdata_offset,
				&result);
			if (result == WINTLS_AGAIN) {
				if (tls->connecting_state != ssl_connect_2_writing)
					tls->connecting_state = ssl_connect_2_reading;
				DEBUGF(infof(tls, "schannel: failed to receive handshake, "
					"need more data"));
				return WINTLS_OK;
			}
			else if ((result != WINTLS_OK) || (nread == 0)) {
				failf(tls, "schannel: failed to receive handshake, "
					"SSL/TLS connection failed");
				return WINTLS_SSL_CONNECT_ERROR;
			}

			/* increase encrypted data buffer offset */
			tls->encdata_offset += nread;
			tls->encdata_is_incomplete = FALSE;
			DEBUGF(infof(tls, "schannel: encrypted data got %zd", nread));
		}

		DEBUGF(infof(tls,
			"schannel: encrypted data buffer: offset %zu length %zu",
			tls->encdata_offset, tls->encdata_length));

		/* setup input buffers */
		InitSecBuffer(&inbuf[0], SECBUFFER_TOKEN, tls->do_malloc(tls->encdata_offset),
			wintlsx_uztoul(tls->encdata_offset));
		InitSecBuffer(&inbuf[1], SECBUFFER_EMPTY, NULL, 0);
		InitSecBufferDesc(&inbuf_desc, inbuf, 2);

		/* setup output buffers */
		InitSecBuffer(&outbuf[0], SECBUFFER_TOKEN, NULL, 0);
		InitSecBuffer(&outbuf[1], SECBUFFER_ALERT, NULL, 0);
		InitSecBuffer(&outbuf[2], SECBUFFER_EMPTY, NULL, 0);
		InitSecBufferDesc(&outbuf_desc, outbuf, 3);

		if (!inbuf[0].pvBuffer) {
			failf(tls, "schannel: unable to allocate memory");
			return WINTLS_OUT_OF_MEMORY;
		}

		/* copy received handshake data into input buffer */
		tls->do_memcpy(inbuf[0].pvBuffer, tls->encdata_buffer,
			tls->encdata_offset);

		sspi_status = s_pSecFn->InitializeSecurityContextA(
			&tls->cred_handle, &tls->ctxt_handle,
			tls->sni_hostname, tls->req_flags,
			0, 0, &inbuf_desc, 0, NULL,
			&outbuf_desc, &tls->ret_flags, &tls->ctxt_time_stamp);

		/* free buffer for received handshake data */
		tls->do_free(inbuf[0].pvBuffer);

		/* check if the handshake was incomplete */
		if (sspi_status == SEC_E_INCOMPLETE_MESSAGE) {
			tls->encdata_is_incomplete = TRUE;
			tls->connecting_state = ssl_connect_2_reading;
			DEBUGF(infof(tls,
				"schannel: received incomplete message, need more data"));
			return WINTLS_OK;
		}

		/* If the server has requested a client certificate, attempt to continue
		   the handshake without one. This will allow connections to servers which
		   request a client certificate but do not require it. */
		if (sspi_status == SEC_I_INCOMPLETE_CREDENTIALS &&
			!(tls->req_flags & ISC_REQ_USE_SUPPLIED_CREDS)) {
			tls->req_flags |= ISC_REQ_USE_SUPPLIED_CREDS;
			tls->connecting_state = ssl_connect_2_writing;
			DEBUGF(infof(tls,
				"schannel: a client certificate has been requested"));
			return WINTLS_OK;
		}

		/* check if the handshake needs to be continued */
		if (sspi_status == SEC_I_CONTINUE_NEEDED || sspi_status == SEC_E_OK) {
			for (i = 0; i < 3; i++) {
				/* search for handshake tokens that need to be send */
				if (outbuf[i].BufferType == SECBUFFER_TOKEN && outbuf[i].cbBuffer > 0) {
					DEBUGF(infof(tls, "schannel: sending next handshake data: "
						"sending %lu bytes.", outbuf[i].cbBuffer));

					/* send handshake token to server */
					written = tls->do_send(tls,
						outbuf[i].pvBuffer, outbuf[i].cbBuffer,
						&result);
					if ((result != WINTLS_OK) ||
						(outbuf[i].cbBuffer != (size_t)written)) {
						failf(tls, "schannel: failed to send next handshake data: "
							"sent %zd of %lu bytes", written, outbuf[i].cbBuffer);
						return WINTLS_SSL_CONNECT_ERROR;
					}
				}

				/* free obsolete buffer */
				if (outbuf[i].pvBuffer) {
					s_pSecFn->FreeContextBuffer(outbuf[i].pvBuffer);
				}
			}
		}
		else {
			char buffer[STRERROR_LEN];
			switch (sspi_status) {
			case SEC_E_INSUFFICIENT_MEMORY:
				failf(tls, "schannel: next InitializeSecurityContext failed: %s",
					wintls_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
				return WINTLS_OUT_OF_MEMORY;
			case SEC_E_WRONG_PRINCIPAL:
				failf(tls, "schannel: SNI or certificate check failed: %s",
					wintls_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
				return WINTLS_PEER_FAILED_VERIFICATION;
			case SEC_E_UNTRUSTED_ROOT:
				failf(tls, "schannel: %s",
					wintls_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
				return WINTLS_PEER_FAILED_VERIFICATION;
				/*
				  case SEC_E_INVALID_HANDLE:
				  case SEC_E_INVALID_TOKEN:
				  case SEC_E_LOGON_DENIED:
				  case SEC_E_TARGET_UNKNOWN:
				  case SEC_E_NO_AUTHENTICATING_AUTHORITY:
				  case SEC_E_INTERNAL_ERROR:
				  case SEC_E_NO_CREDENTIALS:
				  case SEC_E_UNSUPPORTED_FUNCTION:
				  case SEC_E_APPLICATION_PROTOCOL_MISMATCH:
				*/
			default:
				failf(tls, "schannel: next InitializeSecurityContext failed: %s",
					wintls_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
				return WINTLS_SSL_CONNECT_ERROR;
			}
		}

		/* check if there was additional remaining encrypted data */
		if (inbuf[1].BufferType == SECBUFFER_EXTRA && inbuf[1].cbBuffer > 0) {
			DEBUGF(infof(tls, "schannel: encrypted data length: %lu",
				inbuf[1].cbBuffer));
			/*
			  There are two cases where we could be getting extra data here:
			  1) If we're renegotiating a connection and the handshake is already
			  complete (from the server perspective), it can encrypted app data
			  (not handshake data) in an extra buffer at this point.
			  2) (sspi_status == SEC_I_CONTINUE_NEEDED) We are negotiating a
			  connection and this extra data is part of the handshake.
			  We should process the data immediately; waiting for the socket to
			  be ready may fail since the server is done sending handshake data.
			*/
			/* check if the remaining data is less than the total amount
			   and therefore begins after the already processed data */
			if (tls->encdata_offset > inbuf[1].cbBuffer) {
				tls->do_memmove(tls->encdata_buffer,
					(tls->encdata_buffer + tls->encdata_offset) -
					inbuf[1].cbBuffer, inbuf[1].cbBuffer);
				tls->encdata_offset = inbuf[1].cbBuffer;
				if (sspi_status == SEC_I_CONTINUE_NEEDED) {
					doread = FALSE;
					continue;
				}
			}
		}
		else {
			tls->encdata_offset = 0;
		}
		break;
	}

	/* check if the handshake needs to be continued */
	if (sspi_status == SEC_I_CONTINUE_NEEDED) {
		tls->connecting_state = ssl_connect_2_reading;
		return WINTLS_OK;
	}

	/* check if the handshake is complete */
	if (sspi_status == SEC_E_OK) {
		tls->connecting_state = ssl_connect_3;
		DEBUGF(infof(tls, "schannel: SSL/TLS handshake complete"));
	}

	pubkey_ptr = tls->pinnedPubKey;
	if (pubkey_ptr) {
		result = pkp_pin_peer_pubkey(tls, pubkey_ptr);
		if (result) {
			failf(tls, "SSL: public key does not match pinned public key");
			return result;
		}
	}

#ifdef HAS_MANUAL_VERIFY_API
	if (tls->verifypeer && tls->use_manual_cred_validation) {
		return wintls_verify_certificate(tls);
	}
#endif

	return WINTLS_OK;
}

static BOOL
valid_cert_encoding(const CERT_CONTEXT* cert_context)
{
	return (cert_context != NULL) &&
		((cert_context->dwCertEncodingType & X509_ASN_ENCODING) != 0) &&
		(cert_context->pbCertEncoded != NULL) &&
		(cert_context->cbCertEncoded > 0);
}

typedef BOOL(*Read_crt_func)(const CERT_CONTEXT* ccert_context, void* arg);

static void
traverse_cert_store(const CERT_CONTEXT* context, Read_crt_func func,
	void* arg)
{
	const CERT_CONTEXT* current_context = NULL;
	BOOL should_continue = TRUE;
	while (should_continue &&
		(current_context = CertEnumCertificatesInStore(
			context->hCertStore,
			current_context)) != NULL)
		should_continue = func(current_context, arg);

	if (current_context)
		CertFreeCertificateContext(current_context);
}

static BOOL
cert_counter_callback(const CERT_CONTEXT* ccert_context, void* certs_count)
{
	if (valid_cert_encoding(ccert_context))
		(*(int*)certs_count)++;
	return TRUE;
}

struct Adder_args
{
	struct wintls_easy* data;
	wintls_code result;
	int idx;
	int certs_count;
};

static BOOL
add_cert_to_certinfo(const CERT_CONTEXT* ccert_context, void* raw_arg)
{
	struct Adder_args* args = (struct Adder_args*)raw_arg;
	args->result = WINTLS_OK;
	if (valid_cert_encoding(ccert_context)) {
		const char* beg = (const char*)ccert_context->pbCertEncoded;
		const char* end = beg + ccert_context->cbCertEncoded;
		int insert_index = (args->certs_count - 1) - args->idx;
		args->result = wintls_extract_certinfo(args->data, insert_index,
			beg, end);
		args->idx++;
	}
	return args->result == WINTLS_OK;
}




/*
 * Delete the given session ID from the cache.
void wintls_ssl_delsessionid(struct wintls* data, void* ssl_sessionid)
{
	size_t i;

	for (i = 0; i < data->share->max_ssl_sessions; i++) {
		struct wintls_ssl_session* check = &data->share->session[i];

		if (check->sessionid == ssl_sessionid) {
			wintls_ssl_kill_session(check);
			break;
		}
	}
}
 */

/*
wintls_code wintls_ssl_addsessionid(struct wintls* data,
	void* ssl_sessionid,
	size_t idsize,
	BOOL* added)
{
	size_t i;
	struct wintls_ssl_session* store;
	long oldest_age;
	char* clone_host;
	char* clone_conn_to_host;
	int conn_to_port;
	long* general_age;

	if (added)
		*added = FALSE;

	if (!data->share->session)
		return WINTLS_OK;

	store = &data->share->session[0];
	oldest_age = data->share->session[0].age;

	clone_host = strdup(data->hostname);
	if (!clone_host)
		return WINTLS_OUT_OF_MEMORY; 

	if (data->conn_to_host) {
		clone_conn_to_host = strdup(data->conn_to_host);
		if (!clone_conn_to_host) {
			free(clone_host);
			return WINTLS_OUT_OF_MEMORY; 
		}
	}
	else
		clone_conn_to_host = NULL;

	if (data->conn_to_port)
		conn_to_port = data->conn_to_port;
	else
		conn_to_port = -1;

	general_age = &data->share->sessionage;
	for (i = 1; (i < data->share->max_ssl_sessions) &&
		data->share->session[i].sessionid; i++) {
		if (data->share->session[i].age < oldest_age) {
			oldest_age = data->share->session[i].age;
			store = &data->share->session[i];
		}
	}
	if (i == data->share->max_ssl_sessions)
		printf("Debug!\n") && exit(0);
	else
		store = &data->share->session[i];

	store->sessionid = ssl_sessionid;
	store->idsize = idsize;
	store->age = *general_age;   
	free(store->name);
	free(store->conn_to_host);
	store->name = clone_host;              
	store->conn_to_host = clone_conn_to_host; 
	store->conn_to_port = conn_to_port;
	store->remote_port = data->port;
	store->scheme = data->scheme;

	if (!wintls_clone_primary_ssl_config(conn_config, &store->ssl_config)) {
		wintls_free_primary_ssl_config(&store->ssl_config);
		store->sessionid = NULL; 
		free(clone_host);
		free(clone_conn_to_host);
		return WINTLS_OUT_OF_MEMORY;
	}

	if (added)
		*added = TRUE;

	DEBUGF(infof(data, DMSG(data, "Added Session ID to cache for %s://%s:%d"
		" [%s]"), store->scheme, store->name, store->remote_port,
		wintls_ssl_cf_is_proxy(cf) ? "PROXY" : "server"));
	return WINTLS_OK;
}*/



void wintls_ssl_free_certinfo(struct wintls* data)
{
	struct wintls_certinfo* ci = &data->certs;

	if (ci->num_of_certs) {
		/* free all individual lists used */
		int i;
		for (i = 0; i < ci->num_of_certs; i++) {
			wintls_slist_free_all(ci->certinfo[i]);
			ci->certinfo[i] = NULL;
		}

		free(ci->certinfo); /* free the actual array too */
		ci->certinfo = NULL;
		ci->num_of_certs = 0;
	}
}


wintls_code wintls_ssl_init_certinfo(struct wintls* data, int num)
{
	struct wintls_certinfo* ci = &data->certs;
	struct wintls_slist** table;

	/* Free any previous certificate information structures */
	wintls_ssl_free_certinfo(data);

	/* Allocate the required certificate information structures */
	table = calloc((size_t)num, sizeof(struct wintls_slist*));
	if (!table)
		return WINTLS_OUT_OF_MEMORY;

	ci->num_of_certs = num;
	ci->certinfo = table;

	return WINTLS_OK;
}

static wintls_code
schannel_connect_step3(struct wintls* tls)
{
	wintls_code result = WINTLS_OK;
	SECURITY_STATUS sspi_status = SEC_E_OK;
	CERT_CONTEXT* ccert_context = NULL;
#ifdef HAS_ALPN
	SecPkgContext_ApplicationProtocol alpn_result;
#endif

	DEBUGASSERT(ssl_connect_3 == tls->connecting_state);
	DEBUGASSERT(tls);

	DEBUGF(infof(tls,
		"schannel: SSL/TLS connection with %s port %d (step 3/3)",
		tls->hostname, tls->port));

	if (!tls->cred_setup)
		return WINTLS_SSL_CONNECT_ERROR;

	/* check if the required context attributes are met */
	if (tls->ret_flags != tls->req_flags) {
		if (!(tls->ret_flags & ISC_RET_SEQUENCE_DETECT))
			failf(tls, "schannel: failed to setup sequence detection");
		if (!(tls->ret_flags & ISC_RET_REPLAY_DETECT))
			failf(tls, "schannel: failed to setup replay detection");
		if (!(tls->ret_flags & ISC_RET_CONFIDENTIALITY))
			failf(tls, "schannel: failed to setup confidentiality");
		if (!(tls->ret_flags & ISC_RET_ALLOCATED_MEMORY))
			failf(tls, "schannel: failed to setup memory allocation");
		if (!(tls->ret_flags & ISC_RET_STREAM))
			failf(tls, "schannel: failed to setup stream orientation");
		return WINTLS_SSL_CONNECT_ERROR;
	}

#ifdef HAS_ALPN
	if (tls->use_alpn) {
		sspi_status =
			s_pSecFn->QueryContextAttributes(&tls->ctxt_handle,
				SECPKG_ATTR_APPLICATION_PROTOCOL,
				&alpn_result);

		if (sspi_status != SEC_E_OK) {
			failf(tls, "schannel: failed to retrieve ALPN result");
			return WINTLS_SSL_CONNECT_ERROR;
		}

		if (alpn_result.ProtoNegoStatus ==
			SecApplicationProtocolNegotiationStatus_Success) {
			unsigned char prev_alpn = tls->alpn;

			wintls_alpn_set_negotiated(tls, alpn_result.ProtocolId,
				alpn_result.ProtocolIdSize);
			if (tls->recv_renegotiating) {
				if (prev_alpn != tls->alpn &&
					prev_alpn != WINTLS_HTTP_VERSION_NONE) {
					/* Renegotiation selected a different protocol now, we cannot
					 * deal with this */
					failf(tls, "schannel: server selected an ALPN protocol too late");
					return WINTLS_SSL_CONNECT_ERROR;
				}
			}
		}
		else {
			if (!tls->recv_renegotiating)
				wintls_alpn_set_negotiated(tls, NULL, 0);
		}
	}
#endif

	/* save the current session data for possible re-use
	if (tls->sessionid) {
		BOOL incache;
		BOOL added = FALSE;
		struct wintls_schannel_cred* old_cred = NULL;

		wintls_ssl_sessionid_lock(tls);
		incache = !(wintls_ssl_getsessionid(tls, (void**)&old_cred, NULL));
		if (incache) {
			if (old_cred != tls->cred) {
				DEBUGF(infof(tls,
					"schannel: old credential handle is stale, removing"));
				wintls_ssl_delsessionid(tls, (void*)old_cred);
				incache = FALSE;
			}
		}
		if (!incache) {
			result = wintls_ssl_addsessionid(tls,
				sizeof(struct wintls_schannel_cred),
				&added);
			if (result) {
				wintls_ssl_sessionid_unlock(tls);
				failf(tls, "schannel: failed to store credential handle");
				return result;
			}
			else if (added) {
				tls->cred->refcount++;
				DEBUGF(infof(tls,
					"schannel: stored credential handle in session cache"));
			}
		}
		wintls_ssl_sessionid_unlock(tls);
	} */

	if (tls->certinfo) {
		int certs_count = 0;
		sspi_status =
			s_pSecFn->QueryContextAttributes(&tls->ctxt_handle,
				SECPKG_ATTR_REMOTE_CERT_CONTEXT,
				&ccert_context);

		if ((sspi_status != SEC_E_OK) || !ccert_context) {
			failf(tls, "schannel: failed to retrieve remote cert context");
			return WINTLS_PEER_FAILED_VERIFICATION;
		}

		traverse_cert_store(ccert_context, cert_counter_callback, &certs_count);

		result = wintls_ssl_init_certinfo(tls, certs_count);
		if (!result) {
			struct Adder_args args;
			args.data = tls;
			args.idx = 0;
			args.certs_count = certs_count;
			traverse_cert_store(ccert_context, add_cert_to_certinfo, &args);
			result = args.result;
		}
		CertFreeCertificateContext(ccert_context);
		if (result)
			return result;
	}

	tls->connecting_state = ssl_connect_done;

	return WINTLS_OK;
}

static wintls_code
schannel_connect_common(struct wintls* tls,
	BOOL nonblocking, BOOL* done)
{
	wintls_code result;
	//struct ssl_connect_data* connssl = cf->ctx;
	//wintls_socket_t sockfd = wintls_conn_cf_get_socket(cf, data);
	timediff_t timeout_ms;
	int what;

	/* check if the connection has already been established */
	if (ssl_connection_complete == tls->state) {
		*done = TRUE;
		return WINTLS_OK;
	}

	if (ssl_connect_1 == tls->connecting_state) {
		/* check out how much more time we're allowed */
		timeout_ms = wintls_timeleft(tls, NULL, TRUE);

		if (timeout_ms < 0) {
			/* no need to continue if time already is up */
			failf(tls, "SSL/TLS connection timeout");
			return WINTLS_OPERATION_TIMEDOUT;
		}

		result = schannel_connect_step1(tls);
		if (result)
			return result;
	}

	int ret;

	WSAPOLLFD rd = { 0 };
	WSAPOLLFD wr = { 0 };

	//Call WSAPoll for writeability on connecting socket
	rd.fd = tls->socket;
	rd.events = POLLWRNORM;
	wr.fd = tls->socket;
	wr.events = POLLRDNORM;
	WSAPOLLFD fds[2];
	fds[0] = rd;
	fds[1] = wr;
	while (ssl_connect_2 == tls->connecting_state ||
		ssl_connect_2_reading == tls->connecting_state ||
		ssl_connect_2_writing == tls->connecting_state) {

		/* check out how much more time we're allowed */
		timeout_ms = wintls_timeleft(tls, NULL, TRUE);

		if (timeout_ms < 0) {
			/* no need to continue if time already is up */
			failf(tls, "SSL/TLS connection timeout");
			return WINTLS_OPERATION_TIMEDOUT;
		}

		/* if ssl is expecting something, check if it's available. */
		if (tls->connecting_state == ssl_connect_2_reading
			|| tls->connecting_state == ssl_connect_2_writing) {

			if (SOCKET_ERROR == (ret = WSAPoll(&fds,
				2,
				30000
			)))
			{
				printf("DEBUGERROR\n");
				return WINTLS_OPERATION_TIMEDOUT;
			}
			/*if (what < 0) {
				failf(tls, "select/poll on SSL/TLS socket, errno: %d", WSAGetLastError());
				return WINTLS_SSL_CONNECT_ERROR;
			}
			else if (0 == what) {
				if (nonblocking) {
					*done = FALSE;
					return WINTLS_OK;
				}
				else {
					failf(tls, "SSL/TLS connection timeout");
					return WINTLS_OPERATION_TIMEDOUT;
				}
			}*/
			/* socket is readable or writable */
		}

		/* Run transaction, and return to the caller if it failed or if
		 * this connection is part of a multi handle and this loop would
		 * execute again. This permits the owner of a multi handle to
		 * abort a connection attempt before step2 has completed while
		 * ensuring that a client using select() or epoll() will always
		 * have a valid fdset to wait on.
		 */
		result = schannel_connect_step2(tls);
		if (result || (nonblocking &&
			(ssl_connect_2 == tls->connecting_state ||
				ssl_connect_2_reading == tls->connecting_state ||
				ssl_connect_2_writing == tls->connecting_state)))
			return result;

	} /* repeat step2 until all transactions are done. */

	if (ssl_connect_3 == tls->connecting_state) {
		result = schannel_connect_step3(tls);
		if (result)
			return result;
	}

	if (ssl_connect_done == tls->connecting_state) {
		tls->state = ssl_connection_complete;

#ifdef SECPKG_ATTR_ENDPOINT_BINDINGS
		/* When SSPI is used in combination with Schannel
		 * we need the Schannel context to create the Schannel
		 * binding to pass the IIS extended protection checks.
		 * Available on Windows 7 or later.
		 */
		{
			//struct ssl_backend_data* backend = connssl->backend;
			//DEBUGASSERT(backend);
			//tls->sslContext = &tls->ctxt->ctxt_handle;
		}
#endif

		* done = TRUE;
	}
	else
		*done = FALSE;

	/* reset our connection state machine */
	tls->connecting_state = ssl_connect_1;

	return WINTLS_OK;
}

ssize_t
schannel_send(struct wintls* tls,
	const void* buf, size_t len, wintls_code* err)
{
	ssize_t written = -1;
	size_t data_len = 0;
	unsigned char* ptr = NULL;
	SecBuffer outbuf[4];
	SecBufferDesc outbuf_desc;
	SECURITY_STATUS sspi_status = SEC_E_OK;
	wintls_code result;

	DEBUGASSERT(tls);

	/* check if the maximum stream sizes were queried */
	if (tls->stream_sizes.cbMaximumMessage == 0) {
		sspi_status = s_pSecFn->QueryContextAttributes(
			&tls->ctxt_handle,
			SECPKG_ATTR_STREAM_SIZES,
			&tls->stream_sizes);
		if (sspi_status != SEC_E_OK) {
			*err = WINTLS_SEND_ERROR;
			return -1;
		}
	}

	/* check if the buffer is longer than the maximum message length */
	if (len > tls->stream_sizes.cbMaximumMessage) {
		len = tls->stream_sizes.cbMaximumMessage;
	}

	/* calculate the complete message length and allocate a buffer for it */
	data_len = tls->stream_sizes.cbHeader + len +
		tls->stream_sizes.cbTrailer;
	ptr = (unsigned char*)tls->do_malloc(data_len);
	if (!ptr) {
		*err = WINTLS_OUT_OF_MEMORY;
		return -1;
	}

	/* setup output buffers (header, data, trailer, empty) */
	InitSecBuffer(&outbuf[0], SECBUFFER_STREAM_HEADER,
		ptr, tls->stream_sizes.cbHeader);
	InitSecBuffer(&outbuf[1], SECBUFFER_DATA,
		ptr + tls->stream_sizes.cbHeader, wintlsx_uztoul(len));
	InitSecBuffer(&outbuf[2], SECBUFFER_STREAM_TRAILER,
		ptr + tls->stream_sizes.cbHeader + len,
		tls->stream_sizes.cbTrailer);
	InitSecBuffer(&outbuf[3], SECBUFFER_EMPTY, NULL, 0);
	InitSecBufferDesc(&outbuf_desc, outbuf, 4);

	/* copy data into output buffer */
	tls->do_memcpy(outbuf[1].pvBuffer, buf, len);

	/* https://msdn.microsoft.com/en-us/library/windows/desktop/aa375390.aspx */
	sspi_status = s_pSecFn->EncryptMessage(&tls->ctxt_handle, 0,
		&outbuf_desc, 0);

	/* check if the message was encrypted */
	if (sspi_status == SEC_E_OK) {
		written = 0;

		/* send the encrypted message including header, data and trailer */
		len = outbuf[0].cbBuffer + outbuf[1].cbBuffer + outbuf[2].cbBuffer;

		/*
		  It's important to send the full message which includes the header,
		  encrypted payload, and trailer.  Until the client receives all the
		  data a coherent message has not been delivered and the client
		  can't read any of it.

		  If we wanted to buffer the unwritten encrypted bytes, we would
		  tell the client that all data it has requested to be sent has been
		  sent. The unwritten encrypted bytes would be the first bytes to
		  send on the next invocation.
		  Here's the catch with this - if we tell the client that all the
		  bytes have been sent, will the client call this method again to
		  send the buffered data?  Looking at who calls this function, it
		  seems the answer is NO.
		*/
		WSAPOLLFD rd = { 0 };
		WSAPOLLFD wr = { 0 };

		//Call WSAPoll for writeability on connecting socket
		rd.fd = tls->socket;
		rd.events = POLLWRNORM;
		WSAPOLLFD fds[1];
		fds[0] = rd;

		/* send entire message or fail */
		while (len > (size_t)written) {
			ssize_t this_write = 0;
			/*int what;
			timediff_t timeout_ms = wintls_timeleft(tls, NULL, FALSE);
			if (timeout_ms < 0) {
				failf(tls, "schannel: timed out sending data "
					"(bytes sent: %zd)", written);
				*err = WINTLS_OPERATION_TIMEDOUT;
				written = -1;
				break;
			}
			else if (!timeout_ms)
				timeout_ms = LONG_MAX;*/
			//what = SOCKET_WRITABLE(tls->socket, timeout_ms);
			if (SOCKET_ERROR == WSAPoll(&fds,
				1,
				30000
			))
			{
				printf("DEBUGERROR\n");
				return WINTLS_OPERATION_TIMEDOUT;
			}
			/*if (what < 0) {
				failf(tls, "select/poll on SSL socket, errno: %d", WSAGetLastError());
				*err = WINTLS_SEND_ERROR;
				written = -1;
				break;
			}
			else if (0 == what) {
				failf(tls, "schannel: timed out sending data "
					"(bytes sent: %zd)", written);
				*err = WINTLS_OPERATION_TIMEDOUT;
				written = -1;
				break;
			}*/
			/* socket is writable */

			this_write = tls->do_send(tls, ptr + written, len - written, &result);
			if (result == WINTLS_AGAIN)
				continue;
			else if (result != WINTLS_OK) {
				*err = result;
				written = -1;
				break;
			}

			written += this_write;
		}
	}
	else if (sspi_status == SEC_E_INSUFFICIENT_MEMORY) {
		*err = WINTLS_OUT_OF_MEMORY;
	}
	else {
		*err = WINTLS_SEND_ERROR;
	}

	tls->do_free(ptr);

	if (len == (size_t)written)
		/* Encrypted message including header, data and trailer entirely sent.
		   The return value is the number of unencrypted bytes that were sent. */
		written = outbuf[1].cbBuffer;

	return written;
}

ssize_t
schannel_recv(struct wintls* tls,
	char* buf, size_t len, wintls_code* err)
{
	size_t size = 0;
	ssize_t nread = -1;
	unsigned char* reallocated_buffer;
	size_t reallocated_length;
	BOOL done = FALSE;
	SecBuffer inbuf[4];
	SecBufferDesc inbuf_desc;
	SECURITY_STATUS sspi_status = SEC_E_OK;
	/* we want the length of the encrypted buffer to be at least large enough
	   that it can hold all the bytes requested and some TLS record overhead. */
	size_t min_encdata_length = len + WINTLS_SCHANNEL_BUFFER_FREE_SIZE;

	DEBUGASSERT(tls);

	/****************************************************************************
	 * Don't return or set backend->recv_unrecoverable_err unless in the cleanup.
	 * The pattern for return error is set *err, optional infof, goto cleanup.
	 *
	 * Our priority is to always return as much decrypted data to the caller as
	 * possible, even if an error occurs. The state of the decrypted buffer must
	 * always be valid. Transfer of decrypted data to the caller's buffer is
	 * handled in the cleanup.
	 */

	DEBUGF(infof(tls, "schannel: client wants to read %zu bytes", len));
	*err = WINTLS_OK;

	if (len && len <= tls->decdata_offset) {
		infof(tls, "schannel: enough decrypted data is already available");
		goto cleanup;
	}
	else if (tls->recv_unrecoverable_err) {
		*err = tls->recv_unrecoverable_err;
		infof(tls, "schannel: an unrecoverable error occurred in a prior call");
		goto cleanup;
	}
	else if (tls->recv_sspi_close_notify) {
		/* once a server has indicated shutdown there is no more encrypted data */
		infof(tls, "schannel: server indicated shutdown in a prior call");
		goto cleanup;
	}

	/* It's debatable what to return when !len. Regardless we can't return
	   immediately because there may be data to decrypt (in the case we want to
	   decrypt all encrypted cached data) so handle !len later in cleanup.
	*/
	else if (len && !tls->recv_connection_closed) {
		/* increase enc buffer in order to fit the requested amount of data */
		size = tls->encdata_length - tls->encdata_offset;
		if (size < WINTLS_SCHANNEL_BUFFER_FREE_SIZE ||
			tls->encdata_length < min_encdata_length) {
			reallocated_length = tls->encdata_offset +
				WINTLS_SCHANNEL_BUFFER_FREE_SIZE;
			if (reallocated_length < min_encdata_length) {
				reallocated_length = min_encdata_length;
			}
			reallocated_buffer = tls->do_realloc(tls->encdata_buffer, tls->encdata_length, reallocated_length);
			if (!reallocated_buffer) {
				*err = WINTLS_OUT_OF_MEMORY;
				failf(tls, "schannel: unable to re-allocate memory");
				goto cleanup;
			}

			tls->encdata_buffer = reallocated_buffer;
			tls->encdata_length = reallocated_length;
			size = tls->encdata_length - tls->encdata_offset;
			DEBUGF(infof(tls, "schannel: encdata_buffer resized %zu",
				tls->encdata_length));
		}

		DEBUGF(infof(tls,
			"schannel: encrypted data buffer: offset %zu length %zu",
			tls->encdata_offset, tls->encdata_length));

		/* read encrypted data from socket */
		nread = tls->do_recv(tls,
			(char*)(tls->encdata_buffer +
				tls->encdata_offset),
			size, err);
		if (*err) {
			nread = -1;
			if (*err == WINTLS_AGAIN)
				DEBUGF(infof(tls,
					"schannel: recv returned WINTLS_AGAIN"));
			else if (*err == WINTLS_RECV_ERROR)
				infof(tls, "schannel: recv returned WINTLS_RECV_ERROR");
			else
				infof(tls, "schannel: recv returned error %d", *err);
		}
		else if (nread == 0) {
			tls->recv_connection_closed = TRUE;
			DEBUGF(infof(tls, "schannel: server closed the connection"));
		}
		else if (nread > 0) {
			tls->encdata_offset += (size_t)nread;
			tls->encdata_is_incomplete = FALSE;
			DEBUGF(infof(tls, "schannel: encrypted data got %zd", nread));
		}
	}

	DEBUGF(infof(tls,
		"schannel: encrypted data buffer: offset %zu length %zu",
		tls->encdata_offset, tls->encdata_length));

	/* decrypt loop */
	while (tls->encdata_offset > 0 && sspi_status == SEC_E_OK &&
		(!len || tls->decdata_offset < len ||
			tls->recv_connection_closed)) {
		/* prepare data buffer for DecryptMessage call */
		InitSecBuffer(&inbuf[0], SECBUFFER_DATA, tls->encdata_buffer,
			wintlsx_uztoul(tls->encdata_offset));

		/* we need 3 more empty input buffers for possible output */
		InitSecBuffer(&inbuf[1], SECBUFFER_EMPTY, NULL, 0);
		InitSecBuffer(&inbuf[2], SECBUFFER_EMPTY, NULL, 0);
		InitSecBuffer(&inbuf[3], SECBUFFER_EMPTY, NULL, 0);
		InitSecBufferDesc(&inbuf_desc, inbuf, 4);

		/* https://msdn.microsoft.com/en-us/library/windows/desktop/aa375348.aspx
		 */
		sspi_status = s_pSecFn->DecryptMessage(&tls->ctxt_handle,
			&inbuf_desc, 0, NULL);

		/* check if everything went fine (server may want to renegotiate
		   or shutdown the connection context) */
		if (sspi_status == SEC_E_OK || sspi_status == SEC_I_RENEGOTIATE ||
			sspi_status == SEC_I_CONTEXT_EXPIRED) {
			DEBUGF(infof(tls, "sspi %d", sspi_status));
			/* check for successfully decrypted data, even before actual
			   renegotiation or shutdown of the connection context */
			if (inbuf[1].BufferType == SECBUFFER_DATA) {
				DEBUGF(infof(tls, "schannel: decrypted data length: %lu",
					inbuf[1].cbBuffer));

				/* increase buffer in order to fit the received amount of data */
				size = inbuf[1].cbBuffer > WINTLS_SCHANNEL_BUFFER_FREE_SIZE ?
					inbuf[1].cbBuffer : WINTLS_SCHANNEL_BUFFER_FREE_SIZE;
				if (tls->decdata_length - tls->decdata_offset < size ||
					tls->decdata_length < len) {
					/* increase internal decrypted data buffer */
					reallocated_length = tls->decdata_offset + size;
					/* make sure that the requested amount of data fits */
					if (reallocated_length < len) {
						reallocated_length = len;
					}
					reallocated_buffer = tls->do_realloc(tls->decdata_buffer, tls->decdata_length,
						reallocated_length);
					if (!reallocated_buffer) {
						*err = WINTLS_OUT_OF_MEMORY;
						failf(tls, "schannel: unable to re-allocate memory");
						goto cleanup;
					}
					tls->decdata_buffer = reallocated_buffer;
					tls->decdata_length = reallocated_length;
				}

				/* copy decrypted data to internal buffer */
				size = inbuf[1].cbBuffer;
				if (size) {
					tls->do_memcpy(tls->decdata_buffer + tls->decdata_offset,
						inbuf[1].pvBuffer, size);
					tls->decdata_offset += size;
				}

				DEBUGF(infof(tls, "schannel: decrypted data added: %zu", size));
				DEBUGF(infof(tls,
					"schannel: decrypted cached: offset %zu length %zu",
					tls->decdata_offset, tls->decdata_length));
			}

			/* check for remaining encrypted data */
			if (inbuf[3].BufferType == SECBUFFER_EXTRA && inbuf[3].cbBuffer > 0) {
				DEBUGF(infof(tls, "schannel: encrypted data length: %lu",
					inbuf[3].cbBuffer));

				/* check if the remaining data is less than the total amount
				 * and therefore begins after the already processed data
				 */
				if (tls->encdata_offset > inbuf[3].cbBuffer) {
					/* move remaining encrypted data forward to the beginning of
					   buffer */
					tls->do_memmove(tls->encdata_buffer,
						(tls->encdata_buffer + tls->encdata_offset) -
						inbuf[3].cbBuffer, inbuf[3].cbBuffer);
					tls->encdata_offset = inbuf[3].cbBuffer;
				}

				DEBUGF(infof(tls,
					"schannel: encrypted cached: offset %zu length %zu",
					tls->encdata_offset, tls->encdata_length));
			}
			else {
				/* reset encrypted buffer offset, because there is no data remaining */
				tls->encdata_offset = 0;
			}

			/* check if server wants to renegotiate the connection context */
			if (sspi_status == SEC_I_RENEGOTIATE) {
				infof(tls, "schannel: remote party requests renegotiation");
				if (*err && *err != WINTLS_AGAIN) {
					infof(tls, "schannel: can't renegotiate, an error is pending");
					goto cleanup;
				}

				/* begin renegotiation */
				infof(tls, "schannel: renegotiating SSL/TLS connection");
				tls->state = ssl_connection_negotiating;
				tls->connecting_state = ssl_connect_2_writing;
				tls->recv_renegotiating = TRUE;
				*err = schannel_connect_common(tls, FALSE, &done);
				tls->recv_renegotiating = FALSE;
				if (*err) {
					infof(tls, "schannel: renegotiation failed");
					goto cleanup;
				}
				/* now retry receiving data */
				sspi_status = SEC_E_OK;
				infof(tls, "schannel: SSL/TLS connection renegotiated");
				continue;
			}
			/* check if the server closed the connection */
			else if (sspi_status == SEC_I_CONTEXT_EXPIRED) {
				/* In Windows 2000 SEC_I_CONTEXT_EXPIRED (close_notify) is not
				   returned so we have to work around that in cleanup. */
				tls->recv_sspi_close_notify = TRUE;
				if (!tls->recv_connection_closed) {
					tls->recv_connection_closed = TRUE;
					infof(tls, "schannel: server closed the connection");
				}
				goto cleanup;
			}
		}
		else if (sspi_status == SEC_E_INCOMPLETE_MESSAGE) {
			tls->encdata_is_incomplete = TRUE;
			if (!*err)
				*err = WINTLS_AGAIN;
			infof(tls, "schannel: failed to decrypt data, need more data");
			goto cleanup;
		}
		else {
#ifndef WINTLS_DISABLE_VERBOSE_STRINGS
			char buffer[STRERROR_LEN];
#endif
			* err = WINTLS_RECV_ERROR;
			infof(tls, "schannel: failed to read data from server: %s",
				wintls_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
			goto cleanup;
		}
	}

	DEBUGF(infof(tls,
		"schannel: encrypted data buffer: offset %zu length %zu",
		tls->encdata_offset, tls->encdata_length));

	DEBUGF(infof(tls,
		"schannel: decrypted data buffer: offset %zu length %zu",
		tls->decdata_offset, tls->decdata_length));

cleanup:
	/* Warning- there is no guarantee the encdata state is valid at this point */
	DEBUGF(infof(tls, "schannel: schannel_recv cleanup"));

	/* Error if the connection has closed without a close_notify.

	   The behavior here is a matter of debate. We don't want to be vulnerable
	   to a truncation attack however there's some browser precedent for
	   ignoring the close_notify for compatibility reasons.

	   Additionally, Windows 2000 (v5.0) is a special case since it seems it
	   doesn't return close_notify. In that case if the connection was closed we
	   assume it was graceful (close_notify) since there doesn't seem to be a
	   way to tell.
	*/
	if (len && !tls->decdata_offset && tls->recv_connection_closed &&
		!tls->recv_sspi_close_notify) {
		BOOL isWin2k = wintlsx_verify_windows_version(5, 0, 0, PLATFORM_WINNT,
			VERSION_EQUAL);

		if (isWin2k && sspi_status == SEC_E_OK)
			tls->recv_sspi_close_notify = TRUE;
		else {
			*err = WINTLS_RECV_ERROR;
			infof(tls, "schannel: server closed abruptly (missing close_notify)");
		}
	}

	/* Any error other than WINTLS_AGAIN is an unrecoverable error. */
	if (*err && *err != WINTLS_AGAIN)
		tls->recv_unrecoverable_err = *err;

	size = len < tls->decdata_offset ? len : tls->decdata_offset;
	if (size) {
		tls->do_memcpy(buf, tls->decdata_buffer, size);
		tls->do_memmove(tls->decdata_buffer, tls->decdata_buffer + size,
			tls->decdata_offset - size);
		tls->decdata_offset -= size;
		DEBUGF(infof(tls, "schannel: decrypted data returned %zu", size));
		DEBUGF(infof(tls,
			"schannel: decrypted data buffer: offset %zu length %zu",
			tls->decdata_offset, tls->decdata_length));
		*err = WINTLS_OK;
		return (ssize_t)size;
	}

	if (!*err && !tls->recv_connection_closed)
		*err = WINTLS_AGAIN;

	/* It's debatable what to return when !len. We could return whatever error
	   we got from decryption but instead we override here so the return is
	   consistent.
	*/
	if (!len)
		*err = WINTLS_OK;

	return *err ? -1 : 0;
}

wintls_code schannel_connect_nonblocking(struct wintls* data,
	BOOL* done)
{
	return schannel_connect_common(data, TRUE, done);
}

wintls_code schannel_connect(struct wintls* data)
{
	wintls_code result;
	BOOL done = FALSE;

	result = schannel_connect_common(data, FALSE, &done);
	if (result)
		return result;

	DEBUGASSERT(done);

	return WINTLS_OK;
}

static BOOL schannel_data_pending(struct wintls* tls)
{
	DEBUGASSERT(tls);

	if (tls->ctxt_setup) /* SSL/TLS is in use */
		return (tls->decdata_offset > 0 ||
			(tls->encdata_offset > 0 && !tls->encdata_is_incomplete));
	else
		return FALSE;
}
/*
static void schannel_session_free(void* ptr)
{
	struct wintls_schannel_cred* cred = ptr;

	if (cred) {
		s_pSecFn->FreeCredentialsHandle(&cred->cred_handle);
		wintlsx_unicodefree(cred->sni_hostname);
	}
}*/

/* shut down the SSL connection and clean up related memory.
   this function can be called multiple times on the same connection including
   if the SSL connection failed (eg connection made but failed handshake). */
static int schannel_shutdown(struct wintls* tls)
{
	/* See https://msdn.microsoft.com/en-us/library/windows/desktop/aa380138.aspx
	 * Shutting Down an Schannel Connection
	 */

	DEBUGASSERT(tls);

	if (tls->ctxt_setup) {
		infof(tls, "schannel: shutting down SSL/TLS connection with %s port %d",
			tls->hostname, tls->port);
	}

	if (tls->cred_setup && tls->ctxt_setup) {
		SecBufferDesc BuffDesc;
		SecBuffer Buffer;
		SECURITY_STATUS sspi_status;
		SecBuffer outbuf;
		SecBufferDesc outbuf_desc;
		wintls_code result;
		DWORD dwshut = SCHANNEL_SHUTDOWN;

		InitSecBuffer(&Buffer, SECBUFFER_TOKEN, &dwshut, sizeof(dwshut));
		InitSecBufferDesc(&BuffDesc, &Buffer, 1);

		sspi_status = s_pSecFn->ApplyControlToken(&tls->ctxt_handle,
			&BuffDesc);

		if (sspi_status != SEC_E_OK) {
			char buffer[STRERROR_LEN];
			failf(tls, "schannel: ApplyControlToken failure: %s",
				wintls_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
		}

		/* setup output buffer */
		InitSecBuffer(&outbuf, SECBUFFER_EMPTY, NULL, 0);
		InitSecBufferDesc(&outbuf_desc, &outbuf, 1);

		sspi_status = s_pSecFn->InitializeSecurityContext(
			&tls->cred_handle,
			&tls->ctxt_handle,
			tls->sni_hostname,
			tls->req_flags,
			0,
			0,
			NULL,
			0,
			&tls->ctxt_handle,
			&outbuf_desc,
			&tls->ret_flags,
			&tls->ctxt_time_stamp);

		if ((sspi_status == SEC_E_OK) || (sspi_status == SEC_I_CONTEXT_EXPIRED)) {
			/* send close message which is in output buffer */
			ssize_t written = tls->do_send(tls,
				outbuf.pvBuffer, outbuf.cbBuffer,
				&result);
			s_pSecFn->FreeContextBuffer(outbuf.pvBuffer);
			if ((result != WINTLS_OK) || (outbuf.cbBuffer != (size_t)written)) {
				infof(tls, "schannel: failed to send close msg: error %d"
					" (bytes written: %zd)", result, written);
			}
		}
	}

	/* free SSPI Schannel API security context handle */
	if (tls->ctxt_setup) {
		DEBUGF(infof(tls, "schannel: clear security context handle"));
		s_pSecFn->DeleteSecurityContext(&tls->ctxt_handle);
		//wintls_safefree(tls->ctxt);
	}

	//schannel_session_free(tls->cred);
	/* free SSPI Schannel API credential handle
	if (tls->cred) {
		wintls_ssl_sessionid_lock(tls);
		wintls_ssl_sessionid_unlock(tls);
		tls->cred = NULL;
	} */

	/* free internal buffer for received encrypted data */
	if (tls->encdata_buffer) {
		tls->do_free(tls->encdata_buffer);
		tls->encdata_length = 0;
		tls->encdata_offset = 0;
		tls->encdata_is_incomplete = FALSE;
	}

	/* free internal buffer for received decrypted data */
	if (tls->decdata_buffer) {
		tls->do_free(tls->decdata_buffer);
		tls->decdata_length = 0;
		tls->decdata_offset = 0;
	}

	return WINTLS_OK;
}

static void schannel_close(struct wintls* tls)
{
	schannel_shutdown(tls);
}

int schannel_init(void)
{
	return (wintls_sspi_global_init() == WINTLS_OK ? 1 : 0);
}

static void schannel_cleanup(void)
{
	wintls_sspi_global_cleanup();
}

static size_t schannel_version(char* buffer, size_t size)
{
	size = msnprintf(buffer, size, "Schannel");

	return size;
}


wintls_code wintls_win32_random(unsigned char* entropy, size_t length)
{
	memset(entropy, 0, length);

	if (BCryptGenRandom(NULL, entropy, (ULONG)length,
		BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
		return WINTLS_FAILED_INIT;

	return WINTLS_OK;
}


static wintls_code schannel_random(struct wintls_easy* data,
	unsigned char* entropy, size_t length)
{
	(void)data;

	return wintls_win32_random(entropy, length);
}

static void schannel_checksum(const unsigned char* input,
	size_t inputlen,
	unsigned char* checksum,
	size_t checksumlen,
	DWORD provType,
	const unsigned int algId)
{
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	DWORD cbHashSize = 0;
	DWORD dwHashSizeLen = (DWORD)sizeof(cbHashSize);
	DWORD dwChecksumLen = (DWORD)checksumlen;

	/* since this can fail in multiple ways, zero memory first so we never
	 * return old data
	 */
	memset(checksum, 0, checksumlen);

	if (!CryptAcquireContext(&hProv, NULL, NULL, provType,
		CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
		return; /* failed */

	do {
		if (!CryptCreateHash(hProv, algId, 0, 0, &hHash))
			break; /* failed */

		/* workaround for original MinGW, should be (const BYTE*) */
		if (!CryptHashData(hHash, (BYTE*)input, (DWORD)inputlen, 0))
			break; /* failed */

		/* get hash size */
		if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&cbHashSize,
			&dwHashSizeLen, 0))
			break; /* failed */

		/* check hash size */
		if (checksumlen < cbHashSize)
			break; /* failed */

		if (CryptGetHashParam(hHash, HP_HASHVAL, checksum, &dwChecksumLen, 0))
			break; /* failed */
	} while (0);

	if (hHash)
		CryptDestroyHash(hHash);

	if (hProv)
		CryptReleaseContext(hProv, 0);
}

static wintls_code schannel_sha256sum(const unsigned char* input,
	size_t inputlen,
	unsigned char* sha256sum,
	size_t sha256len)
{
	schannel_checksum(input, inputlen, sha256sum, sha256len,
		PROV_RSA_AES, CALG_SHA_256);
	return WINTLS_OK;
}
	


/* ======================================================================
 * source: WintlsSchannel.cpp (entry point)
 ====================================================================== */

// WintlsSchannel.cpp : Defines the entry point for the application.

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <wincrypt.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#pragma warning(push)
#pragma warning(disable:6385) // Invalid data: accessing [buffer-name], the readable size is size1 bytes but size2 bytes may be read
#pragma warning(disable:6101) // Returning uninitialized memory
#include <ws2tcpip.h>
#include <mstcpip.h>
#pragma warning(pop)


struct wintls tls;

#define WINTLS_MAX_INPUT_LENGTH 8000000

wintls_code wintls_setstropt(char** charp, const char* s)
{
	/* Release the previous storage at `charp' and replace by a dynamic storage
	   copy of `s'. Return WINTLS_OK or WINTLS_OUT_OF_MEMORY. */

	wintls_safefree(*charp);

	if (s) {
		if (strlen(s) > WINTLS_MAX_INPUT_LENGTH)
			return WINTLS_BAD_FUNCTION_ARGUMENT;

		*charp = strdup(s);
		if (!*charp)
			return WINTLS_OUT_OF_MEMORY;
	}

	return WINTLS_OK;
}


ssize_t our_send(struct wintls* tls,
	const void* buf,        /* data to write */
	size_t len,             /* amount to write */
	wintls_code* err)
{
	DWORD SendBytes;
	WSABUF DataBuf;
	DataBuf.len = len;
	DataBuf.buf = (CHAR*)buf;

	int rc = WSASend(tls->socket, &DataBuf, 1, &SendBytes, 0, NULL, NULL);
	if (SendBytes <= 0)
		*err = WINTLS_WRITE_ERROR;
	else
		*err = WINTLS_OK;
	return SendBytes;
}

ssize_t our_recv(struct wintls* tls,
	char* buf,              /* store data here */
	size_t len,             /* amount to read */
	wintls_code* err)
{
	int rc = recv(tls->socket, buf, len, 0);
	if (rc < 0)
		*err = WINTLS_READ_ERROR;
	else
		*err = WINTLS_OK;
	return rc;
}


HANDLE heap;
void* malloc_sch(int size)
{
	return HeapAlloc(heap, 0, size);
}

void* memcpy_sch(void* dest, const void* src, size_t count)
{
	return memcpy(dest, src, count);
}

void* memmove_sch(void* dest, const void* src, size_t count)
{
	return memmove(dest, src, count);
}

void free_sch(void* p)
{
	HeapFree(heap, 0, p);
}

void* realloc_sch(void* dest, size_t oldCount, size_t count)
{
	return HeapReAlloc(heap, 0, dest, count);
}

#pragma comment(lib, "Ws2_32.lib")
int main()
{
	heap = HeapCreate(0, 65536, 65536 * 10);

	WSADATA wsaData;
	int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err != 0)
	{
		printf("Startup error");
		WSACleanup();
		return 0;
	}

	int iresult = 0;
	struct sockaddr* serverAddr = NULL;
	SOCKET WSSock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

	ADDRINFOW* result = NULL;
	ADDRINFOW hints;
	ULONG serverAddrLen = 0;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	int rresult = GetAddrInfoW(
		L"tls13.akamai.io",
		L"443",
		&hints,
		&result
	);
	if (rresult != 0) {
		wprintf(L"GetAddrInfoW failed with error: %d\n", rresult);
		WSACleanup();
		return 1;
	}

	serverAddr = result->ai_addr;
	serverAddrLen = (ULONG)result->ai_addrlen;

	int sockErr = WSAConnect(
		WSSock,
		serverAddr,
		serverAddrLen,
		NULL,
		NULL,
		NULL,
		NULL
	);
	if (sockErr == SOCKET_ERROR)
	{
		iresult = WSAGetLastError();
		wprintf(L"WSAConnect returned error %d\n", iresult);
		WSACleanup();
		return 0;
	}

	wintls_win32_init(0);

	char hostnamea[16] = "tls13.akamai.io";
	char tls13[23] = "TLS_AES_256_GCM_SHA384";
	tls.verifyhost = TRUE;
	tls.verifypeer = TRUE;
	tls.verifystatus = FALSE;
	tls.cachesessionid = TRUE;
	tls.socket = WSSock;
	tls.do_recv = &our_recv;
	tls.do_send = &our_send;
	tls.do_malloc = &malloc_sch;
	tls.do_free = &free_sch;
	tls.do_memmove = &memmove_sch;
	tls.do_realloc = &realloc_sch;
	tls.do_memcpy = &memcpy_sch;
	tls.share = (struct wintls_share*)malloc_sch(sizeof(struct wintls_share));
	tls.timeout = 10000;
	tls.connecttimeout = 10000;
	tls.t_startop = wintls_now();
	tls.t_startsingle = wintls_now();
	tls.hostname = hostnamea;
	tls.port = 443;
	tls.buffer_size = 16384;
	tls.use_alpn = TRUE;
	tls.buffer = (char*)malloc_sch(tls.buffer_size);
	tls.version = WINTLS_SSLVERSION_TLSv1_2;
	tls.version_max = WINTLS_SSLVERSION_TLSv1_3;
	tls.cipher_list13 = tls13;

	wintls_code code = schannel_connect(&tls);

	const char* request = "GET / HTTP/1.1\r\nHost: tls13.akamai.io\r\n\r\n";
	schannel_send(&tls, request, strlen(request), &code);

	char* buffer = (char*)malloc_sch(4096);
	long long b = schannel_recv(&tls, buffer, 4096, &code);
	while (code == WINTLS_AGAIN)
	{
		Sleep(100);
		b = schannel_recv(&tls, buffer, 4096, &code);
		printf("%*.*s\n", (int)b, (int)b, buffer);
	}

	if (code == WINTLS_OK && b == 4096)
	{
		while (code == WINTLS_OK)
		{
			Sleep(100);
			b = schannel_recv(&tls, buffer, 4096, &code);
			printf("%*.*s\n", (int)b, (int)b, buffer);
		}
	}

	FreeAddrInfoW(result);
	WSACleanup();
	return 0;
}
