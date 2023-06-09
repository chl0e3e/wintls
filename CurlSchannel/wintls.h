#ifndef __WINTLS_H
#define __WINTLS_H

#ifdef __cplusplus
extern "C" {
#endif

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include "curlcode.h"
#include "msvc.h"
#undef SECURITY_WIN32
#undef SECURITY_KERNEL
#define SECURITY_WIN32 1
#include "timeleft.h"
#include <schannel.h>
#include <sspi.h>
#include <WinSock2.h>
#include "curl_opts.h"
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

/* Different data locks for a single share */
typedef enum {
	CURL_LOCK_DATA_NONE = 0,
	/*  CURL_LOCK_DATA_SHARE is used internally to say that
	 *  the locking is just made to change the internal state of the share
	 *  itself.
	 */
	 CURL_LOCK_DATA_SHARE,
	 CURL_LOCK_DATA_COOKIE,
	 CURL_LOCK_DATA_DNS,
	 CURL_LOCK_DATA_SSL_SESSION,
	 CURL_LOCK_DATA_CONNECT,
	 CURL_LOCK_DATA_PSL,
	 CURL_LOCK_DATA_HSTS,
	 CURL_LOCK_DATA_LAST
} curl_lock_data;

/* Different lock access types */
typedef enum {
	CURL_LOCK_ACCESS_NONE = 0,   /* unspecified action */
	CURL_LOCK_ACCESS_SHARED = 1, /* for read perhaps */
	CURL_LOCK_ACCESS_SINGLE = 2, /* for write perhaps */
	CURL_LOCK_ACCESS_LAST        /* never use */
} curl_lock_access;

BOOL blobcmp(struct curl_blob* first, struct curl_blob* second);

typedef void (*curl_lock_function)(struct wintls* handle,
	curl_lock_data data,
	curl_lock_access locktype,
	void* userptr);

typedef void (*curl_unlock_function)(struct wintls* handle,
	curl_lock_data data,
	void* userptr);


typedef void*(malloc_func)(int size);
typedef void (free_func)(void* p);
typedef void*(memmove_func)(void* dest, const void* src, size_t count);
typedef void* (realloc_func)(void* dest, size_t oldCount, size_t count);
typedef void* (memcpy_func)(void* dest, const void* src, size_t count);
struct curl_blob {
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


#define CURL_GOOD_SHARE 0x7e117a1e
#define GOOD_SHARE_HANDLE(x) ((x) && (x)->magic == CURL_GOOD_SHARE)

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
	//struct ssl_primary_config ssl_config; /* setup for this session */
};

/* info about the certificate chain, only for OpenSSL, GnuTLS, Schannel, NSS
   and GSKit builds. Asked for with CURLOPT_CERTINFO / CURLINFO_CERTINFO */
struct curl_certinfo {
	int num_of_certs;             /* number of certificates with information */
	struct curl_slist** certinfo; /* for each index in this array, there's a
									 linked list with textual information in the
									 format "name: value" */
};

typedef ssize_t Curl_cft_send(struct wintls* tls,
	const void* buf,        /* data to write */
	size_t len,             /* amount to write */
	CURLcode* err);         /* error to return */
typedef ssize_t Curl_cft_recv(struct wintls* tls,
	char* buf,              /* store data here */
	size_t len,             /* amount to read */
	CURLcode* err);         /* error to return */

struct wintls_share
{
	unsigned int magic; /* CURL_GOOD_SHARE */
	char uuid[32];
	unsigned int specifier;
	curl_lock_function lockfunc;
	curl_unlock_function unlockfunc;
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
	CURLcode recv_unrecoverable_err; /* schannel_recv had an unrecoverable err */
	BOOL recv_sspi_close_notify; /* true if connection closed by close_notify */
	BOOL recv_connection_closed; /* true if connection closed, regardless how */
	BOOL recv_renegotiating;     /* true if recv is doing renegotiation */
	BOOL use_alpn; /* true if ALPN is used for this connection */
	BOOL use_manual_cred_validation; /* true if manual cred validation is used */

	//struct ssl_primary_config primary;
	long certverifyresult; /* result from the certificate verification */
	//curl_ssl_ctx_callback fsslctx; /* function to initialize ssl ctx */
	///void* fsslctxp;        /* parameter for call back */
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

	ssl_connection_state state;
	ssl_connect_state connecting_state;
	char* hostname;                   /* hostname for verification */
	char* dispname;                   /* display version of hostname */
	const struct alpn_spec* alpn;     /* ALPN to use or NULL for none */
	//struct ssl_backend_data* backend; /* vtls backend specific props */
	//struct cf_call_data call_data;    /* data handle used in current call */
	struct curltime handshake_done;   /* time when handshake finished */
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

	Curl_cft_send* do_send;                 /* send data */
	Curl_cft_recv* do_recv;                 /* receive data */
	malloc_func* do_malloc;
	free_func* do_free;
	memmove_func* do_memmove;
	realloc_func* do_realloc;
	memcpy_func* do_memcpy;

	char* pinnedPubKey;
	unsigned int timeout;        /* ms, 0 means no timeout */
	unsigned int connecttimeout; /* ms, 0 means no timeout */
	struct curltime t_startsingle;
	struct curltime t_startop;

	struct curl_certinfo certs; /* info about the certs, only populated in
								   OpenSSL, GnuTLS, Schannel, NSS and GSKit
								   builds. Asked for with CURLOPT_CERTINFO
								   / CURLINFO_CERTINFO */

	char* str[STRING_LAST]; /* array of strings, pointing to allocated memory */
	struct curl_blob* blobs[BLOB_LAST];
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