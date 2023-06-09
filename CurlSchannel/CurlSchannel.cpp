// CurlSchannel.cpp : Defines the entry point for the application.
//

#include "CurlSchannel.h"

using namespace std;
#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <Windows.h>
#include <wincrypt.h>

#pragma warning(pop)
#include <winsock2.h>
#include <ws2ipdef.h>
#pragma warning(push)
#pragma warning(disable:6385) // Invalid data: accessing [buffer-name], the readable size is size1 bytes but size2 bytes may be read
#pragma warning(disable:6101) // Returning uninitialized memory
#include <ws2tcpip.h>
#include <mstcpip.h>
#pragma warning(pop)
#include "wintls.h"
#include "system_win32.h"
#include "schannel_curl.h"
#include "curlcode.h"
#include "timeleft.h"

struct wintls tls;

#define CURL_MAX_INPUT_LENGTH 8000000

CURLcode Curl_setstropt(char** charp, const char* s)
{
	/* Release the previous storage at `charp' and replace by a dynamic storage
	   copy of `s'. Return CURLE_OK or CURLE_OUT_OF_MEMORY. */

	Curl_safefree(*charp);

	if (s) {
		if (strlen(s) > CURL_MAX_INPUT_LENGTH)
			return CURLE_BAD_FUNCTION_ARGUMENT;

		*charp = strdup(s);
		if (!*charp)
			return CURLE_OUT_OF_MEMORY;
	}

	return CURLE_OK;
}


ssize_t our_send(struct wintls* tls,
	const void* buf,        /* data to write */
	size_t len,             /* amount to write */
	CURLcode* err)
{

	DWORD SendBytes;
	WSABUF DataBuf;
	DataBuf.len = len;
	DataBuf.buf = (CHAR*)buf;

	int rc = WSASend(tls->socket, &DataBuf, 1, &SendBytes, 0, NULL, NULL);
	//int result = send(tls->socket, (char*) buf, len, 0);
	printf("send %d\n", rc);
	printf("sendbytes: %d\n", SendBytes);
	if (SendBytes <= 0)
	{
		*err = CURLE_WRITE_ERROR;
	}
	else
	{
		*err = CURLE_OK;
	}
	return SendBytes;
}
ssize_t our_recv(struct wintls* tls,
	char* buf,              /* store data here */
	size_t len,             /* amount to read */
	CURLcode* err)
{

	//DWORD RecvBytes;
	///WSABUF DataBuf;
	//DataBuf.len = len;
	//DataBuf.buf = (CHAR*)buf;
	int rc = recv(tls->socket, buf, len, 0);
	int ll = WSAGetLastError();
	// int   rc = WSARecv(tls->socket, &DataBuf, 1, &RecvBytes, 0, NULL, NULL);
	printf("Recv %d\n", rc);
	printf("WSA: %d\n", ll);
	if (rc < 0)
	{
		*err = CURLE_READ_ERROR;
	}
	else
	{
		*err = CURLE_OK;
	}
	return rc;
}


HANDLE heap;
void* malloc_sch(int size)
{
	return HeapAlloc(heap, 0, size);
}

void* memcpy_sch(void* dest, const void* src, std::size_t count)
{
	return std::memcpy(dest, src, count);
}

void* memmove_sch(void* dest, const void* src, std::size_t count)
{
	return std::memmove(dest, src, count);
}


void free_sch(void* p)
{
//	std::free(p);
	HeapFree(heap, 0, p);
	//operator delete(p);
}
void* realloc_sch(void* dest, size_t oldCount, size_t count)
{
	return HeapReAlloc(heap, 0, dest, count);
	//return std::realloc(dest, count);
	//void* new_alloced = malloc_sch(count);
	//std::memcpy(new_alloced, dest, oldCount);
	//free_sch(dest);
	//return new_alloced;
}

#include "curl_opts.h"
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
	//int ReturnValue = WSAConnect(WSSock, (SOCKADDR*)&C_Channel, sizeof(C_Channel), &CallerData, &CalleeData, NULL, NULL);


	ADDRINFOW* result = NULL;
	ADDRINFOW* ptr = NULL;

	ULONG serverAddrLen = 0;
	ADDRINFOW hints;

	//    struct sockaddr_in6 *sockaddr_ipv6;
	LPSOCKADDR sockaddr_ip;

	//-----------------------------------------
	// Get the server IP address from the DNS name.
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

	printf("RResult %d\n", rresult);


	wprintf(L"GetAddrInfoW returned success\n");

	//    struct sockaddr_in6 *sockaddr_ipv6;

	wchar_t ipstringbuffer[46];
	DWORD ipbufferlength = 46;
	int i = 0;
	int iRetval = 0;
	// Retrieve each address and print out the hex bytes
	for (ptr = result; ptr != NULL;ptr = ptr->ai_next) {

		wprintf(L"GetAddrInfoW response %d\n", i++);
		wprintf(L"\tFlags: 0x%x\n", ptr->ai_flags);
		wprintf(L"\tFamily: ");
		switch (ptr->ai_family) {
		case AF_UNSPEC:
			wprintf(L"Unspecified\n");
			break;
		case AF_INET:
			wprintf(L"AF_INET (IPv4)\n");
			sockaddr_ip = (LPSOCKADDR)ptr->ai_addr;
			// The buffer length is changed by each call to WSAAddresstoString
			// So we need to set it for each iteration through the loop for safety
			ipbufferlength = 46;
			iRetval = WSAAddressToStringW(sockaddr_ip, (DWORD)ptr->ai_addrlen, NULL,
				ipstringbuffer, &ipbufferlength);
			if (iRetval)
				wprintf(L"WSAAddressToString failed with %u\n", WSAGetLastError());
			else
				wprintf(L"\tIPv4 address %ws\n", ipstringbuffer);
			break;
		case AF_INET6:
			wprintf(L"AF_INET6 (IPv6)\n");
			// the InetNtop function is available on Windows Vista and later
			// sockaddr_ipv6 = (struct sockaddr_in6 *) ptr->ai_addr;
			// printf("\tIPv6 address %s\n",
			//    InetNtop(AF_INET6, &sockaddr_ipv6->sin6_addr, ipstringbuffer, 46) );

			// We use WSAAddressToString since it is supported on Windows XP and later
			sockaddr_ip = (LPSOCKADDR)ptr->ai_addr;
			// The buffer length is changed by each call to WSAAddresstoString
			// So we need to set it for each iteration through the loop for safety
			ipbufferlength = 46;
			iRetval = WSAAddressToStringW(sockaddr_ip, (DWORD)ptr->ai_addrlen, NULL,
				ipstringbuffer, &ipbufferlength);
			if (iRetval)
				wprintf(L"WSAAddressToString failed with %u\n", WSAGetLastError());
			else
				wprintf(L"\tIPv6 address %s\n", ipstringbuffer);
			break;
		default:
			wprintf(L"Other %ld\n", ptr->ai_family);
			break;
		}
		wprintf(L"\tSocket type: ");
		switch (ptr->ai_socktype) {
		case 0:
			wprintf(L"Unspecified\n");
			break;
		case SOCK_STREAM:
			wprintf(L"SOCK_STREAM (stream)\n");
			break;
		case SOCK_DGRAM:
			wprintf(L"SOCK_DGRAM (datagram) \n");
			break;
		case SOCK_RAW:
			wprintf(L"SOCK_RAW (raw) \n");
			break;
		case SOCK_RDM:
			wprintf(L"SOCK_RDM (reliable message datagram)\n");
			break;
		case SOCK_SEQPACKET:
			wprintf(L"SOCK_SEQPACKET (pseudo-stream packet)\n");
			break;
		default:
			wprintf(L"Other %ld\n", ptr->ai_socktype);
			break;
		}
		wprintf(L"\tProtocol: ");
		switch (ptr->ai_protocol) {
		case 0:
			wprintf(L"Unspecified\n");
			break;
		case IPPROTO_TCP:
			wprintf(L"IPPROTO_TCP (TCP)\n");
			break;
		case IPPROTO_UDP:
			wprintf(L"IPPROTO_UDP (UDP) \n");
			break;
		default:
			wprintf(L"Other %ld\n", ptr->ai_protocol);
			break;
		}
		wprintf(L"\tLength of this sockaddr: %d\n", ptr->ai_addrlen);
		wprintf(L"\tCanonical name: %s\n", ptr->ai_canonname);
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
		wprintf(L"WSAConnect returned error %ld\n", result);
		WSACleanup();
		return 0;
	}

	printf("here\n");

	Curl_win32_init(0);
	/**/



//	struct wintls
//	{
//		char* CApath;          /* certificate dir (doesn't work on windows) */
//		char* CAfile;          /* certificate to verify peer against */
//		char* issuercert;      /* optional issuer certificate filename */
//		char* clientcert;
//		char* cipher_list;     /* list of ciphers to use */
//		char* cipher_list13;   /* list of TLS 1.3 cipher suites to use */
//		char* pinned_key;
//		char* CRLfile;         /* CRL to check certificate revocation */
//		struct curl_blob* cert_blob;
//		struct curl_blob* ca_info_blob;
//		struct curl_blob* issuercert_blob;
//#ifdef USE_TLS_SRP
//		char* username; /* TLS username (for, e.g., SRP) */
//		char* password; /* TLS password (for, e.g., SRP) */
//#endif
//		char* curves;          /* list of curves to use */
//		unsigned char ssl_options;  /* the CURLOPT_SSL_OPTIONS bitmask */
//		unsigned int version_max; /* max supported version the client wants to use */
//		unsigned char version;    /* what version the client wants to use */
//		BOOL verifypeer;       /* set TRUE if this is desired */
//		BOOL verifyhost;       /* set TRUE if CN/SAN must match hostname */
//		BOOL verifystatus;     /* set TRUE if certificate status must be checked */
//		BOOL cachesessionid;        /* cache session IDs or not */
//
//		struct Curl_schannel_cred* cred;
//		struct Curl_schannel_ctxt* ctxt;
//		SecPkgContext_StreamSizes stream_sizes;
//		size_t encdata_length, decdata_length;
//		size_t encdata_offset, decdata_offset;
//		unsigned char* encdata_buffer, * decdata_buffer;
//		/* encdata_is_incomplete: if encdata contains only a partial record that
//		   can't be decrypted without another recv() (that is, status is
//		   SEC_E_INCOMPLETE_MESSAGE) then set this true. after an recv() adds
//		   more bytes into encdata then set this back to false. */
//		BOOL encdata_is_incomplete;
//		unsigned long req_flags, ret_flags;
//		CURLcode recv_unrecoverable_err; /* schannel_recv had an unrecoverable err */
//		BOOL recv_sspi_close_notify; /* true if connection closed by close_notify */
//		BOOL recv_connection_closed; /* true if connection closed, regardless how */
//		BOOL recv_renegotiating;     /* true if recv is doing renegotiation */
//		BOOL use_alpn; /* true if ALPN is used for this connection */
//		BOOL use_manual_cred_validation; /* true if manual cred validation is used */
//
//		//struct ssl_primary_config primary;
//		long certverifyresult; /* result from the certificate verification */
//		//curl_ssl_ctx_callback fsslctx; /* function to initialize ssl ctx */
//		///void* fsslctxp;        /* parameter for call back */
//		char* cert_type; /* format for certificate (default: PEM)*/
//		char* key; /* private key file name */
//		struct curl_blob* key_blob;
//		char* key_type; /* format for private key (default: PEM) */
//		char* key_passwd; /* plain text private key password */
//		BOOL certinfo;     /* gather lots of certificate info */
//		BOOL falsestart;
//		BOOL enable_beast; /* allow this flaw for interoperability's sake */
//		BOOL no_revoke;    /* disable SSL certificate revocation checks */
//		BOOL no_partialchain; /* don't accept partial certificate chains */
//		BOOL revoke_best_effort; /* ignore SSL revocation offline/missing revocation
//									list errors */
//		BOOL native_ca_store; /* use the native ca store of operating system */
//		BOOL auto_client_cert;   /* automatically locate and use a client
//									certificate for authentication (Schannel) */
//
//		ssl_connection_state state;
//		ssl_connect_state connecting_state;
//		char* hostname;                   /* hostname for verification */
//		char* dispname;                   /* display version of hostname */
//		const struct alpn_spec* alpn;     /* ALPN to use or NULL for none */
//		//struct ssl_backend_data* backend; /* vtls backend specific props */
//		struct cf_call_data call_data;    /* data handle used in current call */
//		struct curltime handshake_done;   /* time when handshake finished */
//		int port;                         /* remote port at origin */
//		struct wintls_share* share;
//
//		char* name;       /* host name for which this ID was used */
//		char* conn_to_host; /* host name for the connection (may be NULL) */
//		const char* scheme; /* protocol scheme used */
//		void* sessionid;  /* as returned from the SSL layer */
//		size_t idsize;    /* if known, otherwise 0 */
//		long age;         /* just a number, the higher the more recent */
//		int remote_port;  /* remote port */
//		int conn_to_port; /* remote port for the connection (may be -1) */
//		char* buffer;
//		size_t buffer_size;
//
//		Curl_cft_send* do_send;                 /* send data */
//		Curl_cft_recv* do_recv;                 /* receive data */
//
//		char* pinnedPubKey;
//		unsigned int timeout;        /* ms, 0 means no timeout */
//		unsigned int connecttimeout; /* ms, 0 means no timeout */
//		struct curltime t_startsingle;
//		struct curltime t_startop;
//
//		struct curl_certinfo certs; /* info about the certs, only populated in
//									   OpenSSL, GnuTLS, Schannel, NSS and GSKit
//									   builds. Asked for with CURLOPT_CERTINFO
//									   / CURLINFO_CERTINFO */
//
//		char* str[STRING_LAST]; /* array of strings, pointing to allocated memory */
//		struct curl_blob* blobs[BLOB_LAST];
//		SOCKET socket;

	char hostnamea[16] = "tls13.akamai.io";
	char tls13[23] = "TLS_AES_256_GCM_SHA384";
	//iresult = Curl_setstropt(&tls.str[STRING_SSL_CIPHER13_LIST], "TLS_AES_256_GCM_SHA384");
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
	tls.share = (wintls_share*)malloc_sch(sizeof(wintls_share));
	tls.timeout = 10000;
	tls.connecttimeout = 10000;
	tls.t_startop = Curl_now();
	tls.t_startsingle = Curl_now();
	tls.hostname = hostnamea;
	tls.port = 443;
	tls.buffer_size = 16384;
	tls.use_alpn = TRUE;
	tls.buffer = (char*)malloc_sch(tls.buffer_size);
	tls.version = CURL_SSLVERSION_TLSv1_2;
	tls.version_max = CURL_SSLVERSION_TLSv1_3;
	tls.cipher_list13 = tls13;
	//tls.version = CURL_SSLVERSION_TLSv1_3;

//	iresult = schannel_init();
	printf("res %d\n", iresult);
	CURLcode code = schannel_connect(&tls);
	printf(" aaa %d\n", code);
	printf("after!\n");
	/*
`TLS_AES_256_GCM_SHA384`
`TLS_CHACHA20_POLY1305_SHA256`
`TLS_AES_128_GCM_SHA256`
`TLS_AES_128_CCM_8_SHA256`
`TLS_AES_128_CCM_SHA256`*/
	const char* test = "GET / HTTP/1.1\r\nHost: tls13.akamai.io\r\n\r\n";
	printf(test);
	long long a = schannel_send(&tls, test, strlen(test), &code);
	printf(" bbb %d\n", code);
	printf(" bbba %lli\n", a);
	char* buffer = (char*)malloc_sch(4096);
	long long b = schannel_recv(&tls, buffer, 4096, &code);
	printf(" 1cca %d\n", code);
	printf(" 1cca %lli\n", b);
	while (code == CURLE_AGAIN)
	{
		Sleep(100);
		b = schannel_recv(&tls, buffer, 4096, &code);
		printf(" ccca %d\n", code);
		printf(" ccca %lli\n", b);
		printf("%*.*s\n", b, b, buffer);
	}

	if (code == CURLE_OK && b == 4096)
	{
		while (code == CURLE_OK)
		{
			Sleep(100);
			b = schannel_recv(&tls, buffer, 4096, &code);
			printf(" ccca %d\n", code);
			printf(" ccca %lli\n", b);
			printf("%*.*s\n", b, b, buffer);
		}
	}
	/*if (code != CURLE_AGAIN)
	{
		for (long long i = 0; i < b; i++)
		{
			printf("" + buffer[i]);
		}
	}*/

cleanup:
	//FreeAddrInfoW(aiList);
	WSACleanup();
	return 0;
}
