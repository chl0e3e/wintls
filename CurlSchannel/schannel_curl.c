/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) Marc Hoersken, <info@marc-hoersken.de>
 * Copyright (C) Mark Salisbury, <mark.salisbury@hp.com>
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

 /*
  * Source file for all Schannel-specific code for the TLS/SSL layer. No code
  * but vtls.c should ever call or use these functions.
  */

  //#include "curl_setup.h"

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <stdio.h>
#define EXPOSE_SCHANNEL_INTERNAL_STRUCTS

/*
#include "vtls.h"
#include "vtls_int.h"
#include "strcase.h"
#include "sendf.h"
#include "connect.h" // for the connect timeout
#include "select.h" // for the socket readiness
#include "inet_pton.h" // for IP addr SNI check
#include "curl_multibyte.h"
#include "warnless.h"
#include "x509asn1.h"
#include "curl_printf.h"
#include "multiif.h"
#include "version_win32.h"
#include "rand.h"

#include "curl_memory.h"
#include "memdebug.h"*/

#include "schannel_curl.h"
#include "curlcode.h"
//#include "connection_data.h"
#include "version_win32.h"
#include "strerror.h"
#include "timeleft.h"
#include "schannel_verify.h"
#include "alpn.h"
#include "select.h"
#include "x509asn1.h"
#include "debug.h"
#include "strcase.h"
#include "curl_sspi.h"
#include "curl_multibyte.h"
#include "base64.h"

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
#define CURL_CERT_STORE_PROV_SYSTEM CERT_STORE_PROV_SYSTEM_W
#else
#define CURL_CERT_STORE_PROV_SYSTEM CERT_STORE_PROV_SYSTEM_A
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
#define CURL_SCHANNEL_BUFFER_INIT_SIZE   4096
#define CURL_SCHANNEL_BUFFER_FREE_SIZE   1024

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

#include "wintls.h"
#include "x509asn1.h"

static CURLcode pubkey_pem_to_der(const char* pem,
	unsigned char** der, size_t* der_len)
{
	char* stripped_pem, * begin_pos, * end_pos;
	size_t pem_count, stripped_pem_count = 0, pem_len;
	CURLcode result;

	/* if no pem, exit. */
	if (!pem)
		return CURLE_BAD_CONTENT_ENCODING;

	begin_pos = strstr(pem, "-----BEGIN PUBLIC KEY-----");
	if (!begin_pos)
		return CURLE_BAD_CONTENT_ENCODING;

	pem_count = begin_pos - pem;
	/* Invalid if not at beginning AND not directly following \n */
	if (0 != pem_count && '\n' != pem[pem_count - 1])
		return CURLE_BAD_CONTENT_ENCODING;

	/* 26 is length of "-----BEGIN PUBLIC KEY-----" */
	pem_count += 26;

	/* Invalid if not directly following \n */
	end_pos = strstr(pem + pem_count, "\n-----END PUBLIC KEY-----");
	if (!end_pos)
		return CURLE_BAD_CONTENT_ENCODING;

	pem_len = end_pos - pem;

	stripped_pem = malloc(pem_len - pem_count + 1);
	if (!stripped_pem)
		return CURLE_OUT_OF_MEMORY;

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

	result = Curl_base64_decode(stripped_pem, der, der_len);

	Curl_safefree(stripped_pem);

	return result;
}

CURLcode Curl_pin_peer_pubkey(struct wintls* data,
	const char* pinnedpubkey,
	const unsigned char* pubkey, size_t pubkeylen)
{
	FILE* fp;
	unsigned char* buf = NULL, * pem_ptr = NULL;
	CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;

	/* if a path wasn't specified, don't pin */
	if (!pinnedpubkey)
		return CURLE_OK;
	if (!pubkey || !pubkeylen)
		return result;

	/* only do this if pinnedpubkey starts with "sha256//", length 8 */
	if (strncmp(pinnedpubkey, "sha256//", 8) == 0) {
		CURLcode encode;
		size_t encodedlen, pinkeylen;
		char* encoded, * pinkeycopy, * begin_pos, * end_pos;
		unsigned char* sha256sumdigest;

		/* compute sha256sum of public key */
		sha256sumdigest = malloc(CURL_SHA256_DIGEST_LENGTH);
		if (!sha256sumdigest)
			return CURLE_OUT_OF_MEMORY;
		encode = schannel_sha256sum(pubkey, pubkeylen,
			sha256sumdigest, CURL_SHA256_DIGEST_LENGTH);

		if (encode != CURLE_OK)
			return encode;

		encode = Curl_base64_encode((char*)sha256sumdigest,
			CURL_SHA256_DIGEST_LENGTH, &encoded,
			&encodedlen);
		Curl_safefree(sha256sumdigest);

		if (encode)
			return encode;

		infof(data, " public key hash: sha256//%s", encoded);

		/* it starts with sha256//, copy so we can modify it */
		pinkeylen = strlen(pinnedpubkey) + 1;
		pinkeycopy = malloc(pinkeylen);
		if (!pinkeycopy) {
			Curl_safefree(encoded);
			return CURLE_OUT_OF_MEMORY;
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
				result = CURLE_OK;
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
		Curl_safefree(encoded);
		Curl_safefree(pinkeycopy);
		return result;
	}

	fp = fopen(pinnedpubkey, "rb");
	if (!fp)
		return result;

	do {
		long filesize;
		size_t size, pem_len;
		CURLcode pem_read;

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
		size = (size_t)(filesize & CURL_MASK_USIZE_T);
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
				result = CURLE_OK;
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
			result = CURLE_OK;
	} while (0);

	Curl_safefree(buf);
	Curl_safefree(pem_ptr);
	fclose(fp);

	return result;
}

static CURLcode pkp_pin_peer_pubkey(struct wintls* tls,
	const char* pinnedpubkey)
{
	CERT_CONTEXT* pCertContextServer = NULL;

	/* Result is returned to caller */
	CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;

	DEBUGASSERT(tls);

	/* if a path wasn't specified, don't pin */
	if (!pinnedpubkey)
		return CURLE_OK;

	do {
		SECURITY_STATUS sspi_status;
		const char* x509_der;
		DWORD x509_der_len;
		struct Curl_X509certificate x509_parsed;
		struct Curl_asn1Element* pubkey;

		sspi_status =
			s_pSecFn->QueryContextAttributes(&tls->ctxt_handle,
				SECPKG_ATTR_REMOTE_CERT_CONTEXT,
				&pCertContextServer);

		if ((sspi_status != SEC_E_OK) || !pCertContextServer) {
			char buffer[STRERROR_LEN];
			failf(tls, "schannel: Failed to read remote certificate context: %s",
				Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
			break; /* failed */
		}


		if (!(((pCertContextServer->dwCertEncodingType & X509_ASN_ENCODING) != 0) &&
			(pCertContextServer->cbCertEncoded > 0)))
			break;

		x509_der = (const char*)pCertContextServer->pbCertEncoded;
		x509_der_len = pCertContextServer->cbCertEncoded;
		memset(&x509_parsed, 0, sizeof(x509_parsed));
		if (Curl_parseX509(&x509_parsed, x509_der, x509_der + x509_der_len))
			break;

		pubkey = &x509_parsed.subjectPublicKeyInfo;
		if (!pubkey->header || pubkey->end <= pubkey->header) {
			failf(tls, "SSL: failed retrieving public key from server certificate");
			break;
		}

		result = Curl_pin_peer_pubkey(tls,
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

static CURLcode
set_ssl_version_min_max(DWORD* enabled_protocols,
	struct wintls* tls)
{
	/*long ssl_version = tls->version;
	long ssl_version_max = tls->version_max;
	long i = ssl_version;

	switch (ssl_version_max) {
	case CURL_SSLVERSION_MAX_NONE:
	case CURL_SSLVERSION_MAX_DEFAULT:

		if (curlx_verify_windows_version(10, 0, 20348, PLATFORM_WINNT,
			VERSION_GREATER_THAN_EQUAL)) {
			ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_3;
		}
		else 
			ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_2;

		break;
	}

	for (; i <= (ssl_version_max >> 16); ++i) {
		switch (i) {
		//case CURL_SSLVERSION_TLSv1_0:
		//	(*enabled_protocols) |= SP_PROT_TLS1_0_CLIENT;
		//	break;
		//case CURL_SSLVERSION_TLSv1_1:
		//	(*enabled_protocols) |= SP_PROT_TLS1_1_CLIENT;
		//	break;
		//case CURL_SSLVERSION_TLSv1_2:
		//	(*enabled_protocols) |= SP_PROT_TLS1_2_CLIENT;
		//	break;
		case CURL_SSLVERSION_TLSv1_3:

			if (curlx_verify_windows_version(10, 0, 20348, PLATFORM_WINNT,
				VERSION_GREATER_THAN_EQUAL)) {
				(*enabled_protocols) |= SP_PROT_TLS1_3_CLIENT;
				break;
			}
			else { 
				failf(tls, "schannel: TLS 1.3 not supported on Windows prior to 11");
				return CURLE_SSL_CONNECT_ERROR;
			}
		}
	}*/

	(*enabled_protocols) |= SP_PROT_TLS1_3_CLIENT;

	return CURLE_OK;
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
                                  (1<<CURL_LOCK_DATA_SSL_SESSION)))

typedef enum {
	CURLSHE_OK,  /* all is fine */
	CURLSHE_BAD_OPTION, /* 1 */
	CURLSHE_IN_USE,     /* 2 */
	CURLSHE_INVALID,    /* 3 */
	CURLSHE_NOMEM,      /* 4 out of memory */
	CURLSHE_NOT_BUILT_IN, /* 5 feature not present in lib */
	CURLSHE_LAST        /* never use */
} CURLSHcode;

CURLSHcode
Curl_share_lock(struct wintls* tls, curl_lock_data type,
	curl_lock_access accesstype)
{
	struct wintls_share* share = tls->share;

	if (!share)
		return CURLSHE_INVALID;

	if (share->specifier & (1 << type)) {
		if (share->lockfunc) /* only call this if set! */
			share->lockfunc(tls, type, accesstype, share->clientdata);
	}
	/* else if we don't share this, pretend successful lock */

	return CURLSHE_OK;
}

CURLSHcode
Curl_share_unlock(struct wintls* tls, curl_lock_data type)
{
	struct wintls_share* share = tls->share;

	if (!share)
		return CURLSHE_INVALID;

	if (share->specifier & (1 << type)) {
		if (share->unlockfunc) /* only call this if set! */
			share->unlockfunc(tls, type, share->clientdata);
	}

	return CURLSHE_OK;
}



/*
 * Lock shared SSL session data
void Curl_ssl_sessionid_lock(struct wintls* tls)
{
	if (SSLSESSION_SHARED(tls))
		Curl_share_lock(tls, CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_ACCESS_SINGLE);
}

/*
 * Unlock shared SSL session data
void Curl_ssl_sessionid_unlock(struct wintls* tls)
{
	if (SSLSESSION_SHARED(tls))
		Curl_share_unlock(tls, CURL_LOCK_DATA_SSL_SESSION);
}
 */

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

static CURLcode
set_ssl_ciphers(SCHANNEL_CRED* schannel_cred, char* ciphers,
	ALG_ID* algIds)
{
	char* startCur = ciphers;
	int algCount = 0;
	while (startCur && (0 != *startCur) && (algCount < NUM_CIPHERS)) {
		long alg = strtol(startCur, 0, 0);
		if (!alg)
			alg = get_alg_id_by_name(startCur);
		printf(alg);
		printf("\n");
		if (alg)
			algIds[algCount++] = alg;
		else if (!strncmp(startCur, "USE_STRONG_CRYPTO",
			sizeof("USE_STRONG_CRYPTO") - 1) ||
			!strncmp(startCur, "SCH_USE_STRONG_CRYPTO",
				sizeof("SCH_USE_STRONG_CRYPTO") - 1))
			schannel_cred->dwFlags |= SCH_USE_STRONG_CRYPTO;
		else
			return CURLE_SSL_CIPHER;
		startCur = strchr(startCur, ':');
		if (startCur)
			startCur++;
	}
	schannel_cred->palgSupportedAlgs = algIds;
	schannel_cred->cSupportedAlgs = algCount;
	return CURLE_OK;
}

#ifdef HAS_CLIENT_CERT_PATH

/* Function allocates memory for store_path only if CURLE_OK is returned */
static CURLcode
get_cert_location(TCHAR* path, DWORD* store_name, TCHAR** store_path,
	TCHAR** thumbprint)
{
	TCHAR* sep;
	TCHAR* store_path_start;
	size_t store_name_len;

	sep = _tcschr(path, TEXT('\\'));
	if (!sep)
		return CURLE_SSL_CERTPROBLEM;

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
		return CURLE_SSL_CERTPROBLEM;

	store_path_start = sep + 1;

	sep = _tcschr(store_path_start, TEXT('\\'));
	if (!sep)
		return CURLE_SSL_CERTPROBLEM;

	*thumbprint = sep + 1;
	if (_tcslen(*thumbprint) != CERT_THUMBPRINT_STR_LEN)
		return CURLE_SSL_CERTPROBLEM;

	*sep = TEXT('\0');
	*store_path = strdup(store_path_start);//_tcsdup(store_path_start);
	*sep = TEXT('\\');
	if (!*store_path)
		return CURLE_OUT_OF_MEMORY;

	return CURLE_OK;
}
#endif
CURLcode
schannel_acquire_credential_handle(struct wintls* tls)
{
#ifdef HAS_CLIENT_CERT_PATH
	PCCERT_CONTEXT client_certs[1] = { NULL };
	HCERTSTORE client_cert_store = NULL;
#endif
	SECURITY_STATUS sspi_status = SEC_E_OK;
	CURLcode result;

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
	case CURL_SSLVERSION_DEFAULT:
	case CURL_SSLVERSION_TLSv1:
	case CURL_SSLVERSION_TLSv1_0:
	case CURL_SSLVERSION_TLSv1_1:
	case CURL_SSLVERSION_TLSv1_2:
	case CURL_SSLVERSION_TLSv1_3:
	{
		result = set_ssl_version_min_max(&enabled_protocols, tls);
		if (result != CURLE_OK)
			return result;
		break;
	}
	case CURL_SSLVERSION_SSLv3:
	case CURL_SSLVERSION_SSLv2:
		failf(tls, "SSL versions not supported");
		return CURLE_NOT_BUILT_IN;
	default:
		failf(tls, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
		return CURLE_SSL_CONNECT_ERROR;
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
			cert_path = curlx_convert_UTF8_to_tchar(tls->clientcert);
			if (!cert_path)
				return CURLE_OUT_OF_MEMORY;

			result = get_cert_location(cert_path, &cert_store_name,
				&cert_store_path, &cert_thumbprint_str);

			if (result && (tls->clientcert[0] != '\0'))
				fInCert = fopen(tls->clientcert, "rb");

			if (result && !fInCert) {
				failf(tls, "schannel: Failed to get certificate location"
					" or file for %s",
					tls->clientcert);
				curlx_unicodefree(cert_path);
				return result;
			}
		}

		if ((fInCert || blob) && (tls->cert_type) &&
			(!strcasecompare(tls->cert_type, "P12"))) {
			failf(tls, "schannel: certificate format compatibility error "
				" for %s",
				blob ? "(memory blob)" : tls->clientcert);
			curlx_unicodefree(cert_path);
			return CURLE_SSL_CERTPROBLEM;
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
			curlx_unicodefree(cert_path);
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
					return CURLE_SSL_CERTPROBLEM;
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

				if (curlx_verify_windows_version(6, 0, 0, PLATFORM_WINNT,
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
				return CURLE_SSL_CERTPROBLEM;
			}

			client_certs[0] = CertFindCertificateInStore(
				cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
				CERT_FIND_ANY, NULL, NULL);

			if (!client_certs[0]) {
				failf(tls, "schannel: Failed to get certificate from file %s"
					", last error is 0x%x",
					cert_showfilename_error, GetLastError());
				CertCloseStore(cert_store, 0);
				return CURLE_SSL_CERTPROBLEM;
			}
		}
		else {
			cert_store =
				CertOpenStore(CURL_CERT_STORE_PROV_SYSTEM, 0,
					(HCRYPTPROV)NULL,
					CERT_STORE_OPEN_EXISTING_FLAG | cert_store_name,
					cert_store_path);
			if (!cert_store) {
				failf(tls, "schannel: Failed to open cert store %x %s, "
					"last error is 0x%x",
					cert_store_name, cert_store_path, GetLastError());
				free(cert_store_path);
				curlx_unicodefree(cert_path);
				return CURLE_SSL_CERTPROBLEM;
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
				curlx_unicodefree(cert_path);
				CertCloseStore(cert_store, 0);
				return CURLE_SSL_CERTPROBLEM;
			}

			client_certs[0] = CertFindCertificateInStore(
				cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
				CERT_FIND_HASH, &cert_thumbprint, NULL);

			curlx_unicodefree(cert_path);

			if (!client_certs[0]) {
				/* CRYPT_E_NOT_FOUND / E_INVALIDARG */
				CertCloseStore(cert_store, 0);
				return CURLE_SSL_CERTPROBLEM;
			}
		}
		client_cert_store = cert_store;
	}
#else
	if (data->set.ssl.primary.clientcert || data->set.ssl.primary.cert_blob) {
		failf(data, "schannel: client cert support not built in");
		return CURLE_NOT_BUILT_IN;
	}
#endif

	/* allocate memory for the re-usable credential handle */

	/*
	struct Curl_schannel_cred* p = (struct Curl_schannel_cred*)malloc(sizeof(struct Curl_schannel_cred));
	tls->cred = p;
	if (!tls->cred) {
		failf(tls, "schannel: unable to allocate memory");

#ifdef HAS_CLIENT_CERT_PATH
		if (client_certs[0])
			CertFreeCertificateContext(client_certs[0]);
		if (client_cert_store)
			CertCloseStore(client_cert_store, 0);
#endif

		return CURLE_OUT_OF_MEMORY;
	}*/
	//tls->refcount = 1;

#ifdef HAS_CLIENT_CERT_PATH
	/* Since we did not persist the key, we need to extend the store's
	 * lifetime until the end of the connection
	 */
//	tls->cred->client_cert_store = client_cert_store;
#endif

	/* Windows 10, 1809 (a.k.a. Windows 10 build 17763) */
	if (curlx_verify_windows_version(10, 0, 17763, PLATFORM_WINNT,
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
					return CURLE_SSL_CIPHER;
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
					return CURLE_SSL_CIPHER;
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
			return CURLE_SSL_CIPHER;
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
			if (CURLE_OK != result) {
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
			Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
		//Curl_safefree(tls->cred);
		switch (sspi_status) {
		case SEC_E_INSUFFICIENT_MEMORY:
			return CURLE_OUT_OF_MEMORY;
		case SEC_E_NO_CREDENTIALS:
		case SEC_E_SECPKG_NOT_FOUND:
		case SEC_E_NOT_OWNER:
		case SEC_E_UNKNOWN_CREDENTIALS:
		case SEC_E_INTERNAL_ERROR:
		default:
			return CURLE_SSL_CONNECT_ERROR;
		}
	}

	return CURLE_OK;
}

BOOL
Curl_ssl_config_matches(struct wintls* data,
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
		Curl_safecmp(data->CApath, needle->CApath) &&
		Curl_safecmp(data->CAfile, needle->CAfile) &&
		Curl_safecmp(data->issuercert, needle->issuercert) &&
		Curl_safecmp(data->clientcert, needle->clientcert) &&
#ifdef USE_TLS_SRP
		!Curl_timestrcmp(data->username, needle->username) &&
		!Curl_timestrcmp(data->password, needle->password) &&
#endif
		strcasecompare(data->cipher_list, needle->cipher_list) &&
		strcasecompare(data->cipher_list13, needle->cipher_list13) &&
		strcasecompare(data->curves, needle->curves) &&
		strcasecompare(data->CRLfile, needle->CRLfile) &&
		strcasecompare(data->pinned_key, needle->pinned_key))
		return TRUE;

	return FALSE;
}


/**
BOOL Curl_ssl_getsessionid(struct wintls* tls,
	void** ssl_sessionid,
	size_t* idsize) 
{
	struct wintls* check;
	size_t i;
	long* general_age;
	BOOL no_match = TRUE;

	*ssl_sessionid = NULL;

	DEBUGASSERT(tls->cachesessionid);

	if (!tls->cachesessionid || !tls->share->session)
		return TRUE;

	general_age = &tls->share->sessionage;

	for (i = 0; i < tls->share->max_ssl_sessions; i++) {
		check = &tls->share->session[i];
		if (!check->sessionid)
			continue;
		if (strcasecompare(tls->hostname, check->name) &&
			((!tls->conn_to_host && !check->conn_to_host) ||
				(tls->conn_to_host && check->conn_to_host &&
					strcasecompare(tls->name, check->conn_to_host))) &&
			((!tls->conn_to_port && check->conn_to_port == -1) ||
				(tls->conn_to_port && check->conn_to_port != -1 &&
					tls->conn_to_port == check->conn_to_port)) &&
			(tls->port == check->remote_port) &&
			strcasecompare(tls->scheme, check->scheme) &&
			Curl_ssl_config_matches(tls, check)) {
			(*general_age)++;         
			check->age = *general_age;
			*ssl_sessionid = check->sessionid;
			if (idsize)
				*idsize = check->idsize;
			no_match = FALSE;
			break;
		}
	}

	DEBUGF(infof(tls, DMSG(tls, "%s Session ID in cache for %s %s://%s:%d"),
		no_match ? "Didn't find" : "Found",
		"host",
		tls->scheme, tls->hostname, tls->port));
	return no_match;
}*/

char* Curl_ssl_snihost(struct wintls* tls, const char* host, size_t* olen)
{
	size_t len = strlen(host);
	if (len && (host[len - 1] == '.'))
		len--;
	if (len >= tls->buffer_size)
		return NULL;

	Curl_strntolower(tls->buffer, host, len);
	tls->buffer[len] = 0;
	if (olen)
		*olen = len;
	return tls->buffer;
}

unsigned short curlx_uitous(unsigned int uinum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

	DEBUGASSERT(uinum <= (unsigned int)CURL_MASK_USHORT);
	return (unsigned short)(uinum & (unsigned int)CURL_MASK_USHORT);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}

static CURLcode
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
	struct Curl_schannel_cred* old_cred = NULL;
	struct in_addr addr;
#ifdef ENABLE_IPV6
	struct in6_addr addr6;
#endif
	CURLcode result;
	const char* hostname = tls->hostname;

	DEBUGASSERT(tls);
	DEBUGF(infof(tls,
		"schannel: SSL/TLS connection with %s port %d (step 1/3)",
		hostname, tls->port));

	if (curlx_verify_windows_version(5, 1, 0, PLATFORM_WINNT,
		VERSION_LESS_THAN_EQUAL)) {
		/* Schannel in Windows XP (OS version 5.1) uses legacy handshakes and
		   algorithms that may not be supported by all servers. */
		infof(tls, "schannel: Windows version is old and may not be able to "
			"connect to some servers due to lack of SNI, algorithms, etc.");
	}

#ifdef HAS_ALPN
	/* ALPN is only supported on Windows 8.1 / Server 2012 R2 and above.
	   Also it doesn't seem to be supported for Wine, see curl bug #983. */
	tls->use_alpn = tls->alpn &&
		!GetProcAddress(GetModuleHandle(TEXT("ntdll")),
			"wine_get_version") &&
		curlx_verify_windows_version(6, 3, 0, PLATFORM_WINNT,
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
		if (curlx_verify_windows_version(6, 1, 0, PLATFORM_WINNT,
			VERSION_GREATER_THAN_EQUAL)) {
			tls->use_manual_cred_validation = TRUE;
		}
		else {
			failf(tls, "schannel: this version of Windows is too old to support "
				"certificate verification via CA bundle file.");
			return CURLE_SSL_CACERT_BADFILE;
		}
	}
	else
		tls->use_manual_cred_validation = FALSE;
#else
	if (conn_config->CAfile || conn_config->ca_info_blob) {
		failf(data, "schannel: CA cert support not built in");
		return CURLE_NOT_BUILT_IN;
	}
#endif
#endif

	/* check for an existing re-usable credential handle */
	/*if (tls->sessionid) {
		Curl_ssl_sessionid_lock(tls);
		if (!Curl_ssl_getsessionid(tls, (void**)&old_cred, NULL)) {
			tls->cred = old_cred;
			DEBUGF(infof(tls, "schannel: re-using existing credential handle"));

			tls->cred->refcount++;
			DEBUGF(infof(tls,
				"schannel: incremented credential handle refcount = %d",
				tls->cred->refcount));
		}
		Curl_ssl_sessionid_unlock(tls);
	}*/

	if (!tls->cred_setup) {
		char* snihost;
		result = schannel_acquire_credential_handle(tls);
		if (result)
			return result;
		/* schannel_acquire_credential_handle() sets backend->cred accordingly or
		   it returns error otherwise. */

		   /* A hostname associated with the credential is needed by
			  InitializeSecurityContext for SNI and other reasons. */
		snihost = Curl_ssl_snihost(tls, hostname, NULL);
		if (!snihost) {
			failf(tls, "Failed to set SNI");
			return CURLE_SSL_CONNECT_ERROR;
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

		result = Curl_alpn_to_proto_buf(&proto, tls->alpn);
		if (result) {
			failf(tls, "Error setting ALPN");
			return CURLE_SSL_CONNECT_ERROR;
		}
		tls->do_memcpy(&alpn_buffer[cur], proto.data, proto.len);
		cur += proto.len;

		*list_len = curlx_uitous(cur - list_start_index);
		*extension_len = *list_len +
			(unsigned short)sizeof(unsigned int) +
			(unsigned short)sizeof(unsigned short);

		InitSecBuffer(&inbuf, SECBUFFER_APPLICATION_PROTOCOLS, alpn_buffer, cur);
		InitSecBufferDesc(&inbuf_desc, &inbuf, 1);

		Curl_alpn_to_proto_str(&proto, tls->alpn);
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
	   us problems with inbuf regardless. https://github.com/curl/curl/issues/983
	*/
	sspi_status = s_pSecFn->InitializeSecurityContext(
		&tls->cred_handle, NULL, tls->sni_hostname,
		tls->req_flags, 0, 0,
		(tls->use_alpn ? &inbuf_desc : NULL),
		0, &tls->ctxt_handle,
		&outbuf_desc, &tls->ret_flags, &tls->ctxt_time_stamp);

	if (sspi_status != SEC_I_CONTINUE_NEEDED) {
		char buffer[STRERROR_LEN];
		//Curl_safefree(tls->ctxt_handle);
		switch (sspi_status) {
		case SEC_E_INSUFFICIENT_MEMORY:
			failf(tls, "schannel: initial InitializeSecurityContext failed: %s",
				Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
			return CURLE_OUT_OF_MEMORY;
		case SEC_E_WRONG_PRINCIPAL:
			failf(tls, "schannel: SNI or certificate check failed: %s",
				Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
			return CURLE_PEER_FAILED_VERIFICATION;
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
				Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
			return CURLE_SSL_CONNECT_ERROR;
		}
	}

	DEBUGF(infof(tls, "schannel: sending initial handshake data: "
		"sending %lu bytes.", outbuf.cbBuffer));

	/* send initial handshake data which is now stored in output buffer */
	written = tls->do_send(tls,
		outbuf.pvBuffer, outbuf.cbBuffer,
		&result);
	s_pSecFn->FreeContextBuffer(outbuf.pvBuffer);
	if ((result != CURLE_OK) || (outbuf.cbBuffer != (size_t)written)) {
		failf(tls, "schannel: failed to send initial handshake data: "
			"sent %zd of %lu bytes", written, outbuf.cbBuffer);
		return CURLE_SSL_CONNECT_ERROR;
	}

	DEBUGF(infof(tls, "schannel: sent initial handshake data: "
		"sent %zd bytes", written));

	tls->recv_unrecoverable_err = CURLE_OK;
	tls->recv_sspi_close_notify = FALSE;
	tls->recv_connection_closed = FALSE;
	tls->recv_renegotiating = FALSE;
	tls->encdata_is_incomplete = FALSE;

	/* continue to second handshake step */
	tls->connecting_state = ssl_connect_2;

	return CURLE_OK;
}

CURLcode
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
	CURLcode result;
	BOOL doread;
	const char* pubkey_ptr;

	DEBUGASSERT(tls);

	doread = (tls->connecting_state != ssl_connect_2_writing) ? TRUE : FALSE;

	DEBUGF(infof(tls,
		"schannel: SSL/TLS connection with %s port %d (step 2/3)",
		tls->hostname, tls->port));

	if (!tls->cred_setup || !tls->ctxt_setup)
		return CURLE_SSL_CONNECT_ERROR;

	/* buffer to store previously received and decrypted data */
	if (!tls->decdata_buffer) {
		tls->decdata_offset = 0;
		tls->decdata_length = CURL_SCHANNEL_BUFFER_INIT_SIZE;
		tls->decdata_buffer = tls->do_malloc(tls->decdata_length);
		if (!tls->decdata_buffer) {
			failf(tls, "schannel: unable to allocate memory");
			return CURLE_OUT_OF_MEMORY;
		}
	}

	/* buffer to store previously received and encrypted data */
	if (!tls->encdata_buffer) {
		tls->encdata_is_incomplete = FALSE;
		tls->encdata_offset = 0;
		tls->encdata_length = CURL_SCHANNEL_BUFFER_INIT_SIZE;
		tls->encdata_buffer = tls->do_malloc(tls->encdata_length);
		if (!tls->encdata_buffer) {
			failf(tls, "schannel: unable to allocate memory");
			return CURLE_OUT_OF_MEMORY;
		}
	}

	/* if we need a bigger buffer to read a full message, increase buffer now */
	if (tls->encdata_length - tls->encdata_offset <
		CURL_SCHANNEL_BUFFER_FREE_SIZE) {
		/* increase internal encrypted data buffer */
		size_t reallocated_length = tls->encdata_offset +
			CURL_SCHANNEL_BUFFER_FREE_SIZE;
		reallocated_buffer = tls->do_realloc(tls->encdata_buffer,
			tls->encdata_length, reallocated_length);

		if (!reallocated_buffer) {
			failf(tls, "schannel: unable to re-allocate memory");
			return CURLE_OUT_OF_MEMORY;
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
			if (result == CURLE_AGAIN) {
				if (tls->connecting_state != ssl_connect_2_writing)
					tls->connecting_state = ssl_connect_2_reading;
				DEBUGF(infof(tls, "schannel: failed to receive handshake, "
					"need more data"));
				return CURLE_OK;
			}
			else if ((result != CURLE_OK) || (nread == 0)) {
				failf(tls, "schannel: failed to receive handshake, "
					"SSL/TLS connection failed");
				return CURLE_SSL_CONNECT_ERROR;
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
			curlx_uztoul(tls->encdata_offset));
		InitSecBuffer(&inbuf[1], SECBUFFER_EMPTY, NULL, 0);
		InitSecBufferDesc(&inbuf_desc, inbuf, 2);

		/* setup output buffers */
		InitSecBuffer(&outbuf[0], SECBUFFER_TOKEN, NULL, 0);
		InitSecBuffer(&outbuf[1], SECBUFFER_ALERT, NULL, 0);
		InitSecBuffer(&outbuf[2], SECBUFFER_EMPTY, NULL, 0);
		InitSecBufferDesc(&outbuf_desc, outbuf, 3);

		if (!inbuf[0].pvBuffer) {
			failf(tls, "schannel: unable to allocate memory");
			return CURLE_OUT_OF_MEMORY;
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
			return CURLE_OK;
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
			return CURLE_OK;
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
					if ((result != CURLE_OK) ||
						(outbuf[i].cbBuffer != (size_t)written)) {
						failf(tls, "schannel: failed to send next handshake data: "
							"sent %zd of %lu bytes", written, outbuf[i].cbBuffer);
						return CURLE_SSL_CONNECT_ERROR;
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
					Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
				return CURLE_OUT_OF_MEMORY;
			case SEC_E_WRONG_PRINCIPAL:
				failf(tls, "schannel: SNI or certificate check failed: %s",
					Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
				return CURLE_PEER_FAILED_VERIFICATION;
			case SEC_E_UNTRUSTED_ROOT:
				failf(tls, "schannel: %s",
					Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
				return CURLE_PEER_FAILED_VERIFICATION;
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
					Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
				return CURLE_SSL_CONNECT_ERROR;
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
		return CURLE_OK;
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
		return Curl_verify_certificate(tls);
	}
#endif

	return CURLE_OK;
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
	struct Curl_easy* data;
	CURLcode result;
	int idx;
	int certs_count;
};

static BOOL
add_cert_to_certinfo(const CERT_CONTEXT* ccert_context, void* raw_arg)
{
	struct Adder_args* args = (struct Adder_args*)raw_arg;
	args->result = CURLE_OK;
	if (valid_cert_encoding(ccert_context)) {
		const char* beg = (const char*)ccert_context->pbCertEncoded;
		const char* end = beg + ccert_context->cbCertEncoded;
		int insert_index = (args->certs_count - 1) - args->idx;
		args->result = Curl_extract_certinfo(args->data, insert_index,
			beg, end);
		args->idx++;
	}
	return args->result == CURLE_OK;
}




/*
 * Delete the given session ID from the cache.
void Curl_ssl_delsessionid(struct wintls* data, void* ssl_sessionid)
{
	size_t i;

	for (i = 0; i < data->share->max_ssl_sessions; i++) {
		struct Curl_ssl_session* check = &data->share->session[i];

		if (check->sessionid == ssl_sessionid) {
			Curl_ssl_kill_session(check);
			break;
		}
	}
}
 */

/*
CURLcode Curl_ssl_addsessionid(struct wintls* data,
	void* ssl_sessionid,
	size_t idsize,
	BOOL* added)
{
	size_t i;
	struct Curl_ssl_session* store;
	long oldest_age;
	char* clone_host;
	char* clone_conn_to_host;
	int conn_to_port;
	long* general_age;

	if (added)
		*added = FALSE;

	if (!data->share->session)
		return CURLE_OK;

	store = &data->share->session[0];
	oldest_age = data->share->session[0].age;

	clone_host = strdup(data->hostname);
	if (!clone_host)
		return CURLE_OUT_OF_MEMORY; 

	if (data->conn_to_host) {
		clone_conn_to_host = strdup(data->conn_to_host);
		if (!clone_conn_to_host) {
			free(clone_host);
			return CURLE_OUT_OF_MEMORY; 
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

	if (!Curl_clone_primary_ssl_config(conn_config, &store->ssl_config)) {
		Curl_free_primary_ssl_config(&store->ssl_config);
		store->sessionid = NULL; 
		free(clone_host);
		free(clone_conn_to_host);
		return CURLE_OUT_OF_MEMORY;
	}

	if (added)
		*added = TRUE;

	DEBUGF(infof(data, DMSG(data, "Added Session ID to cache for %s://%s:%d"
		" [%s]"), store->scheme, store->name, store->remote_port,
		Curl_ssl_cf_is_proxy(cf) ? "PROXY" : "server"));
	return CURLE_OK;
}*/



void Curl_ssl_free_certinfo(struct wintls* data)
{
	struct curl_certinfo* ci = &data->certs;

	if (ci->num_of_certs) {
		/* free all individual lists used */
		int i;
		for (i = 0; i < ci->num_of_certs; i++) {
			curl_slist_free_all(ci->certinfo[i]);
			ci->certinfo[i] = NULL;
		}

		free(ci->certinfo); /* free the actual array too */
		ci->certinfo = NULL;
		ci->num_of_certs = 0;
	}
}


CURLcode Curl_ssl_init_certinfo(struct wintls* data, int num)
{
	struct curl_certinfo* ci = &data->certs;
	struct curl_slist** table;

	/* Free any previous certificate information structures */
	Curl_ssl_free_certinfo(data);

	/* Allocate the required certificate information structures */
	table = calloc((size_t)num, sizeof(struct curl_slist*));
	if (!table)
		return CURLE_OUT_OF_MEMORY;

	ci->num_of_certs = num;
	ci->certinfo = table;

	return CURLE_OK;
}

static CURLcode
schannel_connect_step3(struct wintls* tls)
{
	CURLcode result = CURLE_OK;
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
		return CURLE_SSL_CONNECT_ERROR;

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
		return CURLE_SSL_CONNECT_ERROR;
	}

#ifdef HAS_ALPN
	if (tls->use_alpn) {
		sspi_status =
			s_pSecFn->QueryContextAttributes(&tls->ctxt_handle,
				SECPKG_ATTR_APPLICATION_PROTOCOL,
				&alpn_result);

		if (sspi_status != SEC_E_OK) {
			failf(tls, "schannel: failed to retrieve ALPN result");
			return CURLE_SSL_CONNECT_ERROR;
		}

		if (alpn_result.ProtoNegoStatus ==
			SecApplicationProtocolNegotiationStatus_Success) {
			unsigned char prev_alpn = tls->alpn;

			Curl_alpn_set_negotiated(tls, alpn_result.ProtocolId,
				alpn_result.ProtocolIdSize);
			if (tls->recv_renegotiating) {
				if (prev_alpn != tls->alpn &&
					prev_alpn != CURL_HTTP_VERSION_NONE) {
					/* Renegotiation selected a different protocol now, we cannot
					 * deal with this */
					failf(tls, "schannel: server selected an ALPN protocol too late");
					return CURLE_SSL_CONNECT_ERROR;
				}
			}
		}
		else {
			if (!tls->recv_renegotiating)
				Curl_alpn_set_negotiated(tls, NULL, 0);
		}
	}
#endif

	/* save the current session data for possible re-use
	if (tls->sessionid) {
		BOOL incache;
		BOOL added = FALSE;
		struct Curl_schannel_cred* old_cred = NULL;

		Curl_ssl_sessionid_lock(tls);
		incache = !(Curl_ssl_getsessionid(tls, (void**)&old_cred, NULL));
		if (incache) {
			if (old_cred != tls->cred) {
				DEBUGF(infof(tls,
					"schannel: old credential handle is stale, removing"));
				Curl_ssl_delsessionid(tls, (void*)old_cred);
				incache = FALSE;
			}
		}
		if (!incache) {
			result = Curl_ssl_addsessionid(tls,
				sizeof(struct Curl_schannel_cred),
				&added);
			if (result) {
				Curl_ssl_sessionid_unlock(tls);
				failf(tls, "schannel: failed to store credential handle");
				return result;
			}
			else if (added) {
				tls->cred->refcount++;
				DEBUGF(infof(tls,
					"schannel: stored credential handle in session cache"));
			}
		}
		Curl_ssl_sessionid_unlock(tls);
	} */

	if (tls->certinfo) {
		int certs_count = 0;
		sspi_status =
			s_pSecFn->QueryContextAttributes(&tls->ctxt_handle,
				SECPKG_ATTR_REMOTE_CERT_CONTEXT,
				&ccert_context);

		if ((sspi_status != SEC_E_OK) || !ccert_context) {
			failf(tls, "schannel: failed to retrieve remote cert context");
			return CURLE_PEER_FAILED_VERIFICATION;
		}

		traverse_cert_store(ccert_context, cert_counter_callback, &certs_count);

		result = Curl_ssl_init_certinfo(tls, certs_count);
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

	return CURLE_OK;
}

static CURLcode
schannel_connect_common(struct wintls* tls,
	BOOL nonblocking, BOOL* done)
{
	CURLcode result;
	//struct ssl_connect_data* connssl = cf->ctx;
	//curl_socket_t sockfd = Curl_conn_cf_get_socket(cf, data);
	timediff_t timeout_ms;
	int what;

	/* check if the connection has already been established */
	if (ssl_connection_complete == tls->state) {
		*done = TRUE;
		return CURLE_OK;
	}

	if (ssl_connect_1 == tls->connecting_state) {
		/* check out how much more time we're allowed */
		timeout_ms = Curl_timeleft(tls, NULL, TRUE);

		if (timeout_ms < 0) {
			/* no need to continue if time already is up */
			failf(tls, "SSL/TLS connection timeout");
			return CURLE_OPERATION_TIMEDOUT;
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
		timeout_ms = Curl_timeleft(tls, NULL, TRUE);

		if (timeout_ms < 0) {
			/* no need to continue if time already is up */
			failf(tls, "SSL/TLS connection timeout");
			return CURLE_OPERATION_TIMEDOUT;
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
				return CURLE_OPERATION_TIMEDOUT;
			}
			/*if (what < 0) {
				failf(tls, "select/poll on SSL/TLS socket, errno: %d", WSAGetLastError());
				return CURLE_SSL_CONNECT_ERROR;
			}
			else if (0 == what) {
				if (nonblocking) {
					*done = FALSE;
					return CURLE_OK;
				}
				else {
					failf(tls, "SSL/TLS connection timeout");
					return CURLE_OPERATION_TIMEDOUT;
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

	return CURLE_OK;
}

ssize_t
schannel_send(struct wintls* tls,
	const void* buf, size_t len, CURLcode* err)
{
	ssize_t written = -1;
	size_t data_len = 0;
	unsigned char* ptr = NULL;
	SecBuffer outbuf[4];
	SecBufferDesc outbuf_desc;
	SECURITY_STATUS sspi_status = SEC_E_OK;
	CURLcode result;

	DEBUGASSERT(tls);

	/* check if the maximum stream sizes were queried */
	if (tls->stream_sizes.cbMaximumMessage == 0) {
		sspi_status = s_pSecFn->QueryContextAttributes(
			&tls->ctxt_handle,
			SECPKG_ATTR_STREAM_SIZES,
			&tls->stream_sizes);
		if (sspi_status != SEC_E_OK) {
			*err = CURLE_SEND_ERROR;
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
		*err = CURLE_OUT_OF_MEMORY;
		return -1;
	}

	/* setup output buffers (header, data, trailer, empty) */
	InitSecBuffer(&outbuf[0], SECBUFFER_STREAM_HEADER,
		ptr, tls->stream_sizes.cbHeader);
	InitSecBuffer(&outbuf[1], SECBUFFER_DATA,
		ptr + tls->stream_sizes.cbHeader, curlx_uztoul(len));
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
			timediff_t timeout_ms = Curl_timeleft(tls, NULL, FALSE);
			if (timeout_ms < 0) {
				failf(tls, "schannel: timed out sending data "
					"(bytes sent: %zd)", written);
				*err = CURLE_OPERATION_TIMEDOUT;
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
				return CURLE_OPERATION_TIMEDOUT;
			}
			/*if (what < 0) {
				failf(tls, "select/poll on SSL socket, errno: %d", WSAGetLastError());
				*err = CURLE_SEND_ERROR;
				written = -1;
				break;
			}
			else if (0 == what) {
				failf(tls, "schannel: timed out sending data "
					"(bytes sent: %zd)", written);
				*err = CURLE_OPERATION_TIMEDOUT;
				written = -1;
				break;
			}*/
			/* socket is writable */

			this_write = tls->do_send(tls, ptr + written, len - written, &result);
			if (result == CURLE_AGAIN)
				continue;
			else if (result != CURLE_OK) {
				*err = result;
				written = -1;
				break;
			}

			written += this_write;
		}
	}
	else if (sspi_status == SEC_E_INSUFFICIENT_MEMORY) {
		*err = CURLE_OUT_OF_MEMORY;
	}
	else {
		*err = CURLE_SEND_ERROR;
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
	char* buf, size_t len, CURLcode* err)
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
	size_t min_encdata_length = len + CURL_SCHANNEL_BUFFER_FREE_SIZE;

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
	*err = CURLE_OK;

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
		if (size < CURL_SCHANNEL_BUFFER_FREE_SIZE ||
			tls->encdata_length < min_encdata_length) {
			reallocated_length = tls->encdata_offset +
				CURL_SCHANNEL_BUFFER_FREE_SIZE;
			if (reallocated_length < min_encdata_length) {
				reallocated_length = min_encdata_length;
			}
			reallocated_buffer = tls->do_realloc(tls->encdata_buffer, tls->encdata_length, reallocated_length);
			if (!reallocated_buffer) {
				*err = CURLE_OUT_OF_MEMORY;
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
			if (*err == CURLE_AGAIN)
				DEBUGF(infof(tls,
					"schannel: recv returned CURLE_AGAIN"));
			else if (*err == CURLE_RECV_ERROR)
				infof(tls, "schannel: recv returned CURLE_RECV_ERROR");
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
			curlx_uztoul(tls->encdata_offset));

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
				size = inbuf[1].cbBuffer > CURL_SCHANNEL_BUFFER_FREE_SIZE ?
					inbuf[1].cbBuffer : CURL_SCHANNEL_BUFFER_FREE_SIZE;
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
						*err = CURLE_OUT_OF_MEMORY;
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
				if (*err && *err != CURLE_AGAIN) {
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
				*err = CURLE_AGAIN;
			infof(tls, "schannel: failed to decrypt data, need more data");
			goto cleanup;
		}
		else {
#ifndef CURL_DISABLE_VERBOSE_STRINGS
			char buffer[STRERROR_LEN];
#endif
			* err = CURLE_RECV_ERROR;
			infof(tls, "schannel: failed to read data from server: %s",
				Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
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
		BOOL isWin2k = curlx_verify_windows_version(5, 0, 0, PLATFORM_WINNT,
			VERSION_EQUAL);

		if (isWin2k && sspi_status == SEC_E_OK)
			tls->recv_sspi_close_notify = TRUE;
		else {
			*err = CURLE_RECV_ERROR;
			infof(tls, "schannel: server closed abruptly (missing close_notify)");
		}
	}

	/* Any error other than CURLE_AGAIN is an unrecoverable error. */
	if (*err && *err != CURLE_AGAIN)
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
		*err = CURLE_OK;
		return (ssize_t)size;
	}

	if (!*err && !tls->recv_connection_closed)
		*err = CURLE_AGAIN;

	/* It's debatable what to return when !len. We could return whatever error
	   we got from decryption but instead we override here so the return is
	   consistent.
	*/
	if (!len)
		*err = CURLE_OK;

	return *err ? -1 : 0;
}

CURLcode schannel_connect_nonblocking(struct wintls* data,
	BOOL* done)
{
	return schannel_connect_common(data, TRUE, done);
}

CURLcode schannel_connect(struct wintls* data)
{
	CURLcode result;
	BOOL done = FALSE;

	result = schannel_connect_common(data, FALSE, &done);
	if (result)
		return result;

	DEBUGASSERT(done);

	return CURLE_OK;
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
	struct Curl_schannel_cred* cred = ptr;

	if (cred) {
		s_pSecFn->FreeCredentialsHandle(&cred->cred_handle);
		curlx_unicodefree(cred->sni_hostname);
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
		CURLcode result;
		DWORD dwshut = SCHANNEL_SHUTDOWN;

		InitSecBuffer(&Buffer, SECBUFFER_TOKEN, &dwshut, sizeof(dwshut));
		InitSecBufferDesc(&BuffDesc, &Buffer, 1);

		sspi_status = s_pSecFn->ApplyControlToken(&tls->ctxt_handle,
			&BuffDesc);

		if (sspi_status != SEC_E_OK) {
			char buffer[STRERROR_LEN];
			failf(tls, "schannel: ApplyControlToken failure: %s",
				Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
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
			if ((result != CURLE_OK) || (outbuf.cbBuffer != (size_t)written)) {
				infof(tls, "schannel: failed to send close msg: %s"
					" (bytes written: %zd)", curl_easy_strerror(result), written);
			}
		}
	}

	/* free SSPI Schannel API security context handle */
	if (tls->ctxt_setup) {
		DEBUGF(infof(tls, "schannel: clear security context handle"));
		s_pSecFn->DeleteSecurityContext(&tls->ctxt_handle);
		//Curl_safefree(tls->ctxt);
	}

	//schannel_session_free(tls->cred);
	/* free SSPI Schannel API credential handle
	if (tls->cred) {
		Curl_ssl_sessionid_lock(tls);
		Curl_ssl_sessionid_unlock(tls);
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

	return CURLE_OK;
}

static void schannel_close(struct Curl_cfilter* cf, struct Curl_easy* data)
{
	schannel_shutdown(cf, data);
}

int schannel_init(void)
{
	return (Curl_sspi_global_init() == CURLE_OK ? 1 : 0);
}

static void schannel_cleanup(void)
{
	Curl_sspi_global_cleanup();
}

static size_t schannel_version(char* buffer, size_t size)
{
	size = msnprintf(buffer, size, "Schannel");

	return size;
}


CURLcode Curl_win32_random(unsigned char* entropy, size_t length)
{
	memset(entropy, 0, length);

	if (BCryptGenRandom(NULL, entropy, (ULONG)length,
		BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
		return CURLE_FAILED_INIT;

	return CURLE_OK;
}


static CURLcode schannel_random(struct Curl_easy* data,
	unsigned char* entropy, size_t length)
{
	(void)data;

	return Curl_win32_random(entropy, length);
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

static CURLcode schannel_sha256sum(const unsigned char* input,
	size_t inputlen,
	unsigned char* sha256sum,
	size_t sha256len)
{
	schannel_checksum(input, inputlen, sha256sum, sha256len,
		PROV_RSA_AES, CALG_SHA_256);
	return CURLE_OK;
}
	