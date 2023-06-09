#ifndef HEADER_CURL_SCHANNEL_H
#define HEADER_CURL_SCHANNEL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Marc Hoersken, <info@marc-hoersken.de>, et al.
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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
//#include "curl_setup.h"
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
#include "msvc.h"
/* Undefine wincrypt conflicting symbols for BoringSSL. */
#undef X509_NAME
#undef X509_EXTENSIONS
#undef PKCS7_ISSUER_AND_SERIAL
#undef PKCS7_SIGNER_INFO
#undef OCSP_REQUEST
#undef OCSP_RESPONSE

#include <schnlsp.h>
#include <schannel.h>
#include "curl_sspi.h"


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

extern const struct Curl_ssl Curl_ssl_schannel;

CURLcode Curl_verify_certificate(struct wintls* data);

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

#ifndef CURL_SHA256_DIGEST_LENGTH
#define CURL_SHA256_DIGEST_LENGTH 32 /* fixed size */
#endif

#ifndef MAX_PINNED_PUBKEY_SIZE
#define MAX_PINNED_PUBKEY_SIZE 1048576 /* 1MB */
#endif
#define CURL_MASK_USIZE_T ((size_t)~0)
#define CURL_MASK_SSIZE_T (CURL_MASK_USIZE_T >> 1)
#define CURL_MASK_USHORT  ((unsigned short)~0)
#define CURL_MASK_SSHORT  (CURL_MASK_USHORT >> 1)


enum {
    CURL_SSLVERSION_DEFAULT,
    CURL_SSLVERSION_TLSv1, /* TLS 1.x */
    CURL_SSLVERSION_SSLv2,
    CURL_SSLVERSION_SSLv3,
    CURL_SSLVERSION_TLSv1_0,
    CURL_SSLVERSION_TLSv1_1,
    CURL_SSLVERSION_TLSv1_2,
    CURL_SSLVERSION_TLSv1_3,

    CURL_SSLVERSION_LAST /* never use, keep last */
};

enum {
    CURL_SSLVERSION_MAX_NONE = 0,
    CURL_SSLVERSION_MAX_DEFAULT = (CURL_SSLVERSION_TLSv1 << 16),
    CURL_SSLVERSION_MAX_TLSv1_0 = (CURL_SSLVERSION_TLSv1_0 << 16),
    CURL_SSLVERSION_MAX_TLSv1_1 = (CURL_SSLVERSION_TLSv1_1 << 16),
    CURL_SSLVERSION_MAX_TLSv1_2 = (CURL_SSLVERSION_TLSv1_2 << 16),
    CURL_SSLVERSION_MAX_TLSv1_3 = (CURL_SSLVERSION_TLSv1_3 << 16),

    /* never use, keep last */
    CURL_SSLVERSION_MAX_LAST = (CURL_SSLVERSION_LAST << 16)
};

CURLcode schannel_connect_nonblocking(struct wintls* data,
    BOOL* done);

CURLcode schannel_connect(struct wintls* data);

CURLcode
schannel_acquire_credential_handle(struct wintls* tls);

int schannel_init(void);


ssize_t
schannel_send(struct wintls* tls,
    const void* buf, size_t len, CURLcode* err);
ssize_t
schannel_recv(struct wintls* tls,
    char* buf, size_t len, CURLcode* err);
#ifdef __cplusplus
}
#endif

#endif /* HEADER_CURL_SCHANNEL_H */