#ifndef __X509ASN1_H_
#define __X509ASN1_H_
/*
 * Types.
 */

 /* ASN.1 parsed element. */
struct Curl_asn1Element {
	const char* header;         /* Pointer to header byte. */
	const char* beg;            /* Pointer to element data. */
	const char* end;            /* Pointer to 1st byte after element. */
	unsigned char class;        /* ASN.1 element class. */
	unsigned char tag;          /* ASN.1 element tag. */
	BOOL          constructed;  /* Element is constructed. */
};

/* X509 certificate: RFC 5280. */
struct Curl_X509certificate {
	struct Curl_asn1Element certificate;
	struct Curl_asn1Element version;
	struct Curl_asn1Element serialNumber;
	struct Curl_asn1Element signatureAlgorithm;
	struct Curl_asn1Element signature;
	struct Curl_asn1Element issuer;
	struct Curl_asn1Element notBefore;
	struct Curl_asn1Element notAfter;
	struct Curl_asn1Element subject;
	struct Curl_asn1Element subjectPublicKeyInfo;
	struct Curl_asn1Element subjectPublicKeyAlgorithm;
	struct Curl_asn1Element subjectPublicKey;
	struct Curl_asn1Element issuerUniqueID;
	struct Curl_asn1Element subjectUniqueID;
	struct Curl_asn1Element extensions;
};
int Curl_parseX509(struct Curl_X509certificate* cert,
	const char* beg, const char* end);
CURLcode Curl_extract_certinfo(struct wintls* tls, int certnum,
	const char* beg, const char* end);
CURLcode Curl_verifyhost(struct wintls* tls,
	const char* beg, const char* end);

#endif